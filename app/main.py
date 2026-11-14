"""
Triagle — main application.

An AI SOC analyst + responder for MSPs: ingest alerts from multiple client
tools, triage each with conservative-closure logic, correlate into
incidents (attack chains), and present a decided queue an MSP can act on —
plus a client-ready incident report to forward to the end customer.

Triagle — triage, decided.
"""
import os
import json
import time
import datetime

from urllib.parse import quote

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.orchestrator import process_batch
from app.engine.response import execute_action
from app.engine import certin
from app.agent import backend
from app import auth, audit

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SAMPLE_PATH = os.path.join(BASE_DIR, "samples", "incoming_alerts.json")

app = FastAPI(title="Triagle", version="0.3.0", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


# ---- sign-in ---------------------------------------------------------------

class SignInRequired(Exception):
    def __init__(self, next_path="/"):
        self.next_path = next_path


@app.exception_handler(SignInRequired)
def _to_login(request: Request, exc: SignInRequired):
    if request.method == "GET":
        return RedirectResponse(url="/login?next=" + quote(auth.safe_next(exc.next_path), safe="/"),
                                status_code=303)
    return HTMLResponse("Sign in required.", status_code=401)


LOCAL_USER = {"name": "local", "role": "analyst"}


def _session_token(request: Request):
    return request.cookies.get(auth.COOKIE, "")


def current_user(request: Request):
    if not auth.enabled():
        return LOCAL_USER
    return auth.read_session(_session_token(request))


def require_user(request: Request):
    user = current_user(request)
    if not user:
        path = request.url.path + (("?" + request.url.query) if request.url.query else "")
        raise SignInRequired(path)
    return user


def require_analyst(user=Depends(require_user)):
    if user["role"] != "analyst":
        raise HTTPException(status_code=403, detail="Your account can view but not approve actions.")
    return user


def _client_ip(request: Request):
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "")) or "-"


def _is_https(request: Request):
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "") == "https"


def _ctx(request: Request, user, **extra):
    """Things every page needs: who is signed in and the form token."""
    base = {"user": user, "csrf": auth.csrf_token(_session_token(request)),
            "auth_on": auth.enabled()}
    base.update(extra)
    return base


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Cache-Control", "no-store")
    if _is_https(request):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    if current_user(request):
        return RedirectResponse(url=auth.safe_next(next), status_code=303)
    return templates.TemplateResponse(request, "login.html", {"next": auth.safe_next(next), "error": None})


@app.post("/login")
def login_submit(request: Request, username: str = Form(default=""), password: str = Form(default=""),
                 next: str = Form(default="/")):
    ip = _client_ip(request)
    user, reason = auth.check_login(username, password, ip)
    if not user:
        audit.record("sign-in failed", (username or "-")[:64], ip=ip, reason=reason)
        msg = ("Too many failed attempts. Try again in a few minutes." if reason == "locked"
               else "Wrong username or password.")
        return templates.TemplateResponse(request, "login.html",
                                          {"next": auth.safe_next(next), "error": msg},
                                          status_code=429 if reason == "locked" else 401)
    audit.record("signed in", user["name"], ip=ip, role=user["role"])
    resp = RedirectResponse(url=auth.safe_next(next), status_code=303)
    resp.set_cookie(auth.COOKIE, auth.make_session(user), httponly=True, samesite="lax",
                    secure=_is_https(request), max_age=auth._state["session_seconds"], path="/")
    return resp


@app.post("/logout")
def logout(request: Request, csrf: str = Form(default="")):
    user = current_user(request)
    if user and auth.enabled() and auth.csrf_ok(_session_token(request), csrf):
        audit.record("signed out", user["name"], ip=_client_ip(request))
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, user=Depends(require_analyst)):
    return templates.TemplateResponse(request, "audit.html", _ctx(
        request, user, entries=audit.read(300), chain=audit.verify(), log_path=audit.path()))


# process the sample batch once at startup for the demo; in production this
# would be a live queue fed by connectors.
_CACHE = {}


def _load_result():
    if "result" not in _CACHE:
        with open(os.environ.get("TRIAGLE_ALERTS", SAMPLE_PATH)) as f:
            raw = json.load(f)
        demo_clock = os.environ.get("TRIAGLE_DEMO_CLOCK", "false").lower() == "true"
        if demo_clock:
            raw = _rebase_times(raw)
        t0 = time.perf_counter()
        result = process_batch(raw)
        result["metrics"]["demo_clock"] = demo_clock
        result["metrics"]["processing_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        result["metrics"]["backend"] = backend.BACKEND
        _CACHE["result"] = result
    return _CACHE["result"]


_TIME_KEYS = ("created_timestamp", "eventtime", "createdDateTime")


def _rebase_times(raw_alerts):
    """Demo only (TRIAGLE_DEMO_CLOCK=true): shift each client's sample
    timestamps by one amount so that client's newest alert is five minutes
    old. Order and gaps within a client are kept. Lets the 6-hour clock be
    shown running on old sample data."""
    def when(item):
        for k in _TIME_KEYS:
            v = item["raw"].get(k)
            if v:
                try:
                    return k, datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                except ValueError:
                    pass
        return None, None
    target = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    newest = {}
    for item in raw_alerts:
        _, t = when(item)
        if t and (item.get("client") not in newest or t > newest[item.get("client")]):
            newest[item.get("client")] = t
    for item in raw_alerts:
        k, t = when(item)
        if t:
            item["raw"][k] = (t + (target - newest[item.get("client")])).strftime("%Y-%m-%dT%H:%M:%SZ")
    return raw_alerts


def _incident_members(result, incident):
    members = []
    for a in result["alerts"]:
        if a["alert_id"] in incident["alert_ids"]:
            members.append({"alert": a, "verdict": result["verdicts"].get(a["alert_id"], {})})
    members.sort(key=lambda m: m["alert"].get("timestamp", ""))
    return members


def _find_incident(result, entity):
    e = entity.lower()
    for i in result["incidents"]:
        if i["key"].lower() == e or e in (x.lower() for x in i.get("entities", [])):
            return i
    return None


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user=Depends(require_user)):
    result = _load_result()
    # build a combined alert+verdict view, escalated first
    rows = []
    for a in result["alerts"]:
        v = result["verdicts"].get(a["alert_id"], {})
        rows.append({"alert": a, "verdict": v})
    rows.sort(key=lambda r: (not r["verdict"].get("escalate"),
                             {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r["verdict"].get("severity"), 9)))
    for inc in result["incidents"]:
        inc["reportable"] = certin.is_reportable_candidate(_incident_members(result, inc))
    return templates.TemplateResponse(request, "dashboard.html", _ctx(
        request, user, rows=rows, metrics=result["metrics"], incidents=result["incidents"],
        now=datetime.datetime.now().strftime("%d %b %Y, %H:%M")))


@app.get("/alert/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: str, notice: str = "", user=Depends(require_user)):
    result = _load_result()
    alert = next((a for a in result["alerts"] if a["alert_id"] == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"No alert with id {alert_id}")
    verdict = result["verdicts"].get(alert_id)
    trail = result.get("trails", {}).get(alert_id, [])
    actions = result.get("actions", {}).get(alert_id, [])
    return templates.TemplateResponse(request, "detail.html", _ctx(
        request, user, alert=alert, verdict=verdict, trail=trail, actions=actions,
        notice=NOTICES.get(notice, ""), can_approve=user["role"] == "analyst",
        now=datetime.datetime.now().strftime("%d %b %Y, %H:%M")))


NOTICES = {
    "ack": "Not approved: tick the box to confirm you have read the blast radius, then approve again.",
    "done": "That action has already been decided.",
}


@app.post("/action/approve")
def decide_action(request: Request, alert_id: str = Form(...), action_id: str = Form(...),
                  ack: str = Form(default=""), decision: str = Form(default="approve"),
                  reason: str = Form(default=""), csrf: str = Form(default=""),
                  user=Depends(require_analyst)):
    """A signed-in analyst approves or declines a staged action. Approved
    actions then 'execute' (simulated). Every decision is written to the
    audit log with the analyst's name."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    if decision not in ("approve", "decline"):
        raise HTTPException(status_code=400, detail="Unknown decision.")
    result = _load_result()
    act = next((x for x in result.get("actions", {}).get(alert_id, []) if x["action_id"] == action_id), None)
    if act is None:
        raise HTTPException(status_code=404, detail="No such action on that alert.")
    back = f"/alert/{quote(alert_id, safe=':')}"
    if act["status"] != "pending":
        return RedirectResponse(url=back + "?notice=done", status_code=303)

    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    common = dict(alert_id=alert_id, action=act["action_type"], target=act["target"],
                  risk_tier=act["risk_tier"], ip=_client_ip(request))
    if decision == "decline":
        act.update(status="declined", decided_by=user["name"], decided_at=stamp,
                   result_message=f"Declined by {user['name']}" + (f": {reason[:200]}" if reason.strip() else "."))
        audit.record("action declined", user["name"], reason=reason[:200] or None, **common)
        return RedirectResponse(url=back, status_code=303)

    if act.get("requires_ack") and ack != "on":
        # stays pending: a missed checkbox must not throw the action away
        return RedirectResponse(url=back + "?notice=ack", status_code=303)

    act["status"] = "approved"
    res = execute_action(act, approver=user["name"])
    act.update(status="executed" if res["ok"] else "approved", decided_by=user["name"],
               decided_at=stamp, result_message=res["message"])
    audit.record("action approved", user["name"], acknowledged_blast_radius=bool(act.get("requires_ack")),
                 executed=res["ok"], simulated=True, **common)
    return RedirectResponse(url=back, status_code=303)


@app.get("/tuning", response_class=HTMLResponse)
def tuning_page(request: Request, user=Depends(require_user)):
    result = _load_result()
    return templates.TemplateResponse(request, "tuning.html", _ctx(
        request, user, rule_health=result.get("rule_health", []), metrics=result["metrics"],
        now=datetime.datetime.now().strftime("%d %b %Y, %H:%M")))


@app.get("/report/{entity}", response_class=HTMLResponse)
def incident_report(request: Request, entity: str, user=Depends(require_user)):
    """Client-ready incident report for a correlated incident, keyed by the
    incident's entity. This is the artifact an MSP forwards to its customer."""
    result = _load_result()
    incident = _find_incident(result, entity)
    if not incident:
        raise HTTPException(status_code=404, detail=f"No incident found for {entity}")

    members = _incident_members(result, incident)
    client_name = incident.get("client") or (members[0]["alert"]["client"] if members else None)

    any_escalated = any(m["verdict"].get("escalate") for m in members)

    return templates.TemplateResponse(request, "report.html", {
        "incident": incident,
        "members": members,
        "client_name": client_name,
        "any_escalated": any_escalated,
        "reportable": certin.is_reportable_candidate(members),
        "now": datetime.datetime.now().strftime("%d %b %Y, %H:%M"),
    })


@app.get("/certin/{entity}", response_class=HTMLResponse)
def certin_draft(request: Request, entity: str, user=Depends(require_user)):
    """Draft CERT-In incident report for an incident, with the 6-hour clock.
    A draft for a person to check and send; nothing is filed from here."""
    from app.orchestrator import _load_env
    result = _load_result()
    incident = _find_incident(result, entity)
    if not incident:
        raise HTTPException(status_code=404, detail=f"No incident found for {entity}")
    members = _incident_members(result, incident)
    if not certin.is_reportable_candidate(members):
        raise HTTPException(status_code=404, detail="Nothing in this incident was escalated; no report draft.")
    draft = certin.build_draft(incident, members, result.get("actions", {}),
                               threat_intel=_load_env().get("threat_intel"))
    return templates.TemplateResponse(request, "certin.html", {
        "d": draft, "metrics": result["metrics"],
    })


@app.get("/benchmark", response_class=HTMLResponse)
def benchmark_page(request: Request, user=Depends(require_user)):
    """Runs the labelled simulated set in eval/ through the same engine."""
    from eval.run_benchmark import run
    rows, summary, elapsed, _ = run()
    return templates.TemplateResponse(request, "benchmark.html", {
        "rows": rows, "summary": summary, "ms": round(elapsed * 1000),
        "backend": backend.BACKEND,
    })


@app.get("/healthz")
def healthz(request: Request):
    """Public: just enough for an uptime check. Details only when signed in."""
    out = {"ok": True, "version": app.version}
    if current_user(request):
        out.update(backend=backend.BACKEND, mask_pii=backend.MASK_PII,
                   model_calls=backend.STATS["calls"], identifiers_masked=backend.STATS["masked"],
                   sign_in=auth.enabled(), audit_chain_ok=audit.verify()["ok"])
    return out
