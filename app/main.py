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
import hmac
import threading

from urllib.parse import quote

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.orchestrator import process_batch
from app.connectors.sources import normalize
from app.engine.response import execute_action
from app.engine import certin
from app.agent import backend
from app import auth, audit
from app.engine import sources_meta, worknotes, reputation
from app.engine.correlate import GENERIC_ENTITIES

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SAMPLE_PATH = os.path.join(BASE_DIR, "samples", "incoming_alerts.json")

app = FastAPI(title="Triagle", version="0.8.0", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
templates.env.globals.update(
    source_name=sources_meta.source_name,
    source_full=sources_meta.source_full,
    source_list=sources_meta.source_list,
    verdict_label=sources_meta.verdict_label,
)


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
            "auth_on": auth.enabled(),
            "demo_mode": os.environ.get("TRIAGLE_DEMO", "false").lower() == "true"}
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


# ---- the queue ---------------------------------------------------------------
#
# Two lists make up the queue: the seed (sample alerts, loaded once) and the
# live alerts that arrived through /ingest. Everything is held in memory and
# rebuilt from those two lists whenever an alert arrives, so a verdict can
# change when later alerts add context.
#
# What survives a rebuild is kept apart from it:
#   decisions   every approved / declined / auto-run action, by action id,
#               so a new alert never un-approves something
#   rolled      counts for live alerts that aged out of memory
#   feeds       per source: how many alerts, when the last one arrived
_CACHE = {}
_WORKNOTES = {}        # incident alert-id tuple -> (notes text, by_gemini)
_LOCK = threading.RLock()


def _live_limit():
    """How many live alerts are kept in memory (TRIAGLE_LIVE_LIMIT)."""
    try:
        return max(50, int(os.environ.get("TRIAGLE_LIVE_LIMIT", "1500")))
    except ValueError:
        return 1500


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seed_raw():
    """The queue starts from the sample file (optionally time-shifted for the
    demo clock). Live alerts from /ingest and /demo/fire are kept beside it.
    TRIAGLE_SEED=off starts with an empty queue, for a live-only console."""
    if os.environ.get("TRIAGLE_SEED", "on").lower() in ("off", "false", "0", "no"):
        return []
    with open(os.environ.get("TRIAGLE_ALERTS", SAMPLE_PATH)) as f:
        raw = json.load(f)
    if os.environ.get("TRIAGLE_DEMO_CLOCK", "false").lower() == "true":
        raw = _rebase_times(raw)
    return raw


def _ensure_state():
    if "seed" in _CACHE:
        return
    _CACHE["seed"] = _seed_raw()
    _CACHE["live"] = []             # raw ingest items, oldest first
    _CACHE["live_meta"] = []        # (alert_id, timestamp) for each, same order
    _CACHE["seen_ids"] = set()      # every alert id ever accepted, so a replay is not double-counted
    for item in _CACHE["seed"]:
        try:
            _CACHE["seen_ids"].add(normalize(item["source"], item["raw"], item.get("client", "Unknown")).alert_id)
        except (ValueError, KeyError, TypeError, AttributeError):
            pass
    _CACHE["live_count"] = 0
    _CACHE["decisions"] = {}
    _CACHE["rolled"] = {"total": 0, "closed": 0, "escalated": 0, "codes": {}}
    _CACHE["feeds"] = {}
    _CACHE["rev"] = 0
    _CACHE.pop("result", None)


def _remember_decisions(result):
    """Keep what has already happened to each action, and write the audit
    entry the first time an automatic action runs on a live alert."""
    decisions = _CACHE["decisions"]
    live_ids = {aid for aid, _ in _CACHE["live_meta"]}
    for aid, acts in result.get("actions", {}).items():
        for a in acts:
            if a.get("status") == "pending" or a["action_id"] in decisions:
                continue
            decisions[a["action_id"]] = {k: a.get(k) for k in
                                         ("status", "decided_by", "decided_at", "result_message")}
            if a.get("status") == "auto_executed" and aid in live_ids:
                audit.record("action auto-executed", "Triagle · auto-policy", alert_id=aid,
                             action=a["action_type"], target=a["target"], risk_tier=a["risk_tier"],
                             executed=True, simulated=_simulated(), policy_reason=a.get("policy_reason"))


def _simulated():
    from app.engine import action_tools
    return action_tools.execute_mode() != "live"


def _reprocess():
    """Rebuild the decided queue from the current raw alerts."""
    raw = _CACHE["seed"] + _CACHE["live"]
    _CACHE["raw"] = raw
    t0 = time.perf_counter()
    result = process_batch(raw, decided=_CACHE["decisions"])
    m = result["metrics"]
    m["demo_clock"] = os.environ.get("TRIAGLE_DEMO_CLOCK", "false").lower() == "true"
    m["processing_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    m["backend"] = backend.BACKEND
    m["live_alerts"] = _CACHE.get("live_count", 0)

    # totals that include live alerts no longer held in memory
    rolled = _CACHE["rolled"]
    codes = dict(rolled["codes"])
    for v in result["verdicts"].values():
        if v.get("closure_code") and not v.get("escalate"):
            codes[v["closure_code"]] = codes.get(v["closure_code"], 0) + 1
    m["received"] = m["total"] + rolled["total"]
    m["closed_all"] = m["auto_closed"] + rolled["closed"]
    m["escalated_all"] = m["escalated"] + rolled["escalated"]
    m["closed_pct_all"] = round(100 * m["closed_all"] / m["received"]) if m["received"] else 0
    m["closed_by_code"] = codes
    m["rolled_off"] = rolled["total"]

    _remember_decisions(result)
    _CACHE["result"] = result
    _CACHE["rev"] = _CACHE.get("rev", 0) + 1
    return result


def _load_result():
    with _LOCK:
        _ensure_state()
        if "result" not in _CACHE:
            _reprocess()
        return _CACHE["result"]


def _trim():
    """Keep memory bounded on a busy stream. Closed alerts age out first,
    oldest first; an escalated alert is only dropped when nothing else is
    left to drop. What is dropped stays in the running totals."""
    live, meta = _CACHE["live"], _CACHE["live_meta"]
    limit = _live_limit()
    if len(live) <= limit:
        return False
    excess = len(live) - int(limit * 0.9)          # trim below the limit, so not on every alert
    verdicts = _CACHE["result"]["verdicts"]
    by_age = sorted(range(len(live)), key=lambda i: (meta[i][1] or "", i))
    closed = [i for i in by_age if not (verdicts.get(meta[i][0]) or {}).get("escalate")]
    escalated = [i for i in by_age if (verdicts.get(meta[i][0]) or {}).get("escalate")]
    drop = closed[:excess]
    if len(drop) < excess:
        drop += escalated[:excess - len(drop)]
    rolled = _CACHE["rolled"]
    for i in drop:
        v = verdicts.get(meta[i][0]) or {}
        rolled["total"] += 1
        if v.get("escalate"):
            rolled["escalated"] += 1
        else:
            rolled["closed"] += 1
            code = v.get("closure_code")
            if code:
                rolled["codes"][code] = rolled["codes"].get(code, 0) + 1
    gone = set(drop)
    _CACHE["live"] = [x for i, x in enumerate(live) if i not in gone]
    _CACHE["live_meta"] = [x for i, x in enumerate(meta) if i not in gone]
    _reprocess()
    return True


def _add_alerts(items):
    """Add raw ingest items to the live queue and reprocess. An item that no
    connector can read is dropped; one already seen (a SIEM replaying its
    feed) is skipped. Returns the number newly accepted."""
    with _LOCK:
        _load_result()                       # ensure seeded
        fresh, stamp = 0, _now_iso()
        for it in items:
            if not (isinstance(it, dict) and it.get("source") and isinstance(it.get("raw"), dict) and it["raw"]):
                continue
            client = it.get("client") or "Unknown"
            try:
                a = normalize(it["source"], it["raw"], client)
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
            if a.alert_id in _CACHE["seen_ids"]:
                continue
            _CACHE["seen_ids"].add(a.alert_id)
            _CACHE["live"].append({"source": it["source"], "client": client, "raw": it["raw"]})
            _CACHE["live_meta"].append((a.alert_id, a.timestamp))
            feed = _CACHE["feeds"].setdefault((client, a.source), {"client": client, "source": a.source,
                                                                   "count": 0, "first": stamp})
            feed["count"] += 1
            feed["last"] = stamp
            fresh += 1
        if not fresh:
            return 0
        _CACHE["live_count"] = _CACHE.get("live_count", 0) + fresh
        _reprocess()
        _trim()
        return fresh


def _drop_live(keep=lambda item: False):
    """Remove live alerts (all, or those `keep` rejects) and rebuild."""
    with _LOCK:
        _ensure_state()
        pairs = [(x, m) for x, m in zip(_CACHE["live"], _CACHE["live_meta"]) if keep(x)]
        for x, m in zip(_CACHE["live"], _CACHE["live_meta"]):
            if not keep(x):
                _CACHE["seen_ids"].discard(m[0])
        _CACHE["live"] = [x for x, _ in pairs]
        _CACHE["live_meta"] = [m for _, m in pairs]
        if not pairs:
            _CACHE["live_count"] = 0
            _CACHE["rolled"] = {"total": 0, "closed": 0, "escalated": 0, "codes": {}}
            _CACHE["feeds"] = {}
        _reprocess()


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


def _entity_set(alert):
    vals = set()
    for k in ("host", "user", "src_ip", "dst_ip", "entity"):
        v = alert.get(k)
        if v and str(v).strip().lower() not in GENERIC_ENTITIES:
            vals.add(str(v).lower())
    return vals


def _investigation(result, alert):
    """Build the 'what Triagle checked and found' intelligence view for one
    alert: indicator reputation, related alerts on the same client, and the
    correlation reasoning. Pure read over the already-computed result, so it
    never touches the triage pipeline."""
    indicators = reputation.enrich(alert)
    malicious = [r for r in indicators if r["verdict"] == "malicious"]

    focus = _entity_set(alert)
    related = []
    for a in result["alerts"]:
        if a["alert_id"] == alert["alert_id"] or a.get("client") != alert.get("client"):
            continue
        shared = focus & _entity_set(a)
        if shared:
            related.append({"alert": a,
                            "verdict": result["verdicts"].get(a["alert_id"], {}),
                            "shared": sorted(shared)})
    related.sort(key=lambda r: r["alert"].get("timestamp", ""))

    sources_consulted = sorted({s[0] for r in indicators for s in r.get("sources", [])})
    if related:
        linked_by = sorted({s for r in related for s in r["shared"]})
        corr = (f"Linked to {len(related)} other alert(s) on {alert.get('client')} through "
                f"shared {', '.join(linked_by)}. Correlation stays within this client — "
                f"one tenant's data is never used to investigate another's.")
    else:
        corr = "No other alerts on this client share an entity with this one; treated on its own."

    return {
        "indicators": indicators,
        "malicious_count": len(malicious),
        "related": related,
        "sources_consulted": sources_consulted,
        "correlation_note": corr,
    }


def _find_incident(result, ref):
    """By incident reference (INC-xxxxxx), else by the entity it is named
    after or involves. One host can have several incidents over time, so an
    entity resolves to the most recent one."""
    e = ref.lower()
    for i in result["incidents"]:
        if i.get("id", "").lower() == e:
            return i
    newest_first = sorted(result["incidents"], key=lambda i: i.get("last_seen") or "", reverse=True)
    for i in newest_first:
        if i["key"].lower() == e:
            return i
    for i in newest_first:
        if e in (x.lower() for x in i.get("entities", [])):
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
    intel = _investigation(result, alert)
    report_key = next((inc["key"] for inc in result["incidents"] if alert_id in inc["alert_ids"]), None)
    just_decided = any(a.get("status") in ("executed", "approved", "auto_executed", "declined") for a in actions)
    return templates.TemplateResponse(request, "detail.html", _ctx(
        request, user, alert=alert, verdict=verdict, trail=trail, actions=actions, intel=intel,
        report_key=report_key, just_decided=just_decided,
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
    with _LOCK:
        return _decide(request, alert_id, action_id, ack, decision, reason, user)


def _decide(request, alert_id, action_id, ack, decision, reason, user):
    result = _load_result()
    act = next((x for x in result.get("actions", {}).get(alert_id, []) if x["action_id"] == action_id), None)
    if act is None:
        raise HTTPException(status_code=404, detail="No such action on that alert.")
    back = f"/alert/{quote(alert_id, safe=':')}"
    if act["status"] != "pending":
        return RedirectResponse(url=back + "?notice=done", status_code=303)

    def remember():
        _CACHE["decisions"][act["action_id"]] = {k: act.get(k) for k in
                                                 ("status", "decided_by", "decided_at", "result_message")}

    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    common = dict(alert_id=alert_id, action=act["action_type"], target=act["target"],
                  risk_tier=act["risk_tier"], ip=_client_ip(request))
    if decision == "decline":
        act.update(status="declined", decided_by=user["name"], decided_at=stamp,
                   result_message=f"Declined by {user['name']}" + (f": {reason[:200]}" if reason.strip() else "."))
        remember()
        audit.record("action declined", user["name"], reason=reason[:200] or None, **common)
        return RedirectResponse(url=back, status_code=303)

    if act.get("requires_ack") and ack != "on":
        # stays pending: a missed checkbox must not throw the action away
        return RedirectResponse(url=back + "?notice=ack", status_code=303)

    act["status"] = "approved"
    res = execute_action(act, approver=user["name"])
    act.update(status="executed" if res["ok"] else "approved", decided_by=user["name"],
               decided_at=stamp, result_message=res["message"])
    remember()
    audit.record("action approved", user["name"], acknowledged_blast_radius=bool(act.get("requires_ack")),
                 executed=res["ok"], simulated=res.get("mode") != "live", **common)
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

    notes_key = tuple(incident["alert_ids"])
    if notes_key not in _WORKNOTES:
        _WORKNOTES[notes_key] = worknotes.work_notes(incident, members)
    notes_text, notes_by_gemini, notes_provider = _WORKNOTES[notes_key]

    # incident-level intelligence + containment summary
    member_ids = set(incident["alert_ids"])
    seen, indicators = set(), []
    for m in members:
        for r in reputation.enrich(m["alert"]):
            if r["indicator"].lower() not in seen:
                seen.add(r["indicator"].lower())
                indicators.append(r)
    raw_inc_actions = [a for aid, acts in result.get("actions", {}).items()
                       if aid in member_ids for a in acts]
    # one action per (type, target) for the incident ledger — several alerts on
    # the same host each propose isolating it; show the most-progressed one.
    _rank = {"auto_executed": 3, "executed": 3, "approved": 3, "declined": 1, "pending": 0}
    _best = {}
    for a in raw_inc_actions:
        k = (a.get("action_type"), a.get("target"))
        if k not in _best or _rank.get(a.get("status"), 0) > _rank.get(_best[k].get("status"), 0):
            _best[k] = a
    inc_actions = list(_best.values())
    auto_actions = [a for a in inc_actions if a.get("policy") == "auto"]
    pending_actions = [a for a in inc_actions if a.get("status") == "pending"]
    approved_actions = [a for a in inc_actions
                        if a.get("status") in ("executed", "approved")
                        and "auto-policy" not in (a.get("decided_by") or "")]
    declined_actions = [a for a in inc_actions if a.get("status") == "declined"]
    done = len(auto_actions) + len(approved_actions)
    pending = len(pending_actions)
    declined = len(declined_actions)
    bits = []
    if done:
        bits.append(f"{done} contained")
    if declined:
        bits.append(f"{declined} declined by analyst")
    if pending:
        bits.append(f"{pending} awaiting your approval")
    if not inc_actions:
        outcome = "No containment actions required for this incident."
    elif pending:
        outcome = "Partly contained — " + ", ".join(bits) + "."
    else:
        outcome = "Resolved — " + ", ".join(bits) + "."
    intel_summary = {
        "indicators": indicators,
        "malicious_count": sum(1 for r in indicators if r["verdict"] == "malicious"),
        "sources_consulted": sorted({s[0] for r in indicators for s in r.get("sources", [])}),
        "auto_actions": auto_actions,
        "pending_count": len(pending_actions),
        "actions": inc_actions,
        "outcome": outcome,
    }

    return templates.TemplateResponse(request, "report.html", {
        "incident": incident,
        "members": members,
        "client_name": client_name,
        "any_escalated": any_escalated,
        "reportable": certin.is_reportable_candidate(members),
        "work_notes": notes_text,
        "work_notes_by_gemini": notes_by_gemini,
        "work_notes_provider": notes_provider,
        "intel": intel_summary,
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


INGEST_KEY = os.environ.get("TRIAGLE_INGEST_KEY", "")


def _ingest_authorized(request: Request):
    """A SIEM webhook authenticates with the X-Triagle-Key header; a person
    on the console authenticates with their analyst session. Either is fine."""
    key = request.headers.get("x-triagle-key", "")
    if INGEST_KEY and hmac.compare_digest(key, INGEST_KEY):
        return "siem-webhook"
    user = current_user(request)
    if user and (not auth.enabled() or user["role"] == "analyst"):
        return user["name"]
    return None


@app.post("/ingest")
async def ingest(request: Request):
    """Receive one alert, or a list, from a SIEM/EDR webhook or a script.
    Body: a single {source, client, raw} object or a JSON list of them.
    This is how a real SIEM pushes to Triagle; the demo script uses it too."""
    who = _ingest_authorized(request)
    if not who:
        raise HTTPException(status_code=401, detail="Provide a valid X-Triagle-Key header or sign in as an analyst.")
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Body must be JSON.")
    items = body if isinstance(body, list) else [body]
    if len(items) > 50:
        raise HTTPException(status_code=413, detail="Send at most 50 alerts per request.")
    accepted = _add_alerts(items)
    if accepted:
        audit.record("alerts ingested", who, count=accepted, ip=_client_ip(request))
    return {"accepted": accepted, "received": len(items), "queue": len(_CACHE.get("raw", []))}


@app.get("/api/state")
def api_state(request: Request, user=Depends(require_user)):
    """What the console polls to know when to refresh."""
    m = _load_result()["metrics"]
    return {"rev": _CACHE.get("rev", 0), "received": m["received"], "escalated": m["escalated_all"],
            "closed": m["closed_all"], "incidents": m["incident_count"]}


@app.post("/demo/fire")
def demo_fire(request: Request, csrf: str = Form(default=""), benign: str = Form(default="on"),
              user=Depends(require_analyst)):
    """Inject a fresh live attack chain (and one benign alert) so a demo
    audience watches Triagle investigate in real time. Analyst-only."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    from app import demo_attack
    # each fire is ONE clean incident: clear the previous demo attack first so
    # repeated clicks never pile up into a single doubled-up incident. Alerts
    # from a real feed are left alone.
    _drop_live(keep=lambda item: item.get("client") != demo_attack.DEFAULT_CLIENT)
    items = demo_attack.fresh_attack()
    if benign == "on":
        items += demo_attack.fresh_benign()
    accepted = _add_alerts(items)
    audit.record("demo attack fired", user["name"], count=accepted, ip=_client_ip(request))
    # land on the new incident so the judge sees the investigation immediately
    return RedirectResponse(url=f"/report/{quote(demo_attack.HOST, safe='')}", status_code=303)


@app.post("/demo/reset")
def demo_reset(request: Request, csrf: str = Form(default=""), user=Depends(require_analyst)):
    """Drop all live alerts, back to the seed queue. Analyst-only."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    _drop_live()
    audit.record("demo queue reset", user["name"], ip=_client_ip(request))
    return RedirectResponse(url="/", status_code=303)


@app.get("/healthz")
def healthz(request: Request):
    """Public: just enough for an uptime check. Details only when signed in."""
    out = {"ok": True, "version": app.version}
    if current_user(request):
        out.update(backend=backend.BACKEND, mask_pii=backend.MASK_PII,
                   model_calls=backend.STATS["calls"], identifiers_masked=backend.STATS["masked"],
                   sign_in=auth.enabled(), audit_chain_ok=audit.verify()["ok"])
    return out
