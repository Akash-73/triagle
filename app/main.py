"""
Triagle — main application.

An AI SOC analyst + responder for MSPs: ingest alerts from multiple client
tools, triage each with conservative-closure logic, correlate into
incidents (attack chains), and present a decided queue an MSP can act on —
plus a client-ready incident report to forward to the end customer.

Triagle — triage, decided.
"""
import atexit
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
from fastapi.staticfiles import StaticFiles

from app.orchestrator import process_batch
from app.connectors.sources import normalize
from app.engine.response import execute_action, DECISION_KEYS
from app import store
from app.engine import certin, regclock
from app.agent import backend
from app import auth, audit
from app.engine import sources_meta, worknotes, reputation, analyst, genai, usecases
from app.engine.correlate import GENERIC_ENTITIES

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SAMPLE_PATH = os.path.join(BASE_DIR, "samples", "incoming_alerts.json")

app = FastAPI(title="Triagle", version="0.8.0", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
ASSET_V = str(int(os.path.getmtime(os.path.join(BASE_DIR, "static", "triagle.css"))))
templates.env.globals.update(
    source_name=sources_meta.source_name,
    source_full=sources_meta.source_full,
    source_list=sources_meta.source_list,
    verdict_label=sources_meta.verdict_label,
    verdict_words=sources_meta.verdict_words,
    closure_words=sources_meta.closure_words,
)

_IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


def _ist_short(ts):
    """2026-11-22T14:01:12Z -> '22 Nov, 19:31' (IST). Empty if unreadable."""
    try:
        dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(_IST).strftime("%d %b, %H:%M")


def _ago(iso, now=None):
    try:
        then = datetime.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return ""
    secs = int(((now or datetime.datetime.now(datetime.timezone.utc)) - then).total_seconds())
    if secs < 90:
        return f"{max(secs, 0)} s ago"
    if secs < 5400:
        return f"{secs // 60} min ago"
    if secs < 172800:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} d ago"


templates.env.filters["ist_short"] = _ist_short

CLOSURE_WORDS = {
    "BENIGN_EXPECTED": "routine activity", "BENIGN_KNOWN_TOOL": "known admin tools",
    "POSTURE_FINDING": "posture findings", "OPERATIONAL_EVENT": "health events",
    "BENIGN_DUPLICATE": "repeats of an alert already raised", "FP_TUNING": "false positives",
}


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


GUEST_USER = {"name": "guest", "role": "viewer", "guest": True}


def guest_view():
    """TRIAGLE_GUEST=view lets anyone with the address look around without
    signing in. A guest is view-only: reading pages, trying an alert and
    asking about a case. Every change still needs a signed-in analyst."""
    return auth.enabled() and os.environ.get("TRIAGLE_GUEST", "").strip().lower() in ("view", "viewer", "on", "true")


def current_user(request: Request):
    if not auth.enabled():
        return LOCAL_USER
    user = auth.read_session(_session_token(request))
    if user:
        return user
    return dict(GUEST_USER) if guest_view() else None


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


def _model_pill():
    """The one-line model status in the top bar."""
    st = genai.status()
    last = st["last"]
    name = " ".join(w.capitalize() if not w[0].isdigit() else w for w in st["model"].split("-"))
    if not st["configured"]:
        return {"state": "", "label": "No model connected", "title": "Verdicts are decided by rules. Connect Gemini to add explanations."}
    if last.get("ok") is False:
        return {"state": "warn", "label": f"{name} is not answering", "title": last.get("error") or ""}
    if last.get("ok"):
        return {"state": "ok", "label": name, "title": f"Answered in {last.get('seconds')} s through {st['transport']}."}
    return {"state": "", "label": name, "title": f"Set up through {st['transport']}. Not called yet."}


def _nav(result):
    """Counts shown beside the navigation."""
    due = overdue = 0
    for inc in result["incidents"]:
        c = _clock(result, inc)
        if c:
            due += c["open"]
            overdue += c["overdue"]
    m = result["metrics"]
    return {"escalated": m.get("open", m.get("escalated", 0)), "cases": len(result["incidents"]), "due": due,
            "overdue": overdue, "rules": m.get("flagged_rules", 0)}


def _ctx(request: Request, user, **extra):
    """Things every page needs: who is signed in, the form token, the
    navigation counts and the model status."""
    base = {"user": user, "csrf": auth.csrf_token(_session_token(request)),
            "auth_on": auth.enabled(),
            "demo_mode": os.environ.get("TRIAGLE_DEMO", "false").lower() == "true",
            "nav": _nav(_load_result()), "model": _model_pill(), "asset_v": ASSET_V,
            "rev": _CACHE.get("rev", 0),
            "now_ist": datetime.datetime.now(_IST).strftime("%d %b %Y, %H:%M IST")}
    base.update(extra)
    return base


atexit.register(lambda: _flush(force=True))         # a clean stop writes whatever is still unsaved


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    _flush()                                         # writes only if something changed and a save is due
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Cache-Control", "public, max-age=86400" if request.url.path.startswith("/static/")
                            else "no-store")
    if _is_https(request):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    user = current_user(request)
    if user and not user.get("guest"):
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
    resp = RedirectResponse(url="/" if guest_view() else "/login", status_code=303)
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, user=Depends(require_analyst)):
    return templates.TemplateResponse(request, "audit.html", _ctx(
        request, user, active="audit", entries=audit.read(300), chain=audit.verify(), log_path=audit.path()))


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
    _CACHE["tenants"] = regclock.load_tenants()      # client -> sector, from config
    _CACHE["sector_overrides"] = {}                  # client -> sector, set by an analyst
    _CACHE["filings"] = []                           # regulatory reports a person marked as sent
    _CACHE["resolutions"] = {}                       # alert id -> how an analyst closed it
    _CACHE.pop("result", None)
    _restore()


# ---- saved state: the queue and what people decided survive a restart --------

def _snapshot():
    return {"saved_at": _now_iso(), "live": _CACHE["live"], "seen_ids": sorted(_CACHE["seen_ids"]),
            "live_count": _CACHE.get("live_count", 0), "rolled": _CACHE["rolled"],
            "feeds": list(_CACHE["feeds"].values()), "decisions": _CACHE["decisions"],
            "filings": _CACHE["filings"], "sector_overrides": _CACHE["sector_overrides"],
            "resolutions": _CACHE["resolutions"]}


def _restore():
    """Read back what was saved before the last restart. Each alert is read
    again by its connector, so an alert this version can no longer read is
    dropped instead of breaking the queue."""
    state = store.load()
    if not state:
        return False
    live, meta = [], []
    for it in state.get("live") or []:
        try:
            a = normalize(it["source"], it["raw"], it.get("client") or "Unknown")
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        if a.alert_id in _CACHE["seen_ids"]:
            continue                                 # also in the sample set
        live.append({"source": it["source"], "client": it.get("client") or "Unknown", "raw": it["raw"]})
        meta.append((a.alert_id, a.timestamp))
        _CACHE["seen_ids"].add(a.alert_id)
    _CACHE["live"], _CACHE["live_meta"] = live, meta
    _CACHE["seen_ids"].update(str(x) for x in state.get("seen_ids") or [])
    _CACHE["live_count"] = max(int(state.get("live_count") or 0), len(live))
    rolled = state.get("rolled") or {}
    _CACHE["rolled"] = {"total": int(rolled.get("total") or 0), "closed": int(rolled.get("closed") or 0),
                        "escalated": int(rolled.get("escalated") or 0), "codes": dict(rolled.get("codes") or {})}
    _CACHE["feeds"] = {(f.get("client"), f.get("source")): f for f in state.get("feeds") or []
                       if isinstance(f, dict) and f.get("source")}
    _CACHE["decisions"] = {str(k): v for k, v in (state.get("decisions") or {}).items() if isinstance(v, dict)}
    _CACHE["filings"] = [f for f in state.get("filings") or [] if isinstance(f, dict)]
    _CACHE["sector_overrides"] = {str(k): v for k, v in (state.get("sector_overrides") or {}).items()
                                  if v in regclock.SECTORS}
    _CACHE["resolutions"] = {str(k): v for k, v in (state.get("resolutions") or {}).items()
                             if isinstance(v, dict) and v.get("outcome") in RESOLUTIONS}
    _CACHE["restored"] = {"alerts": len(live), "saved_at": state.get("saved_at")}
    return True


def _flush(force=False):
    """Write the state if something changed. The alert queue is written at
    most every few seconds; force=True writes now."""
    if not store.enabled() or not _CACHE.get("dirty") or "seed" not in _CACHE:
        return False
    if not force and time.time() - _CACHE.get("flushed_at", 0.0) < store.interval():
        return False
    with _LOCK:
        ok = store.save(_snapshot())
        _CACHE["flushed_at"] = time.time()           # also after a failure: a broken disk is not retried on every request
        if ok:
            _CACHE["dirty"] = False
        return ok


def _changed(now=False):
    """Something worth keeping changed. now=True for a person's decision."""
    if store.enabled():
        _CACHE["dirty"] = True
        _flush(force=now)


def _remember_decisions(result):
    """Keep what has already happened to each action, and write the audit
    entry the first time an automatic action runs on a live alert."""
    decisions = _CACHE["decisions"]
    live_ids = {aid for aid, _ in _CACHE["live_meta"]}
    for aid, acts in result.get("actions", {}).items():
        for a in acts:
            if a.get("status") == "pending" or a["action_id"] in decisions:
                continue
            decisions[a["action_id"]] = {k: a.get(k) for k in DECISION_KEYS}
            if a.get("status") == "auto_executed" and aid in live_ids:
                audit.record("action auto-executed", "Triagle · auto-policy", alert_id=aid,
                             action=a["action_type"], target=a["target"], risk_tier=a["risk_tier"],
                             executed=True, simulated=True, policy_reason=a.get("policy_reason"))


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
    _apply_resolutions(result)
    _CACHE["result"] = result
    _CACHE["rev"] = _CACHE.get("rev", 0) + 1
    return result


# How an analyst can close an alert Triagle sent to a person.
RESOLUTIONS = {
    "handled": "Real, and dealt with",
    "expected": "Expected activity",
    "false_positive": "False positive",
}


def _apply_resolutions(result):
    """Mark the alerts a person has closed, and count what is still open.
    Triagle's own verdict is kept as it was: the record shows both what
    Triagle said and what the person decided."""
    done = _CACHE.get("resolutions", {})
    still_open = closed_by_person = 0
    for aid, v in result["verdicts"].items():
        v.pop("resolved", None)
        if not v.get("escalate"):
            continue
        if aid in done:
            v["resolved"] = done[aid]
            closed_by_person += 1
        else:
            still_open += 1
    result["metrics"]["open"] = still_open
    result["metrics"]["resolved"] = closed_by_person


def _is_open(verdict):
    return bool(verdict.get("escalate")) and not verdict.get("resolved")


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
        _changed()
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
        _changed(now=True)


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


def _sector(client):
    return regclock.sector_of(client, _CACHE.get("tenants"), _CACHE.get("sector_overrides"))


def _clock(result, incident, members=None):
    """The reporting deadlines for one incident, or None if nothing in it is
    something a person may have to report."""
    members = members if members is not None else _incident_members(result, incident)
    if not certin.is_reportable_candidate(members):
        return None
    return regclock.clocks_for(incident, members, _sector(incident.get("client")),
                               filings=_CACHE.get("filings"))


CLOSED_SHOWN = 40      # closed alerts listed on the console before "show all"
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _source_strip(result):
    """One entry per source tool in the queue: how many alerts, and for a
    live feed when the last one arrived."""
    counts = {}
    for a in result["alerts"]:
        counts[a["source"]] = counts.get(a["source"], 0) + 1
    live = {}
    for f in _CACHE.get("feeds", {}).values():
        cur = live.setdefault(f["source"], {"count": 0, "last": ""})
        cur["count"] += f["count"]
        cur["last"] = max(cur["last"], f.get("last", ""))
    out = []
    for src, n in sorted(counts.items(), key=lambda kv: (kv[0] not in live, -kv[1])):
        out.append({"source": src, "count": n, "live": src in live,
                    "received": live.get(src, {}).get("count", 0),
                    "last": _ago(live[src]["last"]) if src in live else ""})
    return out


def _rows(result, escalated_only=None):
    """Every alert as a table row: the alert, Triagle's verdict, the use case
    it belongs to and the first response action waiting on it."""
    case_of = {aid: inc["id"] for inc in result["incidents"] for aid in inc["alert_ids"]}
    out = []
    for a in result["alerts"]:
        v = result["verdicts"].get(a["alert_id"], {})
        if escalated_only is not None and _is_open(v) != escalated_only:
            continue
        acts = result.get("actions", {}).get(a["alert_id"], [])
        waiting = next((x for x in acts if x.get("status") == "pending"), None)
        out.append({"alert": a, "verdict": v, "uc": usecases.for_alert(a, v), "case": case_of.get(a["alert_id"]),
                    "action": waiting or (acts[0] if acts else None)})
    return out


def _sort_queue(rows):
    """Needs-a-decision first (most severe, then newest), then closed, newest first."""
    rows.sort(key=lambda r: r["alert"].get("timestamp") or "", reverse=True)
    rows.sort(key=lambda r: (0, _SEV_ORDER.get(r["verdict"].get("severity"), 9)) if _is_open(r["verdict"]) else (1, 0))
    return rows


def _cases(result):
    """Incidents as cases: what they are, and the next report due on each."""
    cases = []
    for inc in result["incidents"]:
        members = _incident_members(result, inc)
        clock = _clock(result, inc, members)
        worst = min((_SEV_ORDER.get(m["verdict"].get("severity"), 9) for m in members if m["verdict"].get("escalate")),
                    default=9)
        cases.append({"inc": inc, "uc": usecases.for_case(members), "clock": clock,
                      "probing": certin.probing_only(members),
                      "severity": {v: k for k, v in _SEV_ORDER.items()}.get(worst, "low"),
                      "pending": sum(1 for aid in inc["alert_ids"] for x in result.get("actions", {}).get(aid, [])
                                     if x.get("status") == "pending")})
    cases.sort(key=lambda c: (0 if c["clock"] and c["clock"]["next"] else 1,
                              c["clock"]["next"]["seconds_left"] if c["clock"] and c["clock"]["next"] else 0,
                              _SEV_ORDER.get(c["severity"], 9), -c["inc"]["size"]))
    return cases


def _open_deadlines(cases):
    """Every report still owed, soonest first."""
    rows = []
    for c in cases:
        for r in (c["clock"] or {}).get("rows", []):
            if r["status"] in ("running", "overdue"):
                rows.append({"row": r, "inc": c["inc"]})
    rows.sort(key=lambda d: d["row"]["seconds_left"] if d["row"]["seconds_left"] is not None else 0)
    return rows


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user=Depends(require_user)):
    """Overview: the shift handover. What came in, what was closed and why,
    what needs a person, and which reports are due."""
    result = _load_result()
    need = _sort_queue(_rows(result, escalated_only=True))
    cases = _cases(result)
    dues = _open_deadlines(cases)
    m = result["metrics"]
    codes = sorted(m.get("closed_by_code", {}).items(), key=lambda kv: -kv[1])
    total = max(1, m.get("closed_all", 0) + m.get("escalated", 0))
    breakdown = [{"n": n, "what": CLOSURE_WORDS.get(code, code.lower().replace("_", " ")),
                  "pct": round(100 * n / total, 2)} for code, n in codes]
    if m.get("resolved"):
        breakdown.append({"n": m["resolved"], "what": "closed by a person", "pct": round(100 * m["resolved"] / total, 2)})
    return templates.TemplateResponse(request, "dashboard.html", _ctx(
        request, user, active="overview", need=need[:NEED_SHOWN], need_total=len(need), metrics=m, cases=cases,
        dues=dues, breakdown=breakdown, escalated_pct=round(100 * m.get("open", 0) / total, 2),
        sources=_source_strip(result), overdue=sum(1 for d in dues if d["row"]["status"] == "overdue")))


NEED_SHOWN = 12        # alerts needing a decision listed on the overview


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, show: str = "open", closed: str = "", q: str = "", user=Depends(require_user)):
    """The whole queue: what needs a decision, and what was closed and why."""
    result = _load_result()
    show = show if show in ("open", "closed", "all") else "open"
    rows = _sort_queue(_rows(result, escalated_only={"open": True, "closed": False, "all": None}[show]))
    needle = " ".join(q.lower().split())[:80]
    if needle:
        rows = [r for r in rows if needle in " ".join(str(x) for x in (
            r["alert"].get("title"), r["alert"].get("entity"), r["alert"].get("host"), r["alert"].get("user"),
            r["alert"].get("client"), r["alert"].get("src_ip"), r["uc"]["name"], r["uc"]["technique"],
            r["verdict"].get("closure_code"))).lower()]
    total = len(rows)
    limit = None if (closed == "all" or show == "open") else CLOSED_SHOWN + sum(1 for r in rows if _is_open(r["verdict"]))
    m = result["metrics"]
    return templates.TemplateResponse(request, "alerts.html", _ctx(
        request, user, active="alerts", rows=rows[:limit] if limit else rows, hidden=max(0, total - limit) if limit else 0,
        total=total, show=show, q=needle, metrics=m,
        counts={"open": m.get("open", 0), "closed": len(result["alerts"]) - m.get("open", 0),
                "all": len(result["alerts"])}))


@app.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request, user=Depends(require_user)):
    """Related alerts grouped into one case each."""
    result = _load_result()
    return templates.TemplateResponse(request, "cases.html", _ctx(
        request, user, active="cases", cases=_cases(result)))


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
    report_key = next((inc["id"] for inc in result["incidents"] if alert_id in inc["alert_ids"]), None)
    just_decided = any(a.get("status") in ("executed", "approved", "auto_executed", "declined") for a in actions)
    return templates.TemplateResponse(request, "detail.html", _ctx(
        request, user, active="alerts", alert=alert, verdict=verdict, trail=trail, actions=actions, intel=intel,
        uc=usecases.for_alert(alert, verdict), steps=_step_words(trail), ask_suggested=analyst.SUGGESTED,
        report_key=report_key, just_decided=just_decided, resolutions=RESOLUTIONS,
        notice=NOTICES.get(notice, ""), can_approve=user["role"] == "analyst",
        now=datetime.datetime.now().strftime("%d %b %Y, %H:%M")))


STEP_WORDS = {
    "related_alerts": "Looked for other alerts on the same asset, account and addresses",
    "entity_history": "Compared this with what is normal for the asset",
    "threat_intel": "Checked every address, hash and domain against threat intelligence",
    "timeline": "Put the events in order",
    "burst": "Grouped alerts that are one event",
}


def _step_words(trail):
    return [{"did": STEP_WORDS.get(st.get("tool"), str(st.get("tool", "")).replace("_", " ").capitalize()),
             "found": st.get("result_summary", "")} for st in trail or []]


CONTEXT_MINUTES = 45      # closed alerts this close to a case are shown as context
CONTEXT_SHOWN = 15


def _case_context(result, incident, members):
    """Closed alerts on the same asset around the time of the case: the
    discovery commands and routine events that were not evidence on their
    own. Shown in the timeline so the analyst sees the whole sequence."""
    from app.engine.relate import parse_ts
    times = [t for t in (parse_ts(m["alert"].get("timestamp")) for m in members) if t]
    if not times:
        return []
    lo = min(times) - CONTEXT_MINUTES * 60        # parse_ts gives seconds
    hi = max(times) + CONTEXT_MINUTES * 60
    ids = set(incident["alert_ids"])
    assets = {str(incident.get("key") or "").lower()} | {str(m["alert"].get("host") or "").lower() for m in members}
    assets.discard("")
    out = []
    for a in result["alerts"]:
        if a["alert_id"] in ids or a.get("client") != incident.get("client"):
            continue
        if str(a.get("host") or a.get("entity") or "").lower() not in assets:
            continue
        v = result["verdicts"].get(a["alert_id"], {})
        if v.get("escalate") or signals_kind(a) != "activity":
            continue
        t = parse_ts(a.get("timestamp"))
        if t and lo <= t <= hi:
            out.append({"alert": a, "verdict": v, "uc": usecases.for_alert(a, v), "context": True})
    out.sort(key=lambda r: r["alert"].get("timestamp") or "")
    return out[-CONTEXT_SHOWN:]


def signals_kind(alert):
    from app.engine import signals
    return signals.kind(alert)


def _case_actions(result, incident):
    """One action per (type, target): several alerts on one host each propose
    isolating it; show the one that has progressed furthest."""
    rank = {"auto_executed": 3, "executed": 3, "approved": 3, "declined": 1, "pending": 0}
    best = {}
    for aid in incident["alert_ids"]:
        for a in result.get("actions", {}).get(aid, []):
            k = (a.get("action_type"), a.get("target"))
            if k not in best or rank.get(a.get("status"), 0) > rank.get(best[k].get("status"), 0):
                best[k] = a
    return sorted(best.values(), key=lambda a: (a.get("status") != "pending", a.get("label", "")))


def _case_stages(incident, members, actions, clock, probing):
    """Detected, investigated, contained, reported: where the case stands."""
    pending = sum(1 for a in actions if a["status"] == "pending")
    done = sum(1 for a in actions if a["status"] in ("executed", "approved", "auto_executed"))
    declined = sum(1 for a in actions if a["status"] == "declined")
    escalated = sum(1 for m in members if m["verdict"].get("escalate"))
    stages = [
        {"name": "Detected", "state": "done",
         "note": f"{incident['size']} alerts from {len(incident.get('sources', []))} tool(s)",
         "when": _ist_short(incident.get("first_seen"))},
        {"name": "Investigated", "state": "done",
         "note": f"{escalated} judged to need a person", "when": "by Triagle, in seconds"},
    ]
    if not actions:
        stages.append({"name": "Contained", "state": "none", "note": "No response action proposed", "when": ""})
    elif pending:
        stages.append({"name": "Contained", "state": "current",
                       "note": f"{pending} action{'s' if pending != 1 else ''} waiting for approval",
                       "when": f"{done} done" if done else ""})
    else:
        stages.append({"name": "Contained", "state": "done",
                       "note": f"{done} done" + (f", {declined} declined" if declined else ""), "when": ""})
    if clock is None:
        stages.append({"name": "Reported", "state": "none",
                       "note": "Probing only, no report due" if probing else "No report due", "when": ""})
    elif clock["open"]:
        nxt = clock["next"]
        stages.append({"name": "Reported", "state": "current",
                       "note": f"{clock['open']} report{'s' if clock['open'] != 1 else ''} due, {nxt['name']} first",
                       "when": "", "due_iso": nxt["due_iso"], "hours": nxt["hours"]})
    else:
        stages.append({"name": "Reported", "state": "done" if clock["filed"] else "none",
                       "note": f"{clock['filed']} marked filed" if clock["filed"] else "Nothing binding today", "when": ""})
    return stages


@app.get("/case/{ref}", response_class=HTMLResponse)
def case_page(request: Request, ref: str, notice: str = "", user=Depends(require_user)):
    """One case, worked the way an analyst works it: what it is, what
    happened in order, what Triagle checked, what to do, what to report."""
    result = _load_result()
    incident = _find_incident(result, ref)
    if not incident:
        raise HTTPException(status_code=404, detail=f"No case found for {ref}")
    members = _incident_members(result, incident)
    for m in members:
        m["uc"] = usecases.for_alert(m["alert"], m["verdict"])
    clock = _clock(result, incident, members)
    actions = _case_actions(result, incident)
    probing = certin.probing_only(members)
    steps, seen = [], set()
    for m in members:
        for st in _step_words(result.get("trails", {}).get(m["alert"]["alert_id"], [])):
            if st["found"] not in seen:
                seen.add(st["found"])
                steps.append(st)
    indicators, seen_ind = [], set()
    for m in members:
        for r in reputation.enrich(m["alert"]):
            if r["indicator"].lower() not in seen_ind:
                seen_ind.add(r["indicator"].lower())
                indicators.append(r)
    timeline = sorted(members + _case_context(result, incident, members),
                      key=lambda r: r["alert"].get("timestamp") or "")
    worst = min((_SEV_ORDER.get(m["verdict"].get("severity"), 9) for m in members if m["verdict"].get("escalate")),
                default=3)
    return templates.TemplateResponse(request, "case.html", _ctx(
        request, user, active="cases", incident=incident, members=members, timeline=timeline,
        uc=usecases.for_case(members), severity={v: k for k, v in _SEV_ORDER.items()}.get(worst, "low"),
        clock=clock, actions=actions, steps=steps[:10], indicators=indicators, probing=probing,
        stages=_case_stages(incident, members, actions, clock, probing),
        sector=regclock.SECTORS[_sector(incident.get("client"))]["label"],
        ask_suggested=analyst.SUGGESTED, notice=NOTICES.get(notice, ""),
        can_approve=user["role"] == "analyst", poll=False))


NOTES_RETRY_SECONDS = 60


@app.get("/api/notes")
def api_notes(request: Request, case: str = "", user=Depends(require_user)):
    """The written account of a case. Gemini writes it from the evidence; if
    the model does not answer, a summary built from the same evidence is
    returned and labelled as that. Cached per case."""
    result = _load_result()
    incident = _find_incident(result, case)
    if not incident:
        raise HTTPException(status_code=404, detail="No such case.")
    members = _incident_members(result, incident)
    key = tuple(incident["alert_ids"])
    cached = _WORKNOTES.get(key)
    stale = cached and not cached[1] and time.time() - _NOTES_AT.get(key, 0) > NOTES_RETRY_SECONDS
    if not cached or stale:
        if not _ask_allowed(_client_ip(request), trusted=_trusted(user)) and cached:
            pass                                    # keep the fallback rather than hammer a failing model
        else:
            _WORKNOTES[key] = worknotes.work_notes(incident, members)
            _NOTES_AT[key] = time.time()
    text, by_model, provider = _WORKNOTES[key]
    return {"text": text, "by_model": by_model, "provider": provider,
            "error": None if by_model else genai.STATUS.get("error")}


_NOTES_AT = {}


NOTICES = {
    "ack": "Not approved: tick the box to confirm you have read the blast radius, then approve again.",
    "done": "That action has already been decided.",
    "signin": ("Not run. This action changes a real firewall, and sign-in is turned off on this deployment, "
               "so the approval would have no name on it. Turn sign-in on, then approve again."),
    "failed": "Not done. Nothing was changed. The reason is shown on the action below.",
    "lifted": "The block was lifted. The action is open again and can be approved a second time.",
    "closed": "Triagle closed this alert itself, so there is nothing for a person to decide on it.",
    "notlifted": "The block was not lifted. The reason is shown on the action below.",
}


@app.post("/action/approve")
def decide_action(request: Request, alert_id: str = Form(...), action_id: str = Form(...),
                  ack: str = Form(default=""), decision: str = Form(default="approve"),
                  reason: str = Form(default=""), csrf: str = Form(default=""),
                  next: str = Form(default=""), user=Depends(require_analyst)):
    """A signed-in analyst approves or declines a staged action. An approved
    action then runs: for a connected tool that is a real change, for any
    other it is a rehearsal that shows the exact call. Every decision is
    written to the audit log with the analyst's name."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    if decision not in ("approve", "decline"):
        raise HTTPException(status_code=400, detail="Unknown decision.")
    with _LOCK:
        return _decide(request, alert_id, action_id, ack, decision, reason, user, next)


def _back_to(next_path, default):
    """Only ever back to a case or an alert page on this site."""
    n = str(next_path or "")
    if (n.startswith("/case/") or n.startswith("/alert/")) and "//" not in n and "\\" not in n and len(n) < 200:
        return n.split("?")[0]
    return default


def _find_action(alert_id, action_id):
    result = _load_result()
    act = next((x for x in result.get("actions", {}).get(alert_id, []) if x["action_id"] == action_id), None)
    if act is None:
        raise HTTPException(status_code=404, detail="No such action on that alert.")
    return act


def _remember(act):
    _CACHE["decisions"][act["action_id"]] = {k: act.get(k) for k in DECISION_KEYS}
    _changed(now=True)


def _decide(request, alert_id, action_id, ack, decision, reason, user, next_path=""):
    act = _find_action(alert_id, action_id)
    back = _back_to(next_path, f"/alert/{quote(alert_id, safe=':')}")
    if act["status"] != "pending":
        return RedirectResponse(url=back + "?notice=done", status_code=303)

    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    common = dict(alert_id=alert_id, action=act["action_type"], target=act["target"],
                  risk_tier=act["risk_tier"], ip=_client_ip(request))
    if decision == "decline":
        act.update(status="declined", decided_by=user["name"], decided_at=stamp, error="",
                   result_message=f"Declined by {user['name']}" + (f": {reason[:200]}" if reason.strip() else "."))
        _remember(act)
        audit.record("action declined", user["name"], reason=reason[:200] or None, **common)
        return RedirectResponse(url=back, status_code=303)

    if act.get("requires_ack") and ack != "on":
        # stays pending: a missed checkbox must not throw the action away
        return RedirectResponse(url=back + "?notice=ack", status_code=303)

    real = bool(act.get("real"))
    if real and not auth.enabled():
        # a change to a real system needs a named, signed-in person behind it
        audit.record("real action refused: sign-in is off", user["name"], **common)
        return RedirectResponse(url=back + "?notice=signin", status_code=303)

    act["status"] = "approved"
    res = execute_action(act, approver=user["name"], live=real, approver_ip=_client_ip(request))
    if real and not res["ok"]:
        # Nothing changed. Leave it open with the reason, so it can be put
        # right and approved again.
        act.update(status="pending", decided_by=None, decided_at=None, error=res["message"])
        _remember(act)
        audit.record("real action failed", user["name"], executed=False, simulated=False, mode="live",
                     error=res["message"][:300], **common)
        return RedirectResponse(url=back + "?notice=failed", status_code=303)
    act.update(status="executed" if res["ok"] else "approved", decided_by=user["name"],
               decided_at=stamp, result_message=res["message"], undo=res.get("undo"), error="")
    _remember(act)
    audit.record("action approved", user["name"], acknowledged_blast_radius=bool(act.get("requires_ack")),
                 executed=res["ok"], simulated=res.get("mode") in ("dry_run", "not_connected"), mode=res.get("mode"),
                 rule=(res.get("undo") or {}).get("rule"), **common)
    return RedirectResponse(url=back, status_code=303)


@app.post("/alert/resolve")
def resolve_alert(request: Request, alert_id: str = Form(...), outcome: str = Form(...), note: str = Form(default=""),
                  csrf: str = Form(default=""), user=Depends(require_analyst)):
    """An analyst closes an alert Triagle sent to a person, or opens it again.
    The outcome, the name and the note go on the alert and in the audit log."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    if outcome not in RESOLUTIONS and outcome != "reopen":
        raise HTTPException(status_code=400, detail="Unknown outcome.")
    back = f"/alert/{quote(alert_id, safe=':')}"
    with _LOCK:
        result = _load_result()
        v = result["verdicts"].get(alert_id)
        if v is None:
            raise HTTPException(status_code=404, detail="No such alert.")
        if not v.get("escalate"):
            return RedirectResponse(url=back + "?notice=closed", status_code=303)
        done = _CACHE["resolutions"]
        if outcome == "reopen":
            if done.pop(alert_id, None):
                audit.record("alert reopened", user["name"], alert_id=alert_id, ip=_client_ip(request))
        else:
            words = " ".join(note.split())[:300]
            done[alert_id] = {"outcome": outcome, "label": RESOLUTIONS[outcome], "note": words, "by": user["name"],
                              "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
            audit.record("alert closed by analyst", user["name"], alert_id=alert_id, outcome=outcome,
                         note=words or None, triagle_verdict=v.get("disposition"), ip=_client_ip(request))
        _apply_resolutions(result)
        _CACHE["rev"] = _CACHE.get("rev", 0) + 1
        _changed(now=True)
    return RedirectResponse(url=back, status_code=303)


@app.post("/action/lift")
def lift_action(request: Request, alert_id: str = Form(...), action_id: str = Form(...),
                csrf: str = Form(default=""), next: str = Form(default=""), user=Depends(require_analyst)):
    """Reverse a real change: delete the firewall rule a block added. The
    action goes back to waiting, so it can be approved again."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    from app.engine import gcp_firewall
    with _LOCK:
        act = _find_action(alert_id, action_id)
        back = _back_to(next, f"/alert/{quote(alert_id, safe=':')}")
        undo = act.get("undo") or {}
        if act["status"] != "executed" or undo.get("connector") != "gcp_firewall":
            return RedirectResponse(url=back + "?notice=done", status_code=303)
        if not auth.enabled():
            return RedirectResponse(url=back + "?notice=signin", status_code=303)
        res = gcp_firewall.lift(undo.get("rule"), approver=user["name"])
        common = dict(alert_id=alert_id, action=act["action_type"], target=act["target"],
                      rule=undo.get("rule"), ip=_client_ip(request))
        if not res["ok"]:
            act["error"] = res["message"]
            _remember(act)
            audit.record("block lift failed", user["name"], error=res["message"][:300], **common)
            return RedirectResponse(url=back + "?notice=notlifted", status_code=303)
        act.update(status="pending", decided_by=None, decided_at=None, undo=None, error="",
                   result_message=res["message"])
        _remember(act)
        audit.record("block lifted", user["name"], **common)
        return RedirectResponse(url=back + "?notice=lifted", status_code=303)


@app.get("/tuning", response_class=HTMLResponse)
def tuning_page(request: Request, user=Depends(require_user)):
    result = _load_result()
    return templates.TemplateResponse(request, "tuning.html", _ctx(
        request, user, active="tuning", rule_health=result.get("rule_health", []), metrics=result["metrics"],
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
        "clock": _clock(result, incident, members),
        "work_notes": notes_text,
        "work_notes_by_gemini": notes_by_gemini,
        "work_notes_provider": notes_provider,
        "intel": intel_summary,
        "now": datetime.datetime.now().strftime("%d %b %Y, %H:%M"),
    })


def _notice(request, entity, reg_key):
    """Draft incident report for one regulator, with that regulator's clock.
    A draft for a person to check and send; nothing is filed from here."""
    from app.orchestrator import _load_env
    reg = regclock.regulator(reg_key)
    if not reg:
        raise HTTPException(status_code=404, detail="No such regulator.")
    result = _load_result()
    incident = _find_incident(result, entity)
    if not incident:
        raise HTTPException(status_code=404, detail=f"No incident found for {entity}")
    members = _incident_members(result, incident)
    clock = _clock(result, incident, members)
    if clock is None:
        raise HTTPException(status_code=404, detail="Nothing in this incident was escalated; no report draft.")
    draft = certin.build_draft(incident, members, result.get("actions", {}),
                               threat_intel=_load_env().get("threat_intel"))
    mine = [r for r in clock["rows"] if r["regulator"] == reg_key]
    others = [r for r in clock["rows"] if r["regulator"] != reg_key]
    return templates.TemplateResponse(request, "certin.html", {
        "d": draft, "metrics": result["metrics"], "reg": dict(reg, key=reg_key),
        "rows": mine, "others": others, "clock": clock, "incident": incident,
    })


@app.get("/certin/{entity}", response_class=HTMLResponse)
def certin_draft(request: Request, entity: str, user=Depends(require_user)):
    """Draft CERT-In incident report for an incident, with the 6-hour clock."""
    return _notice(request, entity, "certin")


@app.get("/notice/{entity}/{regulator}", response_class=HTMLResponse)
def notice_draft(request: Request, entity: str, regulator: str, user=Depends(require_user)):
    """The same draft, addressed to another regulator on the incident's clock."""
    return _notice(request, entity, regulator)


# ---- the regulatory clock ------------------------------------------------------

@app.get("/clock", response_class=HTMLResponse)
def clock_page(request: Request, notice: str = "", user=Depends(require_user)):
    """Every incident with a reporting deadline, most urgent first."""
    result = _load_result()
    cards, watching = [], []
    for inc in result["incidents"]:
        members = _incident_members(result, inc)
        attack = [m for m in members if m["verdict"].get("escalate")
                  and m["verdict"].get("disposition") in ("true_positive", "suspicious")]
        if not attack:
            continue
        # the alert that best says what this incident is
        lead = max(attack, key=lambda m: (m["verdict"].get("disposition") == "true_positive",
                                          -_SEV_ORDER.get(m["verdict"].get("severity"), 9),
                                          m["verdict"].get("confidence", 0)))["alert"]
        clock = _clock(result, inc, members)
        if clock is None:
            sources = sorted({m["alert"]["src_ip"] for m in attack if m["alert"].get("src_ip")})
            watching.append({"incident": inc, "headline": lead["title"], "sources": sources,
                             "attempts": len(attack)})
            continue
        cards.append({"incident": inc, "clock": clock,
                      "escalated": sum(1 for m in members if m["verdict"].get("escalate")),
                      "headline": lead["title"]})

    def urgency(card):
        nxt = card["clock"]["next"]
        if nxt is None:
            return (2, 0)
        return (0, nxt["seconds_left"]) if nxt["status"] == "running" else (1, -nxt["seconds_left"])
    cards.sort(key=urgency)
    running = [(r, c) for c in cards for r in c["clock"]["rows"] if r["status"] == "running"]
    late = [(r, c) for c in cards for r in c["clock"]["rows"] if r["status"] == "overdue"]
    pick = (min(running, key=lambda rc: rc[0]["seconds_left"]) if running
            else max(late, key=lambda rc: rc[0]["seconds_left"]) if late else None)
    summary = {
        "incidents": len(cards),
        "open": sum(c["clock"]["open"] for c in cards),
        "overdue": sum(c["clock"]["overdue"] for c in cards),
        "filed": sum(c["clock"]["filed"] for c in cards),
        "next": pick[0] if pick else None, "next_client": pick[1]["incident"]["client"] if pick else None,
    }
    clients = sorted({a["client"] for a in result["alerts"]})
    return templates.TemplateResponse(request, "clock.html", _ctx(
        request, user, active="clock", cards=cards, watching=watching, summary=summary, regulators=regclock.REGULATORS,
        sectors=regclock.SECTORS, tenants=[{"client": c, "sector": _sector(c)} for c in clients],
        can_file=user["role"] == "analyst", metrics=result["metrics"], rev=_CACHE.get("rev", 0),
        notice=CLOCK_NOTICES.get(notice, ""),
        now=datetime.datetime.now(_IST).strftime("%d %b %Y, %H:%M IST")))


CLOCK_NOTICES = {
    "confirm": "Not recorded: tick the box to confirm a person sent the report, then mark it filed again.",
    "done": "That report was already marked as filed.",
}


@app.post("/clock/file")
def clock_file(request: Request, incident: str = Form(...), regulator: str = Form(...),
               deadline: str = Form(...), reference: str = Form(default=""), confirm: str = Form(default=""),
               csrf: str = Form(default=""), user=Depends(require_analyst)):
    """An analyst records that a person sent a report. Triagle does not send
    it. This stops that clock and goes in the audit log."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    with _LOCK:
        result = _load_result()
        inc = _find_incident(result, incident)
        clock = _clock(result, inc) if inc else None
        row = next((r for r in (clock or {}).get("rows", [])
                    if r["regulator"] == regulator and r["deadline"] == deadline), None)
        if row is None:
            raise HTTPException(status_code=404, detail="No such reporting deadline on that incident.")
        back = f"/clock?notice={{}}#{inc['id']}"
        if row["status"] == "filed":
            return RedirectResponse(url=back.format("done"), status_code=303)
        if confirm != "on":
            return RedirectResponse(url=back.format("confirm"), status_code=303)
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        ref = " ".join(reference.split())[:80] or None
        _CACHE["filings"].append({"alert_ids": list(inc["alert_ids"]), "regulator": regulator,
                                  "deadline": deadline, "by": user["name"], "at": stamp, "reference": ref,
                                  "incident": inc["id"], "client": inc["client"]})
        audit.record("regulatory report marked filed", user["name"], incident=inc["id"], client=inc["client"],
                     regulator=row["name"], report=row["label"], due=row["due_iso"],
                     minutes_before_deadline=(row["seconds_left"] // 60 if row["seconds_left"] is not None else None),
                     binding=row["binding"], reference=ref, ip=_client_ip(request))
        _CACHE["rev"] = _CACHE.get("rev", 0) + 1
        _changed(now=True)
    return RedirectResponse(url=f"/clock#{inc['id']}", status_code=303)


@app.post("/tenant/sector")
def tenant_sector(request: Request, client: str = Form(...), sector: str = Form(...),
                  csrf: str = Form(default=""), user=Depends(require_analyst)):
    """Set which sector a client is in, which decides the regulators it reports to."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    if sector not in regclock.SECTORS:
        raise HTTPException(status_code=400, detail="Unknown sector.")
    with _LOCK:
        result = _load_result()
        if client not in {a["client"] for a in result["alerts"]}:
            raise HTTPException(status_code=404, detail="No such client in the queue.")
        previous = _sector(client)
        if previous != sector:
            _CACHE["sector_overrides"][client] = sector
            audit.record("client sector changed", user["name"], client=client, sector=sector,
                         previous=previous, ip=_client_ip(request))
            _CACHE["rev"] = _CACHE.get("rev", 0) + 1
            _changed(now=True)
    return RedirectResponse(url="/clock", status_code=303)


@app.get("/benchmark", response_class=HTMLResponse)
def benchmark_page(request: Request, user=Depends(require_user)):
    """Runs the labelled simulated set in eval/ through the same engine."""
    from eval.run_benchmark import run
    rows, summary, elapsed, _ = run()
    return templates.TemplateResponse(request, "benchmark.html", _ctx(
        request, user, active="benchmark", rows=rows, summary=summary, ms=round(elapsed * 1000),
        backend=backend.BACKEND, poll=False))


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
    out = {"accepted": accepted, "received": len(items), "queue": len(_CACHE.get("raw", []))}
    if request.query_params.get("verdicts") in ("1", "true", "yes"):
        out["verdicts"] = _verdicts_for(items, _base_url(request))
    return out


def _verdicts_for(items, base_url):
    """Triagle's verdict for each alert in a batch, for a tool that wants to
    show it next to its own alert (the Wazuh forwarder writes these back so
    they appear in the Wazuh dashboard). It is the verdict now: a later alert
    can still raise an earlier one."""
    from app.engine import signals
    result = _load_result()
    by_id = {a["alert_id"]: a for a in result["alerts"]}
    case_of = {aid: inc["id"] for inc in result["incidents"] for aid in inc["alert_ids"]}
    out = []
    for it in items:
        if not (isinstance(it, dict) and it.get("source") and isinstance(it.get("raw"), dict)):
            continue
        try:
            a = normalize(it["source"], it["raw"], it.get("client") or "Unknown")
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        alert, v = by_id.get(a.alert_id), result["verdicts"].get(a.alert_id)
        if not alert or not v:
            continue                         # aged out of the queue already
        uc = usecases.for_alert(alert, v)
        out.append({
            "id": str(it["raw"].get("id") or a.alert_id), "alert_id": a.alert_id,
            "verdict": "escalated" if v.get("escalate") else "closed",
            "disposition": v.get("disposition"), "closure_code": v.get("closure_code") or "",
            "closure": sources_meta.closure_words(v.get("closure_code")) if not v.get("escalate")
            else sources_meta.verdict_words(v.get("disposition")),
            "severity": v.get("severity"), "confidence": v.get("confidence"),
            "use_case": uc["name"], "use_case_id": uc["id"], "technique": uc["technique"] or "",
            "kind": signals.kind(alert), "reason": v.get("summary") or "",
            "case": case_of.get(a.alert_id, ""),
            "url": f"{base_url}/alert/{quote(a.alert_id, safe=':')}",
        })
    return out


@app.get("/api/state")
def api_state(request: Request, user=Depends(require_user)):
    """What the console polls to know when to refresh."""
    m = _load_result()["metrics"]
    return {"rev": _CACHE.get("rev", 0), "received": m["received"], "escalated": m["escalated_all"],
            "closed": m["closed_all"], "incidents": m["incident_count"]}


# ---- connectors: set up a source, test the model, try an alert -----------------

TRY_MAX_BYTES = 32_000


def _base_url(request: Request):
    scheme = "https" if _is_https(request) else request.url.scheme
    return f"{scheme}://{request.headers.get('host', request.url.netloc)}"


@app.get("/connectors", response_class=HTMLResponse)
def connectors_page(request: Request, user=Depends(require_user)):
    """Everything Triagle is connected to: alert sources, the model, and the
    tools that carry out an approved action."""
    from app.connectors import examples
    from app.engine import gcp_firewall
    result = _load_result()
    counts = {}
    for a in result["alerts"]:
        counts[a["source"]] = counts.get(a["source"], 0) + 1
    live = {}
    for f in _CACHE.get("feeds", {}).values():
        cur = live.setdefault(f["source"], {"count": 0, "last": "", "clients": set()})
        cur["count"] += f["count"]
        cur["last"] = max(cur["last"], f.get("last", ""))
        cur["clients"].add(f["client"])
    base = _base_url(request)
    sources = []
    for c in examples.CATALOGUE:
        feed = live.get(c["key"])
        sources.append({**c, "live": bool(feed), "received": feed["count"] if feed else 0,
                        "last": _ago(feed["last"]) if feed else "", "in_queue": counts.get(c["key"], 0),
                        "clients": sorted(feed["clients"]) if feed else [],
                        "steps": examples.setup_steps(c["key"], base),
                        "examples": examples.EXAMPLES.get(c["key"], [])})
    # the key is shown only to a signed-in analyst: with sign-in off, anyone
    # holding the address could read it and inject alerts
    show_key = auth.enabled() and user["role"] == "analyst" and bool(INGEST_KEY)
    return templates.TemplateResponse(request, "connectors.html", _ctx(
        request, user, active="connectors", sources=sources, base_url=base,
        ingest_key=INGEST_KEY if show_key else "", key_set=bool(INGEST_KEY),
        model_status=genai.status(), firewall=gcp_firewall.summary(), auth_on=auth.enabled(),
        saved=store.status(), restored=_CACHE.get("restored"),
        examples=examples.EXAMPLES, can_test=user["role"] == "analyst", poll=False))


@app.post("/api/try")
async def api_try(request: Request, user=Depends(require_user)):
    """Triage one pasted alert and return what Triagle would do with it.
    Nothing is stored and nothing joins the queue: the alert is judged on its
    own, the way the first alert from a new customer would be."""
    body = await _json_body(request)
    if auth.enabled() and not auth.csrf_ok(_session_token(request), str(body.get("csrf", ""))):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    if not _ask_allowed(_client_ip(request), trusted=_trusted(user)):
        raise HTTPException(status_code=429, detail="Too many tries. Wait a minute.")
    source = str(body.get("source", ""))
    raw = body.get("raw")
    if isinstance(raw, str):
        if len(raw) > TRY_MAX_BYTES:
            raise HTTPException(status_code=413, detail="That alert is too large. Paste one alert, under 32 KB.")
        try:
            raw = json.loads(raw)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"That is not valid JSON: {str(e)[:120]}")
    if not isinstance(raw, dict) or not raw:
        raise HTTPException(status_code=400, detail="Paste one alert as a JSON object.")
    if len(json.dumps(raw)) > TRY_MAX_BYTES:
        raise HTTPException(status_code=413, detail="That alert is too large. Paste one alert, under 32 KB.")
    # an envelope {source, client, raw} pasted whole is accepted too
    if isinstance(raw.get("raw"), dict) and raw.get("source"):
        source, raw = str(raw["source"]), raw["raw"]
    client = " ".join(str(body.get("client") or "Trial").split())[:60] or "Trial"
    try:
        normalize(source, raw, client)
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise HTTPException(status_code=400, detail=f"Triagle could not read that as a {sources_meta.source_name(source)} alert: {str(e)[:160]}")
    started = time.perf_counter()
    result = process_batch([{"source": source, "client": client, "raw": raw}])
    took_ms = round((time.perf_counter() - started) * 1000, 1)
    alert = result["alerts"][0]
    verdict = result["verdicts"][alert["alert_id"]]
    uc = usecases.for_alert(alert, verdict)
    acts = result.get("actions", {}).get(alert["alert_id"], [])
    audit.record("alert tried on the connectors page", user["name"], source=source,
                 escalated=bool(verdict.get("escalate")), ip=_client_ip(request))
    return {
        "alert": {"title": alert["title"], "asset": alert.get("host") or alert.get("entity"), "user": alert.get("user"),
                  "tool_severity": alert.get("raw_severity"), "source": sources_meta.source_name(source)},
        "verdict": {"escalate": bool(verdict.get("escalate")), "words": sources_meta.verdict_words(verdict.get("disposition"))
                    if verdict.get("escalate") else sources_meta.closure_words(verdict.get("closure_code")),
                    "severity": verdict.get("severity"), "confidence": verdict.get("confidence"),
                    "summary": verdict.get("summary"), "reasoning": verdict.get("reasoning"),
                    "closure_code": verdict.get("closure_code"), "next": verdict.get("recommended_actions") or [],
                    "tuning": verdict.get("tuning_recommendation")},
        "usecase": {"id": uc["id"], "name": uc["name"], "technique": uc["technique"], "tactic": uc["tactic"],
                    "question": uc["question"], "catalogued": uc["catalogued"]},
        "actions": [{"label": a["label"], "target": a["target"],
                     "needs": "a person's approval" if a.get("policy") != "auto" else "nothing, it runs automatically"}
                    for a in acts],
        "ms": took_ms,
    }


# ---- the model: status, a connection test, and questions about a case --------

_ASK_TIMES = {}          # client address -> recent question times
ASK_PER_MINUTE = 6       # per address, for a visitor
ASK_PER_MINUTE_ANALYST = 40
ASK_PER_HOUR_TOTAL = 240  # all visitors together, so an open console cannot run up a bill
_ASK_ALL = []


def _trusted(user):
    """A signed-in analyst. Their calls are not held to the visitors' budget,
    so a stranger using up that budget cannot stop an analyst working."""
    return bool(auth.enabled() and user and user.get("role") == "analyst" and not user.get("guest"))


def _ask_allowed(ip, now=None, trusted=False):
    now = now or time.time()
    key = ("analyst:" + ip) if trusted else ip
    mine = [t for t in _ASK_TIMES.get(key, []) if now - t < 60]
    _ASK_ALL[:] = [t for t in _ASK_ALL if now - t < 3600]
    over = len(mine) >= (ASK_PER_MINUTE_ANALYST if trusted else ASK_PER_MINUTE)
    if over or (not trusted and len(_ASK_ALL) >= ASK_PER_HOUR_TOTAL):
        _ASK_TIMES[key] = mine
        return False
    mine.append(now)
    _ASK_TIMES[key] = mine
    if not trusted:
        _ASK_ALL.append(now)
    return True


def _case_for(result, ref):
    """(case, members, steps, actions, clock) for an incident reference, an
    entity, or a single alert id. None if nothing matches."""
    incident = _find_incident(result, ref)
    if incident:
        members = _incident_members(result, incident)
        ids = set(incident["alert_ids"])
        steps = []
        for m in members:
            for st in result.get("trails", {}).get(m["alert"]["alert_id"], []):
                line = f"{st.get('tool')}: {st.get('result_summary')}"
                if line not in steps:
                    steps.append(line)
        actions = [a for aid, acts in result.get("actions", {}).items() if aid in ids for a in acts]
        return incident, members, steps, actions, _clock(result, incident, members)
    alert = next((a for a in result["alerts"] if a["alert_id"] == ref), None)
    if not alert:
        return None
    case = {"id": alert["alert_id"], "key": alert.get("host") or alert.get("entity"), "client": alert.get("client")}
    members = [{"alert": alert, "verdict": result["verdicts"].get(ref, {})}]
    steps = [f"{st.get('tool')}: {st.get('result_summary')}" for st in result.get("trails", {}).get(ref, [])]
    return case, members, steps, result.get("actions", {}).get(ref, []), None


@app.get("/api/model")
def api_model(request: Request, user=Depends(require_user)):
    """Is the model connected, and if not, why."""
    return genai.status()


@app.post("/api/model/test")
async def api_model_test(request: Request, user=Depends(require_analyst)):
    body = await _json_body(request)
    if auth.enabled() and not auth.csrf_ok(_session_token(request), str(body.get("csrf", ""))):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    if not _ask_allowed(_client_ip(request), trusted=_trusted(user)):
        raise HTTPException(status_code=429, detail="Too many requests. Wait a minute.")
    st = genai.test_connection()
    audit.record("model connection tested", user["name"], ok=bool(st["last"].get("ok")),
                 model=st.get("model"), ip=_client_ip(request))
    return st


async def _analyst_call(request, user):
    """Shared checks for the small JSON calls an analyst makes from a page."""
    body = await _json_body(request)
    if auth.enabled() and not auth.csrf_ok(_session_token(request), str(body.get("csrf", ""))):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    if not _ask_allowed(_client_ip(request), trusted=_trusted(user)):
        raise HTTPException(status_code=429, detail="Too many requests. Wait a minute.")
    return body


@app.post("/api/firewall/check")
async def api_firewall_check(request: Request, user=Depends(require_analyst)):
    """Can Triagle change the connected firewall, and which blocks are in
    force? Reads only; changes nothing."""
    from app.engine import gcp_firewall
    await _analyst_call(request, user)
    if not auth.enabled():
        raise HTTPException(status_code=403, detail="Sign-in is off on this deployment, so the firewall is not shown.")
    res = gcp_firewall.check()
    audit.record("firewall connection checked", user["name"], ok=res["ok"], ip=_client_ip(request))
    return res


@app.post("/api/firewall/lift")
async def api_firewall_lift(request: Request, user=Depends(require_analyst)):
    """Lift one block from the Connectors page: delete a rule Triagle added.
    Works after a restart too, when the action that added it is no longer in
    memory."""
    from app.engine import gcp_firewall
    body = await _analyst_call(request, user)
    if not auth.enabled():
        raise HTTPException(status_code=403, detail="Sign-in is off on this deployment, so nothing was changed.")
    rule = str(body.get("rule", ""))[:80]
    res = gcp_firewall.lift(rule, approver=user["name"])
    audit.record("block lifted" if res["ok"] else "block lift failed", user["name"], rule=rule,
                 ip=_client_ip(request), error=None if res["ok"] else res["message"][:300])
    if res["ok"]:
        with _LOCK:
            # any action that added this rule is open again
            for rec in _CACHE.get("decisions", {}).values():
                if (rec.get("undo") or {}).get("rule") == rule:
                    rec.update(status="pending", decided_by=None, decided_at=None, undo=None, error="",
                               result_message=res["message"])
            _CACHE.pop("result", None)
            _changed(now=True)
    return res


@app.post("/api/ask")
async def api_ask(request: Request, user=Depends(require_user)):
    """One question about one case, answered by the model from that case's
    evidence. The answer is prose; it changes nothing."""
    body = await _json_body(request)
    if auth.enabled() and not auth.csrf_ok(_session_token(request), str(body.get("csrf", ""))):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    question = str(body.get("question", ""))[:analyst.MAX_QUESTION]
    found = _case_for(_load_result(), str(body.get("case", "")))
    if not found:
        raise HTTPException(status_code=404, detail="No such case.")
    if not _ask_allowed(_client_ip(request), trusted=_trusted(user)):
        raise HTTPException(status_code=429, detail="Too many questions. Wait a minute and ask again.")
    case, members, steps, actions, clock = found
    out = analyst.ask(question, case, members, steps, actions, clock)
    audit.record("question asked about a case", user["name"], case=case.get("id") or case.get("key"),
                 answered=out["by_model"], ip=_client_ip(request))
    return out


async def _json_body(request: Request):
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Send a JSON object.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Send a JSON object.")
    return body


@app.post("/demo/fire")
def demo_fire(request: Request, csrf: str = Form(default=""), benign: str = Form(default="on"),
              scenario: str = Form(default=""), user=Depends(require_analyst)):
    """Inject a fresh live attack chain (and one benign alert) so a demo
    audience watches Triagle investigate in real time. Analyst-only."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    from app import demo_attack
    scenario = scenario if scenario in demo_attack.SCENARIOS else demo_attack.DEFAULT
    # each fire is ONE clean incident: clear the previous demo attack first so
    # repeated clicks never pile up into a single doubled-up incident. Alerts
    # from a real feed are left alone.
    _drop_live(keep=lambda item: item.get("client") not in demo_attack.CLIENTS)
    items = demo_attack.fresh_attack(scenario=scenario)
    if benign == "on":
        items += demo_attack.fresh_benign(scenario=scenario)
    accepted = _add_alerts(items)
    audit.record("demo attack fired", user["name"], count=accepted, scenario=scenario, ip=_client_ip(request))
    # land on the new incident so the judge sees the investigation immediately
    return RedirectResponse(url=f"/report/{quote(demo_attack.SCENARIOS[scenario]['host'], safe='')}", status_code=303)


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
    user = current_user(request)
    if user and not user.get("guest"):
        out.update(saved_state=store.status(), backend=backend.BACKEND, mask_pii=backend.MASK_PII,
                   model_calls=backend.STATS["calls"], identifiers_masked=backend.STATS["masked"],
                   sign_in=auth.enabled(), audit_chain_ok=audit.verify()["ok"])
    return out
