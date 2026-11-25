"""
Triagle — main application.

An AI SOC analyst + responder for MSPs: ingest alerts from multiple client
tools, triage each with conservative-closure logic, correlate into
incidents (attack chains), and present a decided queue an MSP can act on —
plus a client-ready incident report to forward to the end customer.

Triagle — triage, decided.
"""
import atexit
import contextvars
import os
import json
import time
import datetime
import hmac
import re
import secrets
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
from app import auth, audit, sso
from app.engine import sources_meta, worknotes, reputation, analyst, genai, usecases, siem_link, tuning
from app.engine import instructions, spotcheck, nightshift
from app.engine.correlate import GENERIC_ENTITIES

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SAMPLE_PATH = os.path.join(BASE_DIR, "samples", "incoming_alerts.json")

app = FastAPI(title="Triagle", version="0.9.0", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
def _asset_version():
    """Changes whenever a stylesheet does, so a browser never keeps an old one."""
    static = os.path.join(BASE_DIR, "static")
    return str(int(max(os.path.getmtime(os.path.join(static, f)) for f in os.listdir(static) if f.endswith(".css"))))


ASSET_V = _asset_version()
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

# Each page carries a random value that its own <script> tags repeat. The
# browser runs only scripts that carry it, so script text that reaches a page
# some other way does not run.
_NONCE = contextvars.ContextVar("csp_nonce", default="")
templates.env.globals["csp_nonce"] = lambda: _NONCE.get()

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


def _forwarded_hops():
    """How many proxies of our own stand in front of the app. Each one adds the
    address it saw to the end of X-Forwarded-For. Cloud Run's front end is one;
    a load balancer in front of that makes two (TRIAGLE_FORWARDED_HOPS)."""
    try:
        return max(0, int(os.environ.get("TRIAGLE_FORWARDED_HOPS", "1" if os.environ.get("K_SERVICE") else "0")))
    except ValueError:
        return 0


def _client_ip(request: Request):
    """The address of whoever is calling. X-Forwarded-For starts with whatever
    the caller chose to send, so only the entries our own proxies added, at the
    end, are believed. With no proxy of ours in front, the header is ignored."""
    peer = (request.client.host if request.client else "") or "-"
    hops = _forwarded_hops()
    if not hops:
        return peer
    parts = [x.strip() for x in request.headers.get("x-forwarded-for", "").split(",") if x.strip()]
    return parts[-hops] if len(parts) >= hops else peer


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
            "overdue": overdue, "rules": m.get("flagged_rules", 0),
            "taught": sum(1 for r in _CACHE.get("taught", []) if instructions.state(r) == "on")}


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
    nonce = secrets.token_urlsafe(16)
    _NONCE.set(nonce)
    resp = await call_next(request)
    _flush()                                         # writes only if something changed and a save is due
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    # Everything the pages load is served from here. A script runs only if it
    # carries this response's nonce, so script text written into a page by
    # anyone else does not run, and neither does an inline handler. Styles are
    # still written in the templates. Nothing may be loaded from another site,
    # framed, or posted to another site.
    resp.headers.setdefault("Content-Security-Policy",
                            f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
                            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
    resp.headers.setdefault("Cache-Control", "public, max-age=86400" if request.url.path.startswith("/static/")
                            else "no-store")
    if _is_https(request):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


SSO_ERRORS = {
    "sso": "Single sign-on did not finish. Try again.",
    "list": "That account is not on this console's list. Ask an analyst to add it.",
}


def _login_ctx(next_path, error=None):
    return {"next": auth.safe_next(next_path), "error": error, "sso_on": sso.configured(), "sso_name": sso.name(),
            "password_on": auth.password_login(), "code_on": auth.any_second_factor()}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/", error: str = ""):
    user = current_user(request)
    if user and not user.get("guest"):
        return RedirectResponse(url=auth.safe_next(next), status_code=303)
    return templates.TemplateResponse(request, "login.html", _login_ctx(next, SSO_ERRORS.get(error)))


@app.post("/login")
def login_submit(request: Request, username: str = Form(default=""), password: str = Form(default=""),
                 code: str = Form(default=""), next: str = Form(default="/")):
    ip = _client_ip(request)
    user, reason = auth.check_login(username, password, ip, code=code)
    if not user:
        audit.record("sign-in failed", (username or "-")[:64], ip=ip, reason=reason)
        msg = ("Too many failed attempts. Try again in a few minutes." if reason == "locked"
               else "Wrong username, password or code." if auth.any_second_factor()
               else "Wrong username or password.")
        return templates.TemplateResponse(request, "login.html", _login_ctx(next, msg),
                                          status_code=429 if reason == "locked" else 401)
    audit.record("signed in", user["name"], ip=ip, role=user["role"],
                 second_factor=True if auth.needs_code(user["name"]) else None)
    resp = RedirectResponse(url=auth.safe_next(next), status_code=303)
    resp.set_cookie(auth.COOKIE, auth.make_session(user), httponly=True, samesite="lax",
                    secure=_is_https(request), max_age=auth._state["session_seconds"], path="/")
    return resp


@app.get("/auth/start")
def sso_start(request: Request, next: str = "/"):
    """Send the browser to the identity provider to sign in."""
    if not sso.configured():
        raise HTTPException(status_code=404, detail="Single sign-on is not set up on this console.")
    back = sso.public_url(_base_url(request)) + "/auth/callback"
    url, cookie = sso.begin(back, auth.safe_next(next))
    if not url:
        return RedirectResponse(url="/login?error=sso", status_code=303)
    resp = RedirectResponse(url=url, status_code=303)
    resp.set_cookie(sso.COOKIE, cookie, httponly=True, samesite="lax", secure=_is_https(request),
                    max_age=sso.START_SECONDS, path="/auth")
    return resp


@app.get("/auth/callback")
def sso_callback(request: Request, code: str = "", state: str = ""):
    """The identity provider sends the browser back here. The address it
    proved is let in only if it is on this console's list."""
    if not sso.configured():
        raise HTTPException(status_code=404, detail="Single sign-on is not set up on this console.")
    ip = _client_ip(request)
    email, nxt, reason = sso.finish(code, state, request.cookies.get(sso.COOKIE, ""))
    user = auth.sso_user(email) if email else None
    if not user:
        audit.record("sign-in failed", (email or "-")[:120], ip=ip, method="single sign-on",
                     reason=reason if not email else "not on the list")
        resp = RedirectResponse(url="/login?error=" + ("list" if email else "sso"), status_code=303)
    else:
        audit.record("signed in", user["name"], ip=ip, role=user["role"], method="single sign-on")
        resp = RedirectResponse(url=auth.safe_next(nxt), status_code=303)
        resp.set_cookie(auth.COOKIE, auth.make_session(user), httponly=True, samesite="lax",
                        secure=_is_https(request), max_age=auth._state["session_seconds"], path="/")
    resp.delete_cookie(sso.COOKIE, path="/auth")
    return resp


@app.post("/logout")
def logout(request: Request, csrf: str = Form(default="")):
    user = current_user(request)
    if user and auth.enabled() and auth.csrf_ok(_session_token(request), csrf):
        audit.record("signed out", user["name"], ip=_client_ip(request))
    resp = RedirectResponse(url="/" if guest_view() else "/login", status_code=303)
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@app.get("/security", response_class=HTMLResponse)
def trust_page(request: Request):
    """Open to anyone: what Triagle holds, who can reach it and what is not
    done yet. It says nothing about this deployment's own settings."""
    return templates.TemplateResponse(request, "trust.html", {
        "asset_v": ASSET_V, "contact": os.environ.get("TRIAGLE_CONTACT", "").strip()[:120],
        "customer_keys": bool(INGEST_KEYS), "unprivileged": os.geteuid() != 0, "platform_log": audit._to_stdout(),
        "as_of": datetime.datetime.now(_IST).strftime("%d %B %Y").lstrip("0")})


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
    _CACHE["taught"] = []                            # rules analysts have taught Triagle
    _CACHE["checks"] = {}                            # alert id -> a person's check of that closure
    _CACHE["second"] = {}                            # alert id -> the model's second reading of that closure
    _CACHE.pop("result", None)
    _restore()


# ---- saved state: the queue and what people decided survive a restart --------

def _snapshot():
    return {"saved_at": _now_iso(), "live": _CACHE["live"], "seen_ids": sorted(_CACHE["seen_ids"]),
            "live_count": _CACHE.get("live_count", 0), "rolled": _CACHE["rolled"],
            "feeds": list(_CACHE["feeds"].values()), "decisions": _CACHE["decisions"],
            "filings": _CACHE["filings"], "sector_overrides": _CACHE["sector_overrides"],
            "resolutions": _CACHE["resolutions"], "outbox": _CACHE.get("outbox"),
            "arrived_at": _CACHE.get("arrived_at", {}),
            "taught": _CACHE.get("taught", []), "checks": _CACHE.get("checks", {}),
            "second": _CACHE.get("second", {}),
            "model_use": {k: genai.USAGE[k] for k in ("calls", "input", "output", "thinking", "since")}}


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
    box = state.get("outbox")
    if isinstance(box, dict) and box.get("epoch") and isinstance(box.get("events"), list):
        _CACHE["outbox"] = {"epoch": str(box["epoch"]), "seq": int(box.get("seq") or 0),
                            "events": [e for e in box["events"] if isinstance(e, dict) and e.get("seq")]}
    kept = {m[0] for m in meta}
    _CACHE["arrived_at"] = {str(k): str(v) for k, v in (state.get("arrived_at") or {}).items() if str(k) in kept}
    _CACHE["taught"] = [r for r in state.get("taught") or []
                        if isinstance(r, dict) and r.get("id") and r.get("outcome") in instructions.OUTCOMES]
    _CACHE["checks"] = {str(k): v for k, v in (state.get("checks") or {}).items()
                        if isinstance(v, dict) and isinstance(v.get("ok"), bool)}
    _CACHE["second"] = {str(k): v for k, v in (state.get("second") or {}).items()
                        if isinstance(v, dict) and v.get("view") in ("agree", "look")}
    genai.load_usage(state.get("model_use"))
    _CACHE["model_calls_saved"] = genai.USAGE["calls"]
    _CACHE["restored"] = {"alerts": len(live), "saved_at": state.get("saved_at")}
    return True


def _flush(force=False):
    """Write the state if something changed. The alert queue is written at
    most every few seconds; force=True writes now."""
    if store.enabled() and "seed" in _CACHE and genai.USAGE["calls"] != _CACHE.get("model_calls_saved", 0):
        _CACHE["dirty"] = True                       # the model was used since the last save
    if not store.enabled() or not _CACHE.get("dirty") or "seed" not in _CACHE:
        return False
    if not force and time.time() - _CACHE.get("flushed_at", 0.0) < store.interval():
        return False
    with _LOCK:
        ok = store.save(_snapshot())
        _CACHE["flushed_at"] = time.time()           # also after a failure: a broken disk is not retried on every request
        if ok:
            _CACHE["dirty"] = False
            _CACHE["model_calls_saved"] = genai.USAGE["calls"]
        return ok


def _changed(now=False):
    """Something worth keeping changed. now=True for a person's decision."""
    if store.enabled():
        _CACHE["dirty"] = True
        _flush(force=now)


# ---- what people did, for the tool the alert came from -----------------------
#
# Triagle's verdict goes back to the SIEM when the alert arrives. What a person
# does afterwards (approves a block, lifts it, closes the alert, files a
# report) happens later, so it is queued here and the tool collects it: the
# Wazuh forwarder asks every few seconds and Wazuh then shows "Triagle: admin
# blocked 2.57.121.25 at the firewall" beside its own alert. Nothing is pushed
# from here, so this works for a SIEM that Triagle cannot reach.

OUTBOX_KEEP = 500        # the most recent events held for collection
OUTBOX_PAGE = 100        # events handed over per request


def _outbox():
    box = _CACHE.get("outbox")
    if not (isinstance(box, dict) and box.get("epoch")):
        # the epoch changes if the queue is ever lost, so a collector knows to start again
        box = _CACHE["outbox"] = {"epoch": secrets.token_hex(6), "seq": 0, "events": []}
    return box


def _tell(request, event, by, alert_id="", client="", **fields):
    """Queue one thing a person did. Every value is kept as a short string."""
    result = _CACHE.get("result") or {}
    alert = next((a for a in result.get("alerts", []) if a["alert_id"] == alert_id), None) if alert_id else None
    verdict = (result.get("verdicts") or {}).get(alert_id) or {}
    base = _base_url(request)
    box = _outbox()
    box["seq"] += 1
    entry = {
        "seq": box["seq"], "at": _now_iso(), "event": event, "by": str(by or ""),
        "client": str(client or (alert or {}).get("client") or ""),
        "alert_id": str(alert_id or ""), "source": str((alert or {}).get("source") or ""),
        "source_alert_id": str(((alert or {}).get("raw") or {}).get("id") or ""),
        "agent": str((alert or {}).get("host") or (alert or {}).get("entity") or ""),
        "use_case": usecases.for_alert(alert, verdict)["name"] if alert else "",
        "url": f"{base}/alert/{quote(alert_id, safe=':')}" if alert_id else base,
    }
    for k, v in fields.items():
        if v not in (None, ""):
            entry[k] = " ".join(str(v).split())[:400]
    box["events"].append(entry)
    del box["events"][:-OUTBOX_KEEP]
    return entry


@app.get("/api/outbox")
def api_outbox(request: Request, client: str = "", after: int = 0, epoch: str = ""):
    """What people have done since `after`, for one customer's tool to show.
    Same key as /ingest. `cursor` is what to pass as `after` next time; if
    `epoch` is not the one this reply carries, the queue started again and
    the caller should too."""
    if not _ingest_authorized(request):
        raise HTTPException(status_code=401, detail="Provide a valid X-Triagle-Key header or sign in as an analyst.")
    client = _key_customer(request) or client        # a customer's key reads that customer's record only
    with _LOCK:
        _ensure_state()
        box = _outbox()
        if epoch != box["epoch"]:
            after = 0
        mine = [e for e in box["events"] if e["seq"] > after and (not client or e.get("client") == client)]
        page = mine[:OUTBOX_PAGE]
        return {"epoch": box["epoch"], "events": page,
                "cursor": page[-1]["seq"] if len(mine) > len(page) else box["seq"]}


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
    result = process_batch(raw, decided=_CACHE["decisions"], taught=_CACHE.get("taught"),
                           overruled={aid: c for aid, c in _CACHE.get("checks", {}).items() if c.get("ok") is False})
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
    m["closed_pct_all"] = (100 * m["closed_all"]) // m["received"] if m["received"] else 0      # never rounded up
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
    # A decision is about the event, not the row it was made on. If an earlier
    # alert of the same burst arrives late, that alert becomes the one the
    # burst is raised on and the decided one is counted under it. The decision
    # moves with the event, so it is not asked for twice.
    for aid in list(done):
        v = result["verdicts"].get(aid) or {}
        head = v.get("duplicate_of") if not v.get("escalate") else None
        if head and (result["verdicts"].get(head) or {}).get("escalate"):
            done.setdefault(head, done[aid])
            del done[aid]
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
    # What a person decided changes what there is to say about the rule
    # behind the alert, so the rules are looked at again with it.
    result["rule_health"] = tuning.analyze_rules(result["alerts"], result["verdicts"])
    result["metrics"]["flagged_rules"] = sum(1 for r in result["rule_health"] if r["flagged"])


def _is_open(verdict):
    return bool(verdict.get("escalate")) and not verdict.get("resolved")


def _not_needed(verdict):
    """A person closed this alert as expected activity or as a false positive,
    so a response still waiting on it has nothing left to respond to."""
    return ((verdict or {}).get("resolved") or {}).get("outcome") in ("expected", "false_positive")


def _waiting(result, alert_ids):
    """Response actions still waiting for approval on these alerts, leaving
    out those on an alert a person has closed as harmless."""
    return sum(1 for aid in alert_ids if not _not_needed(result["verdicts"].get(aid))
               for x in result.get("actions", {}).get(aid, []) if x.get("status") == "pending")


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
    still = {x[0] for x in _CACHE["live_meta"]}
    _CACHE["arrived_at"] = {k: v for k, v in _CACHE.get("arrived_at", {}).items() if k in still}
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
            _CACHE.setdefault("arrived_at", {})[a.alert_id] = stamp
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
        removed_from = set()
        for x, m in zip(_CACHE["live"], _CACHE["live_meta"]):
            if not keep(x):
                _CACHE["seen_ids"].discard(m[0])
                removed_from.add(x.get("client"))
        _CACHE["live"] = [x for x, _ in pairs]
        _CACHE["live_meta"] = [m for _, m in pairs]
        still = {m[0] for _, m in pairs}
        _CACHE["arrived_at"] = {k: v for k, v in _CACHE.get("arrived_at", {}).items() if k in still}
        # a customer whose alerts were all removed is no longer sending
        emptied = removed_from - {x.get("client") for x in _CACHE["live"]}
        _CACHE["feeds"] = {k: f for k, f in _CACHE["feeds"].items() if f.get("client") not in emptied}
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


def _test_clients():
    """Customers that only exist in the built-in test streams."""
    from app import demo_attack
    return demo_attack.CLIENTS


def _real_feeds():
    """Feeds from connected tools. A test stream is not a connected tool."""
    return [f for f in _CACHE.get("feeds", {}).values() if f.get("client") not in _test_clients()]


def _source_strip(result):
    """One entry per source tool in the queue: how many alerts, and for a
    live feed when the last one arrived."""
    counts = {}
    for a in result["alerts"]:
        counts[a["source"]] = counts.get(a["source"], 0) + 1
    live = {}
    for f in _real_feeds():
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
                      "pending": _waiting(result, inc["alert_ids"])})
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
        sources=_source_strip(result), overdue=sum(1 for d in dues if d["row"]["status"] == "overdue"),
        spot=spotcheck.tally(_CACHE.get("checks", {}), _test_clients())))


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
        siem=_siem_link(alert, user),
        uc=usecases.for_alert(alert, verdict), steps=_step_words(trail), ask_suggested=analyst.SUGGESTED,
        report_key=report_key, just_decided=just_decided, resolutions=RESOLUTIONS,
        teachable=instructions.teachable(alert, verdict), teach_days=instructions.DAYS,
        check=_CACHE.get("checks", {}).get(alert_id), second=_CACHE.get("second", {}).get(alert_id),
        not_needed=_not_needed(verdict),
        model_on=genai.configured(),
        checkable=spotcheck.eligible(alert, verdict, _test_clients()),
        notice=NOTICES.get(notice, ""), can_approve=user["role"] == "analyst",
        now=datetime.datetime.now().strftime("%d %b %Y, %H:%M")))


def _siem_link(alert, user):
    """Where to open this alert in the tool it came from. Not for a sample
    alert, which was never in anyone's SIEM, and not for a guest: where a
    customer's SIEM lives is not for everyone who has this console's address."""
    if user.get("guest") or not siem_link.enabled():
        return None
    arrived = {m[0] for m in _CACHE.get("live_meta", [])}
    return siem_link.for_alert(alert) if alert["alert_id"] in arrived else None


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
    # one writer per case: a second request for the same case waits for the
    # first one's answer instead of asking the model the same thing again
    with _notes_lock(key):
        cached = _WORKNOTES.get(key)
        stale = cached and not cached[1] and time.time() - _NOTES_AT.get(key, 0) > NOTES_RETRY_SECONDS
        if not cached or stale:
            if not _ask_allowed(_client_ip(request), trusted=_trusted(user)) and cached:
                pass                                # keep the fallback rather than hammer a failing model
            else:
                _WORKNOTES[key] = worknotes.work_notes(incident, members,
                                                       house=_house(result, incident.get("client")))
                _NOTES_AT[key] = time.time()
        text, by_model, provider = _WORKNOTES[key]
    return {"text": text, "by_model": by_model, "provider": provider,
            "error": None if by_model else genai.STATUS.get("error")}


_NOTES_AT = {}
_NOTES_LOCKS = {}


def _notes_lock(key):
    with _LOCK:
        if len(_NOTES_LOCKS) > 500:
            _NOTES_LOCKS.clear()
        return _NOTES_LOCKS.setdefault(key, threading.Lock())


NOTICES = {
    "ack": "Not approved: tick the box to confirm you have read the blast radius, then approve again.",
    "done": "That action has already been decided.",
    "signin": ("Not run. This action changes a real firewall, and sign-in is turned off on this deployment, "
               "so the approval would have no name on it. Turn sign-in on, then approve again."),
    "failed": "Not done. Nothing was changed. The reason is shown on the action below.",
    "lifted": "The block was lifted. The action is open again and can be approved a second time.",
    "closed": "Triagle closed this alert itself, so there is nothing for a person to decide on it.",
    "notlifted": "The block was not lifted. The reason is shown on the action below.",
    "sentback": "You disagreed with Triagle's closure, so this alert is back in the queue. Decide what it was below.",
    "taught": "Closed, and Triagle will close the same alert on this machine from now on. See Your rules.",
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
        _tell(request, "declined", user["name"], alert_id, action=act["label"], target=act["target"],
              note=reason[:200])
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
    if real and res.get("undo"):
        _tell(request, "blocked", user["name"], alert_id, action=act["label"], target=act["target"],
              rule=res["undo"].get("rule"), result=res["message"], note=reason[:200])
    else:
        # recorded as approved; say plainly whether anything was sent
        sent = {"manual": "a step a person carries out", "live": "sent"}.get(res.get("mode"), "rehearsal, nothing was sent")
        _tell(request, "approved", user["name"], alert_id, action=act["label"], target=act["target"],
              sent=sent, note=reason[:200])
    _remember(act)
    audit.record("action approved", user["name"], acknowledged_blast_radius=bool(act.get("requires_ack")),
                 executed=res["ok"], simulated=res.get("mode") in ("dry_run", "not_connected"), mode=res.get("mode"),
                 rule=(res.get("undo") or {}).get("rule"), **common)
    return RedirectResponse(url=back, status_code=303)


@app.post("/alert/resolve")
def resolve_alert(request: Request, alert_id: str = Form(...), outcome: str = Form(...), note: str = Form(default=""),
                  teach: str = Form(default=""), scope: str = Form(default="machine"), days: str = Form(default=""),
                  csrf: str = Form(default=""), user=Depends(require_analyst)):
    """An analyst closes an alert Triagle sent to a person, or opens it again.
    The outcome, the name and the note go on the alert and in the audit log."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    if outcome not in RESOLUTIONS and outcome != "reopen":
        raise HTTPException(status_code=400, detail="Unknown outcome.")
    back = f"/alert/{quote(alert_id, safe=':')}"
    taught_now = False
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
                _tell(request, "reopened", user["name"], alert_id)
                audit.record("alert reopened", user["name"], alert_id=alert_id, ip=_client_ip(request))
        else:
            words = " ".join(note.split())[:300]
            done[alert_id] = {"outcome": outcome, "label": RESOLUTIONS[outcome], "note": words, "by": user["name"],
                              "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
            _tell(request, "closed_by_analyst", user["name"], alert_id, outcome=RESOLUTIONS[outcome], note=words)
            audit.record("alert closed by analyst", user["name"], alert_id=alert_id, outcome=outcome,
                         note=words or None, triagle_verdict=v.get("disposition"), ip=_client_ip(request))
            alert = next((a for a in result["alerts"] if a["alert_id"] == alert_id), None)
            if teach and outcome in instructions.OUTCOMES and alert and instructions.teachable(alert, v):
                # "close the same thing from now on": the decision becomes a rule this customer owns
                rule = instructions.make(alert, outcome, RESOLUTIONS[outcome], words, user["name"],
                                         scope="account" if scope == "account" else "machine",
                                         days=int(days) if days.isdigit() else instructions.DEFAULT_DAYS)
                _CACHE["taught"].append(rule)
                audit.record("rule taught", user["name"], rule=rule["id"], alert_id=alert_id, outcome=outcome,
                             title=rule["title"], where=instructions.where(rule), until=rule["until"],
                             note=words or None, ip=_client_ip(request))
                _CACHE.pop("result", None)           # it may already cover alerts that arrived since
                result = _load_result()
                taught_now = True
        _apply_resolutions(result)
        _CACHE["rev"] = _CACHE.get("rev", 0) + 1
        _changed(now=True)
    return RedirectResponse(url=back + ("?notice=taught" if taught_now else ""), status_code=303)


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
        _tell(request, "block_lifted", user["name"], alert_id, action=act["label"], target=act["target"],
              rule=undo.get("rule"), result=res["message"])
        _remember(act)
        audit.record("block lifted", user["name"], **common)
        return RedirectResponse(url=back + "?notice=lifted", status_code=303)


@app.get("/tuning", response_class=HTMLResponse)
def tuning_page(request: Request, user=Depends(require_user)):
    result = _load_result()
    return templates.TemplateResponse(request, "tuning.html", _ctx(
        request, user, active="tuning", rule_health=result.get("rule_health", []), metrics=result["metrics"],
        now=datetime.datetime.now().strftime("%d %b %Y, %H:%M")))


def _ist_long(ts):
    """'25 Nov 2026, 21:24 IST' for a stored time, or the text itself."""
    from app.engine.relate import parse_ts
    t = parse_ts(ts)
    if t is None:
        return str(ts or "an unknown time")
    return datetime.datetime.fromtimestamp(t, _IST).strftime("%d %b %Y, %H:%M IST").lstrip("0")


def _house(result, client):
    """What this customer's own analysts have decided before, as text for the
    model: the rules they taught, the alerts they closed themselves, and the
    closures they disagreed with. This is how the model learns from the
    engine and from the customer's people: in context, on every call."""
    by_id = {a["alert_id"]: a for a in result["alerts"]}
    decided = []
    done = sorted(_CACHE.get("resolutions", {}).items(), key=lambda kv: kv[1].get("at") or "", reverse=True)
    for aid, r in done:
        a = by_id.get(aid)
        if a and a.get("client") == client:
            decided.append({"title": a.get("title"), "host": a.get("host") or a.get("entity"),
                            "label": r.get("label"), "note": r.get("note"), "by": r.get("by")})
    for c in _CACHE.get("checks", {}).values():
        if c.get("client") == client and c.get("ok") is False:
            decided.append({"title": c.get("title"), "host": c.get("host"), "by": c.get("by"), "note": "",
                            "label": "should not have been closed without a person"})
    return nightshift.house_knowledge(client, _CACHE.get("taught", []), decided[:8])


# ---- rules a person taught Triagle -------------------------------------------

def _taught_rows(result):
    used = result.get("taught_used", {})
    rows = []
    for r in reversed(_CACHE.get("taught", [])):
        hit = used.get(r["id"], {})
        rows.append({"rule": r, "state": instructions.state(r), "where": instructions.where(r),
                     "count": hit.get("count", 0), "last": hit.get("last", "")})
    rows.sort(key=lambda x: {"on": 0, "ended": 1, "off": 2}[x["state"]])
    return rows


@app.get("/taught", response_class=HTMLResponse)
def taught_page(request: Request, user=Depends(require_user)):
    """The rules analysts have taught Triagle, with who, when, why and how
    often each has been used."""
    result = _load_result()
    return templates.TemplateResponse(request, "taught.html", _ctx(
        request, user, active="taught", rows=_taught_rows(result), days=instructions.DAYS,
        can_change=user["role"] == "analyst"))


@app.post("/taught/change")
def taught_change(request: Request, rule_id: str = Form(...), do: str = Form(...), days: str = Form(default=""),
                  csrf: str = Form(default=""), user=Depends(require_analyst)):
    """Switch a taught rule off, or run it for more days."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    if do not in ("off", "renew"):
        raise HTTPException(status_code=400, detail="Unknown change.")
    with _LOCK:
        _ensure_state()
        rule = next((r for r in _CACHE["taught"] if r["id"] == rule_id), None)
        if rule is None:
            raise HTTPException(status_code=404, detail="No such rule.")
        if do == "off":
            instructions.switch_off(rule, user["name"])
            audit.record("taught rule switched off", user["name"], rule=rule_id, ip=_client_ip(request))
        else:
            instructions.renew(rule, user["name"], int(days) if days.isdigit() else instructions.DEFAULT_DAYS)
            audit.record("taught rule renewed", user["name"], rule=rule_id, until=rule["until"],
                         ip=_client_ip(request))
        _CACHE.pop("result", None)
        _load_result()
        _changed(now=True)
    return RedirectResponse(url="/taught", status_code=303)


# ---- spot checks: how often a person agrees with a closure --------------------

CHECKS_SHOWN = 10
MINUTES_PER_ALERT = 2      # what reading one alert costs a person; used only for the estimate in the pilot report


def _checks_view(result):
    skip = _test_clients()
    checks = _CACHE.get("checks", {})
    second = _CACHE.get("second", {})
    rows = []
    for a in spotcheck.sample(result["alerts"], result["verdicts"], checks, CHECKS_SHOWN, skip):
        v = result["verdicts"][a["alert_id"]]
        rows.append({"alert": a, "verdict": v, "uc": usecases.for_alert(a, v), "second": second.get(a["alert_id"])})
    # what the model would look at again comes first; the rest keep their order
    rows.sort(key=lambda r: 0 if (r["second"] or {}).get("view") == "look" else 1)
    done = sorted(({"id": k, **v} for k, v in checks.items() if v.get("client") not in skip),
                  key=lambda c: c.get("at") or "", reverse=True)
    return {"rows": rows, "tally": spotcheck.tally(checks, skip),
            "waiting": len(spotcheck.waiting(result["alerts"], result["verdicts"], checks, skip)),
            "recent": done[:12], "disagreed": [c for c in done if c.get("ok") is False],
            "unread": sum(1 for r in rows if not r["second"]),
            "second": {"read": len(second), "look": sum(1 for v in second.values() if v.get("view") == "look")}}


READ_NOTICES = {
    "ok": "Gemini has read the closures below. The ones it would look at again are listed first.",
    "failed": "Gemini did not answer, so there is no second reading. Nothing was changed.",
    "none": "Gemini has already read every closure in this sample.",
    "busy": "Too many requests to the model. Wait a minute and ask again.",
}


@app.get("/checks", response_class=HTMLResponse)
def checks_page(request: Request, read: str = "", user=Depends(require_user)):
    """A sample of the alerts Triagle closed, for a person to agree or
    disagree with, and the figure that comes out of it."""
    result = _load_result()
    return templates.TemplateResponse(request, "checks.html", _ctx(
        request, user, active="checks", can_check=user["role"] == "analyst", notice=READ_NOTICES.get(read, ""),
        model_on=genai.configured(), **_checks_view(result)))


@app.post("/checks/read")
def checks_read(request: Request, csrf: str = Form(default=""), user=Depends(require_analyst)):
    """Ask the model to read back over the closures in the sample and say
    which it would look at again. It changes no verdict: it only decides the
    order a person checks them in."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    if not _ask_allowed(_client_ip(request), trusted=_trusted(user)):
        return RedirectResponse(url="/checks?read=busy", status_code=303)
    with _LOCK:
        result = _load_result()
        sample = spotcheck.sample(result["alerts"], result["verdicts"], _CACHE["checks"], CHECKS_SHOWN,
                                  _test_clients())
        todo = [a for a in sample if a["alert_id"] not in _CACHE["second"]]
        # one call per customer, so one customer's house knowledge is never in a prompt with another's alerts
        batches = {}
        for a in todo:
            batches.setdefault(a.get("client") or "", []).append((a, result["verdicts"][a["alert_id"]]))
        houses = {c: _house(result, c) for c in batches}
    rows = [r for group in batches.values() for r in group]
    if not rows:
        return RedirectResponse(url="/checks?read=none", status_code=303)
    found, provider, error = {}, None, None
    for c, group in batches.items():                                    # outside the lock: this is the slow part
        got, by, err = nightshift.second_read(group, houses[c])
        found.update(got)
        provider, error = provider or by, error or err
    with _LOCK:
        at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        for aid, view in found.items():
            _CACHE["second"][aid] = {**view, "at": at, "by": provider or "Gemini"}
        if found:
            _CACHE["rev"] = _CACHE.get("rev", 0) + 1
            _changed(now=True)
    audit.record("closures read by the model", user["name"], asked=len(rows), answered=len(found),
                 would_look_again=sum(1 for v in found.values() if v["view"] == "look"), error=error,
                 ip=_client_ip(request))
    return RedirectResponse(url=f"/checks?read={'ok' if found else 'failed'}", status_code=303)


@app.post("/checks/mark")
def checks_mark(request: Request, alert_id: str = Form(...), agree: str = Form(...),
                back: str = Form(default="", alias="next"), csrf: str = Form(default=""),
                user=Depends(require_analyst)):
    """A person agrees or disagrees with one closure. A disagreement sends
    the alert back to the queue."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    if agree not in ("yes", "no"):
        raise HTTPException(status_code=400, detail="Say yes or no.")
    agreed = agree == "yes"
    with _LOCK:
        result = _load_result()
        alert = next((a for a in result["alerts"] if a["alert_id"] == alert_id), None)
        if alert is None:
            raise HTTPException(status_code=404, detail="No such alert.")
        checks = _CACHE["checks"]
        if alert_id not in checks:
            v = result["verdicts"].get(alert_id) or {}
            if not spotcheck.eligible(alert, v, _test_clients()):
                raise HTTPException(status_code=400, detail="Only a closure Triagle made on its own can be checked.")
            checks[alert_id] = spotcheck.record(
                alert, v, agreed, user["name"],
                datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))
            audit.record("closure checked", user["name"], alert_id=alert_id, agreed=agreed,
                         closure=v.get("closure_code"), ip=_client_ip(request))
            if not agreed:
                _tell(request, "reopened", user["name"], alert_id, note="A person disagreed with the closure")
                _CACHE.pop("result", None)
                _load_result()
            else:
                _CACHE["rev"] = _CACHE.get("rev", 0) + 1
            _changed(now=True)
        else:
            agreed = bool(checks[alert_id].get("ok"))
    if not agreed:
        return RedirectResponse(url=f"/alert/{quote(alert_id, safe=':')}?notice=sentback", status_code=303)
    return RedirectResponse(url=_back_to(back, "/checks"), status_code=303)


@app.post("/checks/undo")
def checks_undo(request: Request, alert_id: str = Form(...), back: str = Form(default="", alias="next"),
                csrf: str = Form(default=""), user=Depends(require_analyst)):
    """Take a check back, for a wrong click."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload the page and try again.")
    with _LOCK:
        _ensure_state()
        rec = _CACHE["checks"].pop(alert_id, None)
        if rec:
            audit.record("closure check withdrawn", user["name"], alert_id=alert_id, was_agreed=rec.get("ok"),
                         ip=_client_ip(request))
            if rec.get("ok") is False:
                _CACHE.pop("result", None)
                _load_result()
            else:
                _CACHE["rev"] = _CACHE.get("rev", 0) + 1
            _changed(now=True)
    return RedirectResponse(url=_back_to(back, "/checks"), status_code=303)


def _share(part, whole):
    """A share as a whole percent, never rounded up: 598 of 600 is 99%, because
    "100% closed" would say nothing went to a person."""
    return (100 * part) // whole if whole else 0


@app.get("/pilot", response_class=HTMLResponse)
def pilot_report(request: Request, user=Depends(require_user)):
    """What a pilot is judged on, on one page: what arrived, what Triagle
    closed and why, what went to a person, how often a person agreed with a
    closure, what people taught it, which rules to fix, and what it cost."""
    result = _load_result()
    skip = _test_clients()
    verdicts = result["verdicts"]
    alerts = [a for a in result["alerts"] if a.get("client") not in skip]
    ids = {a["alert_id"] for a in alerts}
    closed = [a for a in alerts if not verdicts[a["alert_id"]].get("escalate")]
    raised = [verdicts[a["alert_id"]] for a in alerts if verdicts[a["alert_id"]].get("escalate")]
    codes = {}
    under = 0                # repeats and burst members: counted under an alert that went to a person
    for a in closed:
        v = verdicts[a["alert_id"]]
        if v.get("closure_code") in spotcheck.SKIP_CODES:
            under += 1
            continue
        key = "TAUGHT" if v.get("instruction") else (v.get("closure_code") or "")
        codes[key] = codes.get(key, 0) + 1
    own = len(closed) - under
    words = dict(CLOSURE_WORDS, TAUGHT="closed on a rule a person taught")
    reasons = sorted(({"words": words.get(k, k or "other"), "count": n} for k, n in codes.items()),
                     key=lambda r: -r["count"])
    outcomes = {}
    for v in raised:
        if v.get("resolved"):
            outcomes[v["resolved"]["label"]] = outcomes.get(v["resolved"]["label"], 0) + 1
    acts = [x for aid in ids for x in result.get("actions", {}).get(aid, [])]
    stamps = sorted(a["timestamp"] for a in alerts if a.get("timestamp"))
    span_days = 0
    if stamps:
        from app.engine.relate import parse_ts
        t0, t1 = parse_ts(stamps[0]), parse_ts(stamps[-1])
        span_days = max(1, -int(-(t1 - t0) // 86400)) if t0 is not None and t1 is not None else 0
    rules = [r for r in tuning.analyze_rules(alerts, verdicts) if r["flagged"]]
    minutes = MINUTES_PER_ALERT * len(closed)
    return templates.TemplateResponse(request, "pilot.html", _ctx(
        request, user, customers=sorted({a.get("client") or "" for a in alerts}),
        first=stamps[0] if stamps else "", last=stamps[-1] if stamps else "", span_days=span_days,
        received=len(alerts), closed=len(closed), raised=len(raised), own=own, under=under,
        own_pct=_share(own, len(alerts)), not_read_pct=_share(len(closed), len(alerts)),
        still_open=sum(1 for v in raised if not v.get("resolved")), outcomes=outcomes, reasons=reasons,
        cases=sum(1 for inc in result["incidents"] if set(inc["alert_ids"]) & ids),
        approved=sum(1 for x in acts if x.get("status") in ("executed", "approved")),
        declined=sum(1 for x in acts if x.get("status") == "declined"),
        waiting_acts=_waiting(result, ids),
        checks=_checks_view(result), taught=_taught_rows(result), rules=rules[:8], rules_total=len(rules),
        minutes_per_alert=MINUTES_PER_ALERT, hours=round(minutes / 60, 1),
        rolled_off=result["metrics"].get("rolled_off", 0), usage=genai.usage(), model=genai.model_name(),
        now=datetime.datetime.now(_IST).strftime("%d %b %Y, %H:%M IST")))


# ---- the night analyst's paperwork: the morning report and "was this you?" -----

MORNING_HOURS = (8, 12, 24)
MORNING_KEEP_SECONDS = 600       # an analyst gets a fresh summary after this long
_MORNING = {}                    # (customer, hours) -> (written at, text, by the model?, provider)


def _customers(result):
    """Customers with alerts in the queue: real feeds first, then test streams."""
    names = sorted({a.get("client") or "" for a in result["alerts"]} - {""})
    return sorted(names, key=lambda c: c in _test_clients())


def _overnight(result, client, hours):
    """The figures and rows of one customer's morning report."""
    from app.engine.relate import parse_ts
    now = datetime.datetime.now(datetime.timezone.utc)
    since = (now - datetime.timedelta(hours=hours)).timestamp()
    verdicts = result["verdicts"]
    mine = [a for a in result["alerts"] if a.get("client") == client]
    ids = {a["alert_id"] for a in mine}
    recent = [a for a in mine if (parse_ts(a.get("timestamp")) or 0) >= since]
    closed = [verdicts[a["alert_id"]] for a in recent if not verdicts[a["alert_id"]].get("escalate")]
    raised = [verdicts[a["alert_id"]] for a in recent if verdicts[a["alert_id"]].get("escalate")]
    reasons = {}
    for v in closed:
        words = "closed on a rule your analysts taught" if v.get("instruction") else \
            CLOSURE_WORDS.get(v.get("closure_code"), "closed")
        reasons[words] = reasons.get(words, 0) + 1
    open_items = []
    for a in mine:
        v = verdicts[a["alert_id"]]
        if not _is_open(v):
            continue
        uc = usecases.for_alert(a, v)
        acts = v.get("recommended_actions") or []
        open_items.append({
            "id": a["alert_id"], "name": uc["name"], "host": a.get("host") or a.get("entity") or "",
            "user": a.get("user") or "", "severity": v.get("severity") or "medium",
            "when": _ist_long(a.get("timestamp")), "summary": v.get("summary") or "",
            "question": uc["question"], "next": acts[0] if acts else "",
            "count": (v.get("burst") or {}).get("count", 1),
            "new": (parse_ts(a.get("timestamp")) or 0) >= since, "ts": a.get("timestamp") or ""})
    open_items.sort(key=lambda i: i["ts"], reverse=True)
    open_items.sort(key=lambda i: _SEV_ORDER.get(i["severity"], 9))
    cases, due = [], 0
    for c in _cases(result):
        inc = c["inc"]
        if inc.get("client") != client:
            continue
        if any(_is_open(verdicts.get(aid) or {}) for aid in inc["alert_ids"]):
            cases.append({"id": inc["id"], "name": c["uc"]["name"] if c["uc"] else "Related activity",
                          "key": inc["key"], "severity": c["severity"], "alerts": inc["size"]})
        due += sum(1 for r in (c["clock"] or {}).get("rows", []) if r["status"] in ("running", "overdue"))
    acts = [x for aid in ids for x in result.get("actions", {}).get(aid, [])]
    tune = [r for r in tuning.analyze_rules(mine, verdicts) if r["flagged"]][:3]
    return {
        "client": client, "hours": hours, "from": _ist_long((now - datetime.timedelta(hours=hours)).isoformat()),
        "to": _ist_long(now.isoformat()), "arrived": len(recent), "closed": len(closed),
        "repeats": sum(1 for v in closed if v.get("closure_code") in spotcheck.SKIP_CODES),
        "taught": sum(1 for v in closed if v.get("instruction")), "raised": len(raised),
        "decided": sum(1 for v in raised if v.get("resolved")),
        "reasons": sorted(reasons.items(), key=lambda kv: -kv[1]), "open_items": open_items, "cases": cases,
        "approved": sum(1 for x in acts if x.get("status") in ("executed", "approved")),
        "waiting": _waiting(result, ids), "due": due, "tune": tune,
    }


def _morning_pick(result, client, hours):
    names = _customers(result)
    client = client if client in names else (names[0] if names else "")
    return client, hours if hours in MORNING_HOURS else 12, names


@app.get("/morning", response_class=HTMLResponse)
def morning_report(request: Request, client: str = "", hours: int = 12, user=Depends(require_user)):
    """The report for the morning call with one customer, and the handover
    to the day shift. The figures are Triagle's; the summary is written by
    the model from them."""
    result = _load_result()
    client, hours, names = _morning_pick(result, client, hours)
    facts = _overnight(result, client, hours) if client else None
    return templates.TemplateResponse(request, "morning.html", _ctx(
        request, user, f=facts, customers=names, hours_options=MORNING_HOURS,
        fallback=nightshift.morning_fallback(facts) if facts else "",
        now=datetime.datetime.now(_IST).strftime("%d %b %Y, %H:%M IST")))


@app.get("/api/morning")
def api_morning(request: Request, client: str = "", hours: int = 12, user=Depends(require_user)):
    """The written summary at the top of the morning report. A signed-in
    analyst gets it written fresh by the model; anyone else gets the last one
    written, or the plain summary built from the figures."""
    result = _load_result()
    client, hours, _ = _morning_pick(result, client, hours)
    if not client:
        raise HTTPException(status_code=404, detail="No customer has alerts yet.")
    key = (client, hours)
    kept = _MORNING.get(key)
    stale = not kept or time.time() - kept[0] > MORNING_KEEP_SECONDS
    if stale and _trusted(user) and _ask_allowed(_client_ip(request), trusted=True):
        text, by_model, provider = nightshift.morning_summary(_overnight(result, client, hours),
                                                              _house(result, client))
        if by_model or not kept:
            kept = _MORNING[key] = (time.time(), text, by_model, provider)
        audit.record("morning report written", user["name"], client=client, hours=hours, by_model=by_model,
                     ip=_client_ip(request))
    if kept:
        age = time.time() - kept[0]
        written = _ago(datetime.datetime.fromtimestamp(kept[0], datetime.timezone.utc)
                       .strftime("%Y-%m-%dT%H:%M:%SZ")) if age >= 60 else ""       # "just now" needs no saying
        return {"text": kept[1], "by_model": kept[2], "provider": kept[3], "written": written}
    return {"text": nightshift.morning_fallback(_overnight(result, client, hours)), "by_model": False,
            "provider": "automated summary", "written": ""}


@app.post("/api/followup")
def api_followup(request: Request, alert_id: str = Form(...), csrf: str = Form(default=""),
                 user=Depends(require_analyst)):
    """Draft the message that asks an account's owner "was this you?". The
    analyst sends it, changes it or throws it away: nothing is sent from here."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    result = _load_result()
    alert = next((a for a in result["alerts"] if a["alert_id"] == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail="No such alert.")
    if not alert.get("user"):
        raise HTTPException(status_code=400, detail="This alert names no account to write to.")
    if not _ask_allowed(_client_ip(request), trusted=_trusted(user)):
        raise HTTPException(status_code=429, detail="Too many requests. Wait a minute and try again.")
    uc = usecases.for_alert(alert, result["verdicts"].get(alert_id) or {})
    what = uc["name"]
    if alert.get("title") and alert["title"] != uc["name"]:
        what += f" (the security tool called it: {alert['title']})"
    out = nightshift.followup({"user": alert["user"], "host": alert.get("host") or alert.get("entity") or "",
                               "when": _ist_long(alert.get("timestamp")), "what": what,
                               "src_ip": alert.get("src_ip") or "", "customer": alert.get("client") or ""})
    audit.record("follow-up message drafted", user["name"], alert_id=alert_id, to_account=alert["user"],
                 by_model=out["by_model"], ip=_client_ip(request))
    return out


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
    # What became of each action, said plainly: an action whose tool is not
    # connected here was prepared and recorded, not carried out, and a report
    # that goes to a customer must not call that "contained".
    finished = ("auto_executed", "executed", "approved")
    rehearsed = [a for a in inc_actions if a.get("status") in finished
                 and str(a.get("result_message") or "").startswith("Rehearsal:")]
    carried_out = [a for a in inc_actions if a.get("status") in finished and a not in rehearsed]
    pending_actions = [a for a in inc_actions if a.get("status") == "pending"]
    declined_actions = [a for a in inc_actions if a.get("status") == "declined"]
    bits = []
    if carried_out:
        bits.append(f"{len(carried_out)} carried out")
    if rehearsed:
        bits.append(f"{len(rehearsed)} rehearsed")
    if pending_actions:
        bits.append(f"{len(pending_actions)} waiting for approval")
    if declined_actions:
        bits.append(f"{len(declined_actions)} declined")
    intel_summary = {
        "indicators": indicators,
        "flagged": [r for r in indicators if r["verdict"] in ("malicious", "suspicious")],
        "malicious_count": sum(1 for r in indicators if r["verdict"] == "malicious"),
        "actions": inc_actions,
        "rehearsed_count": len(rehearsed),
        "outcome": ", ".join(bits) if bits else "",
    }

    escalated = [m for m in members if m["verdict"].get("escalate")]
    kinds = {m["verdict"].get("disposition") for m in escalated}
    judgement = ("attack" if "true_positive" in kinds else "suspicious" if "suspicious" in kinds
                 else "undecided" if escalated else "routine")
    worst = min((_SEV_ORDER.get(m["verdict"].get("severity"), 9) for m in escalated), default=9)
    next_steps = []
    for m in escalated:
        for step in m["verdict"].get("recommended_actions") or []:
            if step not in next_steps:
                next_steps.append(step)

    return templates.TemplateResponse(request, "report.html", {
        "incident": incident,
        "members": members,
        "client_name": client_name,
        "any_escalated": any_escalated,
        "judgement": judgement,
        "severity": {v: k for k, v in _SEV_ORDER.items()}.get(worst, "low"),
        "uc": usecases.for_case(members),
        "clock": _clock(result, incident, members),
        "notes": _note_pairs(notes_text),
        "work_notes_by_gemini": notes_by_gemini,
        "work_notes_provider": notes_provider,
        "intel": intel_summary,
        "next_steps": next_steps[:8],
        "now": datetime.datetime.now(_IST).strftime("%d %b %Y, %H:%M") + " IST",
        "asset_v": ASSET_V,
    })


def _note_pairs(text):
    """The written account as (label, text) pairs: 'What happened: ...' is a
    label and its text; a line without a short label is text alone."""
    out = []
    for line in str(text or "").split("\n"):
        line = line.strip()
        if not line:
            continue
        i = line.find(":")
        out.append((line[:i], line[i + 1:].strip()) if 0 < i < 28 else ("", line))
    return out


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
    # Sample alerts have their times moved when the demo clock is on. Say so
    # on a draft built from them, and only there: an alert that arrived from
    # a tool keeps its own time.
    arrived = {m[0] for m in _CACHE.get("live_meta", [])}
    shifted = bool(result["metrics"].get("demo_clock")) and any(i not in arrived for i in incident["alert_ids"])
    return templates.TemplateResponse(request, "certin.html", {
        "d": draft, "reg": dict(reg, key=reg_key), "rows": mine, "others": others, "clock": clock,
        "incident": incident, "sample_times_moved": shifted, "asset_v": ASSET_V,
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
        _tell(request, "report_filed", user["name"], client=inc["client"], regulator=row["name"], report=row["label"],
              case=inc["id"], agent=inc.get("key"), reference=ref, url=f"{_base_url(request)}/case/{inc['id']}")
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


def _customer_keys(text=None):
    """TRIAGLE_INGEST_KEYS: one key for each customer, as "Customer name=key"
    lines (or separated by ;). A tool that presents a customer's key can write
    to that customer's queue and read back that customer's record, and to no
    other. {key: customer}.

    The name ends at the first "=", so a key may itself contain "=" (a base64
    key usually ends in one). A customer name may not."""
    text = os.environ.get("TRIAGLE_INGEST_KEYS", "") if text is None else text
    out = {}
    for part in re.split(r"[;\n]+", text):
        name, sep, key = part.partition("=")
        name, key = name.strip(), key.strip()
        if sep and name and len(key) >= 16:          # a short key is refused, not half-trusted
            out[key] = name
    return out


INGEST_KEYS = _customer_keys()


def _key_customer(request: Request):
    """The customer whose key this request carries, or None. Every configured
    key is compared, each in constant time, so the answer takes as long for a
    wrong key as for a right one."""
    given = request.headers.get("x-triagle-key", "")
    found = None
    for key, customer in INGEST_KEYS.items():
        if hmac.compare_digest(given.encode(), key.encode()) and found is None:
            found = customer
    return found


def _ingest_authorized(request: Request):
    """A SIEM webhook authenticates with the X-Triagle-Key header; a person
    on the console authenticates with their analyst session. Either is fine."""
    key = request.headers.get("x-triagle-key", "")
    customer = _key_customer(request)
    if customer:
        return "siem-webhook: " + customer
    if INGEST_KEY and hmac.compare_digest(key.encode(), INGEST_KEY.encode()):
        return "siem-webhook"
    user = current_user(request)
    if user and (not auth.enabled() or user["role"] == "analyst") and not user.get("guest"):
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
    customer = _key_customer(request)
    renamed = 0
    if customer:
        # The key says whose alerts these are. Whatever name the sender wrote is replaced.
        for it in items:
            if isinstance(it, dict):
                if it.get("client") not in (None, "", customer):
                    renamed += 1
                it["client"] = customer
    accepted = _add_alerts(items)
    if accepted or renamed:
        audit.record("alerts ingested", who, count=accepted, ip=_client_ip(request),
                     named_another_customer=renamed or None)
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
    for f in _real_feeds():
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
    # The key is not written into the page: a console is shown on projectors
    # and in screenshots. TRIAGLE_SHOW_INGEST_KEY=on puts it back, for a
    # signed-in analyst, while a first tool is being connected.
    show_key = (auth.enabled() and user["role"] == "analyst" and not user.get("guest") and bool(INGEST_KEY)
                and os.environ.get("TRIAGLE_SHOW_INGEST_KEY", "").strip().lower() in ("on", "true", "1"))
    return templates.TemplateResponse(request, "connectors.html", _ctx(
        request, user, active="connectors", sources=sources, base_url=base,
        ingest_key=INGEST_KEY if show_key else "", key_set=bool(INGEST_KEY or INGEST_KEYS),
        key_customers=sorted(set(INGEST_KEYS.values())),
        model_status=genai.status(), firewall=gcp_firewall.summary(), auth_on=auth.enabled(),
        learns={"taught": sum(1 for r in _CACHE.get("taught", []) if instructions.state(r) == "on"),
                "decided": len(_CACHE.get("resolutions", {})), "checked": len(_CACHE.get("checks", {})),
                "verdicts": len(result["verdicts"])},
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
            added_by = [a for acts in (_CACHE.get("result") or {}).get("actions", {}).values() for a in acts
                        if (a.get("undo") or {}).get("rule") == rule]
            if added_by:
                a = added_by[0]
                _tell(request, "block_lifted", user["name"], a["alert_id"], action=a["label"], target=a["target"],
                      rule=rule, result=res["message"])
            else:                       # the action is no longer in memory; the rule name still says which address
                ip4 = re.match(r"^triagle-block-(\d+)-(\d+)-(\d+)-(\d+)-(?:in|out)$", rule)
                _tell(request, "block_lifted", user["name"], client=gcp_firewall.client(),
                      target=".".join(ip4.groups()) if ip4 else rule, rule=rule, result=res["message"])
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
    out = analyst.ask(question, case, members, steps, actions, clock,
                      house=_house(_load_result(), case.get("client")))
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
    scenario = _scenario(scenario)
    # each fire is ONE clean incident: clear the previous demo attack first so
    # repeated clicks never pile up into a single doubled-up incident. Alerts
    # from a real feed are left alone.
    _drop_live(keep=lambda item: item.get("client") not in demo_attack.CLIENTS)
    items = demo_attack.fresh_attack(scenario=scenario)
    if benign == "on":
        items += demo_attack.fresh_benign(scenario=scenario)
    accepted = _add_alerts(items)
    audit.record("demo attack fired", user["name"], count=accepted, scenario=scenario, ip=_client_ip(request))
    # land on the new case so the investigation is on screen immediately
    case = _find_incident(_load_result(), demo_attack.SCENARIOS[scenario]["host"])
    return RedirectResponse(url=f"/case/{case['id']}" if case else "/alerts", status_code=303)


@app.post("/demo/reset")
def demo_reset(request: Request, csrf: str = Form(default=""), next: str = Form(default=""),
               user=Depends(require_analyst)):
    """Remove the test alerts. Alerts from connected tools are left alone:
    this never empties a real queue. Analyst-only."""
    if auth.enabled() and not auth.csrf_ok(_session_token(request), csrf):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    with _LOCK:
        _CACHE.pop("demo_run", None)
        _drop_live(keep=lambda item: item.get("client") not in _test_clients())
    audit.record("test alerts cleared", user["name"], ip=_client_ip(request))
    return RedirectResponse(url="/live" if next == "live" else "/", status_code=303)


# ---- live: alerts arriving and being decided, and a test stream to watch -------

LIVE_ROWS = 40
TEST_STREAMS = {
    "shift": "A working hour, with one intrusion in it",
    "intrusion": "The intrusion alone",
}


def _demo_on():
    return os.environ.get("TRIAGLE_DEMO", "false").lower() == "true"


def _scenario(asked):
    """The scenario to run: the one asked for if this deployment offers it."""
    from app import demo_attack
    keep = demo_attack.offered()
    if asked in keep:
        return asked
    return demo_attack.DEFAULT if demo_attack.DEFAULT in keep else keep[0]


def _stream_items(kind, scenario):
    from app import demo_attack
    if kind == "shift":
        return demo_attack.fresh_shift(scenario=scenario)
    return demo_attack.fresh_benign(scenario=scenario) + demo_attack.fresh_attack(scenario=scenario)


def _clock_time(iso):
    """'19:52:07' in IST for today, '23 Nov, 19:52' for an earlier day."""
    try:
        dt = datetime.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    dt = dt.astimezone(_IST)
    today = datetime.datetime.now(_IST).date()
    return dt.strftime("%H:%M:%S") if dt.date() == today else dt.strftime("%d %b, %H:%M")


def _short_reason(verdict):
    """The reason in one sentence, for a row with little room: the first
    sentence of the reasoning, without the lead-in that only repeats the
    verdict. The whole reasoning is on the alert's own page."""
    from app.agent import loop
    text = " ".join(str(verdict.get("reasoning") or verdict.get("summary") or "").split())
    if text.startswith(loop.REAL_THREAT_LEAD):
        text = text[len(loop.REAL_THREAT_LEAD):]
        text = text[:1].upper() + text[1:]
    first = text.split(". ", 1)[0].strip()
    return first if not first or first.endswith((".", "!", "?")) else first + "."


def _live_rows(result, limit=LIVE_ROWS):
    """The alerts that arrived most recently, newest first: what the tool
    said, and what Triagle decided. It is the decision as it stands now, so a
    row can change after it appears (a later alert can raise an earlier one)."""
    by_id = {a["alert_id"]: a for a in result["alerts"]}
    arrived = _CACHE.get("arrived_at", {})
    tests = _test_clients()
    rows = []
    for aid, _ in reversed(_CACHE.get("live_meta", [])):
        a, v = by_id.get(aid), result["verdicts"].get(aid)
        if not a or not v:
            continue
        uc = usecases.for_alert(a, v)
        still_open = _is_open(v)
        if v.get("resolved"):
            why = f"{v['resolved']['label']}, closed by {v['resolved']['by']}"
        elif v.get("escalate"):
            why = sources_meta.verdict_words(v.get("disposition"))
        else:
            why = sources_meta.closure_words(v.get("closure_code"))
        at = arrived.get(aid) or a.get("timestamp") or ""
        rows.append({
            "id": aid, "when": _clock_time(at), "arrived": at if aid in arrived else "",
            "client": a.get("client") or "", "tool": sources_meta.source_name(a.get("source")),
            "asset": a.get("host") or a.get("entity") or "", "said": a.get("title") or "",
            "said_severity": str(a.get("raw_severity") or "").lower(), "open": still_open,
            "severity": v.get("severity") if still_open else "", "what": uc["name"], "why": why,
            "reason": _short_reason(v),
            "stands_for": (v.get("burst") or {}).get("count") or 0, "test": a.get("client") in tests,
        })
        if len(rows) >= limit:
            break
    return rows


def _run_summary(result, run):
    """Where the test stream stands: how many of its alerts were sent, and
    what became of them."""
    from app import demo_attack
    s = demo_attack.SCENARIOS[run["scenario"]]
    mine = [a["alert_id"] for a in result["alerts"] if a.get("client") == s["client"]]
    verdicts = [result["verdicts"][i] for i in mine if i in result["verdicts"]]
    still_open = sum(1 for v in verdicts if _is_open(v))
    cases = [inc for inc in result["incidents"] if inc.get("client") == s["client"]]
    case = _find_incident(result, s["host"])
    if case and case.get("client") != s["client"]:
        case = None
    name, report = "", None
    if case:
        members = _incident_members(result, case)
        name = usecases.for_case(members)["name"]
        clock = _clock(result, case, members)
        if clock and clock.get("next"):
            nxt = clock["next"]
            report = {"name": nxt["name"], "due": nxt["due_iso"], "note": nxt["note"], "hours": nxt.get("hours")}
    total = len(run["items"])
    done = run["sent"] >= total
    seconds = None
    if done and run.get("finished"):
        seconds = max(1, round(run["finished"] - run["started"]))
    return {"id": run["id"], "kind": run["kind"], "customer": s["client"], "sent": run["sent"], "total": total,
            "done": done, "seconds": seconds, "closed": len(verdicts) - still_open, "open": still_open,
            "cases": len(cases), "case": case["id"] if case else None, "case_name": name, "report": report}


def _live_state(result):
    m = result["metrics"]
    run = _CACHE.get("demo_run")
    tests = _test_clients()
    rows = _live_rows(result)
    return {
        "rev": _CACHE.get("rev", 0), "now": _now_iso(),
        "counts": {"received": m.get("received", 0), "closed": m.get("closed_all", 0), "open": m.get("open", 0),
                   "by_person": m.get("resolved", 0), "cases": m.get("incident_count", 0)},
        "rows": rows,
        "last": next((r["arrived"] for r in rows if r["arrived"]), ""),
        "test_alerts": sum(1 for a in result["alerts"] if a.get("client") in tests),
        "run": _run_summary(result, run) if run else None,
    }


@app.get("/live", response_class=HTMLResponse)
def live_page(request: Request, user=Depends(require_user)):
    """Alerts as they arrive, each with what the tool said and what Triagle
    decided. An analyst can send a test stream from here and watch it."""
    from app import demo_attack
    result = _load_result()
    keep = demo_attack.offered()
    counts = {k: {kind: len(_stream_items(kind, k)) for kind in TEST_STREAMS} for k in keep}
    return templates.TemplateResponse(request, "live.html", _ctx(
        request, user, active="live", state=_live_state(result), demo_on=_demo_on(),
        can_test=_demo_on() and user["role"] == "analyst", streams=TEST_STREAMS, stream_counts=counts,
        scenarios={k: demo_attack.SCENARIOS[k] for k in keep}, default_scenario=_scenario(""),
        sources=_source_strip(result), poll=False))


@app.get("/api/live")
def api_live(request: Request, rev: int = -1, user=Depends(require_user)):
    """What the Live page polls. Read-only, so a guest may watch. A caller
    that already has this revision gets a short answer."""
    result = _load_result()
    if rev == _CACHE.get("rev", 0):
        return {"rev": rev, "same": True, "now": _now_iso()}
    return _live_state(result)


@app.post("/api/demo/start")
async def api_demo_start(request: Request, user=Depends(require_analyst)):
    """Prepare a test stream. Nothing is sent yet: the page sends it a few
    alerts at a time with /api/demo/step, so the audience watches it arrive.
    The previous test alerts are removed first; a real feed is left alone."""
    body = await _json_body(request)
    if auth.enabled() and not auth.csrf_ok(_session_token(request), str(body.get("csrf", ""))):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    if not _demo_on():
        raise HTTPException(status_code=403, detail="Test streams are turned off on this deployment.")
    scenario = _scenario(body.get("scenario"))
    kind = body.get("kind") if body.get("kind") in TEST_STREAMS else "shift"
    items = _stream_items(kind, scenario)
    with _LOCK:
        _drop_live(keep=lambda item: item.get("client") not in _test_clients())
        run = {"id": secrets.token_hex(4), "items": items, "sent": 0, "scenario": scenario, "kind": kind,
               "started": time.time(), "finished": None}
        _CACHE["demo_run"] = run
        state = _live_state(_load_result())
    audit.record("test stream started", user["name"], scenario=scenario, kind=kind, count=len(items),
                 ip=_client_ip(request))
    return {"run": run["id"], "total": len(items), "state": state}


@app.post("/api/demo/step")
async def api_demo_step(request: Request, user=Depends(require_analyst)):
    """Send the next few alerts of the test stream through the same path a
    real tool's alerts take, and say where the queue now stands."""
    body = await _json_body(request)
    if auth.enabled() and not auth.csrf_ok(_session_token(request), str(body.get("csrf", ""))):
        raise HTTPException(status_code=403, detail="Form expired. Reload and try again.")
    try:
        n = max(1, min(5, int(body.get("n", 1))))
    except (TypeError, ValueError):
        n = 1
    with _LOCK:
        run = _CACHE.get("demo_run")
        if not run or run["id"] != body.get("run"):
            raise HTTPException(status_code=409, detail="That test stream is no longer running.")
        batch = run["items"][run["sent"]:run["sent"] + n]
        if batch:
            _add_alerts(batch)
            run["sent"] += len(batch)
        if run["sent"] >= len(run["items"]) and not run.get("finished"):
            run["finished"] = time.time()
        state = _live_state(_load_result())
    return {"sent": state["run"]["sent"], "total": state["run"]["total"], "done": state["run"]["done"],
            "case": state["run"]["case"], "state": state}


@app.get("/health")
@app.get("/healthz")
def healthz(request: Request):
    """Public: just enough for an uptime check. Details only when signed in.
    Two addresses, because Cloud Run answers /healthz itself and never passes
    it to the service."""
    out = {"ok": True, "version": app.version}
    user = current_user(request)
    if user and not user.get("guest"):
        out.update(saved_state=store.status(), backend=backend.BACKEND, mask_pii=backend.MASK_PII,
                   runs_as="root" if os.geteuid() == 0 else f"unprivileged user {os.geteuid()}",
                   single_sign_on=sso.configured(), second_factor=auth.any_second_factor(),
                   customer_keys=len(set(INGEST_KEYS.values())),
                   model_calls=backend.STATS["calls"], identifiers_masked=backend.STATS["masked"],
                   sign_in=auth.enabled(), audit_chain_ok=audit.verify()["ok"])
    return out
