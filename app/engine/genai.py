"""
Triagle — the model access layer: Gemini on Vertex AI, or a model you run.

One call, and one transport for each deployment, chosen at start:

  - YOUR OWN MODEL. Set TRIAGLE_MODEL_BASE to the address of any server that
    speaks the OpenAI chat format (Ollama, vLLM, LM Studio, a gateway inside
    a bank's network) and every prompt goes there and nowhere else. No call
    is made to Google, even when that server is down. The guardrails are
    plain code and do not change with the model.

  - VERTEX AI (the product path). Used automatically when Triagle runs on
    Cloud Run, or when GOOGLE_CLOUD_PROJECT / TRIAGLE_VERTEX=true is set.
    Auth is IAM, not an API key: the access token comes from the metadata
    server (the service's own identity) or from `gcloud auth` on a laptop.
    Nothing to paste, nothing to leak, and prompts are not used for training.
    The service account needs the role "Vertex AI User".

  - AI STUDIO (a laptop without a project): the generativelanguage API with
    GEMINI_API_KEY. Never used where Vertex AI is enabled, not even when
    Vertex AI fails: it is a different service with different terms.

  - Neither reachable: returns (None, None) and the caller uses its own
    deterministic fallback. Nothing here raises.

Every attempt is recorded in STATUS (which transport, which model, how long,
and the error text if it failed), so the console can say plainly whether the
model is connected and, if not, why. A silent fallback is how a model stays
broken for a week.

The model never decides or acts here. This layer turns a prompt into prose.
Verdicts, response targets and the guardrails are deterministic and live
elsewhere.

Settings:
  TRIAGLE_VERTEX            true / false   force Vertex on or off
  GOOGLE_CLOUD_PROJECT      project id     (read from the metadata server on Cloud Run)
  TRIAGLE_VERTEX_LOCATION   default "global"
  TRIAGLE_MODEL             default "gemini-3.5-flash"
  TRIAGLE_THINKING          minimal / low / medium / high, or "default" to leave
                            the model's own setting alone. Default "low". A caller
                            may ask for another level for one call; with "default"
                            that is ignored too.
  GEMINI_API_KEY            AI Studio key, for the fallback transport
  TRIAGLE_MODEL_BASE        address of your own model server, for example
                            http://10.0.0.5:11434/v1. Set TRIAGLE_MODEL to the
                            name that server knows the model by.
  TRIAGLE_MODEL_KEY         its key, if it asks for one
"""
import os
import queue
import re
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone

import requests

DEFAULT_MODEL = "gemini-3.5-flash"
_METADATA = "http://metadata.google.internal/computeMetadata/v1/"
_META_HEADERS = {"Metadata-Flavor": "Google"}

# What happened on the most recent call, for the console. No prompt text is
# kept here, only how the call went.
STATUS = {"provider": None, "model": None, "ok": None, "error": None, "at": None, "seconds": None,
          "calls": 0, "failures": 0, "retries": 0, "recent": []}

# The last calls, one line each: how long, how many tokens, which thinking
# level. Counts only. It is how a slow model is told from a slow network.
CALLS = deque(maxlen=40)
_this = threading.local()

_cache = {"project": None, "token": None, "token_exp": 0.0}

# What the model has been asked to do and what it cost, as the API itself
# reports it with every answer. Counts only: no prompt or answer is kept.
# Prices are per million tokens, in US dollars, as published for the default
# model; set TRIAGLE_PRICE_IN and TRIAGLE_PRICE_OUT when the price list or
# the model changes. Thinking tokens are billed as output.
USAGE = {"calls": 0, "input": 0, "output": 0, "thinking": 0, "since": None}
PRICE_IN_USD, PRICE_OUT_USD = 1.50, 9.00


def _price(name, default):
    try:
        return max(0.0, float(os.environ.get(name, "")))
    except ValueError:
        return default


def _meter(resp_json):
    """Add one answer's token counts to the running totals."""
    used = resp_json.get("usageMetadata") or {}
    _this.used = (int(used.get("promptTokenCount") or 0), int(used.get("candidatesTokenCount") or 0),
                  int(used.get("thoughtsTokenCount") or 0))
    USAGE["calls"] += 1
    USAGE["input"] += int(used.get("promptTokenCount") or 0)
    USAGE["output"] += int(used.get("candidatesTokenCount") or 0)
    USAGE["thinking"] += int(used.get("thoughtsTokenCount") or 0)
    USAGE["since"] = USAGE["since"] or datetime.now(timezone.utc).isoformat(timespec="seconds")


def usage():
    """Calls, tokens and what they cost at the published price."""
    own = bool(own_base())                    # a model you run is not billed by the token
    p_in = _price("TRIAGLE_PRICE_IN", 0.0 if own else PRICE_IN_USD)
    p_out = _price("TRIAGLE_PRICE_OUT", 0.0 if own else PRICE_OUT_USD)
    cost = (USAGE["input"] * p_in + (USAGE["output"] + USAGE["thinking"]) * p_out) / 1_000_000
    return {**USAGE, "cost_usd": round(cost, 4), "price_in": p_in, "price_out": p_out,
            "per_call_usd": round(cost / USAGE["calls"], 4) if USAGE["calls"] else 0.0}


def mark():
    """A point in the running totals, for cost_since()."""
    return (USAGE["calls"], USAGE["input"], USAGE["output"] + USAGE["thinking"])


def cost_since(point):
    """(calls, US dollars) used since mark(), at the published price. Another
    call made at the same moment is counted in, so a caller says "about"."""
    price = usage()
    usd = ((USAGE["input"] - point[1]) * price["price_in"]
           + (USAGE["output"] + USAGE["thinking"] - point[2]) * price["price_out"]) / 1_000_000
    return USAGE["calls"] - point[0], round(max(0.0, usd), 6)


def load_usage(saved):
    """Carry the totals over a restart."""
    if not isinstance(saved, dict):
        return
    for k in ("calls", "input", "output", "thinking"):
        try:
            USAGE[k] = max(0, int(saved.get(k) or 0))
        except (TypeError, ValueError):
            USAGE[k] = 0
    USAGE["since"] = str(saved["since"]) if saved.get("since") else None

# How long the model may think before it writes. Triagle asks it to put into
# prose a verdict the rules have already reached, so a short think is enough
# and the answer comes back in a few seconds instead of ten.
THINKING_LEVELS = ("minimal", "low", "medium", "high")
_no_thinking = set()      # models that refused the setting; they run on their own default
_refused = set()          # (model, level) pairs a model refused when a caller asked for that level


def _flag(name):
    return os.environ.get(name, "").strip().lower()


def on_cloud_run():
    return bool(os.environ.get("K_SERVICE"))


def own_base():
    """The address of a model the customer runs, or ''."""
    return (os.environ.get("TRIAGLE_MODEL_BASE") or "").strip().rstrip("/")


def vertex_enabled():
    if own_base():
        return False                     # a customer who runs its own model sends nothing to Google
    flag = _flag("TRIAGLE_VERTEX")
    if flag in ("0", "false", "no", "off"):
        return False
    if flag in ("1", "true", "yes", "on"):
        return True
    return bool(os.environ.get("GOOGLE_CLOUD_PROJECT")) or on_cloud_run()


def model_name():
    m = os.environ.get("TRIAGLE_VERTEX_MODEL") or os.environ.get("TRIAGLE_MODEL") or DEFAULT_MODEL
    return m.replace("-latest", "")


def location():
    return (os.environ.get("TRIAGLE_VERTEX_LOCATION") or os.environ.get("GOOGLE_CLOUD_LOCATION")
            or "global")


def project():
    """The project to bill and authorise against: from the environment, or
    from the metadata server when running on Google Cloud."""
    p = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("TRIAGLE_VERTEX_PROJECT")
    if p:
        return p
    if _cache["project"]:
        return _cache["project"]
    if time.time() < _cache.get("project_retry", 0.0):
        return None                      # asked recently and there was no metadata server
    _cache["project_retry"] = time.time() + 300
    try:
        r = requests.get(_METADATA + "project/project-id", headers=_META_HEADERS, timeout=2)
        if r.status_code == 200 and r.text.strip():
            _cache["project"] = r.text.strip()
    except requests.RequestException:
        pass
    return _cache["project"]


def _access_token():
    """A Google Cloud access token with no extra dependency: the metadata
    server on Cloud Run / Compute Engine, else local `gcloud`. Cached until
    shortly before it expires."""
    if _cache["token"] and time.time() < _cache["token_exp"]:
        return _cache["token"]
    try:
        r = requests.get(_METADATA + "instance/service-accounts/default/token",
                         headers=_META_HEADERS, timeout=2)
        if r.status_code == 200:
            body = r.json()
            if body.get("access_token"):
                _cache["token"] = body["access_token"]
                _cache["token_exp"] = time.time() + max(60, int(body.get("expires_in", 300)) - 120)
                return _cache["token"]
    except (requests.RequestException, ValueError):
        pass
    for cmd in (["gcloud", "auth", "print-access-token"], ["gcloud.cmd", "auth", "print-access-token"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            if out.returncode == 0 and out.stdout.strip():
                _cache["token"] = out.stdout.strip()
                _cache["token_exp"] = time.time() + 600
                return _cache["token"]
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def _extract(resp_json):
    cands = resp_json.get("candidates") or []
    if not cands:
        return None
    parts = (cands[0].get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
    return text.strip() or None


def thinking():
    """The thinking level to ask for, or None to leave the model's own."""
    level = _flag("TRIAGLE_THINKING") or "low"
    if level not in THINKING_LEVELS or model_name() in _no_thinking:
        return None
    return level


def _body(system, user, max_tokens, temperature, level=None):
    config = {"maxOutputTokens": max_tokens, "temperature": temperature}
    if level:
        config["thinkingConfig"] = {"thinkingLevel": level.upper()}
    return {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": config,
    }


RETRY_STATUS = (429, 500, 502, 503, 504)
RETRY_WAIT = 1.5          # seconds before the one second try
# How long a written account or an answer is waited for at most. One normally
# takes 2 to 6 seconds, and on the live feed about one in eight hangs for
# twenty seconds or more. So an answer that has not come after WRITE_HEDGE
# seconds is asked for a second time beside the first, and whichever comes
# first is used (write, below). A call that asks for the least thinking
# normally answers in 2 seconds, so it is asked again sooner.
WRITE_SECONDS = 25
WRITE_HEDGE = 7
WRITE_HEDGE_QUICK = 4


def _send(url, headers, body, timeout, again_on_timeout=False):
    """One request, and one more if the service says it is busy or the
    connection drops. A shared quota answers 429 for a moment when it is full,
    and a second try a moment later nearly always goes through.

    A call that timed out is tried again only when the caller asks, which it
    does when it has set a short wait: on the live feed an answer that
    normally takes two seconds sometimes hangs for thirty, and a fresh request
    is answered at once. With the default long wait it is not tried again."""
    for attempt in (1, 2):
        pause = RETRY_WAIT
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=timeout)
        except requests.Timeout:
            if not again_on_timeout or attempt == 2:
                raise
            resp, pause = None, 0            # it has waited long enough already
        except requests.ConnectionError:
            if attempt == 2:
                raise
            resp = None
        if attempt == 1 and (resp is None or resp.status_code in RETRY_STATUS):
            STATUS["retries"] = STATUS.get("retries", 0) + 1
            time.sleep(pause)
            continue
        return resp


def _post(url, headers, system, user, max_tokens, temperature, timeout=60, again=False, level=None):
    """One call to the model.

    `level` asks for a thinking level for this call alone, for example
    "minimal" for a small choice that needs no reasoning. A model that does
    not offer that level answers HTTP 400: the call is made again at the
    usual level, and that level is not asked of that model again. A model
    that has no thinking setting at all answers 400 to the usual level too:
    ask again without, and stop sending it to that model."""
    usual = thinking()
    want = level if (usual and level in THINKING_LEVELS and (model_name(), level) not in _refused) else usual
    _this.level = want
    resp = _send(url, headers, _body(system, user, max_tokens, temperature, want), timeout, again)
    if resp.status_code == 400 and want and want != usual:
        again_usual = _send(url, headers, _body(system, user, max_tokens, temperature, usual), timeout, again)
        if again_usual.status_code == 200:
            _refused.add((model_name(), want))
        resp, want = again_usual, usual
        _this.level = want
    if resp.status_code == 400 and want:
        plain = _send(url, headers, _body(system, user, max_tokens, temperature), timeout, again)
        if plain.status_code == 200:
            _no_thinking.add(model_name())
            _this.level = None
        return plain
    return resp


def _error_text(resp):
    """The short reason a call failed, as the API gave it. Google sends
    {"error": {"message", "status"}}; other servers send {"error": "words"}."""
    try:
        err = resp.json().get("error") or {}
    except (ValueError, AttributeError):
        return f"HTTP {resp.status_code}: {resp.text[:300]}"
    if not isinstance(err, dict):
        return f"HTTP {resp.status_code}: {str(err)[:300]}"
    msg = err.get("message") or ""
    status = err.get("status") or err.get("type") or ""
    return f"HTTP {resp.status_code} {status}: {msg}".strip()[:400]


class ModelError(Exception):
    pass


def vertex_url(proj, loc, model):
    host = "aiplatform.googleapis.com" if loc == "global" else f"{loc}-aiplatform.googleapis.com"
    return (f"https://{host}/v1/projects/{proj}/locations/{loc}"
            f"/publishers/google/models/{model}:generateContent")


def _vertex(system, user, max_tokens, temperature, timeout=60, again=False, level=None):
    proj = project()
    if not proj:
        raise ModelError("No Google Cloud project found. Set GOOGLE_CLOUD_PROJECT.")
    token = _access_token()
    if not token:
        raise ModelError("No Google Cloud credentials found for this service.")
    resp = _post(vertex_url(proj, location(), model_name()),
                 {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                 system, user, max_tokens, temperature, timeout, again, level)
    if resp.status_code != 200:
        if resp.status_code in (401, 403):
            _cache["token"] = None
        raise ModelError(_error_text(resp))
    data = resp.json()
    _meter(data)
    text = _extract(data)
    if not text:
        raise ModelError("The model returned no text.")
    return text


def _ai_studio(system, user, max_tokens, temperature, timeout=60, again=False, level=None):
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        return None
    base = os.environ.get("GEMINI_API_BASE", "https://generativelanguage.googleapis.com/v1beta")
    resp = _post(f"{base}/models/{model_name()}:generateContent",
                 {"x-goog-api-key": key, "Content-Type": "application/json"},
                 system, user, max_tokens, temperature, timeout, again, level)
    if resp.status_code != 200:
        raise ModelError(_error_text(resp))
    data = resp.json()
    _meter(data)
    text = _extract(data)
    if not text:
        raise ModelError("The model returned no text.")
    return text


_THINK = re.compile(r"<think>.*?</think>", re.S | re.I)


def _own(system, user, max_tokens, temperature, timeout=60, again=False):
    """A model the customer runs, over the OpenAI chat format. Reasoning
    models served this way put their working inside <think> tags; that is
    dropped, the same as Gemini's thought parts."""
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("TRIAGLE_MODEL_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    resp = _send(f"{own_base()}/chat/completions", headers,
                 {"model": model_name(), "temperature": temperature, "max_tokens": max_tokens, "stream": False,
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}, timeout, again)
    if resp.status_code != 200:
        raise ModelError(_error_text(resp))
    data = resp.json()
    used = data.get("usage") or {}
    _meter({"usageMetadata": {"promptTokenCount": used.get("prompt_tokens"),
                              "candidatesTokenCount": used.get("completion_tokens")}})
    choice = (data.get("choices") or [{}])[0]
    text = _THINK.sub("", str((choice.get("message") or {}).get("content") or "")).strip()
    if not text:
        raise ModelError("The model returned no text.")
    return text


_answered = [0.0]          # when the model last answered, by the clock


def _record(provider, ok, error, started):
    """Count one call, and say what the console shows about the model.

    A slow answer is asked for a second time beside the first, so two calls
    can be out at once. The slow one may fail long after the other has
    answered. That is a straggler, not a model that is down: it is counted
    and listed, and it does not change what the top bar says. A failure
    changes that only when nothing has answered since the call began."""
    now = time.time()
    at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    seconds = round(now - started, 2)
    straggler = (not ok) and _answered[0] > started
    if ok:
        _answered[0] = now
    if not straggler:
        STATUS.update(provider=provider, model=model_name(), ok=ok, error=error, at=at, seconds=seconds)
    used = getattr(_this, "used", None) if ok else None
    CALLS.append({"at": at, "seconds": seconds, "ok": bool(ok),
                  "in": used[0] if used else None, "out": used[1] if used else None,
                  "thinking": used[2] if used else None, "level": getattr(_this, "level", None)})
    _this.used = None
    STATUS["calls"] += 1
    if not ok:
        STATUS["failures"] += 1
        STATUS["recent"] = (STATUS.get("recent") or [])[-5:] + [
            {"at": at, "provider": provider, "seconds": seconds, "error": str(error)[:200]}]


_FAILS = (ModelError, requests.RequestException, ValueError, KeyError, IndexError, TypeError, AttributeError)


def generate_prose(system, user, max_tokens=4096, temperature=0.2, timeout=60, again_on_timeout=False,
                   thinking_level=None):
    """(text, provider). provider is 'own', 'vertex', 'aistudio' or None.
    Never raises.

    One transport for a deployment, and no other. With TRIAGLE_MODEL_BASE set
    that is the customer's own model. Otherwise, where Vertex AI is enabled,
    it is Vertex AI: a prompt that was promised to Google Cloud is not sent to
    the AI Studio API when Vertex AI is slow, because that is a different
    service with different terms. The AI Studio key is used only on a
    deployment that has no Vertex AI at all, a laptop."""
    _this.level = _this.used = None
    if own_base():
        started = time.time()
        try:
            text = _own(system, user, max_tokens, temperature, timeout, again_on_timeout)
            _record("own", True, None, started)
            return text, "own"
        except _FAILS as e:
            _record("own", False, str(e) or e.__class__.__name__, started)
            return None, None
    if vertex_enabled():
        started = time.time()
        try:
            text = _vertex(system, user, max_tokens, temperature, timeout, again_on_timeout, thinking_level)
            _record("vertex", True, None, started)
            return text, "vertex"
        except _FAILS as e:
            _record("vertex", False, str(e) or e.__class__.__name__, started)
            return None, None
    started = time.time()
    try:
        text = _ai_studio(system, user, max_tokens, temperature, timeout, again_on_timeout, thinking_level)
        if text:
            _record("aistudio", True, None, started)
            return text, "aistudio"
    except _FAILS as e:
        _record("aistudio", False, str(e) or e.__class__.__name__, started)
        return None, None
    STATUS.update(provider=None, ok=False, error="No model is configured for this deployment.",
                  model=model_name(), at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    return None, None


def first(fn, after, limit, again=True):
    """fn() in a thread of its own. If it has not answered after `after`
    seconds, a second fn() is started beside it. Returns the first answer
    that is not None. Returns None when both have failed, or when `limit`
    seconds have passed. A call that fails at once is tried once more at
    once, unless `again` is False. Never raises."""
    answers = queue.Queue()

    def work():
        try:
            answers.put(fn())
        except Exception:
            answers.put(None)

    def start():
        threading.Thread(target=work, daemon=True).start()

    start()
    started, finished = 1, 0
    began = time.time()
    while True:
        now = time.time()
        if now - began >= limit:
            return None
        until = (began + after) if started == 1 else (began + limit)
        try:
            got = answers.get(timeout=max(0.01, min(until, began + limit) - now))
        except queue.Empty:
            if started == 1:
                start()
                started = 2
            continue
        finished += 1
        if got is not None:
            return got
        if finished >= started:
            if started == 2 or not again:
                return None
            start()
            started = 2


def write(system, user, max_tokens=4096, temperature=0.2, thinking_level=None, hedge=None):
    """(text, provider) for words a person is waiting for on a page: an
    account, an answer, a report. Never raises.

    Found on the live site on 26 November: the account of an alert took thirty
    seconds, because the first request hung, was waited for in full, and only
    then asked again. Here a slow answer is asked for a second time beside the
    first, and whichever comes first is used. A request that fails outright is
    not repeated: generate_prose has already asked a busy service once more."""
    after = hedge if hedge is not None else (WRITE_HEDGE_QUICK if thinking_level == "minimal" else WRITE_HEDGE)

    def ask():
        text, provider = generate_prose(system, user, max_tokens=max_tokens, temperature=temperature,
                                        timeout=WRITE_SECONDS, thinking_level=thinking_level)
        return (text, provider) if text else None

    return first(ask, after, WRITE_SECONDS, again=False) or (None, None)


def account_thinking():
    """How much the model thinks before it writes the account of one alert.
    The least, unless told otherwise: the account is four short lines from
    facts it is handed, and a person is watching the page fill.
    TRIAGLE_ACCOUNT_THINKING=low puts it back to the usual level."""
    v = os.environ.get("TRIAGLE_ACCOUNT_THINKING", "minimal").strip().lower()
    return v if v in ("minimal", "low", "medium", "high") else "minimal"


PROVIDER_LABEL = {"vertex": "Gemini on Vertex AI", "aistudio": "Gemini", "own": "your own model"}


def word():
    """What a page calls the model in a sentence: Gemini, or "the model" when
    the customer runs its own."""
    return "the model" if own_base() else "Gemini"


def configured():
    """Is there any transport to try at all?"""
    return bool(own_base()) or vertex_enabled() or bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))


def status():
    """What the console shows about the model."""
    if own_base():                       # the host only: an address can carry a name and a password
        host = re.sub(r"^[a-z]+://", "", own_base(), flags=re.I).split("/")[0].split("@")[-1]
        transport = f"Your own model server at {host}"
    else:
        transport = "Vertex AI" if vertex_enabled() else (
            "AI Studio key" if (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")) else None)
    return {
        "configured": configured(), "transport": transport, "model": model_name(), "own": bool(own_base()),
        "thinking": None if own_base() else thinking(),
        "location": location() if vertex_enabled() else None,
        "project": project() if vertex_enabled() else None,
        "last": dict(STATUS), "usage": usage(), "calls": list(CALLS),
    }


def test_connection():
    """One tiny call, to prove the model answers. Returns status()."""
    generate_prose("You are a connectivity check. Reply with one word.", "Reply with the word: connected",
                   max_tokens=256, temperature=0)
    return status()
