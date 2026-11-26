"""
Triagle — the model access layer: Gemini on Vertex AI, or a model you run.

One call, three transports, chosen at runtime:

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
    GEMINI_API_KEY.

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
                            the model's own setting alone. Default "low".
  GEMINI_API_KEY            AI Studio key, for the fallback transport
  TRIAGLE_MODEL_BASE        address of your own model server, for example
                            http://10.0.0.5:11434/v1. Set TRIAGLE_MODEL to the
                            name that server knows the model by.
  TRIAGLE_MODEL_KEY         its key, if it asks for one
"""
import os
import re
import subprocess
import time
from datetime import datetime, timezone

import requests

DEFAULT_MODEL = "gemini-3.5-flash"
_METADATA = "http://metadata.google.internal/computeMetadata/v1/"
_META_HEADERS = {"Metadata-Flavor": "Google"}

# What happened on the most recent call, for the console. No prompt text is
# kept here, only how the call went.
STATUS = {"provider": None, "model": None, "ok": None, "error": None, "at": None, "seconds": None,
          "calls": 0, "failures": 0, "retries": 0}

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


def _send(url, headers, body, timeout):
    """One request, and one more if the service says it is busy or the
    connection drops. A shared quota answers 429 for a moment when it is full,
    and a second try a moment later nearly always goes through. A call that
    timed out is not tried again: the wait has already been long."""
    for attempt in (1, 2):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=timeout)
        except requests.Timeout:
            raise
        except requests.ConnectionError:
            if attempt == 2:
                raise
            resp = None
        if attempt == 1 and (resp is None or resp.status_code in RETRY_STATUS):
            STATUS["retries"] = STATUS.get("retries", 0) + 1
            time.sleep(RETRY_WAIT)
            continue
        return resp


def _post(url, headers, system, user, max_tokens, temperature, timeout=60):
    """One call to the model. A model that has no thinking setting answers
    HTTP 400 to it: ask again without, and stop sending it to that model."""
    level = thinking()
    resp = _send(url, headers, _body(system, user, max_tokens, temperature, level), timeout)
    if resp.status_code == 400 and level:
        plain = _send(url, headers, _body(system, user, max_tokens, temperature), timeout)
        if plain.status_code == 200:
            _no_thinking.add(model_name())
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


def _vertex(system, user, max_tokens, temperature, timeout=60):
    proj = project()
    if not proj:
        raise ModelError("No Google Cloud project found. Set GOOGLE_CLOUD_PROJECT.")
    token = _access_token()
    if not token:
        raise ModelError("No Google Cloud credentials found for this service.")
    resp = _post(vertex_url(proj, location(), model_name()),
                 {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                 system, user, max_tokens, temperature, timeout)
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


def _ai_studio(system, user, max_tokens, temperature, timeout=60):
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        return None
    base = os.environ.get("GEMINI_API_BASE", "https://generativelanguage.googleapis.com/v1beta")
    resp = _post(f"{base}/models/{model_name()}:generateContent",
                 {"x-goog-api-key": key, "Content-Type": "application/json"},
                 system, user, max_tokens, temperature, timeout)
    if resp.status_code != 200:
        raise ModelError(_error_text(resp))
    data = resp.json()
    _meter(data)
    text = _extract(data)
    if not text:
        raise ModelError("The model returned no text.")
    return text


_THINK = re.compile(r"<think>.*?</think>", re.S | re.I)


def _own(system, user, max_tokens, temperature, timeout=60):
    """A model the customer runs, over the OpenAI chat format. Reasoning
    models served this way put their working inside <think> tags; that is
    dropped, the same as Gemini's thought parts."""
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("TRIAGLE_MODEL_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    resp = _send(f"{own_base()}/chat/completions", headers,
                 {"model": model_name(), "temperature": temperature, "max_tokens": max_tokens, "stream": False,
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}, timeout)
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


def _record(provider, ok, error, started):
    STATUS.update(provider=provider, model=model_name(), ok=ok, error=error,
                  at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  seconds=round(time.time() - started, 2))
    STATUS["calls"] += 1
    if not ok:
        STATUS["failures"] += 1


_FAILS = (ModelError, requests.RequestException, ValueError, KeyError, IndexError, TypeError, AttributeError)


def generate_prose(system, user, max_tokens=4096, temperature=0.2, timeout=60):
    """(text, provider). provider is 'own', 'vertex', 'aistudio' or None.
    With TRIAGLE_MODEL_BASE set, the customer's own model is the only one
    asked. Otherwise Vertex AI when enabled, then the AI Studio key. Never
    raises."""
    if own_base():
        started = time.time()
        try:
            text = _own(system, user, max_tokens, temperature, timeout)
            _record("own", True, None, started)
            return text, "own"
        except _FAILS as e:
            _record("own", False, str(e) or e.__class__.__name__, started)
            return None, None                    # and nothing is sent to anyone else
    errors = []
    if vertex_enabled():
        started = time.time()
        try:
            text = _vertex(system, user, max_tokens, temperature, timeout)
            _record("vertex", True, None, started)
            return text, "vertex"
        except _FAILS as e:
            errors.append(str(e) or e.__class__.__name__)
            _record("vertex", False, errors[-1], started)
    started = time.time()
    try:
        text = _ai_studio(system, user, max_tokens, temperature, timeout)
        if text:
            _record("aistudio", True, None, started)
            return text, "aistudio"
    except _FAILS as e:
        errors.append(str(e) or e.__class__.__name__)
        _record("aistudio", False, errors[-1], started)
    if not errors:
        STATUS.update(provider=None, ok=False, error="No model is configured for this deployment.",
                      model=model_name(), at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    return None, None


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
        "last": dict(STATUS), "usage": usage(),
    }


def test_connection():
    """One tiny call, to prove the model answers. Returns status()."""
    generate_prose("You are a connectivity check. Reply with one word.", "Reply with the word: connected",
                   max_tokens=256, temperature=0)
    return status()
