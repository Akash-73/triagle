"""
Triagle — Gemini access layer (Vertex AI first, AI Studio fallback).

One call, two transports, chosen at runtime so the demo never breaks:

  - VERTEX AI (production): when a Google Cloud project is configured
    (GOOGLE_CLOUD_PROJECT) or TRIAGLE_VERTEX=true. Auth is IAM, not an API
    key — the access token comes from the Cloud Run metadata server (no
    dependency, no secret) or from `gcloud auth` locally. This is the
    enterprise path: IAM, VPC Service Controls, data residency, CMEK, and no
    training on your data — the right place to send security logs.

  - AI STUDIO (dev / laptop): the generativelanguage API with GEMINI_API_KEY.
    Zero setup, fine for a local demo.

  - Neither reachable → returns (None, None) and the caller uses its
    deterministic fallback. Nothing here ever raises.

Which transport ran is reported back, so the UI can show "Gemini on Vertex
AI" vs "Gemini (AI Studio)" honestly.

The model NEVER decides or acts here — this layer only turns a prompt into
prose. Verdicts, response targets and the conservative-closure guardrails are
all deterministic and live elsewhere.
"""
import os
import subprocess

import requests

_METADATA_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/token")


def _vertex_configured():
    if os.environ.get("TRIAGLE_VERTEX", "").lower() in ("1", "true", "yes"):
        return True
    return bool(os.environ.get("GOOGLE_CLOUD_PROJECT"))


def _project():
    return os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("TRIAGLE_VERTEX_PROJECT")


def _location():
    return (os.environ.get("GOOGLE_CLOUD_LOCATION")
            or os.environ.get("TRIAGLE_VERTEX_LOCATION") or "us-central1")


def _vertex_model():
    # Vertex publisher model ids don't use the "-latest" suffix.
    m = os.environ.get("TRIAGLE_VERTEX_MODEL") or os.environ.get("TRIAGLE_MODEL") or "gemini-2.5-flash"
    return m.replace("-latest", "")


def _access_token():
    """Get a Google Cloud access token without extra dependencies.
    1) Cloud Run / GCE metadata server. 2) local `gcloud auth`. Else None."""
    try:
        r = requests.get(_METADATA_TOKEN_URL, headers={"Metadata-Flavor": "Google"}, timeout=2)
        if r.status_code == 200:
            tok = r.json().get("access_token")
            if tok:
                return tok
    except requests.RequestException:
        pass
    for cmd in (["gcloud", "auth", "print-access-token"],
                ["gcloud.cmd", "auth", "print-access-token"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
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


def _body(system, user, max_tokens, temperature):
    return {
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature},
    }


def _vertex(system, user, max_tokens, temperature):
    project, location = _project(), _location()
    if not project:
        return None
    token = _access_token()
    if not token:
        return None
    model = _vertex_model()
    url = (f"https://{location}-aiplatform.googleapis.com/v1/projects/{project}"
           f"/locations/{location}/publishers/google/models/{model}:generateContent")
    resp = requests.post(url, headers={"Authorization": f"Bearer {token}",
                                       "Content-Type": "application/json"},
                         json=_body(system, user, max_tokens, temperature), timeout=45)
    resp.raise_for_status()
    return _extract(resp.json())


def _ai_studio(system, user, max_tokens, temperature):
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        return None
    model = os.environ.get("TRIAGLE_MODEL", "gemini-2.5-flash-lite")
    base = os.environ.get("GEMINI_API_BASE", "https://generativelanguage.googleapis.com/v1beta")
    resp = requests.post(f"{base}/models/{model}:generateContent",
                         headers={"x-goog-api-key": key, "Content-Type": "application/json"},
                         json=_body(system, user, max_tokens, temperature), timeout=45)
    resp.raise_for_status()
    return _extract(resp.json())


def generate_prose(system, user, max_tokens=1024, temperature=0.2):
    """Return (text, provider). provider is 'vertex', 'aistudio' or None.
    Tries Vertex AI when configured, then the AI Studio key. Never raises."""
    if _vertex_configured():
        try:
            text = _vertex(system, user, max_tokens, temperature)
            if text:
                return text, "vertex"
        except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
            pass
    try:
        text = _ai_studio(system, user, max_tokens, temperature)
        if text:
            return text, "aistudio"
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
        pass
    return None, None


PROVIDER_LABEL = {"vertex": "Gemini on Vertex AI", "aistudio": "Gemini"}
