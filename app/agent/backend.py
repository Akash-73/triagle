"""
Triagle Agentic — model-agnostic reasoning backend.

Prophet (and every serious player) is model-agnostic by design — the model
is a swappable commodity; the security context and investigation logic are
the moat. So Triagle talks to whatever backend is configured via one
interface, selected by the TRIAGLE_LLM_BACKEND env var:

    deterministic  (default) — no LLM, rule-based planner. Always works.
    gemini         — Google Gemini via the Gemini API (GEMINI_API_KEY)
    anthropic      — Claude via API key
    deepseek       — DeepSeek API (cheap, strong reasoning)
    nvidia         — NVIDIA NIM free-tier hosted open models
    ollama         — local model, no API cost, data stays on-box

All backends implement complete(system, user) -> str. The agent loop and
guardrails are identical regardless of backend, so swapping models never
touches the security logic.

Every prompt is passed through app.privacy.mask() before it is sent, and the
reply is unmasked on the way back, so Aadhaar numbers, PANs, UPI IDs, mobile
numbers and email addresses do not leave the process. Set
TRIAGLE_MASK_PII=false to turn this off (for a model running on the same box).
"""
import os
import json

import requests

from app import privacy

BACKEND = os.environ.get("TRIAGLE_LLM_BACKEND", "deterministic").lower()
MASK_PII = os.environ.get("TRIAGLE_MASK_PII", "true").lower() != "false"

# running totals for this process: how many prompts went out and how many
# identifiers were masked in them. Counts only — values are never kept here.
STATS = {"calls": 0, "failed": 0, "masked": {}}


def _gemini(system, user):
    """Google Gemini API (generateContent). Asks for JSON back."""
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        return None
    model = os.environ.get("TRIAGLE_MODEL", "gemini-3.8-flash")
    base = os.environ.get("GEMINI_API_BASE", "https://generativelanguage.googleapis.com/v1beta")
    resp = requests.post(
        f"{base}/models/{model}:generateContent",
        headers={"x-goog-api-key": key, "Content-Type": "application/json"},
        json={"system_instruction": {"parts": [{"text": system}]},
              "contents": [{"role": "user", "parts": [{"text": user}]}],
              "generationConfig": {"responseMimeType": "application/json",
                                   "maxOutputTokens": 4096, "temperature": 0}},
        timeout=60,
    )
    resp.raise_for_status()
    cands = resp.json().get("candidates") or []
    if not cands:
        return None
    parts = (cands[0].get("content") or {}).get("parts") or []
    return "".join(p.get("text", "") for p in parts if not p.get("thought")) or None


def parse_json(text):
    """Parse a model reply that should be one JSON object. Tolerates code
    fences and text around the object. Raises ValueError if there is none."""
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t[3:]
        t = t.rsplit("```", 1)[0]
    try:
        return json.loads(t)
    except ValueError:
        a, b = t.find("{"), t.rfind("}")
        if a == -1 or b <= a:
            raise ValueError("no JSON object in model reply")
        return json.loads(t[a:b + 1])


def _anthropic(system, user):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        json={"model": os.environ.get("TRIAGLE_MODEL", "claude-sonnet-4-6"),
              "max_tokens": 1000, "system": system,
              "messages": [{"role": "user", "content": user}]},
        timeout=30,
    )
    resp.raise_for_status()
    return "".join(b["text"] for b in resp.json().get("content", []) if b.get("type") == "text")


def _openai_compatible(system, user, base_url, key_env, default_model):
    """DeepSeek, NVIDIA NIM, and most others speak the OpenAI chat format."""
    key = os.environ.get(key_env)
    if not key:
        return None
    resp = requests.post(
        f"{base_url}/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={"model": os.environ.get("TRIAGLE_MODEL", default_model),
              "max_tokens": 1000,
              "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": user}]},
        timeout=45,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _ollama(system, user):
    base = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    resp = requests.post(
        f"{base}/api/chat",
        json={"model": os.environ.get("TRIAGLE_MODEL", "llama3.1"),
              "stream": False,
              "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": user}]},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _dispatch(system, user):
    if BACKEND == "gemini":
        return _gemini(system, user)
    if BACKEND == "anthropic":
        return _anthropic(system, user)
    if BACKEND == "deepseek":
        return _openai_compatible(system, user, "https://api.deepseek.com/v1",
                                  "DEEPSEEK_API_KEY", "deepseek-chat")
    if BACKEND == "nvidia":
        return _openai_compatible(system, user, "https://integrate.api.nvidia.com/v1",
                                  "NVIDIA_API_KEY", "meta/llama-3.1-70b-instruct")
    if BACKEND == "ollama":
        return _ollama(system, user)
    return None  # deterministic


def complete(system, user):
    """Returns model text, or None if the backend is deterministic/unavailable.
    A None always falls back to the rule engine, so a model outage never
    stops triage."""
    if BACKEND == "deterministic":
        return None
    mapping = {}
    if MASK_PII:
        system, mapping = privacy.mask(system, mapping)
        user, mapping = privacy.mask(user, mapping)
        for kind, n in privacy.summary(mapping).items():
            STATS["masked"][kind] = STATS["masked"].get(kind, 0) + n
    STATS["calls"] += 1
    try:
        out = _dispatch(system, user)
    except (requests.RequestException, KeyError, ValueError, TypeError, IndexError):
        out = None
    if out is None:
        STATS["failed"] += 1
        return None
    return privacy.unmask(out, mapping)


def is_llm_enabled():
    return BACKEND != "deterministic"
