"""
Triagle Agentic — model-agnostic reasoning backend.

Prophet (and every serious player) is model-agnostic by design — the model
is a swappable commodity; the security context and investigation logic are
the moat. So Triagle talks to whatever backend is configured via one
interface, selected by the TRIAGLE_LLM_BACKEND env var:

    deterministic  (default) — no LLM, rule-based planner. Always works.
    anthropic      — Claude via API key
    deepseek       — DeepSeek API (cheap, strong reasoning)
    nvidia         — NVIDIA NIM free-tier hosted open models
    ollama         — local model, no API cost, data stays on-box

All backends implement complete(system, user) -> str. The agent loop and
guardrails are identical regardless of backend, so swapping models never
touches the security logic.
"""
import os
import json

import requests

BACKEND = os.environ.get("TRIAGLE_LLM_BACKEND", "deterministic").lower()


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


def complete(system, user):
    """Returns model text, or None if the backend is deterministic/unavailable."""
    try:
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
    except (requests.RequestException, KeyError, ValueError):
        return None
    return None  # deterministic


def is_llm_enabled():
    return BACKEND != "deterministic"
