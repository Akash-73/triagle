"""
Triagle — AI analyst work notes (Gemini).

Writes the plain-English case notes a human analyst would type after
investigating an incident. Gemini does the writing; if no key is set or the
call fails, a deterministic fallback keeps the page working.

This path calls Gemini DIRECTLY via GEMINI_API_KEY, independent of
TRIAGLE_LLM_BACKEND — so the verdict engine can stay deterministic (instant,
all-tested) while Gemini adds the narrative. That hybrid is deliberate:
rules guarantee safety, Gemini adds reasoning.

Every prompt is PII-masked (app.privacy) before it leaves the process.
"""
import os

import requests

from app import privacy

SYSTEM = (
    "You are a senior SOC (security operations) analyst writing work notes for "
    "an incident case file. You are given a correlated security incident and its "
    "alerts. Write concise analyst work notes in plain English with four short "
    "parts, each labelled: SUMMARY (2-3 sentences telling what happened as an "
    "attack story), TECHNIQUES (the MITRE ATT&CK techniques involved), WHY "
    "ESCALATED (why a human must look), NEXT ACTIONS (the immediate containment "
    "steps). Keep the whole note under 160 words. Base every statement only on "
    "the alerts provided. Do not invent indicators, hostnames or IPs."
)


def _gemini_prose(system, user):
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        return None
    model = os.environ.get("TRIAGLE_MODEL", "gemini-3.8-flash")
    base = os.environ.get("GEMINI_API_BASE", "https://generativelanguage.googleapis.com/v1beta")
    try:
        resp = requests.post(
            f"{base}/models/{model}:generateContent",
            headers={"x-goog-api-key": key, "Content-Type": "application/json"},
            json={"system_instruction": {"parts": [{"text": system}]},
                  "contents": [{"role": "user", "parts": [{"text": user}]}],
                  "generationConfig": {"maxOutputTokens": 1024, "temperature": 0.2}},
            timeout=45,
        )
        resp.raise_for_status()
        cands = resp.json().get("candidates") or []
        if not cands:
            return None
        parts = (cands[0].get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        return text.strip() or None
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
        return None


def _user_prompt(incident, members):
    lines = []
    for m in members:
        a, v = m["alert"], m["verdict"]
        ind = a.get("indicators") or {}
        extra = ind.get("cmdline") or ind.get("sha256") or a.get("dst_ip") or ""
        lines.append(
            f"- {a.get('timestamp')} [{a.get('source')}] {a.get('title')} on "
            f"{a.get('host') or a.get('entity')} (user {a.get('user') or 'n/a'}): "
            f"{a.get('description') or ''} {extra} "
            f"=> verdict {v.get('disposition')}, escalate={v.get('escalate')}")
    return (f"Incident centred on {incident.get('key')} for client "
            f"{incident.get('client')}. {len(members)} correlated alerts across "
            f"{len(incident.get('sources', []))} tools:\n" + "\n".join(lines) +
            "\n\nWrite the analyst work notes.")


def _fallback(incident, members):
    escalated = [m for m in members if m["verdict"].get("escalate")]
    titles = "; ".join(m["alert"]["title"] for m in escalated) or "no escalations"
    return (
        f"SUMMARY: Triagle correlated {len(members)} related alerts across "
        f"{len(incident.get('sources', []))} security tools into one incident on "
        f"{incident.get('key')}. {len(escalated)} were escalated for review.\n"
        f"WHAT FIRED: {titles}.\n"
        f"WHY ESCALATED: one or more alerts carried high-risk signals "
        f"(credential theft, lateral movement, ransomware or C2), which are never "
        f"auto-closed.\n"
        f"NEXT ACTIONS: isolate the affected asset, preserve evidence, reset "
        f"involved credentials, and block external indicators at the perimeter."
    )


def work_notes(incident, members):
    """Returns (text, by_gemini: bool). Never raises."""
    user = _user_prompt(incident, members)
    mapping = {}
    system_m, mapping = privacy.mask(SYSTEM, mapping)
    user_m, mapping = privacy.mask(user, mapping)
    text = _gemini_prose(system_m, user_m)
    if text:
        return privacy.unmask(text, mapping), True
    return _fallback(incident, members), False
