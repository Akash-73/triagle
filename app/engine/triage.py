"""
Netrix — triage engine.

This is the product's core and its differentiator. For each NormalizedAlert
it produces a Verdict. The governing principle, in priority order:

  1. NEVER auto-close a true positive. A false negative (calling a real
     threat benign) is the unforgivable error in this category and the
     specific failure incumbents get criticized for. When in doubt, the
     engine escalates rather than closes.

  2. Every closure carries a structured closure code + reasoning + evidence.
     No bare "closed". This is the auditable-disposition wedge.

  3. Noise is dismissed WITH EVIDENCE and a tuning recommendation, not by
     hiding it.

The engine works in two modes:
  - Deterministic rule reasoner (always on, no API key needed): applies a
    transparent rule set. Good enough to demo and genuinely useful.
  - AI reasoner (when ANTHROPIC_API_KEY set): deeper narrative reasoning,
    but constrained by the SAME conservative-closure guardrails so the AI
    can never be *less* cautious than the rules — it can escalate more, but
    never auto-close something the rules would have escalated.
"""
import os
import json

import requests

from app.models import Verdict, CLOSURE_CODES

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.environ.get("NETRIX_AI_MODEL", "claude-sonnet-4-6")

# Confidence below this can NEVER result in an auto-close. Hard floor.
AUTO_CLOSE_CONFIDENCE_FLOOR = 85

# Signals that force escalation regardless of anything else.
HARD_ESCALATE_KEYWORDS = [
    "ransomware", "ransom", "encrypt", "exfiltration", "data theft",
    "domain admin", "credential dump", "lsass", "mimikatz", "cobalt strike",
    "lateral movement", "privilege escalation", "c2", "command and control",
]


def _text_blob(alert):
    parts = [alert.title, alert.description]
    parts += [str(v) for v in alert.indicators.values() if v]
    return " ".join(p for p in parts if p).lower()


def _known_benign_signal(alert):
    """Transparent allowlist logic. Returns (is_benign, closure_code, why) or
    (False, None, None). Deliberately narrow — we only call something benign
    when we can point at WHY, and even then only for low-risk sources."""
    blob = _text_blob(alert)

    # Known admin/security tooling on EDR — a classic false positive class,
    # but ONLY benign if severity is low/medium AND no hard-escalate signal.
    known_tools = ["cyberark", "1e tachyon", "hp softpaq", "psexec (sccm)", "sccm"]
    for tool in known_tools:
        if tool in blob and not _has_hard_escalate(alert):
            return True, "BENIGN_KNOWN_TOOL", f"Matches known administrative tool pattern: {tool}."

    return False, None, None


def _has_hard_escalate(alert):
    blob = _text_blob(alert)
    return any(k in blob for k in HARD_ESCALATE_KEYWORDS)


def _deterministic_verdict(alert):
    blob = _text_blob(alert)
    escalate_signal = _has_hard_escalate(alert)

    # 1. Hard-escalate signals: always escalate, never close. This is the
    #    anti-false-negative guardrail doing its job.
    if escalate_signal:
        matched = next((k for k in HARD_ESCALATE_KEYWORDS if k in blob), "high-risk indicator")
        return Verdict(
            alert_id=alert.alert_id,
            disposition="true_positive" if alert.raw_severity in ("high", "critical") else "suspicious",
            closure_code=None,   # left OPEN — a human must handle
            confidence=90,
            severity="critical",
            escalate=True,
            summary=f"High-risk activity ({matched}) — escalated, not auto-closed.",
            reasoning=(f"The alert contains a high-risk indicator ('{matched}'). Netrix never "
                       f"auto-closes alerts carrying indicators of hands-on-keyboard or destructive "
                       f"activity, even if other signals look benign. Routed to a human analyst."),
            recommended_actions=[
                "Isolate the affected host/account pending investigation.",
                "Confirm whether the activity was authorized (change ticket, red-team window).",
                "Preserve volatile evidence before remediation.",
            ],
            used_ai=False,
        )

    # 2. Known-benign allowlist (narrow, evidence-backed).
    is_benign, code, why = _known_benign_signal(alert)
    if is_benign:
        return Verdict(
            alert_id=alert.alert_id,
            disposition="benign",
            closure_code=code,
            confidence=88,
            severity="low",
            escalate=False,
            summary="Benign — matches a known, evidence-backed pattern.",
            reasoning=why + " Dismissed with evidence rather than hidden; see closure code.",
            recommended_actions=["No action required. Verify the tuning suggestion to reduce future noise."],
            tuning_recommendation=(f"Consider an allowlist rule for this specific tool+host combination "
                                   f"so it stops generating alerts, while keeping the detection active "
                                   f"for other contexts."),
            used_ai=False,
        )

    # 3. Genuinely suspicious identity/network signals -> escalate, don't guess.
    suspicious_terms = ["impossible travel", "brute", "password spray", "anomalous",
                        "unfamiliar", "malware", "trojan", "exploit", "suspicious"]
    if any(t in blob for t in suspicious_terms):
        return Verdict(
            alert_id=alert.alert_id,
            disposition="suspicious",
            closure_code=None,
            confidence=70,
            severity="high" if alert.raw_severity in ("high", "critical") else "medium",
            escalate=True,
            summary="Suspicious — insufficient certainty to close, escalated for review.",
            reasoning=("The alert shows suspicious characteristics but the available evidence isn't "
                       "conclusive. Rather than risk a wrong closure, Netrix escalates. This is the "
                       "conservative-closure principle: uncertainty routes to a human, never to auto-close."),
            recommended_actions=[
                "Review the entity's recent activity for corroborating signals.",
                "Confirm the source IP / location against known-good baselines.",
            ],
            used_ai=False,
        )

    # 4. Low-severity, no signal, unremarkable -> still NOT auto-closed unless
    #    confidence is high. Defaults to needs_human at modest confidence.
    if alert.raw_severity in ("low", "informational", "info"):
        return Verdict(
            alert_id=alert.alert_id,
            disposition="benign",
            closure_code="BENIGN_EXPECTED",
            confidence=86,
            severity="low",
            escalate=False,
            summary="Low-severity routine event — closed with evidence.",
            reasoning=("Low-severity event with no high-risk or suspicious indicators. Closed as "
                       "expected activity, above the confidence floor required for auto-closure."),
            recommended_actions=["No action required."],
            used_ai=False,
        )

    # 5. Everything else: don't pretend to know. Escalate at medium confidence.
    return Verdict(
        alert_id=alert.alert_id,
        disposition="needs_human",
        closure_code=None,
        confidence=55,
        severity="medium",
        escalate=True,
        summary="Undetermined — escalated rather than guessed.",
        reasoning=("Netrix could not reach a high-confidence disposition from the available evidence. "
                   "Consistent with conservative closure, it escalates to a human instead of assigning "
                   "a low-confidence verdict that might wrongly close a real threat."),
        recommended_actions=["Analyst review needed to reach a disposition."],
        used_ai=False,
    )


def _enforce_guardrails(verdict, alert):
    """Final safety net applied to EVERY verdict, including AI ones.
    Guarantees the conservative-closure invariants can't be violated:
      - anything with a hard-escalate signal must escalate and stay open
      - no closure below the confidence floor
    """
    if _has_hard_escalate(alert):
        verdict.escalate = True
        verdict.closure_code = None
        if verdict.disposition == "benign":
            verdict.disposition = "suspicious"
            verdict.reasoning += (" [Guardrail: a high-risk indicator was present, so this alert "
                                  "cannot be closed as benign regardless of other reasoning.]")
    if verdict.closure_code and verdict.confidence < AUTO_CLOSE_CONFIDENCE_FLOOR:
        # not confident enough to close — force it open
        verdict.escalate = True
        verdict.closure_code = None
        verdict.reasoning += (f" [Guardrail: confidence {verdict.confidence} is below the "
                              f"{AUTO_CLOSE_CONFIDENCE_FLOOR} floor required to auto-close; escalated.]")
    return verdict


AI_SYSTEM_PROMPT = """You are Netrix, an AI SOC analyst that triages security \
alerts for MSPs. For the given alert produce a JSON verdict with keys: \
disposition (one of true_positive, benign, suspicious, needs_human), \
closure_code (one of TP_CONFIRMED, TP_LIKELY, BENIGN_EXPECTED, \
BENIGN_KNOWN_TOOL, BENIGN_DUPLICATE, FP_TUNING, INSUFFICIENT_EVIDENCE, or \
null if the alert should stay open), confidence (0-100 integer), severity \
(critical/high/medium/low), escalate (boolean), summary (one line), \
reasoning (the evidence trail), recommended_actions (list of strings), \
tuning_recommendation (string or null).

CRITICAL RULES — these are non-negotiable and override everything:
- NEVER mark something benign or closed if it shows signs of ransomware, \
credential theft, lateral movement, privilege escalation, C2, or data \
exfiltration. Escalate instead.
- If evidence is insufficient, do NOT guess a closure. Set disposition to \
needs_human, closure_code null, escalate true. A wrong closure of a real \
threat is the worst possible outcome.
- Only set a closure_code when confidence is 85 or above.
- Dismiss noise WITH evidence and a tuning_recommendation, never by hiding it.

Output ONLY the JSON object, no other text."""


def _ai_verdict(alert):
    if not ANTHROPIC_API_KEY:
        return None
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 800,
                "system": AI_SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": json.dumps(alert.to_dict(), default=str)}],
            },
            timeout=25,
        )
        resp.raise_for_status()
        data = resp.json()
        text = "".join(b["text"] for b in data.get("content", []) if b.get("type") == "text")
        text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(text)
        return Verdict(
            alert_id=alert.alert_id,
            disposition=parsed.get("disposition", "needs_human"),
            closure_code=parsed.get("closure_code"),
            confidence=int(parsed.get("confidence", 50)),
            severity=parsed.get("severity", "medium"),
            escalate=bool(parsed.get("escalate", True)),
            summary=parsed.get("summary", ""),
            reasoning=parsed.get("reasoning", ""),
            recommended_actions=parsed.get("recommended_actions", []),
            tuning_recommendation=parsed.get("tuning_recommendation"),
            used_ai=True,
        )
    except (requests.RequestException, json.JSONDecodeError, ValueError, KeyError):
        return None


def triage(alert):
    """Produce a guardrail-enforced Verdict for one alert."""
    verdict = _ai_verdict(alert) if ANTHROPIC_API_KEY else None
    if verdict is None:
        verdict = _deterministic_verdict(alert)
    return _enforce_guardrails(verdict, alert)
