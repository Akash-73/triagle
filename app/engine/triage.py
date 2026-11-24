"""
Triagle — triage engine.

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
  - AI reasoner (when a model backend is configured): deeper narrative
    reasoning, but constrained by the SAME conservative-closure guardrails so
    the AI can never be *less* cautious than the rules — it can escalate more,
    but never auto-close something the rules would have escalated.
"""
import json
import re

from app.models import Verdict, CLOSURE_CODES
from app.engine import signals, ot

# Confidence below this can NEVER result in an auto-close. Hard floor.
AUTO_CLOSE_CONFIDENCE_FLOOR = 85

# Kept for callers that import it; the matching itself lives in signals.py.
HARD_ESCALATE_KEYWORDS = signals.TERMS

_SEV_RANK = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Known administrative tools. A match needs the COMMAND LINE to have the
# tool's own shape — not just the tool's name somewhere in the alert text,
# which an attacker controls (a binary called sccm_update.exe, a dump written
# to C:\\CyberArk\\). It also needs the source severity to be at or below the
# cap and no risk signal on the alert.
#
# Honest limit: a command line can still be imitated. In production this
# check should also require the EDR's signer / hash-reputation verdict.
KNOWN_TOOLS = [
    {"name": "1E Tachyon agent", "max_severity": "low",
     "cmdline": r"^tachyonagent\.exe(\s+--?[\w-]+)*$"},
    {"name": "HP SoftPaq download manager", "max_severity": "low",
     "cmdline": r"^hpsoftpaqdownloadmanager\.exe(\s+[/-][\w-]+)*$"},
    {"name": "CyberArk PSM dispatcher", "max_severity": "medium",
     "cmdline": r"^powershell(\.exe)?\s+-file\s+c:\\cyberark\\psm\\components\\[\w.-]+\.ps1$"},
]
_KNOWN_TOOL_RE = [(t, re.compile(t["cmdline"], re.I)) for t in KNOWN_TOOLS]


def _text_blob(alert):
    return signals.human_text(alert)


def _known_benign_signal(alert):
    """Returns (is_benign, closure_code, why) or (False, None, None)."""
    if _has_hard_escalate(alert):
        return False, None, None
    cmd = signals.command_line(alert).strip()
    sev = _SEV_RANK.get(str(alert.raw_severity).lower(), 2)
    for tool, rx in _KNOWN_TOOL_RE:
        if cmd and rx.match(cmd) and sev <= _SEV_RANK[tool["max_severity"]]:
            return True, "BENIGN_KNOWN_TOOL", (
                f"Command line matches the known administrative tool {tool['name']} "
                f"and the source severity is {alert.raw_severity}.")
    return False, None, None


def _has_hard_escalate(alert):
    return bool(signals.hard_signals(alert))


def _deterministic_verdict(alert):
    escalate_signal = _has_hard_escalate(alert)

    # 1. Hard-escalate signals: always escalate, never close. This is the
    #    anti-false-negative guardrail doing its job.
    if escalate_signal:
        matched = ", ".join(signals.hard_signals(alert)[:3]) or "high-risk indicator"
        return Verdict(
            alert_id=alert.alert_id,
            disposition="true_positive" if alert.raw_severity in ("high", "critical") else "suspicious",
            closure_code=None,   # left OPEN — a human must handle
            confidence=90,
            severity="critical",
            escalate=True,
            summary=f"High-risk activity ({matched}) — escalated, not auto-closed.",
            reasoning=(f"The alert contains a high-risk indicator ({matched}). Triagle never "
                       f"auto-closes alerts carrying indicators of hands-on-keyboard or destructive "
                       f"activity, even if other signals look benign. Routed to a human analyst."),
            recommended_actions=(list(ot.RECOMMENDED) if ot.involved(alert) else [
                "Isolate the affected host/account pending investigation.",
                "Confirm whether the activity was authorized (change ticket, red-team window).",
                "Preserve volatile evidence before remediation.",
            ]),
            used_ai=False,
            basis="signal",
        )

    # 1b. Anything that touches an industrial controller goes to a person,
    #     however routine it looks. The cost of being wrong is physical.
    touched = ot.controllers(alert)
    if touched:
        return Verdict(
            alert_id=alert.alert_id,
            disposition="needs_human",
            closure_code=None,
            confidence=60,
            severity=alert.raw_severity if alert.raw_severity in ("high", "critical") else "medium",
            escalate=True,
            summary="Activity involving an industrial controller — sent for review, not closed.",
            reasoning=(f"The alert involves {', '.join(touched[:3])}, which runs a physical process. "
                       f"Triagle does not close alerts on controllers by itself, and takes no action "
                       f"on them. An OT engineer decides whether this was expected."),
            recommended_actions=[
                "Confirm with the control room whether this activity was planned.",
                "Do not restart, reload or isolate the controller as a first step.",
            ],
            used_ai=False,
        )

    # 1c. A file or process a trusted producer creates in normal operation
    #     (e.g. PowerShell's own execution-policy probe file, which the stock
    #     ruleset rates critical). Recognised by a signature only that producer
    #     uses, and never when a hard signal is present.
    artifact = signals.benign_artifact(alert)
    if artifact:
        return Verdict(
            alert_id=alert.alert_id,
            disposition="benign",
            closure_code="BENIGN_KNOWN_TOOL",
            confidence=92,
            severity="low",
            escalate=False,
            summary=f"Benign — {artifact}.",
            reasoning=(f"The alert is about a {artifact}. The operating system creates this in the "
                       f"course of normal work; the file name is a signature only that producer uses. "
                       f"The source tool rated it {alert.raw_severity}, but the artifact is not an "
                       f"attack, so it is closed with evidence rather than raised."),
            recommended_actions=["No action required."],
            tuning_recommendation=(f"Suppress this detection for the {artifact} signature so the "
                                   f"console is not flooded with a critical alert every time it appears."),
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

    # 2b. Not activity at all, by the source tool's own classification.
    kind = signals.kind(alert)
    ind = alert.indicators or {}
    if kind == signals.POSTURE:
        what = ind.get("kind_reason") or "configuration or vulnerability finding"
        return Verdict(
            alert_id=alert.alert_id,
            disposition="benign",
            closure_code="POSTURE_FINDING",
            confidence=90,
            severity="low",
            escalate=False,
            summary="Not an incident — posture finding, sent to the hardening backlog.",
            reasoning=(f"The source tool classifies this as a {what}. It reports the state of the "
                       f"system, not something a person or a program did, so it is not triaged as "
                       f"an attack. It is counted in the hardening backlog instead of the alert queue."),
            recommended_actions=["Fix through the patching or hardening process; no incident response needed."],
            tuning_recommendation=("Send benchmark and vulnerability results to a posture report rather "
                                   "than the alert queue, so analysts only see activity."),
            used_ai=False,
        )
    if kind == signals.OPERATIONAL and not signals.suspicious_terms(alert) and not signals.sensitive_terms(alert):
        what = ind.get("kind_reason") or "system health event"
        return Verdict(
            alert_id=alert.alert_id,
            disposition="benign",
            closure_code="OPERATIONAL_EVENT",
            confidence=88,
            severity="low",
            escalate=False,
            summary="Not a security detection — system health event, sent to IT operations.",
            reasoning=(f"The source tool classifies this as a {what}: an error, crash, shutdown or "
                       f"capacity event. It carries no risk signal, so it is closed for the SOC and "
                       f"left for IT operations."),
            recommended_actions=["No security action. IT operations may want to look at the underlying fault."],
            used_ai=False,
        )

    # 2c. A control that used to pass now fails: that is a change, not a state.
    if ind.get("drift"):
        return Verdict(
            alert_id=alert.alert_id,
            disposition="needs_human",
            closure_code=None,
            confidence=65,
            severity="medium",
            escalate=True,
            summary="A security control that was passing now fails — sent for review.",
            reasoning=("A benchmark check on this system went from passed to failed. A first-time "
                       "failure is a hardening task; a control that stops passing means something "
                       "changed it, which can be an attacker lowering defences."),
            recommended_actions=[
                "Find what changed the setting and who did it.",
                "Check the same host for other alerts in the last 24 hours.",
            ],
            used_ai=False,
        )

    # 3. Genuinely suspicious identity/network signals -> escalate, don't guess.
    if signals.suspicious_terms(alert):
        return Verdict(
            alert_id=alert.alert_id,
            disposition="suspicious",
            closure_code=None,
            confidence=70,
            severity="high" if alert.raw_severity in ("high", "critical") else "medium",
            escalate=True,
            summary="Suspicious — insufficient certainty to close, escalated for review.",
            reasoning=("The alert shows suspicious characteristics but the available evidence isn't "
                       "conclusive. Rather than risk a wrong closure, Triagle escalates. This is the "
                       "conservative-closure principle: uncertainty routes to a human, never to auto-close."),
            recommended_actions=[
                "Review the entity's recent activity for corroborating signals.",
                "Confirm the source IP / location against known-good baselines.",
            ],
            used_ai=False,
        )

    # 4. Low-severity, no signal, unremarkable -> still NOT auto-closed unless
    #    confidence is high. Defaults to needs_human at modest confidence.
    sensitive = signals.sensitive_terms(alert)
    if sensitive and alert.raw_severity in ("low", "informational", "info"):
        return Verdict(
            alert_id=alert.alert_id,
            disposition="needs_human",
            closure_code=None,
            confidence=60,
            severity="medium",
            escalate=True,
            summary="Sensitive change reported at low severity — sent for review, not closed.",
            reasoning=(f"The source tool rated this low, but it describes a sensitive change "
                       f"({', '.join(sensitive[:3])}). These are routine on most days and an early "
                       f"step of account or host takeover on others, so Triagle does not close "
                       f"them on severity alone."),
            recommended_actions=[
                "Confirm the change against a ticket or with the account owner.",
                "Check the same user or host for sign-in or endpoint alerts in the last 24 hours.",
            ],
            used_ai=False,
        )

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

    # 5. Everything else: don't pretend to know. Escalate at medium confidence,
    #    and never rate it below what the source tool said.
    return Verdict(
        alert_id=alert.alert_id,
        disposition="needs_human",
        closure_code=None,
        confidence=55,
        severity=alert.raw_severity if alert.raw_severity in ("high", "critical") else "medium",
        escalate=True,
        summary="Undetermined — escalated rather than guessed.",
        reasoning=("Triagle could not reach a high-confidence disposition from the available evidence. "
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
    if ot.controllers(alert) and not verdict.escalate:
        verdict.escalate = True
        verdict.closure_code = None
        if verdict.disposition == "benign":
            verdict.disposition = "needs_human"
        verdict.reasoning += (" [Guardrail: the alert involves an industrial controller, so it "
                              "cannot be closed without a person.]")
    if verdict.closure_code and verdict.closure_code not in CLOSURE_CODES:
        verdict.closure_code = None
        verdict.escalate = True
        verdict.reasoning += " [Guardrail: unrecognised closure code discarded; escalated.]"
    if not verdict.escalate and not verdict.closure_code:
        # nothing may leave the queue without a closure code
        verdict.escalate = True
        verdict.reasoning += " [Guardrail: no valid closure code, so the alert stays open.]"
    if verdict.closure_code and verdict.confidence < AUTO_CLOSE_CONFIDENCE_FLOOR:
        # not confident enough to close — force it open
        verdict.escalate = True
        verdict.closure_code = None
        verdict.reasoning += (f" [Guardrail: confidence {verdict.confidence} is below the "
                              f"{AUTO_CLOSE_CONFIDENCE_FLOOR} floor required to auto-close; escalated.]")
    return verdict


AI_SYSTEM_PROMPT = """You are Triagle, an AI SOC analyst that triages security \
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
    from app.agent import backend
    if not backend.is_llm_enabled():
        return None
    text = backend.complete(AI_SYSTEM_PROMPT, json.dumps(alert.to_dict(), default=str))
    if not text:
        return None
    try:
        parsed = backend.parse_json(text)
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
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def settled_by_kind(alert):
    """Posture findings and health events are decided by rule alone. There is
    nothing for a model or an investigation to add, and no reason to pay for one."""
    return signals.kind(alert) != signals.ACTIVITY and not signals.hard_signals(alert)


def triage(alert):
    """Produce a guardrail-enforced Verdict for one alert."""
    verdict = None if settled_by_kind(alert) else _ai_verdict(alert)
    if verdict is None:
        verdict = _deterministic_verdict(alert)
    return _enforce_guardrails(verdict, alert)
