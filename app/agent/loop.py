"""
Triagle Agentic — the investigation loop.

This is the agentic core. For each alert it runs a plan→act→observe→re-plan
loop, exactly the pattern serious AI-SOC platforms use:

  1. PLAN: decide which investigative tool to call next (LLM-planned when a
     backend is configured; rule-planned otherwise).
  2. ACT: call the tool, gather evidence into the InvestigationContext.
  3. OBSERVE / RE-PLAN: with new evidence, decide the next step or conclude.
  4. DETERMINE: produce a Verdict — then hand it to the conservative-closure
     guardrails, which can override any auto-close.

The loop is bounded (max_steps) so it always terminates. Every step is
recorded, so the final determination is fully auditable — "here's exactly
what the analyst checked and why", which is what buyers demand.
"""
import json

from app.models import Verdict
from app.agent import tools as toolmod
from app.agent import backend
from app.engine.triage import _enforce_guardrails
from app.engine import signals

MAX_STEPS = 4

PLANNER_SYSTEM = """You are an autonomous SOC analyst investigating one \
security alert. You have these tools:
{tools}

At each step, decide the single most useful next action. Respond ONLY with \
JSON: {{"action": "tool_name", "args": {{...}}, "rationale": "why"}} to call \
a tool, or {{"action": "conclude", "rationale": "why you have enough"}} when \
you have enough evidence to reach a determination.

Investigate efficiently — don't call tools you don't need. Prioritize \
understanding whether this is a real threat and what an attacker could do."""

DETERMINE_SYSTEM = """You are a senior SOC analyst. Given an alert and the \
evidence gathered during investigation, produce a final determination as \
JSON with keys: disposition (true_positive/benign/suspicious/needs_human), \
closure_code (or null), confidence (0-100), severity \
(critical/high/medium/low), escalate (bool), summary (one line), reasoning \
(cite the evidence), recommended_actions (list), tuning_recommendation (or \
null).

CRITICAL: never mark benign/closed anything showing ransomware, credential \
theft, lateral movement, privilege escalation, C2, or exfiltration — \
escalate instead. If evidence is insufficient, disposition=needs_human, \
escalate=true. Only set closure_code when confidence >= 85. Output ONLY the \
JSON."""


def _llm_plan(ctx):
    manifest = toolmod.tools_manifest()
    tools_desc = "\n".join(f"- {n}: {d}" for n, d in manifest.items())
    already = [s["tool"] for s in ctx.steps]
    user = json.dumps({
        "focus_alert": ctx.focus_alert,
        "evidence_so_far": [e.get("summary") for e in ctx.evidence],
        "tools_already_used": already,
    }, default=str)
    out = backend.complete(PLANNER_SYSTEM.format(tools=tools_desc), user)
    if not out:
        return None
    try:
        plan = backend.parse_json(out)
        return plan if isinstance(plan, dict) and plan.get("action") else None
    except ValueError:
        return None


def _rule_plan(ctx):
    """Deterministic planner: a sensible fixed investigation path that mimics
    how an analyst pivots. Runs when no LLM backend is configured."""
    used = {s["tool"] for s in ctx.steps}
    # 1. always see related alerts first
    if "related_alerts" not in used:
        return {"action": "related_alerts", "args": {}, "rationale": "Check if part of a larger pattern."}
    # 2. build the timeline to understand sequence
    if "timeline" not in used:
        return {"action": "timeline", "args": {}, "rationale": "Understand the attack sequence."}
    # 3. check TI on any indicator
    if "threat_intel" not in used:
        return {"action": "threat_intel", "args": {}, "rationale": "Confirm if indicators are known-bad."}
    # 4. entity history for baseline
    if "entity_history" not in used:
        return {"action": "entity_history", "args": {}, "rationale": "Establish what's normal for this entity."}
    return {"action": "conclude", "rationale": "Gathered related alerts, timeline, TI, and history."}


def _llm_determine(ctx):
    user = json.dumps({
        "focus_alert": ctx.focus_alert,
        "investigation_evidence": ctx.evidence,
    }, default=str)
    out = backend.complete(DETERMINE_SYSTEM, user)
    if not out:
        return None
    try:
        p = backend.parse_json(out)
        return Verdict(
            alert_id=ctx.focus_alert["alert_id"],
            disposition=p.get("disposition", "needs_human"),
            closure_code=p.get("closure_code"),
            confidence=int(p.get("confidence", 50)),
            severity=p.get("severity", "medium"),
            escalate=bool(p.get("escalate", True)),
            summary=p.get("summary", ""),
            reasoning=p.get("reasoning", ""),
            recommended_actions=p.get("recommended_actions", []),
            tuning_recommendation=p.get("tuning_recommendation"),
            used_ai=True,
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def _rule_determine(ctx):
    """Deterministic determination from gathered evidence."""
    alert = ctx.focus_alert
    # count corroborating signals found during investigation
    related = next((e for e in ctx.evidence if e["tool"] == "related_alerts"), {})
    ti = next((e for e in ctx.evidence if e["tool"] == "threat_intel"), {})
    related_count = len(related.get("data", []) or [])
    ti_data = ti.get("data") or {}
    ti_hit = bool(ti_data.get("match"))

    found = signals.hard_signals(alert)
    hard = bool(found)

    if hard or ti_hit:
        conf = 92 if (hard and ti_hit) else 88
        reason_bits = []
        if hard:
            reason_bits.append("the alert carries a high-risk signal (" + ", ".join(found[:3]) + ")")
        if ti_hit:
            reason_bits.append(f"{ti_data.get('indicator')} matched threat intelligence ({ti_data['match']})")
        if related_count:
            reason_bits.append(f"{related_count} related alert(s) on the same client corroborate an active pattern")
        # A threat-intel hit alone (an internet scanner touching the perimeter)
        # is worth a human look but is not a confirmed compromise.
        confirmed = hard
        return Verdict(
            alert_id=alert["alert_id"],
            disposition="true_positive" if confirmed else "suspicious",
            closure_code=None,
            confidence=conf if confirmed else 75,
            severity="critical" if confirmed else ("high" if related_count else "medium"),
            escalate=True,
            summary=("Confirmed high-risk activity — escalated with corroborating evidence." if confirmed
                     else "Known-bad source touching this client — escalated for review."),
            reasoning="Investigation concluded this is a real threat: " + "; ".join(reason_bits) + ".",
            recommended_actions=([
                "Isolate the affected asset/account immediately.",
                "Preserve volatile evidence before remediation.",
                "Block corroborated malicious indicators at the perimeter.",
            ] if confirmed else [
                "Block the source at the perimeter.",
                "Check whether any connection from this source succeeded.",
            ]),
            used_ai=False,
        )

    if related_count >= 2:
        return Verdict(
            alert_id=alert["alert_id"], disposition="suspicious", closure_code=None,
            confidence=72, severity="high", escalate=True,
            summary="Multiple correlated alerts — escalated for human review.",
            reasoning=f"Investigation found {related_count} related alerts forming a pattern, "
                      f"insufficient to auto-close but enough to warrant escalation.",
            recommended_actions=["Review the correlated timeline for attack progression."],
            used_ai=False,
        )

    # nothing corroborating; fall back to the base engine's conservative call
    from app.engine.triage import _deterministic_verdict
    from app.models import NormalizedAlert
    na = NormalizedAlert(**{k: alert.get(k) for k in
        ["alert_id","source","client","timestamp","title","raw_severity","entity",
         "src_ip","user","host","dst_ip","description","indicators","raw"] if k in alert})
    return _deterministic_verdict(na)


def _has_hard_escalate_dict(alert):
    return bool(signals.hard_signals(alert))


def investigate(focus_alert, all_alerts, entity_history=None, threat_intel=None):
    """Run the full agentic investigation loop for one alert. Returns
    (verdict_dict, investigation_trail)."""
    ctx = toolmod.InvestigationContext(focus_alert, all_alerts, entity_history, threat_intel)
    use_llm = backend.is_llm_enabled()

    for _ in range(MAX_STEPS):
        plan = (_llm_plan(ctx) if use_llm else None) or _rule_plan(ctx)
        action = plan.get("action")
        if action == "conclude":
            break
        if action not in toolmod.TOOL_REGISTRY:
            # a model asked for a tool that does not exist; fall back to the fixed path
            plan = _rule_plan(ctx)
            action = plan.get("action")
            if action == "conclude":
                break
        args = plan.get("args")
        toolmod.run_tool(action, ctx, args if isinstance(args, dict) else {})

    verdict = (_llm_determine(ctx) if use_llm else None) or _rule_determine(ctx)

    # convert focus_alert dict to a NormalizedAlert-like for guardrails
    from app.models import NormalizedAlert
    na = NormalizedAlert(**{k: focus_alert.get(k) for k in
        ["alert_id","source","client","timestamp","title","raw_severity","entity",
         "src_ip","user","host","dst_ip","description","indicators","raw"] if k in focus_alert})
    verdict = _enforce_guardrails(verdict, na)

    return verdict.to_dict(), ctx.steps
