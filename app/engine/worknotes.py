"""
Triagle — AI analyst work notes (Gemini).

Writes the plain-English case notes a human analyst would type after
investigating an incident. Gemini does the writing; if no key is set or the
call fails, a deterministic fallback keeps the page working.

This path calls Gemini through app.engine.genai (Vertex AI on Cloud Run),
independent of TRIAGLE_LLM_BACKEND — so the verdict engine can stay
deterministic (instant, all-tested) while Gemini adds the narrative. That
hybrid is deliberate: rules guarantee safety, Gemini adds reasoning.

Every prompt is PII-masked (app.privacy) before it leaves the process.
"""
from app import privacy
from app.engine import genai, ot, signals

SYSTEM = (
    "You are a senior SOC (security operations) analyst writing work notes for "
    "an incident case file. You are given a correlated security incident and its "
    "alerts. Write concise analyst work notes in plain English with four short "
    "parts, each labelled: SUMMARY (2-3 sentences telling what happened as an "
    "attack story), TECHNIQUES (the MITRE ATT&CK techniques involved), WHY "
    "ESCALATED (why a human must look), NEXT ACTIONS (the immediate containment "
    "steps). Keep the whole note under 160 words. Base every statement only on "
    "the alerts provided. Do not invent indicators, hostnames or IPs. If an alert "
    "involves operational technology (a PLC, RTU, HMI, SCADA or other plant "
    "system), never recommend isolating, restarting or reloading it: recommend "
    "calling the control room and containing on the IT side of the boundary."
)


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
    """Notes built from the evidence alone, for when no model is reachable."""
    escalated = [m for m in members if m["verdict"].get("escalate")]
    titles = "; ".join(m["alert"]["title"] for m in escalated) or "no escalations"
    seen = []
    for m in escalated:
        for sig in signals.hard_signals(m["alert"]):
            if sig not in seen:
                seen.append(sig)
    if seen:
        why = ("these alerts carried risk signals that are never closed automatically: "
               + ", ".join(seen[:6]) + ".")
    else:
        why = ("no single alert was conclusive, but together they form a pattern on the same "
               "asset or account, so a person should decide.")
    plant = sorted({name for m in members for name in ot.assets(m["alert"])})
    if plant:
        nxt = (f"call the control room first. Do not isolate, restart or reload {', '.join(plant[:3])}. "
               f"Contain on the IT side of the boundary, preserve evidence, and reset the credentials involved.")
    else:
        nxt = ("isolate the affected asset, preserve evidence, reset involved credentials, "
               "and block external indicators at the perimeter.")
    return (
        f"SUMMARY: Triagle correlated {len(members)} related alerts across "
        f"{len(incident.get('sources', []))} security tools into one incident on "
        f"{incident.get('key')}. {len(escalated)} were escalated for review.\n"
        f"WHAT FIRED: {titles}.\n"
        f"WHY ESCALATED: {why}\n"
        f"NEXT ACTIONS: {nxt}"
    )


def work_notes(incident, members):
    """Returns (text, by_gemini: bool, provider_label: str). Never raises.
    provider_label is 'Gemini on Vertex AI', 'Gemini', or 'automated summary'."""
    user = _user_prompt(incident, members)
    mapping = {}
    system_m, mapping = privacy.mask(SYSTEM, mapping)
    user_m, mapping = privacy.mask(user, mapping)
    text, provider = genai.generate_prose(system_m, user_m, max_tokens=4096, temperature=0.2)
    if text:
        return privacy.unmask(text, mapping), True, genai.PROVIDER_LABEL.get(provider, "Gemini")
    return _fallback(incident, members), False, "automated summary"
