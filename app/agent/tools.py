"""
Triagle Agentic — investigative tools.

This is what separates an *agentic* analyst from a single classification
call: the agent can autonomously call these tools to gather more evidence,
exactly as a human analyst pivots through data during an investigation.

Each tool takes the current investigation context and returns structured
evidence. In production these query real data sources (SIEM, EDR API,
identity provider, threat-intel feeds). Here they query the in-memory
environment (all alerts in the batch + synthetic entity history) so the
full agent loop is real and demoable without external dependencies.

The tool registry is passed to the reasoning layer, which decides WHICH
tool to call at each step — the agent plans, we don't hardcode the path.
"""
from datetime import datetime


class InvestigationContext:
    """Holds everything the agent knows so far about one investigation."""
    def __init__(self, focus_alert, all_alerts, entity_history=None, threat_intel=None):
        self.focus_alert = focus_alert          # the alert being investigated (dict)
        self.all_alerts = all_alerts            # every normalized alert in the batch (list of dict)
        self.entity_history = entity_history or {}   # synthetic per-entity history
        self.threat_intel = threat_intel or {}       # synthetic TI lookups
        self.evidence = []                      # accumulated findings from tool calls
        self.steps = []                         # audit trail of what the agent did

    def record(self, tool, args, result):
        self.steps.append({"tool": tool, "args": args, "result_summary": result.get("summary", "")})
        self.evidence.append(result)


# Generic identifiers that appear across unrelated alerts and must NOT be
# used to link them — otherwise every "system"/"admin" event falsely
# correlates. Mirrors the exclusion in engine/correlate.py.
GENERIC_ENTITIES = {"system", "admin", "administrator", "n/a", "unknown", "-",
                    "multiple", "localsystem", "network service"}


def _entity_values(alert):
    vals = set()
    for k in ("host", "user", "src_ip", "entity"):
        v = alert.get(k)
        if v and str(v).strip().lower() not in GENERIC_ENTITIES:
            vals.add(str(v))
    return vals


# ---- The tools -----------------------------------------------------------

def tool_related_alerts(ctx, args):
    """Find other alerts in the environment sharing an entity with the focus."""
    focus_entities = _entity_values(ctx.focus_alert)
    related = []
    for a in ctx.all_alerts:
        if a["alert_id"] == ctx.focus_alert["alert_id"]:
            continue
        if _entity_values(a) & focus_entities:
            related.append({
                "alert_id": a["alert_id"], "title": a["title"],
                "source": a["source"], "timestamp": a.get("timestamp"),
                "entity": a.get("entity"),
            })
    return {
        "tool": "related_alerts",
        "summary": f"Found {len(related)} related alert(s) sharing an entity with the focus alert.",
        "data": related,
    }


def tool_entity_history(ctx, args):
    """Look up recent behavioral history for an entity (host/user)."""
    entity = args.get("entity") or ctx.focus_alert.get("host") or ctx.focus_alert.get("user")
    hist = ctx.entity_history.get(entity, [])
    return {
        "tool": "entity_history",
        "summary": (f"Retrieved {len(hist)} historical event(s) for {entity}."
                    if hist else f"No prior history on record for {entity} (new/quiet entity)."),
        "data": {"entity": entity, "history": hist},
    }


def tool_threat_intel(ctx, args):
    """Check an indicator (IP / hash / domain) against threat intelligence."""
    indicator = args.get("indicator")
    if not indicator:
        # try to pull one from the focus alert
        ind = ctx.focus_alert.get("indicators", {})
        indicator = ind.get("sha256") or ctx.focus_alert.get("src_ip")
    hit = ctx.threat_intel.get(indicator)
    return {
        "tool": "threat_intel",
        "summary": (f"Threat intel MATCH on {indicator}: {hit}" if hit
                    else f"No threat-intel match for {indicator}."),
        "data": {"indicator": indicator, "match": hit},
    }


def tool_timeline(ctx, args):
    """Build a chronological timeline of the focus + related alerts."""
    focus_entities = _entity_values(ctx.focus_alert)
    events = []
    for a in ctx.all_alerts:
        if _entity_values(a) & focus_entities:
            events.append({"timestamp": a.get("timestamp"), "title": a["title"], "source": a["source"]})
    events.sort(key=lambda e: e.get("timestamp") or "")
    return {
        "tool": "timeline",
        "summary": f"Assembled a {len(events)}-event timeline across the involved entities.",
        "data": events,
    }


TOOL_REGISTRY = {
    "related_alerts": {
        "fn": tool_related_alerts,
        "description": "Find other alerts involving the same host, user, or IP as the alert under investigation. Use to see if this alert is part of a larger pattern.",
        "args": {},
    },
    "entity_history": {
        "fn": tool_entity_history,
        "description": "Get recent behavioral history for a host or user. Use to judge whether current activity is normal for this entity. Args: entity (optional).",
        "args": {"entity": "string (optional)"},
    },
    "threat_intel": {
        "fn": tool_threat_intel,
        "description": "Check an IP, file hash, or domain against threat intelligence. Use to confirm whether an indicator is known-malicious. Args: indicator (optional).",
        "args": {"indicator": "string (optional)"},
    },
    "timeline": {
        "fn": tool_timeline,
        "description": "Assemble a chronological timeline of all activity involving the entities in this alert. Use to understand attack sequence.",
        "args": {},
    },
}


def run_tool(name, ctx, args):
    spec = TOOL_REGISTRY.get(name)
    if not spec:
        return {"tool": name, "summary": f"Unknown tool '{name}'.", "data": None}
    result = spec["fn"](ctx, args or {})
    ctx.record(name, args, result)
    return result


def tools_manifest():
    """Human/LLM-readable description of available tools, for the planner."""
    return {name: spec["description"] for name, spec in TOOL_REGISTRY.items()}
