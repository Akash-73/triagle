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
from app.engine.relate import EntityIndex, GENERIC_ENTITIES, entity_values


class InvestigationContext:
    """Holds everything the agent knows so far about one investigation."""
    def __init__(self, focus_alert, all_alerts, entity_history=None, threat_intel=None, index=None):
        self.focus_alert = focus_alert          # the alert being investigated (dict)
        self.all_alerts = all_alerts            # every normalized alert in the batch (list of dict)
        self.entity_history = entity_history or {}   # synthetic per-entity history
        self.threat_intel = threat_intel or {}       # synthetic TI lookups
        self.evidence = []                      # accumulated findings from tool calls
        self.steps = []                         # audit trail of what the agent did
        self._index = index                     # shared across a batch; built on demand otherwise
        self._related = None

    def related(self):
        """(notable related alerts in the window, routine count). One tenant's
        alerts are never used to investigate another's: the index is keyed by client."""
        if self._related is None:
            if self._index is None:
                self._index = EntityIndex(self.all_alerts)
            self._related = self._index.related(self.focus_alert)
        return self._related

    @property
    def hours(self):
        self.related()
        return self._index.hours

    def strong_count(self):
        self.related()
        return self._index.strong_count(self.focus_alert)

    def record(self, tool, args, result):
        self.steps.append({"tool": tool, "args": args, "result_summary": result.get("summary", "")})
        self.evidence.append(result)


def _entity_values(alert):
    return entity_values(alert)


def _span(hours):
    return f"{hours:g} h" if hours else "any time"


def _indicators_to_check(alert):
    ind = alert.get("indicators", {}) or {}
    out = []
    for v in (ind.get("sha256"), ind.get("domain"), alert.get("dst_ip"), alert.get("src_ip")):
        if v and v not in out:
            out.append(v)
    return out


# ---- The tools -----------------------------------------------------------

MAX_LISTED = 25      # evidence handed to the planner / shown in the trail


def tool_related_alerts(ctx, args):
    """Find other alerts of note in the environment sharing an entity with the focus."""
    notable, routine = ctx.related()
    related = [{
        "alert_id": a["alert_id"], "title": a["title"],
        "source": a["source"], "timestamp": a.get("timestamp"),
        "entity": a.get("entity"),
    } for a in notable[:MAX_LISTED]]
    summary = (f"Found {len(notable)} related alert(s) sharing an entity with the focus alert "
               f"within {_span(ctx.hours)}.")
    if routine:
        summary += f" {routine} routine event(s) on the same entities were not counted."
    return {
        "tool": "related_alerts",
        "summary": summary,
        "data": related,
        "notable_count": len(notable),
        "strong_count": ctx.strong_count(),     # of those, sharing an account or address
        "routine_count": routine,
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
    """Check the alert's indicators (hash / domain / IPs) against threat intelligence."""
    wanted = [args["indicator"]] if args.get("indicator") else _indicators_to_check(ctx.focus_alert)
    checked = []
    for indicator in wanted:
        checked.append(indicator)
        hit = ctx.threat_intel.get(indicator)
        if hit:
            return {
                "tool": "threat_intel",
                "summary": f"Threat intel MATCH on {indicator}: {hit}",
                "data": {"indicator": indicator, "match": hit, "checked": checked},
            }
    return {
        "tool": "threat_intel",
        "summary": ("No threat-intel match for " + ", ".join(checked) + "." if checked
                    else "No indicators on this alert to check."),
        "data": {"indicator": None, "match": None, "checked": checked},
    }


def tool_timeline(ctx, args):
    """Build a chronological timeline of the focus + related alerts of note."""
    notable, _ = ctx.related()
    events = [{"timestamp": a.get("timestamp"), "title": a["title"], "source": a["source"]}
              for a in [ctx.focus_alert] + notable[:MAX_LISTED]]
    events.sort(key=lambda e: e.get("timestamp") or "")
    return {
        "tool": "timeline",
        "summary": f"Assembled a {len(events)}-event timeline across the involved entities.",
        "data": events,
    }


TOOL_REGISTRY = {
    "related_alerts": {
        "fn": tool_related_alerts,
        "description": "Find other alerts of note involving the same host, user, or IP as the alert under investigation, within the correlation window. Routine telemetry is counted but not listed. Use to see if this alert is part of a larger pattern.",
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
