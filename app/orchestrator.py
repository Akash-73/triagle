"""
Triagle — orchestrator.

Takes a batch of raw alerts, normalizes them, then triages each. Two modes:
  - fast triage (engine.triage): single-pass conservative-closure verdict
  - agentic (agent.loop): full plan-act-observe investigation per alert

Correlation runs across the batch in both modes.
"""
import os
import json

from app.connectors.sources import normalize
from app.engine.triage import triage
from app.engine.correlate import correlate
from app.engine.relate import EntityIndex
from app.engine.tuning import analyze_rules
from app.engine.response import propose_actions
from app.engine import bursts, instructions

AGENTIC = os.environ.get("TRIAGLE_AGENTIC", "true").lower() == "true"
_ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples", "investigation_env.json")


def _load_env():
    try:
        return json.load(open(_ENV_PATH))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"entity_history": {}, "threat_intel": {}}


def process_batch(raw_alerts, decided=None, taught=None, overruled=None):
    """taught: the rules analysts have taught Triagle. overruled: closures a
    person checked and disagreed with, by alert id."""
    normalized = []
    for item in raw_alerts:
        try:
            normalized.append(normalize(item["source"], item["raw"], item.get("client", "Unknown")))
        except (ValueError, KeyError):
            continue

    alert_dicts = [a.to_dict() for a in normalized]
    verdicts = {}
    trails = {}
    index = EntityIndex(alert_dicts)          # built once, shared by every investigation

    if AGENTIC:
        from app.agent.loop import investigate
        env = _load_env()
        for a in alert_dicts:
            v, trail = investigate(a, alert_dicts, env.get("entity_history"), env.get("threat_intel"),
                                   index=index)
            verdicts[a["alert_id"]] = v
            trails[a["alert_id"]] = trail
    else:
        for a in normalized:
            verdicts[a.alert_id] = triage(a).to_dict()
            trails[a.alert_id] = []

    # Where a person has spoken, that stands: a rule they taught closes what
    # it covers, and a closure they disagreed with goes back to the queue.
    taught_used = instructions.apply(alert_dicts, verdicts, taught, overruled)

    # One event that the tool reported as many alerts is raised once.
    folded = bursts.fold(alert_dicts, verdicts, trails)

    incidents = correlate(normalized, verdicts)
    rule_health = analyze_rules(alert_dicts, verdicts)

    # Stage response actions (pending human approval) for escalated threats
    actions = {}
    for a in alert_dicts:
        proposed = propose_actions(a, verdicts.get(a["alert_id"], {}), decided)
        if proposed:
            actions[a["alert_id"]] = [p.to_dict() for p in proposed]

    total = len(normalized)
    escalated = sum(1 for v in verdicts.values() if v.get("escalate"))
    auto_closed = sum(1 for v in verdicts.values() if v.get("closure_code") and not v.get("escalate"))
    true_positives = sum(1 for v in verdicts.values() if v.get("disposition") == "true_positive")
    noise_reduced_pct = round((auto_closed / total) * 100) if total else 0

    return {
        "alerts": alert_dicts,
        "verdicts": verdicts,
        "trails": trails,
        "incidents": incidents,
        "rule_health": rule_health,
        "actions": actions,
        "index": index,
        "taught_used": taught_used,
        "metrics": {
            "total": total, "escalated": escalated, "auto_closed": auto_closed,
            "true_positives": true_positives, "noise_reduced_pct": noise_reduced_pct,
            "incident_count": len(incidents),
            "elevated_incidents": sum(1 for i in incidents if i["elevated"]),
            "flagged_rules": sum(1 for r in rule_health if r["flagged"]),
            "staged_actions": sum(len(v) for v in actions.values()),
            "agentic": AGENTIC, "folded": folded,
            "taught_closed": sum(u["count"] for u in taught_used.values()),
        },
    }
