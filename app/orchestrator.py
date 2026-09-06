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
from app.engine.tuning import analyze_rules
from app.engine.response import propose_actions

AGENTIC = os.environ.get("TRIAGLE_AGENTIC", "true").lower() == "true"
_ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples", "investigation_env.json")


def _load_env():
    try:
        return json.load(open(_ENV_PATH))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"entity_history": {}, "threat_intel": {}}


def process_batch(raw_alerts):
    normalized = []
    for item in raw_alerts:
        try:
            normalized.append(normalize(item["source"], item["raw"], item.get("client", "Unknown")))
        except (ValueError, KeyError):
            continue

    alert_dicts = [a.to_dict() for a in normalized]
    verdicts = {}
    trails = {}

    if AGENTIC:
        from app.agent.loop import investigate
        env = _load_env()
        for a in alert_dicts:
            v, trail = investigate(a, alert_dicts, env.get("entity_history"), env.get("threat_intel"))
            verdicts[a["alert_id"]] = v
            trails[a["alert_id"]] = trail
    else:
        for a in normalized:
            verdicts[a.alert_id] = triage(a).to_dict()
            trails[a.alert_id] = []

    incidents = correlate(normalized)
    rule_health = analyze_rules(alert_dicts, verdicts)

    # Stage response actions (pending human approval) for escalated threats
    actions = {}
    for a in alert_dicts:
        proposed = propose_actions(a, verdicts.get(a["alert_id"], {}))
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
        "metrics": {
            "total": total, "escalated": escalated, "auto_closed": auto_closed,
            "true_positives": true_positives, "noise_reduced_pct": noise_reduced_pct,
            "incident_count": len(incidents),
            "elevated_incidents": sum(1 for i in incidents if i["elevated"]),
            "flagged_rules": sum(1 for r in rule_health if r["flagged"]),
            "staged_actions": sum(len(v) for v in actions.values()),
            "agentic": AGENTIC,
        },
    }
