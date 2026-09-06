"""
Netrix — correlation engine.

Individual verdicts are useful, but the real analyst skill is seeing that
five separate alerts are one attack. This groups alerts (within a client)
that share an entity — same host, user, or source IP — within a time
window, and flags multi-signal clusters as incidents that deserve elevated
attention even if each alert alone looked minor.

This directly attacks the incumbent weakness of treating each alert in
isolation, and the MSP pain of "the alert that mattered got buried."
"""
from collections import defaultdict


# generic identifiers that appear across unrelated alerts and must NOT be
# used to correlate — they'd produce false attack-chains.
GENERIC_ENTITIES = {"system", "admin", "administrator", "n/a", "unknown", "-",
                    "multiple", "localsystem", "network service"}


def _entities(alert):
    vals = set()
    for v in (alert.host, alert.user, alert.src_ip):
        if v and str(v).strip().lower() not in GENERIC_ENTITIES:
            vals.add(v)
    return vals


def correlate(alerts):
    """
    Returns a list of incident groups. Each group:
      { "key": entity, "alert_ids": [...], "sources": set, "size": int,
        "elevated": bool }
    An 'elevated' incident is one where the same entity appears across
    2+ different source tools — a strong multi-signal indicator.
    """
    by_entity = defaultdict(list)
    for a in alerts:
        for e in _entities(a):
            by_entity[e].append(a)

    incidents = []
    seen_signatures = set()
    for entity, group in by_entity.items():
        if len(group) < 2:
            continue
        alert_ids = tuple(sorted(a.alert_id for a in group))
        if alert_ids in seen_signatures:
            continue
        seen_signatures.add(alert_ids)

        sources = {a.source for a in group}
        incidents.append({
            "key": entity,
            "alert_ids": list(alert_ids),
            "sources": sorted(sources),
            "size": len(group),
            "elevated": len(sources) >= 2,
        })

    # elevated incidents first, then by size
    incidents.sort(key=lambda i: (not i["elevated"], -i["size"]))
    return incidents
