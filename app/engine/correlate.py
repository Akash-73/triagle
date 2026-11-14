"""
Triagle — correlation engine.

Individual verdicts are useful, but the real analyst skill is seeing that
five separate alerts are one attack. This groups a client's alerts that are
linked through shared entities (host, user, IP) into incidents.

Linking is transitive: if alert A shares a host with B, and B shares a user
with C, all three are one incident, reported once. Alerts from different
clients are never linked, even if they share an IP or a username.
"""
from collections import defaultdict, Counter

# generic identifiers that appear across unrelated alerts and must NOT be
# used to correlate — they'd produce false attack-chains.
GENERIC_ENTITIES = {"system", "admin", "administrator", "n/a", "unknown", "-",
                    "multiple", "localsystem", "network service"}


def _entities(alert):
    vals = set()
    for v in (alert.host, alert.user, alert.src_ip, getattr(alert, "dst_ip", None)):
        if v and str(v).strip().lower() not in GENERIC_ENTITIES:
            vals.add(str(v))
    return vals


def correlate(alerts):
    """
    Returns a list of incidents. Each:
      { "key": primary entity, "client": str, "entities": [...],
        "alert_ids": [...], "sources": [...], "size": int, "elevated": bool }
    'elevated' = the incident spans 2+ different source tools.
    """
    parent = list(range(len(alerts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    first_seen = {}
    for i, a in enumerate(alerts):
        for e in _entities(a):
            k = (a.client, e.lower())
            if k in first_seen:
                parent[find(i)] = find(first_seen[k])
            else:
                first_seen[k] = i

    groups = defaultdict(list)
    for i, a in enumerate(alerts):
        groups[find(i)].append(a)

    incidents = []
    for group in groups.values():
        if len(group) < 2:
            continue
        counts = Counter()
        hosts = Counter()
        for a in group:
            for e in _entities(a):
                counts[e] += 1
            if a.host and str(a.host).lower() not in GENERIC_ENTITIES:
                hosts[a.host] += 1
        # name the incident after the internal asset seen most, else the commonest entity
        key = (hosts.most_common(1) or counts.most_common(1))[0][0]
        sources = sorted({a.source for a in group})
        incidents.append({
            "key": key,
            "client": group[0].client,
            "entities": [e for e, _ in counts.most_common()],
            "alert_ids": sorted(a.alert_id for a in group),
            "sources": sources,
            "size": len(group),
            "elevated": len(sources) >= 2,
        })

    incidents.sort(key=lambda i: (not i["elevated"], -i["size"]))
    return incidents
