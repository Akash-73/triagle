"""
Triagle — correlation engine.

Individual verdicts are useful, but the real analyst skill is seeing that
five separate alerts are one attack. This groups a client's alerts that are
linked through shared entities (host, user, IP) into incidents.

Linking is transitive: if alert A shares a host with B, and B shares a user
with C, all three are one incident, reported once. Alerts from different
clients are never linked, even if they share an IP or a username.

Two limits keep an incident meaning something on a live stream:

  - Only alerts that were escalated can be members. A laptop's routine logons
    share a host with the attack on it, but they are context, not the incident.
  - Two alerts are linked only if they are within the correlation window of
    each other (TRIAGLE_CORRELATION_HOURS, 24 by default). An incident can run
    longer than the window as long as each step follows the last within it.
  - Sharing an account or an address links any two escalated alerts. Sharing
    only a host links them when both are notable in their own right. A package
    install on a server is not part of the brute-force attempt against it just
    because both happened on that server.
"""
import hashlib
from collections import defaultdict, Counter

from app.engine import signals
from app.engine.relate import GENERIC_ENTITIES, parse_ts, window_hours

__all__ = ["correlate", "GENERIC_ENTITIES"]


def _entities(alert):
    vals = set()
    for v in (alert.host, alert.user, alert.src_ip, getattr(alert, "dst_ip", None)):
        if v and str(v).strip().lower() not in GENERIC_ENTITIES:
            vals.add(str(v))
    return vals


def correlate(alerts, verdicts=None, hours=None):
    """
    Returns a list of incidents. Each:
      { "id": stable reference, "key": primary entity, "client": str,
        "entities": [...], "alert_ids": [...], "sources": [...], "size": int,
        "elevated": bool, "first_seen": iso, "last_seen": iso }
    'elevated' = the incident spans 2+ different source tools.

    verdicts: {alert_id: verdict dict}. When given, only escalated alerts are
    linked. When omitted (older callers), every alert can be a member.
    """
    window = (window_hours() if hours is None else hours) * 3600
    if verdicts is not None:
        members = [a for a in alerts if (verdicts.get(a.alert_id) or {}).get("escalate")]
    else:
        members = list(alerts)
    times = [parse_ts(a.timestamp) for a in members]
    order = sorted(range(len(members)), key=lambda i: (times[i] is None, times[i] or 0.0, i))

    parent = list(range(len(members)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    selective = verdicts is not None
    notable = [signals.is_notable(a) if selective else True for a in members]

    def strong(a):
        return {str(v) for v in (a.user, a.src_ip, getattr(a, "dst_ip", None))
                if v and str(v).strip().lower() not in GENERIC_ENTITIES}

    last_seen = {}                       # (client, entity) -> index of the latest member that may link on it
    for i in order:
        a = members[i]
        by_account_or_address = strong(a)
        for e in _entities(a):
            if not notable[i] and e not in by_account_or_address:
                continue                 # only the host in common, and nothing notable about this alert
            k = (a.client, e.lower())
            j = last_seen.get(k)
            if j is not None:
                near = (times[i] is None or times[j] is None or not window
                        or times[i] - times[j] <= window)
                if near:
                    parent[find(i)] = find(j)
            last_seen[k] = i

    groups = defaultdict(list)
    for i in order:
        groups[find(i)].append(members[i])

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
        first = group[0]                 # groups are filled in time order
        ref = hashlib.sha1(f"{first.client}|{first.alert_id}".encode(), usedforsecurity=False).hexdigest()[:6].upper()
        incidents.append({
            "id": f"INC-{ref}",
            "key": key,
            "client": first.client,
            "entities": [e for e, _ in counts.most_common()],
            "alert_ids": sorted(a.alert_id for a in group),
            "sources": sources,
            "size": len(group),
            "elevated": len(sources) >= 2,
            "first_seen": first.timestamp,
            "last_seen": group[-1].timestamp,
        })

    incidents.sort(key=lambda i: (not i["elevated"], -i["size"]))
    return incidents
