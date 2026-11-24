"""
Triagle — bursts: one event, raised once.

One software update writes two dozen package-manager alerts in a minute. One
deployment deletes eleven monitored files in a second. To the tool these are
dozens of alerts; to a person they are one thing to confirm. Left alone they
bury the alert that matters.

This pass runs after every alert has its verdict. It looks only at alerts
Triagle could not decide ("needs a person") that carry no risk term, no
suspicious behaviour and no high rating from the tool. When several of those
on the same machine have the same cause within a few minutes, the earliest
one stays open and says how many it stands for. The others are closed as
"already raised", pointing at it.

What this never does:
  - close the event. A person still decides it, once.
  - touch an alert that was escalated on evidence (a risk term, a behaviour,
    a pattern across alerts, a high or critical rating), or anything about
    operational technology. Those are each raised on their own.
  - fold across machines, customers or tools.

Settings
  TRIAGLE_BURST_MINUTES   longest gap between two alerts of one burst (default 10)
"""
import os
from collections import defaultdict

from app.engine import ot, signals, usecases
from app.engine.relate import parse_ts

MAX_SPAN_SECONDS = 3600          # a burst never stretches past an hour; after that it is raised again
ITEMS_SHOWN = 12

_FAMILY_WORDS = {
    "package_change": ("package-manager events", "Software packages changed"),
    "file_integrity": ("file-change events", "Monitored files changed"),
}


def gap_seconds():
    try:
        return max(1.0, float(os.environ.get("TRIAGLE_BURST_MINUTES", "10"))) * 60
    except ValueError:
        return 600.0


def _eligible(alert, verdict):
    """Undecided, and nothing about it says attack."""
    if not verdict.get("escalate") or verdict.get("disposition") != "needs_human" or verdict.get("pattern"):
        return False
    if str(alert.get("raw_severity") or "").lower() in ("high", "critical"):
        return False
    if signals.kind(alert) != signals.ACTIVITY or ot.involved(alert):
        return False
    if signals.hard_signals(alert) or signals.matched_behaviours(alert) or signals.matched_terms(alert) \
            or signals.suspicious_terms(alert) or signals.sensitive_terms(alert):
        return False
    return bool(alert.get("host") or alert.get("entity"))


def _key(alert):
    family = usecases.change_family(alert)
    host = str(alert.get("host") or alert.get("entity") or "").lower()
    return (alert.get("client"), alert.get("source"), host, family or str(alert.get("title") or "").strip().lower()), family


def _span_words(seconds):
    if seconds < 60:
        return "under a minute"
    if seconds < 3600:
        m = round(seconds / 60)
        return f"{m} minute{'s' if m != 1 else ''}"
    return "an hour"


def _items(family, members):
    """What changed, by name: packages or file paths, in order, without repeats."""
    field = "package" if family == "package_change" else "target_file"
    seen, out = set(), []
    for a in members:
        name = str((a.get("indicators") or {}).get(field) or "").strip()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _file_counts(members):
    deleted = sum(1 for a in members if "deleted" in str(a.get("title") or "").lower())
    added = sum(1 for a in members if "added" in str(a.get("title") or "").lower())
    changed = len(members) - deleted - added
    parts = [f"{n} {word}" for n, word in ((deleted, "deleted"), (changed, "changed"), (added, "added")) if n]
    return ", ".join(parts)


def _raise_once(run, family, verdicts, trails):
    members = [a for _, a in run]
    first, n = members[0], len(members)
    host = first.get("host") or first.get("entity")
    span = _span_words(run[-1][0] - run[0][0])
    items = _items(family, members)
    named = (" (" + ", ".join(items[:6]) + (f" and {len(items) - 6} more" if len(items) > 6 else "") + ")") if items else ""

    v = verdicts[first["alert_id"]]
    if family == "package_change":
        v["summary"] = f"Software packages changed on {host}: {n} events in {span}, raised once."
        v["reasoning"] = (f"{n} package-manager events on {host} in {span}{named}. They are one change for a "
                          f"person to confirm, so it is raised here once and the other {n - 1} are counted under it. "
                          f"Triagle does not close a software change on a server by itself: it cannot tell a "
                          f"planned update from someone installing a tool.")
        v["recommended_actions"] = ["Confirm the change was planned: who ran it, and from which session.",
                                    "If nobody did, treat the host as tampered with and check what was installed."]
    elif family == "file_integrity":
        v["summary"] = f"Monitored files changed on {host}: {_file_counts(members)} in {span}, raised once."
        v["reasoning"] = (f"{n} file-change events on {host} in {span}{named}. They are one change for a "
                          f"person to confirm, so it is raised here once and the other {n - 1} are counted under it. "
                          f"Triagle does not close a change to monitored files by itself: a deployment and an "
                          f"intruder covering tracks look the same from here.")
        v["recommended_actions"] = ["Match the files against a planned change: a deployment, an update or an administrator's edit.",
                                    "If nothing explains it, compare the files with a known-good copy."]
    else:
        v["summary"] = f"{str(first.get('title') or 'Alert').rstrip('.')}: {n} times on {host} in {span}, raised once."
        v["reasoning"] = (f"The same alert fired {n} times on {host} in {span}. It is raised here once and the "
                          f"other {n - 1} are counted under it. " + str(v.get("reasoning") or ""))
    v["basis"] = "correlation"
    v["burst"] = {"count": n, "span": span, "kind": family or "same_alert", "items": items[:ITEMS_SHOWN],
                  "more": max(0, len(items) - ITEMS_SHOWN), "member_ids": [a["alert_id"] for a in members[1:]]}
    if trails is not None:
        trails.setdefault(first["alert_id"], []).append({
            "tool": "burst",
            "result_summary": f"{n - 1} more alert(s) with the same cause on {host} in {span}. Raised once, here."})

    what = _FAMILY_WORDS.get(family, ("alerts with the same name", ""))[0]
    for a in members[1:]:
        old = verdicts[a["alert_id"]]
        verdicts[a["alert_id"]] = {
            **old,
            "disposition": "benign", "closure_code": "BENIGN_DUPLICATE", "confidence": 90, "severity": "low",
            "escalate": False, "basis": "correlation", "duplicate_of": first["alert_id"],
            "summary": f"One of {n} {what} on {host}. Raised once, on the first.",
            "reasoning": (f"This alert has the same cause, machine and tool as {n - 1} others in {span}. "
                          f"They are one event for a person to judge, so it is decided on the earliest one "
                          f"and this one is not raised again."),
            "recommended_actions": ["No separate action. Decide it on the alert that raised the burst."],
            "tuning_recommendation": None,
        }
    return n - 1


def fold(alerts, verdicts, trails=None):
    """Fold bursts in place. Returns how many alerts were folded into another."""
    gap = gap_seconds()
    groups = defaultdict(list)
    family_of = {}
    for a in alerts:
        v = verdicts.get(a["alert_id"])
        if not v or not _eligible(a, v):
            continue
        t = parse_ts(a.get("timestamp"))
        if t is None:
            continue
        key, family = _key(a)
        groups[key].append((t, a))
        family_of[key] = family

    folded = 0
    for key, items in groups.items():
        if len(items) < 2:
            continue
        items.sort(key=lambda x: (x[0], x[1]["alert_id"]))
        run = [items[0]]
        for it in items[1:]:
            if it[0] - run[-1][0] <= gap and it[0] - run[0][0] <= MAX_SPAN_SECONDS:
                run.append(it)
                continue
            if len(run) > 1:
                folded += _raise_once(run, family_of[key], verdicts, trails)
            run = [it]
        if len(run) > 1:
            folded += _raise_once(run, family_of[key], verdicts, trails)
    return folded
