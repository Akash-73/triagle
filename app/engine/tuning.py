"""
Triagle — which detection rules to tune, and which to leave alone.

Triage deals with one alert. This looks at the rule behind it: how the tool
rates the rule, how many of its alerts went to a person, how many Triagle
closed, and for what reason. It answers one question for whoever looks after
the detections: where is the tool asking for attention it does not deserve?

A real feed has several kinds of rule in it, and only one is a tuning
candidate:

  keep      some of its alerts went to a person. A rule that catches things
            is left alone, however often it also fires for nothing.
  tune      every alert was closed, and either the tool rates the rule medium
            or higher, or the alerts were all one recognised harmless thing.
            The record says what they had in common and what to change.
  record    the tool itself rates the rule low and every alert was routine: a
            sign-in, a session closing, an administrator using sudo. That is
            an audit trail doing its job. There is nothing to tune.
  health, posture
            not detections at all by the tool's own classification.
  few       fired once or twice. Too few to say anything.

Two rules about counting:

  - An alert counted under another one belongs to that event and is never
    called noise: a member of a burst, a repeat of a password-guessing
    address already raised, the earlier failed sign-ins from that address.
  - What a person decided outranks what Triagle did. Alerts a person marked
    as false positives make the rule a candidate. Alerts a person confirmed
    as expected do not, unless they also taught Triagle to close the same
    alert from then on (instructions.py) and it has: then the tool is asking
    for attention a person has already said it does not deserve, and the
    lasting fix is in the tool.

This only ever flags. Triagle never switches a rule off: a noisy rule can
still catch the one real attack.
"""
from collections import Counter, defaultdict

from app.engine import sources_meta
from app.engine.relate import sign_in

# A rule must fire at least this many times before it is judged on volume.
MIN_VOLUME_TO_JUDGE = 3

RAISED, EXPECTED, FALSE, CLOSED = "raised", "expected", "false", "closed"
TUNE, KEEP, RECORD, HEALTH, POSTURE, FEW = "tune", "keep", "record", "health", "posture", "few"
_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_ORDER = {TUNE: 0, KEEP: 1, EXPECTED: 2, FEW: 3, RECORD: 4, HEALTH: 4, POSTURE: 4}
_GUESSING = ("password_guessing", "guessing_then_success")


def _rule_key(alert):
    """The detection rule behind an alert: the tool and the rule's name."""
    return f"{alert.get('source', 'unknown')} :: {alert.get('title', 'unknown')}"


def _own_bucket(verdict):
    """What became of an alert on its own account."""
    if not verdict.get("escalate"):
        return CLOSED
    outcome = (verdict.get("resolved") or {}).get("outcome")
    return {"expected": EXPECTED, "false_positive": FALSE}.get(outcome, RAISED)


def _buckets(alerts, verdicts):
    """alert id -> (bucket, counted under another alert?)."""
    raised_for = {}                      # (customer, address) -> the verdict that raised its guessing
    for a in alerts:
        v = verdicts.get(a["alert_id"]) or {}
        if v.get("escalate") and v.get("pattern") in _GUESSING and a.get("src_ip"):
            raised_for.setdefault((a.get("client"), a.get("src_ip")), v)

    out = {}
    for a in alerts:
        v = verdicts.get(a["alert_id"]) or {}
        if v.get("escalate"):
            out[a["alert_id"]] = (_own_bucket(v), False)
            continue
        parent = None
        if v.get("duplicate_of"):
            parent = verdicts.get(v["duplicate_of"])
        elif a.get("src_ip") and sign_in(a) == "failed":
            parent = raised_for.get((a.get("client"), a.get("src_ip")))
        if parent and parent.get("escalate"):
            out[a["alert_id"]] = (_own_bucket(parent), True)
        elif v.get("closure_code") == "BENIGN_DUPLICATE":
            out[a["alert_id"]] = (RAISED, True)      # already raised; that alert has since left the queue
        else:
            out[a["alert_id"]] = (CLOSED, False)
    return out


def _first_sentence(text):
    text = " ".join(str(text or "").split())
    first = text.split(". ", 1)[0].strip()
    return first if not first or first.endswith((".", "!", "?")) else first + "."


def _plural(n, one, many):
    return one if n == 1 else many


def _went_to_a_person(s):
    """How a rule's alerts reached a person, in a sentence."""
    n, under = s["volume"], s["under_raised"]
    own = s[RAISED] - under
    if own and under:
        return (f"{own} went to a person and {under} more {_plural(under, 'is', 'are')} "
                f"counted under {_plural(own, 'it', 'them')}.")
    if own == n:
        return _plural(n, "Its one alert went to a person.", f"All {n} of its alerts went to a person.")
    if own:
        return f"{own} of its {n} alerts went to a person."
    if under == n:
        return _plural(n, "Its one alert is", f"All {n} of its alerts are") + " counted under an alert that went to a person."
    return f"{under} of its {n} alerts are counted under an alert that went to a person."


def _closed_because(s):
    """What the closed alerts had in common, in a sentence."""
    n = s["volume"]
    reason, share = s["reasons"].most_common(1)[0] if s["reasons"] else ("", 0)
    if share != n:
        return f"{share} of the {n} were closed for this reason: {reason}"
    if n == 1:
        return f"It was closed for this reason: {reason}"
    return f"{'Both' if n == 2 else f'All {n}'} were closed for the same reason: {reason}"


def _advice(s):
    """(kind, what to do) for one rule."""
    n, tool, rating = s["volume"], sources_meta.source_name(s["source"]), s["rating"]
    level = f" (level {s['level']})" if s["level"] else ""

    if s[FALSE]:
        k = s[FALSE]
        return TUNE, (f"A person marked {k} of these as {_plural(k, 'a false positive', 'false positives')}. "
                      f"Narrow the rule in {tool}, starting from what "
                      f"{_plural(k, 'that alert shows', 'those alerts have in common')}.")
    if s[RAISED]:
        return KEEP, "Keep it. " + _went_to_a_person(s)
    if s["taught"]:
        k, hosts = s["taught"], ", ".join(sorted(s["taught_hosts"])[:3])
        if s["source"] == "wazuh" and s["rule_id"]:
            how = (f"To stop them at the source, add a child rule of {s['rule_id']} at level 0 in Wazuh "
                   f"for that machine. The rule stays as it is for everything else.")
        else:
            how = f"To stop them at the source, add an exception for that machine in {tool}."
        return TUNE, (f"A person taught Triagle to close this on {hosts}, and it has closed {k} since. {how}")
    if s[EXPECTED]:
        return EXPECTED, "A person confirmed this as expected activity. Nothing to tune."

    # from here on every alert was closed by Triagle
    top_code = s["codes"].most_common(1)[0][0] if s["codes"] else ""
    if top_code == "OPERATIONAL_EVENT":
        return HEALTH, "A health event, not a detection. Triagle closes it for the SOC. It belongs with IT operations."
    if top_code == "POSTURE_FINDING":
        return POSTURE, ("A posture finding, not activity. Send benchmark and vulnerability results to a "
                         "posture report, not the alert queue.")

    specific = s["specific"] == n                  # each closure named a known tool or a recognised artifact
    if specific and (n >= MIN_VOLUME_TO_JUDGE or _RANK[rating] >= _RANK["high"]):
        if s["source"] == "wazuh" and s["rule_id"]:
            how = (f"In Wazuh, a child rule of {s['rule_id']} at level 0 for that case removes it "
                   f"and keeps the rule for everything else.")
        else:
            how = f"In {tool}, add an exception for that case and keep the rule for everything else."
        return TUNE, f"{tool} rates this {rating}{level}. {_closed_because(s)} {how}"
    if _RANK[rating] >= _RANK["medium"] and n >= MIN_VOLUME_TO_JUDGE:
        return TUNE, (f"{tool} rates this {rating}{level}, and Triagle closed every one. {_closed_because(s)} "
                      f"Check them, then lower the rule's rating or narrow it in {tool}.")
    if _RANK[rating] == 0:
        return RECORD, "A record of normal activity, rated low by the tool. Nothing to tune."
    times = "once" if n == 1 else "twice" if n == 2 else f"{n} times"
    return FEW, f"Fired {times}, closed each time. Too few to judge."


def analyze_rules(alerts, verdicts):
    """One record per detection rule, candidates for tuning first:
      { rule, title, source, rule_id, level, rating, volume, to_person, under,
        closed, kind, flagged, recommendation }
    to_person counts alerts that went to a person, including those counted
    under another alert; closed counts alerts Triagle closed with a reason."""
    buckets = _buckets(alerts, verdicts)
    stats = defaultdict(lambda: {"volume": 0, RAISED: 0, EXPECTED: 0, FALSE: 0, CLOSED: 0, "under": 0,
                                 "under_raised": 0, "rating": "low", "levels": set(), "ids": set(),
                                 "codes": Counter(), "reasons": Counter(), "specific": 0,
                                 "taught": 0, "taught_hosts": set(),
                                 "title": "", "source": ""})
    for a in alerts:
        v = verdicts.get(a["alert_id"]) or {}
        s = stats[_rule_key(a)]
        s["volume"] += 1
        s["title"], s["source"] = a.get("title", "unknown"), a.get("source", "unknown")
        rated = str(a.get("raw_severity") or "low").lower()
        if _RANK.get(rated, 0) > _RANK[s["rating"]]:
            s["rating"] = rated
        ind = a.get("indicators") or {}
        if ind.get("rule_level"):
            s["levels"].add(str(ind["rule_level"]))
        if ind.get("rule_id"):
            s["ids"].add(str(ind["rule_id"]))
        bucket, under = buckets[a["alert_id"]]
        s[bucket] += 1
        if under:
            s["under"] += 1
            if bucket == RAISED:
                s["under_raised"] += 1
        if bucket == CLOSED and v.get("instruction"):
            s["taught"] += 1
            s["taught_hosts"].add(str(a.get("host") or a.get("entity") or ""))
        if bucket == CLOSED:
            s["codes"][v.get("closure_code") or ""] += 1
            s["reasons"][_first_sentence(v.get("reasoning") or v.get("summary"))] += 1
            if v.get("tuning_recommendation") and v.get("closure_code") == "BENIGN_KNOWN_TOOL":
                s["specific"] += 1

    records = []
    for rule, s in stats.items():
        s["level"] = next(iter(s["levels"])) if len(s["levels"]) == 1 else ""
        s["rule_id"] = next(iter(s["ids"])) if len(s["ids"]) == 1 else ""
        kind, advice = _advice(s)
        records.append({
            "rule": rule, "title": s["title"], "source": s["source"], "rule_id": s["rule_id"], "level": s["level"],
            "rating": s["rating"], "volume": s["volume"],
            "to_person": s[RAISED] + s[EXPECTED] + s[FALSE], "under": s["under"], "closed": s[CLOSED],
            "kind": kind, "flagged": kind == TUNE, "recommendation": advice,
        })
    records.sort(key=lambda r: (_ORDER[r["kind"]], -_RANK[r["rating"]] if r["kind"] == TUNE else 0,
                                -r["to_person"] if r["kind"] == KEEP else 0, -r["volume"], r["title"]))
    return records
