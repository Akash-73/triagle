"""
Triagle — rules a person has taught it.

The rules built into Triagle cannot know that on this customer's print server
a certain scheduled job is normal. The analyst knows. When they close an alert
Triagle sent them, as expected activity or as a false positive, they can add
"close the same thing from now on". That is a taught rule: the same detection
rule from the same tool, on the same machine and, if they choose, for the same
account.

What a taught rule can never do:

  - Close an alert raised on evidence: a risk signal on the alert itself, a
    known-bad address, a sign-in pattern (password guessing, a sign-in after
    it), anything about operational technology. It only ever applies to an
    alert Triagle sent to a person out of doubt: one it could not decide, one
    that only looked suspicious, or one raised because of the alerts near it.
  - Reach back. It applies to alerts dated after it was given.
  - Last for ever. It runs for a number of days and then stops, unless a
    person renews it. An exception nobody looks at again is how a real attack
    gets closed.
  - Rewrite the record. Switching a rule off stops it from that moment; what
    it closed while it was on stays closed. Renewing a rule that had stopped
    starts it again from now, and leaves the gap as it was. That is why a
    rule keeps a list of the periods it was in force ("windows").
  - Act silently. Every alert it closes says who taught the rule, when and why.

The other half lives here too: a person who checks a closure and disagrees
sends that alert back to the queue (see spotcheck.py for the checking).
"""
import datetime
import secrets

from app.engine import ot, signals
from app.engine.relate import parse_ts

DAYS = (7, 30, 90)
DEFAULT_DAYS = 30
OUTCOMES = ("expected", "false_positive")
_IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


def _iso(when):
    return when.astimezone(datetime.timezone.utc).isoformat(timespec="seconds")


def _day(iso):
    """A stored time as a date in India, e.g. 25 Nov 2026."""
    t = parse_ts(iso)
    if t is None:
        return str(iso or "")
    return datetime.datetime.fromtimestamp(t, _IST).strftime("%d %b %Y").lstrip("0")


def _host(alert):
    return str(alert.get("host") or alert.get("entity") or "").strip()


def _rule_id(alert):
    return str((alert.get("indicators") or {}).get("rule_id") or "").strip()


# What an escalation rests on when it is evidence and not doubt: a risk signal
# on the alert itself, a threat-intelligence match, the step that completes a
# pattern.
_EVIDENCE = ("signal", "intel", "sequence")


def _may_close(alert, verdict):
    """Did Triagle send this to a person out of doubt, not on evidence? Only
    those can be closed by a taught rule: an alert it could not decide, one
    that only looked suspicious by its wording or the tool's rating, or one
    raised because of the alerts around it."""
    if signals.hard_signals(alert) or ot.involved(alert) or verdict.get("pattern"):
        return False
    if verdict.get("basis") in _EVIDENCE:
        return False
    return verdict.get("disposition") in ("needs_human", "suspicious")


def teachable(alert, verdict):
    """Can a person teach Triagle to close this alert next time?"""
    return bool(verdict and verdict.get("escalate") and _host(alert) and _may_close(alert, verdict))


def make(alert, outcome, label, note, by, scope="machine", days=DEFAULT_DAYS, now=None):
    """A taught rule from the alert a person has just closed."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    days = days if days in DAYS else DEFAULT_DAYS
    return {
        "id": "TR-" + secrets.token_hex(3).upper(),
        "client": alert.get("client") or "", "source": alert.get("source") or "",
        "rule_id": _rule_id(alert), "title": alert.get("title") or "",
        "host": _host(alert), "user": str(alert.get("user") or "") if scope == "account" else "",
        "outcome": outcome, "label": label, "note": " ".join(str(note or "").split())[:300],
        "by": by, "at": _iso(now), "until": _iso(now + datetime.timedelta(days=days)), "days": days,
        "windows": [[_iso(now), _iso(now + datetime.timedelta(days=days))]],
        "from_alert": alert["alert_id"], "on": True,
    }


def switch_off(rule, by, now=None):
    """Stop the rule from now. What it closed while it was on stays closed."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    windows = rule.setdefault("windows", [[rule.get("at"), rule.get("until")]])
    end = parse_ts(windows[-1][1])
    if end is None or end > now.timestamp():
        windows[-1][1] = _iso(now)
    rule.update(on=False, until=windows[-1][1], off_by=by, off_at=_iso(now))


def renew(rule, by, days=DEFAULT_DAYS, now=None):
    """Run the rule for `days` more days from now. A rule that had stopped
    starts a new period, so nothing in the gap is closed after the fact."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    days = days if days in DAYS else DEFAULT_DAYS
    until = _iso(now + datetime.timedelta(days=days))
    windows = rule.setdefault("windows", [[rule.get("at"), rule.get("until")]])
    if state(rule, now.timestamp()) == "on":
        windows[-1][1] = until
    else:
        windows.append([_iso(now), until])
    rule.update(on=True, until=until, days=days, renewed_by=by, renewed_at=_iso(now))


def matches(rule, alert):
    """Same customer, same tool, same detection rule, same machine and, if the
    taught rule names one, the same account."""
    if rule.get("client") != alert.get("client") or rule.get("source") != alert.get("source"):
        return False
    if rule.get("rule_id"):
        if rule["rule_id"] != _rule_id(alert):
            return False
    elif str(rule.get("title") or "").casefold() != str(alert.get("title") or "").casefold():
        return False
    if str(rule.get("host") or "").casefold() != _host(alert).casefold():
        return False
    if rule.get("user") and rule["user"].casefold() != str(alert.get("user") or "").casefold():
        return False
    return True


def state(rule, now=None):
    """on | ended (its days ran out) | off (a person switched it off)."""
    if not rule.get("on"):
        return "off"
    now = now if now is not None else datetime.datetime.now(datetime.timezone.utc).timestamp()
    until = parse_ts(rule.get("until"))
    return "on" if until is not None and now <= until else "ended"


def _in_force(rule, when):
    """Was the rule in force at that moment?"""
    for start, until in rule.get("windows") or [[rule.get("at"), rule.get("until")]]:
        a, b = parse_ts(start), parse_ts(until)
        if a is not None and b is not None and a < when <= b:
            return True
    return False


def where(rule):
    return rule.get("host", "") + (f", account {rule['user']}" if rule.get("user") else "")


def _closed(verdict, rule):
    out = dict(verdict)
    false_positive = rule.get("outcome") == "false_positive"
    note = f" ({rule['note']})" if rule.get("note") else ""
    out.update(
        escalate=False, disposition="benign",
        closure_code="FP_TUNING" if false_positive else "BENIGN_EXPECTED",
        confidence=90, severity="low", basis="", pattern="", used_ai=False, tuning_recommendation=None,
        summary=f"Closed on a rule {rule.get('by')} taught Triagle: {str(rule.get('label') or '').lower()} on {where(rule)}.",
        reasoning=(f"{rule.get('by')} closed the same alert on {_day(rule.get('at'))} as "
                   f"{str(rule.get('label') or '').lower()}{note} and asked Triagle to close it from then on, "
                   f"until {_day(rule.get('until'))}. This is taught rule {rule.get('id')}. Without it Triagle "
                   f"would have sent this alert to a person: {verdict.get('summary') or ''}".strip()),
        recommended_actions=[f"No action. If this is no longer expected, switch taught rule {rule.get('id')} off."],
        instruction=rule.get("id"),
    )
    return out


def _sent_back(alert, verdict, check):
    out = dict(verdict)
    rated = str(alert.get("raw_severity") or "").lower()
    if check.get("kind") == "investigator":
        # The engine closed it; the investigator (a model choosing its own checks,
        # not told the verdict) read it as hostile or unexplained. When the two
        # differ a person decides. This is the one thing the model can change.
        out.update(
            escalate=True, disposition="needs_human", closure_code=None, confidence=55,
            severity=rated if rated in ("high", "critical") else "medium", basis="", pattern="", used_ai=True,
            summary="Sent to a person by Triagle's investigator: the engine had closed this, and the investigation disagreed.",
            reasoning=(f"Triagle's engine closed this alert: {verdict.get('summary') or ''} The investigator, a model "
                       f"that chooses its own checks and is not told the verdict, read it differently: "
                       f"{check.get('why') or 'it would have a person look.'} When the engine and the investigator "
                       f"differ, the alert goes to a person. A model can send an alert to a person. It can never close one."),
            recommended_actions=["Read the investigator's steps below, decide what it was and close it with the outcome."],
            overruled={"by": check.get("by"), "at": check.get("at"), "was": verdict.get("closure_code"), "kind": "investigator"},
        )
        return out
    out.update(
        escalate=True, disposition="needs_human", closure_code=None, confidence=55,
        severity=rated if rated in ("high", "critical") else "medium", basis="", pattern="", used_ai=False,
        summary=f"Sent back by {check.get('by')}: Triagle had closed this, and a person disagreed.",
        reasoning=(f"Triagle closed this alert: {verdict.get('summary') or ''} {check.get('by')} checked that "
                   f"closure on {_day(check.get('at'))} and disagreed, so the alert is back in the queue for a "
                   f"decision. The disagreement is counted against Triagle in the spot-check figures."),
        recommended_actions=["Decide what it was and close it with the outcome."],
        overruled={"by": check.get("by"), "at": check.get("at"), "was": verdict.get("closure_code")},
    )
    return out


def apply(alerts, verdicts, rules=None, overruled=None):
    """Change the verdicts where a person has spoken: close what a taught rule
    covers, and send back a closure a person disagreed with.
    Returns {taught rule id: {"count": n, "last": timestamp of the latest alert it closed}}."""
    rules, overruled = rules or [], overruled or {}
    used = {}
    for a in alerts:
        aid = a["alert_id"]
        v = verdicts.get(aid)
        if not v:
            continue
        if aid in overruled:
            if not v.get("escalate"):
                verdicts[aid] = _sent_back(a, v, overruled[aid])
            continue
        if not rules or not v.get("escalate") or not _may_close(a, v):
            continue
        when = parse_ts(a.get("timestamp"))
        if when is None:
            continue
        for rule in rules:
            if _in_force(rule, when) and matches(rule, a):
                verdicts[aid] = _closed(v, rule)
                hit = used.setdefault(rule["id"], {"count": 0, "last": ""})
                hit["count"] += 1
                hit["last"] = max(hit["last"], str(a.get("timestamp") or ""))
                break
    return used
