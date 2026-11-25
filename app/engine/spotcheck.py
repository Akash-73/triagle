"""
Triagle — spot checks: how often a person agrees with a closure.

Triagle closes most alerts with a reason. The first question from anyone who
has to trust it is: what did it close that it should not have? The only
honest answer is a measured one. A person looks at a sample of the closures
and says, for each, "agree" or "disagree". The share they agree with is the
figure a pilot is judged on.

How the sample is drawn:

  - Only closures Triagle decided on its own. An alert counted under one
    that was raised (a repeat, a member of a burst) was not closed on its own
    account, and one closed on a rule a person taught was decided by a
    person.
  - Across every kind of closure, not at random. A feed is mostly one or two
    routine rules; a random sample would be forty copies of the same sign-in.
    The sample takes one alert from each reason for closing in turn, and
    within a reason one from each detection rule in turn.
  - Stable. The same alerts are offered until they are checked, so a person
    can stop and come back.

A disagreement sends the alert back to the queue (instructions.apply) and is
counted against Triagle for as long as the record is kept.
"""
import hashlib

# Closed under another alert, not on its own account.
SKIP_CODES = {"BENIGN_DUPLICATE"}
# Activity closures first: they are where a wrong closure would matter most.
_CODE_ORDER = ["BENIGN_EXPECTED", "BENIGN_KNOWN_TOOL", "FP_TUNING", "POSTURE_FINDING", "OPERATIONAL_EVENT"]


def eligible(alert, verdict, skip_clients=()):
    """A closure Triagle made on its own, for a real customer."""
    return bool(verdict and not verdict.get("escalate") and verdict.get("closure_code")
                and verdict["closure_code"] not in SKIP_CODES and not verdict.get("instruction")
                and alert.get("client") not in skip_clients)


def _rank(seed, text):
    return hashlib.sha1(f"{seed}|{text}".encode(), usedforsecurity=False).hexdigest()      # an ordering, not a secret


def _turns(groups):
    """Take one from each group in turn until all are empty."""
    queues = [list(g) for g in groups if g]
    while queues:
        for q in list(queues):
            yield q.pop(0)
            if not q:
                queues.remove(q)


def waiting(alerts, verdicts, checks, skip_clients=()):
    """Every closure that could still be checked."""
    return [a for a in alerts if a["alert_id"] not in checks
            and eligible(a, verdicts.get(a["alert_id"]), skip_clients)]


def sample(alerts, verdicts, checks, size=10, skip_clients=(), seed="triagle"):
    """The next closures to check: one from each reason in turn, and within a
    reason one from each detection rule in turn."""
    by_code = {}
    for a in waiting(alerts, verdicts, checks, skip_clients):
        code = verdicts[a["alert_id"]]["closure_code"]
        by_code.setdefault(code, {}).setdefault(a.get("title") or "", []).append(a)
    per_code = []
    for code in sorted(by_code, key=lambda c: (_CODE_ORDER.index(c) if c in _CODE_ORDER else len(_CODE_ORDER), c)):
        titles = by_code[code]
        ordered = [sorted(titles[t], key=lambda a: _rank(seed, a["alert_id"]))
                   for t in sorted(titles, key=lambda t: _rank(seed, t))]
        per_code.append(list(_turns(ordered)))
    out = []
    for a in _turns(per_code):
        out.append(a)
        if len(out) >= size:
            break
    return out


def record(alert, verdict, agreed, by, at):
    """What is kept about one check. It outlives the alert, which ages out."""
    return {"ok": bool(agreed), "by": by, "at": at, "title": alert.get("title") or "",
            "client": alert.get("client") or "", "host": alert.get("host") or alert.get("entity") or "",
            "code": verdict.get("closure_code") or "", "summary": verdict.get("summary") or ""}


def tally(checks, skip_clients=()):
    """checked, agreed, disagreed and the share agreed, as a whole number or
    to one decimal place."""
    mine = [c for c in checks.values() if c.get("client") not in skip_clients]
    agreed = sum(1 for c in mine if c.get("ok"))
    n = len(mine)
    pct = None
    if n:
        share = 100 * agreed / n
        pct = int(share) if share == int(share) else int(share * 10) / 10      # never rounded up
    return {"checked": n, "agreed": agreed, "disagreed": n - agreed, "pct": pct}
