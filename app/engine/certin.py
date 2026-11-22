"""
Triagle — CERT-In incident report draft.

For an escalated incident this assembles, from evidence Triagle already has,
a draft of what a CERT-In incident report asks for: what kind of incident,
when it was noticed, which systems, what was seen, which indicators, and
what has been done. It also tracks the 6-hour reporting window.

It is a DRAFT for a person to check, complete and send. It never files
anything. Fields Triagle cannot know (who is reporting, the organisation's
sector, patch levels) are listed as "to complete" rather than guessed.

The incident-type wording follows the list of reportable incidents in
CERT-In's Directions of 28 April 2022 under section 70B(6) of the IT Act.
Check it against the current Directions and reporting form before filing.
"""
from datetime import datetime, timedelta, timezone

from app.engine import signals

REPORTING_WINDOW_HOURS = 6

# (CERT-In incident type, words that point to it)
INCIDENT_TYPES = [
    ("Malicious code attacks (virus / worm / Trojan / bots / spyware / ransomware / cryptominers)",
     ["ransomware", "encrypting files", "malware", "trojan", "c2", "command and control",
      "beaconing", "shadow copy deletion", "recovery disabled", "backup catalog deletion"]),
    ("Compromise of critical systems / information",
     ["lsass", "credential dump", "credential dumping", "lateral movement", "domain admin",
      "privilege escalation", "process memory dump (comsvcs)", "LSASS dump tool",
      "remote service execution (PsExec)", "directory database access", "registry hive dump"]),
    ("Identity theft, spoofing and phishing attacks",
     ["impossibletravel", "impossible travel", "anonymizedipaddress", "phish", "inbox rule",
      "mfa method", "consent", "unfamiliar"]),
    ("Unauthorised access of IT systems / data",
     ["successful sign-in after", "role assigned", "unauthorised", "unauthorized", "remote service"]),
    ("Targeted scanning / probing of critical networks / systems",
     ["port scan", "scan detected", "probing", "passwordspray", "password spray", "brute force"]),
    ("Attacks on applications such as e-governance, e-commerce etc.",
     ["sql injection", "cross-site", "web shell", "webshell"]),
    ("Data breach / data leak",
     ["exfiltration", "data theft", "mass file download", "mass download"]),
    ("Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks",
     ["denial of service", "ddos", "syn flood"]),
]

DATA_EXPOSURE_HINTS = ["exfiltration", "data theft", "mass file download", "mass download",
                       "inbox rule", "forward", "ransomware", "consent"]


def _parse(ts):
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


IST = timezone(timedelta(hours=5, minutes=30))


def _fmt(dt):
    return dt.astimezone(IST).strftime("%d %b %Y, %H:%M IST") if dt else "unknown"


def _evidence_text(alert):
    return (signals.human_text(alert) + " " + " ".join(signals.matched_behaviours(alert))).lower()


def classify(members):
    """[(incident type, [alert titles that support it])]"""
    out = []
    for name, words in INCIDENT_TYPES:
        basis = []
        for m in members:
            if not m["verdict"].get("escalate"):
                continue
            text = _evidence_text(m["alert"])
            if any(w.lower() in text for w in words):
                basis.append(m["alert"]["title"])
        if basis:
            out.append({"type": name, "basis": sorted(set(basis))})
    return out


PROBING = "Targeted scanning / probing of critical networks / systems"


def _attack_members(members):
    return [m for m in members if m["verdict"].get("escalate")
            and m["verdict"].get("disposition") in ("true_positive", "suspicious")]


def probing_only(members):
    """True when everything Triagle judged an attack here is an attempt from
    outside (a scan, a spray, a brute force) with no sign that it worked."""
    attack = _attack_members(members)
    if not attack or any(m["verdict"].get("disposition") == "true_positive" for m in attack):
        return False
    types = classify(attack)
    return bool(types) and all(t["type"] == PROBING for t in types)


def is_reportable_candidate(members):
    """An incident gets a draft and a clock when a human has something real
    to decide: an alert in it was escalated as true positive or suspicious,
    and it is more than probing from outside that shows no sign of success.
    The internet knocks on every server all day; nobody reports each knock."""
    return bool(_attack_members(members)) and not probing_only(members)


def when_noticed(members):
    """When the organisation noticed the incident. Triagle's evidence is the
    first alert it judged an attack on that alert's own evidence. An earlier
    alert that only looks suspicious because of what came later did not start
    the clock: nobody knew then."""
    attack = _attack_members(members)
    own = [m for m in attack if m["verdict"].get("basis") != "correlation"]
    for pool in (own, attack, [m for m in members if m["verdict"].get("escalate")]):
        times = [t for t in (_parse(m["alert"].get("timestamp")) for m in pool) if t]
        if times:
            return min(times)
    return None


def build_draft(incident, members, actions_by_alert, threat_intel=None, now=None, noticed_at=None):
    """members: [{"alert": dict, "verdict": dict}] in time order."""
    now = now or datetime.now(timezone.utc)
    threat_intel = threat_intel or {}
    escalated = [m for m in members if m["verdict"].get("escalate")]

    # The clock runs from when the organisation noticed the incident. Triagle's
    # best evidence for that is the first alert it judged an attack; a person can correct it.
    first = when_noticed(members)
    occurred = min((t for t in (_parse(m["alert"].get("timestamp")) for m in members) if t), default=None)
    noticed = noticed_at or first
    deadline = noticed + timedelta(hours=REPORTING_WINDOW_HOURS) if noticed else None
    remaining = (deadline - now) if deadline else None

    systems = {}
    for m in members:
        a = m["alert"]
        h = a.get("host")
        if h:
            s = systems.setdefault(h, {"name": h, "seen_by": set(), "users": set()})
            s["seen_by"].add(a.get("source"))
            if a.get("user"):
                s["users"].add(a["user"])
    systems = [{"name": s["name"], "seen_by": sorted(x for x in s["seen_by"] if x),
                "users": sorted(s["users"])} for s in systems.values()]

    indicators = []
    seen = set()
    for m in members:
        a = m["alert"]
        ind = a.get("indicators") or {}
        for kind, value in (("file hash", ind.get("sha256")), ("file name", ind.get("filename")),
                            ("command line", ind.get("cmdline")), ("address", a.get("dst_ip")),
                            ("address", a.get("src_ip"))):
            if not value or value in seen:
                continue
            if kind == "address" and any(value == s["name"] for s in systems):
                continue
            seen.add(value)
            indicators.append({"kind": kind, "value": value, "intel": threat_intel.get(value)})

    done, pending = [], []
    for m in members:
        for act in actions_by_alert.get(m["alert"]["alert_id"], []):
            line = f"{act['label']} — {act['target']}"
            if act.get("status") == "declined":
                continue
            if act.get("status") == "executed" and act.get("decided_by"):
                line += f" (approved by {act['decided_by']}, {_fmt(_parse(act.get('decided_at')))})"
            bucket = done if act.get("status") == "executed" else pending
            if line not in bucket:
                bucket.append(line)
    pending = [p for p in pending if not any(d.startswith(p) for d in done)]

    types = classify(members)
    exposure = sorted({h for m in escalated for h in DATA_EXPOSURE_HINTS if h in _evidence_text(m["alert"])})

    narrative = (
        f"{len(members)} related alerts from {len(incident['sources'])} security tool(s) were linked "
        f"into one incident centred on {incident['key']}. {len(escalated)} were escalated for human "
        f"review. The earliest related activity was recorded at {_fmt(occurred)}."
    )

    to_complete = [
        "Reporting person: name, designation, organisation, phone, email",
        "Sector of the affected organisation",
        "Physical location of the affected systems",
        "Operating system, version and last patch date of each affected system",
        "Whether the affected system is critical to the organisation's operations",
        "Whether a similar incident has occurred before",
        "Other agencies or parties already informed",
    ]
    if not noticed:
        to_complete.insert(0, "Time the incident was noticed (no usable alert timestamp)")

    return {
        "reference": f"TRG-{(noticed or now).strftime('%Y%m%d')}-{abs(hash(tuple(incident['alert_ids']))) % 10000:04d}",
        "client": incident.get("client"),
        "key": incident["key"],
        "generated_at": _fmt(now),
        "occurred_at": _fmt(occurred),
        "noticed_at": _fmt(noticed),
        "deadline_at": _fmt(deadline),
        "deadline_iso": deadline.isoformat() if deadline else None,
        "window_hours": REPORTING_WINDOW_HOURS,
        "overdue": bool(remaining is not None and remaining.total_seconds() < 0),
        "minutes_remaining": int(remaining.total_seconds() // 60) if remaining is not None else None,
        "incident_types": types,
        "narrative": narrative,
        "systems": systems,
        "timeline": [{"time": _fmt(_parse(m["alert"].get("timestamp"))), "title": m["alert"]["title"],
                      "detail": m["alert"].get("description") or m["verdict"].get("summary", ""),
                      "source": m["alert"].get("source"), "escalated": bool(m["verdict"].get("escalate"))}
                     for m in members],
        "indicators": indicators,
        "actions_done": done,
        "actions_pending": pending,
        "data_exposure_signals": exposure,
        "to_complete": to_complete,
    }
