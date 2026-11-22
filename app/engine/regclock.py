"""
Triagle — the regulatory clock.

An Indian company that confirms a cyber incident usually owes more than one
report, to more than one regulator, on more than one deadline. Which ones
depends on its sector: a co-operative bank answers to CERT-In and the RBI, a
stock broker to CERT-In and SEBI, a power utility to CERT-In and CSIRT-Power,
and anyone who lost personal data to the Data Protection Board as well.

This module holds those deadlines as data, works out which apply to an
incident, and tracks each one from the moment the incident was noticed until
a person marks the report as filed.

What it does not do:
  - It never files anything. It counts down and drafts; a person sends.
  - It is not legal advice. Each regulator entry names the instrument it
    comes from and says what to verify before relying on it. Two entries are
    not in force yet and are shown as such, so a team can rehearse for them.

The clock runs from when the organisation noticed the incident. Triagle's
evidence for that is the first alert it judged an attack on that alert's own
evidence; a person can correct it. Probing from outside that shows no sign of
success does not start a clock.
"""
import json
import os
from datetime import date, datetime, timedelta, timezone

from app.engine import certin

# ---- the regulators ---------------------------------------------------------
#
# trigger: "always"         any incident a human may need to report
#          "personal_data"  only when the evidence suggests personal data was
#                           read, taken, altered or made unavailable
# in_force_from: None = in force today; a date = binding from that day
REGULATORS = {
    "certin": {
        "name": "CERT-In",
        "long": "Indian Computer Emergency Response Team",
        "instrument": "CERT-In Directions of 28 April 2022, under section 70B(6) of the Information Technology Act, 2000",
        "who": "Every service provider, intermediary, data centre, body corporate and government organisation.",
        "trigger": "always",
        "in_force_from": None,
        "deadlines": [
            {"key": "report", "label": "Report the incident", "hours": 6,
             "channel": "incident@cert-in.org.in"},
        ],
        "verify": "Check the incident type against the current list of reportable incidents and the current reporting form.",
    },
    "rbi": {
        "name": "RBI",
        "long": "Reserve Bank of India",
        "instrument": "RBI directions on cyber security and IT governance for regulated entities",
        "who": "Banks, co-operative banks, NBFCs and other entities the RBI regulates.",
        "trigger": "always",
        "in_force_from": None,
        "deadlines": [
            {"key": "report", "label": "Report the incident", "hours": 6, "channel": "RBI's DAKSH portal"},
        ],
        "verify": "The Direction that applies depends on the kind of entity. Confirm the window and the form on DAKSH.",
    },
    "sebi": {
        "name": "SEBI",
        "long": "Securities and Exchange Board of India",
        "instrument": "SEBI Cybersecurity and Cyber Resilience Framework (CSCRF)",
        "who": "SEBI-regulated entities: stock brokers, depository participants, mutual funds, registrars and others.",
        "trigger": "always",
        "in_force_from": None,
        "deadlines": [
            {"key": "email", "label": "Inform SEBI by email", "hours": 6, "channel": "SEBI's incident mailbox"},
            {"key": "portal", "label": "File on the incident portal", "hours": 24,
             "channel": "SEBI incident reporting portal"},
        ],
        "verify": "Small entities report through the Market SOC. Confirm the route and windows for your entity category.",
    },
    "cea": {
        "name": "CSIRT-Power",
        "long": "Central Electricity Authority, through CSIRT-Power",
        "instrument": "Central Electricity Authority (Cyber Security in Power Sector) Regulations, 2026",
        "who": "Generation, transmission and distribution utilities and other responsible entities in the power sector.",
        "trigger": "always",
        "in_force_from": date(2027, 4, 1),
        "deadlines": [
            {"key": "report", "label": "Report the incident", "hours": 6, "channel": "CSIRT-Power"},
        ],
        "verify": "Notified 31 July 2026 and binding from 1 April 2027. Confirm the windows against the gazette text; sabotage has its own.",
    },
    "dpdp": {
        "name": "Data Protection Board",
        "long": "Data Protection Board of India",
        "instrument": "Digital Personal Data Protection Act, 2023 and the Rules of 2025",
        "who": "Any organisation, when a breach involves personal data it is responsible for.",
        "trigger": "personal_data",
        "in_force_from": date(2027, 5, 13),
        "deadlines": [
            {"key": "detailed", "label": "Detailed breach report", "hours": 72,
             "channel": "Data Protection Board of India"},
        ],
        "also": "The Board and the affected people must also be told without delay, before the detailed report.",
        "verify": "Breach duties are enforceable from 13 May 2027. Whether personal data was affected is a decision for the data-protection lead.",
    },
}

# ---- sectors ------------------------------------------------------------------
SECTORS = {
    "general": {"label": "Business with no sector regulator", "regulators": ["certin", "dpdp"]},
    "bank": {"label": "Bank or co-operative bank", "regulators": ["certin", "rbi", "dpdp"]},
    "nbfc": {"label": "NBFC", "regulators": ["certin", "rbi", "dpdp"]},
    "securities": {"label": "SEBI-regulated entity", "regulators": ["certin", "sebi", "dpdp"]},
    "power": {"label": "Power utility", "regulators": ["certin", "cea", "dpdp"]},
    "healthcare": {"label": "Hospital or healthcare provider", "regulators": ["certin", "dpdp"]},
}
DEFAULT_SECTOR = "general"

_TENANTS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "samples", "tenants.json")


def load_tenants(environ=None):
    """{client name: sector}. From samples/tenants.json, then TRIAGLE_TENANTS
    (a JSON object of client -> sector) on top. Unknown sectors are ignored."""
    environ = os.environ if environ is None else environ
    out = {}
    try:
        with open(environ.get("TRIAGLE_TENANTS_FILE", _TENANTS_PATH)) as f:
            out.update(json.load(f))
    except (OSError, ValueError):
        pass
    try:
        extra = json.loads(environ.get("TRIAGLE_TENANTS", "") or "{}")
        if isinstance(extra, dict):
            out.update(extra)
    except ValueError:
        pass
    clean = {}
    for name, value in out.items():
        sector = value.get("sector") if isinstance(value, dict) else value
        if sector in SECTORS:
            clean[str(name)] = sector
    return clean


def sector_of(client, tenants, overrides=None):
    for source in (overrides or {}, tenants or {}):
        s = source.get(client)
        if s in SECTORS:
            return s
    return DEFAULT_SECTOR


# ---- the clock -----------------------------------------------------------------

def noticed_at(members):
    """When the organisation noticed: the first alert judged an attack on its
    own evidence (see certin.when_noticed)."""
    return certin.when_noticed(members)


def personal_data_signals(members):
    """Words in the escalated evidence that suggest data was read or taken."""
    return sorted({h for m in members if m["verdict"].get("escalate")
                   for h in certin.DATA_EXPOSURE_HINTS if h in certin._evidence_text(m["alert"])})


def _left(seconds):
    seconds = int(abs(seconds))
    h, m = seconds // 3600, (seconds % 3600) // 60
    return f"{h}h {m:02d}m" if h else f"{m}m"


def filing_for(filings, incident, regulator, deadline):
    """A filing belongs to an incident if they share an alert, so it stays
    attached when the incident grows or its reference changes."""
    ids = set(incident.get("alert_ids") or [])
    for f in filings or []:
        if f["regulator"] == regulator and f["deadline"] == deadline and ids & set(f["alert_ids"]):
            return f
    return None


def clocks_for(incident, members, sector, now=None, filings=None):
    """Every deadline that applies to this incident, most urgent first.

    Row status:
      filed          a person recorded that the report was sent
      running        binding, and time is left
      overdue        binding, and the window has passed
      not_in_force   the rule is not binding yet; shown with the time it
                     would have been due, so the team can rehearse
      not_triggered  the rule applies only if personal data was affected and
                     the evidence does not show that
      unknown        no usable timestamp to start the clock from
    """
    now = now or datetime.now(timezone.utc)
    sector = sector if sector in SECTORS else DEFAULT_SECTOR
    start = noticed_at(members)
    data_signals = personal_data_signals(members)
    rows = []
    for reg_key in SECTORS[sector]["regulators"]:
        reg = REGULATORS[reg_key]
        in_force = reg["in_force_from"] is None or now.date() >= reg["in_force_from"]
        triggered = reg["trigger"] == "always" or bool(data_signals)
        for d in reg["deadlines"]:
            due = start + timedelta(hours=d["hours"]) if start else None
            seconds = (due - now).total_seconds() if due else None
            filed = filing_for(filings, incident, reg_key, d["key"])
            if filed:
                status = "filed"
                note = f"Marked filed by {filed['by']}, {certin._fmt(certin._parse(filed['at']))}" + \
                       (f" · ref {filed['reference']}" if filed.get("reference") else "")
            elif not triggered:
                status = "not_triggered"
                note = "No sign in the evidence that personal data was affected. Reassess if that changes."
            elif due is None:
                status = "unknown"
                note = "No usable alert timestamp to start the clock from."
            elif not in_force:
                status = "not_in_force"
                note = (f"Not binding until {reg['in_force_from'].strftime('%d %b %Y')}. "
                        f"Under it this would be due {certin._fmt(due)}.")
            elif seconds < 0:
                status = "overdue"
                note = f"Window passed {_left(seconds)} ago."
            else:
                status = "running"
                note = f"{_left(seconds)} left."
            rows.append({
                "regulator": reg_key, "name": reg["name"], "long": reg["long"],
                "deadline": d["key"], "label": d["label"], "hours": d["hours"], "channel": d["channel"],
                "status": status, "note": note,
                "due_iso": due.isoformat() if due else None, "due_at": certin._fmt(due) if due else "unknown",
                "seconds_left": int(seconds) if seconds is not None else None,
                "binding": in_force, "instrument": reg["instrument"], "verify": reg["verify"],
                "also": reg.get("also"),
                "why": (f"Applies because personal-data signals were seen: {', '.join(data_signals)}."
                        if reg["trigger"] == "personal_data" and triggered else reg["who"]),
                "filed": filed,
            })

    order = {"overdue": 0, "running": 1, "unknown": 2, "not_in_force": 3, "not_triggered": 4, "filed": 5}
    rows.sort(key=lambda r: (order[r["status"]], r["seconds_left"] if r["seconds_left"] is not None else 0))
    open_rows = [r for r in rows if r["status"] in ("running", "overdue")]
    return {
        "sector": sector, "sector_label": SECTORS[sector]["label"],
        "noticed_iso": start.isoformat() if start else None,
        "noticed_at": certin._fmt(start) if start else "unknown",
        "rows": rows,
        "next": open_rows[0] if open_rows else None,          # the deadline to worry about first
        "open": len(open_rows),
        "overdue": sum(1 for r in open_rows if r["status"] == "overdue"),
        "filed": sum(1 for r in rows if r["status"] == "filed"),
        "data_signals": data_signals,
    }


def regulator(key):
    return REGULATORS.get(key)
