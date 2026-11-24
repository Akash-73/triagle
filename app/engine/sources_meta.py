"""
Triagle — human-friendly labels.

Turns raw source keys and verdict codes into words a non-technical viewer
(a client, a judge) understands at a glance. Registered as template helpers
in app/main.py so any page can call them.
"""

SOURCES = {
    "crowdstrike_edr": ("CrowdStrike EDR", "endpoints"),
    "fortinet_fw": ("Fortinet Firewall", "network"),
    "entra_id": ("Microsoft Entra ID", "identity / logins"),
    "wazuh": ("Wazuh SIEM", "endpoints & servers"),
    "ot_monitor": ("OT network monitor", "plant & substation networks"),
    "barracuda_waf": ("Barracuda WAF", "web apps"),
    "nutanix": ("Nutanix", "infrastructure"),
    "cisco_asa": ("Cisco ASA", "network"),
    "palo_alto": ("Palo Alto NGFW", "network"),
}

VERDICTS = {
    "true_positive": "Real attack",
    "suspicious": "Suspicious",
    "benign": "Cleared — routine",
    "needs_human": "Needs review",
}


def _pretty(key):
    return str(key or "").replace("_", " ").title()


def source_name(key):
    return SOURCES.get(key, (_pretty(key), ""))[0]


def source_desc(key):
    return SOURCES.get(key, (_pretty(key), ""))[1]


def source_full(key):
    name, desc = SOURCES.get(key, (_pretty(key), ""))
    return f"{name} · {desc}" if desc else name


def source_list(keys):
    seen, out = set(), []
    for k in keys or []:
        n = source_name(k)
        if n not in seen:
            seen.add(n)
            out.append(n)
    return ", ".join(out)


def verdict_label(disposition):
    return VERDICTS.get(disposition, _pretty(disposition))


# Plain words for the console tables.
VERDICT_WORDS = {"true_positive": "Real attack", "suspicious": "Suspicious",
                 "needs_human": "Needs a person", "benign": "Routine"}
CLOSURE_WORDS = {
    "BENIGN_EXPECTED": "Routine activity", "BENIGN_KNOWN_TOOL": "Known admin tool",
    "POSTURE_FINDING": "Posture finding", "OPERATIONAL_EVENT": "Health event",
    "BENIGN_DUPLICATE": "Already raised", "FP_TUNING": "False positive",
}


def verdict_words(disposition):
    return VERDICT_WORDS.get(disposition, _pretty(disposition))


def closure_words(code):
    return CLOSURE_WORDS.get(code, _pretty(code) if code else "Closed")
