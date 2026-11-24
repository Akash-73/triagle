"""Slow password guessing from one address.

    python -m pytest -q tests/test_slow_guessing.py

The gap this closes. Wazuh raises its own "brute force" alert only when the
failures come fast — eight in two minutes. An attacker who tries one password
every few minutes never trips that rule, and every attempt is a single
low-severity "authentication failed" / "non-existent user" event that triage
would close on its own. The engine keeps, per source address, the failed
sign-ins in time order, and raises the attempt that reaches the threshold —
once. The attempts after it are counted there, not raised again. A later
success from the same address is raised on its own, because that is the attack
working.

Two things it must NOT do: fire when the SIEM already raised its own brute
force for that address (double-counting), and fire when many addresses each
try once (that is noise from the internet, not one account under attack).
"""
import copy
import datetime as dt

from app.orchestrator import process_batch

CLIENT = "Greenvale Co-operative Bank"
T0 = dt.datetime(2026, 11, 24, 0, 0, 0)


def _ts(sec):
    return (T0 + dt.timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def failed_signin(i, sec, src, user="guessme"):
    """A single Wazuh 5710 'non-existent user' alert (level 5, its own band)."""
    return {"source": "wazuh", "client": CLIENT, "raw": {
        "timestamp": _ts(sec), "id": f"{1795478000 + i}.{i}",
        "rule": {"id": "5710", "level": 5,
                 "description": "sshd: Attempt to login using a non-existent user",
                 "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"]},
        "agent": {"id": "000", "name": "wazuh-server"}, "manager": {"name": "wazuh-server"},
        "predecoder": {"program_name": "sshd"}, "decoder": {"parent": "sshd", "name": "sshd"},
        "data": {"srcip": src, "srcuser": user}, "location": "journald"}}


def success_signin(i, sec, src, user="sarkhelakash19"):
    return {"source": "wazuh", "client": CLIENT, "raw": {
        "timestamp": _ts(sec), "id": f"{1795478000 + i}.{i}",
        "rule": {"id": "5715", "level": 3, "description": "sshd: authentication success.",
                 "groups": ["syslog", "sshd", "authentication_success"]},
        "agent": {"id": "000", "name": "wazuh-server"}, "manager": {"name": "wazuh-server"},
        "predecoder": {"program_name": "sshd"}, "decoder": {"parent": "sshd", "name": "sshd"},
        "data": {"srcip": src, "dstuser": user}, "location": "journald"}}


def wazuh_brute_force(i, sec, src):
    """Wazuh's OWN aggregated brute-force alert (5763, level 10)."""
    return {"source": "wazuh", "client": CLIENT, "raw": {
        "timestamp": _ts(sec), "id": f"{1795478000 + i}.{i}",
        "rule": {"id": "5763", "level": 10,
                 "description": "sshd: brute force trying to get access to the system. Authentication failed.",
                 "groups": ["syslog", "sshd", "authentication_failures"],
                 "mitre": {"id": ["T1110"]}},
        "agent": {"id": "000", "name": "wazuh-server"}, "manager": {"name": "wazuh-server"},
        "predecoder": {"program_name": "sshd"}, "decoder": {"parent": "sshd", "name": "sshd"},
        "data": {"srcip": src}, "location": "journald"}}


def _run(items):
    r = process_batch(items)
    return r, [(a, r["verdicts"][a["alert_id"]]) for a in r["alerts"]]


def _escalated(pairs):
    return [(a, v) for a, v in pairs if v["escalate"]]


def test_slow_guessing_from_one_address_is_raised_once():
    # one attempt every ~2.5 min: far too slow for Wazuh's own 8-in-120s rule
    items = [failed_signin(i, i * 160, "142.93.199.148", f"u{i}") for i in range(16)]
    r, pairs = _run(items)
    esc = _escalated(pairs)
    assert len(esc) == 1, "exactly one escalation for the whole run"
    _, v = esc[0]
    assert v["pattern"] == "password_guessing"
    assert v["basis"] == "correlation" and v["disposition"] == "suspicious"
    # the rest are counted under it, not raised, and not closed as plain routine
    dupes = [v for a, v in pairs if v["closure_code"] == "BENIGN_DUPLICATE"]
    assert len(dupes) == 16 - 5          # everything after the fifth


def test_the_threshold_is_the_fifth_attempt():
    items = [failed_signin(i, i * 160, "203.0.113.5", f"u{i}") for i in range(5)]
    r, pairs = _run(items)
    esc = _escalated(pairs)
    assert len(esc) == 1
    assert esc[0][0]["alert_id"] == pairs[4][0]["alert_id"], "the fifth attempt is the one raised"


def test_four_attempts_are_not_enough():
    items = [failed_signin(i, i * 160, "203.0.113.6", f"u{i}") for i in range(4)]
    r, pairs = _run(items)
    assert _escalated(pairs) == []


def test_a_success_after_guessing_is_escalated_and_starts_a_clock():
    items = [failed_signin(i, i * 160, "142.93.199.148", f"u{i}") for i in range(16)]
    items.append(success_signin(99, 16 * 160 + 30, "142.93.199.148"))
    r, pairs = _run(items)
    patterns = {v.get("pattern") for a, v in _escalated(pairs)}
    assert "guessing_then_success" in patterns
    win = next(v for a, v in pairs if v.get("pattern") == "guessing_then_success")
    assert win["severity"] == "high" and win["basis"] == "sequence"


def test_the_success_alert_proposes_blocking_the_outside_address():
    items = [failed_signin(i, i * 160, "142.93.199.148", f"u{i}") for i in range(16)]
    items.append(success_signin(99, 16 * 160 + 30, "142.93.199.148"))
    r, _ = _run(items)
    blocks = [x for acts in r["actions"].values() for x in acts
              if x["action_type"] == "block_indicator" and x["target"] == "142.93.199.148"]
    assert blocks, "an outside address that guessed then signed in should be proposed for blocking"


def test_many_addresses_one_attempt_each_is_not_guessing():
    # the internet knocking: 16 different addresses, one try each
    items = [failed_signin(i, i * 160, f"45.1.1.{i}", f"u{i}") for i in range(16)]
    r, pairs = _run(items)
    assert _escalated(pairs) == [], "one attempt from many addresses is noise, not one account under attack"


def test_the_siems_own_brute_force_is_not_suppressed_as_a_duplicate():
    # raw attempts AND Wazuh's own aggregate from the same address
    items = [failed_signin(i, i * 160, "203.0.113.77", f"u{i}") for i in range(10)]
    items.append(wazuh_brute_force(50, 300, "203.0.113.77"))
    r, pairs = _run(items)
    agg = next(v for a, v in pairs
               if a["title"].startswith("sshd: brute force") and "Authentication failed" in a["title"])
    assert agg["escalate"], "Wazuh's own brute-force alert must always escalate"
    # the per-attempt rule stands down when the SIEM already flagged the source
    assert not any(v.get("pattern") == "password_guessing" for a, v in pairs)


def test_an_inside_address_guessing_is_raised_but_not_auto_blocked():
    items = [failed_signin(i, i * 160, "10.20.4.9", f"u{i}") for i in range(6)]
    r, pairs = _run(items)
    esc = _escalated(pairs)
    assert len(esc) == 1 and esc[0][1]["pattern"] == "password_guessing"
    # an internal address is an asset to look at, not an indicator to block at the perimeter
    blocks = [x for acts in r["actions"].values() for x in acts
              if x["action_type"] == "block_indicator" and x["target"] == "10.20.4.9"]
    assert not blocks
