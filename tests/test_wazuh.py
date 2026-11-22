"""A real SIEM stream: the Wazuh connector, and what the engine learned from it.

    python -m pytest -q tests/test_wazuh.py

Most of these exist because of one finding. The first time the engine was run
against alerts shaped like a real Wazuh feed, it escalated every single one:
on a real host there is always something else nearby, so "two related alerts
on the same host" was true of everything.
"""
import copy
import json
import os

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main, demo_attack
from app.connectors.sources import normalize
from app.connectors import wazuh
from app.engine import signals
from app.engine.correlate import correlate
from app.engine.triage import triage
from app.orchestrator import process_batch

ROOT = os.path.dirname(os.path.dirname(__file__))
KEY = "wz-key"


def wz(rule_id="60106", level=3, description="Windows Logon Success", groups=("windows", "windows_security"),
       mitre=None, agent="WKS-01", ts="2026-11-22T10:00:00.000+0000", eventdata=None, system=None,
       data=None, wid=None, **extra):
    """A Wazuh alert the way alerts.json holds it."""
    raw = {"timestamp": ts, "id": wid or f"1763800000.{abs(hash((rule_id, ts, description))) % 10**7}",
           "rule": {"id": rule_id, "level": level, "description": description, "groups": list(groups)},
           "agent": {"id": "001", "name": agent, "ip": "10.0.0.5"}, "manager": {"name": "wazuh-server"},
           "location": "EventChannel"}
    if mitre:
        raw["rule"]["mitre"] = mitre
    if eventdata is not None or system is not None:
        raw["data"] = {"win": {"system": dict({"eventID": "4624", "channel": "Security"}, **(system or {})),
                               "eventdata": eventdata or {}}}
    if data:
        raw.setdefault("data", {}).update(data)
    raw.update(extra)
    return raw


def item(raw, client="C1"):
    return {"source": "wazuh", "client": client, "raw": raw}


def alert(raw, client="C1"):
    return normalize("wazuh", raw, client)


def proc(cmdline, description="Process started", level=4, **kw):
    return wz("92052", level, description, ("sysmon", "sysmon_eid1_detections", "windows"),
              eventdata={"commandLine": cmdline, "image": "C:\\Windows\\System32\\cmd.exe", "user": "CORP\\j.rao"}, **kw)


# ---- reading a Wazuh alert -------------------------------------------------------

def test_fields_are_read_from_the_native_alert():
    a = alert(wz("92057", 12, "Powershell.exe spawned a powershell process which executed a base64 encoded command",
                 ("sysmon", "windows"), mitre={"id": ["T1059.001"], "tactic": ["Execution"], "technique": ["PowerShell"]},
                 eventdata={"commandLine": "powershell.exe -enc AAAA", "user": "CORP\\j.rao",
                            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            "hashes": "MD5=AA,SHA256=" + "ab" * 32}, wid="1763800000.42"))
    assert a.alert_id == "wz-1763800000.42" and a.source == "wazuh"
    assert a.timestamp == "2026-11-22T10:00:00Z"
    assert a.host == "WKS-01" and a.user == "j.rao" and a.raw_severity == "high"
    assert a.indicators["cmdline"] == "powershell.exe -enc AAAA"
    assert a.indicators["sha256"] == "ab" * 32
    assert a.indicators["mitre_ids"] == "T1059.001" and a.indicators["rule_id"] == "92057"


@pytest.mark.parametrize("level,band", [(0, "low"), (3, "low"), (6, "low"), (7, "medium"), (11, "medium"),
                                        (12, "high"), (14, "high"), (15, "critical")])
def test_severity_uses_wazuhs_own_bands(level, band):
    assert wazuh.severity(level) == band


def test_the_operating_system_is_not_a_person():
    a = alert(wz(eventdata={"subjectUserName": "WKS-01$", "targetUserName": "SYSTEM", "ipAddress": "-"}))
    assert a.user is None and a.src_ip is None
    b = alert(wz(eventdata={"subjectUserName": "WKS-01$", "targetUserName": "j.rao", "ipAddress": "127.0.0.1"}))
    assert b.user == "j.rao" and b.src_ip is None


def test_something_that_is_not_a_wazuh_alert_is_refused():
    with pytest.raises(ValueError):
        normalize("wazuh", {"hello": "world"}, "C1")


# ---- labels and log text are not evidence ----------------------------------------

def test_a_mitre_tactic_label_does_not_escalate_a_logon():
    """Wazuh tags an ordinary logon T1078, whose tactics include Privilege Escalation."""
    a = alert(wz(mitre={"id": ["T1078"], "technique": ["Valid Accounts"],
                        "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]},
                 eventdata={"targetUserName": "j.rao"}))
    assert signals.hard_signals(a) == []
    v = triage(a)
    assert not v.escalate and v.closure_code == "BENIGN_EXPECTED"


def test_the_raw_event_text_is_not_searched():
    a = alert(wz(system={"message": "Process Name: C:\\Windows\\System32\\lsass.exe mimikatz ransomware"},
                 eventdata={"targetUserName": "j.rao"},
                 full_log="lsass credential dumping lateral movement"))
    assert signals.hard_signals(a) == [] and not triage(a).escalate


def test_antimalware_is_not_malware():
    a = alert(wz("62107", 3, "Windows Defender: Antimalware scan started", ("windows", "windows_defender")))
    assert signals.suspicious_terms(a) == [] and not triage(a).escalate
    b = alert(wz("62114", 3, "Windows Defender: Antimalware platform performed an action to protect your system from malware",
                 ("windows", "windows_defender")))
    assert triage(b).escalate


def test_a_database_recovery_message_is_not_boot_recovery():
    a = alert(wz("60807", 3, "The database engine is initiating recovery steps.", ("windows", "windows_application")))
    assert not triage(a).escalate


# ---- kinds: posture, health, drift -------------------------------------------------

def sca(title, result="failed", previous=None, rule_id="19007", level=7):
    check = {"title": title, "result": result}
    if previous:
        check["previous_result"] = previous
    return wz(rule_id, level, f"CIS Benchmark: {title}", ("sca",), data={"sca": {"type": "check", "check": check}},
              location="sca")


def test_a_benchmark_check_that_names_lsass_is_a_posture_finding():
    a = alert(sca("Ensure 'Configure LSASS to run as a protected process' is set to 'Enabled'."))
    assert signals.kind(a) == "posture" and signals.hard_signals(a) == []
    v = triage(a)
    assert not v.escalate and v.closure_code == "POSTURE_FINDING"


def test_a_vulnerability_finding_is_posture_even_when_critical():
    a = alert(wz("23506", 13, "CVE-2026-1142 affects 7-Zip", ("vulnerability-detector",),
                 data={"vulnerability": {"cve": "CVE-2026-1142", "severity": "Critical", "package": {"name": "7-Zip"}}}))
    v = triage(a)
    assert a.raw_severity == "high" and v.closure_code == "POSTURE_FINDING" and not v.escalate


def test_a_control_that_stops_passing_is_a_change_and_reaches_a_human():
    a = alert(sca("Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'.", "failed", "passed",
                  rule_id="19011", level=9))
    assert signals.kind(a) == "activity" and a.indicators["drift"] is True
    assert triage(a).escalate


@pytest.mark.parametrize("rid,level,desc,groups", [
    ("60602", 9, "Windows application error event.", ("windows", "windows_application", "system_error")),
    ("60116", 7, "Windows is shutting down", ("windows", "windows_security", "system_shutdown")),
    ("61110", 10, "Multiple System error events", ("windows", "windows_system")),
])
def test_health_events_are_closed_as_operational(rid, level, desc, groups):
    v = triage(alert(wz(rid, level, desc, groups)))
    assert not v.escalate and v.closure_code == "OPERATIONAL_EVENT"


def test_a_failing_security_control_is_not_waved_through_as_a_health_event():
    a = alert(wz("62103", 10, "Multiple Windows Defender error events", ("windows", "windows_defender", "system_error")))
    assert signals.kind(a) == "activity" and triage(a).escalate


def test_many_logon_failures_are_not_a_health_event():
    assert triage(alert(wz("60204", 10, "Multiple Windows Logon Failures", ("windows", "windows_security")))).escalate


def test_a_posture_label_cannot_hide_a_command_line():
    raw = sca("Ensure something")
    raw["data"]["win"] = {"system": {}, "eventdata": {"commandLine": "vssadmin delete shadows /all"}}
    a = alert(raw)
    assert signals.hard_signals(a) == ["shadow copy deletion"] and triage(a).escalate


# ---- the quiet cases: Wazuh rates them low, the evidence says otherwise ----------------

def test_a_low_rated_alert_whose_command_deletes_shadow_copies_is_escalated():
    a = alert(proc('"C:\\Windows\\system32\\cmd.exe" /c vssadmin delete shadows /all /quiet',
                   "Windows command prompt started by an abnormal process", level=4))
    v = triage(a)
    assert a.raw_severity == "low" and v.escalate and v.severity == "critical"


def test_a_quoted_image_path_does_not_hide_an_encoded_command():
    a = alert(proc('"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoP -W Hidden -enc '
                   'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA', "Powershell process spawned powershell instance"))
    assert "encoded PowerShell" in signals.hard_signals(a)


def test_run_key_persistence_rated_low_is_not_closed():
    a = alert(wz("92302", 6, "Registry entry to be executed on next logon was modified using command line application reg.exe",
                 ("sysmon", "windows")))
    assert a.raw_severity == "low" and triage(a).escalate


def test_an_undetermined_alert_is_never_rated_below_the_source():
    v = triage(alert(wz("60154", 12, "Administrators Group Changed", ("windows", "windows_security", "group_changed"))))
    assert v.escalate and v.severity == "high"


# ---- one busy host must not escalate itself -------------------------------------------

def _busy_host():
    logons = [item(wz(ts=f"2026-11-22T09:{m:02d}:00.000+0000", eventdata={"targetUserName": "j.rao"},
                      wid=f"1763800000.{m}")) for m in range(30)]
    attack = [
        item(proc("powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", "Encoded command", level=12,
                  ts="2026-11-22T09:31:00.000+0000", wid="1763800001.1")),
        item(wz("92040", 12, "net1.exe executed a user creation command", ("sysmon", "windows"),
                eventdata={"commandLine": "net1 user x y /add", "user": "CORP\\j.rao"},
                ts="2026-11-22T09:32:00.000+0000", wid="1763800001.2")),
        item(wz("60154", 12, "Administrators Group Changed", ("windows", "windows_security"),
                eventdata={"subjectUserName": "j.rao"}, ts="2026-11-22T09:33:00.000+0000", wid="1763800001.3")),
    ]
    return logons, attack


def test_routine_events_next_to_an_attack_stay_closed():
    logons, attack = _busy_host()
    r = process_batch(logons + attack)
    esc = [a["alert_id"] for a in r["alerts"] if r["verdicts"][a["alert_id"]]["escalate"]]
    assert sorted(esc) == ["wz-1763800001.1", "wz-1763800001.2", "wz-1763800001.3"]
    assert r["metrics"]["auto_closed"] == 30
    closed = r["verdicts"]["wz-1763800000.5"]
    assert "kept as context" in closed["reasoning"]


def test_an_incident_holds_the_attack_not_the_host_noise():
    logons, attack = _busy_host()
    r = process_batch(logons + attack)
    assert len(r["incidents"]) == 1
    inc = r["incidents"][0]
    assert inc["size"] == 3 and inc["key"] == "WKS-01" and inc["id"].startswith("INC-")
    assert inc["first_seen"] == "2026-11-22T09:31:00Z" and inc["last_seen"] == "2026-11-22T09:33:00Z"


def test_related_alerts_only_count_what_an_analyst_would_stop_at():
    logons, attack = _busy_host()
    r = process_batch(logons + attack)
    step = next(s for s in r["trails"]["wz-1763800001.2"] if s["tool"] == "related_alerts")
    assert step["result_summary"].startswith("Found 2 related alert(s)")
    assert "30 routine event(s)" in step["result_summary"]


def test_alerts_days_apart_on_one_host_are_not_one_incident():
    a = item(wz("60154", 12, "Administrators Group Changed", ts="2026-11-18T09:00:00.000+0000", wid="1.1"))
    b = item(wz("92040", 12, "net1.exe executed a user creation command", ts="2026-11-22T09:00:00.000+0000", wid="1.2"))
    assert process_batch([a, b])["incidents"] == []
    b2 = copy.deepcopy(b)
    b2["raw"]["timestamp"] = "2026-11-18T20:00:00.000+0000"
    assert len(process_batch([a, b2])["incidents"]) == 1


def test_correlate_without_verdicts_still_links_everything():
    a, b = alert(wz(wid="2.1")), alert(wz(wid="2.2"))
    assert len(correlate([a, b])) == 1 and correlate([a, b], verdicts={}) == []


# ---- the labelled Wazuh-shaped set ------------------------------------------------------

def test_wazuh_set_misses_nothing_and_escalates_no_routine_alert():
    items = json.load(open(os.path.join(ROOT, "eval", "wazuh_dataset.json")))
    r = process_batch(items)
    assert len(r["alerts"]) == len(items), "an alert failed to normalise"
    missed, false_esc = [], []
    for it, a in zip(items, r["alerts"]):
        esc = r["verdicts"][a["alert_id"]]["escalate"]
        if it["label"]["threat"] is True and not esc:
            missed.append(a["title"])
        if it["label"]["threat"] is False and esc:
            false_esc.append(a["title"])
    assert missed == [] and false_esc == []
    assert r["metrics"]["noise_reduced_pct"] >= 70


def test_the_dataset_file_matches_its_generator():
    from eval import build_wazuh_dataset as b
    b.ITEMS.clear(); b._seq[0] = 0
    assert b.build() == json.load(open(os.path.join(ROOT, "eval", "wazuh_dataset.json")))


# ---- the live queue -------------------------------------------------------------------------

@pytest.fixture
def live(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s", "TRIAGLE_USERS": ""})
    main._CACHE.clear()
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    yield c
    main._CACHE.clear()


def push(c, items):
    r = c.post("/ingest", headers={"X-Triagle-Key": KEY}, json=items)
    assert r.status_code == 200, r.text
    return r.json()


def _csrf(c, path="/"):
    import re
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get(path).text).group(1)


def test_a_replayed_feed_is_not_counted_twice(live):
    logons, attack = _busy_host()
    assert push(live, attack)["accepted"] == 3
    again = push(live, attack + logons[:2])
    assert again["accepted"] == 2
    ids = [a["alert_id"] for a in main._load_result()["alerts"]]
    assert len(ids) == len(set(ids))


def test_an_approval_survives_the_next_alert(live):
    c2 = item(wz("100200", 12, "Outbound connection to known C2", ("firewall",), agent="FIN-07",
                 data={"srcip": "10.1.1.7", "dstip": "185.220.101.44"}, wid="3.1"))
    push(live, [c2])
    acts = main._load_result()["actions"]["wz-3.1"]
    iso = next(a for a in acts if a["action_type"] == "isolate_host")
    r = live.post("/action/approve", data={"alert_id": "wz-3.1", "action_id": iso["action_id"],
                                           "csrf": _csrf(live, "/alert/wz-3.1")}, follow_redirects=False)
    assert r.status_code == 303
    push(live, [item(wz(wid="3.2", agent="OTHER-HOST"))])          # the queue is rebuilt here
    after = next(a for a in main._load_result()["actions"]["wz-3.1"] if a["action_type"] == "isolate_host")
    assert after["status"] == "executed" and after["decided_by"] == "admin"


def test_an_automatic_action_runs_once_and_is_logged_once(live):
    c2 = item(wz("100200", 12, "Outbound connection to known C2", ("firewall",), agent="FIN-07",
                 data={"srcip": "10.1.1.7", "dstip": "185.220.101.44"}, wid="4.1"))
    push(live, [c2])
    block = next(a for a in main._load_result()["actions"]["wz-4.1"] if a["action_type"] == "block_indicator")
    assert block["status"] == "auto_executed"
    first_time = block["decided_at"]
    for n in range(3):
        push(live, [item(wz(wid=f"4.{n + 2}", agent="OTHER-HOST"))])
    block = next(a for a in main._load_result()["actions"]["wz-4.1"] if a["action_type"] == "block_indicator")
    assert block["status"] == "auto_executed" and block["decided_at"] == first_time
    logged = [e for e in audit.read() if e["event"] == "action auto-executed" and e.get("alert_id") == "wz-4.1"]
    assert len(logged) == 1 and logged[0]["target"] == "185.220.101.44"


def test_memory_is_bounded_and_escalated_alerts_outlive_noise(live, monkeypatch):
    monkeypatch.setenv("TRIAGLE_LIVE_LIMIT", "60")
    _, attack = _busy_host()
    push(live, attack)
    for start in range(0, 100, 50):
        push(live, [item(wz(ts=f"2026-11-22T11:{n % 60:02d}:{n // 60:02d}.000+0000", wid=f"5.{n}",
                            eventdata={"targetUserName": "j.rao"})) for n in range(start, start + 50)])
    res = main._load_result()
    live_alerts = [a for a in res["alerts"] if a["source"] == "wazuh"]
    assert len(live_alerts) <= 60
    assert {"wz-1763800001.1", "wz-1763800001.2", "wz-1763800001.3"} <= {a["alert_id"] for a in live_alerts}
    m = res["metrics"]
    assert m["rolled_off"] > 0 and m["received"] == m["total"] + m["rolled_off"]
    assert m["closed_by_code"]["BENIGN_EXPECTED"] >= 100


def test_firing_the_demo_attack_leaves_a_real_feed_alone(live):
    _, attack = _busy_host()
    push(live, attack)
    r = live.post("/demo/fire", data={"csrf": _csrf(live), "benign": "on"}, follow_redirects=False)
    assert r.status_code == 303
    res = main._load_result()
    assert sum(1 for a in res["alerts"] if a["source"] == "wazuh") == 3
    live.post("/demo/fire", data={"csrf": _csrf(live), "benign": "on"}, follow_redirects=False)
    res = main._load_result()
    assert sum(1 for a in res["alerts"] if a["client"] == demo_attack.DEFAULT_CLIENT) == 6
    assert sum(1 for a in res["alerts"] if a["source"] == "wazuh") == 3


def test_an_incident_can_be_opened_by_its_reference(live):
    _, attack = _busy_host()
    push(live, attack)
    inc = next(i for i in main._load_result()["incidents"] if i["key"] == "WKS-01")
    assert live.get(f"/report/{inc['id']}").status_code == 200
    assert live.get("/report/WKS-01").status_code == 200


def test_state_endpoint_needs_a_session_and_moves_with_the_queue(live):
    assert TestClient(main.app).get("/api/state", follow_redirects=False).status_code in (303, 401)
    before = live.get("/api/state").json()
    push(live, [item(wz(wid="6.1"))])
    after = live.get("/api/state").json()
    assert after["rev"] > before["rev"] and after["received"] == before["received"] + 1
