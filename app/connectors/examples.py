"""
Triagle — example alerts and setup steps for each connector.

Used by the Connectors page: the "try an alert" box loads these, and the
setup panel shows the steps. Every example is an alert in the shape the tool
itself emits. Names, hosts and addresses are invented; addresses come from
the documentation ranges.
"""

# what each connector is, in the order the page lists them
CATALOGUE = [
    {"key": "wazuh", "name": "Wazuh", "kind": "SIEM / XDR", "how": "forwarder",
     "what": "Every alert the Wazuh manager writes, endpoints and servers."},
    {"key": "crowdstrike_edr", "name": "CrowdStrike Falcon", "kind": "EDR", "how": "webhook",
     "what": "Endpoint detections."},
    {"key": "entra_id", "name": "Microsoft Entra ID", "kind": "Identity", "how": "webhook",
     "what": "Risky sign-ins and risk detections."},
    {"key": "fortinet_fw", "name": "Fortinet FortiGate", "kind": "Firewall", "how": "webhook",
     "what": "Threat and traffic events."},
    {"key": "ot_monitor", "name": "OT network monitor", "kind": "OT / ICS", "how": "webhook",
     "what": "Alerts from a plant-network monitor (Zeek ICSNPP, Nozomi, Claroty and similar)."},
    {"key": "generic", "name": "Any other tool", "kind": "Webhook", "how": "webhook",
     "what": "A SIEM, a SOAR playbook or a script. Send a small JSON object; only a title is required."},
]

_PS = "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"

EXAMPLES = {
    "wazuh": [
        {"label": "Obfuscated PowerShell", "raw": {
            "timestamp": "2026-11-24T05:11:33.991+0000", "id": "1795500693.2201455",
            "rule": {"level": 12, "id": "92057", "groups": ["sysmon", "sysmon_eid1_detections", "windows"],
                     "description": "Powershell.exe spawned a powershell process which executed a base64 encoded command",
                     "mitre": {"id": ["T1059.001"], "tactic": ["Execution"], "technique": ["PowerShell"]}},
            "agent": {"id": "014", "name": "FIN-LAPTOP-07", "ip": "10.20.4.17"}, "manager": {"name": "wazuh"},
            "decoder": {"name": "windows_eventchannel"}, "location": "EventChannel",
            "data": {"win": {"system": {"eventID": "1", "computer": "FIN-LAPTOP-07"},
                             "eventdata": {"image": _PS, "parentImage": _PS, "user": "CORP\\\\r.iyer",
                                           "commandLine": f'"{_PS}" -EncodedCommand RwBlAHQALQBEAGEAdABlAA=='}}}}},
        {"label": "PowerShell policy file (rated critical by Wazuh)", "raw": {
            "timestamp": "2026-11-24T05:11:33.100+0000", "id": "1795500693.2201100",
            "rule": {"level": 15, "id": "92213", "groups": ["sysmon", "sysmon_eid11_detections", "windows"],
                     "description": "Executable file dropped in folder commonly used by malware"},
            "agent": {"id": "014", "name": "FIN-LAPTOP-07"}, "manager": {"name": "wazuh"},
            "decoder": {"name": "windows_eventchannel"}, "location": "EventChannel",
            "data": {"win": {"system": {"eventID": "11"}, "eventdata": {
                "image": _PS, "user": "CORP\\\\r.iyer",
                "targetFilename": "C:\\\\Users\\\\r.iyer\\\\AppData\\\\Local\\\\Temp\\\\__PSScriptPolicyTest_lpocpbf5.ccl.ps1"}}}}},
        {"label": "Discovery command", "raw": {
            "timestamp": "2026-11-24T05:10:48.034+0000", "id": "1795500648.2200901",
            "rule": {"level": 3, "id": "92032", "groups": ["sysmon", "sysmon_eid1_detections", "windows"],
                     "description": "Suspicious Windows cmd shell execution"},
            "agent": {"id": "014", "name": "FIN-LAPTOP-07"}, "manager": {"name": "wazuh"},
            "decoder": {"name": "windows_eventchannel"}, "location": "EventChannel",
            "data": {"win": {"system": {"eventID": "1"}, "eventdata": {"commandLine": "whoami  /all",
                                                                       "user": "CORP\\\\r.iyer"}}}}},
    ],
    "crowdstrike_edr": [
        {"label": "Credential dumping", "raw": {
            "detection_id": "ldt:example-101", "created_timestamp": "2026-11-24T08:02:00Z",
            "name": "Credential dumping via LSASS access", "severity": "critical", "tactic": "Credential Access",
            "technique": "OS Credential Dumping", "device": {"hostname": "HQ-WKS-22"}, "user_name": "s.verma",
            "description": "A process opened LSASS memory with read access.",
            "cmdline": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"}},
        {"label": "Remote support tool", "raw": {
            "detection_id": "ldt:example-102", "created_timestamp": "2026-11-24T08:05:00Z",
            "name": "Known admin tool: remote support session", "severity": "low",
            "device": {"hostname": "HQ-WKS-31"}, "user_name": "system",
            "description": "Signed remote-support agent started a scheduled session.",
            "cmdline": "\"C:\\Program Files\\ScreenConnect Client\\ScreenConnect.ClientService.exe\" \"?e=Access\""}},
    ],
    "entra_id": [
        {"label": "Impossible travel", "raw": {
            "id": "signin-example-1", "createdDateTime": "2026-11-24T08:10:00Z", "riskEventType": "impossibleTravel",
            "riskLevel": "high", "userPrincipalName": "a.khan@example.in", "ipAddress": "203.0.113.45",
            "riskDetail": "Sign-in from Lagos NG, 15 minutes after a sign-in from Kolkata IN.",
            "location": "Lagos, NG", "riskState": "atRisk", "clientAppUsed": "Browser"}},
    ],
    "fortinet_fw": [
        {"label": "Port scan from outside", "raw": {
            "logid": "0419016384", "eventtime": "2026-11-24T08:12:00Z", "type": "utm", "subtype": "ips",
            "level": "warning", "attack": "Port scan detected", "severity": "medium", "srcip": "198.51.100.77",
            "dstip": "10.0.5.20", "action": "detected", "msg": "TCP port scan from 198.51.100.77, 412 ports in 30 s"}},
    ],
    "ot_monitor": [
        {"label": "Breaker command to an RTU", "raw": {
            "id": "ot-example-1", "time": "2026-11-24T08:15:00Z", "name": "Unauthorised control command to RTU",
            "severity": "high", "protocol": "IEC 60870-5-104", "source": "PLANT-HMI-04", "target": "SUB-RTU-FEEDER-07",
            "technique": "T0855", "description": "Single command (C_SC_NA_1) OPEN sent to breaker Q0 from an engineering session outside the maintenance window."}},
    ],
    "generic": [
        {"label": "Minimal alert", "raw": {
            "title": "Outbound connection to known C2", "severity": "high", "host": "HQ-WKS-22",
            "user": "s.verma", "dst_ip": "203.0.113.90", "time": "2026-11-24T08:20:00Z",
            "description": "Beaconing every 60 s to an address on the command and control list."}},
        {"label": "Routine event", "raw": {
            "title": "User signed in", "severity": "low", "host": "HQ-WKS-31", "user": "n.rao",
            "time": "2026-11-24T08:21:00Z", "description": "Interactive logon during business hours."}},
    ],
}


def setup_steps(key, base_url, client="Your Company"):
    """The steps to connect one tool, with this deployment's address filled
    in. The ingest key is shown as a placeholder; the page reveals the real
    one only to a signed-in analyst."""
    url = base_url.rstrip("/")
    if key == "wazuh":
        return [
            {"say": "On the Wazuh server, download the forwarder. It reads the alert file Wazuh already writes; nothing changes inside Wazuh.",
             "code": "sudo mkdir -p /opt/triagle && cd /opt/triagle\n"
                     "sudo curl -fsSL -O https://raw.githubusercontent.com/Akash-73/triagle/v0.8-regional/scripts/wazuh_forwarder.py\n"
                     "sudo curl -fsSL -O https://raw.githubusercontent.com/Akash-73/triagle/v0.8-regional/scripts/triagle-forwarder.service"},
            {"say": "Tell it where Triagle is and which customer these alerts belong to.",
             "code": "sudo tee /etc/triagle-forwarder.env >/dev/null <<'EOF'\n"
                     f"TRIAGLE_URL={url}\nTRIAGLE_INGEST_KEY=YOUR_INGEST_KEY\nTRIAGLE_CLIENT=\"{client}\"\nEOF\n"
                     "sudo chmod 600 /etc/triagle-forwarder.env"},
            {"say": "Start it as a service. It sends the last 200 alerts, then follows new ones.",
             "code": "sudo install -m 644 triagle-forwarder.service /etc/systemd/system/\n"
                     "sudo systemctl daemon-reload && sudo systemctl enable --now triagle-forwarder"},
            {"say": "Optional: show Triagle's verdicts inside the Wazuh dashboard. The forwarder writes each verdict "
                    "to a file and these lines make Wazuh read it. The rules are checked before Wazuh restarts. "
                    "Afterwards, filter Threat Hunting by rule.groups: triagle",
             "code": "sudo curl -fsSL -o /var/ossec/etc/rules/triagle_rules.xml "
                     "https://raw.githubusercontent.com/Akash-73/triagle/v0.8-regional/scripts/wazuh/triagle_rules.xml\n"
                     "sudo chown wazuh:wazuh /var/ossec/etc/rules/triagle_rules.xml\n"
                     "sudo chmod 660 /var/ossec/etc/rules/triagle_rules.xml\n"
                     "sudo grep -q triagle-forwarder/verdicts.json /var/ossec/etc/ossec.conf || "
                     "printf '%s\\n' '<ossec_config>' '  <localfile>' '    <log_format>json</log_format>' "
                     "'    <location>/var/lib/triagle-forwarder/verdicts.json</location>' '  </localfile>' "
                     "'</ossec_config>' | sudo tee -a /var/ossec/etc/ossec.conf >/dev/null\n"
                     "sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager"},
        ]
    body = '{"source": "%s", "client": "%s", "raw": { ...the alert exactly as the tool emits it... }}' % (key, client)
    if key == "generic":
        body = ('{"source": "generic", "client": "%s", "raw": {"title": "...", "severity": "high", '
                '"host": "...", "user": "...", "src_ip": "...", "command_line": "..."}}' % client)
    return [
        {"say": "In the tool's webhook, notification or SOAR settings, add an HTTPS POST to this address with this header.",
         "code": f"POST {url}/ingest\nX-Triagle-Key: YOUR_INGEST_KEY\nContent-Type: application/json"},
        {"say": "Send each alert in this envelope. A list of up to 50 in one request also works.", "code": body},
        {"say": "Check it from any machine. A reply of {\"accepted\": 1} means it is connected.",
         "code": f"curl -s -X POST {url}/ingest -H 'X-Triagle-Key: YOUR_INGEST_KEY' -H 'Content-Type: application/json' \\\n  -d '{body}'"},
    ]
