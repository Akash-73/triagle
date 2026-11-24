"""
Triagle — use cases.

A SOC does not work "alerts", it works use cases: "password guessing from one
address", "obfuscated PowerShell", "sign-in after password guessing". The
same use case can arrive from five tools under five rule names. This module
gives each alert the name of the use case it belongs to, the ATT&CK technique
and tactic, and the question an analyst has to answer for it.

The name comes from evidence, in this order:
  1. a pattern Triagle found across alerts (verdict.pattern)
  2. a command-line behaviour (signals.matched_behaviours)
  3. an OT signal
  4. a risk term the source tool wrote (signals.matched_terms)
  5. a softer term (suspicious / sensitive)
  6. the alert kind (posture finding, health event)
If nothing matches, the alert keeps the source tool's own title and is
labelled "Uncatalogued": an honest gap, and a list of what to write next.

Each use case has a stable id (UC-nnn) so it can be referenced in a report,
a tuning note or a playbook.
"""
import re

from app.engine import ot, signals

# id, name, technique, tactic, the analyst's question
CATALOGUE = {
    "password_guessing": ("UC-101", "Password guessing from one address", "T1110.001", "Credential access",
                          "Is the service meant to be reachable from the internet, and did any attempt succeed?"),
    "guessing_then_success": ("UC-102", "Sign-in after password guessing", "T1078", "Initial access",
                              "Was this sign-in the account owner, or the attacker getting in?"),
    "brute_force": ("UC-103", "Brute-force sign-in attempts", "T1110", "Credential access",
                    "Did any attempt succeed, and is the source still trying?"),
    "password_spray": ("UC-104", "Password spraying across accounts", "T1110.003", "Credential access",
                       "Which accounts were tried, and did any of them sign in afterwards?"),
    "impossible_travel": ("UC-105", "Sign-in from an impossible location", "T1078", "Initial access",
                          "Can the user be in both places, or is the session stolen?"),
    "scan": ("UC-107", "Network or port scan from outside", "T1595", "Reconnaissance",
             "Probing only, or did anything answer that should not be exposed?"),
    "user_execution": ("UC-205", "User tricked into running a command", "T1204", "Execution",
                       "What did the command do, and is the same lure reaching other users?"),
    "token_theft": ("UC-106", "Session token theft (phishing proxy)", "T1557", "Credential access",
                    "Which sessions must be revoked, and what did the stolen session touch?"),

    "encoded_powershell": ("UC-201", "Obfuscated PowerShell execution", "T1059.001", "Execution",
                           "What does the encoded command do, and who started it?"),
    "download_cradle": ("UC-202", "PowerShell download and run", "T1105", "Command and control",
                        "What was fetched, from where, and did it run?"),
    "psexec": ("UC-203", "Remote execution with PsExec", "T1569.002", "Lateral movement",
               "Is this an administrator's own tool, or an attacker moving between hosts?"),
    "script_in_temp": ("UC-204", "Script or executable dropped in a temp folder", "T1204", "Execution",
                       "Who dropped the file, and has it run?"),

    "credential_dumping": ("UC-301", "Credential dumping from memory", "T1003.001", "Credential access",
                           "Which accounts were signed in to this host and must be reset?"),
    "hive_dump": ("UC-302", "Registry credential hive dump", "T1003.002", "Credential access",
                  "Which local and cached credentials are exposed?"),
    "ntds": ("UC-303", "Active Directory database theft", "T1003.003", "Credential access",
             "Treat every domain credential as exposed: has the copy left the network?"),
    "lateral_movement": ("UC-304", "Lateral movement between hosts", "T1021", "Lateral movement",
                         "Which hosts has this account reached, and from where did it start?"),
    "privilege_escalation": ("UC-305", "Privilege escalation", "T1068", "Privilege escalation",
                             "What rights were gained, and by which account?"),

    "ransomware": ("UC-401", "Ransomware behaviour", "T1486", "Impact",
                   "How far has encryption spread, and are the backups intact?"),
    "inhibit_recovery": ("UC-402", "Recovery options destroyed", "T1490", "Impact",
                         "This usually comes minutes before encryption: is the host isolated?"),
    "exfiltration": ("UC-403", "Data taken out of the network", "T1041", "Exfiltration",
                     "What data left, how much, and does it include personal data?"),
    "c2": ("UC-404", "Command-and-control traffic", "T1071", "Command and control",
           "Which internal host is talking, and what else has it contacted?"),
    "log_clearing": ("UC-405", "Event logs cleared", "T1070.001", "Defence evasion",
                     "What was the attacker hiding, and is a copy of the logs held elsewhere?"),
    "infostealer": ("UC-406", "Information-stealer malware", "T1555", "Credential access",
                    "Which saved passwords and sessions on this machine are now exposed?"),
    "malware": ("UC-407", "Malware detected on an endpoint", "T1204", "Execution",
                "Did it run, and did the endpoint tool stop it?"),

    "ot_command": ("UC-501", "Unauthorised command to a controller", "T0855", "Impair process control",
                   "Call the control room: was this command expected, and what state is the process in?"),
    "ot_program": ("UC-502", "Controller program or firmware change", "T0843", "Persistence",
                   "Was a change planned? Compare the running logic with the last known good copy."),
    "ot_activity": ("UC-503", "Unexpected activity on an OT network", "T0886", "Lateral movement",
                    "Which IT system reached into the plant network, and should it be able to?"),

    "account_change": ("UC-601", "Privileged account or access change", "T1098", "Persistence",
                       "Was this change requested and approved?"),
    "security_tool_stopped": ("UC-602", "Security tool stopped or tampered with", "T1562.001", "Defence evasion",
                              "Who stopped it, and what ran while it was off?"),
    "config_drift": ("UC-701", "Security setting changed from passed to failed", "T1562", "Defence evasion",
                     "Who changed the setting, and was it deliberate?"),

    "posture": ("UC-801", "Configuration or vulnerability finding", None, "Posture",
                "No attack. Goes to the hardening backlog."),
    "operational": ("UC-802", "System health event", None, "Operations",
                    "No attack. Goes to the operations team."),
    "known_tool": ("UC-803", "Known administration tool", None, "Routine",
                   "No attack. A trusted tool doing its documented job."),
    "routine": ("UC-804", "Routine activity", None, "Routine", "No attack."),
    "discovery": ("UC-805", "Discovery command", "T1087", "Discovery",
                  "Not evidence on its own. Shown as context if a case opens on the same asset."),
}

_BEHAVIOUR_TO = {
    "shadow copy deletion": "inhibit_recovery", "backup catalog deletion": "inhibit_recovery",
    "recovery disabled": "inhibit_recovery",
    "process memory dump (comsvcs)": "credential_dumping", "LSASS dump tool": "credential_dumping",
    "encoded PowerShell": "encoded_powershell", "PowerShell download cradle": "download_cradle",
    "remote service execution (PsExec)": "psexec", "directory database access": "ntds",
    "registry hive dump": "hive_dump", "event log clearing": "log_clearing",
}

# first match wins, so the more specific term comes first
_TERM_TO = [
    (("ransomware", "ransom note", "files encrypted for impact", "data encrypted for impact", "encrypting files"),
     "ransomware"),
    (("shadow copies deleted",), "inhibit_recovery"),
    (("exfiltration", "data theft"), "exfiltration"),
    (("credential dump", "credential dumping", "credential theft", "lsass", "mimikatz",
      "golden ticket", "dcsync", "pass the hash"), "credential_dumping"),
    (("token theft", "session hijack", "adversary-in-the-middle"), "token_theft"),
    (("cobalt strike", "c2", "command and control", "beaconing"), "c2"),
    (("lateral movement",), "lateral_movement"),
    (("domain admin", "privilege escalation"), "privilege_escalation"),
]
_SOFT_TO = [
    (("impossible travel", "unfamiliar"), "impossible_travel"),
    (("password spray",), "password_spray"),
    (("brute",), "brute_force"),
    (("malware", "trojan", "exploit"), "malware"),
]
# identity tools name their detections in camelCase (impossibleTravel,
# passwordSpray); read those as words
_TITLE_TO = [
    (("impossible travel", "unfamiliar features", "unfamiliar sign", "atypical travel", "anonymized ip",
      "anonymous ip", "malicious ip"), "impossible_travel"),
    (("password spray",), "password_spray"),
    (("leaked credentials",), "token_theft"),
    (("infostealer", "stealer"), "infostealer"),
    (("base64 encoded", "encoded command"), "encoded_powershell"),
    (("port scan", "network scan", "scan detected", "scanning"), "scan"),
    (("clickfix", "fake captcha", "human-verification", "copy and paste"), "user_execution"),
]


def _words(title):
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", str(title or "")).lower()


def _get(alert, key):
    return alert.get(key) if isinstance(alert, dict) else getattr(alert, key, None)


def _key_for(alert, verdict):
    verdict = verdict or {}
    if verdict.get("pattern") in CATALOGUE:
        return verdict["pattern"]
    terms = signals.matched_terms(alert)
    if any(t in _TERM_TO[0][0] for t in terms):
        return "ransomware"              # the name analysts use, even when the evidence is a symptom
    behaviours = signals.matched_behaviours(alert)
    for b in behaviours:
        if b in _BEHAVIOUR_TO:
            return _BEHAVIOUR_TO[b]
    title = str(_get(alert, "title") or "").lower()
    ot_signals = ot.signals(alert)
    if ot_signals:
        joined = " ".join(ot_signals).lower()
        if any(w in joined for w in ("program", "logic", "firmware")):
            return "ot_program"
        if ot.controllers(alert) or any(w in joined for w in ("command", "stop", "restart", "force", "setpoint")):
            return "ot_command"
        return "ot_activity"
    spaced = _words(_get(alert, "title"))
    for words, key in _TITLE_TO:             # the tool's own name for it
        if any(w in spaced for w in words):
            return key
    for words, key in _TERM_TO:
        if any(t in words for t in terms):
            return key
    soft = signals.suspicious_terms(alert)
    for words, key in _SOFT_TO:
        if any(t in words for t in soft):
            return key
    ind = _get(alert, "indicators") or {}
    if ind.get("drift"):
        return "config_drift"
    kind = signals.kind(alert)
    if kind == signals.POSTURE:
        return "posture"
    if kind == signals.OPERATIONAL:
        return "operational"
    if signals.routine_discovery(alert):
        return "discovery"
    if signals.sensitive_terms(alert):
        if any(w in title for w in ("stopped", "disabled", "tamper", "uninstall")):
            return "security_tool_stopped"
        return "account_change"
    if ind.get("target_file") and any(w in title for w in ("dropped", "created under")):
        return "script_in_temp"
    code = verdict.get("closure_code")
    if code == "BENIGN_KNOWN_TOOL":
        return "known_tool"
    if code in ("BENIGN_EXPECTED", "BENIGN_DUPLICATE") and not verdict.get("escalate"):
        return "routine"
    return None


def for_alert(alert, verdict=None):
    """{id, name, technique, tactic, question, catalogued} for one alert."""
    key = _key_for(alert, verdict)
    if key:
        uid, name, technique, tactic, question = CATALOGUE[key]
        return {"key": key, "id": uid, "name": name, "technique": technique, "tactic": tactic,
                "question": question, "catalogued": True}
    ind = _get(alert, "indicators") or {}
    technique = str(ind.get("mitre_ids") or ind.get("technique") or "").split(",")[0].strip()
    technique = technique if re.fullmatch(r"T\d{4}(\.\d{3})?", technique) else None
    tactic = str(ind.get("mitre_tactics") or "").split(",")[0].strip() or "Uncatalogued"
    return {"key": None, "id": "UC-000", "name": str(_get(alert, "title") or "Unnamed alert"),
            "technique": technique, "tactic": tactic,
            "question": "No use case is written for this yet. Decide from the evidence below.",
            "catalogued": False}


def for_case(members):
    """The use case that names a case: the most serious one among its
    escalated alerts (Impact before Credential access before the rest)."""
    order = ["ransomware", "inhibit_recovery", "exfiltration", "ot_command", "ot_program", "credential_dumping",
             "ntds", "hive_dump", "guessing_then_success", "token_theft", "lateral_movement", "c2",
             "encoded_powershell", "download_cradle", "psexec", "log_clearing", "infostealer", "malware"]
    found = [for_alert(m["alert"], m["verdict"]) for m in members if m["verdict"].get("escalate")]
    if not found:
        found = [for_alert(m["alert"], m["verdict"]) for m in members]
    if not found:
        return None
    found.sort(key=lambda u: order.index(u["key"]) if u["key"] in order else len(order) + (0 if u["catalogued"] else 1))
    return found[0]
