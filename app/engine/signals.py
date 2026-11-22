"""
Triagle — risk signals.

One place that decides whether an alert carries a signal that must reach a
human. Two kinds:

  TERMS      words an alerting tool uses for hands-on-keyboard or destructive
             activity. Matched on word boundaries, and only in the fields a
             tool writes for people (title, description, tactic, technique).
             Hashes, hostnames and file paths are never searched, so a hash
             that happens to contain "c2" or a host called EC2-APP-01 cannot
             trip it.

  BEHAVIOURS command-line shapes that mean the same thing however the alert
             is titled. These catch the quiet cases: a "low" alert called
             "Volume shadow copy administration" whose command line is
             vssadmin delete shadows.

Both lists are deliberately small and readable. They are a floor under the
model, not a replacement for it.

Two softer lists sit below them: SUSPICIOUS (worth a human look, not proof)
and SENSITIVE (changes that are routine most days and the first step of a
takeover on others).

Alert KINDS. Some sources tell us an alert is not activity at all: a
configuration-benchmark result, a vulnerability-scan finding, a system health
event. A connector records that as indicators["kind"], taken from the source
tool's own classification (never from text an attacker can write). For a
posture finding the title is the name of a check, not a description of what
someone did, so word matching is not run on it. Command lines are always
checked, whatever the kind.
"""
import re
from functools import lru_cache

TERMS = [
    "ransomware", "ransom note", "files encrypted for impact", "data encrypted for impact",
    "encrypting files", "shadow copies deleted", "exfiltration", "data theft",
    "domain admin", "credential dump", "credential dumping", "credential theft", "lsass", "mimikatz",
    "cobalt strike", "lateral movement", "privilege escalation", "c2",
    "command and control", "beaconing", "golden ticket", "dcsync", "pass the hash",
    "token theft", "session hijack", "adversary-in-the-middle",
]
_TERM_RE = [(t, re.compile(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])")) for t in TERMS]

# A real process-creation event often quotes the image path:
#   "C:\Windows\System32\vssadmin.exe" delete shadows /all
# so each tool name may be followed by .exe and a closing quote.
_X = r'(\.exe)?"?'
_ENC = (r"[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|"
        r"encodedcomm|encodedcomma|encodedcomman|encodedcommand)")
BEHAVIOURS = [
    ("shadow copy deletion", r"vssadmin" + _X + r"\s+.*delete\s+shadows|shadowcopy\s+.*delete"),
    ("backup catalog deletion", r"wbadmin" + _X + r"\s+delete\s+(catalog|systemstatebackup)"),
    ("recovery disabled", r"bcdedit" + _X + r"\s+.*recoveryenabled\s+no"),
    ("process memory dump (comsvcs)", r"comsvcs(\.dll)?\W+.*minidump"),
    ("LSASS dump tool", r"procdump.*lsass|sekurlsa|mimikatz"),
    ("encoded PowerShell", r"(powershell|pwsh)" + _X + r"\s+(.*\s)?" + _ENC + r"\s+[a-z0-9+/=]{16,}"),
    ("PowerShell download cradle", r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|\biex\s*\(|invoke-expression"),
    ("remote service execution (PsExec)", r"psexesvc|psexec" + _X + r"\s+\\\\"),
    ("directory database access", r"ntdsutil|ntds\.dit"),
    ("registry hive dump", r"reg" + _X + r"\s+save\s+hklm\\(sam|system|security)"),
    ("event log clearing", r"wevtutil" + _X + r"\s+(cl|clear-log)\s|clear-eventlog"),
]
_BEHAVIOUR_RE = [(name, re.compile(rx, re.I)) for name, rx in BEHAVIOURS]

# Worth a human look, not proof of compromise.
SUSPICIOUS = ["impossible travel", "brute", "password spray", "anomalous",
              "unfamiliar", "malware", "trojan", "exploit", "suspicious"]

# Changes that are routine most days and the first move of an account or host
# takeover on the wrong day. Never auto-closed on severity alone.
SENSITIVE = [
    "inbox rule", "forward", "mfa", "authenticator", "role assigned", "administrator role",
    "consent", "scheduled task", "service created", "service installed", "new account",
    "account created", "shadow copy", "backup catalog", "boot configuration",
    "recovery disabled", "recovery options", "recovery settings", "recovery key", "system recovery",
    "memory dump", "mass file download", "mass download", "firewall rule",
    ("audit log", r"audit log(?!on)"),      # "audit log cleared", not "Audit Logon"
    "log was cleared", "log cleared", "security tool disabled", "tamper",
    # autorun persistence: tools often rate these low
    "next logon", "run key", "autorun", "startup folder", "start-up folder", "startup registry",
    "persistence",
]


def _word_start(terms):
    """Match a term only where a word starts, so "antimalware" is not "malware"
    and "transform" is not "forward". A term may still run on into a longer
    word ("forwarding", "unfamiliarFeatures")."""
    out = []
    for t in terms:
        label, body = (t, re.escape(t)) if isinstance(t, str) else t
        out.append((label, re.compile(r"(?<![a-z0-9])" + body)))
    return out


_SUSPICIOUS_RE = _word_start(SUSPICIOUS)
_SENSITIVE_RE = _word_start(SENSITIVE)

# Kinds a connector may set from the source tool's own classification.
POSTURE = "posture"            # benchmark / vulnerability-scan result
OPERATIONAL = "operational"    # system health, not a security detection
ACTIVITY = "activity"          # everything else (the default)


def _get(alert, key):
    return alert.get(key) if isinstance(alert, dict) else getattr(alert, key, None)


def human_text(alert):
    """Fields written for people. Lower-cased."""
    ind = _get(alert, "indicators") or {}
    parts = [_get(alert, "title"), _get(alert, "description"), ind.get("tactic"), ind.get("technique")]
    return " ".join(str(p) for p in parts if p).lower()


def command_line(alert):
    ind = _get(alert, "indicators") or {}
    return str(ind.get("cmdline") or "")


# The same routine alert arrives hundreds of times on a live stream and each
# alert is looked at several times in one pass, so the scans are memoised on
# the text itself.
@lru_cache(maxsize=16384)
def _scan_text(text):
    return (tuple(t for t, rx in _TERM_RE if rx.search(text)),
            tuple(t for t, rx in _SUSPICIOUS_RE if rx.search(text)),
            tuple(t for t, rx in _SENSITIVE_RE if rx.search(text)))


@lru_cache(maxsize=16384)
def _scan_cmd(cmd):
    return tuple(name for name, rx in _BEHAVIOUR_RE if rx.search(cmd))


def matched_terms(alert):
    return list(_scan_text(human_text(alert))[0])


def matched_behaviours(alert):
    cmd = command_line(alert)
    return list(_scan_cmd(cmd)) if cmd else []


def kind(alert):
    """posture | operational | activity. Set by a connector; activity if unset."""
    ind = _get(alert, "indicators") or {}
    k = ind.get("kind")
    return k if k in (POSTURE, OPERATIONAL) else ACTIVITY


def hard_signals(alert):
    """Everything that forces escalation. Empty list = none."""
    if kind(alert) == POSTURE:
        # the title is a check name ("Ensure LSASS runs as a protected process"),
        # not activity; only a command line can carry a signal here
        return matched_behaviours(alert)
    return matched_terms(alert) + matched_behaviours(alert)


def suspicious_terms(alert):
    return list(_scan_text(human_text(alert))[1])


def sensitive_terms(alert):
    return list(_scan_text(human_text(alert))[2])


_SEV_HIGH = ("high", "critical")
_SEV_LOW = ("low", "informational", "info")


def is_notable(alert):
    """Would an analyst pivoting on this host or user stop at this alert?
    Routine low-severity telemetry and posture findings are not notable, so
    they never count as corroboration for something else."""
    if kind(alert) != ACTIVITY:
        return bool(matched_behaviours(alert))
    if hard_signals(alert) or (_get(alert, "indicators") or {}).get("drift"):
        return True
    sev = str(_get(alert, "raw_severity") or "").lower()
    if sev in _SEV_HIGH:
        return True
    return bool(suspicious_terms(alert) or sensitive_terms(alert))


def has_own_weight(alert):
    """Can related activity raise this alert? Only if it is security-relevant
    in its own right: not a posture or health event, and either above low
    severity or carrying a suspicious or sensitive term."""
    if kind(alert) != ACTIVITY:
        return False
    sev = str(_get(alert, "raw_severity") or "").lower()
    if sev not in _SEV_LOW:
        return True
    return bool(suspicious_terms(alert) or sensitive_terms(alert))
