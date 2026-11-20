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
"""
import re

TERMS = [
    "ransomware", "ransom note", "files encrypted for impact", "data encrypted for impact",
    "encrypting files", "shadow copies deleted", "exfiltration", "data theft",
    "domain admin", "credential dump", "credential dumping", "credential theft", "lsass", "mimikatz",
    "cobalt strike", "lateral movement", "privilege escalation", "c2",
    "command and control", "beaconing", "golden ticket", "dcsync", "pass the hash",
    "token theft", "session hijack", "adversary-in-the-middle",
]
_TERM_RE = [(t, re.compile(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])")) for t in TERMS]

BEHAVIOURS = [
    ("shadow copy deletion", r"vssadmin(\.exe)?\s+.*delete\s+shadows|shadowcopy\s+.*delete"),
    ("backup catalog deletion", r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)"),
    ("recovery disabled", r"bcdedit(\.exe)?\s+.*recoveryenabled\s+no"),
    ("process memory dump (comsvcs)", r"comsvcs(\.dll)?\W+.*minidump"),
    ("LSASS dump tool", r"procdump.*lsass|sekurlsa|mimikatz"),
    ("encoded PowerShell", r"powershell(\.exe)?\s+.*-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{16,}"),
    ("PowerShell download cradle", r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|\biex\s*\(|invoke-expression"),
    ("remote service execution (PsExec)", r"psexesvc|psexec(\.exe)?\s+\\\\"),
    ("directory database access", r"ntdsutil|ntds\.dit"),
    ("registry hive dump", r"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)"),
    ("event log clearing", r"wevtutil(\.exe)?\s+cl\s|clear-eventlog"),
]
_BEHAVIOUR_RE = [(name, re.compile(rx, re.I)) for name, rx in BEHAVIOURS]

# Changes that are routine most days and the first move of an account or host
# takeover on the wrong day. Never auto-closed on severity alone.
SENSITIVE = [
    "inbox rule", "forward", "mfa", "authenticator", "role assigned", "administrator role",
    "consent", "scheduled task", "service created", "service installed", "new account",
    "account created", "shadow copy", "backup catalog", "boot configuration", "recovery",
    "memory dump", "mass file download", "mass download", "firewall rule", "audit log",
    "security tool disabled", "tamper",
]


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


def matched_terms(alert):
    text = human_text(alert)
    return [t for t, rx in _TERM_RE if rx.search(text)]


def matched_behaviours(alert):
    cmd = command_line(alert)
    return [name for name, rx in _BEHAVIOUR_RE if cmd and rx.search(cmd)]


def hard_signals(alert):
    """Everything that forces escalation. Empty list = none."""
    return matched_terms(alert) + matched_behaviours(alert)


def sensitive_terms(alert):
    text = human_text(alert)
    return [t for t in SENSITIVE if t in text]
