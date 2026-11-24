"""
Triagle — Wazuh connector.

Reads an alert exactly as Wazuh writes it to /var/ossec/logs/alerts/alerts.json
(one JSON object per line) and returns a NormalizedAlert. Nothing is rewritten
on the Wazuh side: the forwarder ships the alert untouched and the mapping
lives here, where it can be tested.

Three decisions worth knowing about:

  SEVERITY  Wazuh rates a rule from 0 to 15. We use the same bands the Wazuh
            dashboard uses: 0-6 low, 7-11 medium, 12-14 high, 15 critical.

  KIND      Wazuh tags every rule with groups. Three families are not activity
            on the machine and are marked so the engine can treat them for
            what they are:
              posture      benchmark results (sca) and vulnerability-scan
                           findings (vulnerability-detector)
              operational  errors, crashes, shutdowns, full disks
            Everything else is activity and goes through normal triage. A
            benchmark check that goes from passed to failed is a change, not
            a state, so it stays activity and is flagged as drift.

  TEXT      The only words matched against the risk-term lists are the rule
            description, which the Wazuh ruleset wrote. MITRE tactic labels
            are kept for display but not matched: Wazuh tags an ordinary
            logon with "Privilege Escalation" because a valid account could
            be used for it, and a label is not evidence. The raw event text
            (full_log, the Windows event message) is not matched either,
            because it holds file paths and other strings an attacker can
            choose. Command lines are matched, by the behaviour patterns.
"""
import hashlib
import ipaddress
import re
from datetime import datetime, timezone

from app.models import NormalizedAlert

POSTURE_GROUPS = {"sca", "vulnerability-detector", "ciscat", "oscap"}
OPERATIONAL_GROUPS = {"system_error", "system_shutdown", "low_diskspace"}
# health-looking rules from these families are still left as activity: a
# security control that keeps failing is worth a look
NOT_OPERATIONAL_GROUPS = {"windows_defender", "windows_firewall", "firewall"}
OPERATIONAL_RULE_IDS = {"61105", "64103"}          # unexpected power loss / file system full
_MULTIPLE_HEALTH = re.compile(r"^multiple .*\b(error|warning|critical)\b.*events?\.?$")
DRIFT_RULE_IDS = {"19011", "19014"}                # benchmark check: passed/NA -> failed

# principals that are the operating system, not a person
_SYSTEM_PRINCIPALS = {"", "-", "system", "local service", "network service", "localsystem",
                      "anonymous logon", "window manager", "font driver host", "n/a", "none"}
_SYSTEM_PREFIXES = ("dwm-", "umfd-")


def severity(level):
    try:
        n = int(level)
    except (TypeError, ValueError):
        return "medium"
    if n >= 15:
        return "critical"
    if n >= 12:
        return "high"
    if n >= 7:
        return "medium"
    return "low"


def _ts(value):
    """Wazuh writes 2026-11-22T14:01:12.345+0000. Return ...Z in UTC."""
    s = str(value or "").strip()
    if not s:
        return ""
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _principal(*candidates):
    """First candidate that is a person or a named service account."""
    for c in candidates:
        if not c:
            continue
        u = str(c).strip()
        if "\\" in u:
            u = u.rsplit("\\", 1)[-1]
        low = u.lower()
        if low in _SYSTEM_PRINCIPALS or low.endswith("$") or low.startswith(_SYSTEM_PREFIXES):
            continue
        return u
    return None


def _ip(*candidates):
    """First candidate that is a usable address (not loopback, not empty)."""
    for c in candidates:
        if not c:
            continue
        s = str(c).strip()
        if s.startswith("::ffff:"):
            s = s[7:]
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
            continue
        return s
    return None


def _sha256(hashes):
    m = re.search(r"SHA256=([0-9A-Fa-f]{64})", str(hashes or ""))
    return m.group(1).lower() if m else None


def _groups(rule):
    return [str(g).strip().lower() for g in (rule.get("groups") or []) if str(g).strip()]


AUTH_FAILED_GROUPS = {"authentication_failed", "authentication_failures", "invalid_login"}
AUTH_SUCCESS_GROUPS = {"authentication_success"}


def sign_in(groups):
    """failed | success | None, from Wazuh's own rule groups."""
    g = set(groups)
    if g & AUTH_FAILED_GROUPS:
        return "failed"
    if g & AUTH_SUCCESS_GROUPS:
        return "success"
    return None


def classify(raw):
    """(kind, reason, drift) from Wazuh's own rule groups."""
    rule = raw.get("rule") or {}
    groups = set(_groups(rule))
    rid = str(rule.get("id") or "")
    desc = str(rule.get("description") or "").strip().lower()

    if "sca" in groups:
        check = ((raw.get("data") or {}).get("sca") or {}).get("check") or {}
        went_bad = (str(check.get("result") or "").lower() == "failed"
                    and str(check.get("previous_result") or "").lower() in ("passed", "not applicable"))
        if rid in DRIFT_RULE_IDS or went_bad:
            return "activity", "benchmark check that stopped passing", True
        return "posture", "configuration-benchmark result", False
    if groups & POSTURE_GROUPS:
        return "posture", "vulnerability-scan finding", False

    if not groups & NOT_OPERATIONAL_GROUPS:
        if groups & OPERATIONAL_GROUPS or rid in OPERATIONAL_RULE_IDS or _MULTIPLE_HEALTH.match(desc):
            return "operational", "system health event", False
    return "activity", "", False


def _describe(raw, host):
    """One neutral line built from structured fields only."""
    data = raw.get("data") or {}
    system = (data.get("win") or {}).get("system") or {}
    if system:
        channel = str(system.get("channel") or system.get("providerName") or "Windows").split("/")[0]
        channel = channel.replace("Microsoft-Windows-", "")
        return f"{channel} event {system.get('eventID', '?')} on {host}."
    if raw.get("syscheck"):
        return f"File integrity monitoring: {str((raw['syscheck']).get('event') or 'change')} on {host}."
    if data.get("vulnerability"):
        v = data["vulnerability"]
        return f"Vulnerability scan: {v.get('cve', 'CVE')} ({str(v.get('severity') or 'unrated').lower()}) on {host}."
    if data.get("sca"):
        return f"Configuration benchmark result on {host}."
    loc = str(raw.get("location") or "").strip()
    return f"Log source {loc} on {host}." if loc else f"Reported by the Wazuh agent on {host}."


def from_wazuh(raw, client):
    """A Wazuh alert, as written to alerts.json."""
    rule = raw.get("rule")
    if not isinstance(rule, dict) or not rule.get("description"):
        raise ValueError("not a Wazuh alert: no rule.description")
    agent = raw.get("agent") or {}
    manager = raw.get("manager") or {}
    data = raw.get("data") or {}
    win = data.get("win") or {}
    # Wazuh writes Windows event data with every backslash doubled
    # (C:\\Windows\\System32). Undo that once, so paths and command lines read
    # the way Windows wrote them and match the way an analyst would search.
    ev = {k: (v.replace("\\\\", "\\") if isinstance(v, str) else v)
          for k, v in (win.get("eventdata") or {}).items()}
    system = win.get("system") or {}
    mitre = rule.get("mitre") or {}
    syscheck = raw.get("syscheck") or {}
    vuln = data.get("vulnerability") or {}

    host = agent.get("name") or system.get("computer") or manager.get("name") or "unknown"
    user = _principal(ev.get("user"), ev.get("subjectUserName"), ev.get("targetUserName"),
                      data.get("srcuser"), data.get("dstuser"))
    target_user = _principal(ev.get("targetUserName"), data.get("dstuser"))
    src_ip = _ip(data.get("srcip"), ev.get("ipAddress"), ev.get("sourceIp"), ev.get("sourceAddress"))
    dst_ip = _ip(data.get("dstip"), ev.get("destinationIp"), ev.get("destAddress"))

    wid = raw.get("id")
    if not wid:
        seed = f"{raw.get('timestamp')}|{rule.get('id')}|{agent.get('id')}|{raw.get('full_log', '')[:200]}"
        wid = hashlib.sha1(seed.encode()).hexdigest()[:16]

    kind, reason, drift = classify(raw)
    groups = _groups(rule)
    if "triagle" in groups or "triagle" in (raw.get("data") or {}):
        # Triagle's own verdict, written back to Wazuh and read by it as a log
        # line. It is not an alert to triage; taking it in would loop.
        raise ValueError("a Triagle verdict read back from Wazuh is not an alert")
    # The behaviour patterns are matched against the command line. PowerShell
    # script-block logging (event 4104) does not fill commandLine — it logs the
    # code that ran in scriptBlockText — so a download cradle or an encoded
    # payload would be invisible if that field were ignored. Read it as the
    # command line when there is no process command line.
    cmdline = ev.get("commandLine") or data.get("command") or ev.get("scriptBlockText") or ""

    def joined(v):
        return ", ".join(str(x) for x in v) if isinstance(v, (list, tuple)) else (str(v) if v else None)

    indicators = {
        "cmdline": str(cmdline)[:2000] or None,
        "image": ev.get("image"),
        "parent_image": ev.get("parentImage"),
        "target_file": ev.get("targetFilename") or syscheck.get("path"),
        "registry_key": ev.get("targetObject"),
        "sha256": _sha256(ev.get("hashes")) or syscheck.get("sha256_after"),
        "domain": ev.get("queryName"),
        "dstport": ev.get("destinationPort") or data.get("dstport"),
        "target_user": target_user if target_user and target_user != user else None,
        "logon_type": ev.get("logonType"),
        "event_id": system.get("eventID"),
        "channel": system.get("channel"),
        "cve": vuln.get("cve"),
        "package": (vuln.get("package") or {}).get("name") or data.get("package"),
        "rule_id": str(rule.get("id") or "") or None,
        "rule_level": str(rule.get("level")) if rule.get("level") is not None else None,
        "rule_groups": joined(groups),
        "mitre_ids": joined(mitre.get("id")),
        "mitre_techniques": joined(mitre.get("technique")),
        "mitre_tactics": joined(mitre.get("tactic")),
        "agent_id": agent.get("id"),
        "agent_ip": agent.get("ip"),
        "log_source": raw.get("location"),
        "kind": kind if kind != "activity" else None,
        "kind_reason": reason or None,
        "drift": True if drift else None,
        "auth": sign_in(groups),
    }

    return NormalizedAlert(
        alert_id=f"wz-{wid}",
        source="wazuh",
        client=client,
        timestamp=_ts(raw.get("timestamp")),
        title=str(rule.get("description")).strip()[:240],
        raw_severity=severity(rule.get("level")),
        entity=host,
        host=host,
        user=user,
        src_ip=src_ip,
        dst_ip=dst_ip,
        description=_describe(raw, host),
        indicators={k: v for k, v in indicators.items() if v not in (None, "")},
        raw=raw,
    )
