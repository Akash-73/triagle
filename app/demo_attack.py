"""
Triagle — live demo attack generator.

Produces a fresh, coherent attack chain with timestamps ending ~1 minute ago,
so someone watching the screen sees Triagle investigate a *live* incident and
the reporting clocks start running. Nothing here is real: the clients, users,
hosts and the single public C2 IP are invented. The C2 IP and the loader hash
are ones already in the intel pack, so the threat-intel match fires without
any extra setup.

Used by POST /demo/fire (buttons on the dashboard) and by
scripts/fire_attack.py (which POSTs to /ingest over the network).

Two scenarios, the same intrusion in two regulated sectors:

  bank    a co-operative bank. Phish -> impossible-travel sign-in -> LSASS
          credential theft on an application server -> lateral movement to
          the domain controller -> ransomware behaviour -> beacon to known C2.
          Reports to CERT-In and the RBI.

  power   a power utility. The same chain, but the foothold is an operator
          station (an HMI) and the attacker goes on to send a control command
          to an RTU. Shows the OT rules: the HMI is not isolated, nothing is
          done to the RTU, containment is at the IT/OT boundary.

TRIAGLE_DEMO_SCENARIO picks the default (bank). TRIAGLE_DEMO_SCENARIOS limits
which ones a deployment offers at all.
"""
import datetime
import os

C2_IP = "185.220.101.44"                      # in the intel pack
LOADER_HASH = "e3b0c44298fc1c149afbf4c8996fb924"

SCENARIOS = {
    "bank": {
        "label": "co-operative bank",
        "client": "Northgate Urban Co-operative Bank",
        "host": "NUB-CBS-APP-02", "dc": "NUB-DC-01", "wks": "NUB-WKS-22",
        "user": "r.deshmukh", "upn": "r.deshmukh@northgatebank.example", "home": "Pune IN",
    },
    "power": {
        "label": "power utility (OT)",
        "client": "Tirupati Power Grid",
        "host": "TPG-SCADA-HMI-04", "dc": "TPG-DC-01", "wks": "TPG-WKS-22",
        "user": "r.deshmukh", "upn": "r.deshmukh@tirupatipower.example", "home": "Hyderabad IN",
        "rtu": "TPG-RTU-FEEDER-07",
    },
}


def offered():
    """The scenarios this deployment offers, in order. TRIAGLE_DEMO_SCENARIOS
    is a comma-separated list (for example "bank"); unset means all of them."""
    asked = [x.strip().lower() for x in os.environ.get("TRIAGLE_DEMO_SCENARIOS", "").split(",") if x.strip()]
    keep = [k for k in SCENARIOS if k in asked] if asked else list(SCENARIOS)
    return keep or list(SCENARIOS)


def default_scenario():
    name = os.environ.get("TRIAGLE_DEMO_SCENARIO", "bank").lower()
    keep = offered()
    return name if name in keep else keep[0]


DEFAULT = default_scenario()
DEFAULT_CLIENT = SCENARIOS[DEFAULT]["client"]
HOST = SCENARIOS[DEFAULT]["host"]
DC = SCENARIOS[DEFAULT]["dc"]
USER = SCENARIOS[DEFAULT]["user"]
UPN = SCENARIOS[DEFAULT]["upn"]
CLIENTS = {s["client"] for s in SCENARIOS.values()}      # every tenant this module can fire into


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def fresh_attack(client=None, now=None, tag=None, scenario=None):
    """Return a list of raw ingest items (source/client/raw) for one attack,
    timestamps ending ~1 min ago. `tag` makes the ids unique across repeated
    fires so a second demo does not collide with the first."""
    s = SCENARIOS[scenario if scenario in SCENARIOS else DEFAULT]
    client = client or s["client"]
    host, dc, user, upn = s["host"], s["dc"], s["user"], s["upn"]
    now = now or datetime.datetime.now(datetime.timezone.utc)
    tag = tag or now.strftime("%H%M%S")

    def at(mins_ago):
        return _iso(now - datetime.timedelta(minutes=mins_ago))

    items = [
        {"source": "entra_id", "client": client, "raw": {
            "id": f"si-{tag}-1", "createdDateTime": at(12), "riskEventType": "impossibleTravel",
            "riskLevel": "high", "userPrincipalName": upn, "ipAddress": "45.146.10.22",
            "riskDetail": f"Sign-in from Rotterdam NL, 9 minutes after a sign-in from {s['home']}.",
            "location": "Rotterdam, NL", "riskState": "atRisk", "host_hint": host}},
        {"source": "crowdstrike_edr", "client": client, "raw": {
            "detection_id": f"ldt:{tag}:1", "created_timestamp": at(9),
            "name": "Credential dumping via LSASS access", "severity": "high",
            "hostname": host, "user_name": user,
            "description": "Handle opened to lsass.exe by an unsigned binary shortly after a risky sign-in.",
            "tactic": "Credential Access", "technique": "LSASS Memory",
            "filename": "svc_host.exe", "cmdline": "svc_host.exe -dump lsass"}},
        {"source": "crowdstrike_edr", "client": client, "raw": {
            "detection_id": f"ldt:{tag}:2", "created_timestamp": at(6),
            "name": "Lateral movement via remote service", "severity": "high",
            "hostname": dc, "user_name": user,
            "description": f"Remote service created on {dc} from {host} using harvested credentials.",
            "tactic": "Lateral Movement", "cmdline": "psexesvc.exe"}},
        {"source": "crowdstrike_edr", "client": client, "raw": {
            "detection_id": f"ldt:{tag}:3", "created_timestamp": at(3),
            "name": "Ransomware behavior detected", "severity": "critical",
            "hostname": dc, "user_name": user,
            "description": "Process rapidly encrypting files; shadow copies being deleted.",
            "tactic": "Impact", "sha256": LOADER_HASH, "filename": "lockbit_x.exe",
            "cmdline": "vssadmin.exe delete shadows /all /quiet"}},
        {"source": "fortinet_fw", "client": client, "raw": {
            "logid": f"fg-{tag}", "eventtime": at(1),
            "attack": "Outbound connection to known C2", "crlevel": "high",
            "srcip": host, "dstip": C2_IP, "dstport": "8443", "service": "HTTPS",
            "action": "detected", "msg": "Beaconing pattern to known command and control infrastructure."}},
    ]
    if s.get("rtu"):
        # the step that makes it an OT incident: a control command to a field device
        items.insert(3, {"source": "ot_monitor", "client": client, "raw": {
            "id": f"ot-{tag}", "time": at(4), "severity": "high",
            "alert": "Unauthorised control command to RTU",
            "protocol": "IEC 60870-5-104", "function": "C_SC_NA_1 single command (breaker open)",
            "src_asset": host, "dst_asset": s["rtu"], "technique": "T0855 Unauthorized Command Message",
            "detail": f"{host} sent a breaker command to {s['rtu']} outside any switching order. "
                      f"This station does not normally issue control commands."}})
    return items


# A single out-of-the-blue benign alert, for showing Triagle correctly CLOSING
# noise live (so the demo is not only escalations).
def fresh_benign(client=None, now=None, tag=None, scenario=None):
    s = SCENARIOS[scenario if scenario in SCENARIOS else DEFAULT]
    client = client or s["client"]
    now = now or datetime.datetime.now(datetime.timezone.utc)
    tag = tag or now.strftime("%H%M%S")
    return [{"source": "crowdstrike_edr", "client": client, "raw": {
        "detection_id": f"ldt:{tag}:b", "created_timestamp": _iso(now - datetime.timedelta(minutes=1)),
        "name": "Known admin tool: 1E Tachyon agent", "severity": "low", "hostname": s["wks"],
        "user_name": "SYSTEM", "description": "1E Tachyon agent performing routine software inventory.",
        "filename": "TachyonAgent.exe", "cmdline": "TachyonAgent.exe --inventory"}}]


# ---- a working hour: mostly routine, with one intrusion in it ---------------
#
# The intrusion above is five alerts that all matter. A real queue is the
# opposite: dozens of alerts that do not, and the few that do somewhere among
# them. This builds that hour for the same customer, in the order it would
# arrive, so someone watching the Live page sees the routine ones closed one
# by one, each with its reason, and the intrusion raised out of the middle.

def _routine(s, client, at, tag):
    wks = [f"{s['wks'][:-2]}{n:02d}" for n in (3, 7, 9, 11, 14, 18, 21, 25)]
    people = ["a.kulkarni", "s.pillai", "m.fernandes", "v.joshi"]
    domain = s["upn"].split("@", 1)[1]
    paw = s["wks"].replace("WKS", "PAW")[:-2] + "01"
    out = []

    def edr(n, mins, name, sev, host, user, desc, cmd, exe):
        out.append((mins, {"source": "crowdstrike_edr", "client": client, "raw": {
            "detection_id": f"ldt:{tag}:r{n}", "created_timestamp": at(mins), "name": name, "severity": sev,
            "hostname": host, "user_name": user, "description": desc, "cmdline": cmd, "filename": exe}}))

    def fw(n, mins, src, dst, msg):
        out.append((mins, {"source": "fortinet_fw", "client": client, "raw": {
            "logid": f"fg-{tag}-r{n}", "eventtime": at(mins), "attack": "Traffic allowed", "crlevel": "low",
            "srcip": src, "dstip": dst, "msg": msg, "action": "accept"}}))

    def signin(n, mins, who, ip):
        out.append((mins, {"source": "entra_id", "client": client, "raw": {
            "id": f"si-{tag}-r{n}", "createdDateTime": at(mins), "riskEventType": "Password changed",
            "riskLevel": "low", "userPrincipalName": f"{who}@{domain}", "ipAddress": ip,
            "riskDetail": "User changed their own password from the office network after the 90-day expiry notice."}}))

    # the morning software-inventory run across the branch workstations
    for i, host in enumerate(wks):
        edr(i, 58 - 2 * i, "Known admin tool: 1E Tachyon agent", "low", host, "SYSTEM",
            "1E Tachyon agent performing routine scheduled software inventory.",
            "TachyonAgent.exe --inventory", "TachyonAgent.exe")
    for i, host in enumerate(wks[:3]):
        edr(20 + i, 41 - 3 * i, "HP SoftPaq driver update flagged", "low", host, "SYSTEM",
            "HP SoftPaq download manager updating drivers.",
            "HPSoftPaqDownloadManager.exe", "HPSoftPaqDownloadManager.exe")
    for i in range(2):                    # rated medium by the tool; it is the privileged-access system doing its job
        edr(30 + i, 34 - 27 * i, "Suspicious PowerShell execution", "medium", paw, "d.shah",
            "CyberArk PSM dispatcher launching PowerShell for privileged session management.",
            "powershell.exe -File C:\\CyberArk\\PSM\\Components\\dispatch.ps1", "powershell.exe")
    for i, host in enumerate(wks[3:5]):
        edr(40 + i, 31 - 20 * i, "Disk encryption enabled", "low", host, "SYSTEM",
            "BitLocker encryption turned on by device-management policy.", "manage-bde -on C:", "manage-bde.exe")
    for i, host in enumerate(wks[5:7]):
        edr(50 + i, 19 - 14 * i, "Software inventory scan", "low", host, "SYSTEM",
            "Routine inventory of installed software.", "TachyonAgent.exe --inventory", "TachyonAgent.exe")
    for i in range(6):
        fw(i, (50, 40, 30, 20, 10, 4)[i], f"10.20.5.{20 + i}", "8.8.8.8", "Routine outbound HTTPS to public DNS resolver.")
    for i, who in enumerate(people[:3]):
        signin(i, (44, 27, 8)[i], who, f"10.20.3.{8 + i}")
    return out


def fresh_shift(client=None, now=None, tag=None, scenario=None):
    """A working hour for one customer: about thirty routine alerts from
    three tools with one intrusion among them, oldest first (the order they
    would arrive in). Nothing here is real."""
    s = SCENARIOS[scenario if scenario in SCENARIOS else DEFAULT]
    client = client or s["client"]
    now = now or datetime.datetime.now(datetime.timezone.utc)
    tag = tag or now.strftime("%H%M%S")

    def at(mins_ago):
        return _iso(now - datetime.timedelta(minutes=mins_ago))

    timed = _routine(s, client, at, tag)
    attack = fresh_attack(client=client, now=now, tag=tag, scenario=scenario)
    # the intrusion's own times, so it lands among the last quarter of the hour
    for item in attack:
        raw = item["raw"]
        stamp = raw.get("createdDateTime") or raw.get("created_timestamp") or raw.get("eventtime") or raw.get("time")
        mins = (now - datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)).total_seconds() / 60
        timed.append((mins, item))
    timed.sort(key=lambda x: -x[0])                 # oldest first
    return [item for _, item in timed]
