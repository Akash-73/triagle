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

TRIAGLE_DEMO_SCENARIO picks the default (bank).
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


def default_scenario():
    name = os.environ.get("TRIAGLE_DEMO_SCENARIO", "bank").lower()
    return name if name in SCENARIOS else "bank"


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
