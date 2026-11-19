"""
Triagle — live demo attack generator.

Produces a fresh, coherent attack chain with timestamps ending ~1 minute ago,
so a judge watching the screen sees Triagle investigate a *live* incident and
the CERT-In 6-hour clock start running. Nothing here is real: the client,
users, hosts and the single public C2 IP are invented. The C2 IP and the
loader hash are ones already in samples/investigation_env.json, so the
threat-intel match fires without any extra setup.

Used by POST /demo/fire (a button on the dashboard) and by
scripts/fire_attack.py (which POSTs to /ingest over the network).

The chain, on a power-utility client, is the story the pitch tells:
  phish -> impossible-travel sign-in -> LSASS credential theft ->
  lateral movement -> ransomware behaviour + shadow-copy deletion ->
  outbound beacon to known C2.
"""
import datetime

C2_IP = "185.220.101.44"                      # in investigation_env threat_intel
LOADER_HASH = "e3b0c44298fc1c149afbf4c8996fb924"
DEFAULT_CLIENT = "Tirupati Power Grid"
HOST = "TPG-SCADA-HMI-04"
DC = "TPG-DC-01"
USER = "r.deshmukh"
UPN = "r.deshmukh@tirupatipower.example"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def fresh_attack(client=DEFAULT_CLIENT, now=None, tag=None):
    """Return a list of raw ingest items (source/client/raw) for one attack,
    timestamps ending ~1 min ago. `tag` makes the ids unique across repeated
    fires so a second demo does not collide with the first."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    tag = tag or now.strftime("%H%M%S")

    def at(mins_ago):
        return _iso(now - datetime.timedelta(minutes=mins_ago))

    return [
        {"source": "entra_id", "client": client, "raw": {
            "id": f"si-{tag}-1", "createdDateTime": at(12), "riskEventType": "impossibleTravel",
            "riskLevel": "high", "userPrincipalName": UPN, "ipAddress": "45.146.10.22",
            "riskDetail": "Sign-in from Rotterdam NL, 9 minutes after a sign-in from Hyderabad IN.",
            "location": "Rotterdam, NL", "riskState": "atRisk", "host_hint": HOST}},
        {"source": "crowdstrike_edr", "client": client, "raw": {
            "detection_id": f"ldt:{tag}:1", "created_timestamp": at(9),
            "name": "Credential dumping via LSASS access", "severity": "high",
            "hostname": HOST, "user_name": USER,
            "description": "Handle opened to lsass.exe by an unsigned binary shortly after a risky sign-in.",
            "tactic": "Credential Access", "technique": "LSASS Memory",
            "filename": "svc_host.exe", "cmdline": "svc_host.exe -dump lsass"}},
        {"source": "crowdstrike_edr", "client": client, "raw": {
            "detection_id": f"ldt:{tag}:2", "created_timestamp": at(6),
            "name": "Lateral movement via remote service", "severity": "high",
            "hostname": DC, "user_name": USER,
            "description": f"Remote service created on {DC} from {HOST} using harvested credentials.",
            "tactic": "Lateral Movement", "cmdline": "psexesvc.exe"}},
        {"source": "crowdstrike_edr", "client": client, "raw": {
            "detection_id": f"ldt:{tag}:3", "created_timestamp": at(3),
            "name": "Ransomware behavior detected", "severity": "critical",
            "hostname": DC, "user_name": USER,
            "description": "Process rapidly encrypting files; shadow copies being deleted.",
            "tactic": "Impact", "sha256": LOADER_HASH, "filename": "lockbit_x.exe",
            "cmdline": "vssadmin.exe delete shadows /all /quiet"}},
        {"source": "fortinet_fw", "client": client, "raw": {
            "logid": f"fg-{tag}", "eventtime": at(1),
            "attack": "Outbound connection to known C2", "crlevel": "high",
            "srcip": HOST, "dstip": C2_IP, "dstport": "8443", "service": "HTTPS",
            "action": "detected", "msg": "Beaconing pattern to known command and control infrastructure."}},
    ]


# A single out-of-the-blue benign alert, for showing Triagle correctly CLOSING
# noise live (so the demo is not only escalations).
def fresh_benign(client=DEFAULT_CLIENT, now=None, tag=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    tag = tag or now.strftime("%H%M%S")
    return [{"source": "crowdstrike_edr", "client": client, "raw": {
        "detection_id": f"ldt:{tag}:b", "created_timestamp": _iso(now - datetime.timedelta(minutes=1)),
        "name": "Known admin tool: 1E Tachyon agent", "severity": "low", "hostname": "TPG-WKS-22",
        "user_name": "SYSTEM", "description": "1E Tachyon agent performing routine software inventory.",
        "filename": "TachyonAgent.exe", "cmdline": "TachyonAgent.exe --inventory"}}]
