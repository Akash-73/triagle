"""
Netrix — source connectors.

Each connector takes a raw alert (as the source tool emits it) and returns
a NormalizedAlert. In production these would pull from tool APIs/webhooks;
for the demo they parse sample JSON in each tool's native shape, which is
what proves the normalization layer actually works across heterogeneous
sources — the exact "tool sprawl" pain MSPs have.
"""
from app.models import NormalizedAlert


def from_crowdstrike(raw, client):
    """CrowdStrike Falcon EDR detection shape."""
    return NormalizedAlert(
        alert_id=raw.get("detection_id", raw.get("id", "unknown")),
        source="crowdstrike_edr",
        client=client,
        timestamp=raw.get("created_timestamp", ""),
        title=raw.get("name", raw.get("tactic", "EDR detection")),
        raw_severity=str(raw.get("severity", raw.get("max_severity", "medium"))).lower(),
        entity=raw.get("device", {}).get("hostname", raw.get("hostname", "unknown")),
        host=raw.get("device", {}).get("hostname", raw.get("hostname")),
        user=raw.get("user_name"),
        description=raw.get("description", ""),
        indicators={
            "sha256": raw.get("sha256"),
            "filename": raw.get("filename"),
            "cmdline": raw.get("cmdline"),
            "tactic": raw.get("tactic"),
            "technique": raw.get("technique"),
        },
        raw=raw,
    )


def from_fortinet(raw, client):
    """Fortinet FortiGate firewall log shape."""
    return NormalizedAlert(
        alert_id=raw.get("logid", raw.get("id", "unknown")),
        source="fortinet_fw",
        client=client,
        timestamp=raw.get("eventtime", raw.get("date", "")),
        title=raw.get("attack", raw.get("action", "Firewall event")),
        raw_severity=str(raw.get("crlevel", raw.get("level", "medium"))).lower(),
        entity=raw.get("srcip", "unknown"),
        src_ip=raw.get("srcip"),
        host=raw.get("dstip"),
        description=raw.get("msg", ""),
        indicators={
            "dstport": raw.get("dstport"),
            "service": raw.get("service"),
            "action": raw.get("action"),
        },
        raw=raw,
    )


def from_entra(raw, client):
    """Microsoft Entra ID (Azure AD) sign-in / risk event shape."""
    upn = raw.get("userPrincipalName", "unknown")
    # derive the local-part username so identity alerts can be linked to
    # EDR alerts that only carry the short username (entity resolution).
    short_user = upn.split("@")[0] if "@" in upn else upn
    return NormalizedAlert(
        alert_id=raw.get("id", "unknown"),
        source="entra_id",
        client=client,
        timestamp=raw.get("createdDateTime", ""),
        title=raw.get("riskEventType", raw.get("activityDisplayName", "Identity event")),
        raw_severity=str(raw.get("riskLevel", "medium")).lower(),
        entity=upn,
        user=short_user,
        src_ip=raw.get("ipAddress"),
        host=raw.get("host_hint"),
        description=raw.get("riskDetail", ""),
        indicators={
            "upn": upn,
            "location": raw.get("location"),
            "riskState": raw.get("riskState"),
            "clientApp": raw.get("clientAppUsed"),
        },
        raw=raw,
    )


CONNECTORS = {
    "crowdstrike_edr": from_crowdstrike,
    "fortinet_fw": from_fortinet,
    "entra_id": from_entra,
}


def normalize(source, raw, client):
    fn = CONNECTORS.get(source)
    if not fn:
        raise ValueError(f"no connector for source '{source}'")
    return fn(raw, client)
