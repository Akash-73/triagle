"""
Triagle — source connectors.

Each connector takes a raw alert (as the source tool emits it) and returns
a NormalizedAlert. In production these would pull from tool APIs/webhooks;
for the demo they parse sample JSON in each tool's native shape, which is
what proves the normalization layer actually works across heterogeneous
sources — the exact "tool sprawl" pain MSPs have.
"""
from app.models import NormalizedAlert
from app.connectors.wazuh import from_wazuh


def _is_public_ip(value):
    import ipaddress
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False          # a hostname, so an internal asset name
    # the documentation ranges (RFC 5737) are "private" to Python but stand in
    # for internet addresses in sample data, so treat them as public
    doc = any(ip in ipaddress.ip_network(n) for n in
              ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
    return doc or ip.is_global


def _internal_side(src, dst):
    for v in (dst, src):
        if v and not _is_public_ip(v):
            return v
    return None


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
            "domain": raw.get("domain"),
            "url_host": raw.get("url_host"),
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
        dst_ip=raw.get("dstip"),
        # the internal asset is whichever side is not a public address
        host=_internal_side(raw.get("srcip"), raw.get("dstip")),
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


def from_ot_monitor(raw, client):
    """An OT network monitor's alert (Zeek ICSNPP, Nozomi, Claroty and
    similar all report the same things): who sent what, over which industrial
    protocol, to which controller. The controller is the asset; the sender is
    kept as the source so containment can be proposed on that side."""
    target = raw.get("dst_asset") or raw.get("dstip") or "unknown"
    return NormalizedAlert(
        alert_id=raw.get("id", "unknown"),
        source="ot_monitor",
        client=client,
        timestamp=raw.get("time", ""),
        title=raw.get("alert", "OT network event"),
        raw_severity=str(raw.get("severity", "medium")).lower(),
        entity=target,
        host=target,
        src_ip=raw.get("src_asset") or raw.get("srcip"),
        dst_ip=raw.get("dstip"),
        description=raw.get("detail", ""),
        indicators={
            "protocol": raw.get("protocol"),
            "function": raw.get("function"),
            "ot_source": raw.get("src_asset") or raw.get("srcip"),
            "ot_target": target,
            "technique": raw.get("technique"),
        },
        raw=raw,
    )


CONNECTORS = {
    "crowdstrike_edr": from_crowdstrike,
    "fortinet_fw": from_fortinet,
    "entra_id": from_entra,
    "wazuh": from_wazuh,
    "ot_monitor": from_ot_monitor,
}


def normalize(source, raw, client):
    fn = CONNECTORS.get(source)
    if not fn:
        raise ValueError(f"no connector for source '{source}'")
    return fn(raw, client)
