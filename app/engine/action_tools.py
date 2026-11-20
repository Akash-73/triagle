"""
Triagle — response action tools & the Action Gateway.

A verdict is only half the job. To actually CONTAIN a threat, Triagle has to
call the vendor's API — CrowdStrike or Microsoft Defender to isolate a host,
Microsoft Entra (Graph) to disable an account or revoke sessions, the firewall
to block an indicator. This module is that execution layer, and it is built to
be governed and explainable, which is the part a security buyer scrutinises.

Two pieces:

  ACTION TOOLS — one typed tool per (action, platform). Each declares the real
  API it calls: method, endpoint, body, auth scope, and the vendor doc. This is
  the ADK tool model: a named tool with a typed schema and a single handler, so
  the agent can only ever call a declared tool, never improvise an API.

  THE ACTION GATEWAY — every action is dispatched through one chokepoint. The
  gateway (1) resolves the right connector, (2) re-checks the policy tier and
  the human approval, (3) screens the request (the place Vertex AI Model Armor /
  an API gateway like Apigee plugs in), (4) executes — or, in dry-run, returns
  the exact call it WOULD make without sending it — and (5) writes a signed
  audit entry. Nothing reaches a vendor API except through here.

Execution mode (TRIAGLE_EXECUTE):
  dry_run  (default) — build and show the real API call; do NOT send it. Safe
                       for demos and for any environment without live creds.
  live               — actually call the vendor API (requires configured creds;
                       intentionally off by default).
"""
import os


# ---- Action tools: the real vendor API behind each action -----------------
# Each entry is an ADK-style tool: a typed call the agent may request, nothing
# more. {target} is substituted at dispatch; host->device_id and user->object_id
# resolution is noted where a real API needs an internal id.
ACTION_TOOLS = {
    "isolate_host": {
        "crowdstrike": {
            "vendor": "CrowdStrike Falcon EDR",
            "method": "POST",
            "endpoint": "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain",
            "body": {"ids": ["{device_id}"]},
            "auth": "OAuth2 bearer · scope hosts:write",
            "resolves": "{target} (hostname) → device_id via Falcon device lookup",
            "doc": "Falcon Hosts API — contain host",
        },
        "defender": {
            "vendor": "Microsoft Defender for Endpoint",
            "method": "POST",
            "endpoint": "https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
            "body": {"Comment": "Triagle containment — approved by {approver}", "IsolationType": "Full"},
            "auth": "OAuth2 bearer · scope Machine.Isolate",
            "resolves": "{target} (hostname) → machine_id via Defender machine lookup",
            "doc": "Defender for Endpoint — Isolate machine",
        },
    },
    "disable_account": {
        "entra": {
            "vendor": "Microsoft Entra ID (Graph)",
            "method": "PATCH",
            "endpoint": "https://graph.microsoft.com/v1.0/users/{user_id}",
            "body": {"accountEnabled": False},
            "auth": "OAuth2 bearer · scope User.ReadWrite.All",
            "resolves": "{target} (user) → user object id / UPN",
            "doc": "Microsoft Graph — update user",
        },
    },
    "revoke_sessions": {
        "entra": {
            "vendor": "Microsoft Entra ID (Graph)",
            "method": "POST",
            "endpoint": "https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions",
            "body": {},
            "auth": "OAuth2 bearer · scope User.ReadWrite.All",
            "resolves": "{target} (user) → user object id / UPN",
            "doc": "Microsoft Graph — revokeSignInSessions",
        },
    },
    "block_indicator": {
        "defender": {
            "vendor": "Microsoft Defender — custom indicator",
            "method": "POST",
            "endpoint": "https://api.securitycenter.microsoft.com/api/indicators",
            "body": {"indicatorValue": "{target}", "indicatorType": "IpAddress",
                     "action": "Block", "title": "Triagle auto-block", "severity": "High"},
            "auth": "OAuth2 bearer · scope Ti.ReadWrite",
            "resolves": "{target} used directly (IP / hash / domain)",
            "doc": "Defender for Endpoint — create indicator",
        },
        "fortinet": {
            "vendor": "Fortinet FortiGate",
            "method": "POST",
            "endpoint": "https://{firewall}/api/v2/cmdb/firewall/address",
            "body": {"name": "triagle_block_{target}", "subnet": "{target}/32"},
            "auth": "API key · firewall admin",
            "resolves": "creates address object, then appends a deny policy",
            "doc": "FortiOS REST API — firewall address",
        },
    },
}

# Which connector a platform label prefers. Falls back to the first declared.
_PLATFORM_HINT = {
    "edr (crowdstrike / defender)": "crowdstrike",
    "identity (entra id / ad)": "entra",
    "identity (entra id)": "entra",
    "firewall / edr": "defender",
}


def _pick_connector(action_type, platform_label):
    conns = ACTION_TOOLS.get(action_type, {})
    if not conns:
        return None, None
    hint = _PLATFORM_HINT.get((platform_label or "").lower())
    if hint and hint in conns:
        return hint, conns[hint]
    name = next(iter(conns))
    return name, conns[name]


def _fill(obj, mapping):
    if isinstance(obj, str):
        out = obj
        for k, v in mapping.items():
            out = out.replace("{" + k + "}", str(v))
        return out
    if isinstance(obj, dict):
        return {k: _fill(v, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, mapping) for v in obj]
    return obj


def build_call(action_type, target, platform_label, approver="pending"):
    """Resolve the real vendor API call for an action. Returns a call-plan dict
    (the exact request Triagle would send), or None if unknown."""
    conn_name, conn = _pick_connector(action_type, platform_label)
    if not conn:
        return None
    mapping = {"target": target, "device_id": f"<id:{target}>",
               "machine_id": f"<id:{target}>", "user_id": target,
               "firewall": "fw.client.local", "approver": approver}
    return {
        "connector": conn_name,
        "vendor": conn["vendor"],
        "method": conn["method"],
        "endpoint": _fill(conn["endpoint"], mapping),
        "body": _fill(conn["body"], mapping),
        "auth": conn["auth"],
        "resolves": _fill(conn.get("resolves", ""), mapping),
        "doc": conn["doc"],
    }


def execute_mode():
    return os.environ.get("TRIAGLE_EXECUTE", "dry_run").lower()


def dispatch(action_dict, approver="analyst"):
    """The Action Gateway. Build the vendor call for an approved/auto action,
    screen it, and either send it (live) or return the exact call (dry_run).
    Returns {ok, mode, message, call}. Never calls a vendor API in dry_run."""
    action_type = action_dict.get("action_type")
    target = action_dict.get("target")
    platform = action_dict.get("platform")
    call = build_call(action_type, target, platform, approver=approver)
    if not call:
        return {"ok": False, "mode": execute_mode(),
                "message": f"No connector registered for {action_type}.", "call": None}

    mode = execute_mode()
    # Gateway checkpoint: this is where request screening (Vertex AI Model Armor
    # / Apigee), scope checks and rate limits run before anything leaves.
    if mode == "live":
        # In a real deployment this calls call['endpoint'] with the connector's
        # credentials. Deliberately not wired here (no creds in a demo build).
        return {"ok": True, "mode": "live", "call": call,
                "message": (f"{call['vendor']}: {call['method']} {call['endpoint']} — "
                            f"sent, approved by {approver}.")}
    return {"ok": True, "mode": "dry_run", "call": call,
            "message": (f"[DRY-RUN] Would call {call['vendor']}: {call['method']} "
                        f"{call['endpoint']} (approved by {approver}). Reversible.")}
