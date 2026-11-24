"""
Triagle — Google Cloud firewall: the response action that is real.

Every other action in Triagle is a rehearsal until a customer connects that
tool. This one is connected. When an analyst approves "Block indicator" for a
customer whose machines sit on a Google Cloud network, Triagle adds a deny
rule to that network's firewall. The address is cut off within seconds, the
rule shows in the Cloud console like any other, and lifting the block deletes
it again.

It is deliberately narrow:

  ONE CUSTOMER   Only alerts from the customer named in the settings, and only
                 for hosts that are on this network. Sample data and every
                 other customer stay rehearsals.
  ONE PERSON     Only a signed-in analyst's approval reaches this module.
                 Nothing automatic does, and neither does the "try an alert"
                 box: this module is called from the approve route only.
  ONE ADDRESS    The rule is a /32 (one address), never a range.
  PUBLIC ONLY    Private, reserved and documentation addresses are refused,
                 and so are Google's own management ranges, the approver's own
                 address, and anything listed in TRIAGLE_NEVER_BLOCK.
  ITS OWN RULES  Rules are named triagle-block-*. Triagle only ever lists and
                 deletes rules with that name, and stops adding at a limit.

Auth is the service's own identity (the same token the model calls use). The
service account needs the role Compute Security Admin on the project.

Settings
  TRIAGLE_GCP_FIREWALL_CLIENT    the customer whose machines are on this network. Unset = off.
  TRIAGLE_GCP_FIREWALL_HOSTS     host names on this network, comma separated (default: all of that customer's)
  TRIAGLE_GCP_FIREWALL_PROJECT   default: the project Triagle runs in
  TRIAGLE_GCP_FIREWALL_NETWORK   default "default"
  TRIAGLE_GCP_FIREWALL_TAGS      optional network tags: the rule then applies to those machines only
  TRIAGLE_GCP_FIREWALL_MAX       most rules Triagle will keep at once (default 40)
  TRIAGLE_NEVER_BLOCK            addresses or ranges that must never be blocked, comma separated
"""
import ipaddress
import os
import re
import time
from datetime import datetime, timezone

import requests

from app.engine import genai

API = "https://compute.googleapis.com/compute/v1"
PREFIX = "triagle-block-"
PRIORITY = 900                      # ahead of ordinary allow rules, which sit at 1000 and above
VENDOR = "Google Cloud firewall"
DOC = "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/insert"
ROLE = "Compute Security Admin (roles/compute.securityAdmin)"
_NAME = re.compile(r"^triagle-block-[a-z0-9][a-z0-9-]{0,46}-(in|out)$")
_NEEDED = ["compute.firewalls.create", "compute.firewalls.delete", "compute.firewalls.list",
           "compute.networks.updatePolicy"]

# Google's own ranges that reach machines on the network. Blocking them would
# cut off browser SSH (Identity-Aware Proxy) or health checks.
PROTECTED = {
    "35.235.240.0/20": "Google's browser-SSH range (Identity-Aware Proxy)",
    "130.211.0.0/22": "Google's health-check range",
    "35.191.0.0/16": "Google's health-check range",
}

DIRECTIONS = {"in": "INGRESS", "out": "EGRESS"}


def _list(name):
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def client():
    return os.environ.get("TRIAGLE_GCP_FIREWALL_CLIENT", "").strip()


def enabled():
    return bool(client())


def project():
    return os.environ.get("TRIAGLE_GCP_FIREWALL_PROJECT", "").strip() or genai.project()


def network():
    return os.environ.get("TRIAGLE_GCP_FIREWALL_NETWORK", "").strip() or "default"


def hosts():
    return [h.lower() for h in _list("TRIAGLE_GCP_FIREWALL_HOSTS")]


def max_rules():
    try:
        return max(1, int(os.environ.get("TRIAGLE_GCP_FIREWALL_MAX", "40")))
    except ValueError:
        return 40


def covers(alert_client, host):
    """Is this alert about a machine on the connected network?"""
    if not enabled() or str(alert_client or "").strip().lower() != client().lower():
        return False
    named = hosts()
    return not named or str(host or "").strip().lower() in named


def _address(value):
    try:
        return ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None


def refusal(target, approver_ip=None):
    """Why this address must not be blocked, or None if it may be."""
    ip = _address(target)
    if ip is None:
        return "It is not an internet address (a file hash or a domain cannot be blocked at this firewall)."
    if not ip.is_global:
        return f"{ip} is a private or reserved address, not one on the internet."
    for net, what in PROTECTED.items():
        if ip.version == 4 and ip in ipaddress.ip_network(net):
            return f"{ip} is in {what}. Blocking it would cut off access to the machines."
    for entry in _list("TRIAGLE_NEVER_BLOCK"):
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return f"{ip} is on this deployment's never-block list."
        except ValueError:
            continue
    mine = _address(approver_ip)
    if mine is not None and mine == ip:
        return f"{ip} is the address you are connecting from. Triagle does not block the person approving."
    return None


def rule_name(target, direction="in"):
    ip = _address(target)
    slug = re.sub(r"[^a-z0-9]+", "-", ip.compressed.lower()).strip("-")
    return f"{PREFIX}{slug}-{direction if direction in DIRECTIONS else 'in'}"


def _clean(text, limit):
    return re.sub(r"[^\w .,:@/+-]", "", str(text or ""))[:limit]


def rule_body(target, direction="in", approver="pending", alert_id="", stamp=None):
    ip = _address(target)
    direction = direction if direction in DIRECTIONS else "in"
    cidr = f"{ip.compressed}/{32 if ip.version == 4 else 128}"
    stamp = stamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = {
        "name": rule_name(target, direction),
        "description": (f"Blocked by Triagle. Approved by {_clean(approver, 60)} on {stamp}. "
                        f"Alert {_clean(alert_id, 80)}. Lift it from the Triagle console.")[:500],
        "network": f"projects/{project()}/global/networks/{network()}",
        "direction": DIRECTIONS[direction],
        "priority": PRIORITY,
        "denied": [{"IPProtocol": "all"}],
    }
    body["sourceRanges" if direction == "in" else "destinationRanges"] = [cidr]
    tags = _list("TRIAGLE_GCP_FIREWALL_TAGS")
    if tags:
        body["targetTags"] = tags
    return body


def plan(target, direction="in", approver="pending", alert_id=""):
    """The call exactly as it will be sent, for the action card."""
    way = "from" if direction != "out" else "to"
    return {
        "connector": "gcp_firewall",
        "vendor": VENDOR,
        "method": "POST",
        "endpoint": f"{API}/projects/{project() or '<project>'}/global/firewalls",
        "body": rule_body(target, direction, approver, alert_id, stamp="<time of approval>"),
        "auth": f"Triagle's own service identity, with the role {ROLE}",
        "resolves": f"a deny rule for traffic {way} {target} on the network {network()}",
        "doc": DOC,
        "live": True,
    }


# ---- the calls ---------------------------------------------------------------

def _error(resp):
    try:
        err = resp.json().get("error") or {}
    except ValueError:
        err = {}
    msg = str(err.get("message") or resp.text or "").strip().replace("\n", " ")[:300]
    if resp.status_code == 403:
        return (f"Google Cloud refused it: Triagle's service account is not allowed to change this firewall. "
                f"Grant it the role {ROLE}. ({msg})")
    if resp.status_code == 404:
        return f"Google Cloud could not find the project or the network {network()}. ({msg})"
    return f"Google Cloud answered {resp.status_code}: {msg}"


def _call(method, path, body=None, params=None, timeout=12):
    """(response, error). One of the two is None."""
    proj = project()
    if not proj:
        return None, "No Google Cloud project is set, so nothing was sent."
    token = genai._access_token()
    if not token:
        return None, "No Google Cloud identity is available here, so nothing was sent."
    try:
        r = requests.request(method, f"{API}/projects/{proj}/{path}", json=body, params=params,
                             headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
    except requests.RequestException as e:
        return None, f"Google Cloud could not be reached: {type(e).__name__}."
    return r, None


def _wait(operation, tries=8):
    """Follow a firewall operation to the end. (done, error)."""
    name = (operation or {}).get("name")
    op = operation or {}
    for _ in range(tries):
        if op.get("status") == "DONE":
            errs = ((op.get("error") or {}).get("errors")) or []
            return True, ("; ".join(str(e.get("message") or e.get("code")) for e in errs)[:300] or None)
        if not name:
            return False, None
        time.sleep(1)
        r, err = _call("GET", f"global/operations/{name}", timeout=8)
        if err or r.status_code != 200:
            return False, None
        try:
            op = r.json()
        except ValueError:
            return False, None
    return op.get("status") == "DONE", None


def blocks():
    """The blocks in force: every rule Triagle has added. {ok, rules, error}"""
    r, err = _call("GET", "global/firewalls", params={
        "maxResults": 500,
        "fields": "items(name,description,direction,sourceRanges,destinationRanges,network,creationTimestamp,disabled)"})
    if err:
        return {"ok": False, "rules": [], "error": err}
    if r.status_code != 200:
        return {"ok": False, "rules": [], "error": _error(r)}
    try:
        items = r.json().get("items") or []
    except ValueError:
        return {"ok": False, "rules": [], "error": "Google Cloud sent an answer Triagle could not read."}
    rules = []
    for it in items:
        name = str(it.get("name") or "")
        if not _NAME.match(name):
            continue
        ranges = it.get("sourceRanges") or it.get("destinationRanges") or []
        rules.append({"name": name, "address": (ranges[0].split("/")[0] if ranges else ""),
                      "direction": "out" if it.get("direction") == "EGRESS" else "in",
                      "network": str(it.get("network") or "").rsplit("/", 1)[-1],
                      "description": it.get("description") or "", "created": it.get("creationTimestamp") or "",
                      "disabled": bool(it.get("disabled"))})
    rules.sort(key=lambda x: x["created"], reverse=True)
    return {"ok": True, "rules": rules, "error": None}


def block(target, direction="in", approver="analyst", alert_id="", approver_ip=None):
    """Add the deny rule. {ok, message, rule}. Never raises."""
    if not enabled():
        return {"ok": False, "rule": None, "message": "The Google Cloud firewall is not connected."}
    why = refusal(target, approver_ip)
    if why:
        return {"ok": False, "rule": None, "message": f"Not blocked. {why}"}
    direction = direction if direction in DIRECTIONS else "in"
    name = rule_name(target, direction)
    way = "from" if direction == "in" else "to"

    current = blocks()
    if current["ok"]:
        if any(x["name"] == name for x in current["rules"]):
            return {"ok": True, "rule": name,
                    "message": f"Already blocked: the rule {name} is in force on the network {network()}."}
        if len(current["rules"]) >= max_rules():
            return {"ok": False, "rule": None,
                    "message": (f"Not blocked. Triagle already keeps {len(current['rules'])} blocks, its limit here. "
                                f"Lift some that are no longer needed first.")}

    r, err = _call("POST", "global/firewalls", body=rule_body(target, direction, approver, alert_id))
    if err:
        return {"ok": False, "rule": None, "message": f"Not blocked. {err}"}
    if r.status_code == 409:
        return {"ok": True, "rule": name,
                "message": f"Already blocked: the rule {name} is in force on the network {network()}."}
    if r.status_code not in (200, 201):
        return {"ok": False, "rule": None, "message": f"Not blocked. {_error(r)}"}
    try:
        op = r.json()
    except ValueError:
        op = {}
    done, op_error = _wait(op)
    if op_error:
        return {"ok": False, "rule": None, "message": f"Not blocked. Google Cloud reported: {op_error}"}
    state = "is in force" if done else "was accepted and is being applied"
    return {"ok": True, "rule": name,
            "message": (f"Blocked. The firewall rule {name} {state} on the network {network()}: "
                        f"all traffic {way} {target} is denied. Approved by {approver}.")}


def lift(name, approver="analyst"):
    """Delete one of Triagle's own rules. {ok, message}"""
    name = str(name or "")
    if not _NAME.match(name):
        return {"ok": False, "message": "That is not a rule Triagle added, so it was left alone."}
    if not enabled():
        return {"ok": False, "message": "The Google Cloud firewall is not connected."}
    r, err = _call("DELETE", f"global/firewalls/{name}")
    if err:
        return {"ok": False, "message": f"Not lifted. {err}"}
    if r.status_code == 404:
        return {"ok": True, "message": f"The rule {name} was already gone."}
    if r.status_code not in (200, 204):
        return {"ok": False, "message": f"Not lifted. {_error(r)}"}
    try:
        op = r.json()
    except ValueError:
        op = {}
    done, op_error = _wait(op)
    if op_error:
        return {"ok": False, "message": f"Not lifted. Google Cloud reported: {op_error}"}
    return {"ok": True, "message": (f"Block lifted by {approver}: the rule {name} "
                                    f"{'is deleted' if done else 'is being deleted'}.")}


def check():
    """Can Triagle change this firewall? Asked without changing anything.
    {ok, message, rules}"""
    if not enabled():
        return {"ok": False, "rules": [], "message": "Not connected. Set TRIAGLE_GCP_FIREWALL_CLIENT to turn it on."}
    seen = blocks()
    if not seen["ok"]:
        return {"ok": False, "rules": [], "message": seen["error"]}
    count = len(seen["rules"])
    have = None
    token = genai._access_token()
    try:
        r = requests.post(f"https://cloudresourcemanager.googleapis.com/v1/projects/{project()}:testIamPermissions",
                          json={"permissions": _NEEDED}, headers={"Authorization": f"Bearer {token}"}, timeout=8)
        if r.status_code == 200:
            have = set(r.json().get("permissions") or [])
    except (requests.RequestException, ValueError):
        have = None
    where = f"the network {network()} in {project()}"
    if have is None:
        return {"ok": True, "rules": seen["rules"],
                "message": (f"Triagle can read the firewall of {where} ({count} of its blocks in force). "
                            f"Whether it may add a rule is confirmed the first time a block is approved.")}
    missing = [p for p in _NEEDED if p not in have]
    if missing:
        return {"ok": False, "rules": seen["rules"],
                "message": (f"Triagle can read the firewall of {where} but may not change it. "
                            f"Grant its service account the role {ROLE}. Missing: {', '.join(missing)}.")}
    return {"ok": True, "rules": seen["rules"],
            "message": f"Ready. Triagle may add and remove its own rules on {where}. {count} of its blocks in force."}


def summary():
    """What the Connectors page says before anything is called."""
    return {"enabled": enabled(), "client": client(), "hosts": hosts(), "project": project() if enabled() else None,
            "network": network(), "role": ROLE, "max": max_rules()}
