"""
Triagle — response actions ("the responder half").

When triage confirms a real threat, Triagle can recommend and stage
concrete containment actions — isolate a host, disable an account, block an
indicator. But every action is GATED behind explicit human approval before
it executes. Nothing auto-executes. This is deliberate:

  - The product's whole trust proposition is "it won't do the wrong thing."
    Auto-remediation that isolates the wrong host or locks out a real user
    is exactly the catastrophic action a cautious buyer fears.
  - So Triagle proposes the right action with full context; a human clicks
    approve; only then does it "execute" (here, simulated; in production it
    calls the EDR/IdP API).
  - Higher-impact actions (e.g. isolating a domain controller) are marked
    high-risk and require the approver to acknowledge the blast radius.

Each proposed action carries: what it does, why, its blast-radius note, and
its risk tier — so the human approves with eyes open.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional


# Action catalogue: what Triagle can propose. Each maps (in production) to a
# real API call on the relevant platform.
ACTION_CATALOG = {
    "isolate_host": {
        "label": "Isolate host from network",
        "platform": "EDR (CrowdStrike / Defender)",
        "reversible": True,
    },
    "disable_account": {
        "label": "Disable user account",
        "platform": "Identity (Entra ID / AD)",
        "reversible": True,
    },
    "revoke_sessions": {
        "label": "Revoke active sessions / tokens",
        "platform": "Identity (Entra ID)",
        "reversible": True,
    },
    "block_indicator": {
        "label": "Block indicator (IP / hash / domain) at perimeter",
        "platform": "Firewall / EDR",
        "reversible": True,
    },
}

# Hosts whose isolation is high-impact — isolating these disrupts many
# users/services, so approval must acknowledge blast radius.
HIGH_IMPACT_HOST_HINTS = ["dc", "domain", "srv", "server", "vcenter", "esxi", "sql", "db"]


@dataclass
class ProposedAction:
    action_id: str
    alert_id: str
    action_type: str          # key in ACTION_CATALOG
    target: str               # the host/account/indicator to act on
    label: str
    platform: str
    rationale: str            # why this action, tied to the verdict
    blast_radius: str         # what approving this affects
    risk_tier: str            # "standard" | "high_impact"
    status: str = "pending"   # pending | approved | executed | declined
    requires_ack: bool = False

    def to_dict(self):
        return asdict(self)


def _is_high_impact(target):
    t = (target or "").lower()
    return any(h in t for h in HIGH_IMPACT_HOST_HINTS)


def propose_actions(alert, verdict):
    """
    Given an alert and its verdict, propose containment actions — but ONLY
    for verdicts that warrant response (escalated true-positive/suspicious).
    Benign verdicts get no actions. Returns a list of ProposedAction.
    """
    if not verdict.get("escalate"):
        return []
    if verdict.get("disposition") not in ("true_positive", "suspicious"):
        return []

    actions = []
    host = alert.get("host")
    user = alert.get("user")
    src_ip = alert.get("src_ip")
    indicators = alert.get("indicators", {}) or {}
    title = (alert.get("title") or "").lower()
    aid = alert.get("alert_id")

    def add(action_type, target, rationale, blast):
        if not target:
            return
        spec = ACTION_CATALOG[action_type]
        high = action_type == "isolate_host" and _is_high_impact(target)
        actions.append(ProposedAction(
            action_id=f"{aid}:{action_type}:{target}",
            alert_id=aid,
            action_type=action_type,
            target=target,
            label=spec["label"],
            platform=spec["platform"],
            rationale=rationale,
            blast_radius=(f"HIGH IMPACT — {target} looks like shared infrastructure; "
                          f"isolating it may disrupt many users/services. Confirm before approving."
                          if high else blast),
            risk_tier="high_impact" if high else "standard",
            requires_ack=high,
        ))

    # Host containment for endpoint threats.
    if host and any(k in title for k in ["ransomware", "credential", "lsass", "malware", "lateral"]):
        add("isolate_host", host,
            "Endpoint shows confirmed hands-on/destructive activity; isolating contains spread.",
            f"Removes {host} from the network. Reversible once cleared.")

    # C2/beaconing: isolate the internal host, BLOCK the external dst IP.
    if any(k in title for k in ["c2", "command and control", "beacon"]):
        internal = host or alert.get("src_ip")      # the internal asset
        external = alert.get("dst_ip")              # the external C2
        if external == internal:
            external = None
        if internal:
            add("isolate_host", internal,
                "Host is beaconing to known C2; isolating cuts the channel.",
                f"Removes {internal} from the network. Reversible once cleared.")
        if external:
            add("block_indicator", external,
                "External C2 infrastructure; blocking prevents further contact.",
                f"Blocks {external} at the perimeter. Reversible.")

    # Account containment — skip placeholder/generic principals.
    GENERIC_PRINCIPALS = {"multiple", "unknown", "n/a", "-", "various", "several"}
    real_user = user if (user and str(user).strip().lower() not in GENERIC_PRINCIPALS) else None
    if real_user and any(k in title for k in ["impossibletravel", "impossible travel", "password", "signin", "sign-in", "account", "identity"]):
        add("disable_account", real_user,
            "Identity shows likely compromise; disabling blocks further attacker use.",
            f"Blocks sign-in for {real_user}. Reversible.")
        add("revoke_sessions", real_user,
            "Kills any live attacker sessions/tokens for the account.",
            f"Signs {real_user} out everywhere. Reversible.")

    # Indicator blocking for scan/spray/brute — block the SOURCE ip only.
    if src_ip and any(k in title for k in ["scan", "brute", "spray"]):
        add("block_indicator", src_ip,
            "Source IP conducting scanning/spray activity; blocking stops it.",
            f"Blocks {src_ip} at the perimeter. Reversible.")

    return actions


def execute_action(proposed_action_dict, approver="analyst"):
    """
    'Execute' an approved action. In this build it's simulated — it returns
    a result record as if the platform API had been called. In production
    this dispatches to the real EDR/IdP/firewall API. It refuses to execute
    anything not explicitly approved.
    """
    if proposed_action_dict.get("status") != "approved":
        return {"ok": False, "message": "Action not approved — refusing to execute."}
    return {
        "ok": True,
        "message": (f"[SIMULATED] {proposed_action_dict['label']} on "
                    f"{proposed_action_dict['target']} executed via "
                    f"{proposed_action_dict['platform']}, approved by {approver}."),
        "reversible": True,
    }
