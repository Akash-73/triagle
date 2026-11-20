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
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

from app.engine import reputation
from app.engine import action_tools


# --- The automation policy -------------------------------------------------
#
# Triagle does NOT auto-run everything, and it does NOT gate everything behind
# a human either. It tiers by blast radius, exactly like a real SOAR playbook:
#
#   AUTO  — reversible, low-blast-radius containment that a mature SOC already
#           automates: block a *confirmed-malicious* indicator at the
#           perimeter, or revoke a compromised account's live sessions/tokens.
#           Done immediately so the attacker loses access in seconds, and fully
#           reversible if wrong.
#   HUMAN — anything that can disrupt production or lock out a real person:
#           isolating a host (above all a server/DC) or disabling an account.
#           These ALWAYS wait for an analyst, regardless of confidence.
#
# Auto actions still need the verdict to clear a high confidence bar.
AUTO_EXECUTE_FLOOR = 90
AUTO_ELIGIBLE_ACTIONS = {"block_indicator", "revoke_sessions"}
ALWAYS_HUMAN_ACTIONS = {"isolate_host", "disable_account"}


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
    status: str = "pending"   # pending | approved | executed | declined | auto_executed
    requires_ack: bool = False
    policy: str = "approval"  # "auto" | "approval" — who is allowed to run it
    policy_reason: str = ""   # why it is auto-eligible, or why it needs a human
    result_message: str = ""  # populated when auto-executed
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None
    tool_call: Optional[dict] = None   # the exact vendor API call behind this action

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
    confidence = int(verdict.get("confidence", 0) or 0)

    def _policy_for(action_type, target, risk_tier):
        """Decide whether this action may auto-run or must wait for a human.
        Returns (policy, reason)."""
        if action_type in ALWAYS_HUMAN_ACTIONS or risk_tier != "standard":
            if action_type == "isolate_host":
                return "approval", "Isolating a host can disrupt production — a human decides."
            if action_type == "disable_account":
                return "approval", "Disabling an account can lock out a real user — a human decides."
            return "approval", "High-impact action — a human decides."
        if action_type not in AUTO_ELIGIBLE_ACTIONS:
            return "approval", "Requires analyst review."
        if confidence < AUTO_EXECUTE_FLOOR:
            return "approval", (f"Confidence {confidence}% is below the {AUTO_EXECUTE_FLOOR}% bar "
                                f"for automatic action — a human decides.")
        if action_type == "block_indicator" and not reputation.is_confirmed_malicious(target):
            return "approval", "Indicator is not confirmed malicious — a human decides before blocking."
        if action_type == "block_indicator":
            return "auto", (f"Indicator is confirmed malicious and confidence is {confidence}%. "
                            f"Blocking at the perimeter is reversible and low-impact, so Triagle "
                            f"blocks it automatically and logs it for you.")
        return "auto", (f"Confidence is {confidence}%. Revoking the compromised account's live "
                        f"sessions is reversible and contains the attacker immediately, so Triagle "
                        f"does it automatically and logs it for you.")

    def add(action_type, target, rationale, blast):
        if not target:
            return
        spec = ACTION_CATALOG[action_type]
        high = action_type == "isolate_host" and _is_high_impact(target)
        risk_tier = "high_impact" if high else "standard"
        policy, reason = _policy_for(action_type, target, risk_tier)
        act = ProposedAction(
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
            risk_tier=risk_tier,
            requires_ack=high,
            policy=policy,
            policy_reason=reason,
        )
        act.tool_call = action_tools.build_call(action_type, target, spec["platform"])
        if policy == "auto":
            stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
            disp = action_tools.dispatch(act.to_dict(), approver="Triagle · auto-policy")
            act.status = "auto_executed"
            act.decided_by = "Triagle · auto-policy"
            act.decided_at = stamp
            act.result_message = disp["message"]
        actions.append(act)

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
    if real_user and any(k in title for k in ["impossibletravel", "impossible travel", "password", "signin", "sign-in", "account", "identity", "token", "phish", "aitm", "compromise", "hijack", "session"]):
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
    Execute an approved action by dispatching it through the Action Gateway,
    which resolves the vendor connector and calls the real EDR/IdP/firewall API
    (or, in dry-run, returns the exact call without sending it). Refuses to
    execute anything not explicitly approved.
    """
    if proposed_action_dict.get("status") != "approved":
        return {"ok": False, "message": "Action not approved — refusing to execute."}
    result = action_tools.dispatch(proposed_action_dict, approver=approver)
    return {"ok": result["ok"], "message": result["message"],
            "call": result.get("call"), "mode": result.get("mode"), "reversible": True}
