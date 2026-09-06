"""
Netrix — core data structures.

A NormalizedAlert is what every connector produces, regardless of source
tool (EDR, firewall, identity provider). The triage engine only ever sees
NormalizedAlerts, so adding a new source tool never touches the engine.

A Verdict is what the engine produces for each alert. The design priority
is CONSERVATIVE CLOSURE: the engine must never auto-close a real threat.
That's the whole wedge against incumbents that wrongly close true positives
as false positives. So a Verdict carries not just a disposition but a
confidence, an explicit escalation flag, and the evidence trail behind the
decision.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


# ---- Disposition & closure taxonomy -------------------------------------

# What the engine decided the alert IS.
DISPOSITIONS = ["true_positive", "benign", "suspicious", "needs_human"]

# Structured closure codes — the auditable "why", which incumbents fumble.
# Every closed alert gets exactly one of these, never a bare "closed".
CLOSURE_CODES = {
    "TP_CONFIRMED": "Confirmed true positive — real malicious/again-policy activity",
    "TP_LIKELY": "Likely true positive — strong indicators, needs response",
    "BENIGN_EXPECTED": "Benign — expected/authorized activity for this environment",
    "BENIGN_KNOWN_TOOL": "Benign — known admin/security tool behavior",
    "BENIGN_DUPLICATE": "Benign — duplicate of an already-handled alert",
    "FP_TUNING": "False positive — noisy detection, tuning recommended",
    "INSUFFICIENT_EVIDENCE": "Cannot decide with available evidence — escalated",
}


@dataclass
class NormalizedAlert:
    alert_id: str
    source: str                    # e.g. "crowdstrike_edr", "fortinet_fw", "entra_id"
    client: str                    # which MSP client this belongs to (multi-tenant)
    timestamp: str
    title: str
    raw_severity: str              # severity as the source tool reported it
    entity: str                    # primary asset/user involved
    src_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    description: str = ""
    indicators: dict = field(default_factory=dict)   # hashes, domains, ports, etc.
    raw: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class Verdict:
    alert_id: str
    disposition: str               # one of DISPOSITIONS
    closure_code: Optional[str]    # one of CLOSURE_CODES keys, or None if open
    confidence: int                # 0-100
    severity: str                  # engine's own severity: critical/high/medium/low
    escalate: bool                 # TRUE = a human MUST look; never auto-closed
    summary: str                   # one-line plain-English disposition
    reasoning: str                 # the evidence trail / why
    recommended_actions: list = field(default_factory=list)
    tuning_recommendation: Optional[str] = None   # how to fix the detection, if noisy
    used_ai: bool = False

    def to_dict(self):
        return asdict(self)
