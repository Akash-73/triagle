"""
Triagle — detection self-tuning analyzer.

Closes the loop that most triage tools leave open: it doesn't just triage
alerts, it watches how each *detection rule* is performing and flags the
noisy ones for tuning — so the source of the noise gets fixed, not just
the individual alerts dismissed.

For each rule (identified by the alert title/source pair), it tracks:
  - how many alerts that rule produced
  - how many were real signal (escalated / true-positive / suspicious)
  - how many were benign noise (auto-closed as benign/FP)

A rule that fires a lot but is almost always benign is a tuning candidate.
Crucially this only ever FLAGS — it never suppresses a rule, because a
noisy-looking rule can still occasionally catch the one real threat.
Suppression stays a human decision. This matches the product's
conservative philosophy: the system surfaces the problem, the human
decides the fix.
"""
from collections import defaultdict

# A rule must fire at least this many times before we judge it — you can't
# call a rule "noisy" from one or two alerts.
MIN_VOLUME_TO_JUDGE = 3

# If this fraction (or more) of a rule's alerts are benign noise, and none
# were real threats, it's a tuning candidate.
NOISE_THRESHOLD = 0.8


def _rule_key(alert):
    """Identify the detection rule behind an alert. In real deployments this
    would be the SIEM rule ID; here we use source + title, which is stable
    per detection."""
    return f"{alert.get('source', 'unknown')} :: {alert.get('title', 'unknown')}"


def analyze_rules(alerts, verdicts):
    """
    Returns a list of per-rule health records, noisiest-flagged first:
      { rule, volume, signal, noise, noise_ratio, flagged, recommendation }
    """
    stats = defaultdict(lambda: {"volume": 0, "signal": 0, "noise": 0, "sources": set()})

    for a in alerts:
        v = verdicts.get(a["alert_id"], {})
        key = _rule_key(a)
        s = stats[key]
        s["volume"] += 1
        s["sources"].add(a.get("source", "unknown"))
        disp = v.get("disposition")
        if v.get("escalate") or disp in ("true_positive", "suspicious"):
            s["signal"] += 1
        elif disp == "benign" or v.get("closure_code"):
            s["noise"] += 1

    records = []
    for rule, s in stats.items():
        vol = s["volume"]
        noise_ratio = (s["noise"] / vol) if vol else 0
        # flag only if: enough volume, mostly noise, AND zero real signal
        flagged = (
            vol >= MIN_VOLUME_TO_JUDGE
            and noise_ratio >= NOISE_THRESHOLD
            and s["signal"] == 0
        )
        rec = None
        if flagged:
            rec = (f"This detection fired {vol} times and every one was benign. "
                   f"It's a strong tuning candidate — add an environment-specific "
                   f"allowlist (by host + parent process + account) so it stops "
                   f"generating noise, while keeping it active for other contexts. "
                   f"Review before suppressing: confirm none of the {vol} were real.")
        records.append({
            "rule": rule,
            "volume": vol,
            "signal": s["signal"],
            "noise": s["noise"],
            "noise_ratio": round(noise_ratio, 2),
            "flagged": flagged,
            "recommendation": rec,
        })

    # flagged (noisiest) first, then by volume
    records.sort(key=lambda r: (not r["flagged"], -r["volume"]))
    return records
