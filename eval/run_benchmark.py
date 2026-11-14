"""
Scores Triagle against eval/dataset.json.

    python -m eval.run_benchmark            # table + summary
    python -m eval.run_benchmark --json     # machine-readable

Two numbers matter:
  missed threats     - a real attack alert that was NOT escalated (the unforgivable one)
  false escalations  - a benign alert that was sent to a human (the cost of caution)
"""
import json
import os
import sys
import time

from app.orchestrator import process_batch

HERE = os.path.dirname(__file__)


def score(items, verdicts, ids):
    rows = []
    for item, aid in zip(items, ids):
        v = verdicts.get(aid, {})
        lab = item["label"]
        esc = bool(v.get("escalate"))
        if lab["threat"] is True:
            outcome = "caught" if esc else "MISSED"
        elif lab["threat"] is False:
            outcome = "closed" if not esc else "false-escalation"
        else:
            outcome = "ambiguous"
        rows.append({"alert_id": aid, "title": item["raw"].get("name") or item["raw"].get("attack")
                     or item["raw"].get("riskEventType"), "scenario": lab["scenario"],
                     "split": lab["split"], "threat": lab["threat"], "escalated": esc,
                     "disposition": v.get("disposition"), "confidence": v.get("confidence"),
                     "outcome": outcome})
    return rows


def summarise(rows):
    def part(split=None):
        r = [x for x in rows if split is None or x["split"] == split]
        threats = [x for x in r if x["threat"] is True]
        benign = [x for x in r if x["threat"] is False]
        missed = sum(1 for x in threats if x["outcome"] == "MISSED")
        fe = sum(1 for x in benign if x["outcome"] == "false-escalation")
        return {"alerts": len(r), "threats": len(threats), "missed": missed,
                "catch_rate_pct": round(100 * (len(threats) - missed) / len(threats), 1) if threats else None,
                "benign": len(benign), "false_escalations": fe,
                "benign_closed_pct": round(100 * (len(benign) - fe) / len(benign), 1) if benign else None}
    return {"all": part(), "dev": part("dev"), "holdout": part("holdout")}


def run():
    items = json.load(open(os.path.join(HERE, "dataset.json")))
    t0 = time.perf_counter()
    result = process_batch(items)
    elapsed = time.perf_counter() - t0
    ids = [a["alert_id"] for a in result["alerts"]]
    assert len(ids) == len(items), "an alert failed to normalise"
    rows = score(items, result["verdicts"], ids)
    return rows, summarise(rows), elapsed, result


if __name__ == "__main__":
    rows, summary, elapsed, _ = run()
    if "--json" in sys.argv:
        print(json.dumps({"summary": summary, "rows": rows, "seconds": round(elapsed, 3)}, indent=1))
        sys.exit(0)
    for r in rows:
        flag = {"MISSED": "!!", "false-escalation": " ~"}.get(r["outcome"], "  ")
        print(f'{flag} {r["outcome"]:17} {r["split"]:8} {r["scenario"]:16} {str(r["disposition"]):14} {r["title"]}')
    print()
    for k, s in summary.items():
        print(f'{k:8} threats {s["threats"]:2}  missed {s["missed"]:2}  catch {s["catch_rate_pct"]}%   '
              f'benign {s["benign"]:2}  false-esc {s["false_escalations"]:2}  closed {s["benign_closed_pct"]}%')
    print(f"\n{len(rows)} alerts investigated in {elapsed*1000:.0f} ms (deterministic engine, no model calls)")
