---
name: triagle-detection-playbook
description: Use when adding a new alert type, detection rule, investigation playbook, or log source to Triagle. Keeps new detections measurable and honest.
---

# Adding a detection to Triagle

Follow these steps so every new detection is tested and can't quietly
regress. Do not tune logic to pass one example.

## 1. Add the signal, not a special case
Put new risk wording in `TERMS` and new command-line shapes in `BEHAVIOURS`
in `app/engine/signals.py`. Match terms on word boundaries and only in
human-written fields (title, description, tactic) — never in hashes,
hostnames, or file paths, or a hash containing "c2" will false-trigger.

## 2. Add a labelled pair to the benchmark
In `eval/dataset.json` add at least two cases: one that IS the threat
(`threat: true`) and one benign look-alike that must NOT escalate
(`threat: false`) — e.g. a real attack vs. an admin tool or a scary-sounding
but harmless alert. Mark some `split: "holdout"`.

## 3. Measure, don't guess
Run `python -m eval.run_benchmark`. The number that matters is
`missed` (real threats not escalated) — it must stay 0. Watch that
`false_escalations` does not climb. If a benign case now escalates, fix the
signal, don't delete the case.

## 4. New log source
Add a parser in `app/connectors/sources.py` that normalises the vendor's
fields into the common alert shape (including `dst_ip` for the internal-asset
logic). Add one sample alert of that source to `samples/incoming_alerts.json`.

## 5. Keep it conservative
When unsure whether something is benign, escalate. A false escalation costs a
human a minute; a missed attack costs a breach. This is the whole point of
Triagle — never trade it away for a cleaner-looking queue.
