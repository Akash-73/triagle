---
name: triagle-safety-guardrails
description: Use whenever editing Triagle's triage, verdict, investigation, response, or model-backend code (app/engine/*, app/agent/*, app/main.py approve route). Enforces the safety rules that must never be weakened.
---

# Triagle safety guardrails

Triagle decides whether a security alert is a real attack and stages
containment actions. A wrong "close" can hide a live breach, and an
auto-executed action can take a hospital or a power plant offline. These
rules are non-negotiable. If a change would break one, stop and flag it
instead of making the change.

## Never auto-close a risk signal
An alert carrying a hard risk signal — ransomware, credential theft / LSASS,
lateral movement, C2 / command-and-control, data exfiltration, or any
command-line behaviour in `app/engine/signals.py` — is ALWAYS escalated to a
human, even at 99% model confidence. Never add a code path, model backend, or
config that lets such an alert be auto-closed. `_enforce_guardrails` in
`app/engine/triage.py` is the final gate; every verdict passes through it.
Never bypass it or make it conditional.

## A human approves every action
Response actions (isolate host, disable account, block indicator) are staged
as `pending` and only execute after a signed-in analyst approves them. Never
add auto-approval or auto-execution. The approve route requires an analyst
role and a valid CSRF token — keep both.

## Personal data never leaves in the clear
Every prompt sent to a model API goes through `app.privacy.mask()` first
(Aadhaar, PAN, UPI, mobile, email) and is unmasked on the reply. Any new
model backend must call `complete()` in `app/agent/backend.py`, which does
this — never call a model API directly from elsewhere.

## Model-agnostic, guardrails-identical
A new model backend (Gemini, Claude, local) is added in
`app/agent/backend.py` only. The investigation loop and the guardrails are
the same for every backend. The model may escalate MORE than the rules; it
may never escalate LESS.

## Prove it with a test
Any change to verdict, signal, correlation, or approval logic needs a test in
`tests/`. Run `python -m pytest -q` and keep it green. For detection changes,
also run `python -m eval.run_benchmark` and confirm `missed` stays at 0.
