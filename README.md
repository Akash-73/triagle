# Triagle — Agentic AI SOC Analyst

**Triage, decided.**

Triagle is an agentic AI SOC analyst built for MSPs. For every alert it runs
an autonomous investigation — planning which evidence to gather, calling
investigative tools, reasoning over what it finds, and reaching an auditable
determination — with one guarantee the field's incumbents break: **it never
wrongly closes a real threat.**

## Agentic, not just AI-assisted

Most "AI triage" makes a single classification call. Triagle runs a real
investigation loop per alert, the same pattern serious AI-SOC platforms use:

```
alert → PLAN (which tool next?) → ACT (call tool, gather evidence)
      → OBSERVE → RE-PLAN → ... → DETERMINE (verdict + evidence trail)
                                        → CONSERVATIVE-CLOSURE GUARDRAILS
```

The agent autonomously calls investigative tools:
- **related_alerts** — is this part of a larger pattern?
- **timeline** — what's the attack sequence?
- **threat_intel** — are the indicators known-malicious?
- **entity_history** — what's normal for this host/user?

Every determination is fully auditable: the exact steps the agent took are
recorded and shown, so you can see *why* it concluded what it did.

## The moat: conservative closure

A false negative — calling a real threat benign — is the unforgivable error
in triage, and the specific failure incumbents get criticized for. Triagle's
guardrail layer wraps every verdict (including the LLM's) and makes wrongful
closure structurally impossible:

- Alerts carrying ransomware / credential-theft / lateral-movement / C2 /
  exfiltration signals are **always escalated, never auto-closed** — even at
  99% model confidence (verified by test).
- No closure below the confidence floor.
- Noise is dismissed **with evidence and a tuning recommendation**, not hidden.

This means Triagle can run on a cheaper/weaker model and still never miss a
real threat — the guardrails are the safety net.

## Model-agnostic by design

Like every serious player, the model is a swappable commodity — the security
context and investigation logic are the moat. Set `TRIAGLE_LLM_BACKEND`:

| Backend | Env vars | Notes |
|---|---|---|
| `deterministic` (default) | none | rule-based planner, zero cost, always works |
| `anthropic` | `ANTHROPIC_API_KEY` | Claude — top reasoning quality |
| `deepseek` | `DEEPSEEK_API_KEY` | cheap, strong reasoning |
| `nvidia` | `NVIDIA_API_KEY` | NIM free-tier hosted open models |
| `ollama` | `OLLAMA_HOST` | fully local — data never leaves your infra |

The agent loop, tools, and guardrails are identical across all backends.
Running fully local (Ollama) is a **data-privacy selling point** for
security buyers in India / EMEA.

## Quick start

```bash
pip install -r requirements.txt
# default: agentic mode, deterministic planner (no keys needed)
uvicorn app.main:app --reload --port 8000
```

Open `http://localhost:8000`. Click the ransomware alert to watch the agent's
autonomous investigation trail and its evidence-backed determination.

### Turn on a real model

```bash
export TRIAGLE_LLM_BACKEND=deepseek
export DEEPSEEK_API_KEY=...
# or nvidia / ollama / anthropic
```

### Fast (non-agentic) mode

```bash
export TRIAGLE_AGENTIC=false   # single-pass triage instead of investigation loop
```

## Architecture

```
app/
  connectors/sources.py   normalize EDR/firewall/identity alerts
  engine/triage.py        conservative-closure verdict + guardrails
  engine/correlate.py     link alerts into incidents (entity resolution)
  agent/
    tools.py              investigative tools the agent can call
    backend.py            model-agnostic LLM interface (5 backends)
    loop.py               the plan-act-observe-determine investigation loop
  orchestrator.py         batch processing, agentic or fast mode
templates/                console, alert detail (with trail), incident report
samples/                  synthetic multi-client alerts + investigation env
```

## Roadmap

- [x] Detection self-tuning — flags noisy rules for tuning (never auto-suppresses)

- [x] Response actions (isolate host, disable account) with human sign-off gates
- [ ] Analyst feedback loop — learn per-client "normal"
- [ ] Live connectors (API/webhook) for real tools
- [ ] Vector-DB context store for richer investigation
- [ ] Per-client SLA + closure-code analytics

## License

MIT — © 2026 Akash Sarkhel
