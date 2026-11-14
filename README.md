# Triagle — Agentic AI SOC Analyst

**Triage, decided.**

Triagle is an agentic AI SOC analyst built for MSPs. For every alert it runs
an autonomous investigation — planning which evidence to gather, calling
investigative tools, reasoning over what it finds, and reaching an auditable
determination — built around one rule: **an alert carrying a risk signal is
never closed automatically, whatever the model says.**

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
  99% model confidence (`tests/test_triagle.py`).
- Signals are matched two ways: words in the alert's title/description, and
  command-line behaviour (shadow-copy deletion, comsvcs MiniDump, encoded
  PowerShell, PsExec...) so a quietly titled "low" alert is still caught.
- The admin-tool allowlist matches the tool's command line, not its name in
  free text, so `sccm_update.exe` or a dump written to `C:\CyberArk\` does
  not buy an attacker a closure.
- No closure below the confidence floor.
- Noise is dismissed **with evidence and a tuning recommendation**, not hidden.

The guardrails are a floor under the model, not a proof. See "Measured" below
for what has and has not been tested.

## Model-agnostic by design

Like every serious player, the model is a swappable commodity — the security
context and investigation logic are the moat. Set `TRIAGLE_LLM_BACKEND`:

| Backend | Env vars | Notes |
|---|---|---|
| `deterministic` (default) | none | rule-based planner, zero cost, always works |
| `gemini` | `GEMINI_API_KEY` | Google Gemini API; default model `gemini-3.8-flash`, override with `TRIAGLE_MODEL` |
| `anthropic` | `ANTHROPIC_API_KEY` | Claude — top reasoning quality |
| `deepseek` | `DEEPSEEK_API_KEY` | cheap, strong reasoning |
| `nvidia` | `NVIDIA_API_KEY` | NIM free-tier hosted open models |
| `ollama` | `OLLAMA_HOST` | fully local — data never leaves your infra |

The agent loop, tools, and guardrails are identical across all backends.
Running fully local (Ollama) is a **data-privacy selling point** for
security buyers in India / EMEA.

## Personal data never leaves in the clear

Every prompt is masked before it goes to a model API and unmasked on the way
back: Aadhaar (with check-digit validation), PAN, UPI IDs, Indian mobile
numbers and email addresses become placeholders like `<AADHAAR_1>`. Pattern
matching only — it does not find names or addresses. `TRIAGLE_MASK_PII=false`
turns it off for a model running on the same machine.

## CERT-In report draft

Each escalated incident has a draft at `/certin/<entity>`: incident type,
times, affected systems, timeline, indicators, actions taken and proposed,
points to check for a DPDP breach assessment, and the 6-hour reporting clock.
It is a draft for a person to complete and send. Nothing is filed, and
fields Triagle cannot know are listed, not guessed. Check the incident-type
wording against CERT-In's current Directions before relying on it.

`TRIAGLE_DEMO_CLOCK=true` shifts the sample alerts' timestamps to end five
minutes ago so the clock can be shown running.

## Sign-in and the audit log

Nobody reaches the console without signing in.

| Variable | What it does |
|---|---|
| `TRIAGLE_ADMIN_PASSWORD` | Password for the built-in user `admin` (an analyst) |
| `TRIAGLE_USERS` | More users: `name:role:hash,name:role:hash`. Role is `analyst` (can approve and decline actions, sees the audit log) or `viewer` (read only). Make a hash with `python -m app.auth hash` |
| `TRIAGLE_SECRET` | Signs session cookies. Set it, or everyone is signed out when the app restarts |
| `TRIAGLE_SESSION_HOURS` | Session length, default 8 |
| `TRIAGLE_AUDIT_LOG` | Where the audit log is written, default `data/audit.jsonl` |
| `TRIAGLE_AUTH=off` | Turns sign-in off. Laptop demos only; the dashboard shows a red "sign-in is OFF" |

If no user is configured the app does not run open: it creates `admin` with
a random password and prints it once in the server log.

Five wrong passwords lock that username and address out for five minutes.
Approve, decline and sign-out forms carry a token tied to the session.

Every sign-in, failed sign-in, approval and decline is written to the audit
log with the user's name, the alert, the action and its target. Entries are
chained by hash; `/audit` shows the log and whether the chain is intact.
The chain detects edited or removed lines. It does not stop someone with
server access from deleting the file, so ship it off the box for anything
that matters. On a host with an ephemeral disk (Render's free tier) the log
is lost on redeploy unless you mount a disk.

Not yet: password reset, per-client access (every user sees every client),
single sign-on, two-factor. Who approved an action is kept in the audit log,
but the action's status on the page resets when the app restarts.

## Measured

```bash
pip install -r requirements-dev.txt
python -m pytest -q                 # 80 tests, no network or key needed
python eval/build_dataset.py        # regenerate the labelled set
python -m eval.run_benchmark        # or open /benchmark in the app
```

`eval/dataset.json` is 38 simulated, labelled alerts across five clients:
loud and quiet ransomware, phishing-to-account-takeover, brute force,
attackers hiding behind allowlisted tool names, routine admin noise, and
harmless alerts that contain alarming words.

| Deterministic engine | v0.1 | v0.2 |
|---|---|---|
| Real threats missed | 3 of 21 | 0 of 21 |
| Benign alerts sent to a human | 4 of 15 | 1 of 15 |

What this does not show: the alerts are simulated and written by the engine's
author, so it is a regression check on known attack shapes, not evidence of
accuracy in a real environment. The model backends are covered by stubbed
tests only; no live model run is included in these numbers.

## Quick start

```bash
pip install -r requirements.txt
# default: agentic mode, deterministic planner (no keys needed)
export TRIAGLE_ADMIN_PASSWORD='choose-one'     # Windows cmd: set TRIAGLE_ADMIN_PASSWORD=choose-one
uvicorn app.main:app --reload --port 8000
```

Open `http://localhost:8000` and sign in as `admin`. Click the ransomware alert to watch the agent's
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
  engine/signals.py       risk terms + command-line behaviours
  engine/triage.py        conservative-closure verdict + guardrails
  engine/correlate.py     link a client's alerts into incidents (never across clients)
  engine/certin.py        CERT-In report draft + 6-hour clock
  privacy.py              Aadhaar / PAN / UPI / mobile / email masking
  auth.py                 sign-in, roles, sessions, form tokens
  audit.py                append-only, hash-chained audit log
  agent/
    tools.py              investigative tools the agent can call
    backend.py            model-agnostic LLM interface (5 backends)
    loop.py               the plan-act-observe-determine investigation loop
  orchestrator.py         batch processing, agentic or fast mode
templates/                console, alert detail (with trail), incident report
samples/                  synthetic multi-client alerts + investigation env
eval/                     labelled simulated dataset + benchmark
tests/                    test suite
```

## Roadmap

- [x] Detection self-tuning — flags noisy rules for tuning (never auto-suppresses)

- [x] Response actions (isolate host, disable account) with human sign-off gates
- [x] Gemini backend, personal-data masking, CERT-In draft, benchmark
- [ ] Live run of the benchmark on a model backend
- [x] Sign-in with roles and a hash-chained audit log of approvals
- [ ] Per-client access control; storage so action status survives a restart
- [ ] Analyst feedback loop — learn per-client "normal"
- [ ] Live connectors (API/webhook) for real tools
- [ ] Vector-DB context store for richer investigation
- [ ] Per-client SLA + closure-code analytics

## License

MIT — © 2026 Akash Sarkhel
