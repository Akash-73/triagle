# Triagle — AI SOC analyst

**Triage, decided.**

Triagle sits on top of the SIEM and security tools a company already has. It
triages every alert, never closes a real attack, and keeps the company inside
the regulator's reporting clock. It is built for India's regulated mid-market
(co-operative banks, NBFCs, brokers, hospitals, utilities) and the MSSPs that
serve them: organisations that are required to run a SOC and cannot staff one.

For every alert it runs an investigation — planning which evidence to gather,
calling investigative tools, reasoning over what it finds, and reaching an
auditable determination — built around one rule: **an alert carrying a risk
signal is never closed automatically, whatever the model says.**

## Runs on a real SIEM stream

`POST /ingest` takes alerts from any tool with a connector. The Wazuh
connector reads an alert exactly as Wazuh writes it; a forwarder on the Wazuh
server ships them (see [docs/WAZUH.md](docs/WAZUH.md)).

The first run against alerts shaped like a real Wazuh feed was a failure
worth recording. v0.7 escalated **68 of 68**. On a real host there is always
another alert nearby, so the rule "two related alerts on the same host means
escalate" was true of everything, and one laptop's routine logons became part
of every incident. What changed:

- Related alerts only count when an analyst would stop at them, and only
  inside a 24-hour window.
- An incident holds the escalated alerts, not the host's noise. Sharing an
  account or an address links two alerts; sharing only a host links them
  when both are notable in their own right.
- The source tool's own classification is used: benchmark results and
  vulnerability findings are posture, errors and shutdowns are health
  events. Neither is triaged as an attack. A benchmark check that stops
  passing is a change and is escalated.
- A MITRE tactic label is not evidence. Wazuh tags an ordinary logon with
  "Privilege Escalation".
- A low rule level never excuses a command line.

On the same 68 alerts now: 15 of 15 attack steps escalated, 41 of 41 routine
alerts closed with a reason, 18 escalated in all.

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

## The regulatory clock

A confirmed incident usually owes more than one report, to more than one
regulator, on more than one deadline. `/clock` shows every incident with a
report to consider, which regulators that client answers to, and a live
countdown for each deadline. Each has a draft; a person checks and sends it,
then marks it filed, which stops that clock and goes in the audit log.
Triagle never files anything itself.

| Sector | Reports to |
|---|---|
| Bank, co-operative bank, NBFC | CERT-In (6 h) · RBI (6 h) |
| SEBI-regulated entity | CERT-In (6 h) · SEBI email (6 h) and portal (24 h) |
| Power utility | CERT-In (6 h) · CSIRT-Power (6 h, binding from 1 April 2027) |
| Anyone, if personal data was affected | Data Protection Board (72 h, enforceable from 13 May 2027) |

The deadlines are data in `app/engine/regclock.py`, each with the instrument
it comes from and a line on what to verify. Rules that are not binding yet
are shown as such, with the time they would have been due. This is a working
aid for a compliance lead, not legal advice.

Two judgement rules are built in. The clock starts at the first alert Triagle
judged an attack on that alert's own evidence, not at an earlier weak signal
that only looks suspicious in hindsight. And probing from outside that shows
no sign of success does not start a clock: it is listed as watched.

Which sector a client is in comes from `samples/tenants.json`, the
`TRIAGLE_TENANTS` variable, or the selector on the clock page.

Each draft (`/notice/<incident>/<regulator>`, and `/certin/<incident>`)
holds: incident type, times, affected systems, timeline, indicators, actions
taken and proposed, and points to check for a DPDP breach assessment. Fields
Triagle cannot know are listed, not guessed.

`TRIAGLE_DEMO_CLOCK=true` shifts the sample alerts' timestamps to end five
minutes ago so the clocks can be shown running.

## Care around operational technology

Triagle does not detect attacks on industrial control systems; an OT network
monitor does that, and its alerts arrive through the `ot_monitor` connector.
What Triagle adds is care about what happens next. In IT the safe reflex is
to isolate the machine. In a plant or a substation that reflex can stop a
process, or take the screen away from the operators keeping it safe.

- An alert that touches a controller (PLC, RTU, IED, DCS, safety system) is
  never closed without a person, whatever a model says.
- A controller or an operator station (HMI, SCADA server, historian,
  engineering workstation) is never isolated. Containment is proposed at the
  IT/OT boundary firewall instead, with the blast radius spelled out, and it
  needs an engineer's approval and acknowledgement.
- The first proposed step is a phone call to the control room. Triagle
  records that it was made; there is no system call.
- Nothing is automatic when an OT asset is involved, including actions that
  are automatic elsewhere, such as blocking a confirmed-malicious address.

Assets are recognised by name, or listed in `TRIAGLE_OT_CONTROLLERS` and
`TRIAGLE_OT_STATIONS`. In a real deployment the list comes from the OT
monitor's inventory. See `app/engine/ot.py` and `tests/test_ot.py`.

## Demo scenarios

With `TRIAGLE_DEMO=true` the console has two "fire live attack" buttons. Both
run the same intrusion; the sector changes what Triagle does about it.

| Scenario | Tenant | What it shows |
|---|---|---|
| `bank` (default) | a co-operative bank | CERT-In and RBI clocks running together; host isolation and account actions with human approval |
| `power` | a power utility | the foothold is an HMI and the attacker sends a breaker command to an RTU: no isolation, containment at the boundary, CSIRT-Power on the clock |

All clients in the samples and scenarios are invented.

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
| `TRIAGLE_GUEST=view` | Anyone with the address can look around, try an alert and ask about a case without signing in. Every change still needs a signed-in analyst |
| `TRIAGLE_STATE_FILE` | Saves the queue, decisions and filed reports to this file so a restart does not empty the console. See [docs/DEPLOY.md](docs/DEPLOY.md) |

If no user is configured the app does not run open: it creates `admin` with
a random password and prints it once in the server log.

Five wrong passwords lock that username and address out for five minutes.
Approve, decline and sign-out forms carry a token tied to the session.

Every sign-in, failed sign-in, approval and decline is written to the audit
log with the user's name, the alert, the action and its target. Entries are
chained by hash; `/audit` shows the log and whether the chain is intact.
The chain detects edited or removed lines. It does not stop someone with
server access from deleting the file, so ship it off the box for anything
that matters. On Cloud Run each entry is also written to Google Cloud
Logging, which survives a redeploy. On a host with an ephemeral disk (Render's free tier) the log
is lost on redeploy unless you mount a disk.

Not yet: password reset, per-client access (every user sees every client),
single sign-on, two-factor. The queue, action status and filings are held in
memory: they survive new alerts arriving but not a restart. The audit log is
the durable record of who approved, declined or filed what.

## Measured

```bash
pip install -r requirements-dev.txt
python -m pytest -q                 # 182 tests, no network or key needed
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

`eval/wazuh_dataset.json` is 68 labelled alerts in Wazuh's own format, built
from the stock 4.14 ruleset: routine Windows and Linux telemetry, benchmark
and vulnerability findings, health events, SSH brute force from the internet,
and two hands-on intrusions on a workstation.

| Wazuh-shaped set | v0.7 | v0.8 |
|---|---|---|
| Attack steps missed | 0 of 15 | 0 of 15 |
| Routine alerts sent to a human | 41 of 41 | 0 of 41 |
| Escalated in total | 68 of 68 | 18 of 68 |

What this does not show: the alerts are simulated and written by the engine's
author, so it is a regression check on known attack shapes, not evidence of
accuracy in a real environment. The measurement that matters is a live feed. The model backends are covered by stubbed
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
  connectors/wazuh.py     read a Wazuh alert as Wazuh writes it
  engine/signals.py       risk terms, command-line behaviours, alert kinds
  engine/triage.py        conservative-closure verdict + guardrails
  engine/relate.py        what else of note happened on this host / user, recently
  engine/correlate.py     link a client's alerts into incidents (never across clients)
  engine/regclock.py      regulators, sectors and the reporting clock
  engine/ot.py            OT assets and the rules that hold around them
  engine/certin.py        report draft; when the clock starts; what is reportable
  privacy.py              Aadhaar / PAN / UPI / mobile / email masking
  auth.py                 sign-in, roles, sessions, form tokens
  audit.py                append-only, hash-chained audit log
  agent/
    tools.py              investigative tools the agent can call
    backend.py            model-agnostic LLM interface (5 backends)
    loop.py               the plan-act-observe-determine investigation loop
  orchestrator.py         batch processing, agentic or fast mode
templates/                console, alert detail (with trail), incident report
scripts/wazuh_forwarder.py  runs on the Wazuh server, posts alerts to /ingest
samples/                  synthetic multi-client alerts, tenant sectors, investigation env
eval/                     labelled simulated datasets + benchmark
tests/                    test suite
```

## Roadmap

- [x] Detection self-tuning — flags noisy rules for tuning (never auto-suppresses)

- [x] Response actions (isolate host, disable account) with human sign-off gates
- [x] Gemini backend, personal-data masking, CERT-In draft, benchmark
- [ ] Live run of the benchmark on a model backend
- [x] Sign-in with roles and a hash-chained audit log of approvals
- [x] Saved state: the queue, decisions and filed reports survive a restart
- [ ] Per-client access control
- [ ] Analyst feedback loop — learn per-client "normal"
- [x] Live connector: Wazuh, with a forwarder and a queue that holds up on a real stream
- [x] Regulatory clock: CERT-In, RBI, SEBI, CSIRT-Power, Data Protection Board
- [x] OT-safe response: no isolation of controllers or operator stations, containment at the boundary
- [x] One real containment action end to end: an approved block becomes a Google Cloud firewall rule, and can be lifted ([docs/RESPONSE.md](docs/RESPONSE.md))
- [ ] Live threat-intelligence feeds
- [ ] Vector-DB context store for richer investigation
- [ ] Per-client SLA + closure-code analytics

## License

MIT — © 2026 Akash Sarkhel
