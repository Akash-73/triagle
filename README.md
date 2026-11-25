# Triagle — AI SOC analyst

**Triage, decided.**

Triagle sits on top of the SIEM and security tools a company already has. It
triages every alert, never closes a real attack, and keeps the company inside
the regulator's reporting clock. It is built for managed security providers in
India, the firms that run the night shift for many companies, and for the
regulated organisations they watch: co-operative banks, NBFCs, brokers,
hospitals and utilities that are required to run a SOC and cannot staff one.

Live since 24 November 2026 on a real Wazuh feed, on Google Cloud Run:
<https://triagle-20867456071.us-central1.run.app> (anyone can look around; a
change needs a signed-in analyst). How it is secured, and what is not done
yet, is on its public page [/security](https://triagle-20867456071.us-central1.run.app/security)
and in [SECURITY.md](SECURITY.md).

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

It also answers inside the SIEM. Each verdict, and everything a person then
does about it, is written back to Wazuh as its own entry: "Triagle closed:
Known tool or system file on FIN-LAPTOP-07", "Triagle: admin blocked
2.57.121.25 at the firewall". A ready-made Wazuh dashboard shows how many
alerts were closed and why, what Wazuh rated critical that Triagle closed,
and what people did. The analyst sees the detection, the verdict and the
response without leaving the tool they already use.

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
| `gemini` | `GEMINI_API_KEY` | Google Gemini API; default model `gemini-3.5-flash`, override with `TRIAGLE_MODEL` |
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

## Teaching it, and checking it

Two things a customer can do from the screen, without anyone changing Triagle's code.

**Teach it.** When an analyst closes an alert as expected activity or as a false
positive, they can tick "Do the same next time". Triagle then closes the same
detection rule on that machine (and, if they choose, for that account) from then on.
The rules are listed under **Your rules**, with who taught each one, why, how often it
has been used and when it runs out.

- A taught rule runs for 7, 30 or 90 days and then stops, unless someone renews it.
- It never closes an alert raised on evidence: a risk signal on the alert, a known-bad
  address, a sign-in pattern such as password guessing, or anything about operational
  technology.
- It never reaches back. Switching it off stops it from that moment and leaves what it
  closed as it was.
- Once a taught rule has been used, **Detection tuning** says how to make the same
  change in the tool itself.

**Check it.** **Spot checks** offers a sample of the alerts Triagle closed on its own,
taken across every reason for closing and every detection rule. An analyst agrees or
disagrees with each. A disagreement sends the alert back to the queue. The share agreed
with is the figure a pilot is judged on, and it is never rounded up.

**Pilot report** (`/pilot`) puts it on one printable page: what arrived, what was
closed and why, what went to a person, the agreement figure, what people taught it,
which rules to fix in the tool, and what the model cost.

The model's cost is counted from the token figures the API returns with each answer
(see **Connectors**, Model). Prices are per million tokens in US dollars and default to
the published price of the default model. Set `TRIAGLE_PRICE_IN` and
`TRIAGLE_PRICE_OUT` if the price list or the model changes.

## The night analyst's paperwork

One analyst on a night shift does four jobs: watches the queue, writes the report for
the morning call with the customer, mails users to ask "was this you?", and writes the
handover. The engine does the first. Gemini does the writing for the other three.

- **Morning report** (`/morning`): one customer, the last 8, 12 or 24 hours. Figures,
  what needs the customer's answer and the question to ask, open cases, the handover
  for the day shift and the rules to fix. The summary at the top is written by Gemini
  from those figures when a signed-in analyst opens the page; a visitor sees the last
  one written, or a plain summary built by rule.
- **Ask the user**: on an alert that names an account, "Draft the message" writes the
  mail that asks the owner whether it was them. The analyst sends it, changes it or
  throws it away. Nothing is sent from Triagle.
- **Second reading**: on Spot checks, "Ask Gemini to read these" has the model read
  back over the engine's closures and say which it would look at again, with a
  reason. Those are listed first. It changes no verdict.

**What the model learns from.** Before it writes or reads, Gemini is given what the
engine decided and why, and what this customer's own analysts decided before: the
rules they taught, the alerts they closed themselves and the closures they disagreed
with. That is in context, on every call. Nothing is sent anywhere for training.

**Why the engine comes first.** The engine settles every alert in milliseconds and the
same way every time, so the model is only called where language or a second opinion
adds something: a case, a report, a message, a review. The cost of that is counted
and shown under Connectors, Model.

## Telling the SIEM what to fix

The Detection tuning page looks at the rule behind each alert: what the tool
rates it, how many of its alerts went to a person, how many Triagle closed,
and why. Its first run on a real feed was also worth recording. It marked 15
of 28 rules as tuning candidates, because every alert from them had been
closed. Thirteen of those were sign-ins, sessions closing and an administrator
using sudo: records the tool itself rates low, with nothing to tune. It also
called the repeats of a password-guessing address "86% noise", when they were
the attack. What changed:

- A rule the tool rates low whose alerts were all routine is a record, not a
  candidate.
- A rule is a candidate when every alert was closed and the tool still rates
  it medium or higher, or the alerts were all one recognised harmless thing.
  The page says what they had in common and, for Wazuh, names the rule to
  override with a child rule at level 0.
- An alert counted under another one (a member of a burst, a repeat of an
  address already raised, the earlier failed sign-ins from that address)
  belongs to that event. It is never called noise.
- What a person decided outranks what Triagle did: alerts marked as false
  positives make the rule a candidate, alerts confirmed as expected do not.

Triagle only flags. It never switches a rule off, because a noisy rule can
still catch the one real attack. See `app/engine/tuning.py` and
`tests/test_tuning.py`.

## Watching it work, and testing it

The **Live** page lists alerts as they arrive, newest first. Each row shows
what the tool said and what Triagle decided, with the reason in a sentence.
Anyone who may look at the console may watch it, a guest included.

With `TRIAGLE_DEMO=true` a signed-in analyst can also send a test stream from
that page. It is sent one alert at a time through the same path a connected
tool's alerts take, so the decisions on screen are the engine's own:

| Test stream | What arrives |
|---|---|
| A working hour, with one intrusion in it | about thirty alerts from three tools for an invented customer. The routine ones are closed, each with its reason; the five that are the intrusion are raised as one case, and the reporting clock starts |
| The intrusion alone | the same five alerts and one routine one |

Every test alert is marked "test" and belongs to a customer of its own, so
starting or clearing a stream never touches a connected tool's alerts.

Two customers are built in; the sector changes what Triagle does about the
same intrusion. `TRIAGLE_DEMO_SCENARIOS=bank` limits a deployment to one.

| Scenario | Customer | What it shows |
|---|---|---|
| `bank` (default) | a co-operative bank | CERT-In and RBI clocks running together; host isolation and account actions with human approval |
| `power` | a power utility | the foothold is an HMI and the attacker sends a breaker command to an RTU: no isolation, containment at the boundary, CSIRT-Power on the clock |

All customers in the samples and test streams are invented.

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
| `TRIAGLE_ADMIN_TOTP`, or a fourth field in `TRIAGLE_USERS` | A second factor: a six-digit code from an authenticator app (RFC 6238). `python -m app.auth totp name` makes the key |
| `TRIAGLE_OIDC_CLIENT_ID`, `TRIAGLE_OIDC_CLIENT_SECRET`, `TRIAGLE_OIDC_USERS` | Single sign-on with Google, Microsoft Entra ID or any OpenID Connect provider, for the addresses on the list and nobody else |
| `TRIAGLE_INGEST_KEYS` | One intake key for each customer, as `Customer name=key` lines. The key, not the sender, decides whose queue an alert joins |

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

Not yet: password reset, and a login for each client (every signed-in user
sees every client in the deployment; each client's feed has its own key).
The queue, decisions and filings are held in memory and saved to one file,
so they survive a restart. There is no database yet.

## Security

What is in place, with the code and the tests in this repository:

- **Sign-in.** Salted scrypt password hashes, a lockout after five failures,
  an optional authenticator code, optional single sign-on, roles checked on
  the server, and a token on every form.
- **A key for each customer.** A customer's key writes to that customer's
  queue and reads back that customer's record, and no other.
- **Nothing acts alone.** A response runs only after a named analyst
  approves it, and each approval goes in a hash-chained audit log.
- **Pages.** A content-security policy under which a script runs only if it
  is one of Triagle's own files or carries a one-time code made for that
  page. No framing, strict transport security, no caching.
- **The image.** It cannot be built unless every test passes. The app gives
  up root before it starts, unless its storage is still mounted for root, in
  which case it says so in its log.
- **The pipeline.** Tests, a dependency audit, an image check and CodeQL
  code scanning run on every push.
- **A deployment.** `scripts/harden_cloud.sh` backs up the saved state,
  moves secrets into Secret Manager, ties the intake key to its customer,
  and puts the previous revision back by itself if the feed stops getting
  in. See [docs/DEPLOY.md](docs/DEPLOY.md).

What is not done: an independent penetration test, a database, a login for
each client, and an Indian hosting region. To report a problem, see
[SECURITY.md](SECURITY.md).

## Measured

```bash
pip install -r requirements-dev.txt
python -m pytest -q                 # 429 tests, no network or key needed
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
- [x] A key for each client's feed, so one client cannot write to or read another's queue
- [ ] A login for each client
- [x] Analyst feedback loop: an analyst teaches a rule from the screen, for one client and one machine
- [x] Second factor and single sign-on (OpenID Connect)
- [x] Hardened build: strict script policy, unprivileged image, tests that block a build, code scanning
- [ ] A database in place of the single state file
- [ ] An independent penetration test
- [x] Live connector: Wazuh, with a forwarder and a queue that holds up on a real stream
- [x] Regulatory clock: CERT-In, RBI, SEBI, CSIRT-Power, Data Protection Board
- [x] OT-safe response: no isolation of controllers or operator stations, containment at the boundary
- [x] One real containment action end to end: an approved block becomes a Google Cloud firewall rule, and can be lifted ([docs/RESPONSE.md](docs/RESPONSE.md))
- [ ] Live threat-intelligence feeds
- [ ] Vector-DB context store for richer investigation
- [ ] Per-client SLA + closure-code analytics

## License

MIT — © 2026 Akash Sarkhel
