# Connecting Wazuh to Triagle

Wazuh detects. Triagle decides what a person needs to see, proposes the
response, and starts the reporting clock. Nothing changes inside Wazuh: no
custom rules, no plugin. A small forwarder on the Wazuh server reads the
alert file Wazuh already writes and posts each alert to Triagle.

```
endpoints / servers ──agent──▶ Wazuh manager ──▶ /var/ossec/logs/alerts/alerts.json
                                                          │  scripts/wazuh_forwarder.py
                                                          ▼
                                              Triagle  POST /ingest   (X-Triagle-Key)
```

## 1. On Triagle

Set an ingest key and (optionally) say which sector the client is in, so the
regulatory clock knows who they report to.

| Variable | Example | What it does |
|---|---|---|
| `TRIAGLE_INGEST_KEY` | a long random string | The forwarder must send the same value in `X-Triagle-Key` |
| `TRIAGLE_TENANTS` | `{"Acme Bank": "bank"}` | Client name → sector: `general`, `bank`, `nbfc`, `securities`, `power`, `healthcare`. Can also be changed on the Regulatory clock page |
| `TRIAGLE_LIVE_LIMIT` | `1500` | Live alerts kept in memory. Closed alerts age out first; totals keep counting |
| `TRIAGLE_CORRELATION_HOURS` | `24` | How far apart two alerts can be and still belong to one incident |
| `TRIAGLE_SEED` | `off` | Start with an empty queue instead of the sample alerts |

## 2. On the Wazuh server

```bash
sudo mkdir -p /opt/triagle
sudo curl -fsSL -o /opt/triagle/wazuh_forwarder.py \
  https://raw.githubusercontent.com/Akash-73/triagle/v0.8-regional/scripts/wazuh_forwarder.py

# try it by hand first: prints what it would send, sends nothing
sudo python3 /opt/triagle/wazuh_forwarder.py --dry-run --replay 5 --once --state ""

# then send the last 200 alerts and keep following
sudo python3 /opt/triagle/wazuh_forwarder.py \
  --triagle https://YOUR-TRIAGLE-URL --key YOUR_INGEST_KEY --client "Your Company" --replay 200
```

To run it as a service, use `scripts/triagle-forwarder.service` (the steps
are in the comments at the top of that file). It runs as the `wazuh` user and
keeps the key in a root-only environment file.

The forwarder keeps its place in the file, follows Wazuh's daily rotation,
and retries when Triagle is unreachable. Triagle ignores an alert it has
already seen, so replaying is safe.

## 3. What Triagle does with a Wazuh alert

| Wazuh field | Becomes | Note |
|---|---|---|
| `rule.description` | title | The only text matched against the risk-term lists |
| `rule.level` | severity | Wazuh's own bands: 0–6 low, 7–11 medium, 12–14 high, 15 critical |
| `rule.groups` | kind | `sca`, `vulnerability-detector` → posture finding. `system_error`, `system_shutdown`, `low_diskspace` → health event. Everything else → activity |
| `agent.name` | host | |
| `data.win.eventdata.commandLine` | command line | Matched against the behaviour patterns, whatever the rule level |
| `data.win.eventdata.user` / `subjectUserName` / `targetUserName`, `data.srcuser` | user | `SYSTEM`, machine accounts and service principals are not treated as people |
| `data.srcip`, `eventdata.ipAddress`, `destinationIp` | addresses | Loopback and empty values are dropped |
| `rule.mitre.*` | shown, not matched | Wazuh tags an ordinary logon with "Privilege Escalation". A label is not evidence |
| `full_log`, the Windows event message | kept in the raw alert, not matched | They hold paths and strings an attacker can choose |

Decisions that follow from this:

- **Posture findings** (benchmark and vulnerability results) are closed as
  `POSTURE_FINDING` and counted for the hardening backlog. A benchmark check
  that goes from passed to failed is a change, so it is escalated.
- **Health events** are closed as `OPERATIONAL_EVENT`, unless they come from
  a security control (Defender, the firewall).
- **Routine low-level activity** is closed as `BENIGN_EXPECTED`, unless the
  title carries a sensitive term or the command line matches a behaviour.
- **A low rule level never excuses a command line.** A level-4 alert whose
  command deletes shadow copies is escalated as a real attack.
- **Related alerts** only count when an analyst would stop at them, and only
  within the correlation window. An incident contains the escalated alerts,
  not the host's routine noise.
- **Probing from outside** with no sign of success (SSH brute force against
  an exposed server) is escalated and can be blocked, but does not start a
  regulatory clock.

## 4. Check it

`python -m pytest -q tests/test_wazuh.py` runs the connector and the engine
against 68 labelled alerts built from the stock Wazuh 4.14 ruleset
(`eval/wazuh_dataset.json`). The requirement: no attack step closed, no
routine alert escalated.

## 5. Triagle inside the Wazuh dashboard

Wazuh keeps each alert as a fixed record: there is no status to set and
nothing to mark as closed. So Triagle writes its answer beside the alert
instead, as entries of its own, and Wazuh shows the detection, the verdict and
the response in one place.

Two kinds of entry:

- **The verdict.** The forwarder asks Triagle for its verdict on every alert it
  sends: "Triagle closed: Known tool or system file on FIN-LAPTOP-07" or
  "Triagle escalated: Obfuscated PowerShell execution on FIN-LAPTOP-07".
- **What people did next.** Every few seconds the forwarder asks Triagle what
  has been done since: "Triagle: admin blocked 2.57.121.25 at the firewall",
  "Triagle: admin closed "Software installed or changed on a server" on
  db-01 as: Expected activity".

Both are appended, one JSON object per line, to
`/var/lib/triagle-forwarder/verdicts.json`. Point Wazuh at that file:

```bash
sudo curl -fsSL -o /var/ossec/etc/rules/triagle_rules.xml \
  https://raw.githubusercontent.com/Akash-73/triagle/v0.8-regional/scripts/wazuh/triagle_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/triagle_rules.xml
sudo chmod 660 /var/ossec/etc/rules/triagle_rules.xml

# tell Wazuh to read the file (skipped if already there)
sudo grep -q triagle-forwarder/verdicts.json /var/ossec/etc/ossec.conf || \
  printf '%s\n' '<ossec_config>' '  <localfile>' '    <log_format>json</log_format>' \
  '    <location>/var/lib/triagle-forwarder/verdicts.json</location>' '  </localfile>' \
  '</ossec_config>' | sudo tee -a /var/ossec/etc/ossec.conf >/dev/null

# check the rules load, and only then restart
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

In the dashboard open Threat Hunting, Events, and filter `rule.groups: triagle`.
Useful columns: `rule.description`, `data.triagle.agent`,
`data.triagle.wazuh_rule_level`, `data.triagle.reason`, `data.triagle.url`.

| Rule | Level | Group | Meaning |
|---|---|---|---|
| 100501 | 3 | `triagle_closed` | Triagle closed the alert, with the reason |
| 100502 | 10 | `triagle_escalated` | Triagle sent it to a person |
| 100503 | 13 | `triagle_escalated` | Sent to a person, and rated critical |
| 100511 | 8 | `triagle_response` | A person blocked an address at the firewall |
| 100512 | 8 | `triagle_response` | A person lifted a block |
| 100513 | 4 | `triagle_response` | A person approved an action (says if it was a rehearsal) |
| 100514 | 3 | `triagle_response` | A person declined an action |
| 100515 | 4 | `triagle_response` | A person closed the alert, with the outcome |
| 100516 | 4 | `triagle_response` | A person reopened it |
| 100517 | 5 | `triagle_response` | A person marked a regulator's report as filed |

What to know:
- By default benchmark results and health events are not written back
  (`TRIAGLE_WRITEBACK=activity`). Use `all` for everything or `off` for nothing.
- It is the verdict at the time the alert arrived. A later alert can raise an
  earlier one in Triagle; that change is not written back.
- What people did is collected every 5 seconds (`TRIAGLE_EVENTS_SECONDS`). The
  forwarder remembers how far it has read, so nothing is written twice.
- These entries are never forwarded to Triagle again, so there is no loop.

## 6. A ready-made dashboard

`scripts/wazuh/triagle_dashboard.ndjson` is a dashboard called "Triagle" for
the Wazuh dashboard. It shows how many alerts Triagle closed and how many it
sent to a person, why it closed them, both over time, what Wazuh rated high or
critical that Triagle closed, what was sent to a person, and what people did
about it. It refreshes every 30 seconds.

Import it once the first verdicts have arrived:

1. Download `triagle_dashboard.ndjson` from this repository.
2. In the Wazuh dashboard open the menu, Dashboards Management, Saved objects.
3. Click Import, choose the file, and import.
4. Open it from the menu under Explore, Dashboards, or go straight to
   `https://<your-wazuh>/app/dashboards#/view/triagle-dashboard`.

If the import asks which index pattern to use, choose `wazuh-alerts-*`. If a
panel says a field is not found, open the Wazuh home page once, so it
refreshes its list of fields, and reload the dashboard. Importing the file
again replaces the earlier copy.

The file is built by `scripts/wazuh/make_dashboard.py` for OpenSearch
Dashboards 2.x, which the Wazuh dashboard 4.x is built on.
