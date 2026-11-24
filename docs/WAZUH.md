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

## 5. Triagle's verdicts inside the Wazuh dashboard

The forwarder asks Triagle for its verdict on every alert it sends and appends
it, one JSON object per line, to `/var/lib/triagle-forwarder/verdicts.json`.
Point Wazuh at that file and each verdict becomes an entry in the Wazuh
dashboard: "Triagle closed: Known tool or system file on FIN-LAPTOP-07" or
"Triagle escalated: Obfuscated PowerShell execution on FIN-LAPTOP-07".

```bash
sudo curl -fsSL -o /var/ossec/etc/rules/triagle_rules.xml \
  https://raw.githubusercontent.com/Akash-73/triagle/v0.8-regional/scripts/wazuh/triagle_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/triagle_rules.xml
sudo chmod 660 /var/ossec/etc/rules/triagle_rules.xml

# tell Wazuh to read the verdicts file (skipped if already there)
sudo grep -q triagle-forwarder/verdicts.json /var/ossec/etc/ossec.conf || \
  printf '%s\n' '<ossec_config>' '  <localfile>' '    <log_format>json</log_format>' \
  '    <location>/var/lib/triagle-forwarder/verdicts.json</location>' '  </localfile>' \
  '</ossec_config>' | sudo tee -a /var/ossec/etc/ossec.conf >/dev/null

# check the rules load, and only then restart
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

In the dashboard open Threat Hunting, Events, and filter `rule.groups: triagle`.
Useful columns: `data.triagle.agent`, `data.triagle.wazuh_rule`,
`data.triagle.reason`, `data.triagle.case`.

| Rule | Level | Meaning |
|---|---|---|
| 100501 | 3 | Triagle closed the alert, with the reason |
| 100502 | 10 | Triagle escalated it to a person |
| 100503 | 13 | Escalated, and Triagle rated it critical |

What to know:
- By default benchmark results and health events are not written back
  (`TRIAGLE_WRITEBACK=activity`). Use `all` for everything or `off` for nothing.
- It is the verdict at the time the alert arrived. A later alert can raise an
  earlier one in Triagle; that change is not written back.
- Verdict entries are never forwarded to Triagle again, so there is no loop.
