#!/usr/bin/env python3
"""
Triagle forwarder for Wazuh.

Runs on the Wazuh server. Follows /var/ossec/logs/alerts/alerts.json (the
file Wazuh itself writes every alert to, one JSON object per line) and posts
each new alert, untouched, to Triagle's /ingest webhook. Triagle does the
reading and the triage; this script only moves alerts.

    python3 wazuh_forwarder.py --triagle https://your-triagle.run.app \\
        --key <TRIAGLE_INGEST_KEY> --client "Your Company"

Needs nothing but Python 3.8+ (standard library only).

What it takes care of:
  - sends in batches of up to 50, every couple of seconds
  - remembers how far it got (--state), so a restart neither loses nor
    repeats alerts
  - follows Wazuh's daily rotation of alerts.json
  - if Triagle is unreachable it keeps its place and retries; nothing is
    dropped unless the backlog passes --max-backlog lines
  - --replay N sends the last N alerts already in the file on first start,
    so a fresh console is not empty
  - writes Triagle's verdict for each alert to --verdicts (one JSON object per
    line). Point Wazuh at that file and the verdict shows up in the Wazuh
    dashboard next to the alert: "Triagle closed: ..." / "Triagle escalated:
    ...". Those entries are never forwarded back, so there is no loop.

Settings can also come from the environment (TRIAGLE_URL, TRIAGLE_INGEST_KEY,
TRIAGLE_CLIENT), which is how the systemd unit passes the key without it
appearing in the process list.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BATCH = 50                      # Triagle's /ingest limit per request
MAX_MESSAGE = 4000              # trim very long Windows event messages


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def trim(alert):
    """Cap the one field that can be huge. Everything else is sent as is."""
    try:
        system = alert["data"]["win"]["system"]
        if len(system.get("message", "")) > MAX_MESSAGE:
            system["message"] = system["message"][:MAX_MESSAGE] + " …[trimmed]"
    except (KeyError, TypeError):
        pass
    if len(alert.get("full_log", "") or "") > MAX_MESSAGE:
        alert["full_log"] = alert["full_log"][:MAX_MESSAGE] + " …[trimmed]"
    return alert


def wanted(alert, min_level):
    rule = alert.get("rule")
    if not isinstance(rule, dict) or not rule.get("description"):
        return False
    groups = rule.get("groups") or []
    if "triagle" in groups or (isinstance(alert.get("data"), dict) and "triagle" in alert["data"]):
        return False                      # Triagle's own verdict, read back by Wazuh: never send it round again
    try:
        return int(rule.get("level", 0)) >= min_level
    except (TypeError, ValueError):
        return True


def post(url, key, items, timeout=30):
    """POST one batch. Returns (ok, text, verdicts). verdicts is the list
    Triagle sends back, one entry per alert it could read (empty on failure
    or from an older Triagle)."""
    req = urllib.request.Request(
        url.rstrip("/") + "/ingest?verdicts=1", data=json.dumps(items).encode(),
        headers={"Content-Type": "application/json", "X-Triagle-Key": key,
                 "User-Agent": "triagle-wazuh-forwarder/1.1"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read().decode("utf-8", "replace")
        try:
            verdicts = json.loads(text).get("verdicts") or []
        except (ValueError, AttributeError):
            verdicts = []
        return True, text[:200], verdicts if isinstance(verdicts, list) else []
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:200]
        if e.code in (401, 403):
            # a wrong key is a setup fault: keep the alerts and keep trying
            return False, f"HTTP {e.code}: the key was refused. Check it matches Triagle's TRIAGLE_INGEST_KEY", []
        # other 4xx (bad payload) will not get better by retrying the same batch
        fatal = 400 <= e.code < 500 and e.code not in (408, 429)
        return (None if fatal else False), f"HTTP {e.code}: {body}", []
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, f"{type(e).__name__}: {e}", []


VERDICTS_MAX_BYTES = 16 << 20       # start the verdicts file again past this size
SKIP_KINDS = ("posture", "operational")


def verdict_lines(batch, verdicts, mode="activity"):
    """One JSON line per verdict, in the shape triagle_rules.xml reads.
    mode: "all", "activity" (leave out benchmark results and health events,
    which are not triage decisions), or "off"."""
    if mode == "off" or not verdicts:
        return []
    raw_by_id = {str(it["raw"].get("id")): it["raw"] for it in batch if isinstance(it.get("raw"), dict)}
    out = []
    for v in verdicts:
        if not isinstance(v, dict) or v.get("verdict") not in ("closed", "escalated"):
            continue
        if mode == "activity" and v.get("kind") in SKIP_KINDS:
            continue
        raw = raw_by_id.get(str(v.get("id")), {})
        rule = raw.get("rule") or {}
        agent = raw.get("agent") or {}
        out.append(json.dumps({"triagle": {
            "verdict": v["verdict"],
            "closure": str(v.get("closure") or ""), "closure_code": str(v.get("closure_code") or ""),
            "severity": str(v.get("severity") or ""), "confidence": str(v.get("confidence") or ""),
            "use_case": str(v.get("use_case") or ""), "use_case_id": str(v.get("use_case_id") or ""),
            "technique": str(v.get("technique") or ""), "reason": str(v.get("reason") or "")[:400],
            "case": str(v.get("case") or ""), "url": str(v.get("url") or ""),
            "agent": str(agent.get("name") or ""), "wazuh_alert_id": str(raw.get("id") or v.get("id") or ""),
            "wazuh_rule_id": str(rule.get("id") or ""), "wazuh_rule_level": str(rule.get("level") or ""),
            "wazuh_rule": str(rule.get("description") or "")[:200],
        }}, separators=(",", ":")))
    return out


def write_verdicts(path, lines):
    """Append lines to the verdicts file. Never fatal: forwarding alerts
    matters more than writing verdicts back."""
    if not path or not lines:
        return 0
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > VERDICTS_MAX_BYTES:
            open(path, "w").close()
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return len(lines)
    except OSError as e:
        log(f"could not write verdicts to {path}: {e}")
        return 0


class Follower:
    """Reads complete new lines from a file that grows and gets rotated."""

    def __init__(self, path, state_path):
        self.path = path
        self.state_path = state_path
        self.inode = None
        self.offset = 0

    def load_state(self):
        try:
            with open(self.state_path) as f:
                st = json.load(f)
            self.inode, self.offset = st.get("inode"), int(st.get("offset", 0))
            return True
        except (OSError, ValueError, TypeError):
            return False

    def save_state(self):
        if not self.state_path:
            return
        tmp = self.state_path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
            with open(tmp, "w") as f:
                json.dump({"inode": self.inode, "offset": self.offset, "path": self.path}, f)
            os.replace(tmp, self.state_path)
        except OSError as e:
            log(f"could not save state to {self.state_path}: {e}")

    def start_at_end(self, replay=0):
        """First run: begin at the end of the file, or `replay` lines before it."""
        try:
            st = os.stat(self.path)
        except OSError:
            self.inode, self.offset = None, 0
            return
        self.inode, self.offset = st.st_ino, st.st_size
        if replay > 0:
            self.offset = self._offset_of_last(replay, st.st_size)

    def _offset_of_last(self, n, size):
        """Byte offset where the last n complete lines begin."""
        chunk, pos, found = 1 << 16, size, 0
        with open(self.path, "rb") as f:
            while pos > 0:
                step = min(chunk, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step)
                i = len(data)
                while True:
                    i = data.rfind(b"\n", 0, i)
                    if i < 0:
                        break
                    if pos + i + 1 < size:           # ignore the newline that ends the file
                        found += 1
                        if found == n:
                            return pos + i + 1
        return 0

    def read(self, max_bytes=4 << 20):
        """Return (complete new lines, offset after them). Does not move the
        saved position: call commit() once they have been delivered."""
        try:
            st = os.stat(self.path)
        except OSError:
            return [], self.offset
        if self.inode is not None and (st.st_ino != self.inode or st.st_size < self.offset):
            log("alerts file was rotated; starting the new one from the top")
            self.offset = 0
        self.inode = st.st_ino
        if st.st_size <= self.offset:
            return [], self.offset
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            data = f.read(max_bytes)
        end = data.rfind(b"\n")
        if end < 0:
            return [], self.offset                 # a line still being written
        lines = data[:end].split(b"\n")
        return lines, self.offset + end + 1

    def commit(self, offset):
        self.offset = offset
        self.save_state()


def run(args):
    f = Follower(args.alerts, args.state)
    if args.from_start:
        f.inode, f.offset = None, 0
    elif not f.load_state():
        f.start_at_end(args.replay)
    log(f"following {args.alerts} from byte {f.offset} -> {args.triagle} as client '{args.client}' "
        f"(level >= {args.min_level})")
    if args.verdicts and args.writeback != "off" and not args.dry_run:
        write_verdicts(args.verdicts, [])
        try:                                         # make sure the file exists for Wazuh to open
            os.makedirs(os.path.dirname(args.verdicts) or ".", exist_ok=True)
            open(args.verdicts, "a").close()
            log(f"writing Triagle's verdicts to {args.verdicts} ({args.writeback})")
        except OSError as e:
            log(f"verdicts will not be written back ({e})")

    sent_total, dropped_total, written_total, last_report, backoff = 0, 0, 0, time.time(), 0
    while True:
        lines, new_offset = f.read()
        items = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except ValueError:
                continue
            if isinstance(alert, dict) and wanted(alert, args.min_level):
                items.append({"source": "wazuh", "client": args.client, "raw": trim(alert)})

        if len(items) > args.max_backlog:
            dropped_total += len(items) - args.max_backlog
            log(f"backlog of {len(items)} is over --max-backlog; keeping the newest {args.max_backlog}")
            items = items[-args.max_backlog:]

        delivered = True
        for i in range(0, len(items), BATCH):
            batch = items[i:i + BATCH]
            if args.dry_run:
                for it in batch:
                    r = it["raw"]["rule"]
                    log(f"[dry-run] level {r.get('level')} {r.get('description')}")
                sent_total += len(batch)
                continue
            ok, text, verdicts = post(args.triagle, args.key, batch)
            if ok:
                sent_total += len(batch)
                backoff = 0
                written_total += write_verdicts(args.verdicts, verdict_lines(batch, verdicts, args.writeback))
            elif ok is None:
                log(f"Triagle refused a batch and retrying will not help ({text}); skipping {len(batch)} alert(s)")
                dropped_total += len(batch)
            else:
                backoff = min(60, max(2, backoff * 2))
                log(f"could not reach Triagle ({text}); retrying in {backoff}s")
                delivered = False
                break

        if delivered:
            if new_offset != f.offset:
                f.commit(new_offset)
        else:
            if args.once:
                log("giving up (--once); nothing was marked as sent")
                return 2
            time.sleep(backoff)
            continue                                 # same position, same lines, try again

        if args.once and not lines:
            log(f"done: {sent_total} forwarded, {dropped_total} dropped")
            return 0
        if time.time() - last_report >= 60:
            log(f"{sent_total} alert(s) forwarded so far, {dropped_total} dropped, "
                f"{written_total} verdict(s) written back")
            last_report = time.time()
        if not lines:
            time.sleep(args.interval)


def main():
    ap = argparse.ArgumentParser(description="Forward Wazuh alerts to Triagle")
    ap.add_argument("--alerts", default=os.environ.get("WAZUH_ALERTS", "/var/ossec/logs/alerts/alerts.json"))
    ap.add_argument("--triagle", default=os.environ.get("TRIAGLE_URL", ""), help="Triagle base URL")
    ap.add_argument("--key", default=os.environ.get("TRIAGLE_INGEST_KEY", ""), help="Triagle's TRIAGLE_INGEST_KEY")
    ap.add_argument("--client", default=os.environ.get("TRIAGLE_CLIENT", "Wazuh"), help="tenant name shown in Triagle")
    ap.add_argument("--min-level", type=int, default=int(os.environ.get("TRIAGLE_MIN_LEVEL", "3")),
                    help="forward alerts at or above this Wazuh rule level (default 3, Wazuh's own alert threshold)")
    ap.add_argument("--state", default=os.environ.get("TRIAGLE_STATE", "/var/lib/triagle-forwarder/position.json"),
                    help="where to remember the position in the alerts file ('' to disable)")
    ap.add_argument("--replay", type=int, default=0, help="on first start, also send the last N alerts in the file")
    ap.add_argument("--from-start", action="store_true", help="ignore saved position and send the whole file")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between checks for new alerts")
    ap.add_argument("--max-backlog", type=int, default=5000)
    ap.add_argument("--verdicts", default=os.environ.get("TRIAGLE_VERDICTS", "/var/lib/triagle-forwarder/verdicts.json"),
                    help="file to append Triagle's verdicts to, for Wazuh to read ('' to disable)")
    ap.add_argument("--writeback", choices=("activity", "all", "off"),
                    default=os.environ.get("TRIAGLE_WRITEBACK", "activity"),
                    help="which verdicts to write back: activity (default; leaves out benchmark results and "
                         "health events), all, or off")
    ap.add_argument("--once", action="store_true", help="send what is there, then exit")
    ap.add_argument("--dry-run", action="store_true", help="print what would be sent; send nothing")
    args = ap.parse_args()
    if not args.dry_run and not (args.triagle and args.key):
        ap.error("--triagle and --key are required (or set TRIAGLE_URL and TRIAGLE_INGEST_KEY)")
    try:
        return run(args)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
