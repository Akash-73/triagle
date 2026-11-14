"""
Triagle — audit log.

Every sign-in and every decision on a response action is written here:
who, when, what, on which alert. The log is append-only and each entry
carries a hash of the entry before it, so an edited or deleted line breaks
the chain and verify() says where.

What that does and does not give you: it detects after-the-fact edits to
the file. It does not stop someone with access to the server from deleting
the whole file or rewriting the entire chain. For that, ship the log off
the box (a SIEM, object storage with retention lock).

File: TRIAGLE_AUDIT_LOG, default data/audit.jsonl. On hosts with an
ephemeral disk (Render's free tier) it is lost on redeploy; mount a disk or
point the variable at persistent storage.
"""
import hashlib
import json
import os
import threading
from datetime import datetime, timezone

_lock = threading.Lock()
GENESIS = "0" * 64


def path():
    base = os.path.dirname(os.path.dirname(__file__))
    return os.environ.get("TRIAGLE_AUDIT_LOG", os.path.join(base, "data", "audit.jsonl"))


def _digest(prev, entry):
    body = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev + body).encode()).hexdigest()


def _last_hash(p):
    last = GENESIS
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line).get("hash", last)
                    except ValueError:
                        pass
    return last


def record(event, user, **fields):
    """Append one entry. Returns it. Never raises into the request path for
    a full disk etc. — but the caller is told via the 'written' flag."""
    entry = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "event": event, "user": user or "-"}
    entry.update({k: v for k, v in fields.items() if v is not None})
    p = path()
    with _lock:
        try:
            os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
            prev = _last_hash(p)
            entry["prev"] = prev
            entry["hash"] = _digest(prev, {k: v for k, v in entry.items() if k != "hash"})
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            entry["written"] = True
        except OSError:
            entry["written"] = False
    return entry


def read(limit=200):
    """Newest first."""
    p = path()
    if not os.path.exists(p):
        return []
    out = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append({"event": "UNREADABLE LINE", "user": "-", "time": ""})
    return out[::-1][:limit]


def verify():
    """Walk the chain. Returns {"ok": bool, "entries": n, "broken_at": line no or None}."""
    p = path()
    if not os.path.exists(p):
        return {"ok": True, "entries": 0, "broken_at": None}
    prev = GENESIS
    n = 0
    with open(p, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            n += 1
            try:
                entry = json.loads(line)
            except ValueError:
                return {"ok": False, "entries": n, "broken_at": i}
            claimed = entry.get("hash")
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("prev") != prev or claimed != _digest(prev, body):
                return {"ok": False, "entries": n, "broken_at": i}
            prev = claimed
    return {"ok": True, "entries": n, "broken_at": None}
