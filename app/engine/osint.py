"""
Triagle — open-source intelligence on addresses.

An analyst who sees a stranger's address on an alert checks it against the
public blocklists before deciding. This module does that check, and does it
without sending the address anywhere.

How: once every few hours Triagle downloads IPsum, a public feed that is
rebuilt daily from 30+ public blocklists of attacking addresses and says, for
each address, how many of those lists it is on (github.com/stamparm/ipsum,
public domain). The list is held in memory and every lookup is made here.
No indicator from a customer's alert leaves this deployment to be checked.

What it is used for: evidence on the alert and case pages, and context for
Gemini when it writes an account. What it is NOT used for: the verdict. The
engine's verdict comes from the alert and its neighbours, the same way every
time. A feed that changes daily does not move it, and a feed that is down
cannot break triage.

Settings
  TRIAGLE_OSINT         on | off. Unset: on when running on Cloud Run, off elsewhere,
                        so a laptop, a test run or an air-gapped install makes no call.
  TRIAGLE_OSINT_URL     where the list is fetched from (default: IPsum on GitHub).
  TRIAGLE_OSINT_HOURS   how often to fetch it again (default 6).

Nothing here raises. If the list cannot be fetched, lookups answer "not
checked" and the page says so.
"""
import ipaddress
import os
import threading
import time

import requests

DEFAULT_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
NAME = "IPsum"
ABOUT = "a public feed rebuilt daily from 30+ blocklists of attacking addresses"
MAX_BYTES = 30_000_000              # the list is about 2 MB; anything far bigger is not the list
RETRY_SECONDS = 600                 # after a failed fetch, wait this long before trying again
FETCH_TIMEOUT = 8

_state = {"lists": {}, "updated": "", "fetched_at": 0.0, "tried_at": 0.0, "error": None}
_lock = threading.Lock()


def enabled():
    flag = os.environ.get("TRIAGLE_OSINT", "").strip().lower()
    if flag in ("on", "true", "1"):
        return True
    if flag in ("off", "false", "0"):
        return False
    return bool(os.environ.get("K_SERVICE"))


def _hours():
    try:
        return max(1.0, float(os.environ.get("TRIAGLE_OSINT_HOURS", "6")))
    except ValueError:
        return 6.0


def parse(text):
    """({address: number of lists}, the feed's own 'Last update' line)."""
    lists, updated = {}, ""
    for line in text.splitlines():
        if line.startswith("#"):
            if "last update:" in line.lower():
                updated = line.split(":", 1)[1].strip()
            continue
        parts = line.split()
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        lists[parts[0]] = int(parts[1])
    return lists, updated


def _fetch():
    url = os.environ.get("TRIAGLE_OSINT_URL", "").strip() or DEFAULT_URL
    if not url.startswith("https://"):
        raise ValueError("the list must be fetched over https")
    r = requests.get(url, timeout=FETCH_TIMEOUT, headers={"User-Agent": "Triagle"})
    r.raise_for_status()
    if len(r.content) > MAX_BYTES:
        raise ValueError("the reply is too large to be the list")
    lists, updated = parse(r.text)
    if len(lists) < 1000:                       # an empty or cut-off reply must not replace a good list
        raise ValueError(f"the reply held only {len(lists)} addresses")
    return lists, updated


def ensure(now=None):
    """Make sure a recent list is in memory. Fetches at most once at a time;
    a request that arrives while another is fetching uses what is there."""
    if not enabled():
        return False
    now = time.time() if now is None else now
    fresh = _state["lists"] and now - _state["fetched_at"] < _hours() * 3600
    if fresh or now - _state["tried_at"] < RETRY_SECONDS:
        return bool(_state["lists"])
    if not _lock.acquire(blocking=False):
        return bool(_state["lists"])
    try:
        _state["tried_at"] = now
        lists, updated = _fetch()
        _state.update(lists=lists, updated=updated, fetched_at=now, error=None)
    except Exception as e:                      # a feed must never take the console down
        _state["error"] = f"{type(e).__name__}: {e}"[:200]
    finally:
        _lock.release()
    return bool(_state["lists"])


def _public(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def lookup(value):
    """What the public blocklists say about one address, or None if it is not a
    public address or no list is loaded. {"address", "lists", "words"}."""
    ip = _public(value)
    if not ip or not ensure():
        return None
    n = _state["lists"].get(ip, 0)
    if n >= 3:
        words = f"On {n} public blocklists. Reported as an attacker by several independent sources."
    elif n:
        words = f"On {n} public blocklist{'s' if n > 1 else ''}. Reported, but thin on its own."
    else:
        words = "On none of the public blocklists. That clears nothing: a new attacker is on none."
    return {"address": ip, "lists": n, "words": words}


def lines(addresses):
    """One plain line for each public address, for a prompt. Empty if nothing was checked."""
    out, seen = [], set()
    for a in addresses:
        hit = lookup(a)
        if hit and hit["address"] not in seen:
            seen.add(hit["address"])
            out.append(f"- {hit['address']}: on {hit['lists']} of the public blocklists that {NAME} reads")
    return "\n".join(out)


def status():
    return {"enabled": enabled(), "source": NAME, "addresses": len(_state["lists"]),
            "updated": _state["updated"] or None, "fetched_at": _state["fetched_at"] or None,
            "error": _state["error"]}
