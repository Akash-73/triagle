"""
Triagle — what else happened around this alert.

One index per batch, built once. It answers the question an analyst asks
when pivoting on a host, a user or an address: "what else of note happened
here, around the same time?"

Two rules, both learned from running against a real SIEM stream:

  ONLY NOTABLE ALERTS COUNT. One laptop produces hundreds of routine events a
  day: logons, service changes, benchmark results. If every alert on the same
  host counted as corroboration, every alert would corroborate every other
  one and the whole stream would escalate. So a related alert only counts
  when it would make an analyst stop: a risk signal, a suspicious or
  sensitive term, or high severity (signals.is_notable).

  ONLY RECENT ALERTS COUNT. Two alerts on the same server a week apart are
  not one story. The window is TRIAGLE_CORRELATION_HOURS, 24 by default.

Lookups cost the number of notable alerts in the window, not the size of the
batch, so a host with thousands of routine events stays cheap.

One pattern is counted separately, because no single alert in it is notable:
FAILED SIGN-INS FROM ONE ADDRESS. A SIEM raises "brute force" when failures
come fast (Wazuh: 8 in 2 minutes). An attacker who tries one password every
few minutes never trips that, and every attempt is a low-severity event. So
the index keeps, per source address, the failed sign-ins in time order, and
can say "this is the 5th from that address in 24 hours".
"""
import bisect
import os
from datetime import datetime, timezone

from app.engine import signals

# identifiers that appear across unrelated alerts and must not link them
GENERIC_ENTITIES = {"system", "admin", "administrator", "n/a", "unknown", "-",
                    "multiple", "localsystem", "network service", "root"}

ENTITY_FIELDS = ("host", "user", "src_ip", "dst_ip", "entity")
# Sharing an account or an address is strong evidence two alerts belong
# together. Sharing only a host is weak on a busy machine.
STRONG_FIELDS = ("user", "src_ip", "dst_ip")


def window_hours():
    try:
        return max(0.0, float(os.environ.get("TRIAGLE_CORRELATION_HOURS", "24")))
    except ValueError:
        return 24.0


def parse_ts(ts):
    """Epoch seconds, or None if the timestamp cannot be read."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def guessing_threshold():
    """Failed sign-ins from one address, inside the window, before it is
    raised as password guessing (TRIAGLE_GUESSING_THRESHOLD, 5 by default)."""
    try:
        return max(2, int(os.environ.get("TRIAGLE_GUESSING_THRESHOLD", "5")))
    except ValueError:
        return 5


def sign_in(alert):
    """failed | success | None, as the source tool classified it."""
    return (alert.get("indicators") or {}).get("auth")


def entity_values(alert, fields=ENTITY_FIELDS):
    """Lower-cased host / user / addresses of an alert dict, minus generic ones."""
    vals = set()
    for k in fields:
        v = alert.get(k)
        if v and str(v).strip().lower() not in GENERIC_ENTITIES:
            vals.add(str(v).lower())
    return vals


class EntityIndex:
    """Per (client, entity): notable alerts in time order, and how many
    routine ones there were."""

    def __init__(self, alerts, hours=None):
        self.alerts = alerts
        self.hours = window_hours() if hours is None else hours
        self.window = self.hours * 3600
        self.pos = {}
        self.times = []
        self.notable = []
        self._n_times = {}      # key -> sorted [t] of notable alerts
        self._n_idx = {}        # key -> [idx] in the same order
        self._n_untimed = {}    # key -> [idx] of notable alerts with no usable time
        self._r_times = {}      # key -> sorted [t] of routine alerts
        self._r_untimed = {}    # key -> count
        self._f_times = {}      # (client, source address) -> sorted [t] of failed sign-ins
        self._f_rank = {}       # alert index -> its position in that list

        rows = []
        for i, a in enumerate(alerts):
            self.pos[a.get("alert_id")] = i
            t = parse_ts(a.get("timestamp"))
            n = signals.is_notable(a)
            self.times.append(t)
            self.notable.append(n)
            rows.append((t if t is not None else 0.0, i, t is None, n))
        rows.sort()
        for t, i, untimed, n in rows:
            client = alerts[i].get("client")
            src = alerts[i].get("src_ip")
            if src and not untimed and sign_in(alerts[i]) == "failed":
                seen = self._f_times.setdefault((client, str(src).lower()), [])
                self._f_rank[i] = len(seen)
                seen.append(t)
            for e in entity_values(alerts[i]):
                key = (client, e)
                if n and untimed:
                    self._n_untimed.setdefault(key, []).append(i)
                elif n:
                    self._n_times.setdefault(key, []).append(t)
                    self._n_idx.setdefault(key, []).append(i)
                elif untimed:
                    self._r_untimed[key] = self._r_untimed.get(key, 0) + 1
                else:
                    self._r_times.setdefault(key, []).append(t)

    def _span(self, times, t):
        if t is None or not self.window:
            return 0, len(times)
        return bisect.bisect_left(times, t - self.window), bisect.bisect_right(times, t + self.window)

    def failed_signins(self, alert):
        """Failed sign-ins from this alert's source address, inside the window
        and up to this alert (itself included when it is one). 0 if the alert
        has no source address or no usable time."""
        src = alert.get("src_ip")
        me = self.pos.get(alert.get("alert_id"), -1)
        t = self.times[me] if me >= 0 else parse_ts(alert.get("timestamp"))
        if not src or t is None:
            return 0
        times = self._f_times.get((alert.get("client"), str(src).lower()))
        if not times:
            return 0
        start = bisect.bisect_left(times, t - self.window) if self.window else 0
        rank = self._f_rank.get(me)
        end = rank + 1 if rank is not None else bisect.bisect_right(times, t)
        return max(0, end - start)

    def strong_count(self, alert):
        """How many notable alerts in the window share an account or an
        address with this one (not merely the host)."""
        me = self.pos.get(alert.get("alert_id"), -1)
        t = self.times[me] if me >= 0 else parse_ts(alert.get("timestamp"))
        client = alert.get("client")
        found = set()
        for e in entity_values(alert, STRONG_FIELDS):
            key = (client, e)
            times = self._n_times.get(key)
            if times:
                lo, hi = self._span(times, t)
                found.update(self._n_idx[key][lo:hi])
            found.update(self._n_untimed.get(key, ()))
        found.discard(me)
        return len(found)

    def related(self, alert):
        """(notable alerts sharing an entity inside the window, in time order;
        count of routine events on the same entities inside the window)."""
        me = self.pos.get(alert.get("alert_id"), -1)
        t = self.times[me] if me >= 0 else parse_ts(alert.get("timestamp"))
        client = alert.get("client")
        found = set()
        routine = 0
        for e in entity_values(alert):
            key = (client, e)
            times = self._n_times.get(key)
            if times:
                lo, hi = self._span(times, t)
                found.update(self._n_idx[key][lo:hi])
            found.update(self._n_untimed.get(key, ()))
            rt = self._r_times.get(key)
            here = self._r_untimed.get(key, 0)
            if rt:
                lo, hi = self._span(rt, t)
                here += hi - lo
            routine = max(routine, here)       # the busiest shared entity, not a double count
        found.discard(me)
        if me >= 0 and not self.notable[me] and routine:
            routine -= 1                        # do not count the alert itself
        ordered = sorted(found, key=lambda i: (self.times[i] is None, self.times[i] or 0.0, i))
        return [self.alerts[i] for i in ordered], max(routine, 0)
