"""
Triagle — a link from an alert back to the tool that raised it.

An analyst reading a verdict here should be one click from the same alert in
their SIEM, with the raw event and everything around it. This builds that
link for a Wazuh dashboard: Discover, filtered to the alert itself and to
whatever Triagle wrote back about it (the verdict, and what people did).

The other direction needs no code: every verdict Triagle writes back to Wazuh
carries data.triagle.url, the address of the alert here.

The address is in the form the dashboard's own "share" links use
(/app/discover#/?_g=...&_a=...), which OpenSearch Dashboards 2.x reads and
carries over to its current Discover.

Settings
  TRIAGLE_WAZUH_URL      address of the Wazuh dashboard, e.g. https://wazuh.example.org
  TRIAGLE_WAZUH_CLIENT   only this customer's alerts are in that Wazuh (optional)
  TRIAGLE_WAZUH_INDEX    id of the alerts index pattern (default wazuh-alerts-*)
"""
import datetime
import os
import re
from urllib.parse import quote

_SAFE_ID = re.compile(r"[\w.:\-]+")
_LOOK_BACK = datetime.timedelta(hours=1)      # show the hour before the alert as well
# What Discover shows for each hit, so the page opens as a readable table and
# not as one block of raw fields: the rule, its level, the machine, and the
# way back to this alert in Triagle.
COLUMNS = ("rule.description", "rule.level", "agent.name", "data.triagle.url")


def base():
    url = os.environ.get("TRIAGLE_WAZUH_URL", "").strip().rstrip("/")
    return url if url.startswith(("https://", "http://")) else ""


def client():
    return os.environ.get("TRIAGLE_WAZUH_CLIENT", "").strip()


def index():
    return os.environ.get("TRIAGLE_WAZUH_INDEX", "").strip() or "wazuh-alerts-*"


def enabled():
    return bool(base())


def _rison(text):
    """A string as the dashboard's address format writes it."""
    return "'" + str(text).replace("!", "!!").replace("'", "!'") + "'"


def _since(timestamp):
    try:
        dt = datetime.datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return "now-30d"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    dt = dt.astimezone(datetime.timezone.utc) - _LOOK_BACK
    return _rison(dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"))


def wazuh_id(alert):
    """The id Wazuh gave the alert, or '' if this is not a Wazuh alert."""
    if alert.get("source") != "wazuh":
        return ""
    aid = str(alert.get("alert_id") or "")
    wid = aid[3:] if aid.startswith("wz-") else ""
    return wid if _SAFE_ID.fullmatch(wid) else ""


def for_alert(alert):
    """Where to open this alert in Wazuh, or None: no dashboard was named,
    the alert did not come from Wazuh, or it belongs to another customer."""
    wid = wazuh_id(alert)
    if not (enabled() and wid):
        return None
    if client() and alert.get("client") != client():
        return None
    query = f'id:"{wid}" or data.triagle.wazuh_alert_id:"{wid}"'
    g = f"(time:(from:{_since(alert.get('timestamp'))},to:now))"
    a = f"(columns:!({','.join(COLUMNS)}),index:{_rison(index())},query:(language:kuery,query:{_rison(query)}))"
    safe = "()!:,'*-._~"
    return {"name": "Wazuh", "url": f"{base()}/app/discover#/?_g={quote(g, safe=safe)}&_a={quote(a, safe=safe)}"}
