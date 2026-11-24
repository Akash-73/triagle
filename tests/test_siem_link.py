"""From an alert here to the same alert in Wazuh, in one click.

    python -m pytest -q tests/test_siem_link.py

With TRIAGLE_WAZUH_URL set, a Wazuh alert's page links to the Wazuh
dashboard: Discover, filtered to that alert and to what Triagle wrote back
about it. The way back is data.triagle.url on every verdict in Wazuh.
"""
from html import unescape
from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient

from app import auth, demo_attack, main
from app.connectors import examples
from app.engine import siem_link

KEY = "link-key"
BANK = "Greenvale Co-operative Bank"
RAW = examples.EXAMPLES["wazuh"][0]["raw"]
WAZUH = "https://wazuh.example.org"


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    monkeypatch.setenv("TRIAGLE_GUEST", "view")
    monkeypatch.setenv("TRIAGLE_WAZUH_URL", WAZUH + "/")
    monkeypatch.delenv("TRIAGLE_WAZUH_CLIENT", raising=False)
    monkeypatch.delenv("TRIAGLE_WAZUH_INDEX", raising=False)
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s"})
    main._CACHE.clear()
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    assert c.post("/ingest", headers={"X-Triagle-Key": KEY},
                  json=[{"source": "wazuh", "client": BANK, "raw": RAW}]).json()["accepted"] == 1
    yield c
    main._CACHE.clear()
    auth.load_config()


def _alert_id():
    return next(a["alert_id"] for a in main._load_result()["alerts"] if a["client"] == BANK and a["source"] == "wazuh"
                and a["alert_id"] in {m[0] for m in main._CACHE["live_meta"]})


def test_a_wazuh_alert_links_to_itself_in_wazuh(site):
    aid = _alert_id()
    page = site.get(f"/alert/{aid}").text
    assert page.count("Open in Wazuh") == 2, "at the top, and beside the tool's evidence"
    href = unescape(page.split('class="btn small" href="')[1].split('"')[0])
    assert href.startswith(WAZUH + "/app/discover#/?_g=(time:(from:'") and "//app" not in href
    plain = unquote(href)
    wid = str(RAW["id"])
    assert f"""query:'id:"{wid}" or data.triagle.wazuh_alert_id:"{wid}"'""" in plain
    assert "index:'wazuh-alerts-*'" in plain and "language:kuery" in plain and plain.endswith("))")
    assert "_a=(columns:!(rule.description,rule.level,agent.name,data.triagle.url)," in plain, "a table, not raw fields"
    assert 'target="_blank" rel="noopener noreferrer"' in page


def test_the_search_starts_an_hour_before_the_alert_and_runs_to_now(site):
    link = siem_link.for_alert({"source": "wazuh", "alert_id": "wz-1732456789.123456", "client": BANK,
                                "timestamp": "2026-11-24T14:22:07.000+0000"})
    assert "time:(from:'2026-11-24T13:22:07.000Z',to:now)" in unquote(link["url"])
    undated = siem_link.for_alert({"source": "wazuh", "alert_id": "wz-1.2", "client": BANK, "timestamp": "soon"})
    assert "time:(from:now-30d,to:now)" in unquote(undated["url"])


def test_a_guest_is_not_shown_where_the_siem_is(site):
    guest = TestClient(main.app)
    page = guest.get(f"/alert/{_alert_id()}")
    assert page.status_code == 200 and "Open in Wazuh" not in page.text and "wazuh.example.org" not in page.text


def test_only_alerts_that_came_from_that_wazuh_get_the_link(site, monkeypatch):
    # an alert from another tool
    main._add_alerts(demo_attack.fresh_attack())
    other = next(a["alert_id"] for a in main._load_result()["alerts"] if a["client"] in demo_attack.CLIENTS)
    assert "Open in Wazuh" not in site.get(f"/alert/{other}").text
    # a sample alert that ships with the product was never in this Wazuh
    arrived = {m[0] for m in main._CACHE["live_meta"]}
    sample = next(a["alert_id"] for a in main._load_result()["alerts"] if a["alert_id"] not in arrived)
    assert "Open in Wazuh" not in site.get(f"/alert/{sample}").text
    # the Wazuh belongs to one customer, and this alert is another's
    monkeypatch.setenv("TRIAGLE_WAZUH_CLIENT", "Someone Else Ltd")
    assert "Open in Wazuh" not in site.get(f"/alert/{_alert_id()}").text
    monkeypatch.setenv("TRIAGLE_WAZUH_CLIENT", BANK)
    assert "Open in Wazuh" in site.get(f"/alert/{_alert_id()}").text


def test_no_link_unless_the_dashboard_is_named(site, monkeypatch):
    monkeypatch.delenv("TRIAGLE_WAZUH_URL")
    assert "Open in Wazuh" not in site.get(f"/alert/{_alert_id()}").text
    monkeypatch.setenv("TRIAGLE_WAZUH_URL", "wazuh.example.org")          # not an address
    assert siem_link.enabled() is False


def test_an_id_that_could_break_the_query_gets_no_link():
    import os
    os.environ["TRIAGLE_WAZUH_URL"] = WAZUH
    try:
        for bad in ('wz-1" or *:*', "wz-1'2", "wz-", "1732.1"):
            assert siem_link.for_alert({"source": "wazuh", "alert_id": bad, "client": BANK}) is None, bad
    finally:
        del os.environ["TRIAGLE_WAZUH_URL"]
