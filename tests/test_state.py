"""Saved state: a restart does not empty the console.

    python -m pytest -q tests/test_state.py

With TRIAGLE_STATE_FILE set, the live queue, what people decided and the
reports they marked as filed are written to a file and read back at start.
A "restart" here is the same thing the process does: memory is cleared and
the next request builds the state again.
"""
import gzip
import json
import os

import pytest
from fastapi.testclient import TestClient

from app import auth, main, store
from app.connectors import examples

KEY = "state-key"
BANK = "Greenvale Co-operative Bank"
ENCODED = examples.EXAMPLES["wazuh"][0]["raw"]
PROBE = examples.EXAMPLES["wazuh"][1]["raw"]
DISCOVERY = examples.EXAMPLES["wazuh"][2]["raw"]


def _items(*raws):
    return [{"source": "wazuh", "client": BANK, "raw": r} for r in raws]


def _restart():
    main._CACHE.clear()


def _client():
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    return c


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    monkeypatch.setenv("TRIAGLE_STATE_FILE", str(tmp_path / "data" / "state.json.gz"))
    monkeypatch.setenv("TRIAGLE_STATE_SECONDS", "0")
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s"})
    _restart()
    yield _client()
    _restart()
    auth.load_config()


def _ingest(c, *raws):
    return c.post("/ingest", headers={"X-Triagle-Key": KEY}, json=_items(*raws)).json()


def _csrf(page):
    return page.split('name="csrf" value="')[1].split('"')[0]


def test_the_queue_survives_a_restart(site):
    assert _ingest(site, ENCODED, PROBE, DISCOVERY)["accepted"] == 3
    before = main._load_result()
    ids = {a["alert_id"] for a in before["alerts"]}
    received = before["metrics"]["received"]
    assert os.path.exists(store.path())

    _restart()
    after = main._load_result()
    assert {a["alert_id"] for a in after["alerts"]} == ids
    assert after["metrics"]["received"] == received and after["metrics"]["live_alerts"] == 3
    assert main._CACHE["restored"]["alerts"] == 3
    assert _ingest(site, ENCODED, PROBE)["accepted"] == 0, "a tool replaying its feed is not counted twice"
    page = site.get("/connectors").text
    assert "a restart does not empty this console" in page and "3 alerts were restored" in page
    assert "Sending" in page, "the source still shows as connected"


def test_a_decision_and_a_filed_report_survive_a_restart(site):
    res = main._load_result()
    aid, act = next((aid, a) for aid, acts in res["actions"].items() for a in acts
                    if a["status"] == "pending" and not a.get("requires_ack"))
    page = site.get(f"/alert/{aid}").text
    site.post("/action/approve", data={"alert_id": aid, "action_id": act["action_id"], "csrf": _csrf(page),
                                       "decision": "decline", "reason": "known scanner"}, follow_redirects=False)
    clock = site.get("/clock").text
    assert 'action="/clock/file"' in clock
    form = clock.split('action="/clock/file"')[1].split("</form>")[0]
    fields = {k: v for k, v in (pair.split('" value="') for pair in
                                [x.split('"')[0] + '" value="' + x.split('value="')[1].split('"')[0]
                                 for x in form.split('name="')[1:] if 'value="' in x.split(">")[0]])}
    fields.update(confirm="on", reference="CERT-IN-REF-1")
    assert site.post("/clock/file", data=fields, follow_redirects=False).status_code == 303
    assert len(main._CACHE["filings"]) == 1

    _restart()
    after = main._load_result()
    kept = next(a for a in after["actions"][aid] if a["action_id"] == act["action_id"])
    assert kept["status"] == "declined" and "known scanner" in kept["result_message"]
    assert main._CACHE["filings"][0]["reference"] == "CERT-IN-REF-1"
    assert "CERT-IN-REF-1" in site.get("/clock").text


def test_clearing_the_test_alerts_is_saved_and_leaves_a_real_feed_alone(site):
    _ingest(site, ENCODED, DISCOVERY)                      # a connected tool's alerts
    token = _csrf(site.get("/").text)
    site.post("/demo/fire", data={"csrf": token, "benign": "on"}, follow_redirects=False)
    from app import demo_attack

    def test_alerts(result):
        return [a for a in result["alerts"] if a["client"] in demo_attack.CLIENTS]
    assert len(test_alerts(main._load_result())) == 6
    assert site.post("/demo/reset", data={"csrf": token}, follow_redirects=False).status_code == 303
    _restart()
    after = main._load_result()
    assert test_alerts(after) == [], "the test alerts are gone"
    assert sum(1 for a in after["alerts"] if a["client"] == BANK) == 2, "the tool's alerts are not"
    assert _ingest(site, ENCODED)["accepted"] == 0


def test_alert_saves_are_spaced_out_but_a_decision_is_saved_at_once(site, monkeypatch):
    monkeypatch.setenv("TRIAGLE_STATE_SECONDS", "3600")
    writes = []
    real = store.save
    monkeypatch.setattr(store, "save", lambda state: writes.append(len(state["live"])) or real(state))
    _ingest(site, ENCODED)
    _ingest(site, PROBE)
    _ingest(site, DISCOVERY)
    assert writes == [1], "the first save happens, the next two wait"
    assert main._CACHE["dirty"] is True
    assert main._flush(force=True) and writes == [1, 3] and main._CACHE["dirty"] is False
    res = main._load_result()
    aid, act = next((aid, a) for aid, acts in res["actions"].items() for a in acts if a["status"] == "pending")
    page = site.get(f"/alert/{aid}").text
    site.post("/action/approve", data={"alert_id": aid, "action_id": act["action_id"], "csrf": _csrf(page),
                                       "decision": "decline"}, follow_redirects=False)
    assert len(writes) == 3, "a person's decision does not wait"


def test_a_file_that_cannot_be_read_is_left_alone_and_the_console_starts(site):
    os.makedirs(os.path.dirname(store.path()), exist_ok=True)
    with open(store.path(), "wb") as f:
        f.write(b"\x1f\x8b not really gzip")
    _restart()
    assert site.get("/").status_code == 200 and main._load_result()["metrics"]["live_alerts"] == 0
    with open(store.path(), "wb") as f:
        f.write(gzip.compress(json.dumps({"version": 99, "live": _items(ENCODED)}).encode()))
    _restart()
    assert main._load_result()["metrics"]["live_alerts"] == 0, "a file from another version is ignored"


def test_an_alert_the_connector_can_no_longer_read_is_dropped_on_restore(site):
    _ingest(site, ENCODED)
    main._flush(force=True)
    with open(store.path(), "rb") as f:
        state = json.loads(gzip.decompress(f.read()))
    state["live"].append({"source": "wazuh", "client": BANK, "raw": {"nonsense": True}})
    state["live"].append({"source": "no-such-tool", "client": BANK, "raw": {"title": "x"}})
    with open(store.path(), "wb") as f:
        f.write(gzip.compress(json.dumps(state).encode()))
    _restart()
    assert main._load_result()["metrics"]["live_alerts"] == 1


def test_nothing_is_written_unless_asked(site, monkeypatch, tmp_path):
    monkeypatch.delenv("TRIAGLE_STATE_FILE")
    _restart()
    _ingest(site, ENCODED)
    assert not (tmp_path / "data").exists() and store.status()["enabled"] is False
    assert "held in memory" in site.get("/connectors").text


def test_a_disk_that_refuses_the_write_does_not_stop_the_console(site, monkeypatch, tmp_path):
    blocked = tmp_path / "file-not-folder"
    blocked.write_text("")
    monkeypatch.setenv("TRIAGLE_STATE_FILE", str(blocked / "state.json"))
    _restart()
    assert _ingest(site, ENCODED)["accepted"] == 1
    assert store.status()["error"] and "not being saved" in site.get("/connectors").text


def test_plain_json_works_as_well_as_compressed(site, monkeypatch, tmp_path):
    monkeypatch.setenv("TRIAGLE_STATE_FILE", str(tmp_path / "state.json"))
    _restart()
    _ingest(site, ENCODED)
    main._flush(force=True)
    assert json.loads((tmp_path / "state.json").read_text())["version"] == store.VERSION
    _restart()
    assert main._load_result()["metrics"]["live_alerts"] == 1
