"""What people do in Triagle, shown in the SIEM the alert came from.

    python -m pytest -q tests/test_response_writeback.py

Triagle's verdict reaches Wazuh when the alert arrives. What a person does
afterwards (approves a block, lifts it, closes the alert, files a report)
happens later. Triagle queues each of those; the forwarder asks for them every
few seconds and writes them to the file Wazuh reads, so the SIEM shows the
detection, the verdict and the response in one place.

What must hold: the queue is only readable with the ingest key; a customer's
tool gets that customer's events only; nothing is delivered twice or lost when
the write fails or Triagle restarts; and an event read back by Wazuh is never
taken in as an alert.
"""
import importlib.util
import json
import os
import types
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient

from app import auth, main
from tests.test_firewall import ATTACKER, BANK, RULE, Cloud, guesses, block_action
from app.engine import gcp_firewall, genai

ROOT = os.path.dirname(os.path.dirname(__file__))
KEY = "out-key"

spec = importlib.util.spec_from_file_location("wazuh_forwarder_events", os.path.join(ROOT, "scripts", "wazuh_forwarder.py"))
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


@pytest.fixture
def app(tmp_path, monkeypatch):
    for k in ("TRIAGLE_GCP_FIREWALL_PROJECT", "TRIAGLE_GCP_FIREWALL_NETWORK", "TRIAGLE_GCP_FIREWALL_TAGS",
              "TRIAGLE_GCP_FIREWALL_MAX", "TRIAGLE_NEVER_BLOCK", "TRIAGLE_EXECUTE", "K_SERVICE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_STATE_FILE", str(tmp_path / "state.json.gz"))
    monkeypatch.setenv("TRIAGLE_STATE_SECONDS", "0")
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "demo-project")
    monkeypatch.setenv("TRIAGLE_GCP_FIREWALL_CLIENT", BANK)
    monkeypatch.setenv("TRIAGLE_GCP_FIREWALL_HOSTS", "wazuh-demo")
    cloud = Cloud()
    monkeypatch.setattr(gcp_firewall.requests, "request", cloud.request)
    monkeypatch.setattr(gcp_firewall.requests, "post", cloud.post)
    monkeypatch.setattr(gcp_firewall.time, "sleep", lambda s: None)
    monkeypatch.setattr(genai, "_access_token", lambda: "tok")
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s",
                      "TRIAGLE_USERS": "jury:viewer:" + auth.hash_password("look")})
    main._CACHE.clear()
    main._ASK_TIMES.clear()
    main._ASK_ALL.clear()
    c = TestClient(main.app)
    c.post("/login", data={"username": "admin", "password": "pw"})
    assert c.post("/ingest", headers={"X-Triagle-Key": KEY}, json=guesses()).json()["accepted"] == 5
    yield c
    main._CACHE.clear()
    auth.load_config()


def _csrf(page):
    return page.split('name="csrf" value="')[1].split('"')[0]


def _outbox(c, **params):
    r = TestClient(main.app).get("/api/outbox", params={"client": BANK, **params}, headers={"X-Triagle-Key": KEY})
    assert r.status_code == 200
    return r.json()


def _approve(c, act, **extra):
    page = c.get(f"/alert/{act['alert_id']}").text
    return c.post("/action/approve", data={"alert_id": act["alert_id"], "action_id": act["action_id"],
                                           "csrf": _csrf(page), **extra}, follow_redirects=False)


def test_a_real_block_and_its_lifting_are_queued_for_the_siem(app):
    assert _outbox(app)["events"] == []
    act = block_action(main._load_result())
    _approve(app, act, reason="Seen all week")
    box = _outbox(app)
    (e,) = box["events"]
    assert e["event"] == "blocked" and e["by"] == "admin" and e["target"] == ATTACKER and e["rule"] == RULE
    assert e["client"] == BANK and e["agent"] == "wazuh-demo" and e["source"] == "wazuh"
    assert e["use_case"] == "Password guessing from one address" and e["note"] == "Seen all week"
    assert e["source_alert_id"] and act["alert_id"] == "wz-" + e["source_alert_id"]
    assert e["url"].endswith("/alert/" + act["alert_id"]) and "is in force" in e["result"]

    page = app.get(f"/alert/{act['alert_id']}").text
    app.post("/action/lift", data={"alert_id": act["alert_id"], "action_id": act["action_id"], "csrf": _csrf(page)})
    events = _outbox(app, after=box["cursor"], epoch=box["epoch"])["events"]
    assert [x["event"] for x in events] == ["block_lifted"] and events[0]["target"] == ATTACKER


def test_lifting_from_the_connectors_page_is_queued_too(app):
    act = block_action(main._load_result())
    _approve(app, act)
    token = app.get("/connectors").text.split("var CSRF = ")[1].split(",")[0].strip().strip('"')
    assert app.post("/api/firewall/lift", json={"csrf": token, "rule": RULE}).json()["ok"]
    last = _outbox(app)["events"][-1]
    assert last["event"] == "block_lifted" and last["target"] == ATTACKER and last["agent"] == "wazuh-demo"


def test_rehearsals_declines_and_analyst_decisions_are_queued_and_say_what_they_were(app):
    res = main._load_result()
    aid, act = next((aid, a) for aid, acts in res["actions"].items() for a in acts
                    if a["status"] == "pending" and not a["real"] and not a.get("requires_ack"))
    _approve(app, act)
    client = res["verdicts"] and next(a["client"] for a in res["alerts"] if a["alert_id"] == aid)
    ev = _outbox(app, client=client)["events"][-1]
    assert ev["event"] == "approved" and ev["sent"] == "rehearsal, nothing was sent" and ev["action"] == act["label"]

    guess = block_action(main._load_result())
    page = app.get(f"/alert/{guess['alert_id']}").text
    app.post("/action/approve", data={"alert_id": guess["alert_id"], "action_id": guess["action_id"],
                                      "csrf": _csrf(page), "decision": "decline", "reason": "Our own scanner"})
    app.post("/alert/resolve", data={"alert_id": guess["alert_id"], "outcome": "expected",
                                     "note": "Authorised scan", "csrf": _csrf(page)})
    app.post("/alert/resolve", data={"alert_id": guess["alert_id"], "outcome": "reopen", "csrf": _csrf(page)})
    kinds = [(e["event"], e.get("outcome", ""), e.get("note", "")) for e in _outbox(app)["events"]]
    assert kinds == [("declined", "", "Our own scanner"), ("closed_by_analyst", "Expected activity", "Authorised scan"),
                     ("reopened", "", "")]


def test_a_filed_report_is_queued_for_that_customer(app):
    clock = app.get("/clock").text
    form = clock.split('action="/clock/file"')[1].split("</form>")[0]
    fields = {x.split('"')[0]: x.split('value="')[1].split('"')[0]
              for x in form.split('name="')[1:] if 'value="' in x.split(">")[0]}
    fields.update(confirm="on", reference="REF-77")
    assert app.post("/clock/file", data=fields, follow_redirects=False).status_code == 303
    filed = main._CACHE["filings"][0]
    ev = _outbox(app, client=filed["client"])["events"][-1]
    assert ev["event"] == "report_filed" and ev["by"] == "admin" and ev["reference"] == "REF-77"
    assert ev["regulator"] and ev["report"] and ev["url"].endswith("/case/" + filed["incident"])
    assert _outbox(app)["events"] == [], "another customer's tool is not told"


def test_the_queue_needs_the_key_and_a_view_only_account_cannot_read_it(app):
    _approve(app, block_action(main._load_result()))
    fresh = TestClient(main.app)
    assert fresh.get("/api/outbox", params={"client": BANK}).status_code == 401
    assert fresh.get("/api/outbox", params={"client": BANK}, headers={"X-Triagle-Key": "wrong"}).status_code == 401
    fresh.post("/login", data={"username": "jury", "password": "look"})
    assert fresh.get("/api/outbox", params={"client": BANK}).status_code == 401
    assert app.get("/api/outbox", params={"client": BANK}).status_code == 200, "a signed-in analyst may look"


def test_the_cursor_moves_on_and_a_lost_queue_starts_again(app):
    act = block_action(main._load_result())
    _approve(app, act)
    box = _outbox(app)
    assert box["cursor"] == box["events"][-1]["seq"]
    assert _outbox(app, after=box["cursor"], epoch=box["epoch"])["events"] == []
    assert len(_outbox(app, after=box["cursor"], epoch="some-older-queue")["events"]) == 1, "a new queue is read from the top"

    main._CACHE.clear()                                   # a restart: the queue comes back from the saved state
    again = _outbox(app, after=0)
    assert again["epoch"] == box["epoch"] and [e["event"] for e in again["events"]] == ["blocked"]


# ---- the forwarder ----------------------------------------------------------

def _args(tmp_path, **kw):
    base = dict(triagle="http://triagle", key=KEY, client=BANK, verdicts=str(tmp_path / "wz" / "verdicts.json"),
                writeback="activity", dry_run=False, events_every=5.0)
    base.update(kw)
    return types.SimpleNamespace(**base)


def _through_app(app):
    def fetch(url, key, client, after=0, epoch="", timeout=15):
        r = TestClient(main.app).get("/api/outbox", params={"client": client, "after": after, "epoch": epoch},
                                     headers={"X-Triagle-Key": key})
        return r.json() if r.status_code == 200 else None
    return fetch


def test_the_forwarder_writes_each_event_once_in_the_shape_the_rules_read(app, tmp_path, monkeypatch):
    monkeypatch.setattr(fw, "fetch_events", _through_app(app))
    args = _args(tmp_path)
    cursor = fw.Cursor(str(tmp_path / "wz" / "events-position.json"))
    assert fw.collect_events(args, cursor) == 0

    act = block_action(main._load_result())
    _approve(app, act)
    assert fw.collect_events(args, cursor) == 1
    assert fw.collect_events(args, cursor) == 0, "nothing is written twice"
    (line,) = [json.loads(x) for x in open(args.verdicts).read().splitlines()]
    t = line["triagle"]
    assert t["event"] == "blocked" and t["by"] == "admin" and t["target"] == ATTACKER and t["agent"] == "wazuh-demo"
    assert t["wazuh_alert_id"] == act["alert_id"][3:], "the Wazuh alert it is about"
    assert all(isinstance(v, str) and v for v in t.values()), "plain, non-empty strings"
    assert "seq" not in t and "client" not in t and "verdict" not in t

    again = fw.Cursor(str(tmp_path / "wz" / "events-position.json"))        # the forwarder restarts
    assert (again.epoch, again.after) == (cursor.epoch, cursor.after) and fw.collect_events(args, again) == 0


def test_if_the_write_fails_the_event_is_kept_for_next_time(app, tmp_path, monkeypatch):
    monkeypatch.setattr(fw, "fetch_events", _through_app(app))
    _approve(app, block_action(main._load_result()))
    blocked = tmp_path / "not-a-folder"
    blocked.write_text("")
    cursor = fw.Cursor("")
    assert fw.collect_events(_args(tmp_path, verdicts=str(blocked / "verdicts.json")), cursor) == 0
    assert cursor.after == 0
    assert fw.collect_events(_args(tmp_path), cursor) == 1


def test_an_older_triagle_or_no_network_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, "fetch_events", lambda *a, **k: None)
    assert fw.collect_events(_args(tmp_path), fw.Cursor("")) == 0
    assert fw.fetch_events("http://127.0.0.1:9", KEY, BANK, timeout=1) is None        # nothing is listening there
    assert fw.event_lines([{"no": "event"}, "junk", None]) == []


def test_every_event_kind_has_a_wazuh_rule_and_the_fields_it_shows(app):
    tree = ET.parse(os.path.join(ROOT, "scripts", "wazuh", "triagle_rules.xml"))
    by_event = {}
    for r in tree.getroot().findall("rule"):
        for f in r.findall("field"):
            if f.get("name") == "triagle.event" and f.text.startswith("^"):
                by_event[f.text.strip("^$")] = r
    assert set(by_event) == {"blocked", "block_lifted", "approved", "declined", "closed_by_analyst", "reopened",
                             "report_filed"}
    for r in by_event.values():
        assert "triagle_response" in r.findtext("group") and 3 <= int(r.get("level")) <= 8
    assert int(by_event["blocked"].get("level")) == 8 and "triagle_real_change" in by_event["blocked"].findtext("group")


def test_an_event_read_back_by_wazuh_never_becomes_an_alert(app):
    _approve(app, block_action(main._load_result()))
    t = json.loads(fw.event_lines(_outbox(app)["events"])[0])["triagle"]
    echoed = {"timestamp": "2026-11-24T12:00:00.000+0000", "id": "1795522000.77",
              "rule": {"level": 8, "id": "100511", "groups": ["triagle", "triagle_response"],
                       "description": f"Triagle: {t['by']} blocked {t['target']} at the firewall"},
              "agent": {"id": "000", "name": "wazuh-demo"}, "manager": {"name": "wazuh-demo"},
              "decoder": {"name": "json"}, "data": {"triagle": t},
              "location": "/var/lib/triagle-forwarder/verdicts.json"}
    assert not fw.wanted(echoed, 3)
    before = len(main._load_result()["alerts"])
    r = app.post("/ingest", headers={"X-Triagle-Key": KEY}, json=[{"source": "wazuh", "client": BANK, "raw": echoed}])
    assert r.json()["accepted"] == 0 and len(main._load_result()["alerts"]) == before
