"""Live ingest, the demo-fire button, and the webhook key.  python -m pytest -q"""
import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main, demo_attack

KEY = "demo-key-xyz"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_INGEST_KEY", KEY)
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s",
                      "TRIAGLE_USERS": "viewerbob:viewer:" + auth.hash_password("look")})
    main._CACHE.clear()
    yield
    main._CACHE.clear()


def anon():
    return TestClient(main.app)


def analyst():
    c = anon()
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    return c


def csrf(c, path="/"):
    import re
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get(path).text).group(1)


# ---- the webhook -------------------------------------------------------------

def test_siem_webhook_key_accepts_an_alert():
    base = len(main._load_result()["alerts"])
    r = anon().post("/ingest", headers={"X-Triagle-Key": KEY}, json=demo_attack.fresh_attack())
    assert r.status_code == 200 and r.json()["accepted"] == 5
    assert len(main._load_result()["alerts"]) == base + 5

def test_ingest_without_a_key_or_session_is_rejected():
    r = anon().post("/ingest", json={"source": "crowdstrike_edr", "client": "X", "raw": {"name": "y"}})
    assert r.status_code == 401
    r = anon().post("/ingest", headers={"X-Triagle-Key": "wrong"}, json={"source": "x", "raw": {}})
    assert r.status_code == 401

def test_a_single_object_or_a_list_both_work():
    one = {"source": "crowdstrike_edr", "client": "Acme", "raw":
           {"detection_id": "z1", "created_timestamp": "2026-11-19T10:00:00Z", "name": "Routine", "severity": "low"}}
    r = anon().post("/ingest", headers={"X-Triagle-Key": KEY}, json=one)
    assert r.status_code == 200 and r.json()["accepted"] == 1

def test_junk_items_are_dropped_not_crashed():
    r = anon().post("/ingest", headers={"X-Triagle-Key": KEY},
                    json=[{"nonsense": 1}, {"source": "crowdstrike_edr", "raw": {"name": "ok", "severity": "low",
                          "detection_id": "q", "created_timestamp": "2026-11-19T10:00:00Z"}}])
    assert r.status_code == 200 and r.json()["accepted"] == 1

def test_oversized_batch_is_refused():
    big = [{"source": "crowdstrike_edr", "raw": {"name": "x"}}] * 51
    assert anon().post("/ingest", headers={"X-Triagle-Key": KEY}, json=big).status_code == 413

def test_bad_json_is_a_400():
    r = anon().post("/ingest", headers={"X-Triagle-Key": KEY, "Content-Type": "application/json"}, content=b"{not json")
    assert r.status_code == 400

def test_ingest_is_recorded_in_the_audit_log():
    anon().post("/ingest", headers={"X-Triagle-Key": KEY}, json=demo_attack.fresh_attack())
    assert any(e["event"] == "alerts ingested" and e["user"] == "siem-webhook" for e in audit.read())

def test_an_ingested_attack_becomes_an_escalated_incident():
    anon().post("/ingest", headers={"X-Triagle-Key": KEY}, json=demo_attack.fresh_attack())
    res = main._load_result()
    inc = next(i for i in res["incidents"] if i["client"] == demo_attack.DEFAULT_CLIENT)
    assert inc["size"] == 5 and inc["elevated"]
    assert any(res["verdicts"][a]["escalate"] for a in inc["alert_ids"])
    # the C2 beacon pulls a threat-intel match in its trail
    c2 = next(a for a in inc["alert_ids"] if res["verdicts"][a]["severity"] == "critical")
    assert res["verdicts"][c2]["disposition"] == "true_positive"


# ---- the demo-fire button ----------------------------------------------------

def test_analyst_can_fire_a_demo_attack():
    c = analyst()
    base = len(main._load_result()["alerts"])
    r = c.post("/demo/fire", data={"csrf": csrf(c), "benign": "on"}, follow_redirects=False)
    assert r.status_code == 303 and demo_attack.HOST in r.headers["location"]
    assert len(main._load_result()["alerts"]) == base + 6          # 5 attack + 1 benign
    assert any(e["event"] == "demo attack fired" for e in audit.read())

def test_fire_needs_the_form_token():
    c = analyst()
    assert c.post("/demo/fire", data={"csrf": "bad"}).status_code == 403

def test_viewer_cannot_fire():
    c = anon(); c.post("/login", data={"username": "viewerbob", "password": "look"})
    assert c.post("/demo/fire", data={"csrf": csrf(c)}).status_code == 403

def test_reset_clears_live_alerts():
    c = analyst()
    c.post("/demo/fire", data={"csrf": csrf(c)})
    seeded = len(main._seed_raw())
    r = c.post("/demo/reset", data={"csrf": csrf(c)}, follow_redirects=False)
    assert r.status_code == 303
    assert len(main._load_result()["alerts"]) == seeded
    assert main._CACHE["live_count"] == 0

def test_fired_attack_closes_the_benign_alert_live():
    c = analyst()
    c.post("/demo/fire", data={"csrf": csrf(c), "benign": "on"})
    res = main._load_result()
    benign = [a for a in res["alerts"] if a.get("client") == demo_attack.DEFAULT_CLIENT
              and "Tachyon" in (a.get("title") or "")]
    assert benign and not res["verdicts"][benign[0]["alert_id"]]["escalate"]


# ---- the demo controls only show in demo mode --------------------------------

def test_fire_button_shows_only_in_demo_mode(monkeypatch):
    c = analyst()
    assert "Run a scenario" in c.get("/").text
    monkeypatch.setenv("TRIAGLE_DEMO", "false")
    assert "Run a scenario" not in c.get("/").text
