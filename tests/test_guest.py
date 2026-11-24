"""Guest view: anyone with the address can look, nobody without a sign-in can change.

    python -m pytest -q tests/test_guest.py

TRIAGLE_GUEST=view opens the console to a visitor (a jury member, a buyer on
a call) without a sign-in wall. A guest reads pages, tries an alert and asks
about a case. Every route that changes something still needs a signed-in
analyst, and the ingest key and the audit log stay hidden.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app import auth, main
from app.connectors import examples

KEY = "guest-key"


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    monkeypatch.setenv("TRIAGLE_GUEST", "view")
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s"})
    main._CACHE.clear()
    main._ASK_TIMES.clear()
    main._ASK_ALL.clear()
    yield TestClient(main.app)
    main._CACHE.clear()
    auth.load_config()


def test_a_guest_can_look_around(site):
    for path in ("/", "/alerts?show=all", "/cases", "/clock", "/connectors", "/tuning", "/benchmark"):
        r = site.get(path)
        assert r.status_code == 200, path
        assert "Viewing as a guest" in r.text and 'href="/login"' in r.text
    aid = main._load_result()["alerts"][0]["alert_id"]
    assert site.get(f"/alert/{aid}").status_code == 200


def test_a_guest_is_told_what_this_is_and_an_analyst_is_not(site):
    intro = "Triagle works the alert queue of a security operations team."
    assert intro in site.get("/").text
    analyst = TestClient(main.app)
    analyst.post("/login", data={"username": "admin", "password": "pw"})
    assert intro not in analyst.get("/").text


def test_a_guest_can_try_an_alert(site):
    page = site.get("/connectors").text
    token = page.split("var CSRF = ")[1].split(",")[0].strip().strip('"')
    raw = examples.EXAMPLES["wazuh"][0]["raw"]
    r = site.post("/api/try", json={"source": "wazuh", "raw": json.dumps(raw), "csrf": token})
    assert r.status_code == 200 and r.json()["verdict"]["escalate"] is True


def test_a_guest_can_change_nothing_and_sees_no_secrets(site):
    res = main._load_result()
    aid, act = next((aid, a) for aid, acts in res["actions"].items() for a in acts if a["status"] == "pending")
    page = site.get(f"/alert/{aid}").text
    assert "Approve and run" not in page and "Waiting for approval" in page
    token = page.split('name="csrf" value="')[1].split('"')[0] if 'name="csrf"' in page else "x"
    form = {"alert_id": aid, "action_id": act["action_id"], "csrf": token}
    assert site.post("/action/approve", data=form).status_code == 403
    assert site.post("/action/lift", data=form).status_code == 403
    assert site.post("/demo/fire", data={"csrf": token, "scenario": "bank"}).status_code == 403
    assert site.post("/demo/reset", data={"csrf": token}).status_code == 403
    assert site.post("/api/model/test", json={"csrf": token}).status_code == 403
    assert site.post("/api/firewall/check", json={"csrf": token}).status_code == 403
    assert site.get("/audit").status_code == 403
    assert set(site.get("/healthz").json()) == {"ok", "version"}, "no deployment details for a guest"
    assert KEY not in site.get("/connectors").text
    assert next(a for a in main._load_result()["actions"][aid] if a["action_id"] == act["action_id"])["status"] == "pending"


def test_signing_in_from_guest_view_gives_an_analyst(site):
    assert site.get("/login").status_code == 200, "a guest is shown the sign-in page, not bounced away from it"
    assert site.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    page = site.get("/").text
    assert "Viewing as a guest" not in page and "Sign out" in page
    assert site.get("/audit").status_code == 200


def test_without_the_setting_a_visitor_is_sent_to_sign_in(site, monkeypatch):
    monkeypatch.delenv("TRIAGLE_GUEST")
    r = site.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_guest_view_does_nothing_when_sign_in_is_off(site):
    auth.load_config({"TRIAGLE_AUTH": "off"})
    assert main.guest_view() is False
    assert "Viewing as a guest" not in site.get("/").text
