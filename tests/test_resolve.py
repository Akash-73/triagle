"""An analyst closes an alert Triagle sent to a person.

    python -m pytest -q tests/test_resolve.py

"Needs a decision" has to go down when someone decides. The analyst picks
what it was (real and dealt with, expected activity, a false positive), the
alert leaves the open list, and the answer is recorded with their name next
to Triagle's own verdict, which is kept as it was.
"""
import datetime as dt

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main
from tests.test_bursts import update, T0

KEY = "rk"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_STATE_FILE", str(tmp_path / "state.json.gz"))
    monkeypatch.setenv("TRIAGLE_STATE_SECONDS", "0")
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s",
                      "TRIAGLE_USERS": "jury:viewer:" + auth.hash_password("look")})
    main._CACHE.clear()
    c = TestClient(main.app)
    c.post("/login", data={"username": "admin", "password": "pw"})
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    start = int((now - dt.timedelta(minutes=30) - T0.replace(tzinfo=dt.timezone.utc)).total_seconds())
    assert c.post("/ingest", headers={"X-Triagle-Key": KEY}, json=update(start=start)).json()["accepted"] == 24
    yield c
    main._CACHE.clear()
    auth.load_config()


def _burst():
    res = main._load_result()
    return next(a["alert_id"] for a in res["alerts"] if res["verdicts"][a["alert_id"]].get("burst"))


def _csrf(page):
    return page.split('name="csrf" value="')[1].split('"')[0]


def _resolve(c, aid, outcome, note="", token=None):
    token = token or _csrf(c.get(f"/alert/{aid}").text)
    return c.post("/alert/resolve", data={"alert_id": aid, "outcome": outcome, "note": note, "csrf": token},
                  follow_redirects=False)


def test_closing_an_alert_takes_it_off_the_open_list_and_records_who_and_why(app):
    aid = _burst()
    before = main._load_result()["metrics"]["open"]
    page = app.get(f"/alert/{aid}").text
    assert "Your decision" in page and "Expected activity" in page and "False positive" in page
    assert _resolve(app, aid, "expected", "Monthly patching,  change CHG-104").status_code == 303

    res = main._load_result()
    v = res["verdicts"][aid]
    assert res["metrics"]["open"] == before - 1 and res["metrics"]["resolved"] == 1
    assert v["escalate"] is True and v["disposition"] == "needs_human", "Triagle's own verdict is kept as it was"
    assert v["resolved"]["outcome"] == "expected" and v["resolved"]["by"] == "admin"
    assert v["resolved"]["note"] == "Monthly patching, change CHG-104"
    assert f'/alert/{aid}"' not in app.get("/alerts?show=open").text
    closed = app.get("/alerts?show=closed&q=Greenvale&closed=all").text
    assert f'/alert/{aid}"' in closed and "closed by admin" in closed and "CHG-104" in closed
    assert "closed by a person" in app.get("/").text
    entry = next(e for e in audit.read() if e["event"] == "alert closed by analyst")
    assert entry["outcome"] == "expected" and entry["triagle_verdict"] == "needs_human" and entry["alert_id"] == aid
    page = app.get(f"/alert/{aid}").text
    assert "closed by admin" in page and "Open it again" in page


def test_it_can_be_opened_again(app):
    aid = _burst()
    before = main._load_result()["metrics"]["open"]
    _resolve(app, aid, "false_positive")
    _resolve(app, aid, "reopen")
    res = main._load_result()
    assert res["metrics"]["open"] == before and "resolved" not in res["verdicts"][aid]
    assert any(e["event"] == "alert reopened" for e in audit.read())


def test_the_decision_survives_new_alerts_and_a_restart(app):
    aid = _burst()
    _resolve(app, aid, "handled", "Rebuilt the host")
    from tests.test_bursts import dpkg_installed
    app.post("/ingest", headers={"X-Triagle-Key": KEY}, json=[dpkg_installed(9 * 3600, "zlib1g", n=777)])
    assert main._load_result()["verdicts"][aid]["resolved"]["outcome"] == "handled"
    main._CACHE.clear()                                    # a restart
    v = main._load_result()["verdicts"][aid]
    assert v["resolved"]["label"] == "Real, and dealt with" and v["resolved"]["note"] == "Rebuilt the host"


def test_only_a_signed_in_analyst_can_close_or_reopen(app):
    aid = _burst()
    jury = TestClient(main.app)
    jury.post("/login", data={"username": "jury", "password": "look"})
    page = jury.get(f"/alert/{aid}").text
    assert "Waiting for an analyst" in page and 'value="expected"' not in page
    assert jury.post("/alert/resolve", data={"alert_id": aid, "outcome": "expected", "csrf": "x"}).status_code == 403
    assert _resolve(app, aid, "expected", token="wrong").status_code == 403
    assert "resolved" not in main._load_result()["verdicts"][aid]


def test_an_alert_triagle_closed_itself_is_not_for_a_person_to_close(app):
    res = main._load_result()
    closed = next(a["alert_id"] for a in res["alerts"] if not res["verdicts"][a["alert_id"]]["escalate"])
    assert "Your decision" not in app.get(f"/alert/{closed}").text
    token = _csrf(app.get(f"/alert/{_burst()}").text)
    r = _resolve(app, closed, "expected", token=token)
    assert r.status_code == 303 and "notice=closed" in r.headers["location"]
    assert _resolve(app, _burst(), "nonsense", token=token).status_code == 400
    assert _resolve(app, "no-such-alert", "expected", token=token).status_code == 404
