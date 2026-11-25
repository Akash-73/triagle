"""A person teaches Triagle: "close the same thing from now on".

    python -m pytest -q tests/test_taught.py

A false alarm must not need a change to Triagle's code. The analyst who
closes an alert as expected activity can ask for the same alert on that
machine to be closed from then on. The rule says who taught it and why, runs
for a set number of days, never closes an alert that was raised on evidence,
never reaches back, and can be switched off.
"""
import datetime as dt

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main
from app.engine import instructions
from tests.test_bursts import update, dpkg_installed, dpkg_half, file_changed, T0

KEY = "rk"


def _secs(when):
    return int((when - T0.replace(tzinfo=dt.timezone.utc)).total_seconds())


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
    assert _send(c, update(start=_secs(now - dt.timedelta(minutes=30)))) == 24
    yield c
    main._CACHE.clear()
    auth.load_config()


def _send(c, items):
    return c.post("/ingest", headers={"X-Triagle-Key": KEY}, json=items).json()["accepted"]


def _head():
    res = main._load_result()
    return next(a for a in res["alerts"] if res["verdicts"][a["alert_id"]].get("burst"))


def _csrf(page):
    return page.split('name="csrf" value="')[1].split('"')[0]


def _teach(c, aid, outcome="expected", note="Monthly patching", **more):
    data = {"alert_id": aid, "outcome": outcome, "note": note, "teach": "1",
            "csrf": _csrf(c.get(f"/alert/{aid}").text)}
    data.update(more)
    return c.post("/alert/resolve", data=data, follow_redirects=False)


def _later(rule_id, minutes=1, host="wazuh-demo", n=900):
    """One more alert from the same detection rule, dated after now."""
    when = _secs(dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes))
    make = dpkg_installed if rule_id == "2902" else dpkg_half
    return make(when, "nginx", n=n, host=host)


def test_closing_with_do_the_same_next_time_makes_a_rule_and_the_next_alert_is_closed(app):
    head = _head()
    rid = head["indicators"]["rule_id"]
    page = app.get(f"/alert/{head['alert_id']}").text
    assert "Do the same next time" in page and "for 30 days" in page
    r = _teach(app, head["alert_id"])
    assert r.status_code == 303 and r.headers["location"].endswith("?notice=taught")

    rule = main._CACHE["taught"][0]
    assert rule["rule_id"] == rid and rule["host"] == "wazuh-demo" and rule["by"] == "admin"
    assert rule["outcome"] == "expected" and rule["note"] == "Monthly patching" and rule["user"] == ""
    assert instructions.state(rule) == "on" and rule["days"] == 30
    entry = next(e for e in audit.read() if e["event"] == "rule taught")
    assert entry["rule"] == rule["id"] and entry["alert_id"] == head["alert_id"]

    open_before = main._load_result()["metrics"]["open"]
    out = app.post("/ingest?verdicts=1", headers={"X-Triagle-Key": KEY}, json=[_later(rid)]).json()
    assert out["accepted"] == 1 and out["verdicts"][0]["verdict"] == "closed"
    res = main._load_result()
    new = next(a for a in res["alerts"] if a["alert_id"].endswith(rid + "900"))
    v = res["verdicts"][new["alert_id"]]
    assert v["escalate"] is False and v["instruction"] == rule["id"] and v["closure_code"] == "BENIGN_EXPECTED"
    assert "admin" in v["summary"] and "Monthly patching" in v["reasoning"] and rule["id"] in v["reasoning"]
    assert res["metrics"]["open"] == open_before and res["metrics"]["taught_closed"] == 1

    listing = app.get("/taught").text
    assert rule["id"] in listing and "In force" in listing and "Monthly patching" in listing
    detail = app.get(f"/alert/{new['alert_id']}").text
    assert f'/taught#{rule["id"]}' in detail and "Was this right?" not in detail, "a person already decided this one"


def test_a_taught_rule_is_for_one_rule_on_one_machine_and_never_reaches_back(app):
    head = _head()
    rid = head["indicators"]["rule_id"]
    other = "2904" if rid == "2902" else "2902"
    res = main._load_result()
    closed_before = {a["alert_id"] for a in res["alerts"] if not res["verdicts"][a["alert_id"]].get("escalate")}
    _teach(app, head["alert_id"])
    _send(app, [_later(rid, host="branch-07", n=901), _later(other, n=902),
                file_changed(_secs(dt.datetime.now(dt.timezone.utc)) + 90, "/etc/passwd", n=903)])
    res = main._load_result()
    for a in res["alerts"]:
        v = res["verdicts"][a["alert_id"]]
        assert not v.get("instruction"), "another machine, another rule and another kind of alert are untouched"
    # nothing that was already in the queue changed hands
    assert {a["alert_id"] for a in res["alerts"]
            if not res["verdicts"][a["alert_id"]].get("escalate")} >= closed_before
    assert res["verdicts"][head["alert_id"]]["resolved"]["outcome"] == "expected"


def test_only_expected_activity_and_false_positive_can_be_taught(app):
    head = _head()
    assert _teach(app, head["alert_id"], outcome="handled").status_code == 303
    assert main._CACHE["taught"] == [], "'real, and dealt with' is not something to repeat"


def test_an_alert_raised_on_evidence_cannot_be_taught_away():
    base = {"alert_id": "x1", "source": "wazuh", "client": "Bank", "host": "srv1", "user": "root",
            "timestamp": "2026-11-25T10:00:00Z", "title": "sshd: authentication failed.", "raw_severity": "medium",
            "description": "", "indicators": {"rule_id": "5716", "auth": "failed"}}
    guessing = {"escalate": True, "disposition": "suspicious", "basis": "correlation", "pattern": "password_guessing"}
    undecided = {"escalate": True, "disposition": "needs_human", "basis": "", "pattern": ""}
    intel = {"escalate": True, "disposition": "suspicious", "basis": "intel", "pattern": ""}
    assert instructions.teachable(base, undecided)
    assert instructions.teachable(base, {"escalate": True, "disposition": "suspicious", "basis": "", "pattern": ""})
    assert instructions.teachable(base, {"escalate": True, "disposition": "suspicious", "basis": "correlation"})
    assert not instructions.teachable(base, {"escalate": True, "disposition": "true_positive", "basis": "signal"})
    assert not instructions.teachable(base, {"escalate": True, "disposition": "suspicious", "basis": "sequence"})
    assert not instructions.teachable(base, dict(undecided, escalate=False))
    assert not instructions.teachable(base, guessing)
    assert not instructions.teachable(base, intel)
    assert not instructions.teachable(dict(base, title="Ransomware behavior detected"), undecided)
    assert not instructions.teachable(dict(base, host="", entity=""), undecided)

    rule = instructions.make(base, "expected", "Expected activity", "", "admin",
                             now=dt.datetime(2026, 11, 25, 9, 0, tzinfo=dt.timezone.utc))
    verdicts = {"x1": dict(guessing, summary="Password guessing from 203.0.113.9")}
    assert instructions.apply([base], verdicts, [rule]) == {}
    assert verdicts["x1"]["escalate"] is True, "a sign-in pattern stays with a person whatever was taught"
    verdicts = {"x1": dict(undecided, summary="Undetermined")}
    assert instructions.apply([base], verdicts, [rule]) == {rule["id"]: {"count": 1, "last": base["timestamp"]}}
    assert verdicts["x1"]["escalate"] is False


def test_switching_a_rule_off_stops_it_from_then_on_and_keeps_what_it_closed(app):
    head = _head()
    rid = head["indicators"]["rule_id"]
    _teach(app, head["alert_id"])
    rule = main._CACHE["taught"][0]
    # the rule was given a little while ago, so alerts can be dated before and after it is switched off
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)
    rule["at"] = past.isoformat(timespec="seconds")
    rule["windows"][0][0] = rule["at"]
    _send(app, [_later(rid, minutes=-5, n=910)])
    token = _csrf(app.get("/taught").text)
    assert app.post("/taught/change", data={"rule_id": rule["id"], "do": "off", "csrf": token},
                    follow_redirects=False).status_code == 303
    off = main._CACHE["taught"][0]
    assert instructions.state(off) == "off"
    # say it was switched off three minutes ago, so an alert can fall in the gap before it is started again
    off["windows"][0][1] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=3)).isoformat(timespec="seconds")
    _send(app, [_later(rid, minutes=-2, n=911)])
    res = main._load_result()
    by_n = {a["alert_id"][-3:]: res["verdicts"][a["alert_id"]] for a in res["alerts"]}
    assert by_n["910"].get("instruction") == rule["id"], "closed while the rule was on: stays closed"
    assert by_n["911"]["escalate"] is True and not by_n["911"].get("instruction")
    assert "Switched off" in app.get("/taught").text

    # started again: from now, and the gap stays as it was
    app.post("/taught/change", data={"rule_id": rule["id"], "do": "renew", "days": "7", "csrf": token})
    again = main._CACHE["taught"][0]
    assert instructions.state(again) == "on" and len(again["windows"]) == 2 and again["days"] == 7
    _send(app, [_later(rid, minutes=4, n=912)])
    res = main._load_result()
    by_n = {a["alert_id"][-3:]: res["verdicts"][a["alert_id"]] for a in res["alerts"]}
    assert by_n["912"].get("instruction") == rule["id"]
    assert not by_n["911"].get("instruction")
    events = [e["event"] for e in audit.read()]
    assert "taught rule switched off" in events and "taught rule renewed" in events


def test_a_rule_runs_out_after_its_days(app):
    head = _head()
    _teach(app, head["alert_id"], days="7")
    rule = main._CACHE["taught"][0]
    assert rule["days"] == 7
    week_on = dt.datetime.now(dt.timezone.utc).timestamp() + 8 * 86400
    assert instructions.state(rule, week_on) == "ended"
    assert not instructions._in_force(rule, week_on)


def test_a_viewer_cannot_teach_or_change_a_rule_and_it_survives_a_restart(app):
    head = _head()
    rid = head["indicators"]["rule_id"]
    _teach(app, head["alert_id"], scope="account")
    rule = dict(main._CACHE["taught"][0])
    viewer = TestClient(main.app)
    viewer.post("/login", data={"username": "jury", "password": "look"})
    page = viewer.get("/taught").text
    assert rule["id"] in page and "Switch off" not in page
    assert viewer.post("/taught/change", data={"rule_id": rule["id"], "do": "off",
                                               "csrf": _csrf(viewer.get("/alerts").text) if 'name="csrf"' in viewer.get("/alerts").text else ""},
                       follow_redirects=False).status_code == 403

    main._CACHE.clear()                       # a restart
    assert [r["id"] for r in (main._load_result() and main._CACHE["taught"])] == [rule["id"]]
    _send(app, [_later(rid, n=920)])
    res = main._load_result()
    assert any(v.get("instruction") == rule["id"] for v in res["verdicts"].values())


def test_the_tuning_page_points_at_the_tool_once_a_taught_rule_has_been_used(app):
    head = _head()
    rid = head["indicators"]["rule_id"]
    _teach(app, head["alert_id"])
    _send(app, [_later(rid, n=930), _later(rid, minutes=2, n=931)])
    res = main._load_result()
    rec = next(r for r in res["rule_health"] if r["rule_id"] == rid)
    assert rec["flagged"] and "A person taught Triagle to close this on wazuh-demo" in rec["recommendation"]
    assert f"child rule of {rid} at level 0" in rec["recommendation"]
