"""Spot checks: how often a person agrees with a closure.

    python -m pytest -q tests/test_checks.py

"What did it close that it should not have?" has one honest answer: a
measured one. A person is shown a sample of the closures, spread across every
reason and every detection rule, and agrees or disagrees with each. The share
agreed is the figure. A disagreement sends the alert back to the queue.
"""
import datetime as dt

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main
from app.engine import spotcheck
from tests.test_bursts import _wz, update, T0

KEY = "ck"


def _secs(when):
    return int((when - T0.replace(tzinfo=dt.timezone.utc)).total_seconds())


def routine(start):
    """Ordinary audit-trail alerts that Triagle closes on its own: six from
    one rule, one each from two others."""
    opened = [_wz(start + 10 * i, "5501", 3, "PAM: Login session opened.", ("pam", "syslog", "authentication_success"),
                  {"dstuser": "deploy"}, n=i) for i in range(6)]
    closed = [_wz(start + 70, "5502", 3, "PAM: Login session closed.", ("pam", "syslog"), {"dstuser": "deploy"}, n=20)]
    sudo = [_wz(start + 80, "5402", 3, "Successful sudo to ROOT executed.", ("syslog", "sudo"),
                {"srcuser": "deploy", "dstuser": "root", "command": "/usr/bin/systemctl status nginx"}, n=30)]
    return opened + closed + sudo


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_STATE_FILE", str(tmp_path / "state.json.gz"))
    monkeypatch.setenv("TRIAGLE_STATE_SECONDS", "0")
    monkeypatch.setenv("TRIAGLE_SEED", "off")
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s",
                      "TRIAGLE_USERS": "jury:viewer:" + auth.hash_password("look")})
    main._CACHE.clear()
    c = TestClient(main.app)
    c.post("/login", data={"username": "admin", "password": "pw"})
    start = _secs(dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(minutes=30))
    assert c.post("/ingest", headers={"X-Triagle-Key": KEY}, json=routine(start) + update(start=start + 200)).json()["accepted"] == 32
    yield c
    main._CACHE.clear()
    auth.load_config()


def _csrf(page):
    return page.split('name="csrf" value="')[1].split('"')[0]


def _own_closures():
    res = main._load_result()
    return [a for a in res["alerts"] if spotcheck.eligible(a, res["verdicts"][a["alert_id"]])]


def _mark(c, aid, agree, token=None):
    token = token or _csrf(c.get("/checks").text)
    return c.post("/checks/mark", data={"alert_id": aid, "agree": agree, "csrf": token}, follow_redirects=False)


def test_the_sample_is_spread_across_rules_and_leaves_out_what_was_not_closed_on_its_own(app):
    res = main._load_result()
    mine = _own_closures()
    assert len(mine) == 8, "the eight routine alerts; the software update went to a person as one burst"
    members = [a for a in res["alerts"] if res["verdicts"][a["alert_id"]].get("closure_code") == "BENIGN_DUPLICATE"]
    assert members and not any(spotcheck.eligible(a, res["verdicts"][a["alert_id"]]) for a in members)

    three = spotcheck.sample(res["alerts"], res["verdicts"], {}, size=3)
    assert {a["title"] for a in three} == {"PAM: Login session opened.", "PAM: Login session closed.",
                                           "Successful sudo to ROOT executed."}
    again = spotcheck.sample(res["alerts"], res["verdicts"], {}, size=3)
    assert [a["alert_id"] for a in three] == [a["alert_id"] for a in again], "the same alerts until they are checked"

    page = app.get("/checks").text
    assert "No closure has been checked yet." in page and "Check these next" in page
    assert ">Agree<" in page and ">Disagree<" in page and "8</b> more could be checked" in page


def test_agreeing_is_counted_and_disagreeing_sends_the_alert_back(app):
    first, second = _own_closures()[:2]
    assert _mark(app, first["alert_id"], "yes").headers["location"] == "/checks"
    assert spotcheck.tally(main._CACHE["checks"]) == {"checked": 1, "agreed": 1, "disagreed": 0, "pct": 100}
    assert "Agreement <b>100%</b>" in app.get("/checks").text

    open_before = main._load_result()["metrics"]["open"]
    r = _mark(app, second["alert_id"], "no")
    assert r.headers["location"].endswith(f"/alert/{second['alert_id']}?notice=sentback")
    res = main._load_result()
    v = res["verdicts"][second["alert_id"]]
    assert v["escalate"] is True and v["disposition"] == "needs_human" and v["closure_code"] is None
    assert v["summary"].startswith("Sent back by admin") and v["overruled"]["by"] == "admin"
    assert res["metrics"]["open"] == open_before + 1
    page = app.get(f"/alert/{second['alert_id']}?notice=sentback").text
    assert "back in the queue" in page and "Your decision" in page

    tally = spotcheck.tally(main._CACHE["checks"])
    assert tally == {"checked": 2, "agreed": 1, "disagreed": 1, "pct": 50}
    listing = app.get("/checks").text
    assert "Closures a person disagreed with" in listing and "6</b> more could be checked" in listing
    events = [e for e in audit.read() if e["event"] == "closure checked"]
    assert sorted(e["agreed"] for e in events) == [False, True]

    # the person then decides what it was, like any other alert sent to them
    token = _csrf(app.get(f"/alert/{second['alert_id']}").text)
    app.post("/alert/resolve", data={"alert_id": second["alert_id"], "outcome": "handled", "csrf": token})
    assert main._load_result()["verdicts"][second["alert_id"]]["resolved"]["outcome"] == "handled"
    assert spotcheck.tally(main._CACHE["checks"])["disagreed"] == 1, "closing it does not erase the disagreement"


def test_a_check_can_be_taken_back_and_is_not_counted_twice(app):
    one = _own_closures()[0]
    token = _csrf(app.get("/checks").text)
    _mark(app, one["alert_id"], "no", token)
    _mark(app, one["alert_id"], "yes", token)
    assert spotcheck.tally(main._CACHE["checks"])["checked"] == 1 and main._CACHE["checks"][one["alert_id"]]["ok"] is False
    app.post("/checks/undo", data={"alert_id": one["alert_id"], "csrf": token})
    assert main._CACHE["checks"] == {}
    assert main._load_result()["verdicts"][one["alert_id"]]["escalate"] is False, "back to Triagle's own closure"


def test_only_triagles_own_closures_can_be_checked_and_only_by_an_analyst(app):
    res = main._load_result()
    member = next(a for a in res["alerts"] if res["verdicts"][a["alert_id"]].get("closure_code") == "BENIGN_DUPLICATE")
    raised = next(a for a in res["alerts"] if res["verdicts"][a["alert_id"]].get("escalate"))
    assert _mark(app, member["alert_id"], "yes").status_code == 400
    assert _mark(app, raised["alert_id"], "yes").status_code == 400
    assert _mark(app, "wz-nope", "yes").status_code == 404
    one = _own_closures()[0]
    assert _mark(app, one["alert_id"], "maybe").status_code == 400
    assert _mark(app, one["alert_id"], "yes", token="wrong").status_code == 403

    viewer = TestClient(main.app)
    viewer.post("/login", data={"username": "jury", "password": "look"})
    page = viewer.get("/checks").text
    assert "Check these next" in page and ">Agree<" not in page
    assert viewer.post("/checks/mark", data={"alert_id": one["alert_id"], "agree": "yes", "csrf": "x"},
                       follow_redirects=False).status_code == 403
    assert "Was this right?" in app.get(f"/alert/{one['alert_id']}").text
    assert "Was this right?" not in viewer.get(f"/alert/{one['alert_id']}").text


def test_the_pilot_report_carries_the_figures_and_checks_survive_a_restart(app):
    a, b, c = _own_closures()[:3]
    token = _csrf(app.get("/checks").text)
    for alert, answer in ((a, "yes"), (b, "yes"), (c, "no")):
        _mark(app, alert["alert_id"], answer, token)
    main._CACHE.clear()                                   # a restart
    assert spotcheck.tally(main._load_result() and main._CACHE["checks"])["checked"] == 3
    assert main._load_result()["verdicts"][c["alert_id"]]["escalate"] is True, "still sent back after a restart"

    page = app.get("/pilot").text
    assert "What Triagle did with 32 alerts" in page
    assert "A person has checked 3 of its closures and agreed with 2 (66.6%)" in page
    assert "It closed 7 on its own with a written reason, counted 23 repeats under an alert it had already raised" in page
    assert "Disagreed, and sent back to the queue" in page and "A person disagreed with" in page
    assert "Routine activity" in page and "Reading those alerts by hand" in page
    assert "Calls to the model" in page and "$0.0000" in page

    viewer = TestClient(main.app)
    viewer.post("/login", data={"username": "jury", "password": "look"})
    assert viewer.get("/pilot").status_code == 200


def test_the_share_closed_is_never_rounded_up():
    assert main._share(598, 600) == 99                       # 99.67: "100%" would say nothing went to a person
    assert main._share(600, 600) == 100 and main._share(594, 600) == 99
    assert main._share(0, 0) == 0


def test_agreement_is_never_rounded_up():
    checks = {str(i): {"ok": i != 0, "client": "Bank"} for i in range(300)}
    assert spotcheck.tally(checks)["pct"] == 99.6            # 299 of 300 is 99.67: not shown as 99.7 or 100
    assert spotcheck.tally({})["pct"] is None
    assert spotcheck.tally(checks, skip_clients={"Bank"})["checked"] == 0
