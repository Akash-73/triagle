"""The Live page: alerts as they arrive, and a test stream sent from the page.

    python -m pytest -q tests/test_live.py

The page shows the alerts that arrived most recently, each with what the tool
said and what Triagle decided. An analyst can send a scripted stream from it,
a few alerts at a time, so someone watching sees each one arrive and be
decided. Nothing here is typed into a terminal.

What these check:
  - anyone who may look at the console may watch; only an analyst can send
  - the stream goes through the same path a connected tool's alerts take
  - starting or clearing a stream never touches a connected tool's alerts
  - the numbers the page shows are the engine's, not written into the page
"""
import pytest
from fastapi.testclient import TestClient

from app import auth, demo_attack, main
from app.connectors import examples

KEY = "live-key"
REAL = "Greenvale Co-operative Bank"
TEST = "Northgate Urban Co-operative Bank"
ENCODED = examples.EXAMPLES["wazuh"][0]["raw"]
DISCOVERY = examples.EXAMPLES["wazuh"][2]["raw"]


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    monkeypatch.setenv("TRIAGLE_GUEST", "view")
    monkeypatch.delenv("TRIAGLE_DEMO_SCENARIOS", raising=False)
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s"})
    main._CACHE.clear()
    yield
    main._CACHE.clear()
    auth.load_config()


def guest():
    return TestClient(main.app)


def analyst():
    c = guest()
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    return c


def token(c):
    return c.get("/live").text.split('name="csrf" value="')[1].split('"')[0]


def real_alerts(c, *raws):
    items = [{"source": "wazuh", "client": REAL, "raw": r} for r in raws]
    return c.post("/ingest", headers={"X-Triagle-Key": KEY}, json=items).json()["accepted"]


def send(c, kind="shift", scenario="bank", n=5):
    """Start a stream and step it to the end, as the page does. Returns the
    last answer and how many steps it took."""
    t = token(c)
    start = c.post("/api/demo/start", json={"csrf": t, "kind": kind, "scenario": scenario})
    assert start.status_code == 200, start.text
    run, steps = start.json()["run"], 0
    while True:
        r = c.post("/api/demo/step", json={"csrf": t, "run": run, "n": n})
        assert r.status_code == 200, r.text
        steps += 1
        if r.json()["done"]:
            return r.json(), steps
        assert steps < 60


# ---- watching -----------------------------------------------------------------

def test_anyone_who_may_look_may_watch(site):
    g = guest()
    page = g.get("/live")
    assert page.status_code == 200 and "Arriving now" in page.text
    assert 'id="send"' not in page.text and "A signed-in analyst can send" in page.text
    state = g.get("/api/live").json()
    assert state["rows"] == [] and state["run"] is None and state["counts"]["received"] > 0
    assert 'href="/live"' in g.get("/").text, "it is in the navigation"


def test_an_analyst_gets_the_send_button_only_where_test_streams_are_on(site, monkeypatch):
    a = analyst()
    page = a.get("/live").text
    assert 'id="send"' in page and "Send the test stream" in page
    assert "A working hour, with one intrusion in it" in page and "The intrusion alone" in page
    monkeypatch.setenv("TRIAGLE_DEMO", "false")
    page = a.get("/live").text
    assert "Test stream" not in page and "Arriving now" in page, "the feed is still there"
    r = a.post("/api/demo/start", json={"csrf": token(a), "kind": "shift"})
    assert r.status_code == 403 and "turned off" in r.json()["detail"]


def test_the_feed_is_newest_first_and_says_what_was_decided(site):
    a = analyst()
    assert real_alerts(a, ENCODED, DISCOVERY) == 2
    state = a.get("/api/live").json()
    rows = state["rows"]
    assert [r["client"] for r in rows] == [REAL, REAL] and not any(r["test"] for r in rows)
    newest, older = rows
    assert older["open"] is True and older["severity"] in ("critical", "high", "medium")
    assert older["tool"].startswith("Wazuh") and older["said"] and older["why"] and older["what"]
    assert newest["arrived"] and state["last"] == newest["arrived"]
    for r in rows:
        assert a.get(f"/alert/{r['id']}").status_code == 200, "each row opens its alert"
    # nothing changed since: the page is told so instead of being sent it all again
    again = a.get(f"/api/live?rev={state['rev']}").json()
    assert again["same"] is True and "rows" not in again
    assert "rows" in a.get(f"/api/live?rev={state['rev'] - 1}").json()


# ---- sending ---------------------------------------------------------------------

def test_a_guest_cannot_send_or_step(site):
    g = guest()
    t = token(analyst())
    assert g.post("/api/demo/start", json={"csrf": t, "kind": "shift"}).status_code == 403
    assert g.post("/api/demo/step", json={"csrf": t, "run": "x"}).status_code == 403
    assert main._CACHE.get("demo_run") is None


def test_a_send_needs_the_form_token(site):
    a = analyst()
    assert a.post("/api/demo/start", json={"csrf": "wrong", "kind": "shift"}).status_code == 403
    assert a.post("/api/demo/start", content=b"not json").status_code == 400


def test_a_working_hour_arrives_a_few_at_a_time_and_is_decided(site):
    a = analyst()
    t = token(a)
    start = a.post("/api/demo/start", json={"csrf": t, "kind": "shift", "scenario": "bank"}).json()
    total = start["total"]
    assert total == len(demo_attack.fresh_shift(scenario="bank")) and start["state"]["run"]["sent"] == 0
    assert start["state"]["test_alerts"] == 0, "starting sends nothing"

    one = a.post("/api/demo/step", json={"csrf": t, "run": start["run"], "n": 1}).json()
    assert one["sent"] == 1 and one["done"] is False
    assert len(one["state"]["rows"]) == 1 and one["state"]["rows"][0]["test"] is True
    assert one["state"]["run"]["seconds"] is None

    three = a.post("/api/demo/step", json={"csrf": t, "run": start["run"], "n": 3}).json()
    assert three["sent"] == 4 and [r["test"] for r in three["state"]["rows"]] == [True] * 4

    last = three
    while not last["done"]:
        last = a.post("/api/demo/step", json={"csrf": t, "run": start["run"], "n": 5}).json()
    run = last["state"]["run"]
    assert run["sent"] == run["total"] == total and run["customer"] == TEST
    assert run["closed"] + run["open"] == total
    assert run["open"] == 5 and run["cases"] == 1, "the intrusion is raised, as one case"
    assert run["closed"] >= 25, "the routine alerts are closed"
    assert run["seconds"] >= 1
    assert run["case"] and a.get(f"/case/{run['case']}").status_code == 200
    assert run["report"]["name"] and run["report"]["due"], "the reporting clock has started"

    # what the page shows is the engine's verdict on each alert, read back from the queue
    res = main._load_result()
    mine = [x for x in res["alerts"] if x["client"] == TEST]
    assert sum(1 for x in mine if res["verdicts"][x["alert_id"]]["escalate"]) == run["open"]
    closed_rows = [r for r in last["state"]["rows"] if not r["open"]]
    assert closed_rows and all(r["why"] and r["severity"] == "" for r in closed_rows)
    # a step after the end sends nothing more
    more = a.post("/api/demo/step", json={"csrf": t, "run": start["run"], "n": 5}).json()
    assert more["sent"] == total and more["done"] is True


def test_the_intrusion_alone(site):
    a = analyst()
    out, steps = send(a, kind="intrusion", n=1)
    run = out["state"]["run"]
    assert steps == run["total"] == 6
    assert run["open"] == 5 and run["closed"] == 1 and run["cases"] == 1 and out["case"] == run["case"]


def test_a_stream_never_touches_a_connected_tools_alerts(site):
    a = analyst()
    assert real_alerts(a, ENCODED, DISCOVERY) == 2
    send(a, kind="intrusion")
    res = main._load_result()
    assert sum(1 for x in res["alerts"] if x["client"] == REAL) == 2
    assert a.get("/api/live").json()["test_alerts"] == 6

    # a second stream replaces the first; it does not pile up on it
    send(a, kind="intrusion")
    assert a.get("/api/live").json()["test_alerts"] == 6

    # clearing takes the test alerts and the run away, and nothing else
    r = a.post("/demo/reset", data={"csrf": token(a), "next": "live"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/live"
    state = a.get("/api/live").json()
    assert state["test_alerts"] == 0 and state["run"] is None
    assert [r["client"] for r in state["rows"]] == [REAL, REAL]
    assert real_alerts(a, ENCODED) == 0, "the tool's alerts are still known"


def test_a_stream_someone_else_restarted_stops_here(site):
    a = analyst()
    t = token(a)
    first = a.post("/api/demo/start", json={"csrf": t, "kind": "shift"}).json()
    a.post("/api/demo/step", json={"csrf": t, "run": first["run"], "n": 2})
    second = a.post("/api/demo/start", json={"csrf": t, "kind": "intrusion"}).json()
    stale = a.post("/api/demo/step", json={"csrf": t, "run": first["run"], "n": 2})
    assert stale.status_code == 409 and "no longer running" in stale.json()["detail"]
    assert a.get("/api/live").json()["test_alerts"] == 0, "the first stream's alerts were cleared"
    assert a.post("/api/demo/step", json={"csrf": t, "run": second["run"], "n": 1}).json()["sent"] == 1


def test_a_deployment_can_offer_one_scenario_only(site, monkeypatch):
    a = analyst()
    assert '<select name="scenario"' in a.get("/live").text, "both are offered by default"
    monkeypatch.setenv("TRIAGLE_DEMO_SCENARIOS", "bank")
    page = a.get("/live").text
    assert '<select name="scenario"' not in page and "Tirupati" not in page
    out, _ = send(a, kind="intrusion", scenario="power")
    assert out["state"]["run"]["customer"] == TEST, "asking for one that is not offered runs the one that is"
    r = a.post("/demo/fire", data={"csrf": token(a), "scenario": "power"}, follow_redirects=False)
    assert r.status_code == 303
    assert {x["client"] for x in main._CACHE["live"]} == {TEST}, "the older one-click route keeps to the list too"


def test_when_an_alert_arrived_survives_a_restart(site, tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("TRIAGLE_STATE_SECONDS", "0")
    main._CACHE.clear()
    a = analyst()
    real_alerts(a, ENCODED)
    before = a.get("/api/live").json()["rows"][0]
    assert before["arrived"]
    main._CACHE.clear()                                    # what a restart does
    after = a.get("/api/live").json()["rows"][0]
    assert after["id"] == before["id"] and after["arrived"] == before["arrived"]


def test_a_cases_account_is_written_once_however_many_ask_at_the_same_time(site, monkeypatch):
    import threading
    import time
    a = analyst()
    out, _ = send(a, kind="intrusion")
    case = out["case"]
    calls = []

    def slow_writer(incident, members, house=""):
        calls.append(incident["id"])
        time.sleep(0.4)
        return ("Written account.", True, "vertex")

    monkeypatch.setattr(main.worknotes, "work_notes", slow_writer)
    main._WORKNOTES.clear()
    answers = []

    def ask():
        answers.append(a.get(f"/api/notes?case={case}").json())

    threads = [threading.Thread(target=ask) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1, "the page that opens the case does not ask the model again"
    assert [x["text"] for x in answers] == ["Written account."] * 3 and all(x["by_model"] for x in answers)


# ---- the documents a case produces ------------------------------------------------

def test_the_report_does_not_call_a_rehearsed_action_done(site):
    a = analyst()
    out, _ = send(a, kind="intrusion")
    page = a.get(f"/report/{out['case']}").text
    assert "Incident report " + out["case"] in page and "Northgate Urban Co-operative Bank" in page
    assert "rehearsed" in page and "not connected to this deployment" in page
    assert "auto-contained" not in page.lower() and "contained" not in page.lower()
    assert "waiting for approval" in page.lower()
    for old_wording in ("for this demo", "in production", "AI SOC analyst", "dry-run"):
        assert old_wording not in page, old_wording
    assert " IST" in page.split('class="about"')[1].split("</div>")[0], "the report's own time is in IST, like the alerts'"


def test_a_draft_from_alerts_that_arrived_does_not_talk_about_moved_times(site, monkeypatch):
    monkeypatch.setenv("TRIAGLE_DEMO_CLOCK", "true")
    main._CACHE.clear()
    a = analyst()
    out, _ = send(a, kind="intrusion")
    draft = a.get(f"/notice/{out['case']}/certin").text
    assert "Draft report to CERT-In" in draft and "nothing has been filed" in draft
    assert "samples that ship with Triagle" not in draft, "these alerts arrived; their times are their own"
    assert "CrowdStrike" in draft and "crowdstrike_edr" not in draft, "tools are named as people know them"
    assert 'data-due="' in draft
