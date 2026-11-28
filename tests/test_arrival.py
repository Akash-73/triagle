"""Work on arrival: the model reads every closure and investigates every alert
for a person without waiting to be asked.

    python -m pytest -q tests/test_arrival.py

The model is stood in for. What is tested is the plain code around it: what
is read and what is left out, that the work can raise an alert and never
close one, what it costs and where it stops, and what survives a restart.
"""
import json
import re

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, demo_attack, main
from app.connectors import examples
from app.engine import genai, nightshift, spotcheck, worknotes

KEY = "arrival-intake-key"
BANK = "Greenvale Co-operative Bank"
BENIGN = {"view": "benign", "confidence": 90, "summary": "Routine.", "reasons": ["Nothing hostile in the record."], "next": []}
SUSPICIOUS = {"view": "suspicious", "confidence": 85, "summary": "This needs a person.",
              "reasons": ["The record is unexplained."], "next": ["Ask the owner."]}
IN, OUT = 1000, 200                                  # tokens each stand-in call reports
ONE_CALL = (IN * genai.PRICE_IN_USD + OUT * genai.PRICE_OUT_USD) / 1_000_000


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    for name in ("TRIAGLE_GUEST", "TRIAGLE_AGENT", "TRIAGLE_AGENT_STEPS", "K_SERVICE", "TRIAGLE_OSINT", "TRIAGLE_STATE_FILE",
                 "TRIAGLE_ARRIVAL_DAILY_USD", "TRIAGLE_ARRIVAL_BATCH", "TRIAGLE_ARRIVAL_SECONDS", "TRIAGLE_ARRIVAL_THINKING",
                 "TRIAGLE_PRICE_IN", "TRIAGLE_PRICE_OUT", "TRIAGLE_MODEL_BASE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TRIAGLE_ARRIVAL", "on")
    monkeypatch.setenv("TRIAGLE_PUBLIC_URL", "https://triagle.example")
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    monkeypatch.setattr(main, "WORK_KEY", "")
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": "s" * 40})
    saved = dict(genai.USAGE), dict(genai.STATUS)
    for store in (main._CACHE, main._WORKNOTES, main._NOTES_AT, main._ASK_TIMES):
        store.clear()
    yield
    genai.USAGE.update(saved[0])
    genai.STATUS.clear()
    genai.STATUS.update(saved[1])
    for store in (main._CACHE, main._WORKNOTES, main._NOTES_AT):
        store.clear()


def a_model(monkeypatch, reading=BENIGN, doubt=(), answers=True, garbled=False):
    """A stand-in for the model on all three jobs. `doubt`: words in a closed
    alert's line that make the reading say 'look'. Counts its calls by job and
    reports tokens the way the API does."""
    calls = {"read": 0, "plan": 0, "reading": 0, "account": 0, "seen": []}

    def generate(system, user, **kw):
        if not answers:
            genai.STATUS.update(ok=False, error="The model did not answer.")
            return None, None
        genai.STATUS.update(ok=True, error=None)
        genai.USAGE["calls"] += 1
        genai.USAGE["input"] += IN
        genai.USAGE["output"] += OUT
        calls["seen"].append((system, user, kw))
        if system.startswith(nightshift.SECOND_SYSTEM[:60]):
            calls["read"] += 1
            if garbled:
                return "I would rather not say.", "vertex"
            rows = re.findall(r"^(\d+)\. (.*)$", user, flags=re.M)
            return json.dumps([{"n": int(n), "view": "look" if any(w in line for w in doubt) else "agree",
                                "why": "A reason in one sentence."} for n, line in rows]), "vertex"
        if system.startswith(worknotes.ALERT_SYSTEM[:60]):
            calls["account"] += 1
            return "What happened: something was seen.\nWhy it matters: a person should look.", "vertex"
        if "Give your own reading" in system:
            calls["reading"] += 1
            return json.dumps(reading), "vertex"
        calls["plan"] += 1
        return json.dumps({"tool": "conclude", "why": "enough"}), "vertex"

    monkeypatch.setattr(genai, "configured", lambda: True)
    monkeypatch.setattr(genai, "generate_prose", generate)
    return calls


def work_until_done(rounds=40):
    out = None
    for _ in range(rounds):
        out = main.arrival_work()
        if not out["did"]:
            return out
    raise AssertionError("the work never finished")


def signed_in():
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "correct horse"}, follow_redirects=False).status_code == 303
    return c


def send(*raws, client=BANK, source="wazuh"):
    r = TestClient(main.app).post("/ingest", headers={"X-Triagle-Key": KEY},
                                  json=[{"source": source, "client": client, "raw": raw} for raw in raws])
    assert r.status_code == 200
    return r.json()["accepted"]


def sorted_queue():
    """(own closures, alerts for a person, everything) for real customers."""
    r, skip = main._load_result(), main._test_clients()
    own = [a for a in r["alerts"] if spotcheck.eligible(a, r["verdicts"][a["alert_id"]], skip)]
    raised = [a for a in r["alerts"] if r["verdicts"][a["alert_id"]].get("escalate") and a["client"] not in skip]
    return own, raised, r


# ---- what is done ------------------------------------------------------------------

def test_it_is_off_until_it_is_switched_on_and_then_nothing_is_asked_of_the_model(monkeypatch):
    calls = a_model(monkeypatch)
    monkeypatch.delenv("TRIAGLE_ARRIVAL")
    assert main.arrival_work() == {"on": False, "did": []}
    r = TestClient(main.app).post("/api/work", headers={"X-Triagle-Key": KEY})
    assert r.status_code == 200 and r.json() == {"on": False, "did": []}
    assert "on every alert" not in signed_in().get("/").text, "nothing to show until it has worked or is on"
    assert calls["seen"] == [] and main._CACHE["second"] == {} and main._CACHE["agent"] == {}


def test_every_closure_is_read_and_every_alert_for_a_person_is_investigated(monkeypatch):
    calls = a_model(monkeypatch)
    own, raised, before = sorted_queue()
    assert len(own) >= 5 and len(raised) >= 5
    was = {a["alert_id"]: bool(before["verdicts"][a["alert_id"]].get("escalate")) for a in before["alerts"]}
    out = work_until_done()
    assert out["waiting"] == {"need": 0, "look": 0, "read": 0} and out["paused"] is None
    second, runs = main._CACHE["second"], main._CACHE["agent"]
    # every closure Triagle made on its own was read, and says it was not asked for
    assert {a["alert_id"] for a in own} == set(second)
    assert all(v["auto"] and v["view"] == "agree" and v["by"] == "Gemini on Vertex AI" for v in second.values())
    # every alert that needs a person has the full second opinion and its account, before anyone opens it
    assert {a["alert_id"] for a in raised} == set(runs)
    assert all(r["by"] == main.ARRIVAL_NAME and r["auto"] and r["usable"] for r in runs.values())
    assert out["read"] == len(own) and out["investigated"] == len(raised) == out["accounts"] == calls["account"]
    assert out["covered"] == len(own) + len(raised) and out["raised"] == 0 and out["failed"] == 0
    # one customer to a call, so one customer's house knowledge is never beside another's alerts
    by_client = {}
    for a in own:
        by_client.setdefault(a["client"], []).append(a)
    assert out["reads"] == calls["read"] == len(by_client)
    for system, user, kw in calls["seen"]:
        if system.startswith(nightshift.SECOND_SYSTEM[:60]):
            assert kw.get("thinking_level") == "low" and kw.get("temperature") == 0
    # nothing a model said changed a verdict: what was closed is closed, what was raised is raised
    after = main._load_result()["verdicts"]
    assert {k: bool(v.get("escalate")) for k, v in after.items()} == was
    events = [e["event"] for e in audit.read()]
    assert events.count("alert investigated by the model on arrival") == len(raised)
    assert events.count("closures read by the model on arrival") == len(by_client)
    # a second round finds nothing to do and asks the model nothing
    asked = len(calls["seen"])
    assert main.arrival_work()["did"] == [] and len(calls["seen"]) == asked


def test_a_closure_the_reading_doubts_is_investigated_and_goes_to_a_person_and_never_the_other_way(monkeypatch):
    own, raised, _ = sorted_queue()
    doubted = own[0]
    a_model(monkeypatch, reading=SUSPICIOUS, doubt=(doubted["title"],))
    out = work_until_done()
    same_title = [a for a in own if a["title"] == doubted["title"]]
    assert out["looks"] == len(same_title) and out["raised"] == len(same_title)
    assert out["investigated"] == len(raised) + len(same_title)
    v = main._load_result()["verdicts"][doubted["alert_id"]]
    assert v["escalate"] and v["overruled"]["kind"] == "investigator", "the closure went to a person"
    assert main._CACHE["agent"][doubted["alert_id"]]["effect"] == "raise"
    assert main._CACHE["checks"] == {}, "it is not counted as a person's disagreement"
    # the SIEM is told, with a link that works although no request was being answered
    told = [e for e in main._CACHE["outbox"]["events"] if e["event"] == "reopened" and e["alert_id"] == doubted["alert_id"]]
    assert len(told) == 1 and told[0]["url"].startswith("https://triagle.example/alert/")
    # the account for the person who will open it is already written
    c = signed_in()
    note = c.get("/api/notes", params={"alert": doubted["alert_id"]}).json()
    assert note["by_model"] and note["unasked"]

    # the other way: a model that calls everything harmless closes nothing
    for store in (main._CACHE, main._WORKNOTES):
        store.clear()
    a_model(monkeypatch, reading=BENIGN)
    own, raised, _ = sorted_queue()
    work_until_done()
    after = main._load_result()["verdicts"]
    assert all(after[a["alert_id"]]["escalate"] for a in raised), "every alert for a person is still with a person"
    assert not any(r["effect"] == "raise" for r in main._CACHE["agent"].values())


def test_test_streams_repeats_and_closures_people_made_are_left_out(monkeypatch):
    a_model(monkeypatch)
    assert send(*[i["raw"] for i in demo_attack.fresh_benign()], client=demo_attack.DEFAULT_CLIENT, source="crowdstrike_edr")
    assert send(*[e["raw"] for e in examples.EXAMPLES["wazuh"]]) == 3
    # an analyst closes one alert by hand before the model gets to it
    c = signed_in()
    r = main._load_result()
    mine = next(a for a in r["alerts"] if a["client"] == BANK and r["verdicts"][a["alert_id"]].get("escalate"))
    page = c.get(f"/alert/{mine['alert_id']}").text
    token = re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)
    done = c.post("/alert/resolve", data={"alert_id": mine["alert_id"], "outcome": "expected", "note": "a planned test",
                                          "csrf": token}, follow_redirects=False)
    assert done.status_code == 303
    out = work_until_done()
    touched = set(main._CACHE["second"]) | set(main._CACHE["agent"])
    by_id = {a["alert_id"]: a for a in main._load_result()["alerts"]}
    assert not any(by_id[i]["client"] in main._test_clients() for i in touched), "a test stream is not a customer"
    assert mine["alert_id"] not in touched, "a person decided it: the model is not asked afterwards"
    # the mix is that of the alerts the connected tool sent: not the samples, not the test stream
    assert out["mix"] == {"total": 3, "own": 2, "raised": 1, "repeats": 0, "by_people": 1, "gave_up": 0}
    own, raised, _ = sorted_queue()
    assert out["read"] == len(own) and out["investigated"] == len(raised) - 1, "the samples are read and investigated all the same"


def test_a_doubted_closure_is_investigated_once_for_its_kind_and_the_rest_are_counted_under_it(monkeypatch):
    """Found on the live feed on 28 November: of the first 82 closures read, 33
    were flagged, most for the tool's rating alone, and the same routine event
    on the same laptop was being investigated again each time it fired. At
    2.8 cents an investigation, a thousand alerts would have cost nine dollars."""
    policy = examples.EXAMPLES["wazuh"][1]["raw"]                            # a probe file Wazuh rates critical: closed
    title = main.normalize("wazuh", policy, BANK).title
    calls = a_model(monkeypatch, reading=BENIGN, doubt=(title,))
    work_until_done()                                                        # the samples first, out of the way
    same = [dict(policy, id=f"1795900{n}.1") for n in range(4)]
    assert send(*same) == 4
    r = main._load_result()
    mine = [a["alert_id"] for a in r["alerts"] if a["client"] == BANK]
    assert len(mine) == 4 and not any(r["verdicts"][i].get("escalate") for i in mine), "four closures of one kind"
    before, asked = main._arrival_view(), calls["reading"]
    out = work_until_done()
    assert out["looks"] - before["looks"] == 4, "the reading doubted all four"
    assert out["investigated"] - before["investigated"] == 1 and out["same"] == 3, "one investigation stands for the kind"
    assert calls["reading"] - asked == 2, "the evidence was read twice, for one alert"
    second = main._CACHE["second"]
    first = next(i for i in mine if i in main._CACHE["agent"])
    assert all(second[i]["same_as"] == first for i in mine if i != first) and "same_as" not in second[first]
    assert out["waiting"] == {"need": 0, "look": 0, "read": 0}
    c = signed_in()
    other = next(i for i in mine if i != first)
    page = c.get(f"/alert/{other}").text
    assert "an alert of the same kind" in page and f'/alert/{first}#agent' in page
    made = {row["id"]: row["model"] for row in c.get("/api/live").json()["rows"]}
    assert made[other]["words"] == "Agrees, by its kind" and made[first]["state"] == "run"
    assert "Counted under an investigation of their kind" in c.get("/").text
    # a different machine is a different kind
    elsewhere = json.loads(json.dumps(policy))
    elsewhere["id"], elsewhere["agent"]["name"] = "17959009.1", "OTHER-LAPTOP"
    assert send(elsewhere) == 1
    out2 = work_until_done()
    assert out2["investigated"] - out["investigated"] == 1 and out2["same"] == 3
    # and an agreement stands for a week, not for ever
    for k in main._arrival()["kinds"].values():
        k["at"] = "2026-11-01T00:00:00Z"
    assert send(dict(policy, id="17959010.1")) == 1
    out3 = work_until_done()
    assert out3["investigated"] - out2["investigated"] == 1 and out3["same"] == 3


def test_investigations_kept_before_this_was_built_stand_for_their_kind_too(monkeypatch):
    policy = examples.EXAMPLES["wazuh"][1]["raw"]
    title = main.normalize("wazuh", policy, BANK).title
    a_model(monkeypatch, reading=BENIGN, doubt=(title,))
    work_until_done()
    assert send(dict(policy, id="17959020.1")) == 1
    work_until_done()                                                        # read, doubted, investigated, agreed
    first = next(a["alert_id"] for a in main._load_result()["alerts"] if a["client"] == BANK)
    assert first in main._CACHE["agent"]
    main._arrival()["kinds"].clear()                                         # as on a deployment that kept runs before 0.11.4
    main._CACHE.pop("kinds_seeded", None)
    assert send(dict(policy, id="17959021.1"), dict(policy, id="17959022.1")) == 2
    before = main._arrival_view()
    out = work_until_done()
    assert out["investigated"] == before["investigated"] and out["same"] - before["same"] == 2


def test_an_investigation_that_disagreed_stands_for_nothing_so_each_of_its_kind_is_investigated(monkeypatch):
    policy = examples.EXAMPLES["wazuh"][1]["raw"]
    title = main.normalize("wazuh", policy, BANK).title
    a_model(monkeypatch, reading=SUSPICIOUS, doubt=(title,))
    assert send(*[dict(policy, id=f"1795901{n}.1") for n in range(3)]) == 3
    out = work_until_done()
    r = main._load_result()
    mine = [a["alert_id"] for a in r["alerts"] if a["client"] == BANK]
    assert out["same"] == 0 and main._arrival()["kinds"] == {}
    assert all(i in main._CACHE["agent"] and r["verdicts"][i]["escalate"] for i in mine), "all three went to a person"


def test_the_second_reader_is_told_that_a_tools_rating_is_not_a_reason_by_itself():
    assert "The tool's own rating is not such a reason by itself" in nightshift.SECOND_SYSTEM
    assert "an outside address the reason does not account for" in nightshift.SECOND_SYSTEM
    assert "tool rating of high or critical" not in nightshift.SECOND_SYSTEM


# ---- what it costs, and where it stops ---------------------------------------------

def test_the_cost_is_counted_by_job_from_the_token_counts(monkeypatch):
    calls = a_model(monkeypatch)
    out = work_until_done()
    assert out["usd_read"] == pytest.approx(calls["read"] * ONE_CALL, abs=1e-4)
    assert out["usd_account"] == pytest.approx(calls["account"] * ONE_CALL, abs=1e-4)
    assert out["usd_investigate"] == pytest.approx((calls["plan"] + calls["reading"]) * ONE_CALL, abs=1e-4)
    assert out["usd"] == pytest.approx(len(calls["seen"]) * ONE_CALL, abs=1e-3) == pytest.approx(out["today_usd"], abs=1e-3)
    # too few closures read to say what one costs, so no figure for a thousand alerts is made up
    assert out["read"] < main.ARRIVAL_READS_ENOUGH and out["usd_one_read"] is None and out["per_1000_usd"] is None
    assert out["usd_one_investigation"] == pytest.approx((out["usd_investigate"] + out["usd_account"]) / out["investigated"], abs=1e-4)
    # with enough of both, the figure is the queue's own mix at the measured cost of each job
    monkeypatch.setattr(main, "ARRIVAL_READS_ENOUGH", 5)
    out = main._arrival_view()
    mix = out["mix"]
    assert mix["total"] == len(main._load_result()["alerts"]), "no tool is connected, so the mix is the samples'"
    one_read = out["usd_read"] / out["read"]
    one_run = (out["usd_investigate"] + out["usd_account"]) / out["investigated"]
    assert out["per_1000_usd"] == pytest.approx(1000 * (mix["own"] * one_read + mix["raised"] * one_run) / mix["total"], abs=0.01)


def test_the_days_budget_stops_the_work_and_midnight_in_india_starts_it_again(monkeypatch):
    calls = a_model(monkeypatch)
    monkeypatch.setenv("TRIAGLE_ARRIVAL_DAILY_USD", str(ONE_CALL * 2.5))     # the third call takes it over
    out = main.arrival_work()
    assert len(out["did"]) == 1 and "budget is spent" in out["paused"]
    assert out["today_usd"] >= out["cap_usd"] and out["waiting"]["need"] > 0
    asked = len(calls["seen"])
    assert main.arrival_work()["did"] == [] and len(calls["seen"]) == asked, "nothing more is spent today"
    page = signed_in().get("/").text
    assert "paused" in page and "budget is spent" in page
    main._arrival()["day"] = "2026-11-27"                                    # yesterday, in India
    out = main.arrival_work()
    assert len(out["did"]) >= 1 and len(calls["seen"]) > asked
    assert out["usd"] > out["today_usd"], "the running total is kept; the day starts again"


def test_the_alerts_that_were_already_here_are_investigated_and_read_in_turn(monkeypatch):
    """Switched on over a week of alerts on 28 November, the work spent its first
    hour on investigations alone, and nothing said what reading a closure cost."""
    a_model(monkeypatch)
    did = []
    for _ in range(6):
        out = main.arrival_work(seconds=0.001)                               # one piece a round
        did += out["did"]
    kinds = ["read" if d.startswith("read") else "investigated" for d in did]
    assert kinds[:4] == ["investigated", "read", "investigated", "read"], kinds
    # an alert that arrives now goes ahead of both
    assert send(examples.EXAMPLES["wazuh"][0]["raw"]) == 1
    assert "Powershell.exe" in main.arrival_work(seconds=0.001)["did"][0]


def test_a_backlog_never_takes_the_whole_day_so_a_new_alert_does_not_wait(monkeypatch):
    calls = a_model(monkeypatch)
    monkeypatch.setenv("TRIAGLE_ARRIVAL_DAILY_USD", str(ONE_CALL * 12))       # seven calls' worth for what was already here
    out = work_until_done()
    assert 0 < out["investigated"] < len(sorted_queue()[1]), "the backlog stopped part of the way"
    assert out["cap_usd"] * main.ARRIVAL_BACKLOG_SHARE <= out["today_usd"] < out["cap_usd"]
    assert "already here" in out["paused"] and "New alerts are still read" in out["paused"]
    asked = len(calls["seen"])
    assert send(examples.EXAMPLES["wazuh"][1]["raw"]) == 1                    # a closure arrives now
    out = main.arrival_work()
    assert out["did"] == ["read 1 closure"] and len(calls["seen"]) == asked + 1
    r = main._load_result()
    new = next(a for a in r["alerts"] if a["client"] == BANK)
    assert main._CACHE["second"][new["alert_id"]]["auto"], "the new alert was read out of the share kept for today"
    assert out["waiting"]["need"] > 0 and "already here" in out["paused"], "the backlog still waits for tomorrow"
    main._arrival()["day"] = "2026-11-27"
    assert len(main.arrival_work()["did"]) >= 1, "and goes on the next day"


def test_a_model_that_does_not_answer_pauses_the_work_and_no_alert_is_blamed(monkeypatch):
    a_model(monkeypatch, answers=False)
    out = main.arrival_work()
    assert len(out["did"]) == 1 and out["failed"] == 1 and "did not answer" in out["paused"]
    assert main._arrival()["tried"] == {} and out["mix"]["gave_up"] == 0
    assert main.arrival_work()["did"] == [], "it waits before asking again"
    calls = a_model(monkeypatch)                                             # the model is back
    main._arrival()["pause_until"] = 0
    out = work_until_done()
    assert out["waiting"] == {"need": 0, "look": 0, "read": 0} and calls["read"] > 0


def test_an_answer_that_cannot_be_used_is_asked_for_once_more_and_then_the_alert_is_left_alone(monkeypatch):
    calls = a_model(monkeypatch, garbled=True)
    own, raised, _ = sorted_queue()
    out = work_until_done()
    assert out["read"] == 0 and out["investigated"] == len(raised), "the investigations still got their readings"
    assert out["mix"]["gave_up"] == len(own) and out["waiting"]["read"] == 0
    by_client = {}
    for a in own:
        by_client[a["client"]] = by_client.get(a["client"], 0) + 1
    # each customer's batch once, then again a few at a time, and no more
    again = sum(-(-n // main.ARRIVAL_AGAIN) for n in by_client.values())
    assert calls["read"] == len(by_client) + again
    assert main._CACHE["second"] == {}, "no reading is made up for a closure the model could not read"
    asked = calls["read"]
    assert main.arrival_work()["did"] == [] and calls["read"] == asked
    main._arrival()["day"] = "2026-11-27"                                    # the next day they are asked about again
    assert main._arrival_view()["waiting"]["read"] == len(own)


def test_one_round_at_a_time(monkeypatch):
    calls = a_model(monkeypatch)
    assert main._ARRIVAL_BUSY.acquire(blocking=False)
    try:
        out = main.arrival_work()
    finally:
        main._ARRIVAL_BUSY.release()
    assert out["busy"] is True and out["did"] == [] and calls["seen"] == []


# ---- who may start it --------------------------------------------------------------

def test_the_work_is_started_by_a_key_or_by_a_signed_in_analyst_and_by_nobody_else(monkeypatch):
    a_model(monkeypatch)
    monkeypatch.setenv("TRIAGLE_ARRIVAL_SECONDS", "1")
    anon = TestClient(main.app)
    assert anon.post("/api/work").status_code == 401
    assert anon.post("/api/work", headers={"X-Triagle-Key": "wrong"}).status_code == 401
    monkeypatch.setenv("TRIAGLE_GUEST", "view")
    assert TestClient(main.app).post("/api/work", json={}).status_code == 401, "a guest starts nothing"
    monkeypatch.delenv("TRIAGLE_GUEST")
    r = anon.post("/api/work", headers={"X-Triagle-Key": KEY})
    assert r.status_code == 200 and r.json()["on"] and r.json()["did"]
    monkeypatch.setattr(main, "WORK_KEY", "a-key-for-the-scheduler")
    assert anon.post("/api/work", headers={"X-Triagle-Key": "a-key-for-the-scheduler"}).status_code == 200
    monkeypatch.setattr(main, "WORK_KEY", "short")
    assert anon.post("/api/work", headers={"X-Triagle-Key": "short"}).status_code == 401, "a short key is not a key"
    c = signed_in()
    assert c.post("/api/work", json={"csrf": "nope"}).status_code == 403
    token = re.search(r'name="csrf" value="([0-9a-f]+)"', c.get("/checks").text).group(1)
    assert c.post("/api/work", json={"csrf": token}).status_code == 200
    assert any(e["event"] == "work done on arrival" and e["user"] == "scheduler" for e in audit.read())
    assert anon.get("/api/arrival", follow_redirects=False).status_code in (303, 401), "the figures need a sign-in or a guest pass"
    assert c.get("/api/arrival").json()["on"] is True


def test_the_cost_of_a_thousand_alerts_uses_everything_the_tools_sent_not_only_what_is_still_held(monkeypatch):
    """Found on the live feed on 28 November: closed alerts age out of the queue
    before raised ones do, so of 1,500 alerts held 90 were for a person, where
    the tools had sent well over 3,000. Priced on the queue alone, a thousand
    alerts would have looked about twice as dear as they are."""
    a_model(monkeypatch)
    monkeypatch.setattr(main, "ARRIVAL_READS_ENOUGH", 2)
    monkeypatch.setattr(main, "ARRIVAL_RUNS_ENOUGH", 1)
    assert send(*[e["raw"] for e in examples.EXAMPLES["wazuh"]]) == 3
    held = work_until_done()
    assert held["stream"] == {"total": 3, "own": 2, "raised": 1, "repeats": 0}
    main._CACHE["rolled"] = {"total": 97, "closed": 96, "escalated": 1, "codes": {"BENIGN_DUPLICATE": 40, "BENIGN_EXPECTED": 56}}
    out = main._arrival_view()
    assert out["stream"] == {"total": 100, "own": 58, "raised": 2, "repeats": 40}
    assert out["mix"]["total"] == 3, "what is held is still counted as what is held"
    one_read, one_run = out["usd_read"] / out["read"], (out["usd_investigate"] + out["usd_account"]) / out["investigated"]
    assert out["per_1000_usd"] == pytest.approx(1000 * (58 * one_read + 2 * one_run) / 100, abs=0.01)
    assert out["per_1000_usd"] < held["per_1000_usd"] / 5


# ---- what a person sees ------------------------------------------------------------

def test_the_overview_and_the_alert_page_say_what_was_done_without_being_asked(monkeypatch):
    a_model(monkeypatch)
    out = work_until_done()
    own, raised, _ = sorted_queue()
    c = signed_in()
    page = c.get("/").text
    assert "<h2>Gemini on every alert</h2>" in page and "read by Gemini without being asked" in page
    assert f"<b>{out['covered']}</b>" in page and "Closures read again" in page and "Alerts investigated in full" in page
    assert "It can never close one." in page
    closed = c.get(f"/alert/{own[0]['alert_id']}").text
    assert "agrees with the closure" in closed and "Read without being asked" in closed
    opened = c.get(f"/alert/{raised[0]['alert_id']}").text
    run = json.loads(re.search(r"data-run='([^']+)'", opened).group(1).replace("&#34;", '"').replace("&#39;", "'"))
    assert run["auto"] is True and run["by"] == main.ARRIVAL_NAME
    assert "Triagle ran this without being asked" in opened
    note = c.get("/api/notes", params={"alert": raised[0]["alert_id"]}).json()
    assert note["by_model"] and re.fullmatch(r"\d\d \w{3}, \d\d:\d\d", note["unasked"])
    assert "without being asked, ' + j.unasked" in opened
    assert "Triagle, on arrival" in c.get("/checks").text
    report = c.get("/pilot").text
    assert "Read by the model without being asked" in report and f"{out['investigated']} alerts investigated in full" in report


def test_the_public_page_on_data_handling_says_what_the_model_reads_on_this_deployment(monkeypatch):
    anyone = TestClient(main.app)
    monkeypatch.delenv("TRIAGLE_ARRIVAL")
    a_model(monkeypatch)
    off = anyone.get("/security").text
    assert "No model is called to sort the alerts that nobody opens." in off and "It reads every alert" not in off
    monkeypatch.setenv("TRIAGLE_ARRIVAL", "on")
    on = anyone.get("/security").text
    assert "No model is called to sort" not in on, "that would no longer be true here"
    assert "It reads every alert, after the verdict" in on and "It can never close one." in on
    assert "For every alert that needs a decision, and whenever an analyst asks," in on
    assert "What a visitor says on the Try page" in on and "what guests may cost the model in a day is limited" in on
    monkeypatch.setattr(genai, "configured", lambda: False)                  # switched on, but no model to do it
    assert "No model is called to sort the alerts that nobody opens." in anyone.get("/security").text


def test_the_live_page_shows_what_the_model_made_of_each_alert_as_it_lands(monkeypatch):
    a_model(monkeypatch, reading=SUSPICIOUS, doubt=("cmd shell",))
    c = signed_in()
    assert send(*[e["raw"] for e in examples.EXAMPLES["wazuh"]]) == 3
    before = c.get("/api/live").json()
    assert before["model_column"] and before["model_word"] == "Gemini"
    assert [r["model"]["state"] for r in before["rows"]] == ["waiting"] * 3, "arrived, decided by rule, not yet read"
    work_until_done()
    after = c.get("/api/live").json()
    assert after["rev"] != before["rev"], "the page is told there is something new to draw"
    made = {r["said"]: r["model"] for r in after["rows"]}
    raised = made["Powershell.exe spawned a powershell process which executed a base64 encoded command"]
    assert raised["state"] == "run" and raised["words"] == "Agrees" and raised["sub"].startswith("Suspicious, 85%. ")
    assert raised["sub"].endswith("s after arrival")
    agreed = made["Executable file dropped in folder commonly used by malware"]
    assert (agreed["state"], agreed["words"], agreed["tag"]) == ("read", "Agrees", "ok") and agreed["sub"]
    doubted = made["Suspicious Windows cmd shell execution"]
    assert doubted["state"] == "run" and doubted["words"] == "Sent to a person" and doubted["tag"] == "warn", \
        "the reading doubted the closure, the investigation disagreed with it, and a person now decides"
    assert after["counts"]["by_model"] == main._arrival()["read"] + main._arrival()["investigated"] > 0
    page = c.get("/live").text
    assert "What Gemini made of it" in page and "read by ' + state.model_word + ' without being asked.'" in page
    # with the work switched off and nothing read, the column is not drawn at all
    for store in (main._CACHE, main._WORKNOTES):
        store.clear()
    monkeypatch.delenv("TRIAGLE_ARRIVAL")
    send(examples.EXAMPLES["wazuh"][1]["raw"])
    off = c.get("/api/live").json()
    assert off["model_column"] is False and off["rows"][0]["model"] is None


def test_a_test_stream_is_read_too_when_asked_and_what_it_costs_is_in_no_measured_figure(monkeypatch):
    calls = a_model(monkeypatch)
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    before = work_until_done()                                               # the samples, read and investigated
    stream = demo_attack.fresh_benign() + demo_attack.fresh_attack()
    assert send(*[i["raw"] for i in stream[:1]], client=demo_attack.DEFAULT_CLIENT, source=stream[0]["source"]) == 1
    c = signed_in()
    assert c.get("/api/live").json()["rows"][0]["model"] is None, "a test stream is left alone unless asked"
    assert work_until_done()["did"] == []
    monkeypatch.setenv("TRIAGLE_ARRIVAL_TESTS", "on")
    for item in stream[1:]:
        assert send(item["raw"], client=demo_attack.DEFAULT_CLIENT, source=item["source"]) == 1
    rows = c.get("/api/live").json()["rows"]
    assert all(r["test"] for r in rows) and "waiting" in {(r["model"] or {}).get("state") for r in rows}
    asked = len(calls["seen"])
    out = work_until_done()
    assert len(calls["seen"]) > asked and out["tests"] >= len(stream) - 1 and out["usd_tests"] > 0
    # nothing measured moved: not the counts, not the cost of a closure or an investigation, not the mix
    for k in ("read", "reads", "investigated", "accounts", "raised", "usd_read", "usd_investigate", "usd_account",
              "usd_one_investigation", "covered", "mix", "stream", "typical_wait_s"):
        assert out[k] == before[k], k
    assert out["usd"] == pytest.approx(before["usd"] + out["usd_tests"], abs=1e-3), "the total spent says all of it"
    assert main._arrival()["waits"] == [], "a test stream's wait is not a feed's"
    rows = c.get("/api/live").json()["rows"]
    states = {(r["model"] or {}).get("state") for r in rows}
    assert states <= {"run", "read", "under"} and "run" in states, states
    assert any("after arrival" in r["model"]["sub"] for r in rows if r["model"]["state"] == "run")
    # an analyst's Live page starts the work at once; a guest's does not, and a guest could not
    assert "var canNudge = true" in c.get("/live").text
    monkeypatch.setenv("TRIAGLE_GUEST", "view")
    guest = TestClient(main.app)
    assert "var canNudge = false" in guest.get("/live").text and guest.post("/api/work", json={}).status_code == 401
    # clearing the test alerts takes what the model made of them along
    ids = {r["id"] for r in rows}
    assert ids & (set(main._CACHE["agent"]) | set(main._CACHE["second"]))
    token = re.search(r'name="csrf" value="([0-9a-f]+)"', c.get("/live").text).group(1)
    assert c.post("/demo/reset", data={"csrf": token, "next": "live"}, follow_redirects=False).status_code == 303
    kept = set(main._CACHE["agent"]) | set(main._CACHE["second"]) | set(main._arrival()["done"]) | set(main._arrival()["notes"])
    assert not ids & kept and kept, "the customers' own records stay"


def test_an_alert_that_arrives_after_the_work_began_has_its_wait_measured(monkeypatch):
    a_model(monkeypatch)
    work_until_done()
    assert main._arrival()["waits"] == [], "the alerts that were already there say nothing about the wait"
    assert send(*[e["raw"] for e in examples.EXAMPLES["wazuh"]]) == 3
    out = work_until_done()
    assert len(main._arrival()["waits"]) == 3 and all(0 <= w < 60 for w in main._arrival()["waits"])
    r = main._load_result()
    new = next(a for a in r["alerts"] if a["client"] == BANK and r["verdicts"][a["alert_id"]].get("escalate"))
    assert main._CACHE["agent"][new["alert_id"]]["after_s"] < 60
    assert out["typical_wait_s"] is None, "three alerts are too few to call anything typical"
    main._arrival()["waits"] = [30, 40, 50, 60, 200]
    assert main._arrival_view()["typical_wait_s"] == 50


# ---- a restart ---------------------------------------------------------------------

def test_the_record_the_readings_and_the_accounts_survive_a_restart(monkeypatch, tmp_path):
    monkeypatch.setenv("TRIAGLE_STATE_FILE", str(tmp_path / "data" / "state.json.gz"))
    calls = a_model(monkeypatch)
    assert send(*[e["raw"] for e in examples.EXAMPLES["wazuh"]]) == 3
    before = work_until_done()
    r = main._load_result()
    mine = next(a for a in r["alerts"] if a["client"] == BANK and r["verdicts"][a["alert_id"]].get("escalate"))
    seed = next(a for a in r["alerts"] if a["client"] != BANK and r["verdicts"][a["alert_id"]].get("escalate"))
    for store in (main._CACHE, main._WORKNOTES, main._NOTES_AT):             # the process starts again
        store.clear()
    after = main._arrival_view()
    for k in ("read", "reads", "investigated", "accounts", "usd", "usd_read", "usd_investigate", "usd_account", "since"):
        assert after[k] == before[k], k
    assert after["waiting"] == {"need": 0, "look": 0, "read": 0}, "nothing is read or investigated a second time"
    asked = len(calls["seen"])
    assert main.arrival_work()["did"] == [] and len(calls["seen"]) == asked
    c = signed_in()
    for a in (mine, seed):                                                   # a live alert, and one loaded with the product
        note = c.get("/api/notes", params={"alert": a["alert_id"]}).json()
        assert note["by_model"] and note["unasked"] and note["text"].startswith("What happened")
    assert len(calls["seen"]) == asked, "the account written on arrival is shown, not written again"
    assert "Read without being asked" in c.get(f"/alert/{next(iter(main._CACHE['second']))}").text


def test_a_saved_record_that_cannot_be_read_starts_from_nothing():
    main._load_result()
    main._arrival_restore({"read": "many", "tried": [1, 2]})
    assert main._arrival()["read"] == 0 and main._arrival()["tried"] == {}
    main._arrival_restore({"read": 7, "usd_read": 0.5, "notes": {"x": {"k": [True, None]}}})
    assert main._arrival()["read"] == 0, "one bad part and none of it is taken"
    main._arrival_restore({"read": 7, "usd_read": 0.5, "done": {"a": 1}, "waits": [3, "4"], "day": "2026-11-28"})
    a = main._arrival()
    assert (a["read"], a["usd_read"], a["done"], a["waits"], a["day"]) == (7, 0.5, {"a": 1}, [3, 4], "2026-11-28")
