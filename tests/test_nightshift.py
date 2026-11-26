"""The night analyst's paperwork, and the model's second reading.

    python -m pytest -q tests/test_nightshift.py

One analyst on a night shift watches the queue, writes the report for the
morning call, mails users to ask "was this you?", and writes the handover.
Triagle's engine does the first. The model does the writing for the other
three, from what the engine decided and from what this customer's analysts
decided before. It can also read back over closures and say which a person
should check first. It never changes a verdict and never sends anything.
"""
import datetime as dt
import json

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main
from app.engine import analyst, genai, nightshift, worknotes
from tests.test_bursts import update, T0
from tests.test_checks import routine

KEY = "nk"


def _secs(when):
    return int((when - T0.replace(tzinfo=dt.timezone.utc)).total_seconds())


@pytest.fixture
def model(monkeypatch):
    """A stand-in for Gemini that records what it is sent."""
    box = {"calls": [], "reply": None}

    def fake(system, user, max_tokens=4096, temperature=0.2, timeout=60, again_on_timeout=False):
        box["calls"].append({"system": system, "user": user, "temperature": temperature, "wait": (timeout, again_on_timeout)})
        reply = box["reply"](system, user) if callable(box["reply"]) else box["reply"]
        return (reply, "vertex") if reply else (None, None)

    monkeypatch.setattr(genai, "generate_prose", fake)
    monkeypatch.setattr(genai, "configured", lambda: True)
    return box


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
    main._MORNING.clear()
    main._ASK_TIMES.clear()
    main._ASK_ALL.clear()
    c = TestClient(main.app)
    c.post("/login", data={"username": "admin", "password": "pw"})
    start = _secs(dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(minutes=30))
    assert c.post("/ingest", headers={"X-Triagle-Key": KEY},
                  json=routine(start) + update(start=start + 200)).json()["accepted"] == 32
    yield c
    main._CACHE.clear()
    main._MORNING.clear()
    auth.load_config()


def _viewer():
    v = TestClient(main.app)
    v.post("/login", data={"username": "jury", "password": "look"})
    return v


def _csrf(page):
    return page.split('name="csrf" value="')[1].split('"')[0]


# ---- house knowledge ---------------------------------------------------------------

def test_house_knowledge_is_this_customers_rules_and_decisions_only():
    taught = [{"id": "TR-1", "client": "Bank A", "on": True, "title": "New dpkg installed", "host": "srv1", "user": "",
               "label": "Expected activity", "note": "Monthly patching"},
              {"id": "TR-2", "client": "Bank B", "on": True, "title": "Other", "host": "x", "label": "Expected activity"},
              {"id": "TR-3", "client": "Bank A", "on": False, "title": "Old", "host": "srv2", "label": "False positive"}]
    decided = [{"title": "File deleted", "host": "srv1", "label": "False positive", "note": "Deployment", "by": "meera"}]
    text = nightshift.house_knowledge("Bank A", taught, decided)
    assert "TR-1" in text and "Monthly patching" in text and "meera judged 'File deleted' on srv1: false positive" in text
    assert "TR-2" not in text and "TR-3" not in text, "another customer's rule and a rule switched off are left out"
    assert nightshift.house_knowledge("Bank C", taught, []) == ""
    assert len(nightshift.house_knowledge("Bank A", taught, decided * 40).splitlines()) == nightshift.HOUSE_LINES


def test_the_case_account_and_the_answers_read_the_house_knowledge(model):
    model["reply"] = "What happened: a thing."
    incident = {"key": "srv1", "client": "Bank A", "sources": ["wazuh"], "id": "INC-1"}
    members = [{"alert": {"timestamp": "2026-11-25T10:00:00Z", "source": "wazuh", "title": "File deleted", "host": "srv1"},
                "verdict": {"disposition": "needs_human", "escalate": True}}]
    worknotes.work_notes(incident, members, house="- Standing rule TR-1: 'File deleted' on srv1 is expected activity.")
    assert "HOUSE KNOWLEDGE" in model["calls"][-1]["user"] and "TR-1" in model["calls"][-1]["user"]
    worknotes.work_notes(incident, members)
    assert "HOUSE KNOWLEDGE" not in model["calls"][-1]["user"]
    analyst.ask("What happened?", incident, members, house="- meera judged 'File deleted' on srv1: false positive.")
    sent = model["calls"][-1]["user"]
    assert "HOUSE KNOWLEDGE" in sent and "meera judged" in sent and sent.index("CASE EVIDENCE") < sent.index("HOUSE KNOWLEDGE")


# ---- the second reading ------------------------------------------------------------

def test_a_second_reading_is_read_strictly_and_never_guessed():
    good = '```json\n[{"n": 1, "view": "agree", "why": "Routine session."}, {"n": 2, "view": "LOOK", "why": "Root  ran  an unusual program."}]\n```'
    assert nightshift.parse_second(good, 2) == {1: {"view": "agree", "why": "Routine session."},
                                                 2: {"view": "look", "why": "Root ran an unusual program."}}
    assert nightshift.parse_second("I think they are all fine.", 3) == {}
    assert nightshift.parse_second('[{"n": 9, "view": "agree"}, {"n": "x", "view": "look"}, {"n": 1, "view": "close it"}, 7]', 2) == {}
    assert nightshift.parse_second('[{"n": 1, "view": "agree", "why": "a"}, {"n": 1, "view": "look", "why": "b"}]', 1)[1]["view"] == "agree"
    assert nightshift.parse_second("[not json]", 1) == {}


def test_the_second_reader_is_sent_masked_alerts_and_changes_nothing(model):
    a = {"alert_id": "wz-1", "title": "PAM: Login session opened.", "raw_severity": "low", "host": "srv1",
         "user": "ravi.k@greenvale.example", "indicators": {"rule_level": 3}}
    v = {"reasoning": "Low-severity routine event.", "closure_code": "BENIGN_EXPECTED", "escalate": False}
    model["reply"] = '[{"n": 1, "view": "look", "why": "Worth a glance."}]'
    found, provider, error = nightshift.second_read([(a, dict(v))], house="- Standing rule TR-1: x")
    assert found == {"wz-1": {"view": "look", "why": "Worth a glance."}} and error is None and provider
    sent = model["calls"][-1]
    assert "ravi.k@greenvale.example" not in sent["user"], "an email address is masked before it leaves"
    assert "HOUSE KNOWLEDGE" in sent["user"] and sent["temperature"] == 0
    assert v["escalate"] is False and v["closure_code"] == "BENIGN_EXPECTED"

    model["reply"] = "no list here"
    assert nightshift.second_read([(a, v)])[2] == "The model's reply could not be read as a list."
    model["reply"] = None
    found, provider, error = nightshift.second_read([(a, v)])
    assert found == {} and provider is None and error
    assert nightshift.second_read([]) == ({}, None, None)


def test_asking_gemini_to_read_the_sample_orders_it_and_survives_a_restart(app, model):
    def reply(system, user):
        n = user.count("\n   Closed because:")
        return json.dumps([{"n": i + 1, "view": "look" if i == n - 1 else "agree", "why": f"reason {i + 1}"}
                           for i in range(n)])
    model["reply"] = reply
    page = app.get("/checks").text
    assert "Ask Gemini to read these" in page and "Not read yet" in page
    r = app.post("/checks/read", data={"csrf": _csrf(page)}, follow_redirects=False)
    assert r.headers["location"] == "/checks?read=ok"
    second = main._CACHE["second"]
    assert len(second) == 8 and sum(1 for v in second.values() if v["view"] == "look") == 1
    res = main._load_result()
    assert all(not res["verdicts"][aid]["escalate"] for aid in second), "a second reading changes no verdict"

    page = app.get("/checks?read=ok").text
    assert "listed first" in page and "Look again" in page and "Agrees" in page
    assert page.index("Look again") < page.index("Agrees"), "what the model would look at again comes first"
    assert "Gemini has read <b>8</b> as a second reader and would look again at <b>1</b>" in page
    flagged = next(aid for aid, v in second.items() if v["view"] == "look")
    assert "would look at it again" in app.get(f"/alert/{flagged}").text
    assert "Gemini has read 8 closures as a second reader" in app.get("/pilot").text
    entry = next(e for e in audit.read() if e["event"] == "closures read by the model")
    assert entry["asked"] == 8 and entry["answered"] == 8 and entry["would_look_again"] == 1

    calls = len(model["calls"])
    r = app.post("/checks/read", data={"csrf": _csrf(page)}, follow_redirects=False)
    assert r.headers["location"] == "/checks?read=none" and len(model["calls"]) == calls, "nothing is read twice"

    main._CACHE.clear()                                   # a restart
    assert len(main._load_result() and main._CACHE["second"]) == 8


def test_a_failed_reading_stores_nothing_and_a_viewer_cannot_ask(app, model):
    model["reply"] = None
    page = app.get("/checks").text
    r = app.post("/checks/read", data={"csrf": _csrf(page)}, follow_redirects=False)
    assert r.headers["location"] == "/checks?read=failed" and main._CACHE["second"] == {}
    assert "did not answer" in app.get("/checks?read=failed").text
    assert app.post("/checks/read", data={"csrf": "wrong"}, follow_redirects=False).status_code == 403
    viewer = _viewer()
    assert "Ask Gemini to read these" not in viewer.get("/checks").text
    assert viewer.post("/checks/read", data={"csrf": "x"}, follow_redirects=False).status_code == 403


# ---- "was this you?" ---------------------------------------------------------------

FACTS = {"user": "deploy", "host": "wazuh-demo", "when": "25 Nov 2026, 21:24 IST",
         "what": "A sign-in session was opened", "src_ip": "203.0.113.9", "customer": "Greenvale Co-operative Bank"}


def test_the_follow_up_is_the_models_when_well_formed_and_a_template_when_not(model):
    model["reply"] = "Subject: Please confirm a sign-in on your account\n\nHello,\n\nWe saw a sign-in.\n\nSecurity Operations"
    out = nightshift.followup(FACTS)
    assert out["by_model"] and out["subject"] == "Please confirm a sign-in on your account"
    assert out["body"].startswith("Hello,") and out["body"].endswith("Security Operations")
    sent = model["calls"][-1]["user"]
    assert "Account: deploy" in sent and "203.0.113.9" in sent and "never ask for their password" in model["calls"][-1]["system"]

    for bad in ("Hello, was this you?", "Subject: only a subject", None):
        model["reply"] = bad
        out = nightshift.followup(FACTS)
        assert not out["by_model"] and out["provider"] == "template"
        assert "deploy" in out["subject"] and "25 Nov 2026, 21:24 IST" in out["body"]
        assert "We will never ask for your password" in out["body"] and "203.0.113.9" in out["body"]
        assert "http" not in out["body"], "no links in a message that asks someone to trust it"


def test_an_analyst_drafts_a_follow_up_for_an_alert_that_names_an_account(app, model):
    model["reply"] = "Subject: Was this you?\n\nHello,\n\nPlease confirm.\n\nSecurity Operations"
    res = main._load_result()
    signin = next(a for a in res["alerts"] if a.get("user") == "deploy")
    nobody = next(a for a in res["alerts"] if not a.get("user"))
    token = _csrf(app.get("/checks").text)
    # a person disagrees with the closure, so the alert is back in the queue and can be followed up
    app.post("/checks/mark", data={"alert_id": signin["alert_id"], "agree": "no", "csrf": token})
    page = app.get(f"/alert/{signin['alert_id']}").text
    assert "Ask the user" in page and "Draft the message" in page

    r = app.post("/api/followup", data={"alert_id": signin["alert_id"], "csrf": token})
    assert r.status_code == 200 and r.json()["subject"] == "Was this you?" and r.json()["by_model"] is True
    sent = model["calls"][-1]["user"]
    assert "Account: deploy" in sent and "Machine: wazuh-demo" in sent and "IST" in sent
    entry = next(e for e in audit.read() if e["event"] == "follow-up message drafted")
    assert entry["to_account"] == "deploy" and entry["by_model"] is True

    assert app.post("/api/followup", data={"alert_id": nobody["alert_id"], "csrf": token}).status_code == 400
    assert app.post("/api/followup", data={"alert_id": "wz-nope", "csrf": token}).status_code == 404
    assert app.post("/api/followup", data={"alert_id": signin["alert_id"], "csrf": "wrong"}).status_code == 403
    viewer = _viewer()
    assert "Ask the user" not in viewer.get(f"/alert/{signin['alert_id']}").text
    assert viewer.post("/api/followup", data={"alert_id": signin["alert_id"], "csrf": "x"}).status_code == 403


# ---- the morning report ------------------------------------------------------------

def test_the_morning_report_has_the_figures_the_questions_and_the_handover(app, model):
    page = app.get("/morning").text
    assert "Morning report" in page and "Prepared for Greenvale Co-operative Bank" in page
    assert "The last 12 hours" in page and "For the day shift" in page and "Needs an answer" in page
    assert "32 alerts arrived in the last 12 hours" in page, "the plain summary is on the page before the model answers"
    assert "Software installed or changed on a server" in page
    assert app.get("/morning?hours=24").text.count("The last 24 hours") == 1
    assert "The last 12 hours" in app.get("/morning?hours=5&client=Nobody").text, "an unknown customer or period falls back"

    facts = main._overnight(main._load_result(), "Greenvale Co-operative Bank", 12)
    assert (facts["arrived"], facts["closed"], facts["raised"], facts["repeats"]) == (32, 31, 1, 23)
    assert len(facts["open_items"]) == 1 and facts["open_items"][0]["count"] == 24 and facts["open_items"][0]["new"]
    assert nightshift.morning_fallback(facts).startswith("Not a quiet period for Greenvale Co-operative Bank: 32 alerts")
    assert _viewer().get("/morning").status_code == 200


def test_the_summary_is_written_by_the_model_for_an_analyst_and_kept_for_everyone_else(app, model):
    model["reply"] = "A  quiet night.\nOne item needs your answer."
    viewer = _viewer()
    first = viewer.get("/api/morning").json()
    assert first["by_model"] is False and first["provider"] == "automated summary" and not model["calls"], \
        "a visitor cannot make the model write"

    out = app.get("/api/morning").json()
    assert out == {"text": "A quiet night. One item needs your answer.", "by_model": True,
                   "provider": "Gemini on Vertex AI", "written": out["written"]}
    sent = model["calls"][-1]["user"]
    assert "Alerts arrived: 32" in sent and "Waiting for a decision:" in sent and "Question to answer:" in sent
    assert app.get("/api/morning").json()["text"] == out["text"] and len(model["calls"]) == 1, "kept, not written again"
    assert viewer.get("/api/morning").json()["by_model"] is True, "a visitor reads the one the analyst had written"
    assert next(e for e in audit.read() if e["event"] == "morning report written")["by_model"] is True

    # what the analysts taught goes to the model with the figures
    head = next(a for a in main._load_result()["alerts"] if main._load_result()["verdicts"][a["alert_id"]].get("burst"))
    token = _csrf(app.get(f"/alert/{head['alert_id']}").text)
    app.post("/alert/resolve", data={"alert_id": head["alert_id"], "outcome": "expected", "note": "Monthly patching",
                                     "teach": "1", "csrf": token})
    main._MORNING.clear()
    app.get("/api/morning")
    assert "HOUSE KNOWLEDGE" in model["calls"][-1]["user"] and "Monthly patching" in model["calls"][-1]["user"]


def test_each_customers_closures_are_read_with_that_customers_knowledge_only(app, model):
    from tests.test_bursts import _wz
    start = _secs(dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(minutes=20))
    other = [_wz(start + i, "5501", 3, "PAM: Login session opened.", ("pam", "syslog", "authentication_success"),
                 {"dstuser": "ops"}, host="branch-01", client="Second Customer Ltd", n=700 + i) for i in range(2)]
    assert app.post("/ingest", headers={"X-Triagle-Key": KEY}, json=other).json()["accepted"] == 2
    main._CACHE["taught"].append({"id": "TR-GREEN", "client": "Greenvale Co-operative Bank", "on": True,
                                  "title": "PAM: Login session opened.", "host": "wazuh-demo", "user": "",
                                  "outcome": "expected", "label": "Expected activity", "note": "Deploy account",
                                  "at": "2026-11-25T00:00:00+00:00", "until": "2026-12-25T00:00:00+00:00"})
    model["reply"] = lambda system, user: json.dumps(
        [{"n": i + 1, "view": "agree", "why": "Routine."} for i in range(user.count("Closed because:"))])
    app.post("/checks/read", data={"csrf": _csrf(app.get("/checks").text)})
    prompts = [c["user"] for c in model["calls"]]
    assert len(prompts) == 2, "one call per customer"
    for text in prompts:
        mine = "branch-01" in text
        assert mine != ("wazuh-demo" in text), "a prompt holds one customer's alerts"
        assert ("TR-GREEN" in text) == (not mine), "and only that customer's taught rules"
    assert len(main._CACHE["second"]) == 10
