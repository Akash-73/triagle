"""The Try page: anyone pastes one alert, sees what Triagle makes of it, and
says whether it was right.

    python -m pytest -q tests/test_try.py

What a visitor does here touches no queue, verdict or action. The one thing
kept is their answer, in a record of its own. The model is stood in for.
"""
import json
import re

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main
from app.connectors import examples
from app.engine import genai, nightshift, worknotes

RAW = examples.EXAMPLES["wazuh"][0]["raw"]            # encoded PowerShell: goes to a person
ROUTINE = examples.EXAMPLES["wazuh"][1]["raw"]        # a policy probe file the tool rates critical: closed
IN, OUT = 1000, 200
ONE_CALL = (IN * genai.PRICE_IN_USD + OUT * genai.PRICE_OUT_USD) / 1_000_000
SUSPICIOUS = {"view": "suspicious", "confidence": 85, "summary": "This needs a person.",
              "reasons": ["The command is encoded."], "next": ["Ask the owner."]}


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    for name in ("TRIAGLE_AGENT", "TRIAGLE_AGENT_STEPS", "K_SERVICE", "TRIAGLE_OSINT", "TRIAGLE_STATE_FILE", "TRIAGLE_ARRIVAL",
                 "TRIAGLE_VISITOR_DAILY_USD", "TRIAGLE_VISITOR_RUNS", "TRIAGLE_PRICE_IN", "TRIAGLE_PRICE_OUT", "TRIAGLE_MODEL_BASE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TRIAGLE_GUEST", "view")
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": "s" * 40})
    saved = dict(genai.USAGE), dict(genai.STATUS)
    for store in (main._CACHE, main._WORKNOTES, main._NOTES_AT, main._ASK_TIMES, main._TRY_TIMES, main._FEEDBACK_TIMES):
        store.clear()
    del main._AGENT_VISITOR_TIMES[:], main._ASK_ALL[:], main._FEEDBACK_ALL[:]
    yield
    genai.USAGE.update(saved[0])
    genai.STATUS.clear()
    genai.STATUS.update(saved[1])
    for store in (main._CACHE, main._WORKNOTES, main._NOTES_AT):
        store.clear()


def a_model(monkeypatch, reading=SUSPICIOUS):
    calls = {"plan": 0, "reading": 0, "account": 0}

    def generate(system, user, **kw):
        genai.STATUS.update(ok=True, error=None)
        genai.USAGE["calls"] += 1
        genai.USAGE["input"] += IN
        genai.USAGE["output"] += OUT
        if system.startswith(worknotes.ALERT_SYSTEM[:60]):
            calls["account"] += 1
            return "What happened: PowerShell ran an encoded command.\nWhy it matters: encoding hides what is run.", "vertex"
        if "Give your own reading" in system:
            calls["reading"] += 1
            return json.dumps(reading), "vertex"
        calls["plan"] += 1
        return json.dumps({"tool": "conclude", "why": "enough"}), "vertex"

    monkeypatch.setattr(genai, "configured", lambda: True)
    monkeypatch.setattr(genai, "generate_prose", generate)
    return calls


def guest():
    return TestClient(main.app)


def analyst():
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "correct horse"}, follow_redirects=False).status_code == 303
    return c


def token(c):
    return re.search(r'var CSRF = "([0-9a-f]+)"', c.get("/try").text).group(1)


def say(c, right="yes", raw=RAW, **more):
    return c.post("/api/try/feedback", json={"source": "wazuh", "raw": raw, "right": right, "csrf": token(c), **more})


def everything():
    """What a visitor must not be able to change, as one string."""
    r = main._load_result()
    return json.dumps([r["verdicts"], [a["alert_id"] for a in r["alerts"]], r.get("actions"), main._CACHE["decisions"],
                       main._CACHE["second"], main._CACHE["agent"], main._CACHE["checks"], main._CACHE["taught"]],
                      sort_keys=True, default=str)


# ---- trying an alert -----------------------------------------------------------------

def test_a_guest_opens_the_page_tries_an_alert_and_nothing_joins_the_queue():
    c = guest()
    page = c.get("/try")
    assert page.status_code == 200 and "Judge this alert" in page.text and "Nothing you paste is kept" in page.text
    assert 'href="/try"' in c.get("/").text, "it is in the navigation for everyone"
    before = everything()
    r = c.post("/api/try", json={"source": "wazuh", "raw": json.dumps(RAW), "csrf": token(c)})
    assert r.status_code == 200
    j = r.json()
    assert j["verdict"]["escalate"] and j["usecase"]["name"] and j["ms"] >= 0
    closed = c.post("/api/try", json={"source": "wazuh", "raw": ROUTINE, "csrf": token(c)}).json()
    assert not closed["verdict"]["escalate"] and closed["verdict"]["closure_code"]
    assert everything() == before
    assert main._CACHE["tries"]["visitors"] == 2 and main._CACHE["tries"]["since"]
    a = analyst()
    assert a.post("/api/try", json={"source": "wazuh", "raw": RAW, "csrf": token(a)}).status_code == 200
    assert main._CACHE["tries"]["visitors"] == 2, "a signed-in analyst trying their own product is not a visitor"
    assert c.post("/api/try", json={"source": "wazuh", "raw": RAW, "csrf": "nope"}).status_code == 403
    assert '"tried": 2' in c.get("/try").text, "the page is handed the count it shows"


def test_a_script_cannot_hammer_the_rules_and_a_person_is_never_slowed(monkeypatch):
    c = guest()
    t = token(c)
    codes = [c.post("/api/try", json={"source": "wazuh", "raw": ROUTINE, "csrf": t}).status_code for _ in range(32)]
    assert codes[:30] == [200] * 30 and codes[30:] == [429, 429]
    a = analyst()
    assert a.post("/api/try", json={"source": "wazuh", "raw": ROUTINE, "csrf": token(a)}).status_code == 200


def test_the_model_writes_the_account_of_a_tried_alert_and_nothing_is_kept(monkeypatch):
    calls = a_model(monkeypatch)
    c = guest()
    before = everything()
    r = c.post("/api/try/account", json={"source": "wazuh", "raw": RAW, "csrf": token(c)})
    assert r.status_code == 200
    j = r.json()
    assert j["by_model"] and j["provider"] == "Gemini on Vertex AI" and j["text"].startswith("What happened")
    assert calls["account"] == 1 and main._WORKNOTES == {} and everything() == before
    assert c.post("/api/try/account", json={"source": "wazuh", "raw": "{not json", "csrf": token(c)}).status_code == 400
    monkeypatch.setattr(genai, "configured", lambda: False)
    assert c.post("/api/try/account", json={"source": "wazuh", "raw": RAW, "csrf": token(c)}).status_code == 503
    assert "Triagle's account" not in c.get("/try").text, "no model, so the page does not promise an account"


def test_the_second_opinion_on_a_tried_alert_is_shown_and_nothing_is_kept(monkeypatch):
    a_model(monkeypatch)
    monkeypatch.setenv("TRIAGLE_VISITOR_RUNS", "2")
    c = guest()
    before = everything()
    r = c.post("/api/try/opinion", json={"source": "wazuh", "raw": RAW, "csrf": token(c)})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
    events = [json.loads(x) for x in r.text.splitlines() if x.strip()]
    assert [e["type"] for e in events][-2:] == ["reading", "result"] and events[0]["type"] == "step"
    done = events[-1]
    assert done["kept"] is False and done["reload"] is False and done["result"]["usable"]
    assert done["result"]["agrees"] is True, "raised by rule, and the model also wants a person to look"
    # a closure the model disagrees with: here it only says what would happen
    r = c.post("/api/try/opinion", json={"source": "wazuh", "raw": ROUTINE, "csrf": token(c)})
    done = [json.loads(x) for x in r.text.splitlines() if x.strip()][-1]
    assert done["result"]["effect"] == "raise" and done["kept"] is False
    assert everything() == before and main._CACHE["agent"] == {}
    # two an hour for all visitors together, as set
    r = c.post("/api/try/opinion", json={"source": "wazuh", "raw": RAW, "csrf": token(c)})
    assert r.status_code == 429 and "this hour's second opinions" in r.json()["detail"]
    a = analyst()
    assert a.post("/api/try/opinion", json={"source": "wazuh", "raw": RAW, "csrf": token(a)}).status_code == 200
    assert main._CACHE["agent"] == {}, "an analyst's run on a pasted alert is not kept either: it is in no queue"
    assert [e["event"] for e in audit.read()].count("second opinion on a tried alert") == 3


# ---- saying whether it was right -----------------------------------------------------

def test_a_visitor_says_whether_the_verdict_was_right_and_it_is_kept_and_counted():
    c = guest()
    before = everything()
    r = say(c, "no", comment="  This is our patching tool.\nIt runs every night. ", role="SOC analyst",
            contact="  meera@example.org ")
    assert r.status_code == 200 and r.json()["answers"] == 1 and r.json()["no"] == 1
    assert say(c, "yes", raw=ROUTINE).json()["yes"] == 1
    assert say(c, "partly", role="Chief Wizard").json() == {"ok": True, "answers": 3, "yes": 1, "partly": 1, "no": 1,
                                                           "changes": [], "tried": 0}
    assert say(c, "maybe").status_code == 400 and say(c, "yes", raw="{not json").status_code == 400
    assert c.post("/api/try/feedback", json={"source": "wazuh", "raw": RAW, "right": "yes", "csrf": "nope"}).status_code == 403
    first, second, third = main._CACHE["feedback"]
    assert first["right"] == "no" and first["by"] == "visitor" and first["role"] == "SOC analyst"
    assert first["comment"] == "This is our patching tool.\nIt runs every night." and first["contact"] == "meera@example.org"
    # what Triagle said is worked out here, not taken from the page
    assert first["escalated"] is True and first["words"] and first["title"] == main.normalize("wazuh", RAW, "Trial").title
    assert second["escalated"] is False and second["code"]
    assert third["role"] == "", "a role is one of the list, or nothing"
    assert first["raw"] is None, "the alert is not kept unless they ask"
    assert everything() == before, "an answer changes no verdict, queue or action"
    e = audit.read()[0]
    assert e["event"] == "answer left on the try page" and e["answer"] == "partly" and e["with_alert"] is False


def test_the_alert_is_kept_only_when_they_send_it_along_and_only_an_analyst_can_open_it():
    c = guest()
    say(c, "no", keep_alert=True, comment="wrong")
    say(c, "no", keep_alert="yes please")                                    # only a plain true counts
    kept, not_kept = main._CACHE["feedback"]
    assert kept["raw"] == RAW and not_kept["raw"] is None
    a = analyst()
    page = a.get(f"/try?fb={kept['id']}").text
    assert json.dumps(RAW["rule"]["description"]) in page, "the analyst gets the alert back in the box"
    assert json.dumps(RAW["rule"]["description"]) not in "".join(re.findall(r"LOADED = (.*?), MODEL", c.get(f"/try?fb={kept['id']}").text)), \
        "a guest with the address of someone's answer gets nothing"
    assert "LOADED = null" in c.get(f"/try?fb={kept['id']}").text
    # only the newest few keep their alert; every answer stays
    main.FEEDBACK_RAW_KEEP, was = 2, main.FEEDBACK_RAW_KEEP
    try:
        for _ in range(3):
            main._FEEDBACK_TIMES.clear()
            say(c, "yes", keep_alert=True)
    finally:
        main.FEEDBACK_RAW_KEEP = was
    assert len(main._CACHE["feedback"]) == 5 and sum(1 for f in main._CACHE["feedback"] if f["raw"]) == 2
    assert main._CACHE["feedback"][0]["raw"] is None


def test_what_a_signed_in_analyst_says_is_kept_apart_and_never_counted():
    a, c = analyst(), guest()
    r = say(a, "yes", comment="my own test")
    assert r.status_code == 200 and r.json()["answers"] == 0
    assert main._CACHE["feedback"][0]["by"] == "admin"
    say(c, "yes")
    assert main._feedback_tally()["answers"] == 1
    page = a.get("/feedback").text
    assert "signed in here, not counted" in page and "<b>1</b> answer from visitors" in page


def test_too_many_answers_from_one_place_are_refused():
    c = guest()
    codes = [say(c, "yes").status_code for _ in range(main.FEEDBACK_PER_ADDRESS + 1)]
    assert codes == [200] * main.FEEDBACK_PER_ADDRESS + [429]
    assert len(main._CACHE["feedback"]) == main.FEEDBACK_PER_ADDRESS


def test_only_an_analyst_reads_the_answers_and_what_changed_because_of_one_is_shown_to_everyone():
    c = guest()
    say(c, "no", comment="This is our patching tool.", contact="meera@example.org", role="SOC lead or manager")
    fid = main._CACHE["feedback"][0]["id"]
    assert c.get("/feedback", follow_redirects=False).status_code == 403
    assert "meera@example.org" not in c.get("/try").text and "patching tool" not in c.get("/try").text
    a = analyst()
    page = a.get("/feedback").text
    for words in ("This is our patching tool.", "meera@example.org", "SOC lead or manager", "Wrong", "Feedback"):
        assert words in page, words
    assert '<span class="count" title="Answers visitors left on the Try page">1</span>' in page
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)
    assert c.post("/feedback/change", data={"id": fid, "change": "x", "csrf": csrf}, follow_redirects=False).status_code == 403
    assert a.post("/feedback/change", data={"id": fid, "change": "x", "csrf": "nope"}, follow_redirects=False).status_code == 403
    r = a.post("/feedback/change", data={"id": fid, "change": "  A known patching tool is now closed as routine.  ", "csrf": csrf},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/feedback#{fid}"
    shown = c.get("/try").text
    assert "Changed because someone here said so" in shown and "A known patching tool is now closed as routine." in shown
    assert "meera@example.org" not in shown and "This is our patching tool." not in shown, "the note is public; the answer is not"
    assert main._feedback_tally()["changes"][0]["what"] == "A known patching tool is now closed as routine."
    assert a.post("/feedback/change", data={"id": "nope", "change": "x", "csrf": csrf}, follow_redirects=False).status_code == 404
    # spam is removed, and the audit log says who removed what
    assert a.post("/feedback/remove", data={"id": fid, "csrf": csrf}, follow_redirects=False).status_code == 303
    assert main._CACHE["feedback"] == [] and "Changed because someone here said so" not in c.get("/try").text
    events = [e["event"] for e in audit.read()]
    assert events[0] == "answer removed from the try page's record" and "change noted against an answer" in events


def test_answers_and_the_count_of_tries_survive_a_restart(monkeypatch, tmp_path):
    monkeypatch.setenv("TRIAGLE_STATE_FILE", str(tmp_path / "data" / "state.json.gz"))
    c = guest()
    c.post("/api/try", json={"source": "wazuh", "raw": RAW, "csrf": token(c)})
    say(c, "partly", comment="close", keep_alert=True)
    main._CACHE.clear()                                                      # the process starts again
    t = main._feedback_tally() if main._load_result() else None
    assert t["answers"] == 1 and t["partly"] == 1 and t["tried"] == 1
    assert main._CACHE["feedback"][0]["comment"] == "close" and main._CACHE["feedback"][0]["raw"] == RAW


# ---- what visitors may spend on the model --------------------------------------------

def test_visitors_have_a_days_budget_for_the_model_and_rules_still_answer_when_it_is_spent(monkeypatch):
    calls = a_model(monkeypatch)
    monkeypatch.setenv("TRIAGLE_VISITOR_DAILY_USD", str(ONE_CALL * 1.5))      # the second call takes it over
    c = guest()
    body = {"source": "wazuh", "raw": RAW, "csrf": token(c)}
    assert c.post("/api/try/account", json=body).status_code == 200
    assert main._visitors()["usd"] == pytest.approx(ONE_CALL, abs=1e-5) and not main._visitors_over()
    assert c.post("/api/try/account", json=body).status_code == 200
    assert main._visitors_over()
    for path in ("/api/try/account", "/api/try/opinion"):
        r = c.post(path, json=body)
        assert r.status_code == 429 and "today's budget for the model" in r.json()["detail"], path
    asked = calls["account"]
    # an alert in the queue: the account and a question are refused the same way, with nothing asked of the model
    aid = main._load_result()["alerts"][0]["alert_id"]
    assert c.get("/api/notes", params={"alert": aid}).json()["by_model"] is False and calls["account"] == asked
    # the verdict is decided by rule, costs nothing and still works
    assert c.post("/api/try", json=body).status_code == 200
    assert c.post("/api/try/feedback", json={**body, "right": "yes"}).status_code == 200
    # a signed-in analyst is not held to the visitors' budget, and does not spend from it
    a = analyst()
    spent = main._visitors()["usd"]
    assert a.post("/api/try/account", json={"source": "wazuh", "raw": RAW, "csrf": token(a)}).status_code == 200
    assert main._visitors()["usd"] == spent
    # midnight in India: the day starts again
    main._visitors()["day"] = "2026-11-27"
    assert not main._visitors_over() and c.post("/api/try/account", json=body).status_code == 200
    assert "visitors" in main._snapshot()


def test_without_a_sign_in_there_are_no_visitors_and_no_budget(monkeypatch):
    a_model(monkeypatch)
    auth.load_config({"TRIAGLE_AUTH": "off"})
    monkeypatch.setenv("TRIAGLE_VISITOR_DAILY_USD", "0")
    c = TestClient(main.app)
    r = c.post("/api/try/account", json={"source": "wazuh", "raw": RAW})
    assert r.status_code == 200 and r.json()["by_model"], "the person at the keyboard is the owner"
    assert main._visitors()["usd"] == 0
