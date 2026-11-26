"""The model layer: Gemini on Vertex AI, its status, and questions about a case.

    python -m pytest -q tests/test_model.py

No network. Every call to the metadata server or the model is faked, so these
tests pin what is sent and what happens when the model fails. Two rules matter
most: a failure is reported, never hidden; and when the model does not answer,
nothing is invented in its place.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app import auth, main, demo_attack
from app.engine import analyst, genai


class FakeResp:
    def __init__(self, status=200, body=None, text=""):
        self.status_code = status
        self._body = body
        self.text = text or (json.dumps(body) if body is not None else "")

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def model_reply(text):
    return FakeResp(200, {"candidates": [{"content": {"parts": [{"text": text}]}}]})


@pytest.fixture(autouse=True)
def _clean(tmp_path, monkeypatch):
    for k in ("TRIAGLE_VERTEX", "GOOGLE_CLOUD_PROJECT", "TRIAGLE_VERTEX_PROJECT", "K_SERVICE", "TRIAGLE_MODEL",
              "TRIAGLE_VERTEX_MODEL", "TRIAGLE_VERTEX_LOCATION", "GOOGLE_CLOUD_LOCATION", "GEMINI_API_KEY",
              "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    genai._cache.clear()
    genai._cache.update(project=None, token=None, token_exp=0.0)
    genai.STATUS.update(provider=None, model=None, ok=None, error=None, at=None, seconds=None, calls=0, failures=0)
    genai._no_thinking.clear()
    monkeypatch.delenv("TRIAGLE_THINKING", raising=False)
    for k in ("TRIAGLE_MODEL_BASE", "TRIAGLE_MODEL_KEY", "TRIAGLE_PRICE_IN", "TRIAGLE_PRICE_OUT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(genai, "RETRY_WAIT", 0)
    genai.STATUS["retries"] = 0
    genai.STATUS["recent"] = []
    main._ASK_TIMES.clear()
    main._ASK_ALL.clear()
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s",
                      "TRIAGLE_USERS": "viewerbob:viewer:" + auth.hash_password("look")})
    main._CACHE.clear()
    yield
    main._CACHE.clear()


@pytest.fixture
def cloud_run(monkeypatch):
    """Pretend to be on Cloud Run: a metadata server that knows the project
    and hands out a token, and a model endpoint that records what it is sent."""
    sent = {"posts": []}
    monkeypatch.setenv("K_SERVICE", "triagle")

    def fake_get(url, headers=None, timeout=None):
        assert headers == {"Metadata-Flavor": "Google"}
        if url.endswith("project/project-id"):
            return FakeResp(200, None, "demo-project")
        if url.endswith("service-accounts/default/token"):
            return FakeResp(200, {"access_token": "tok-123", "expires_in": 3600})
        return FakeResp(404, None, "")

    def fake_post(url, headers=None, json=None, timeout=None):
        sent["posts"].append({"url": url, "headers": headers, "json": json})
        return sent.get("reply") or model_reply("connected")

    monkeypatch.setattr(genai.requests, "get", fake_get)
    monkeypatch.setattr(genai.requests, "post", fake_post)
    return sent


# ---- transport ---------------------------------------------------------------

def test_the_global_endpoint_has_no_region_in_the_host():
    assert genai.vertex_url("p", "global", "gemini-3.5-flash") == (
        "https://aiplatform.googleapis.com/v1/projects/p/locations/global"
        "/publishers/google/models/gemini-3.5-flash:generateContent")
    assert genai.vertex_url("p", "asia-south1", "m").startswith("https://asia-south1-aiplatform.googleapis.com/")


def test_nothing_is_configured_on_a_plain_laptop():
    assert not genai.vertex_enabled() and not genai.configured()
    text, provider = genai.generate_prose("s", "u")
    assert (text, provider) == (None, None)
    assert genai.STATUS["ok"] is False and "No model is configured" in genai.STATUS["error"]


def test_on_cloud_run_vertex_is_used_with_the_services_own_identity(cloud_run):
    text, provider = genai.generate_prose("system text", "user text")
    assert (text, provider) == ("connected", "vertex")
    post = cloud_run["posts"][0]
    assert "/projects/demo-project/locations/global/" in post["url"]
    assert post["url"].endswith("/models/gemini-3.5-flash:generateContent")
    assert post["headers"]["Authorization"] == "Bearer tok-123"
    assert post["json"]["systemInstruction"]["parts"][0]["text"] == "system text"
    st = genai.status()
    assert st["transport"] == "Vertex AI" and st["last"]["ok"] is True and st["project"] == "demo-project"


def test_vertex_can_be_switched_off_even_on_cloud_run(cloud_run, monkeypatch):
    monkeypatch.setenv("TRIAGLE_VERTEX", "false")
    assert not genai.vertex_enabled()
    assert genai.generate_prose("s", "u") == (None, None)
    assert cloud_run["posts"] == []


def test_a_refused_call_is_reported_with_the_apis_own_reason(cloud_run):
    cloud_run["reply"] = FakeResp(403, {"error": {"code": 403, "status": "PERMISSION_DENIED",
                                                  "message": "Permission 'aiplatform.endpoints.predict' denied"}})
    assert genai.generate_prose("s", "u") == (None, None)          # never raises
    last = genai.status()["last"]
    assert last["ok"] is False and "PERMISSION_DENIED" in last["error"] and "aiplatform" in last["error"]
    assert last["failures"] == 1


def test_an_empty_reply_counts_as_a_failure(cloud_run):
    cloud_run["reply"] = FakeResp(200, {"candidates": [{"content": {"parts": [{"text": "x", "thought": True}]}}]})
    assert genai.generate_prose("s", "u") == (None, None)
    assert "no text" in genai.STATUS["error"]


def test_the_model_is_asked_for_a_short_think(cloud_run, monkeypatch):
    genai.generate_prose("s", "u")
    config = cloud_run["posts"][0]["json"]["generationConfig"]
    assert config["thinkingConfig"] == {"thinkingLevel": "LOW"} and "thinkingBudget" not in str(config)
    assert genai.status()["thinking"] == "low"
    monkeypatch.setenv("TRIAGLE_THINKING", "high")
    genai.generate_prose("s", "u")
    assert cloud_run["posts"][1]["json"]["generationConfig"]["thinkingConfig"] == {"thinkingLevel": "HIGH"}
    for leave_alone in ("default", "off", "nonsense"):
        monkeypatch.setenv("TRIAGLE_THINKING", leave_alone)
        genai.generate_prose("s", "u")
        assert "thinkingConfig" not in cloud_run["posts"][-1]["json"]["generationConfig"], leave_alone
        assert genai.status()["thinking"] is None


def test_a_model_without_that_setting_is_asked_again_without_it_and_then_left_alone(cloud_run, monkeypatch):
    refused = FakeResp(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT",
                                       "message": "Unknown name thinkingLevel"}})

    def post(url, headers=None, json=None, timeout=None):
        cloud_run["posts"].append({"url": url, "json": json})
        return refused if "thinkingConfig" in json["generationConfig"] else model_reply("written anyway")

    monkeypatch.setattr(genai.requests, "post", post)
    assert genai.generate_prose("s", "u") == ("written anyway", "vertex")
    assert len(cloud_run["posts"]) == 2 and "thinkingConfig" not in cloud_run["posts"][1]["json"]["generationConfig"]
    assert genai.STATUS["ok"] is True and genai.status()["thinking"] is None
    assert genai.generate_prose("s", "u") == ("written anyway", "vertex")
    assert len(cloud_run["posts"]) == 3, "the next call does not try the setting again"


def test_one_call_can_ask_for_less_thinking_and_falls_back_if_the_model_has_no_such_level(cloud_run, monkeypatch):
    """Choosing the next check is a small choice, so the investigator asks for
    the least thinking on those calls. A model that does not offer that level
    is asked again at the usual one, and is not asked for it a second time."""
    genai.generate_prose("s", "u", thinking_level="minimal")
    assert cloud_run["posts"][0]["json"]["generationConfig"]["thinkingConfig"] == {"thinkingLevel": "MINIMAL"}
    assert genai.status()["calls"][-1]["level"] == "minimal" and genai.status()["calls"][-1]["ok"] is True
    genai.generate_prose("s", "u")
    assert cloud_run["posts"][1]["json"]["generationConfig"]["thinkingConfig"] == {"thinkingLevel": "LOW"}
    cloud_run["posts"].clear()
    refused = FakeResp(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": "MINIMAL is not supported"}})

    def post(url, headers=None, json=None, timeout=None):
        cloud_run["posts"].append(json["generationConfig"].get("thinkingConfig"))
        return refused if json["generationConfig"].get("thinkingConfig") == {"thinkingLevel": "MINIMAL"} else model_reply("at the usual level")

    monkeypatch.setattr(genai.requests, "post", post)
    genai._refused.clear()
    assert genai.generate_prose("s", "u", thinking_level="minimal") == ("at the usual level", "vertex")
    assert cloud_run["posts"] == [{"thinkingLevel": "MINIMAL"}, {"thinkingLevel": "LOW"}]
    assert genai.generate_prose("s", "u", thinking_level="minimal") == ("at the usual level", "vertex")
    assert cloud_run["posts"][2:] == [{"thinkingLevel": "LOW"}], "it is not asked for that level again"
    assert genai.status()["thinking"] == "low", "and the usual setting is not blamed"
    genai._refused.clear()
    # an operator who said to leave the model's own setting alone is obeyed on these calls too
    monkeypatch.setenv("TRIAGLE_THINKING", "default")
    genai.generate_prose("s", "u", thinking_level="minimal")
    assert cloud_run["posts"][-1] is None


def test_a_call_refused_for_another_reason_is_still_reported(cloud_run):
    cloud_run["reply"] = FakeResp(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT",
                                                  "message": "The prompt is too long"}})
    assert genai.generate_prose("s", "u") == (None, None)
    assert "too long" in genai.STATUS["error"] and genai.status()["thinking"] == "low", "the setting is not blamed"


def test_the_model_can_be_changed_by_setting(cloud_run, monkeypatch):
    monkeypatch.setenv("TRIAGLE_MODEL", "gemini-9-test")
    monkeypatch.setenv("TRIAGLE_VERTEX_LOCATION", "asia-south1")
    genai.generate_prose("s", "u")
    assert "asia-south1-aiplatform.googleapis.com" in cloud_run["posts"][0]["url"]
    assert "/models/gemini-9-test:" in cloud_run["posts"][0]["url"]


# ---- a busy service is asked once more ------------------------------------------

BUSY = FakeResp(429, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "Quota"}})


def _answers(cloud_run, monkeypatch, replies):
    replies = list(replies)

    def post(url, headers=None, json=None, timeout=None):
        cloud_run["posts"].append({"url": url, "json": json, "timeout": timeout})
        r = replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(genai.requests, "post", post)


def test_a_busy_service_is_asked_once_more(cloud_run, monkeypatch):
    _answers(cloud_run, monkeypatch, [BUSY, model_reply("second time lucky")])
    assert genai.generate_prose("s", "u") == ("second time lucky", "vertex")
    assert len(cloud_run["posts"]) == 2 and genai.STATUS["retries"] == 1 and genai.STATUS["failures"] == 0


def test_and_only_once(cloud_run, monkeypatch):
    _answers(cloud_run, monkeypatch, [BUSY, FakeResp(503, {"error": {"status": "UNAVAILABLE", "message": "Busy"}}),
                                      model_reply("never reached")])
    assert genai.generate_prose("s", "u") == (None, None)
    assert len(cloud_run["posts"]) == 2 and "UNAVAILABLE" in genai.STATUS["error"]


def test_a_dropped_connection_is_tried_again_and_a_timeout_is_not(cloud_run, monkeypatch):
    _answers(cloud_run, monkeypatch, [genai.requests.ConnectionError("reset"), model_reply("after the reset")])
    assert genai.generate_prose("s", "u") == ("after the reset", "vertex")
    cloud_run["posts"].clear()
    _answers(cloud_run, monkeypatch, [genai.requests.ReadTimeout("slow"), model_reply("never reached")])
    assert genai.generate_prose("s", "u", timeout=7) == (None, None)
    assert len(cloud_run["posts"]) == 1 and cloud_run["posts"][0]["timeout"] == 7


def test_a_slow_answer_is_asked_for_again_only_when_the_wait_was_short(cloud_run, monkeypatch):
    """On the live feed an answer that takes two seconds sometimes hangs for
    thirty. The investigator sets a short wait and asks once more."""
    _answers(cloud_run, monkeypatch, [genai.requests.ReadTimeout("slow"), model_reply("at the second asking")])
    assert genai.generate_prose("s", "u", timeout=10, again_on_timeout=True) == ("at the second asking", "vertex")
    assert [p["timeout"] for p in cloud_run["posts"]] == [10, 10] and genai.STATUS["retries"] == 1
    cloud_run["posts"].clear()
    _answers(cloud_run, monkeypatch, [genai.requests.ReadTimeout("slow"), genai.requests.ReadTimeout("slow"), model_reply("never")])
    assert genai.generate_prose("s", "u", timeout=10, again_on_timeout=True) == (None, None)
    assert len(cloud_run["posts"]) == 2, "once more, and no more"


def test_a_slow_answer_that_gives_up_after_the_other_has_answered_does_not_say_the_model_is_down(cloud_run):
    """Found on the live site on 26 November. A slow answer is asked for a
    second time beside the first. The second answered and the run finished.
    Twenty seconds later the first timed out, and the top bar said "Gemini is
    not answering" on every page until the next call. A failure now changes
    the top bar only when nothing has answered since that call began."""
    import time
    slow_began = time.time() - 20                                    # the first asking, still out
    assert genai.generate_prose("s", "u") == ("connected", "vertex")  # the second asking answers
    assert main._model_pill()["state"] == "ok"
    genai._record("vertex", False, "Read timed out. (read timeout=20)", slow_began)   # the first gives up
    assert genai.STATUS["ok"] is True and main._model_pill()["state"] == "ok"
    assert genai.STATUS["failures"] == 1 and genai.STATUS["recent"][-1]["error"].startswith("Read timed out")
    assert [c["ok"] for c in genai.status()["calls"]][-2:] == [True, False], "it is still counted and listed"

    # a call that began after the last answer, and failed, does say so
    cloud_run["reply"] = FakeResp(503, {"error": {"status": "UNAVAILABLE", "message": "Busy"}})
    assert genai.generate_prose("s", "u") == (None, None)
    assert genai.STATUS["ok"] is False and main._model_pill()["label"].endswith("is not answering")
    # and the next answer clears it
    cloud_run["reply"] = None
    assert genai.generate_prose("s", "u") == ("connected", "vertex") and main._model_pill()["state"] == "ok"


def test_a_prompt_promised_to_vertex_ai_goes_nowhere_else(cloud_run, monkeypatch):
    """Found on the live site on 26 November: when Vertex AI was slow, the
    prompt was sent on to the AI Studio API with an old key. That is another
    service with other terms, and the page says prompts go to Google Cloud."""
    monkeypatch.setenv("GEMINI_API_KEY", "an-old-key")
    _answers(cloud_run, monkeypatch, [FakeResp(500, {"error": {"status": "INTERNAL", "message": "Try later"}})] * 2 + [model_reply("never")])
    assert genai.generate_prose("s", "u") == (None, None)
    assert len(cloud_run["posts"]) == 2 and all("aiplatform.googleapis.com" in p["url"] for p in cloud_run["posts"])
    last = genai.status()["last"]
    assert last["provider"] == "vertex" and "INTERNAL" in last["error"]
    assert last["recent"][-1]["error"] == last["error"] and last["recent"][-1]["provider"] == "vertex", "the last failures are kept"
    # a laptop with no Vertex AI still uses its key
    monkeypatch.setenv("TRIAGLE_VERTEX", "false")
    monkeypatch.delenv("K_SERVICE")
    _answers(cloud_run, monkeypatch, [model_reply("from the key")])
    assert genai.generate_prose("s", "u") == ("from the key", "aistudio")


def test_a_refusal_is_not_asked_again(cloud_run, monkeypatch):
    _answers(cloud_run, monkeypatch, [FakeResp(403, {"error": {"status": "PERMISSION_DENIED", "message": "No"}}),
                                      model_reply("never reached")])
    assert genai.generate_prose("s", "u") == (None, None) and len(cloud_run["posts"]) == 1


# ---- a model the customer runs ---------------------------------------------------

def chat_reply(text, **usage):
    return FakeResp(200, {"choices": [{"message": {"role": "assistant", "content": text}}], "usage": usage})


def test_a_customers_own_model_is_the_only_one_asked(cloud_run, monkeypatch):
    """On Cloud Run with Vertex AI available, one setting sends every prompt
    to the customer's server instead, and nothing goes to Google."""
    monkeypatch.setenv("TRIAGLE_MODEL_BASE", "http://10.0.0.5:11434/v1/")
    monkeypatch.setenv("TRIAGLE_MODEL", "llama3.1")
    monkeypatch.setenv("TRIAGLE_MODEL_KEY", "local-key")
    cloud_run["reply"] = chat_reply("<think>The rule says so.</think>\nWritten on the bank's own server.",
                                    prompt_tokens=120, completion_tokens=30)
    before = dict(genai.USAGE)
    assert genai.configured() and not genai.vertex_enabled()
    assert genai.generate_prose("the system part", "the alert", max_tokens=900, temperature=0.0) == \
        ("Written on the bank's own server.", "own")
    assert len(cloud_run["posts"]) == 1
    sent = cloud_run["posts"][0]
    assert sent["url"] == "http://10.0.0.5:11434/v1/chat/completions" and "google" not in sent["url"]
    assert sent["headers"]["Authorization"] == "Bearer local-key"
    assert sent["json"]["model"] == "llama3.1" and sent["json"]["temperature"] == 0.0 and sent["json"]["max_tokens"] == 900
    assert sent["json"]["messages"] == [{"role": "system", "content": "the system part"},
                                        {"role": "user", "content": "the alert"}]
    assert genai.USAGE["input"] - before["input"] == 120 and genai.USAGE["output"] - before["output"] == 30
    st = genai.status()
    assert st["own"] and st["transport"] == "Your own model server at 10.0.0.5:11434" and st["thinking"] is None
    assert st["project"] is None and st["usage"]["price_in"] == 0 and st["usage"]["price_out"] == 0
    assert genai.PROVIDER_LABEL["own"] == "your own model"
    genai.load_usage(before)


def test_when_the_customers_model_is_down_nothing_is_sent_to_anyone_else(cloud_run, monkeypatch):
    monkeypatch.setenv("TRIAGLE_MODEL_BASE", "https://someone:hunter2@models.bank.example/v1")
    monkeypatch.setenv("GEMINI_API_KEY", "a-key-that-must-not-be-used")
    cloud_run["reply"] = FakeResp(404, {"error": "model 'gemini-3.5-flash' not found"})      # the error is a plain string
    assert genai.generate_prose("s", "u") == (None, None)                                      # and never raises
    assert [p["url"] for p in cloud_run["posts"]] == ["https://someone:hunter2@models.bank.example/v1/chat/completions"]
    last = genai.status()["last"]
    assert last["ok"] is False and "not found" in last["error"] and last["provider"] == "own"
    assert genai.status()["transport"] == "Your own model server at models.bank.example", "no name or password is shown"


def test_the_investigator_runs_on_a_customers_own_model(cloud_run, monkeypatch):
    """The whole loop, guardrails included, over the other transport: the
    rules are code, so they do not change with the model."""
    from app.engine import investigator
    monkeypatch.setenv("TRIAGLE_MODEL_BASE", "http://localhost:11434/v1")
    monkeypatch.setenv("TRIAGLE_MODEL", "qwen2.5")
    plan = iter(['{"tool": "timeline", "why": "what else happened"}', '{"tool": "format_the_disk", "why": "x"}',
                 '{"tool": "related_alerts", "why": "is it alone"}', '{"tool": "conclude", "why": "enough"}'])

    def post(url, headers=None, json=None, timeout=None):
        cloud_run["posts"].append({"url": url})
        system = json["messages"][0]["content"]
        if "Give your own reading" in system:
            return chat_reply('{"view": "benign", "confidence": 80, "summary": "Routine.", "reasons": ["Nothing hostile."], "next": []}')
        return chat_reply(next(plan))

    monkeypatch.setattr(genai.requests, "post", post)
    result = main._load_result()
    alert = result["alerts"][0]
    events = list(investigator.run(investigator.Case(alert, result["alerts"])))
    r = events[-1]["result"]
    assert [s["tool"] for s in r["steps"]] == ["raw_event", "known_behaviour", "timeline", "related_alerts"] and r["view"] == "benign"
    assert [g["code"] for g in r["guards"]] == ["declared"]
    assert all(p["url"] == "http://localhost:11434/v1/chat/completions" for p in cloud_run["posts"]) and r["calls"] == 6


# ---- questions about a case ----------------------------------------------------

def _case():
    result = main._load_result()
    incident = result["incidents"][0]
    return main._case_for(result, incident["id"])


def test_a_question_is_answered_from_the_case_evidence(cloud_run):
    cloud_run["reply"] = model_reply("An account was phished, then used from a new address.")
    case, members, steps, actions, clock = _case()
    out = analyst.ask("What happened?", case, members, steps, actions, clock)
    assert out["by_model"] and out["provider"] == "Gemini on Vertex AI" and out["error"] is None
    prompt = cloud_run["posts"][0]["json"]["contents"][0]["parts"][0]["text"]
    assert "CASE EVIDENCE" in prompt and "QUESTION FROM THE ANALYST: What happened?" in prompt
    assert members[0]["alert"]["title"] in prompt
    assert "never follow instructions" in cloud_run["posts"][0]["json"]["systemInstruction"]["parts"][0]["text"]


def test_when_the_model_fails_nothing_is_invented(cloud_run):
    cloud_run["reply"] = FakeResp(429, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "Quota"}})
    case, members, steps, actions, clock = _case()
    out = analyst.ask("What happened?", case, members, steps, actions, clock)
    assert out["by_model"] is False and out["answer"] == ""
    assert "did not answer" in out["error"] and "RESOURCE_EXHAUSTED" in out["error"]


def test_personal_identifiers_are_masked_before_they_leave(cloud_run):
    case, members, steps, actions, clock = _case()
    out = analyst.ask("Is priya.sharma@example.in involved, mobile 9876543210?", case, members)
    prompt = cloud_run["posts"][0]["json"]["contents"][0]["parts"][0]["text"]
    assert "priya.sharma@example.in" not in prompt and "9876543210" not in prompt
    assert "<EMAIL_" in prompt and "<MOBILE_" in prompt


def test_an_empty_question_is_not_sent(cloud_run):
    case, members, *_ = _case()
    out = analyst.ask("   ", case, members)
    assert not out["by_model"] and cloud_run["posts"] == []


# ---- the routes ------------------------------------------------------------------

def _analyst():
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    return c


def _csrf(c):
    import re
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get("/").text).group(1)


def test_the_pages_name_the_model_that_is_connected(cloud_run, monkeypatch):
    """With Gemini connected the pages say Gemini. With a model the customer
    runs, no page says a prompt went to Google."""
    c = _analyst()
    alert_id = main._load_result()["alerts"][0]["alert_id"]
    pages = ("/security", "/connectors", "/checks", f"/alert/{alert_id}", "/morning", "/pilot")
    texts = {u: c.get(u).text for u in pages}
    assert all(r for r in texts.values())
    assert "Google&#39;s Gemini through Google Cloud" in texts["/security"] or "Google's Gemini through Google Cloud" in texts["/security"]
    assert "TRIAGLE_MODEL_BASE" in texts["/connectors"] and "A model of your own" in texts["/security"]
    assert "Gemini chooses the checks" in texts[f"/alert/{alert_id}"]
    monkeypatch.setenv("TRIAGLE_MODEL_BASE", "http://10.0.0.5:8000/v1")
    monkeypatch.setenv("TRIAGLE_MODEL", "llama3.1")
    for u in pages:
        page = c.get(u)
        assert page.status_code == 200 and "Gemini" not in page.text, u
    assert "none to Google" in c.get("/connectors").text and "The model chooses the checks" in c.get(f"/alert/{alert_id}").text
    assert "Your own model server at 10.0.0.5:8000" in c.get("/connectors").text


def test_the_ask_box_names_the_model_even_when_it_is_not_answering(cloud_run):
    """The top bar may say the model is not answering. The sentence under the
    question box is about which model answers, so it uses the model's name."""
    c = _analyst()
    alert_id = main._load_result()["alerts"][0]["alert_id"]
    cloud_run["reply"] = FakeResp(503, {"error": {"status": "UNAVAILABLE", "message": "Busy"}})
    assert genai.generate_prose("s", "u") == (None, None)
    page = c.get(f"/alert/{alert_id}").text
    assert "Gemini 3.5 Flash is not answering</a>" in page, "the top bar says so"
    assert "is not answering answers" not in page and "Gemini 3.5 Flash answers from the evidence on this page" in page


def test_model_status_needs_a_sign_in_and_reports_the_transport(cloud_run):
    assert TestClient(main.app).get("/api/model", follow_redirects=False).status_code in (303, 307, 401)
    c = _analyst()
    st = c.get("/api/model").json()
    assert st["configured"] and st["transport"] == "Vertex AI" and st["model"] == "gemini-3.5-flash"


def test_the_connection_test_reports_success_and_is_audited(cloud_run):
    c = _analyst()
    st = c.post("/api/model/test", json={"csrf": _csrf(c)}).json()
    assert st["last"]["ok"] is True
    from app import audit
    assert any(e["event"] == "model connection tested" for e in audit.read(200))


def test_ask_route_answers_for_an_incident_and_for_a_single_alert(cloud_run):
    cloud_run["reply"] = model_reply("Short answer.")
    c = _analyst()
    token = _csrf(c)
    result = main._load_result()
    inc = result["incidents"][0]["id"]
    r = c.post("/api/ask", json={"case": inc, "question": "What happened?", "csrf": token})
    assert r.status_code == 200 and r.json()["answer"] == "Short answer."
    alert_id = result["alerts"][0]["alert_id"]
    r = c.post("/api/ask", json={"case": alert_id, "question": "Why?", "csrf": token})
    assert r.status_code == 200 and r.json()["by_model"]


def test_ask_route_rejects_an_unknown_case_and_a_bad_token(cloud_run):
    c = _analyst()
    token = _csrf(c)
    assert c.post("/api/ask", json={"case": "INC-NOPE", "question": "x", "csrf": token}).status_code == 404
    inc = main._load_result()["incidents"][0]["id"]
    assert c.post("/api/ask", json={"case": inc, "question": "x", "csrf": "bad"}).status_code == 403
    assert c.post("/api/ask", content="not json", headers={"Content-Type": "application/json"}).status_code == 400


def test_questions_are_rate_limited(cloud_run):
    """A visitor (here the view-only account) is held to a few a minute. A
    signed-in analyst has a separate, larger allowance, so a stranger using up
    the visitors' budget cannot stop an analyst working."""
    c = _analyst()
    inc = main._load_result()["incidents"][0]["id"]
    v = TestClient(main.app)
    v.post("/login", data={"username": "viewerbob", "password": "look"})
    vt = _csrf(v)
    codes = [v.post("/api/ask", json={"case": inc, "question": "x", "csrf": vt}).status_code
             for _ in range(main.ASK_PER_MINUTE + 2)]
    assert codes[:main.ASK_PER_MINUTE] == [200] * main.ASK_PER_MINUTE
    assert codes[-1] == 429
    token = _csrf(c)
    assert c.post("/api/ask", json={"case": inc, "question": "x", "csrf": token}).status_code == 200
    main._ASK_ALL.extend([__import__("time").time()] * main.ASK_PER_HOUR_TOTAL)        # visitors' hour is spent
    assert c.post("/api/ask", json={"case": inc, "question": "x", "csrf": token}).status_code == 200
    codes = [c.post("/api/ask", json={"case": inc, "question": "x", "csrf": token}).status_code
             for _ in range(main.ASK_PER_MINUTE_ANALYST)]
    assert codes[-1] == 429, "an analyst is still limited, just less tightly"


def test_the_model_meter_counts_tokens_and_prices_them(cloud_run, monkeypatch):
    genai.load_usage({})
    cloud_run["reply"] = FakeResp(200, {"candidates": [{"content": {"parts": [{"text": "An account."}]}}],
                                        "usageMetadata": {"promptTokenCount": 3000, "candidatesTokenCount": 500,
                                                          "thoughtsTokenCount": 100, "totalTokenCount": 3600}})
    assert genai.generate_prose("s", "u") == ("An account.", "vertex")
    assert genai.generate_prose("s", "u")[0] == "An account."
    use = genai.usage()
    assert (use["calls"], use["input"], use["output"], use["thinking"]) == (2, 6000, 1000, 200)
    # 6,000 in at $1.50 a million and 1,200 out (thinking is billed as output) at $9.00 a million
    assert use["cost_usd"] == round((6000 * 1.50 + 1200 * 9.00) / 1_000_000, 4) == 0.0198
    assert use["per_call_usd"] == 0.0099 and use["since"]
    monkeypatch.setenv("TRIAGLE_PRICE_IN", "0.5")
    monkeypatch.setenv("TRIAGLE_PRICE_OUT", "3")
    assert genai.usage()["cost_usd"] == 0.0066

    # the totals come back after a restart, and a damaged record does no harm
    saved = {k: genai.USAGE[k] for k in ("calls", "input", "output", "thinking", "since")}
    genai.load_usage({"calls": "x"})
    assert genai.usage()["calls"] == 0
    genai.load_usage(saved)
    assert genai.usage()["calls"] == 2 and genai.status()["usage"]["input"] == 6000
    genai.load_usage({})
