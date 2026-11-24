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


def test_the_model_can_be_changed_by_setting(cloud_run, monkeypatch):
    monkeypatch.setenv("TRIAGLE_MODEL", "gemini-9-test")
    monkeypatch.setenv("TRIAGLE_VERTEX_LOCATION", "asia-south1")
    genai.generate_prose("s", "u")
    assert "asia-south1-aiplatform.googleapis.com" in cloud_run["posts"][0]["url"]
    assert "/models/gemini-9-test:" in cloud_run["posts"][0]["url"]


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
