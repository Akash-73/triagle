"""What makes the console safe to put in front of a customer: a second factor,
single sign-on, a key for each customer, the caller's real address, and a
page policy that refuses scripts that are not ours.

    python -m pytest -q tests/test_hardening.py
"""
import base64
import glob
import json
import os
import re
import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main, sso

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RFC_KEY = base64.b32encode(b"12345678901234567890").decode()      # the key in RFC 6238's test vectors
SECRET = "s3cret"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    for name in ("TRIAGLE_OIDC_CLIENT_ID", "TRIAGLE_OIDC_CLIENT_SECRET", "TRIAGLE_OIDC_ISSUER", "TRIAGLE_OIDC_NAME",
                 "TRIAGLE_PUBLIC_URL", "K_SERVICE", "TRIAGLE_FORWARDED_HOPS", "TRIAGLE_GUEST"):
        monkeypatch.delenv(name, raising=False)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": SECRET})
    main._CACHE.clear()
    sso._cache.clear()
    yield
    monkeypatch.setattr(main, "INGEST_KEYS", {})
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": SECRET})


def anon():
    return TestClient(main.app)


def last_event():
    return audit.read()[0]


# ---- a second factor ---------------------------------------------------------------

def test_codes_match_the_standards_own_examples():
    for at, code in ((59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (2000000000, "279037")):
        assert auth.totp_code(RFC_KEY, at) == code
    key = auth.new_totp_key()
    assert len(base64.b32decode(key + "=" * (-len(key) % 8))) == 20 and key != auth.new_totp_key()


def _with_code(now=1234567890):
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_ADMIN_TOTP": RFC_KEY, "TRIAGLE_SECRET": SECRET})
    return now


def test_a_user_with_a_key_cannot_sign_in_without_the_code():
    now = _with_code()
    assert auth.check_login("admin", "correct horse", now=now) == (None, "invalid")
    assert auth.check_login("admin", "correct horse", now=now, code="000000") == (None, "invalid")
    user, reason = auth.check_login("admin", "correct horse", now=now, code="005924")
    assert reason == "ok" and user == {"name": "admin", "role": "analyst"}


def test_a_code_works_once_and_a_clock_a_little_off_is_forgiven():
    now = _with_code()
    assert auth.check_login("admin", "correct horse", now=now, code="005924")[1] == "ok"
    assert auth.check_login("admin", "correct horse", now=now + 1, code="005924")[1] == "invalid", "read over a shoulder"
    nxt = auth.totp_code(RFC_KEY, now + 30)
    assert auth.check_login("admin", "correct horse", now=now + 5, code=nxt)[1] == "ok"       # the phone runs 25 s fast
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_ADMIN_TOTP": RFC_KEY, "TRIAGLE_SECRET": SECRET})
    old = auth.totp_code(RFC_KEY, now - 90)
    assert auth.check_login("admin", "correct horse", now=now, code=old)[1] == "invalid"       # three steps old


def test_a_wrong_code_counts_towards_the_lockout_and_says_nothing_about_the_password():
    now = _with_code()
    for _ in range(auth.MAX_FAILURES):
        assert auth.check_login("admin", "correct horse", "9.9.9.9", now=now, code="111111") == (None, "invalid")
    assert auth.check_login("admin", "correct horse", "9.9.9.9", now=now, code="005924") == (None, "locked")


def test_a_key_that_cannot_be_read_locks_the_account_instead_of_dropping_the_second_factor():
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_ADMIN_TOTP": "not base32 !!", "TRIAGLE_SECRET": SECRET})
    assert auth.needs_code("admin")
    assert auth.check_login("admin", "correct horse", code="123456")[1] == "invalid"


def test_a_named_user_carries_a_key_as_a_fourth_field():
    auth.load_config({"TRIAGLE_SECRET": SECRET,
                      "TRIAGLE_USERS": f"asha:analyst:{auth.hash_password('pw one')}:{RFC_KEY},vik:viewer:{auth.hash_password('pw two')}"})
    assert auth.needs_code("asha") and not auth.needs_code("vik")
    assert auth.check_login("vik", "pw two")[1] == "ok"
    assert auth.check_login("asha", "pw one", now=59)[1] == "invalid"
    assert auth.check_login("asha", "pw one", now=59, code="287 082")[0] == {"name": "asha", "role": "analyst"}


def test_the_sign_in_page_asks_for_a_code_only_when_someone_has_one():
    assert 'name="code"' not in anon().get("/login").text
    _with_code()
    page = anon().get("/login").text
    assert 'name="code"' in page and "authenticator app" in page
    r = anon().post("/login", data={"username": "admin", "password": "correct horse", "code": "000000"})
    assert r.status_code == 401 and "Wrong username, password or code." in r.text


def test_the_command_that_makes_a_key_prints_one_an_app_can_read():
    out = subprocess.run([sys.executable, "-m", "app.auth", "totp", "asha"], cwd=ROOT, capture_output=True, text=True,
                         env={**os.environ, "TRIAGLE_ADMIN_PASSWORD": "x"}).stdout
    key = re.search(r"Key for asha:\s+([A-Z2-7]{32})", out).group(1)
    assert f"otpauth://totp/Triagle:asha?secret={key}&issuer=Triagle" in out


# ---- single sign-on ----------------------------------------------------------------

CLIENT = "client-123.apps.googleusercontent.com"


class Provider:
    """Stands in for the identity provider's token endpoint."""

    def __init__(self, monkeypatch, **claims):
        self.claims = {"iss": "https://accounts.google.com", "aud": CLIENT, "exp": 4102444800,
                       "email": "asha@example.com", "email_verified": True}
        self.claims.update(claims)
        self.sent = None
        monkeypatch.setattr(sso.requests, "post", self._post)
        monkeypatch.setattr(sso.requests, "get", self._get)

    def _get(self, url, **kw):
        raise sso.requests.RequestException("no network in tests")       # falls back to the known Google endpoints

    def _post(self, url, data=None, **kw):
        self.sent = {"url": url, **data}
        body = base64.urlsafe_b64encode(json.dumps(self.claims).encode()).decode().rstrip("=")

        class R:
            status_code = 200

            @staticmethod
            def json():
                return {"id_token": "e30." + body + ".sig", "access_token": "x"}
        return R()


def _sso_on(monkeypatch, users="asha@example.com:analyst,vik@example.com:viewer", **extra):
    monkeypatch.setenv("TRIAGLE_OIDC_CLIENT_ID", CLIENT)
    monkeypatch.setenv("TRIAGLE_OIDC_CLIENT_SECRET", "shh")
    env = {"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": SECRET, "TRIAGLE_OIDC_USERS": users,
           "TRIAGLE_OIDC_CLIENT_ID": CLIENT, "TRIAGLE_OIDC_CLIENT_SECRET": "shh"}
    env.update(extra)
    auth.load_config(env)


def _start(c, nxt="/alerts"):
    r = c.get("/auth/start", params={"next": nxt}, follow_redirects=False)
    assert r.status_code == 303
    return r, dict(p.split("=", 1) for p in r.headers["location"].split("?", 1)[1].split("&"))


def test_without_a_provider_there_is_no_single_sign_on():
    assert anon().get("/auth/start", follow_redirects=False).status_code == 404
    assert anon().get("/auth/callback", follow_redirects=False).status_code == 404
    assert "/auth/start" not in anon().get("/login").text


def test_the_browser_is_sent_to_the_provider_with_a_state_a_nonce_and_a_challenge(monkeypatch):
    _sso_on(monkeypatch)
    Provider(monkeypatch)
    c = anon()
    assert "Sign in with Google" in c.get("/login").text
    r, q = _start(c)
    assert r.headers["location"].startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert q["client_id"] == CLIENT and q["response_type"] == "code" and q["code_challenge_method"] == "S256"
    assert q["redirect_uri"] == "http%3A%2F%2Ftestserver%2Fauth%2Fcallback" and len(q["state"]) >= 24 and len(q["nonce"]) >= 24
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(sso.COOKIE + "=") and "HttpOnly" in cookie and "Path=/auth" in cookie


def _finish(c, monkeypatch, tamper=None, **claims):
    """Start, then come back from the provider. Returns (response, provider)."""
    _, q = _start(c)
    p = Provider(monkeypatch, nonce=q["nonce"], **claims)
    params = {"code": "the-code", "state": q["state"]}
    if tamper:
        params.update(tamper)
    return c.get("/auth/callback", params=params, follow_redirects=False), p


def test_an_address_on_the_list_gets_in_with_its_role(monkeypatch):
    _sso_on(monkeypatch)
    c = anon()
    r, p = _finish(c, monkeypatch)
    assert r.status_code == 303 and r.headers["location"] == "/alerts"
    assert p.sent["url"] == "https://oauth2.googleapis.com/token" and p.sent["code"] == "the-code"
    assert p.sent["client_secret"] == "shh" and len(p.sent["code_verifier"]) >= 43
    assert p.sent["redirect_uri"] == "http://testserver/auth/callback"
    assert "asha@example.com" in c.get("/").text
    assert c.get("/audit").status_code == 200                              # an analyst
    e = last_event()
    assert (e["event"], e["user"], e["method"]) == ("signed in", "asha@example.com", "single sign-on")

    v = anon()
    r, _ = _finish(v, monkeypatch, email="Vik@Example.com")
    assert r.status_code == 303 and v.get("/audit").status_code == 403     # a viewer


def test_an_address_that_is_not_on_the_list_is_refused_and_logged(monkeypatch):
    _sso_on(monkeypatch)
    c = anon()
    r, _ = _finish(c, monkeypatch, email="stranger@example.com")
    assert r.headers["location"] == "/login?error=list"
    assert c.get("/", follow_redirects=False).status_code == 303           # still not signed in
    e = last_event()
    assert (e["event"], e["user"], e["reason"]) == ("sign-in failed", "stranger@example.com", "not on the list")
    assert "That account is not on this console" in c.get("/login?error=list").text


@pytest.mark.parametrize("claims,tamper,reason", [
    ({}, {"state": "someone-elses"}, "state"),
    ({"aud": "another-app"}, None, "issuer"),
    ({"iss": "https://evil.example"}, None, "issuer"),
    ({"exp": 1}, None, "expired"),
    ({"nonce": "replayed"}, None, "nonce"),
    ({"email_verified": False}, None, "unverified"),
    ({"email": ""}, None, "unverified"),
])
def test_a_reply_that_does_not_add_up_is_refused(monkeypatch, claims, tamper, reason):
    _sso_on(monkeypatch)
    c = anon()
    _, q = _start(c)
    Provider(monkeypatch, **{"nonce": q["nonce"], **claims})
    params = {"code": "the-code", "state": q["state"]}
    params.update(tamper or {})
    r = c.get("/auth/callback", params=params, follow_redirects=False)
    assert r.headers["location"] == "/login?error=sso"
    assert last_event()["reason"] == reason
    assert c.get("/", follow_redirects=False).status_code == 303


def test_a_reply_cannot_be_finished_by_a_browser_that_did_not_start_it(monkeypatch):
    _sso_on(monkeypatch)
    started = anon()
    _, q = _start(started)
    Provider(monkeypatch, nonce=q["nonce"])
    other = anon()                                                          # the attacker's link, opened by a victim
    r = other.get("/auth/callback", params={"code": "the-code", "state": q["state"]}, follow_redirects=False)
    assert r.headers["location"] == "/login?error=sso" and last_event()["reason"] == "expired"


def test_the_way_back_stays_on_this_site(monkeypatch):
    _sso_on(monkeypatch)
    c = anon()
    _, q = _start(c, nxt="https://evil.example/x")
    Provider(monkeypatch, nonce=q["nonce"])
    r = c.get("/auth/callback", params={"code": "c", "state": q["state"]}, follow_redirects=False)
    assert r.headers["location"] == "/"


def test_someone_taken_off_the_list_is_signed_out(monkeypatch):
    _sso_on(monkeypatch)
    c = anon()
    _finish(c, monkeypatch)
    assert c.get("/", follow_redirects=False).status_code == 200
    _sso_on(monkeypatch, users="vik@example.com:viewer")
    assert c.get("/", follow_redirects=False).status_code == 303


def test_password_sign_in_can_be_turned_off_once_single_sign_on_works(monkeypatch):
    _sso_on(monkeypatch, TRIAGLE_PASSWORD_LOGIN="off")
    page = anon().get("/login").text
    assert "Sign in with Google" in page and 'name="password"' not in page
    assert anon().post("/login", data={"username": "admin", "password": "correct horse"}).status_code == 401
    # ...but not when it would lock everyone out
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": SECRET, "TRIAGLE_PASSWORD_LOGIN": "off"})
    assert auth.password_login() and auth.check_login("admin", "correct horse")[1] == "ok"


def test_another_provider_is_found_by_its_own_address(monkeypatch):
    _sso_on(monkeypatch)
    monkeypatch.setenv("TRIAGLE_OIDC_ISSUER", "https://login.example.com/tenant/v2.0")
    asked = []

    class Doc:
        status_code = 200

        @staticmethod
        def json():
            return {"issuer": "https://login.example.com/tenant/v2.0",
                    "authorization_endpoint": "https://login.example.com/authorize",
                    "token_endpoint": "https://login.example.com/token"}
    monkeypatch.setattr(sso.requests, "get", lambda url, **kw: asked.append(url) or Doc())
    r = anon().get("/auth/start", follow_redirects=False)
    assert asked == ["https://login.example.com/tenant/v2.0/.well-known/openid-configuration"]
    assert r.headers["location"].startswith("https://login.example.com/authorize?")
    assert "Sign in with single sign-on" in anon().get("/login").text


# ---- the caller's address ----------------------------------------------------------

class _Req:
    def __init__(self, forwarded=None, peer="10.0.0.9"):
        self.headers = {"x-forwarded-for": forwarded} if forwarded else {}
        self.client = type("C", (), {"host": peer})()


def test_the_header_is_ignored_when_no_proxy_of_ours_is_in_front():
    assert main._client_ip(_Req("1.2.3.4")) == "10.0.0.9"


def test_only_the_entry_our_own_proxy_added_is_believed(monkeypatch):
    monkeypatch.setenv("K_SERVICE", "triagle")                             # Cloud Run: its front end adds the last entry
    assert main._client_ip(_Req("6.6.6.6, 203.0.113.7")) == "203.0.113.7", "the first entry is the caller's own claim"
    assert main._client_ip(_Req("203.0.113.7")) == "203.0.113.7"
    assert main._client_ip(_Req(None)) == "10.0.0.9"
    monkeypatch.setenv("TRIAGLE_FORWARDED_HOPS", "2")                      # a load balancer in front of that
    assert main._client_ip(_Req("6.6.6.6, 203.0.113.7, 35.191.0.1")) == "203.0.113.7"


def test_a_guesser_cannot_dodge_the_lockout_by_changing_the_header(monkeypatch):
    monkeypatch.setenv("K_SERVICE", "triagle")
    c = anon()
    for i in range(auth.MAX_FAILURES):
        r = c.post("/login", data={"username": f"user{i}", "password": "x"},
                   headers={"X-Forwarded-For": f"10.9.9.{i}, 203.0.113.7"})
        assert r.status_code == 401
    r = c.post("/login", data={"username": "admin", "password": "correct horse"},
               headers={"X-Forwarded-For": "8.8.8.8, 203.0.113.7"})
    assert r.status_code == 429


# ---- a key for each customer -------------------------------------------------------

BANK_KEY, GRID_KEY = "bank-key-0123456789abcdef", "grid-key-0123456789abcdef"


def _edr(n, host="FIN-07"):
    return {"detection_id": f"hk-{n}", "created_timestamp": "2026-11-25T10:00:00Z", "name": "Routine software inventory",
            "severity": "low", "hostname": host, "user_name": "u1", "description": ""}


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setenv("TRIAGLE_SEED", "off")
    monkeypatch.setattr(main, "INGEST_KEYS", main._customer_keys(f"Bank One={BANK_KEY}; Grid Two={GRID_KEY}"))
    main._CACHE.clear()
    return anon()


def _clients():
    return {a["alert_id"]: a["client"] for a in main._load_result()["alerts"]}


def test_the_key_decides_whose_alert_it_is(keyed):
    r = keyed.post("/ingest", headers={"X-Triagle-Key": BANK_KEY},
                   json=[{"source": "crowdstrike_edr", "client": "Bank One", "raw": _edr(1)},
                         {"source": "crowdstrike_edr", "client": "Grid Two", "raw": _edr(2)},       # not theirs to write to
                         {"source": "crowdstrike_edr", "raw": _edr(3)}])
    assert r.status_code == 200 and r.json()["accepted"] == 3
    assert set(_clients().values()) == {"Bank One"}
    e = last_event()
    assert e["user"] == "siem-webhook: Bank One" and e["named_another_customer"] == 1
    keyed.post("/ingest", headers={"X-Triagle-Key": GRID_KEY}, json={"source": "crowdstrike_edr", "client": "Bank One", "raw": _edr(4)})
    assert sorted(_clients().values()).count("Grid Two") == 1


def test_a_wrong_or_missing_key_is_refused(keyed):
    for headers in ({}, {"X-Triagle-Key": "nope"}, {"X-Triagle-Key": BANK_KEY[:-1]}, {"X-Triagle-Key": ""}):
        r = keyed.post("/ingest", headers=headers, json={"source": "crowdstrike_edr", "client": "Bank One", "raw": _edr(9)})
        assert r.status_code == 401
    assert main._customer_keys("Tiny=short") == {}, "a short key is refused, not half-trusted"


def test_a_key_may_contain_an_equals_sign():
    """A base64 key usually ends in "=". The customer's name ends at the first one."""
    key = "c2VjcmV0LWtleS1mb3ItYS1iYW5r=="
    assert main._customer_keys(f"Greenvale Co-operative Bank={key}") == {key: "Greenvale Co-operative Bank"}
    assert main._customer_keys(f"Bank One={BANK_KEY}\nGrid Two = {key} ; ") == {BANK_KEY: "Bank One", key: "Grid Two"}


def test_a_customers_key_reads_back_that_customers_record_only(keyed):
    with main._LOCK:
        main._ensure_state()
        box = main._outbox()
        for i, client in enumerate(("Bank One", "Grid Two", "Bank One")):
            box["seq"] += 1
            box["events"].append({"seq": box["seq"], "client": client, "event": "closed by an analyst", "alert_id": f"a{i}"})
    mine = keyed.get("/api/outbox", headers={"X-Triagle-Key": GRID_KEY}, params={"client": "Bank One"}).json()["events"]
    assert [e["client"] for e in mine] == ["Grid Two"], "asking for another customer by name changes nothing"
    assert len(keyed.get("/api/outbox", headers={"X-Triagle-Key": BANK_KEY}).json()["events"]) == 2


def test_the_shared_key_still_works_for_a_deployment_that_has_not_moved_yet(monkeypatch):
    monkeypatch.setenv("TRIAGLE_SEED", "off")
    monkeypatch.setattr(main, "INGEST_KEY", "one-shared-key-for-everything")
    main._CACHE.clear()
    r = anon().post("/ingest", headers={"X-Triagle-Key": "one-shared-key-for-everything"},
                    json={"source": "crowdstrike_edr", "client": "Greenvale", "raw": _edr(1)})
    assert r.status_code == 200 and set(_clients().values()) == {"Greenvale"}


# ---- a page policy that refuses scripts that are not ours ---------------------------

PAGES = ["/", "/live", "/alerts", "/cases", "/clock", "/morning", "/connectors", "/tuning", "/taught", "/checks",
         "/benchmark", "/audit", "/pilot", "/alert/ldt:aaa101", "/login"]


def _signed_in():
    c = anon()
    assert c.post("/login", data={"username": "admin", "password": "correct horse"}, follow_redirects=False).status_code == 303
    return c


def test_the_policy_allows_only_our_own_scripts():
    r = _signed_in().get("/")
    csp = r.headers["content-security-policy"]
    script = re.search(r"script-src ([^;]+)", csp).group(1)
    assert "'unsafe-inline'" not in script and "'unsafe-eval'" not in script and "'self'" in script
    assert re.search(r"'nonce-[A-Za-z0-9_-]{16,}'", script)
    assert "frame-ancestors 'none'" in csp and "form-action 'self'" in csp and "object-src 'none'" in csp
    assert "geolocation=()" in r.headers["permissions-policy"]


@pytest.mark.parametrize("path", PAGES)
def test_every_script_on_every_page_carries_that_pages_nonce(path):
    c = _signed_in() if path != "/login" else anon()
    r = c.get(path)
    assert r.status_code == 200, path
    nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'", r.headers["content-security-policy"]).group(1)
    tags = re.findall(r"<script\b([^>]*)>", r.text)
    assert tags, path
    for attrs in tags:
        assert f'nonce="{nonce}"' in attrs or 'src="/static/' in attrs, (path, attrs)
    assert not re.search(r"<[a-z][^>]*\son[a-z]+\s*=", r.text), f"an inline handler on {path}"
    assert "javascript:" not in r.text.lower()


def test_two_pages_never_share_a_nonce():
    c = _signed_in()
    seen = {re.search(r"'nonce-([A-Za-z0-9_-]+)'", c.get("/").headers["content-security-policy"]).group(1) for _ in range(5)}
    assert len(seen) == 5


def test_no_template_has_an_inline_handler_or_a_bare_script():
    for path in glob.glob(os.path.join(ROOT, "templates", "*.html")):
        text = open(path, encoding="utf-8").read()
        assert "<script>" not in text, path
        assert not re.search(r"\son(click|change|submit|load|error|input|keyup|keydown)\s*=", text), path


# ---- every route, by who may call it ------------------------------------------------
#
# The list is read from the application itself, so a route added later is
# checked without anyone remembering to add it here.

OPEN_TO_ALL = {"/login", "/logout", "/health", "/healthz", "/auth/start", "/auth/callback", "/security"}
BY_KEY = {"/ingest", "/api/outbox"}                      # a tool's key, or a signed-in analyst
# a viewer may ask about a case, try an alert and watch the investigator work; none of these stores anything
READ_ONLY_POSTS = {"/api/ask", "/api/try", "/api/agent/run", "/api/try/account", "/api/try/opinion"}
# The one thing a visitor may leave: whether the verdict on an alert they tried was right. It is kept in a
# record of its own. It joins no queue, changes no verdict and runs no action (tests/test_try.py).
A_VISITOR_MAY_LEAVE = {"/api/try/feedback"}


def _routes(method):
    out = []
    for r in main.app.routes:
        if method in (getattr(r, "methods", None) or ()):
            out.append(r.path.replace("{alert_id}", "ldt:aaa101").replace("{ref}", "INC-000000")
                       .replace("{entity}", "MRD-FIN-07").replace("{regulator}", "certin"))
    return sorted(out)


def _post(c, path):
    form = c.post(path, data={"alert_id": "ldt:aaa101", "action_id": "x"}, follow_redirects=False)
    body = c.post(path, json={"alert_id": "ldt:aaa101"}, follow_redirects=False)
    return form.status_code, body.status_code


def test_nobody_reaches_a_page_or_an_action_without_signing_in():
    c = anon()
    for path in _routes("GET"):
        if path in OPEN_TO_ALL:
            continue
        r = c.get(path, follow_redirects=False)
        assert r.status_code in (303, 401), (path, r.status_code)
        if r.status_code == 303:
            assert r.headers["location"].startswith("/login"), path
    for path in _routes("POST"):
        if path in OPEN_TO_ALL:
            continue
        assert set(_post(c, path)) <= {401}, (path, _post(c, path))


def test_a_viewer_and_a_guest_can_change_nothing(monkeypatch):
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": SECRET,
                      "TRIAGLE_USERS": "vik:viewer:" + auth.hash_password("look only")})
    viewer = anon()
    assert viewer.post("/login", data={"username": "vik", "password": "look only"}, follow_redirects=False).status_code == 303
    monkeypatch.setenv("TRIAGLE_GUEST", "view")
    guest = anon()
    assert guest.get("/", follow_redirects=False).status_code == 200            # the guest view is on
    before = json.dumps(main._load_result()["verdicts"], sort_keys=True, default=str)
    for who, c in (("viewer", viewer), ("guest", guest)):
        for path in _routes("POST"):
            if path in OPEN_TO_ALL or path in READ_ONLY_POSTS or path in A_VISITOR_MAY_LEAVE:
                continue
            codes = set(_post(c, path))
            assert codes <= {401, 403}, (who, path, codes)
    assert json.dumps(main._load_result()["verdicts"], sort_keys=True, default=str) == before
    assert guest.get("/audit", follow_redirects=False).status_code == 403


def test_an_analysts_request_without_the_form_token_is_refused():
    import inspect
    c = _signed_in()
    for path in _routes("POST"):
        if path in OPEN_TO_ALL or path in BY_KEY:
            continue
        codes = set(_post(c, path))
        assert codes <= {400, 403, 422}, (path, codes)   # refused, or not even readable: never carried out
    # and every handler that changes something checks the token itself
    for r in main.app.routes:
        if "POST" in (getattr(r, "methods", None) or ()) and r.path not in {"/login"} | BY_KEY:
            source = inspect.getsource(r.endpoint)
            assert "csrf" in source or "_analyst_call(" in source, r.path


# ---- the public page that says what Triagle holds -----------------------------------

def test_anyone_can_read_how_data_is_handled_and_it_gives_nothing_away(monkeypatch):
    monkeypatch.setenv("TRIAGLE_CONTACT", "security@example.com")
    r = anon().get("/security")
    assert r.status_code == 200
    for words in ("What Triagle is given", "A key on the way in", "Masked first", "Not done yet",
                  "An independent penetration test", "security@example.com", "Report a vulnerability"):
        assert words in r.text, words
    # it claims only what is true of the deployment serving it
    assert "A key for each customer" not in r.text
    monkeypatch.setattr(main, "INGEST_KEYS", {"k" * 20: "Bank One"})
    assert "A key for each customer" in anon().get("/security").text
    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    assert "unprivileged user" not in anon().get("/security").text
    monkeypatch.setattr(main.os, "geteuid", lambda: 10001)
    assert "runs as an unprivileged user" in anon().get("/security").text
    # nothing about this deployment: no customer, no machine, no setting
    for secret in ("correct horse", "MRD-FIN-07", "Meridian", SECRET):
        assert secret not in r.text
    assert "/security" in anon().get("/login").text


# ---- open-source intelligence on addresses -----------------------------------------

from app.engine import osint, reputation, worknotes

FEED = "# IPsum\n# Last update: Thu, 26 Nov 2026 03:00:45 +0100\n#\n" + "\n".join(
    ["2.57.121.112\t8", "92.118.39.71\t2", "bad line", "300.1.1.1\t5", "10.0.0.5\t4"]
    + [f"45.{i // 250}.{i % 250}.7\t1" for i in range(1200)])


@pytest.fixture
def lists(monkeypatch):
    """The public lists, loaded from text, with no call made."""
    monkeypatch.setenv("TRIAGLE_OSINT", "on")
    got, updated = osint.parse(FEED)
    monkeypatch.setattr(osint, "_state", {"lists": got, "updated": updated, "fetched_at": time.time(),
                                          "tried_at": time.time(), "error": None})
    monkeypatch.setattr(osint, "_fetch", lambda: (_ for _ in ()).throw(AssertionError("no call is expected")))


def test_the_public_lists_are_off_unless_asked_for_or_on_cloud_run(monkeypatch):
    monkeypatch.delenv("TRIAGLE_OSINT", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.setattr(osint, "_fetch", lambda: (_ for _ in ()).throw(AssertionError("no call is expected")))
    assert not osint.enabled() and osint.lookup("2.57.121.112") is None
    monkeypatch.setenv("K_SERVICE", "triagle")
    assert osint.enabled()
    monkeypatch.setenv("TRIAGLE_OSINT", "off")
    assert not osint.enabled()


def test_an_address_is_looked_up_here_and_a_private_one_is_not(lists):
    assert osint.parse(FEED)[1] == "Thu, 26 Nov 2026 03:00:45 +0100"
    assert osint.lookup("2.57.121.112")["lists"] == 8 and "several independent" in osint.lookup("2.57.121.112")["words"]
    assert osint.lookup("92.118.39.71")["lists"] == 2 and "thin" in osint.lookup("92.118.39.71")["words"]
    assert osint.lookup("8.8.8.8")["lists"] == 0 and "clears nothing" in osint.lookup("8.8.8.8")["words"]
    assert osint.lookup("10.0.0.5") is None and osint.lookup("not an address") is None
    assert osint.lines(["2.57.121.112", "10.0.0.5", "2.57.121.112"]).count("\n") == 0


def test_a_failed_or_short_fetch_keeps_the_list_that_is_there(monkeypatch):
    monkeypatch.setenv("TRIAGLE_OSINT", "on")
    good = {"2.57.121.112": 8}
    monkeypatch.setattr(osint, "_state", {"lists": good, "updated": "x", "fetched_at": 0.0, "tried_at": 0.0, "error": None})
    monkeypatch.setattr(osint, "_fetch", lambda: (_ for _ in ()).throw(ValueError("the reply held only 3 addresses")))
    assert osint.ensure() and osint.lookup("2.57.121.112")["lists"] == 8
    assert "only 3" in osint.status()["error"]
    calls = []
    monkeypatch.setattr(osint, "_fetch", lambda: calls.append(1) or ({}, ""))
    osint.ensure()
    assert not calls, "after a failure it waits before trying again"


def test_the_lists_are_shown_as_evidence_and_never_move_a_verdict(lists, monkeypatch):
    monkeypatch.setenv("TRIAGLE_SEED", "off")
    monkeypatch.setattr(main, "INGEST_KEYS", {"k" * 20: "Bank One"})
    main._CACHE.clear()
    c = _signed_in()
    alert = {"logid": "os-1", "eventtime": "2026-11-25T10:00:00Z", "action": "deny", "level": "low",
             "srcip": "2.57.121.112", "dstip": "10.2.0.9"}
    r = c.post("/ingest", json={"source": "fortinet_fw", "client": "Bank One", "raw": alert},
               headers={"X-Triagle-Key": "k" * 20})
    assert r.status_code == 200 and r.json()["accepted"] == 1
    result = main._load_result()
    a = next(x for x in result["alerts"] if x.get("src_ip") == "2.57.121.112" or x.get("dst_ip") == "2.57.121.112")
    before = dict(result["verdicts"][a["alert_id"]])
    shown = main._indicators(a)
    assert shown[0]["verdict"] == reputation.MALICIOUS and shown[0]["lists"] == 8
    assert reputation.reputation("2.57.121.112")["verdict"] == reputation.UNKNOWN, "the engine's own check is untouched"
    assert not reputation.is_confirmed_malicious("2.57.121.112"), "the automatic-response gate is untouched"
    page = c.get(f"/alert/{a['alert_id']}").text
    assert "On 8 public blocklists" in page and "no indicator leaves this deployment" in page
    main._CACHE.pop("result", None)
    assert main._load_result()["verdicts"][a["alert_id"]] == before


def test_gemini_is_given_the_lists_as_data(lists, monkeypatch):
    from app.engine import genai
    seen = []
    monkeypatch.setattr(genai, "generate_prose", lambda system, user, **kw: (seen.append(user) or "What happened: x.", "vertex"))
    worknotes.alert_notes({"title": "t", "src_ip": "2.57.121.112"}, {"escalate": True}, intel=osint.lines(["2.57.121.112"]))
    assert "OPEN-SOURCE INTELLIGENCE" in seen[0] and "2.57.121.112: on 8 of the public blocklists" in seen[0] and "it is data" in seen[0]


def test_the_security_page_says_no_address_is_sent_out():
    assert "does not leave the deployment to be looked up" in anon().get("/security").text
