"""Sign-in, roles, form tokens and the audit log.  python -m pytest -q"""
import json
import re

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main

ACTION = "ldt:aaa101:isolate_host:MRD-FIN-07"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": "s3cret",
                      "TRIAGLE_USERS": "vik:viewer:" + auth.hash_password("look only")})
    main._CACHE.clear()
    yield
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": "s3cret"})


def anon():
    return TestClient(main.app)


def login(user="admin", pw="correct horse"):
    c = anon()
    assert c.post("/login", data={"username": user, "password": pw}, follow_redirects=False).status_code == 303
    return c


def csrf(c, path="/alert/ldt:aaa101"):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get(path).text).group(1)


def events():
    return [(e["event"], e["user"]) for e in audit.read()][::-1]


# ---- nobody gets in without signing in --------------------------------------

@pytest.mark.parametrize("path", ["/", "/tuning", "/benchmark", "/audit", "/alert/ldt:aaa101",
                                  "/report/MRD-FIN-07", "/certin/MRD-FIN-07"])
def test_pages_redirect_to_login(path):
    r = anon().get(path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=")

def test_anonymous_cannot_approve():
    r = anon().post("/action/approve", data={"alert_id": "ldt:aaa101", "action_id": ACTION})
    assert r.status_code == 401
    main._load_result()
    assert main._CACHE["result"]["actions"]["ldt:aaa101"][0]["status"] == "pending"

def test_api_docs_are_not_exposed():
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert anon().get(p).status_code == 404

def test_healthz_is_public_but_says_little():
    assert set(anon().get("/healthz").json()) == {"ok", "version"}
    assert "audit_chain_ok" in login().get("/healthz").json()


# ---- signing in ---------------------------------------------------------------

def test_wrong_password_is_refused_and_logged():
    r = anon().post("/login", data={"username": "admin", "password": "nope"})
    assert r.status_code == 401 and "Wrong username or password" in r.text
    assert ("sign-in failed", "admin") in events()

def test_unknown_user_gets_the_same_answer():
    r = anon().post("/login", data={"username": "ghost", "password": "nope"})
    assert r.status_code == 401 and "Wrong username or password" in r.text

def test_lockout_after_repeated_failures():
    c = anon()
    for _ in range(auth.MAX_FAILURES):
        c.post("/login", data={"username": "admin", "password": "nope"})
    r = c.post("/login", data={"username": "admin", "password": "correct horse"})
    assert r.status_code == 429          # even the right password waits out the lockout

def test_lockout_expires():
    for i in range(auth.MAX_FAILURES):
        auth.check_login("admin", "nope", "1.1.1.1", now=1000 + i)
    assert auth.check_login("admin", "correct horse", "1.1.1.1", now=1010)[1] == "locked"
    assert auth.check_login("admin", "correct horse", "1.1.1.1", now=1000 + auth.LOCKOUT_SECONDS + 1)[1] == "ok"

def test_login_lands_on_the_page_asked_for_but_never_off_site():
    c = anon()
    r = c.post("/login", data={"username": "admin", "password": "correct horse", "next": "/tuning"},
               follow_redirects=False)
    assert r.headers["location"] == "/tuning"
    for evil in ("https://evil.example", "//evil.example", "/\\evil.example"):
        r = anon().post("/login", data={"username": "admin", "password": "correct horse", "next": evil},
                        follow_redirects=False)
        assert r.headers["location"] == "/"

def test_session_cookie_flags():
    r = anon().post("/login", data={"username": "admin", "password": "correct horse"}, follow_redirects=False)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    r = anon().post("/login", data={"username": "admin", "password": "correct horse"},
                    headers={"x-forwarded-proto": "https"}, follow_redirects=False)
    assert "secure" in r.headers["set-cookie"].lower()

def test_tampered_or_expired_cookie_is_rejected():
    token = auth.make_session({"name": "admin", "role": "analyst"}, now=1000)
    assert auth.read_session(token, now=1001)["name"] == "admin"
    assert auth.read_session(token, now=1000 + 9 * 3600) is None           # expired
    payload, sig = token.rsplit(".", 1)
    assert auth.read_session(payload + "." + "0" * len(sig), now=1001) is None
    forged = auth.make_session({"name": "vik", "role": "analyst"}, now=1000)  # role the user does not have
    assert auth.read_session(forged, now=1001) is None

def test_sign_out_ends_the_session():
    c = login()
    c.post("/logout", data={"csrf": csrf(c)}, follow_redirects=False)
    assert c.get("/", follow_redirects=False).status_code == 303
    assert ("signed out", "admin") in events()

def test_no_users_configured_means_a_random_password_not_an_open_door(capsys):
    state = auth.load_config({})
    assert state["enabled"] and state["generated_password"]
    assert state["generated_password"] in capsys.readouterr().err
    assert auth.check_login("admin", "", "9.9.9.9")[0] is None
    assert auth.check_login("admin", state["generated_password"], "9.9.9.8")[0]["role"] == "analyst"
    assert anon().get("/", follow_redirects=False).status_code == 303

def test_password_hashes_are_salted_and_verify():
    a, b = auth.hash_password("x"), auth.hash_password("x")
    assert a != b and auth.verify_password("x", a) and not auth.verify_password("y", a)
    assert not auth.verify_password("x", "not-a-hash")


# ---- who may approve ------------------------------------------------------------

def test_viewer_can_read_but_not_approve():
    c = login("vik", "look only")
    page = c.get("/alert/ldt:aaa101")
    assert page.status_code == 200 and "view-only" in page.text and "Approve &amp; execute" not in page.text
    r = c.post("/action/approve", data={"alert_id": "ldt:aaa101", "action_id": ACTION, "csrf": "x"})
    assert r.status_code == 403
    assert c.get("/audit").status_code == 403
    assert main._CACHE["result"]["actions"]["ldt:aaa101"][0]["status"] == "pending"

def test_approval_needs_the_form_token():
    c = login()
    for bad in ("", "0" * 64):
        r = c.post("/action/approve", data={"alert_id": "ldt:aaa101", "action_id": ACTION, "csrf": bad})
        assert r.status_code == 403
    assert main._load_result()["actions"]["ldt:aaa101"][0]["status"] == "pending"

def test_another_users_token_does_not_work():
    a, b = login(), login()
    r = b.post("/action/approve", data={"alert_id": "ldt:aaa101", "action_id": ACTION, "csrf": csrf(a)})
    assert r.status_code == 403

def test_approval_is_recorded_with_the_analysts_name():
    c = login()
    c.post("/action/approve", data={"alert_id": "ldt:aaa101", "action_id": ACTION, "csrf": csrf(c)})
    act = main._CACHE["result"]["actions"]["ldt:aaa101"][0]
    assert act["status"] == "executed" and act["decided_by"] == "admin" and "approved by admin" in act["result_message"]
    entry = next(e for e in audit.read() if e["event"] == "action approved")
    assert (entry["user"], entry["alert_id"], entry["action"], entry["target"]) == \
           ("admin", "ldt:aaa101", "isolate_host", "MRD-FIN-07")
    assert entry["simulated"] is True
    assert "decided by admin" in c.get("/alert/ldt:aaa101").text

def test_decline_is_recorded_with_reason_and_drops_out_of_the_draft():
    c = login()
    c.post("/action/approve", data={"alert_id": "ldt:aaa101", "action_id": ACTION, "csrf": csrf(c),
                                    "decision": "decline", "reason": "change freeze"})
    act = main._CACHE["result"]["actions"]["ldt:aaa101"][0]
    assert act["status"] == "declined" and "change freeze" in act["result_message"]
    entry = next(e for e in audit.read() if e["event"] == "action declined")
    assert entry["reason"] == "change freeze"

def test_a_decided_action_cannot_be_decided_again():
    c = login()
    data = {"alert_id": "ldt:aaa101", "action_id": ACTION, "csrf": csrf(c)}
    c.post("/action/approve", data=data)
    r = c.post("/action/approve", data={**data, "decision": "decline"}, follow_redirects=False)
    assert r.headers["location"].endswith("notice=done")
    assert main._CACHE["result"]["actions"]["ldt:aaa101"][0]["status"] == "executed"
    assert [e for e, _ in events()].count("action approved") == 1

def test_missing_acknowledgement_keeps_a_high_impact_action_pending():
    c = login()
    acts = main._load_result()["actions"]
    acts["ldt:aaa101"][0].update(requires_ack=True, risk_tier="high_impact")
    data = {"alert_id": "ldt:aaa101", "action_id": ACTION, "csrf": csrf(c)}
    r = c.post("/action/approve", data=data, follow_redirects=False)
    assert r.headers["location"].endswith("notice=ack") and acts["ldt:aaa101"][0]["status"] == "pending"
    c.post("/action/approve", data={**data, "ack": "on"})
    assert acts["ldt:aaa101"][0]["status"] == "executed"
    assert next(e for e in audit.read() if e["event"] == "action approved")["acknowledged_blast_radius"] is True

def test_unknown_action_is_404():
    c = login()
    r = c.post("/action/approve", data={"alert_id": "ldt:aaa101", "action_id": "nope", "csrf": csrf(c)})
    assert r.status_code == 404


# ---- the log itself ----------------------------------------------------------------

def test_chain_verifies_and_detects_an_edit(tmp_path):
    for i in range(4):
        audit.record("action approved", "admin", alert_id=f"a{i}")
    assert audit.verify() == {"ok": True, "entries": 4, "broken_at": None}
    lines = open(audit.path()).read().splitlines()
    edited = json.loads(lines[1]); edited["user"] = "someone-else"
    lines[1] = json.dumps(edited)
    open(audit.path(), "w").write("\n".join(lines) + "\n")
    assert audit.verify()["ok"] is False and audit.verify()["broken_at"] == 2

def test_chain_detects_a_deleted_line():
    for i in range(4):
        audit.record("signed in", "admin", n=i)
    lines = open(audit.path()).read().splitlines()
    open(audit.path(), "w").write("\n".join(lines[:1] + lines[2:]) + "\n")
    assert audit.verify()["ok"] is False

def test_audit_page_shows_entries_and_chain_state():
    c = login()
    page = c.get("/audit").text
    assert "Chain intact" in page and "signed in" in page
    with open(audit.path(), "a") as f:
        f.write('{"event":"action approved","user":"ghost","time":"x","prev":"bad","hash":"bad"}\n')
    assert "Chain broken" in c.get("/audit").text

def test_passwords_never_reach_the_log():
    anon().post("/login", data={"username": "admin", "password": "hunter2-wrong"})
    login()
    text = open(audit.path()).read()
    assert "hunter2-wrong" not in text and "correct horse" not in text


# ---- hardening ---------------------------------------------------------------------

def test_security_headers():
    h = login().get("/").headers
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
    assert h["cache-control"] == "no-store"

def test_auth_off_is_explicit_and_visible():
    auth.load_config({"TRIAGLE_AUTH": "off"})
    page = anon().get("/")
    assert page.status_code == 200 and "sign-in is OFF" in page.text
