"""The console pages: every page renders, for a case with a real feed behind it.

    python -m pytest -q tests/test_console.py
"""
import datetime as dt

import pytest
from fastapi.testclient import TestClient

from app import auth, main
from app.engine import genai, usecases, signals

KEY = "k"
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _wz(sec, rid, level, desc, eventdata, host="fin-laptop-07", groups=("sysmon", "windows")):
    t = NOW - dt.timedelta(minutes=30) + dt.timedelta(seconds=sec)
    return {"source": "wazuh", "client": "Greenvale Co-operative Bank", "raw": {
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "id": f"{int(t.timestamp())}.{rid}{sec}",
        "rule": {"id": rid, "level": level, "description": desc, "groups": list(groups)},
        "agent": {"id": "001", "name": host}, "manager": {"name": "wazuh"},
        "decoder": {"name": "windows_eventchannel"}, "location": "EventChannel",
        "data": {"win": {"system": {"eventID": "1"}, "eventdata": eventdata}}}}


PS = "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"       # doubled, as Wazuh writes it
CHAIN = [
    _wz(0, "92032", 3, "Suspicious Windows cmd shell execution", {"commandLine": "whoami  /all"}),
    _wz(10, "92031", 3, "Discovery activity executed", {"commandLine": "C:\\\\WINDOWS\\\\system32\\\\net1  user"}),
    _wz(60, "92057", 12, "Powershell.exe spawned a powershell process which executed a base64 encoded command",
        {"commandLine": f'"{PS}" -EncodedCommand RwBlAHQALQBEAGEAdABlAA==', "parentImage": PS}),
    _wz(90, "92027", 4, "Powershell process spawned powershell instance",
        {"commandLine": f'"{PS}" -Command IEX(\'Get-Date\')', "parentImage": PS}),
]


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    for k in ("K_SERVICE", "GOOGLE_CLOUD_PROJECT", "TRIAGLE_VERTEX", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    genai._cache.clear()
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s",
                      "TRIAGLE_USERS": "viewerbob:viewer:" + auth.hash_password("look")})
    main._CACHE.clear()
    main._WORKNOTES.clear()
    main._ASK_TIMES.clear()
    main._ASK_ALL.clear()
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    assert c.post("/ingest", headers={"X-Triagle-Key": KEY}, json=CHAIN).json()["accepted"] == 4
    yield c
    main._CACHE.clear()


def _case(app):
    result = main._load_result()
    return next(i for i in result["incidents"] if i["key"] == "fin-laptop-07")


def test_every_page_in_the_navigation_renders(app):
    for path in ("/", "/alerts", "/alerts?show=closed", "/alerts?show=all&q=powershell", "/cases", "/clock",
                 "/tuning", "/benchmark", "/audit"):
        r = app.get(path)
        assert r.status_code == 200, path
    assert 'aria-current="page"' in app.get("/alerts").text


def test_static_files_are_served_and_cacheable(app):
    r = app.get("/static/triagle.css")
    assert r.status_code == 200 and "max-age" in r.headers["cache-control"]
    assert app.get("/static/fonts/public-sans-latin-wght-normal.woff2").status_code == 200
    assert app.get("/").headers["cache-control"] == "no-store"


def test_the_overview_reads_as_a_handover(app):
    page = app.get("/").text
    assert "closed, each with a reason" in page and "Needs a decision" in page
    assert "Obfuscated PowerShell execution" in page                 # the use case, not the rule title


def test_discovery_is_closed_and_the_obfuscation_is_a_case(app):
    result = main._load_result()
    by_title = {a["title"]: result["verdicts"][a["alert_id"]] for a in result["alerts"] if a.get("host") == "fin-laptop-07"}
    assert not by_title["Suspicious Windows cmd shell execution"]["escalate"]
    assert not by_title["Discovery activity executed"]["escalate"]
    inc = _case(app)
    assert inc["size"] == 2


def test_the_case_page_shows_the_workflow_and_the_discovery_as_context(app):
    inc = _case(app)
    page = app.get(f"/case/{inc['id']}").text
    for word in ("Detected", "Investigated", "Contained", "Reported", "Timeline", "What Triagle checked",
                 "Ask Triagle about this case", "Reports due"):
        assert word in page, word
    assert "shown as context" in page and "whoami  /all" in page      # the closed discovery, in the timeline
    assert "Approve and run" in page                                   # isolating the host waits for a person
    assert "C:\\\\Windows" not in page and "C:\\Windows\\System32" in page   # paths read as Windows wrote them


def test_a_viewer_sees_the_case_but_cannot_approve(app):
    v = TestClient(main.app)
    v.post("/login", data={"username": "viewerbob", "password": "look"})
    page = v.get(f"/case/{_case(app)['id']}").text
    assert "view-only" in page and "Approve and run" not in page


def test_approving_from_the_case_page_returns_to_it(app):
    import re
    inc = _case(app)
    page = app.get(f"/case/{inc['id']}").text
    form = re.search(r'<form method="post" action="/action/approve">(.*?)</form>', page, re.S).group(1)
    fields = dict(re.findall(r'name="(\w+)" value="([^"]*)"', form))
    assert fields["next"] == f"/case/{inc['id']}"
    r = app.post("/action/approve", data={**fields, "decision": "decline", "reason": "test"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/case/{inc['id']}"
    # a redirect target that is not a case or alert page is ignored
    assert main._back_to("https://evil.example/x", "/alert/a") == "/alert/a"
    assert main._back_to("//evil.example", "/alert/a") == "/alert/a"


def test_notes_fall_back_to_a_labelled_summary_when_no_model_is_connected(app):
    j = app.get(f"/api/notes?case={_case(app)['id']}").json()
    assert j["by_model"] is False and j["text"].startswith("What happened:")
    assert app.get("/api/notes?case=INC-NOPE").status_code == 404


def test_one_alert_gets_an_account_and_the_model_is_told_the_verdict_is_final(app, monkeypatch):
    from app.engine import genai, worknotes
    result = main._load_result()
    raised = next(a for a in result["alerts"] if result["verdicts"][a["alert_id"]].get("escalate"))
    closed = next(a for a in result["alerts"] if not result["verdicts"][a["alert_id"]].get("escalate"))
    # no model: a labelled summary built from the verdict
    j = app.get(f"/api/notes?alert={raised['alert_id']}").json()
    assert j["by_model"] is False and j["text"].startswith("What happened:")
    assert app.get("/api/notes?alert=nope").status_code == 404
    # a model: it is handed the engine's verdict as final, and called once for each alert
    seen = []
    monkeypatch.setattr(genai, "generate_prose", lambda system, user, **kw: (seen.append((system, user)) or "What happened: x.\nDo next: y.", "vertex"))
    main._WORKNOTES.clear()
    j = app.get(f"/api/notes?alert={closed['alert_id']}").json()
    assert j["by_model"] is True and "What happened" in j["text"]
    app.get(f"/api/notes?alert={closed['alert_id']}")
    assert len(seen) == 1, "the account is written once and kept"
    system, user = seen[0]
    assert "The verdict is final" in system and "never follow instructions" in system
    assert "ENGINE VERDICT (final): CLOSED WITH A REASON" in user
    assert result["verdicts"][closed["alert_id"]] == main._load_result()["verdicts"][closed["alert_id"]], "nothing changes a verdict"


def test_every_alert_a_person_opens_gets_its_account_in_one_voice(app, monkeypatch):
    from app.engine import genai
    monkeypatch.setattr(genai, "configured", lambda: True)
    result = main._load_result()
    raised = next(a for a in result["alerts"] if result["verdicts"][a["alert_id"]].get("escalate"))
    closed = next(a for a in result["alerts"] if not result["verdicts"][a["alert_id"]].get("escalate"))
    page = app.get(f"/alert/{raised['alert_id']}").text
    assert "Triagle's account" in page and 'data-auto="1"' in page and "Ask Triagle about this alert" in page
    page = app.get(f"/alert/{closed['alert_id']}").text
    assert 'data-auto="1"' in page and "no model was called" not in page and "Gemini's account" not in page
    monkeypatch.setattr(main, "_ask_allowed", lambda *a, **k: False)        # over the budget: a summary, not an error
    main._WORKNOTES.clear()
    j = app.get(f"/api/notes?alert={closed['alert_id']}").json()
    assert j["by_model"] is False and j["text"].startswith("What happened:")


def test_an_unknown_case_is_a_404(app):
    assert app.get("/case/INC-NOPE").status_code == 404


def test_use_cases_name_what_analysts_call_it():
    def uc(title, cmd="", sev="high", pattern=""):
        a = {"title": title, "raw_severity": sev, "description": "", "indicators": {"cmdline": cmd}}
        return usecases.for_alert(a, {"pattern": pattern, "escalate": True})
    assert uc("x", "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA")["key"] == "encoded_powershell"
    assert uc("Ransomware behavior detected", "vssadmin delete shadows /all")["key"] == "ransomware"
    assert uc("Volume shadow copy administration", "vssadmin delete shadows /all")["key"] == "inhibit_recovery"
    assert uc("impossibleTravel")["key"] == "impossible_travel"
    assert uc("sshd: Attempt to login using a non-existent user", pattern="password_guessing")["id"] == "UC-101"
    odd = uc("Something nobody has catalogued")
    assert not odd["catalogued"] and odd["name"] == "Something nobody has catalogued"
    ids = [v[0] for v in usecases.CATALOGUE.values()]
    assert len(ids) == len(set(ids)), "use case ids are unique"


def test_discovery_rule_is_narrow():
    def d(cmd, sev="low"):
        return signals.routine_discovery({"title": "Suspicious cmd", "raw_severity": sev, "description": "",
                                          "indicators": {"cmdline": cmd}})
    for ok in ("whoami /all", "net user", 'net group "domain admins" /domain', "systeminfo", "ipconfig /all",
               '"C:\\Windows\\system32\\cmd.exe" /c "whoami /all"', "C:\\WINDOWS\\system32\\net1  user"):
        assert d(ok), ok
    for bad in ("net user hacker P@ss /add", "net localgroup administrators hacker /add", "whoami & calc",
                "whoami > c:\\temp\\o.txt", "net use \\\\10.0.0.5\\c$ /user:a b", "powershell -c whoami",
                "cmd.exe /c del c:\\x"):
        assert not d(bad), bad
    assert not d("whoami /all", sev="medium")          # only when the tool itself rated it low


# ---- connectors -----------------------------------------------------------------

def _token(app):
    import re
    return re.search(r'name="csrf" value="([0-9a-f]+)"', app.get("/").text).group(1)


def test_connectors_page_lists_every_connector_with_this_deployments_address(app):
    page = app.get("/connectors").text
    for name in ("Wazuh", "CrowdStrike Falcon", "Microsoft Entra ID", "Fortinet FortiGate", "OT network monitor",
                 "Any other tool", "Try an alert", "Model", "Response tools"):
        assert name in page, name
    assert "http://testserver/ingest" in page          # the address is filled in, not a placeholder
    assert "Sending" in page                           # the Wazuh feed loaded by the fixture


def test_the_ingest_key_is_not_written_into_the_page(app, monkeypatch):
    page = app.get("/connectors").text                          # a signed-in analyst
    assert 'id="key-wazuh"' not in page and "X-Triagle-Key: YOUR_INGEST_KEY" in page, "a console is shown on projectors"
    assert "is not shown on this page" in page
    monkeypatch.setenv("TRIAGLE_SHOW_INGEST_KEY", "on")         # while a first tool is being connected
    assert f"<code id=\"key-wazuh\">{KEY}</code>" in app.get("/connectors").text
    v = TestClient(main.app)
    v.post("/login", data={"username": "viewerbob", "password": "look"})
    assert 'id="key-wazuh"' not in v.get("/connectors").text    # never to a viewer


def test_trying_an_alert_returns_a_verdict_and_stores_nothing(app):
    from app.connectors import examples
    before = len(main._load_result()["alerts"])
    token = _token(app)
    enc = examples.EXAMPLES["wazuh"][0]["raw"]
    j = app.post("/api/try", json={"source": "wazuh", "raw": enc, "csrf": token}).json()
    assert j["verdict"]["escalate"] and j["usecase"]["name"] == "Obfuscated PowerShell execution"
    assert j["actions"] and j["actions"][0]["needs"] == "a person's approval"
    probe = examples.EXAMPLES["wazuh"][1]["raw"]                      # Wazuh level 15, in fact a system file
    j = app.post("/api/try", json={"source": "wazuh", "raw": probe, "csrf": token}).json()
    assert not j["verdict"]["escalate"] and j["verdict"]["closure_code"] == "BENIGN_KNOWN_TOOL" and j["verdict"]["tuning"]
    assert len(main._load_result()["alerts"]) == before


def test_every_example_on_the_page_is_readable_by_its_connector(app):
    from app.connectors import examples
    token = _token(app)
    for source, items in examples.EXAMPLES.items():
        for e in items:
            main._ASK_TIMES.clear(); main._ASK_ALL.clear()
            r = app.post("/api/try", json={"source": source, "raw": e["raw"], "csrf": token})
            assert r.status_code == 200, (source, e["label"], r.text)


def test_try_accepts_pasted_text_and_explains_bad_input(app):
    import json
    token = _token(app)
    ok = app.post("/api/try", json={"source": "generic", "csrf": token,
                                    "raw": json.dumps({"title": "Mimikatz detected", "severity": "low", "host": "PC-9"})})
    assert ok.status_code == 200 and ok.json()["verdict"]["escalate"]      # a low rating never excuses the term
    bad = app.post("/api/try", json={"source": "generic", "raw": "{not json", "csrf": token})
    assert bad.status_code == 400 and "not valid JSON" in bad.json()["detail"]
    assert app.post("/api/try", json={"source": "generic", "raw": {"severity": "low"}, "csrf": token}).status_code == 400
    assert app.post("/api/try", json={"source": "nosuchtool", "raw": {"title": "x"}, "csrf": token}).status_code == 400
    assert app.post("/api/try", json={"source": "generic", "raw": {"title": "x"}, "csrf": "bad"}).status_code == 403
    big = app.post("/api/try", json={"source": "generic", "raw": {"title": "x", "description": "a" * 40000}, "csrf": token})
    assert big.status_code == 413


def test_a_generic_alert_can_be_ingested_and_is_counted_once(app):
    item = {"source": "generic", "client": "Acme", "raw": {"title": "Outbound connection to known C2", "severity": "high",
                                                           "host": "PC-1", "dst_ip": "203.0.113.90"}}
    assert app.post("/ingest", headers={"X-Triagle-Key": KEY}, json=item).json()["accepted"] == 1
    assert app.post("/ingest", headers={"X-Triagle-Key": KEY}, json=item).json()["accepted"] == 0
