"""Detection tuning: which rules deserve a change, and which are doing their job.

    python -m pytest -q tests/test_tuning.py

Written against a real Wazuh feed. The first version of this page called 15
of 28 rules "tuning candidates", because every alert from them had been
closed. Thirteen of those were sign-ins, sessions closing and sudo by an
administrator: records the tool itself rates low, with nothing to tune. It
also called the repeats of a password-guessing address "86% noise", when
they were the attack.

What a rule's alerts became decides what is said about the rule:

  - some went to a person                      -> keep it
  - all closed, tool rates it medium or more,
    or all one recognised harmless thing       -> tune it, and how
  - all closed, tool rates it low              -> a record, nothing to tune
"""
import datetime as dt

import pytest
from fastapi.testclient import TestClient

from app import auth, main
from app.engine import tuning
from app.orchestrator import process_batch

BANK = "Greenvale Co-operative Bank"
T0 = dt.datetime(2026, 11, 24, 6, 0, 0)


def _wz(i, sec, rid, level, desc, groups, host="wazuh-demo", data=None, win=None, syscheck=None):
    t = T0 + dt.timedelta(seconds=sec)
    raw = {"timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "id": f"{int(t.timestamp())}.{rid}{i:03d}",
           "rule": {"id": rid, "level": level, "description": desc, "groups": list(groups)},
           "agent": {"id": "000", "name": host}, "manager": {"name": "wazuh-demo"}, "location": "journald"}
    if data:
        raw["data"] = data
    if win:
        raw["data"] = {"win": {"system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational"},
                               "eventdata": win}}
    if syscheck:
        raw["syscheck"] = syscheck
    return {"source": "wazuh", "client": BANK, "raw": raw}


def pam_closed(i):
    return _wz(i, 600 * i, "5502", 3, "PAM: Login session closed.", ("pam", "syslog"))


def sudo_root(i):
    return _wz(i, 600 * i + 5, "5402", 3, "Successful sudo to ROOT executed.", ("syslog", "sudo"),
               data={"srcuser": "akash", "dstuser": "root", "command": "/usr/bin/systemctl status wazuh-manager"})


def compat_db(i):
    """Wazuh rule 92058, level 12: Windows' own scheduled compatibility-database merge."""
    return _wz(i, 900 * i + 7, "92058", 12, "Application Compatibility Database launched",
               ("sysmon", "sysmon_eid1_detections", "windows"), host="akash-laptop",
               win={"commandLine": "C:\\WINDOWS\\system32\\sdbinst.exe -m -bg",
                    "image": "C:\\Windows\\System32\\sdbinst.exe", "user": "NT AUTHORITY\\SYSTEM",
                    "parentImage": "C:\\Windows\\System32\\svchost.exe"})


def failed_signin(i, sec, src):
    return _wz(i, sec, "5710", 5, "sshd: Attempt to login using a non-existent user",
               ("syslog", "sshd", "authentication_failed", "invalid_login"),
               data={"srcip": src, "srcuser": "admin"})


def file_deleted(i, sec):
    return _wz(i, sec, "553", 7, "File deleted.", ("ossec", "syscheck", "syscheck_entry_deleted", "syscheck_file"),
               syscheck={"path": f"/etc/wazuh-indexer/certs/node-{i}.pem", "event": "deleted"})


def system_error(i):
    return _wz(i, 700 * i + 11, "61102", 5, "Windows System error event", ("windows", "windows_system", "system_error"),
               host="akash-laptop")


def rules(items):
    r = process_batch(items)
    return {x["title"]: x for x in tuning.analyze_rules(r["alerts"], r["verdicts"])}, r


# ---- the three kinds ----------------------------------------------------------------

def test_a_record_the_tool_rates_low_is_not_a_tuning_candidate():
    got, r = rules([pam_closed(i) for i in range(12)] + [sudo_root(i) for i in range(9)])
    for title in ("PAM: Login session closed.", "Successful sudo to ROOT executed."):
        x = got[title]
        assert x["kind"] == "record" and x["flagged"] is False, title
        assert x["closed"] == x["volume"] and x["to_person"] == 0 and x["rating"] == "low"
        assert "Nothing to tune" in x["recommendation"] and "Narrow" not in x["recommendation"]
    assert r["metrics"]["flagged_rules"] == 0


def test_a_rule_the_tool_rates_high_that_is_always_the_same_harmless_thing_is_a_candidate():
    got, r = rules([compat_db(i) for i in range(10)] + [pam_closed(i) for i in range(5)])
    x = got["Application Compatibility Database launched"]
    assert x["kind"] == "tune" and x["flagged"] and x["rating"] == "high" and x["level"] == "12" and x["rule_id"] == "92058"
    assert x["volume"] == x["closed"] == 10
    say = x["recommendation"]
    assert say.startswith("Wazuh SIEM rates this high (level 12). All 10 were closed for the same reason:")
    assert "compatibility-database merge" in say
    assert "a child rule of 92058 at level 0" in say and "keeps the rule for everything else" in say
    assert r["metrics"]["flagged_rules"] == 1
    assert list(got)[0] == "Application Compatibility Database launched", "candidates come first"


def test_one_alert_is_enough_when_the_tool_calls_it_high_and_triagle_recognised_the_thing():
    got, _ = rules([compat_db(0)])
    x = got["Application Compatibility Database launched"]
    assert x["flagged"] and "It was closed for this reason:" in x["recommendation"]


def test_the_rule_wazuh_rates_critical_for_a_browser_updating_itself():
    """Stock rule 92213, level 15, on a real laptop: the browser's own updater."""
    from tests.test_demo_chain import _drop, UNPACK, EDGE
    got, _ = rules([_drop(UNPACK, EDGE)])
    x = got["Executable file dropped in folder commonly used by malware"]
    assert x["flagged"] and x["rating"] == "critical" and x["level"] == "15"
    assert x["recommendation"].startswith("Wazuh SIEM rates this critical (level 15). It was closed for this reason:")
    assert "browser component update file" in x["recommendation"] and "child rule of 92213" in x["recommendation"]


def test_another_tool_is_told_to_add_an_exception_in_its_own_words():
    from app import demo_attack
    got, _ = rules([i for i in demo_attack.fresh_shift() if "Tachyon" in str(i["raw"].get("name"))])
    x = got["Known admin tool: 1E Tachyon agent"]
    assert x["flagged"] and "In CrowdStrike EDR, add an exception for that case" in x["recommendation"]
    assert "1E Tachyon agent" in x["recommendation"] and "child rule" not in x["recommendation"]


# ---- what is counted under another alert is never called noise --------------------------

def test_password_guessing_and_everything_counted_under_it_is_kept():
    attacker = [failed_signin(i, 3000 * i, "2.57.121.112") for i in range(8)]       # 5th is raised, 3 repeats
    passer_by = [failed_signin(50, 100, "198.51.100.7")]                              # tried once
    got, r = rules(attacker + passer_by)
    x = got["sshd: Attempt to login using a non-existent user"]
    raised = [v for v in r["verdicts"].values() if v["escalate"]]
    assert len(raised) == 1 and raised[0]["pattern"] == "password_guessing"
    assert x["kind"] == "keep" and not x["flagged"]
    assert x["volume"] == 9 and x["to_person"] == 8 and x["under"] == 7 and x["closed"] == 1
    assert x["recommendation"] == "Keep it. 1 went to a person and 7 more are counted under it."


def test_a_burst_waiting_for_a_person_is_kept_and_its_members_are_not_noise():
    got, r = rules([file_deleted(i, i) for i in range(11)])
    x = got["File deleted."]
    assert sum(1 for v in r["verdicts"].values() if v["escalate"]) == 1
    assert x["kind"] == "keep" and x["to_person"] == 11 and x["under"] == 10 and x["closed"] == 0
    assert x["recommendation"] == "Keep it. 1 went to a person and 10 more are counted under it."


# ---- a person's decision outranks Triagle's ------------------------------------------------

@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_SEED", "off")
    monkeypatch.setattr(main, "INGEST_KEY", "k")
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s"})
    main._CACHE.clear()
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    yield c
    main._CACHE.clear()
    auth.load_config()


def _decide(c, outcome):
    res = main._load_result()
    aid = next(a for a, v in res["verdicts"].items() if v["escalate"])
    token = c.get(f"/alert/{aid}").text.split('name="csrf" value="')[1].split('"')[0]
    assert c.post("/alert/resolve", data={"alert_id": aid, "csrf": token, "outcome": outcome},
                  follow_redirects=False).status_code == 303
    return {x["title"]: x for x in main._load_result()["rule_health"]}["File deleted."]


def test_expected_activity_confirmed_by_a_person_is_not_a_candidate(site):
    main._add_alerts([file_deleted(i, i) for i in range(6)])
    x = _decide(site, "expected")
    assert x["kind"] == "expected" and not x["flagged"] and x["to_person"] == 6
    assert x["recommendation"] == "A person confirmed this as expected activity. Nothing to tune."
    assert main._load_result()["metrics"]["flagged_rules"] == 0


def test_a_false_positive_marked_by_a_person_makes_the_rule_a_candidate(site):
    main._add_alerts([file_deleted(i, i) for i in range(6)])
    x = _decide(site, "false_positive")
    assert x["kind"] == "tune" and x["flagged"]
    assert x["recommendation"].startswith("A person marked 6 of these as false positives.")
    assert main._load_result()["metrics"]["flagged_rules"] == 1
    page = site.get("/tuning").text
    assert "Tuning candidate" in page and "1 to tune" in page
    # opened again, it goes back to waiting for a person
    y = _decide_again(site)
    assert y["kind"] == "keep" and not y["flagged"]


def _decide_again(c):
    res = main._load_result()
    aid = next(a for a, v in res["verdicts"].items() if v["escalate"])
    token = c.get(f"/alert/{aid}").text.split('name="csrf" value="')[1].split('"')[0]
    c.post("/alert/resolve", data={"alert_id": aid, "csrf": token, "outcome": "reopen"}, follow_redirects=False)
    return {x["title"]: x for x in main._load_result()["rule_health"]}["File deleted."]


# ---- not detections at all ---------------------------------------------------------------------

def test_a_health_event_is_not_a_candidate_however_often_it_fires():
    got, r = rules([system_error(i) for i in range(6)])
    x = got["Windows System error event"]
    assert all(v["closure_code"] == "OPERATIONAL_EVENT" for v in r["verdicts"].values())
    assert x["kind"] == "health" and not x["flagged"] and "IT operations" in x["recommendation"]


# ---- the page ---------------------------------------------------------------------------------------

def test_the_page_on_a_feed_shaped_like_the_real_one(site):
    feed = ([pam_closed(i) for i in range(12)] + [sudo_root(i) for i in range(9)] + [compat_db(i) for i in range(10)]
            + [failed_signin(i, 3000 * i, "2.57.121.112") for i in range(8)] + [system_error(i) for i in range(3)])
    assert main._add_alerts(feed) == len(feed)
    page = site.get("/tuning").text
    assert "5, 1 to tune" in page, "five rules, one of them a candidate"
    assert page.count("Tuning candidate") == 1
    assert "The tool rates it" in page and "Went to a person" in page and "Closed by Triagle" in page
    assert "rule 92058" in page and "level 12" in page and "7 under another" in page
    assert "Share that was noise" not in page
    # each rule opens the alerts it raised
    link = page.split("Application Compatibility Database launched</a>")[0].rsplit('href="', 1)[1].split('"')[0]
    listed = site.get(link.replace("&amp;", "&")).text
    assert listed.count('data-href="/alert/') == 10
    # the count beside the navigation is the number of candidates, not of quiet rules
    nav = site.get("/").text.split('href="/tuning"')[1].split("</a>")[0]
    assert '<span class="count">1</span>' in nav
