"""The regulatory clock: which reports an incident owes, to whom, by when.

    python -m pytest -q tests/test_regclock.py
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main
from app.engine import certin, regclock
from app.orchestrator import process_batch

ROOT = os.path.dirname(os.path.dirname(__file__))
KEY = "clock-key"
UTC = timezone.utc


def _members(r, inc):
    return sorted(({"alert": a, "verdict": r["verdicts"][a["alert_id"]]} for a in r["alerts"]
                   if a["alert_id"] in inc["alert_ids"]), key=lambda m: m["alert"]["timestamp"])


@pytest.fixture(scope="module")
def seed():
    with open(os.path.join(ROOT, "samples", "incoming_alerts.json")) as f:
        return process_batch(json.load(f))


@pytest.fixture(scope="module")
def wz():
    with open(os.path.join(ROOT, "eval", "wazuh_dataset.json")) as f:
        return process_batch(json.load(f))


def _incident(r, client, key=None):
    return next(i for i in r["incidents"] if i["client"] == client and (key is None or i["key"] == key))


def _clock(r, inc, sector, now):
    return regclock.clocks_for(inc, _members(r, inc), sector, now=now)


def _by(clock):
    return {(row["regulator"], row["deadline"]): row for row in clock["rows"]}


# ---- which regulators, by sector ---------------------------------------------------

def test_a_bank_owes_certin_and_rbi_within_six_hours(seed):
    inc = _incident(seed, "Meridian Textiles")
    start = regclock.noticed_at(_members(seed, inc))
    rows = _by(_clock(seed, inc, "bank", start + timedelta(hours=1)))
    for reg in ("certin", "rbi"):
        row = rows[(reg, "report")]
        assert row["status"] == "running" and row["hours"] == 6 and row["seconds_left"] == 5 * 3600
        assert row["due_iso"] == (start + timedelta(hours=6)).isoformat()


def test_a_broker_owes_sebi_twice(seed):
    inc = _incident(seed, "Sterling Securities")
    start = regclock.noticed_at(_members(seed, inc))
    rows = _by(_clock(seed, inc, "securities", start + timedelta(hours=7)))
    assert rows[("sebi", "email")]["status"] == "overdue"           # 6 h window has passed
    assert rows[("sebi", "portal")]["status"] == "running"          # 24 h window has not
    assert rows[("sebi", "portal")]["seconds_left"] == 17 * 3600
    assert rows[("certin", "report")]["status"] == "overdue"


def test_a_rule_that_is_not_binding_yet_is_shown_as_such(seed):
    inc = _incident(seed, "Meridian Textiles")
    start = regclock.noticed_at(_members(seed, inc))
    before = _by(_clock(seed, inc, "power", datetime(2026, 11, 22, tzinfo=UTC)))[("cea", "report")]
    assert before["status"] == "not_in_force" and before["binding"] is False and "01 Apr 2027" in before["note"]
    after = regclock.clocks_for(inc, _members(seed, inc), "power", now=datetime(2027, 4, 2, tzinfo=UTC))
    assert _by(after)[("cea", "report")]["status"] == "overdue"     # binding now, and the 2026 alert is long past
    assert start is not None


def test_the_data_protection_clock_needs_a_sign_of_personal_data(seed):
    ransomware = _incident(seed, "Meridian Textiles")
    scan = _incident(seed, "Sterling Securities")
    live = datetime(2027, 6, 1, tzinfo=UTC)
    assert _by(_clock(seed, ransomware, "general", live))[("dpdp", "detailed")]["status"] == "overdue"
    assert _by(_clock(seed, scan, "general", live))[("dpdp", "detailed")]["status"] == "not_triggered"
    assert _by(_clock(seed, ransomware, "general", datetime(2026, 11, 22, tzinfo=UTC)))[("dpdp", "detailed")]["status"] == "not_in_force"


def test_an_unknown_sector_falls_back_to_the_general_profile(seed):
    inc = _incident(seed, "Meridian Textiles")
    c = regclock.clocks_for(inc, _members(seed, inc), "astrology")
    assert c["sector"] == "general" and {r["regulator"] for r in c["rows"]} == {"certin", "dpdp"}


def test_every_regulator_names_its_instrument_and_what_to_verify():
    for key, reg in regclock.REGULATORS.items():
        assert reg["instrument"] and reg["verify"] and reg["deadlines"], key
        assert reg["trigger"] in ("always", "personal_data")
    for sector in regclock.SECTORS.values():
        assert sector["regulators"][0] == "certin"
        assert all(k in regclock.REGULATORS for k in sector["regulators"])


def test_tenant_sectors_come_from_file_then_environment(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"A Bank": "bank", "Nonsense Co": "wizardry", "B Ltd": {"sector": "power"}}))
    t = regclock.load_tenants({"TRIAGLE_TENANTS_FILE": str(f), "TRIAGLE_TENANTS": '{"A Bank": "nbfc", "C": "securities"}'})
    assert t == {"A Bank": "nbfc", "B Ltd": "power", "C": "securities"}
    assert regclock.sector_of("C", t) == "securities" and regclock.sector_of("Unknown", t) == "general"
    assert regclock.sector_of("C", t, {"C": "bank"}) == "bank"


# ---- when the clock starts, and when it does not ---------------------------------------

def test_the_clock_starts_at_the_first_real_attack_alert_not_an_earlier_weak_signal(wz):
    inc = _incident(wz, "Sahyadri Co-operative Bank", "SCB-BR2-WKS-014")
    members = _members(wz, inc)
    assert members[0]["alert"]["title"] == "New Windows Service Created"         # 04:15, a judgement call
    assert members[0]["verdict"]["basis"] == "correlation"
    assert regclock.noticed_at(members) == datetime(2026, 11, 22, 10, 2, 10, tzinfo=UTC)   # the encoded PowerShell


def test_probing_from_outside_does_not_start_a_clock(wz):
    inc = _incident(wz, "Sahyadri Co-operative Bank", "wazuh-server")
    members = _members(wz, inc)
    assert all("brute force" in m["alert"]["title"] for m in members)
    assert certin.probing_only(members) and not certin.is_reportable_candidate(members)


def test_a_package_install_is_not_part_of_the_brute_force_against_the_same_server(wz):
    inc = _incident(wz, "Sahyadri Co-operative Bank", "wazuh-server")
    titles = [m["alert"]["title"] for m in _members(wz, inc)]
    assert not any("dpkg" in t for t in titles) and len(titles) == 2
    dpkg = next(a for a in wz["alerts"] if "dpkg" in a["title"])
    v = wz["verdicts"][dpkg["alert_id"]]
    assert v["escalate"] and v["disposition"] == "needs_human"                   # still seen, on its own


def test_an_alert_tied_to_the_attackers_account_joins_the_incident(wz):
    inc = _incident(wz, "Sahyadri Co-operative Bank", "SCB-BR2-WKS-014")
    assert "User account enabled or created" in [m["alert"]["title"] for m in _members(wz, inc)]


def test_a_confirmed_attack_is_reportable_even_with_probing_around_it(seed):
    members = _members(seed, _incident(seed, "Meridian Textiles"))
    assert not certin.probing_only(members) and certin.is_reportable_candidate(members)


# ---- the web console ---------------------------------------------------------------------

@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_DEMO_CLOCK", "true")              # sample incidents are 5 minutes old
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s",
                      "TRIAGLE_USERS": "viewerbob:viewer:" + auth.hash_password("look")})
    main._CACHE.clear()
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    yield c
    main._CACHE.clear()


def _csrf(c, path="/clock"):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get(path).text).group(1)


def _inc(client):
    return next(i for i in main._load_result()["incidents"] if i["client"] == client)


def _file(c, inc, regulator="certin", deadline="report", confirm="on", reference="", csrf=None):
    return c.post("/clock/file", data={"incident": inc["id"], "regulator": regulator, "deadline": deadline,
                                       "confirm": confirm, "reference": reference,
                                       "csrf": csrf or _csrf(c)}, follow_redirects=False)


def test_clock_page_lists_each_regulator_for_the_clients_sector(app):
    page = app.get("/clock").text
    assert "Regulatory clock" in page and "Sterling Securities" in page
    card = page[page.index("Sterling Securities"):]
    card = card[:card.index('class="card"')] if 'class="card"' in card else card
    assert "Inform SEBI by email" in card and "File on the incident portal" in card and "CERT-In" in card
    assert "Northwind Logistics" in page[page.index("Watching"):]          # a scan and a spray: watched, no clock


def test_a_draft_is_addressed_to_the_regulator_asked_for(app):
    inc = _inc("Sterling Securities")
    page = app.get(f"/notice/{inc['id']}/sebi").text
    assert "SEBI INCIDENT REPORT — DRAFT" in page and "Cybersecurity and Cyber Resilience Framework" in page
    assert "Other deadlines on this incident" in page and f"/notice/{inc['id']}/certin" in page
    assert app.get(f"/notice/{inc['id']}/nobody").status_code == 404
    wrong = app.get(f"/notice/{inc['id']}/rbi").text                       # a broker does not report to the RBI
    assert "not among the regulators for this client" in wrong


def test_marking_a_report_filed_stops_that_clock_and_is_audited(app):
    inc = _inc("Sterling Securities")
    r = _file(app, inc, "sebi", "email", reference="SEBI/ACK/2026/0042")
    assert r.status_code == 303 and r.headers["location"].endswith("#" + inc["id"])
    clock = main._clock(main._load_result(), _inc("Sterling Securities"))
    rows = {(x["regulator"], x["deadline"]): x for x in clock["rows"]}
    assert rows[("sebi", "email")]["status"] == "filed" and "admin" in rows[("sebi", "email")]["note"]
    assert rows[("sebi", "portal")]["status"] == "running" and rows[("certin", "report")]["status"] == "running"
    entry = next(e for e in audit.read() if e["event"] == "regulatory report marked filed")
    assert entry["user"] == "admin" and entry["regulator"] == "SEBI" and entry["reference"] == "SEBI/ACK/2026/0042"
    assert entry["minutes_before_deadline"] > 300
    assert "SEBI/ACK/2026/0042" in app.get("/clock").text


def test_filing_needs_the_confirmation_tick_the_form_token_and_an_analyst(app):
    inc = _inc("Meridian Textiles")
    r = _file(app, inc, confirm="")
    assert r.status_code == 303 and "notice=confirm" in r.headers["location"]
    assert _file(app, inc, csrf="bad").status_code == 403
    assert main._CACHE["filings"] == []
    viewer = TestClient(main.app)
    viewer.post("/login", data={"username": "viewerbob", "password": "look"})
    assert _file(viewer, inc, csrf=_csrf(viewer, "/")).status_code == 403
    assert "Mark filed" not in viewer.get("/clock").text
    assert _file(app, inc, regulator="sebi", deadline="email").status_code == 404      # not on this client's clock


def test_a_report_cannot_be_filed_twice_and_survives_new_alerts(app):
    inc = _inc("Meridian Textiles")
    assert _file(app, inc).status_code == 303
    again = _file(app, inc)
    assert "notice=done" in again.headers["location"] and len(main._CACHE["filings"]) == 1
    # the queue is rebuilt when an alert arrives; the filing must still be attached
    app.post("/ingest", headers={"X-Triagle-Key": KEY}, json={"source": "crowdstrike_edr", "client": "Meridian Textiles", "raw": {
        "detection_id": "late-1", "created_timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "name": "Ransomware behavior detected", "severity": "critical", "hostname": "MRD-FIN-07", "user_name": "p.nair"}})
    grown = _inc("Meridian Textiles")
    assert grown["size"] == inc["size"] + 1
    assert next(x for x in main._clock(main._load_result(), grown)["rows"] if x["regulator"] == "certin")["status"] == "filed"


def test_an_analyst_can_set_a_clients_sector_and_the_clock_follows(app):
    inc = _inc("Meridian Textiles")
    assert {r["regulator"] for r in main._clock(main._load_result(), inc)["rows"]} == {"certin", "dpdp"}
    r = app.post("/tenant/sector", data={"client": "Meridian Textiles", "sector": "bank", "csrf": _csrf(app)},
                 follow_redirects=False)
    assert r.status_code == 303
    assert {r["regulator"] for r in main._clock(main._load_result(), inc)["rows"]} == {"certin", "rbi", "dpdp"}
    assert any(e["event"] == "client sector changed" and e["sector"] == "bank" and e["previous"] == "general"
               for e in audit.read())
    assert app.post("/tenant/sector", data={"client": "Meridian Textiles", "sector": "wizardry",
                                            "csrf": _csrf(app)}).status_code == 400
    assert app.post("/tenant/sector", data={"client": "Nobody Ltd", "sector": "bank",
                                            "csrf": _csrf(app)}).status_code == 404


def test_the_console_shows_the_deadline_on_the_incident_and_caps_the_closed_list(app, monkeypatch):
    page = app.get("/").text
    assert "Reporting deadlines running" in page and 'data-due="' in page
    assert "Probing from outside, no sign it worked" in page                # Northwind: scan + spray
    monkeypatch.setattr(main, "CLOSED_SHOWN", 3)
    page = app.get("/").text
    assert "closed alerts — show all" in page
    assert "closed alerts — show all" not in app.get("/?closed=all").text


def test_pages_need_a_session():
    main._CACHE.clear()
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s", "TRIAGLE_USERS": ""})
    c = TestClient(main.app)
    assert c.get("/clock", follow_redirects=False).status_code == 303
    assert c.post("/clock/file", data={"incident": "x", "regulator": "certin", "deadline": "report"}).status_code == 401
    main._CACHE.clear()
