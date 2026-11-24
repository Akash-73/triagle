"""Care around operational technology: what Triagle will not do near a plant.

    python -m pytest -q tests/test_ot.py
"""
import re

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main, demo_attack
from app.connectors.sources import normalize
from app.engine import ot, signals
from app.engine.response import propose_actions
from app.engine.triage import triage, _enforce_guardrails
from app.models import Verdict
from app.orchestrator import process_batch


def otm(**kw):
    raw = {"id": "ot-1", "time": "2026-11-22T10:00:00Z", "severity": "high",
           "alert": "Unauthorised control command to RTU", "protocol": "IEC 60870-5-104",
           "src_asset": "PLANT-HMI-02", "dst_asset": "SUB7-RTU-03", "technique": "T0855 Unauthorized Command Message",
           "detail": "Breaker command outside any switching order."}
    raw.update(kw)
    return normalize("ot_monitor", raw, "Utility A")


def edr(**kw):
    raw = {"detection_id": "e-1", "created_timestamp": "2026-11-22T10:00:00Z", "name": "x", "severity": "low",
           "hostname": "FIN-07", "user_name": "u1", "description": ""}
    raw.update(kw)
    return normalize("crowdstrike_edr", raw, "Utility A")


def actions(alert):
    v = triage(alert).to_dict()
    return v, {(a.action_type, a.target): a for a in propose_actions(alert.to_dict(), v)}


# ---- recognising OT -------------------------------------------------------------------

@pytest.mark.parametrize("name,kind", [
    ("SUB7-RTU-03", ot.CONTROLLER), ("PLC-LINE2", ot.CONTROLLER), ("plant1_ied_14", ot.CONTROLLER),
    ("TPG-SCADA-HMI-04", ot.OPERATOR), ("HISTORIAN-01", ot.OPERATOR), ("EWS-3", ot.OPERATOR),
    ("FIN-07", None), ("MAIL-RELAY-01", None), ("ANALYSIS-SRV", None), ("DISPLAY-KIOSK", None),
    ("10.2.3.4", None), (None, None),
])
def test_assets_are_recognised_by_name(name, kind):
    assert ot.asset_class(name) == kind


def test_an_explicit_asset_list_overrides_names(monkeypatch):
    monkeypatch.setenv("TRIAGLE_OT_CONTROLLERS", "10.50.1.*, PUMP-A")
    monkeypatch.setenv("TRIAGLE_OT_STATIONS", "CTRLROOM-PC-1")
    assert ot.asset_class("10.50.1.20") == ot.CONTROLLER and ot.asset_class("pump-a") == ot.CONTROLLER
    assert ot.asset_class("CTRLROOM-PC-1") == ot.OPERATOR and ot.asset_class("10.50.2.20") is None


def test_ot_words_mean_nothing_on_an_office_laptop():
    a = edr(name="Firmware update installed", description="Dock firmware updated; restart command issued.")
    assert not ot.involved(a) and ot.signals(a) == [] and not triage(a).escalate


# ---- never closed without a person -------------------------------------------------------

def test_a_command_to_a_controller_is_a_real_attack_signal():
    a = otm()
    assert "ICS technique T0855" in signals.hard_signals(a)
    v = triage(a)
    assert v.escalate and v.closure_code is None and v.severity == "critical"


def test_even_a_routine_looking_event_on_a_controller_reaches_a_person():
    a = otm(alert="Modbus read holding registers", severity="low", technique=None, protocol="Modbus",
            detail="Periodic poll.", dst_asset="PLC-LINE2")
    assert signals.hard_signals(a) == []
    v = triage(a)
    assert v.escalate and v.disposition == "needs_human" and "PLC-LINE2" in v.reasoning


def test_a_model_cannot_close_an_alert_on_a_controller():
    a = otm(alert="Modbus read holding registers", severity="low", technique=None, dst_asset="PLC-LINE2")
    v = _enforce_guardrails(Verdict(a.alert_id, "benign", "BENIGN_EXPECTED", 99, "low", False, "fine", "ok"), a)
    assert v.escalate and v.closure_code is None and v.disposition != "benign"


# ---- nothing is done to an OT asset --------------------------------------------------------

def test_a_controller_is_never_isolated_and_the_plant_is_called():
    v, acts = actions(otm())
    assert ("isolate_host", "SUB7-RTU-03") not in acts
    assert ("ot_notify", "SUB7-RTU-03") in acts
    cut = acts[("segment_ot_boundary", "PLANT-HMI-02")]            # the sender, not the controller
    assert cut.risk_tier == "high_impact" and cut.requires_ack and cut.policy == "approval"
    assert "controller keeps running" in cut.blast_radius
    assert not any(t == "SUB7-RTU-03" and k != "ot_notify" for k, t in acts)


def test_an_operator_station_with_malware_is_cut_off_at_the_boundary_not_isolated():
    a = edr(name="Credential dumping via LSASS access", severity="high", hostname="TPG-SCADA-HMI-04")
    v, acts = actions(a)
    assert v["escalate"] and ("isolate_host", "TPG-SCADA-HMI-04") not in acts
    cut = acts[("segment_ot_boundary", "TPG-SCADA-HMI-04")]
    assert cut.requires_ack and "Operators keep their view" in cut.blast_radius
    assert ("ot_notify", "TPG-SCADA-HMI-04") in acts


def test_the_same_alert_on_an_office_host_still_proposes_isolation():
    _, acts = actions(edr(name="Credential dumping via LSASS access", severity="high", hostname="FIN-07"))
    assert ("isolate_host", "FIN-07") in acts and not any(k.startswith("segment") or k == "ot_notify" for k, _ in acts)


def test_nothing_is_automatic_when_an_ot_asset_is_involved():
    c2 = {"logid": "f1", "eventtime": "2026-11-22T10:00:00Z", "attack": "Outbound connection to known C2",
          "crlevel": "high", "dstip": "185.220.101.44", "msg": "Beaconing."}
    office = process_batch([{"source": "fortinet_fw", "client": "U", "raw": dict(c2, srcip="FIN-07")}])
    plant = process_batch([{"source": "fortinet_fw", "client": "U", "raw": dict(c2, srcip="TPG-SCADA-HMI-04")}])
    block = lambda r: next(a for a in r["actions"]["f1"] if a["action_type"] == "block_indicator")
    assert block(office)["status"] == "auto_executed"
    assert block(plant)["status"] == "pending" and "operational technology" in block(plant)["policy_reason"]


# ---- the two demo scenarios --------------------------------------------------------------------

def test_the_power_scenario_adds_a_command_to_an_rtu_and_no_action_touches_it():
    r = process_batch(demo_attack.fresh_attack(scenario="power", tag="t1"))
    assert len(r["alerts"]) == 6 and len(r["incidents"]) == 1 and r["incidents"][0]["size"] == 6
    rtu = demo_attack.SCENARIOS["power"]["rtu"]
    every = [a for acts in r["actions"].values() for a in acts]
    assert {a["action_type"] for a in every if a["target"] == rtu} == {"ot_notify"}
    assert not any(a["action_type"] == "isolate_host" and ot.asset_class(a["target"]) for a in every)
    assert not any(a["status"] == "auto_executed" and a["alert_id"] != "ldt:t1:3" for a in every
                   if ot.involved(next(x for x in r["alerts"] if x["alert_id"] == a["alert_id"])))


def test_the_bank_scenario_is_the_default_and_has_no_ot_in_it():
    assert demo_attack.DEFAULT == "bank"
    r = process_batch(demo_attack.fresh_attack(tag="t2"))
    assert len(r["alerts"]) == 5 and not any(ot.involved(a) for a in r["alerts"])
    assert r["incidents"][0]["client"] == demo_attack.SCENARIOS["bank"]["client"]


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TRIAGLE_DEMO", "true")
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s", "TRIAGLE_USERS": ""})
    main._CACHE.clear()
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    yield c
    main._CACHE.clear()


def _csrf(c, path="/"):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get(path).text).group(1)


def test_each_scenario_fires_into_its_own_tenant_with_its_own_regulators(app):
    r = app.post("/demo/fire", data={"csrf": _csrf(app), "scenario": "power"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/case/INC-")
    landed = main._find_incident(main._load_result(), r.headers["location"].rsplit("/", 1)[1])
    assert landed["client"] == "Tirupati Power Grid" and "TPG-SCADA-HMI-04" in landed["entities"]
    page = app.get("/clock").text
    card = page[page.index('<h2>Tirupati Power Grid'):]
    card = card[:card.index('</section>')]
    assert "CSIRT-Power" in card and "Power utility" in card
    # CSIRT-Power's rule binds from 1 April 2027 and the Data Protection Board's from 13 May 2027.
    # Until both have passed the card says so; after that every deadline on it is running.
    import datetime
    from app.engine import regclock
    today = datetime.datetime.now(datetime.timezone.utc).date()
    starts = [regclock.REGULATORS[k]["in_force_from"] for k in regclock.SECTORS["power"]["regulators"]]
    assert ("not binding yet" in card) == any(d and d > today for d in starts)
    r = app.post("/demo/fire", data={"csrf": _csrf(app), "scenario": "bank"}, follow_redirects=False)
    res = main._load_result()
    landed = main._find_incident(res, r.headers["location"].rsplit("/", 1)[1])
    assert landed["client"] == "Northgate Urban Co-operative Bank" and "NUB-CBS-APP-02" in landed["entities"]
    assert not any(a["client"] == "Tirupati Power Grid" for a in res["alerts"])     # one demo incident at a time
    inc = next(i for i in res["incidents"] if i["client"] == "Northgate Urban Co-operative Bank")
    assert {x["regulator"] for x in main._clock(res, inc)["rows"]} == {"certin", "rbi", "dpdp"}


def test_recording_the_call_to_the_control_room_makes_no_system_call(app):
    app.post("/demo/fire", data={"csrf": _csrf(app), "scenario": "power"})
    res = main._load_result()
    aid, act = next((aid, a) for aid, acts in res["actions"].items() for a in acts if a["action_type"] == "ot_notify")
    page = app.get(f"/alert/{aid}").text
    assert "Record the call as made" in page and "Manual step — no system call" in page
    r = app.post("/action/approve", data={"alert_id": aid, "action_id": act["action_id"],
                                          "csrf": _csrf(app, f"/alert/{aid}")}, follow_redirects=False)
    assert r.status_code == 303
    done = next(a for a in main._load_result()["actions"][aid] if a["action_id"] == act["action_id"])
    assert done["status"] == "executed" and "No system call is made" in done["result_message"]
    entry = next(e for e in audit.read() if e["event"] == "action approved")
    assert entry["mode"] == "manual" and entry["simulated"] is False
