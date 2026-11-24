"""Verdicts written back to Wazuh.

    python -m pytest -q tests/test_writeback.py

The forwarder asks Triagle for its verdict on each alert and writes it to a
file Wazuh reads, so "Triagle closed: ..." shows up in the Wazuh dashboard
next to the alert. Three things must hold: the reply carries a verdict for
every alert Triagle could read; the lines are in the shape the Wazuh rules
expect; and a verdict that Wazuh reads back is never taken in as an alert.
"""
import importlib.util
import json
import os
import re
import types
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient

from app import auth, main
from app.connectors import examples

ROOT = os.path.dirname(os.path.dirname(__file__))
KEY = "wb-key"

spec = importlib.util.spec_from_file_location("wazuh_forwarder", os.path.join(ROOT, "scripts", "wazuh_forwarder.py"))
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)

ENCODED = examples.EXAMPLES["wazuh"][0]["raw"]          # level 12, obfuscated PowerShell
PROBE = examples.EXAMPLES["wazuh"][1]["raw"]            # level 15, in fact a system file
DISCOVERY = examples.EXAMPLES["wazuh"][2]["raw"]        # level 3, whoami
SCA = {"timestamp": "2026-11-24T05:00:00.000+0000", "id": "1795500000.1",
       "rule": {"level": 7, "id": "19007", "groups": ["sca"],
                "description": "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0: Ensure 'Minimum password "
                               "length' is set to '14 or more character(s)'."},
       "agent": {"id": "014", "name": "FIN-LAPTOP-07"}, "manager": {"name": "wazuh"}, "decoder": {"name": "sca"},
       "data": {"sca": {"type": "check", "check": {"id": "26003", "title": "Minimum password length",
                                                   "result": "failed"}}},
       "location": "sca"}


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s"})
    main._CACHE.clear()
    yield TestClient(main.app)
    main._CACHE.clear()


def _items(*raws):
    return [{"source": "wazuh", "client": "Greenvale Co-operative Bank", "raw": r} for r in raws]


def _send(app, items, verdicts=True):
    return app.post("/ingest" + ("?verdicts=1" if verdicts else ""), headers={"X-Triagle-Key": KEY}, json=items).json()


def test_ingest_returns_a_verdict_for_each_alert_when_asked(app):
    assert "verdicts" not in _send(app, _items(DISCOVERY), verdicts=False)        # only when asked for
    by = {v["id"]: v for v in _send(app, _items(ENCODED, PROBE, SCA))["verdicts"]}
    assert set(by) == {ENCODED["id"], PROBE["id"], SCA["id"]}
    enc, probe, sca = by[ENCODED["id"]], by[PROBE["id"]], by[SCA["id"]]
    assert enc["verdict"] == "escalated" and enc["use_case"] == "Obfuscated PowerShell execution"
    assert enc["technique"] == "T1059.001" and enc["url"].endswith("/alert/" + enc["alert_id"])
    assert probe["verdict"] == "closed" and probe["closure_code"] == "BENIGN_KNOWN_TOOL" and probe["kind"] == "activity"
    assert sca["verdict"] == "closed" and sca["kind"] == "posture"


def test_an_alert_already_seen_still_gets_its_verdict(app):
    _send(app, _items(ENCODED), verdicts=False)
    j = _send(app, _items(ENCODED))
    assert j["accepted"] == 0 and j["verdicts"][0]["verdict"] == "escalated"      # a replay refills the verdicts file


def test_lines_are_in_the_shape_the_wazuh_rules_read(app):
    batch = _items(ENCODED, PROBE, SCA)
    verdicts = _send(app, batch)["verdicts"]
    lines = [json.loads(x) for x in fw.verdict_lines(batch, verdicts)]
    assert len(lines) == 2, "the benchmark result is left out by default"
    enc = next(x["triagle"] for x in lines if x["triagle"]["verdict"] == "escalated")
    assert enc["agent"] == "FIN-LAPTOP-07" and enc["wazuh_rule_id"] == "92057" and enc["wazuh_rule_level"] == "12"
    assert enc["wazuh_alert_id"] == ENCODED["id"] and enc["use_case"] == "Obfuscated PowerShell execution"
    closed = next(x["triagle"] for x in lines if x["triagle"]["verdict"] == "closed")
    assert closed["closure"] == "Known admin tool" and closed["wazuh_rule_level"] == "15"
    assert all(isinstance(v, str) for x in lines for v in x["triagle"].values()), "plain strings, so Wazuh fields are simple"
    assert len(fw.verdict_lines(batch, verdicts, "all")) == 3
    assert fw.verdict_lines(batch, verdicts, "off") == []
    assert fw.verdict_lines(batch, [{"verdict": "nonsense"}, "junk", None]) == []


def test_the_forwarder_writes_verdicts_as_it_forwards(app, tmp_path, monkeypatch):
    alerts = tmp_path / "alerts.json"
    alerts.write_text("\n".join(json.dumps(a) for a in (DISCOVERY, ENCODED, PROBE, SCA)) + "\n")
    verdicts = tmp_path / "state" / "verdicts.json"

    def post(url, key, items, timeout=30):
        r = app.post("/ingest?verdicts=1", headers={"X-Triagle-Key": key}, json=items)
        return r.status_code == 200, r.text[:200], r.json().get("verdicts", [])
    monkeypatch.setattr(fw, "post", post)
    args = types.SimpleNamespace(alerts=str(alerts), state=str(tmp_path / "state" / "pos.json"), from_start=True,
                                 replay=0, triagle="http://t", key=KEY, client="Greenvale Co-operative Bank",
                                 min_level=3, max_backlog=5000, dry_run=False, once=True, interval=0.01,
                                 verdicts=str(verdicts), writeback="activity")
    assert fw.run(args) == 0
    lines = [json.loads(x)["triagle"] for x in verdicts.read_text().splitlines()]
    assert [x["verdict"] for x in lines] == ["closed", "escalated", "closed"]      # whoami, encoded, probe; no benchmark
    assert lines[0]["use_case"] == "Discovery command"
    assert len(main._load_result()["alerts"]) >= 4


def _as_wazuh_would_raise(line):
    """A verdict line after Wazuh has read it and matched rule 100501/100502."""
    t = json.loads(line)["triagle"]
    closed = t["verdict"] == "closed"
    return {"timestamp": "2026-11-24T05:20:00.000+0000", "id": "1795501200.99",
            "rule": {"level": 3 if closed else 10, "id": "100501" if closed else "100502",
                     "description": f"Triagle {'closed' if closed else 'escalated'}: {t['use_case']} on {t['agent']}",
                     "groups": ["triagle", "triagle_closed" if closed else "triagle_escalated"]},
            "agent": {"id": "000", "name": "wazuh"}, "manager": {"name": "wazuh"}, "decoder": {"name": "json"},
            "data": {"triagle": t}, "location": "/var/lib/triagle-forwarder/verdicts.json"}


def test_a_verdict_read_back_by_wazuh_never_becomes_an_alert(app):
    batch = _items(ENCODED)
    echoed = _as_wazuh_would_raise(fw.verdict_lines(batch, _send(app, batch)["verdicts"])[0])
    assert not fw.wanted(echoed, 3), "the forwarder skips it"
    before = len(main._load_result()["alerts"])
    r = _send(app, _items(echoed))
    assert r["accepted"] == 0 and r["verdicts"] == [], "and Triagle refuses it even if it is sent"
    assert len(main._load_result()["alerts"]) == before
    assert fw.wanted(ENCODED, 3)                                     # ordinary alerts still go


def test_a_missing_folder_does_not_stop_forwarding(tmp_path):
    assert fw.write_verdicts("", ["x"]) == 0
    blocked = tmp_path / "file-not-dir"
    blocked.write_text("")
    assert fw.write_verdicts(str(blocked / "v.json"), ["x"]) == 0    # cannot create: reported, not raised


def test_the_wazuh_rules_file_is_well_formed_and_uses_the_custom_id_range():
    tree = ET.parse(os.path.join(ROOT, "scripts", "wazuh", "triagle_rules.xml"))
    rules = tree.getroot().findall("rule")
    ids = [int(r.get("id")) for r in rules]
    assert ids == [100500, 100501, 100502, 100503] and all(100000 <= i <= 120000 for i in ids)
    assert tree.getroot().get("name") == "triagle,"
    used = {f.get("name") for r in rules for f in r.findall("field")}
    used |= {x for r in rules for x in re.findall(r"\$\(([a-z_.]+)\)", r.findtext("description"))}
    line = json.loads(fw.verdict_lines(_items(ENCODED), [{"id": ENCODED["id"], "verdict": "escalated"}])[0])
    assert all(f.split(".", 1)[1] in line["triagle"] for f in used), "every field a rule uses is written by the forwarder"
