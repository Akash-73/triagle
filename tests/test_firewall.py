"""The response action that is real: blocking an address at the Google Cloud firewall.

    python -m pytest -q tests/test_firewall.py

No network. Google Cloud is faked, so these tests pin exactly what would be
sent and, more to the point, when nothing may be sent at all. The rules:

  - it is off unless a customer is named, and then only for that customer's
    machines on that network;
  - only a signed-in analyst's approval reaches the firewall. Rebuilding the
    queue, the automatic tier and the "try an alert" box never do;
  - one public address per rule. Private and reserved addresses, Google's own
    management ranges, the never-block list and the approver's own address
    are refused;
  - Triagle lists and deletes only rules it added;
  - a call that fails changes nothing and leaves the action open, with the
    reason on it.
"""
import datetime as dt
import json

import pytest
from fastapi.testclient import TestClient

from app import audit, auth, main
from app.engine import action_tools, gcp_firewall, genai
from app.orchestrator import process_batch

KEY = "fw-key"
BANK = "Greenvale Co-operative Bank"
ATTACKER = "93.184.216.34"                     # a public address, standing in for the guesser
RULE = "triagle-block-93-184-216-34-in"
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


class FakeResp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body) if body is not None else ""

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class Cloud:
    """A Google Cloud project with a firewall, in memory."""

    def __init__(self):
        self.calls = []
        self.fail = None
        self.granted = list(gcp_firewall._NEEDED)
        self.rules = {"default-allow-ssh": {"name": "default-allow-ssh", "direction": "INGRESS",
                                            "sourceRanges": ["0.0.0.0/0"], "network": "x/global/networks/default"}}

    def request(self, method, url, json=None, params=None, headers=None, timeout=None):
        assert headers == {"Authorization": "Bearer tok"}
        assert "/projects/demo-project/" in url
        path = url.split("/projects/demo-project/")[1]
        self.calls.append((method, path, json))
        if self.fail:
            return FakeResp(*self.fail)
        if method == "GET" and path == "global/firewalls":
            return FakeResp(200, {"items": list(self.rules.values())})
        if method == "POST" and path == "global/firewalls":
            if json["name"] in self.rules:
                return FakeResp(409, {"error": {"message": "already exists"}})
            self.rules[json["name"]] = {**json, "creationTimestamp": "2026-11-24T10:00:00.000-08:00"}
            return FakeResp(200, {"name": "operation-1", "status": "RUNNING"})
        if method == "GET" and path.startswith("global/operations/"):
            return FakeResp(200, {"name": "operation-1", "status": "DONE"})
        if method == "DELETE" and path.startswith("global/firewalls/"):
            name = path.rsplit("/", 1)[1]
            if name not in self.rules:
                return FakeResp(404, {"error": {"message": "not found"}})
            del self.rules[name]
            return FakeResp(200, {"name": "operation-2", "status": "DONE"})
        return FakeResp(404, {"error": {"message": "unknown"}})

    def post(self, url, json=None, headers=None, timeout=None):            # the permission check
        return FakeResp(200, {"permissions": self.granted})

    def changes(self):
        return [(m, p) for m, p, _ in self.calls if m in ("POST", "DELETE")]


@pytest.fixture
def cloud(tmp_path, monkeypatch):
    for k in ("TRIAGLE_GCP_FIREWALL_CLIENT", "TRIAGLE_GCP_FIREWALL_HOSTS", "TRIAGLE_GCP_FIREWALL_PROJECT",
              "TRIAGLE_GCP_FIREWALL_NETWORK", "TRIAGLE_GCP_FIREWALL_TAGS", "TRIAGLE_GCP_FIREWALL_MAX",
              "TRIAGLE_NEVER_BLOCK", "TRIAGLE_EXECUTE", "K_SERVICE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "demo-project")
    c = Cloud()
    monkeypatch.setattr(gcp_firewall.requests, "request", c.request)
    monkeypatch.setattr(gcp_firewall.requests, "post", c.post)
    monkeypatch.setattr(gcp_firewall.time, "sleep", lambda s: None)
    monkeypatch.setattr(genai, "_access_token", lambda: "tok")
    return c


@pytest.fixture
def connected(cloud, monkeypatch):
    monkeypatch.setenv("TRIAGLE_GCP_FIREWALL_CLIENT", BANK)
    monkeypatch.setenv("TRIAGLE_GCP_FIREWALL_HOSTS", "wazuh-demo")
    return cloud


def guesses(n=5, src=ATTACKER, host="wazuh-demo", client=BANK):
    """n failed sign-ins from one address, two minutes apart: too slow for the
    SIEM's own brute-force rule, and exactly what Triagle raises."""
    out = []
    for i in range(n):
        t = NOW - dt.timedelta(minutes=40) + dt.timedelta(seconds=150 * i)
        out.append({"source": "wazuh", "client": client, "raw": {
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "id": f"{int(t.timestamp())}.{i}",
            "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user",
                     "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"]},
            "agent": {"id": "000", "name": host}, "manager": {"name": host},
            "decoder": {"parent": "sshd", "name": "sshd"}, "data": {"srcip": src, "srcuser": "admin"},
            "location": "journald"}})
    return out


def block_action(result):
    """The block proposed for the guesser (the sample data proposes others)."""
    return next(a for acts in result["actions"].values() for a in acts
                if a["action_type"] == "block_indicator" and a["target"] == ATTACKER)


def _csrf(page):
    return page.split('name="csrf" value="')[1].split('"')[0]


@pytest.fixture
def app(connected, monkeypatch):
    monkeypatch.setattr(main, "INGEST_KEY", KEY)
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s",
                      "TRIAGLE_USERS": "jury:viewer:" + auth.hash_password("look")})
    main._CACHE.clear()
    main._ASK_TIMES.clear()
    main._ASK_ALL.clear()
    c = TestClient(main.app)
    assert c.post("/login", data={"username": "admin", "password": "pw"}, follow_redirects=False).status_code == 303
    assert c.post("/ingest", headers={"X-Triagle-Key": KEY}, json=guesses()).json()["accepted"] == 5
    yield c
    main._CACHE.clear()
    auth.load_config()


def _approve(app, act, **extra):
    page = app.get(f"/alert/{act['alert_id']}").text
    return app.post("/action/approve", data={"alert_id": act["alert_id"], "action_id": act["action_id"],
                                             "csrf": _csrf(page), **extra}, follow_redirects=False)


def _action(act):
    return next(a for a in main._load_result()["actions"][act["alert_id"]] if a["action_id"] == act["action_id"])


# ---- when it applies ---------------------------------------------------------

def test_off_by_default_so_every_block_is_a_rehearsal(cloud):
    act = block_action(process_batch(guesses()))
    assert act["real"] is False and act["tool_call"]["connector"] != "gcp_firewall"
    assert action_tools.dispatch(act, approver="a", live=True)["mode"] == "dry_run"
    assert cloud.calls == []


def test_for_the_connected_customer_a_block_is_real_and_waits_for_a_person(connected):
    act = block_action(process_batch(guesses()))
    assert act["real"] is True and act["status"] == "pending" and act["policy"] == "approval"
    assert act["target"] == ATTACKER and act["platform"] == "Google Cloud firewall"
    call = act["tool_call"]
    assert call["method"] == "POST" and call["endpoint"].endswith("/projects/demo-project/global/firewalls")
    body = call["body"]
    assert body["name"] == RULE and body["sourceRanges"] == [ATTACKER + "/32"]
    assert body["denied"] == [{"IPProtocol": "all"}] and body["direction"] == "INGRESS" and body["priority"] == 900
    assert body["network"] == "projects/demo-project/global/networks/default"
    assert connected.calls == [], "working out what to propose never calls Google Cloud"


def test_another_customer_or_a_machine_on_another_network_stays_a_rehearsal(connected):
    assert block_action(process_batch(guesses(client="Meridian Capital")))["real"] is False
    assert block_action(process_batch(guesses(host="fin-laptop-07")))["real"] is False


def test_the_addresses_that_are_never_blocked(connected, monkeypatch):
    monkeypatch.setenv("TRIAGLE_NEVER_BLOCK", "8.8.8.0/24, 1.1.1.1")
    ok = gcp_firewall.refusal
    assert ok(ATTACKER) is None
    assert "private or reserved" in ok("10.20.4.17") and "private or reserved" in ok("127.0.0.1")
    assert "private or reserved" in ok("203.0.113.45"), "documentation addresses are sample data"
    assert "browser-SSH" in ok("35.235.240.9") and "health-check" in ok("35.191.3.3")
    assert "never-block" in ok("8.8.8.8") and "never-block" in ok("1.1.1.1")
    assert "you are connecting from" in ok(ATTACKER, approver_ip=ATTACKER)
    assert "not an internet address" in ok("evil.example") and "not an internet address" in ok("d41d8cd98f00b204")
    res = gcp_firewall.block("10.20.4.17", approver="admin")
    assert res["ok"] is False and connected.calls == []


def test_a_destination_is_blocked_outbound(connected):
    body = gcp_firewall.rule_body(ATTACKER, "out", "admin", "wz-1")
    assert body["direction"] == "EGRESS" and body["destinationRanges"] == [ATTACKER + "/32"]
    assert "sourceRanges" not in body and body["name"].endswith("-out")


# ---- a person approves -------------------------------------------------------

def test_approving_adds_the_rule_and_lifting_deletes_it(app, connected):
    act = block_action(main._load_result())
    page = app.get(f"/alert/{act['alert_id']}").text
    assert "Real change" in page and "Approve and block" in page
    assert connected.changes() == []

    assert _approve(app, act).status_code == 303
    assert connected.changes() == [("POST", "global/firewalls")]
    sent = connected.rules[RULE]
    assert sent["sourceRanges"] == [ATTACKER + "/32"] and "Approved by admin" in sent["description"]
    done = _action(act)
    assert done["status"] == "executed" and done["undo"] == {"connector": "gcp_firewall", "rule": RULE}
    assert "is in force" in done["result_message"]
    entry = next(e for e in audit.read() if e["event"] == "action approved")
    assert entry["mode"] == "live" and entry["simulated"] is False and entry["rule"] == RULE

    page = app.get(f"/alert/{act['alert_id']}").text
    assert "Done, for real" in page and "Lift the block" in page
    r = app.post("/action/lift", data={"alert_id": act["alert_id"], "action_id": act["action_id"],
                                       "csrf": _csrf(page)}, follow_redirects=False)
    assert r.status_code == 303 and "notice=lifted" in r.headers["location"]
    assert RULE not in connected.rules and connected.changes()[-1] == ("DELETE", f"global/firewalls/{RULE}")
    again = _action(act)
    assert again["status"] == "pending" and again["undo"] is None and "Block lifted by admin" in again["result_message"]
    assert any(e["event"] == "block lifted" for e in audit.read())
    assert _approve(app, act).status_code == 303 and RULE in connected.rules, "and it can be blocked again"


def test_the_decision_survives_the_queue_being_rebuilt(app, connected):
    act = block_action(main._load_result())
    _approve(app, act)
    app.post("/ingest", headers={"X-Triagle-Key": KEY}, json=guesses(1, src="198.51.100.9"))      # forces a rebuild
    assert _action(act)["status"] == "executed" and _action(act)["undo"]["rule"] == RULE
    assert connected.changes() == [("POST", "global/firewalls")], "rebuilding never sends the call a second time"


def test_a_refused_call_changes_nothing_and_leaves_the_action_open(app, connected):
    act = block_action(main._load_result())
    connected.fail = (403, {"error": {"message": "Required 'compute.firewalls.create' permission"}})
    r = _approve(app, act)
    assert "notice=failed" in r.headers["location"]
    left = _action(act)
    assert left["status"] == "pending" and "Compute Security Admin" in left["error"] and left["undo"] is None
    assert "Last attempt" in app.get(f"/alert/{act['alert_id']}").text
    failed = next(e for e in audit.read() if e["event"] == "real action failed")
    assert failed["executed"] is False
    connected.fail = None
    _approve(app, act)
    assert _action(act)["status"] == "executed" and _action(act)["error"] == ""


def test_an_address_already_blocked_is_not_an_error(app, connected):
    connected.rules[RULE] = {"name": RULE, "direction": "INGRESS", "sourceRanges": [ATTACKER + "/32"],
                             "network": "x/global/networks/default"}
    act = block_action(main._load_result())
    _approve(app, act)
    assert _action(act)["status"] == "executed" and "Already blocked" in _action(act)["result_message"]
    assert connected.changes() == []


def test_triagle_stops_at_its_limit(app, connected, monkeypatch):
    monkeypatch.setenv("TRIAGLE_GCP_FIREWALL_MAX", "1")
    connected.rules["triagle-block-1-2-3-4-in"] = {"name": "triagle-block-1-2-3-4-in", "sourceRanges": ["1.2.3.4/32"]}
    act = block_action(main._load_result())
    _approve(app, act)
    assert _action(act)["status"] == "pending" and "its limit" in _action(act)["error"]
    assert connected.changes() == []


# ---- who and what can never reach the firewall -------------------------------

def test_with_sign_in_off_nothing_real_runs(app, connected):
    act = block_action(main._load_result())
    auth.load_config({"TRIAGLE_AUTH": "off"})
    r = app.post("/action/approve", data={"alert_id": act["alert_id"], "action_id": act["action_id"]},
                 follow_redirects=False)
    assert "notice=signin" in r.headers["location"]
    assert _action(act)["status"] == "pending" and connected.calls == []
    assert app.post("/api/firewall/check", json={}).status_code == 403
    assert app.post("/api/firewall/lift", json={"rule": RULE}).status_code == 403


def test_a_view_only_account_cannot_approve_lift_or_look(app, connected):
    act = block_action(main._load_result())
    jury = TestClient(main.app)
    jury.post("/login", data={"username": "jury", "password": "look"})
    page = jury.get(f"/alert/{act['alert_id']}").text
    assert "A signed-in analyst approves this one" in page and "Approve and block" not in page
    data = {"alert_id": act["alert_id"], "action_id": act["action_id"], "csrf": "x"}
    assert jury.post("/action/approve", data=data).status_code == 403
    assert jury.post("/action/lift", data=data).status_code == 403
    assert jury.post("/api/firewall/check", json={}).status_code == 403
    assert jury.post("/api/firewall/lift", json={"rule": RULE}).status_code == 403
    assert connected.calls == []


def test_the_automatic_tier_and_the_try_box_never_reach_the_firewall(app, connected):
    act = block_action(main._load_result())
    res = action_tools.dispatch(act, approver="Triagle · auto-policy")           # live is False unless a person approved
    assert res["ok"] is False and res["mode"] == "dry_run" and connected.calls == []
    page = app.get("/connectors").text
    token = page.split("var CSRF = ")[1].split(",")[0].strip().strip('"')
    r = app.post("/api/try", json={"source": "wazuh", "client": BANK, "raw": json.dumps(guesses(1)[0]["raw"]),
                                   "csrf": token})
    assert r.status_code == 200 and connected.calls == []


def test_only_rules_triagle_added_are_listed_or_deleted(connected):
    connected.rules[RULE] = {"name": RULE, "direction": "INGRESS", "sourceRanges": [ATTACKER + "/32"],
                             "network": "x/global/networks/default", "description": "Blocked by Triagle."}
    connected.rules["triagle-block-notes"] = {"name": "triagle-block-notes"}      # a person's rule, similar name
    listed = gcp_firewall.blocks()
    assert [r["name"] for r in listed["rules"]] == [RULE] and listed["rules"][0]["address"] == ATTACKER
    for name in ("default-allow-ssh", "triagle-block-notes", "", "../default-allow-ssh"):
        assert gcp_firewall.lift(name)["ok"] is False
    assert connected.changes() == [] and "default-allow-ssh" in connected.rules


# ---- the Connectors page ------------------------------------------------------

def test_the_connectors_page_checks_access_and_lifts_a_block(app, connected):
    page = app.get("/connectors").text
    assert "Google Cloud firewall" in page and "Check access and show blocks" in page and "wazuh-demo" in page
    token = page.split("var CSRF = ")[1].split(",")[0].strip().strip('"')
    act = block_action(main._load_result())
    _approve(app, act)

    res = app.post("/api/firewall/check", json={"csrf": token}).json()
    assert res["ok"] and res["message"].startswith("Ready.") and [r["name"] for r in res["rules"]] == [RULE]
    connected.granted = ["compute.firewalls.list"]
    res = app.post("/api/firewall/check", json={"csrf": token}).json()
    assert res["ok"] is False and "may not change it" in res["message"] and "compute.firewalls.create" in res["message"]

    assert app.post("/api/firewall/lift", json={"rule": RULE}).status_code == 403, "needs the form token"
    res = app.post("/api/firewall/lift", json={"csrf": token, "rule": RULE}).json()
    assert res["ok"] and RULE not in connected.rules
    assert _action(act)["status"] == "pending", "the action that added it is open again"
    assert app.post("/api/firewall/lift", json={"csrf": token, "rule": "default-allow-ssh"}).json()["ok"] is False


def test_an_unconnected_tool_is_never_reported_as_sent(cloud, monkeypatch):
    monkeypatch.setenv("TRIAGLE_EXECUTE", "live")
    res = action_tools.dispatch({"action_type": "isolate_host", "target": "HQ-WKS-22",
                                 "platform": "EDR (CrowdStrike / Defender)"}, approver="admin", live=True)
    assert res["ok"] is False and res["mode"] == "not_connected" and "Not sent" in res["message"]
    monkeypatch.delenv("TRIAGLE_EXECUTE")
    res = action_tools.dispatch({"action_type": "isolate_host", "target": "HQ-WKS-22",
                                 "platform": "EDR (CrowdStrike / Defender)"}, approver="admin", live=True)
    assert res["ok"] and res["message"].startswith("Rehearsal:")
