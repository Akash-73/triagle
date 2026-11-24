"""Bursts: one event the tool reported as many alerts is raised once.

    python -m pytest -q tests/test_bursts.py

Taken from a real Wazuh server. One software update wrote 24 package-manager
alerts in two minutes, and one change deleted 11 monitored files in a second.
Each was an undecided, medium-rated alert, so the queue showed 37 rows for two
events and the one real alert, password guessing from the internet, sat among
them.

The rule: undecided alerts with the same cause on the same machine within a
few minutes become one open alert that says how many it stands for. Nothing is
closed without a person: the event still needs a decision, once. An alert
that was escalated on evidence is never folded.
"""
import datetime as dt

import pytest
from fastapi.testclient import TestClient

from app import auth, main
from app.engine import bursts, usecases
from app.orchestrator import process_batch

BANK = "Greenvale Co-operative Bank"
T0 = dt.datetime(2026, 11, 24, 6, 6, 0)


def _wz(sec, rid, level, desc, groups, data=None, host="wazuh-demo", client=BANK, syscheck=None, n=0):
    t = T0 + dt.timedelta(seconds=sec)
    raw = {"timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "id": f"{int(t.timestamp())}.{rid}{n}",
           "rule": {"id": rid, "level": level, "description": desc, "groups": list(groups)},
           "agent": {"id": "000", "name": host}, "manager": {"name": host},
           "decoder": {"name": "dpkg-decoder" if "dpkg" in groups else "syscheck_integrity_changed"},
           "data": data or {}, "location": "/var/log/dpkg.log" if "dpkg" in groups else "syscheck"}
    if syscheck:
        raw["syscheck"] = syscheck
    return {"source": "wazuh", "client": client, "raw": raw}


def dpkg_installed(sec, pkg, n=0, **kw):
    return _wz(sec, "2902", 7, "New dpkg (Debian Package) installed.", ("syslog", "dpkg", "config_changed"),
               {"package": pkg, "dpkg_status": "installed", "arch": "amd64"}, n=n, **kw)


def dpkg_half(sec, pkg, n=0, **kw):
    return _wz(sec, "2904", 7, "Dpkg (Debian Package) half configured.", ("syslog", "dpkg", "config_changed"),
               {"package": pkg, "dpkg_status": "half-configured", "arch": "amd64"}, n=n, **kw)


def file_deleted(sec, path, n=0, **kw):
    return _wz(sec, "553", 7, "File deleted.", ("ossec", "syscheck", "syscheck_entry_deleted", "syscheck_file"),
               syscheck={"path": path, "event": "deleted"}, n=n, **kw)


def file_changed(sec, path, n=0, **kw):
    return _wz(sec, "550", 7, "Integrity checksum changed.",
               ("ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"),
               syscheck={"path": path, "event": "modified"}, n=n, **kw)


def update(start=0):
    """One software update as the server reported it: 24 alerts in 66 seconds."""
    pkgs = ["libssl3", "openssl", "libc6", "libc-bin", "curl", "libcurl4", "tzdata", "python3-apt", "apt"]
    out = [dpkg_installed(start + 7 * i, p, n=i) for i, p in enumerate(pkgs)]
    out += [dpkg_half(start + 4 * i + 1, pkgs[i % len(pkgs)], n=100 + i) for i in range(15)]
    return out


def deployment(start=0):
    paths = [f"/etc/app/conf.d/{i:02d}-rule.conf" for i in range(11)]
    return [file_deleted(start, p, n=i) for i, p in enumerate(paths)] + \
           [file_changed(start - 34, "/etc/app/app.conf", n=50), file_changed(start - 35, "/etc/app/rules.xml", n=51)]


def _open(r):
    return [(a, r["verdicts"][a["alert_id"]]) for a in r["alerts"] if r["verdicts"][a["alert_id"]]["escalate"]]


def test_one_software_update_is_one_decision_not_twenty_four():
    r = process_batch(update())
    opened = _open(r)
    assert len(opened) == 1 and r["metrics"]["folded"] == 23
    a, v = opened[0]
    assert v["disposition"] == "needs_human", "still for a person: Triagle does not close a software change itself"
    assert v["burst"]["count"] == 24 and "24 events" in v["summary"] and "raised once" in v["summary"]
    assert "libssl3" in v["burst"]["items"] and "libssl3" in v["reasoning"]
    assert usecases.for_alert(a, v)["name"] == "Software installed or changed on a server"
    for other in r["alerts"]:
        if other["alert_id"] == a["alert_id"]:
            continue
        ov = r["verdicts"][other["alert_id"]]
        assert ov["closure_code"] == "BENIGN_DUPLICATE" and ov["duplicate_of"] == a["alert_id"]
    earliest = min(r["alerts"], key=lambda x: x["timestamp"])
    assert a["alert_id"] == earliest["alert_id"], "the earliest alert is the one that stays open"
    assert any(st["tool"] == "burst" for st in r["trails"][a["alert_id"]])


def test_one_change_to_monitored_files_is_one_decision_with_the_paths():
    r = process_batch(deployment(start=100))
    opened = _open(r)
    assert len(opened) == 1
    a, v = opened[0]
    assert "11 deleted, 2 changed" in v["summary"] and v["burst"]["count"] == 13
    assert "/etc/app/app.conf" in v["burst"]["items"] and v["burst"]["more"] == 1
    assert usecases.for_alert(a, v)["id"] == "UC-703"


def test_the_real_queue_goes_from_thirty_eight_rows_to_three():
    from tests.test_firewall import guesses
    items = update(start=3000) + deployment(start=100) + guesses(5)
    r = process_batch(items)
    opened = _open(r)
    names = sorted(usecases.for_alert(a, v)["name"] for a, v in opened)
    assert names == ["Monitored files changed or deleted", "Password guessing from one address",
                     "Software installed or changed on a server"]
    assert sum(1 for a, v in opened if v.get("pattern") == "password_guessing") == 1


def test_two_updates_hours_apart_are_two_decisions():
    r = process_batch(update(start=0) + [dpkg_installed(4 * 3600 + i, f"pkg{i}", n=900 + i) for i in range(3)])
    assert sorted(v["burst"]["count"] for _, v in _open(r)) == [3, 24]


def test_a_long_run_is_raised_again_each_hour(monkeypatch):
    steady = [dpkg_installed(300 * i, f"pkg{i}", n=i) for i in range(30)]          # one every 5 minutes, 2.5 hours
    r = process_batch(steady)
    assert len(_open(r)) == 3


def test_nothing_is_folded_across_machines_customers_or_causes():
    items = [dpkg_installed(0, "curl", n=1), dpkg_installed(5, "curl", n=2, host="db-01"),
             dpkg_installed(9, "curl", n=3, client="Meridian Textiles"), file_deleted(11, "/etc/x", n=4)]
    r = process_batch(items)
    assert len(_open(r)) == 4 and r["metrics"]["folded"] == 0


def test_an_alert_escalated_on_evidence_is_never_folded():
    """Same title, same machine, same minute, but each one carries a risk
    term or a high rating. Every one stays open on its own."""
    risky = [_wz(i, "100200", 7, "Ransomware note written to disk", ("syslog", "custom"), n=i) for i in range(3)]
    high = [_wz(20 + i, "100201", 13, "Kernel module loaded from tmp", ("syslog", "custom"), n=10 + i) for i in range(3)]
    r = process_batch(risky + high)
    assert len(_open(r)) == 6 and r["metrics"]["folded"] == 0
    for a in r["alerts"]:
        assert not bursts._eligible(a, r["verdicts"][a["alert_id"]])


def test_a_single_undecided_alert_is_left_as_it_was():
    r = process_batch([dpkg_installed(0, "curl")])
    (a, v), = _open(r)
    assert "burst" not in v and v["summary"].startswith("Undetermined")


def test_the_gap_is_a_setting(monkeypatch):
    two = [dpkg_installed(0, "a", n=1), dpkg_installed(15 * 60, "b", n=2)]
    assert len(_open(process_batch(two))) == 2
    monkeypatch.setenv("TRIAGLE_BURST_MINUTES", "20")
    assert len(_open(process_batch(two))) == 1


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGLE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(main, "INGEST_KEY", "k")
    auth.load_config({"TRIAGLE_ADMIN_PASSWORD": "pw", "TRIAGLE_SECRET": "s"})
    main._CACHE.clear()
    c = TestClient(main.app)
    c.post("/login", data={"username": "admin", "password": "pw"})
    yield c
    main._CACHE.clear()
    auth.load_config()


def test_the_console_shows_the_count_and_links_a_folded_alert_to_its_burst(app):
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    start = int((now - dt.timedelta(minutes=30) - T0.replace(tzinfo=dt.timezone.utc)).total_seconds())
    assert app.post("/ingest", headers={"X-Triagle-Key": "k"}, json=update(start=start)).json()["accepted"] == 24
    res = main._load_result()
    rep = next(a for a in res["alerts"] if res["verdicts"][a["alert_id"]].get("burst"))
    page = app.get("/alerts?show=open&q=Greenvale").text
    assert page.count('data-href="/alert/wz-') == 1 and "24 alerts" in page
    detail = app.get(f"/alert/{rep['alert_id']}").text
    assert "Stands for" in detail and "libssl3" in detail and "Grouped alerts that are one event" in detail
    other = res["verdicts"][rep["alert_id"]]["burst"]["member_ids"][0]
    folded = app.get(f"/alert/{other}").text
    assert "Already raised" in folded and f'href="/alert/{rep["alert_id"]}"' in folded
