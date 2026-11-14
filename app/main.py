"""
Triagle — main application.

An AI SOC analyst + responder for MSPs: ingest alerts from multiple client
tools, triage each with conservative-closure logic, correlate into
incidents (attack chains), and present a decided queue an MSP can act on —
plus a client-ready incident report to forward to the end customer.

Triagle — triage, decided.
"""
import os
import json
import time
import datetime

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.orchestrator import process_batch
from app.engine.response import execute_action
from app.engine import certin
from app.agent import backend

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SAMPLE_PATH = os.path.join(BASE_DIR, "samples", "incoming_alerts.json")

app = FastAPI(title="Triagle", version="0.2.0")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# process the sample batch once at startup for the demo; in production this
# would be a live queue fed by connectors.
_CACHE = {}


def _load_result():
    if "result" not in _CACHE:
        with open(os.environ.get("TRIAGLE_ALERTS", SAMPLE_PATH)) as f:
            raw = json.load(f)
        demo_clock = os.environ.get("TRIAGLE_DEMO_CLOCK", "false").lower() == "true"
        if demo_clock:
            raw = _rebase_times(raw)
        t0 = time.perf_counter()
        result = process_batch(raw)
        result["metrics"]["demo_clock"] = demo_clock
        result["metrics"]["processing_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        result["metrics"]["backend"] = backend.BACKEND
        _CACHE["result"] = result
    return _CACHE["result"]


_TIME_KEYS = ("created_timestamp", "eventtime", "createdDateTime")


def _rebase_times(raw_alerts):
    """Demo only (TRIAGLE_DEMO_CLOCK=true): shift each client's sample
    timestamps by one amount so that client's newest alert is five minutes
    old. Order and gaps within a client are kept. Lets the 6-hour clock be
    shown running on old sample data."""
    def when(item):
        for k in _TIME_KEYS:
            v = item["raw"].get(k)
            if v:
                try:
                    return k, datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                except ValueError:
                    pass
        return None, None
    target = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    newest = {}
    for item in raw_alerts:
        _, t = when(item)
        if t and (item.get("client") not in newest or t > newest[item.get("client")]):
            newest[item.get("client")] = t
    for item in raw_alerts:
        k, t = when(item)
        if t:
            item["raw"][k] = (t + (target - newest[item.get("client")])).strftime("%Y-%m-%dT%H:%M:%SZ")
    return raw_alerts


def _incident_members(result, incident):
    members = []
    for a in result["alerts"]:
        if a["alert_id"] in incident["alert_ids"]:
            members.append({"alert": a, "verdict": result["verdicts"].get(a["alert_id"], {})})
    members.sort(key=lambda m: m["alert"].get("timestamp", ""))
    return members


def _find_incident(result, entity):
    e = entity.lower()
    for i in result["incidents"]:
        if i["key"].lower() == e or e in (x.lower() for x in i.get("entities", [])):
            return i
    return None


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    result = _load_result()
    # build a combined alert+verdict view, escalated first
    rows = []
    for a in result["alerts"]:
        v = result["verdicts"].get(a["alert_id"], {})
        rows.append({"alert": a, "verdict": v})
    rows.sort(key=lambda r: (not r["verdict"].get("escalate"),
                             {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r["verdict"].get("severity"), 9)))
    for inc in result["incidents"]:
        inc["reportable"] = certin.is_reportable_candidate(_incident_members(result, inc))
    return templates.TemplateResponse(request, "dashboard.html", {
        "rows": rows,
        "metrics": result["metrics"],
        "incidents": result["incidents"],
        "now": datetime.datetime.now().strftime("%d %b %Y, %H:%M"),
    })


@app.get("/alert/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: str):
    result = _load_result()
    alert = next((a for a in result["alerts"] if a["alert_id"] == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"No alert with id {alert_id}")
    verdict = result["verdicts"].get(alert_id)
    trail = result.get("trails", {}).get(alert_id, [])
    actions = result.get("actions", {}).get(alert_id, [])
    return templates.TemplateResponse(request, "detail.html", {
        "alert": alert,
        "verdict": verdict,
        "trail": trail,
        "actions": actions,
        "now": datetime.datetime.now().strftime("%d %b %Y, %H:%M"),
    })


@app.post("/action/approve")
def approve_action(alert_id: str = Form(...), action_id: str = Form(...), ack: str = Form(default="")):
    """Human approves a staged action, which then 'executes' (simulated).
    High-impact actions require the ack checkbox."""
    result = _load_result()
    acts = result.get("actions", {}).get(alert_id, [])
    for act in acts:
        if act["action_id"] == action_id:
            if act.get("requires_ack") and ack != "on":
                act["status"] = "declined"
                act["result_message"] = "Declined — high-impact action requires blast-radius acknowledgement."
            else:
                act["status"] = "approved"
                res = execute_action(act, approver="analyst")
                act["status"] = "executed" if res["ok"] else "approved"
                act["result_message"] = res["message"]
            break
    return RedirectResponse(url=f"/alert/{alert_id}", status_code=303)


@app.get("/tuning", response_class=HTMLResponse)
def tuning_page(request: Request):
    result = _load_result()
    return templates.TemplateResponse(request, "tuning.html", {
        "rule_health": result.get("rule_health", []),
        "metrics": result["metrics"],
        "now": datetime.datetime.now().strftime("%d %b %Y, %H:%M"),
    })


@app.get("/report/{entity}", response_class=HTMLResponse)
def incident_report(request: Request, entity: str):
    """Client-ready incident report for a correlated incident, keyed by the
    incident's entity. This is the artifact an MSP forwards to its customer."""
    result = _load_result()
    incident = _find_incident(result, entity)
    if not incident:
        raise HTTPException(status_code=404, detail=f"No incident found for {entity}")

    members = _incident_members(result, incident)
    client_name = incident.get("client") or (members[0]["alert"]["client"] if members else None)

    any_escalated = any(m["verdict"].get("escalate") for m in members)

    return templates.TemplateResponse(request, "report.html", {
        "incident": incident,
        "members": members,
        "client_name": client_name,
        "any_escalated": any_escalated,
        "reportable": certin.is_reportable_candidate(members),
        "now": datetime.datetime.now().strftime("%d %b %Y, %H:%M"),
    })


@app.get("/certin/{entity}", response_class=HTMLResponse)
def certin_draft(request: Request, entity: str):
    """Draft CERT-In incident report for an incident, with the 6-hour clock.
    A draft for a person to check and send; nothing is filed from here."""
    from app.orchestrator import _load_env
    result = _load_result()
    incident = _find_incident(result, entity)
    if not incident:
        raise HTTPException(status_code=404, detail=f"No incident found for {entity}")
    members = _incident_members(result, incident)
    if not certin.is_reportable_candidate(members):
        raise HTTPException(status_code=404, detail="Nothing in this incident was escalated; no report draft.")
    draft = certin.build_draft(incident, members, result.get("actions", {}),
                               threat_intel=_load_env().get("threat_intel"))
    return templates.TemplateResponse(request, "certin.html", {
        "d": draft, "metrics": result["metrics"],
    })


@app.get("/benchmark", response_class=HTMLResponse)
def benchmark_page(request: Request):
    """Runs the labelled simulated set in eval/ through the same engine."""
    from eval.run_benchmark import run
    rows, summary, elapsed, _ = run()
    return templates.TemplateResponse(request, "benchmark.html", {
        "rows": rows, "summary": summary, "ms": round(elapsed * 1000),
        "backend": backend.BACKEND,
    })


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": app.version, "backend": backend.BACKEND,
            "mask_pii": backend.MASK_PII, "model_calls": backend.STATS["calls"],
            "identifiers_masked": backend.STATS["masked"]}
