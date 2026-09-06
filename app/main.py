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
import datetime

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.orchestrator import process_batch
from app.engine.response import execute_action

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SAMPLE_PATH = os.path.join(BASE_DIR, "samples", "incoming_alerts.json")

app = FastAPI(title="Triagle", version="0.1.0")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# process the sample batch once at startup for the demo; in production this
# would be a live queue fed by connectors.
_CACHE = {}


def _load_result():
    if "result" not in _CACHE:
        raw = json.load(open(SAMPLE_PATH))
        _CACHE["result"] = process_batch(raw)
    return _CACHE["result"]


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
    incident = next((i for i in result["incidents"] if i["key"] == entity), None)
    if not incident:
        return HTMLResponse(f"<p>No incident found for {entity}</p>", status_code=404)

    members = []
    client_name = None
    for a in result["alerts"]:
        if a["alert_id"] in incident["alert_ids"]:
            v = result["verdicts"].get(a["alert_id"], {})
            members.append({"alert": a, "verdict": v})
            client_name = a["client"]
    # order members chronologically to read as an attack timeline
    members.sort(key=lambda m: m["alert"].get("timestamp", ""))

    worst = max((m["verdict"].get("confidence", 0) for m in members), default=0)
    any_escalated = any(m["verdict"].get("escalate") for m in members)

    return templates.TemplateResponse(request, "report.html", {
        "incident": incident,
        "members": members,
        "client_name": client_name,
        "any_escalated": any_escalated,
        "now": datetime.datetime.now().strftime("%d %b %Y, %H:%M"),
    })
