"""
Triagle — care around operational technology (OT).

Triagle does not detect attacks on industrial control systems. An OT network
monitor does that. What Triagle adds is care about what happens next.

In IT the safe reflex is to isolate the machine. In a plant or a substation
that reflex can stop a process, or take the screen away from the operators
who are keeping it safe. So three rules hold whenever an OT asset is involved:

  1. An alert that touches a controller is never closed without a person.
  2. Nothing is done to an OT asset automatically, and a controller or an
     operator station is never isolated. Containment is proposed on the IT
     side of the boundary instead, where it stops the attacker and leaves
     the process running.
  3. The plant is told. The first proposed step is a phone call.

Two kinds of asset:
  controller        PLC, RTU, IED, DCS, safety system. Runs the process.
  operator station  HMI, SCADA server, historian, engineering workstation.
                    People watch and steer the process from it.

An asset is recognised by its name (TPG-RTU-FEEDER-07, PLANT2-HMI-01), or by
being listed in TRIAGLE_OT_CONTROLLERS / TRIAGLE_OT_STATIONS (comma-separated
names; a trailing * matches a prefix). Names are a starting point: a real
deployment takes the asset list from the OT monitor's inventory.
"""
import os
import re

CONTROLLER = "controller"
OPERATOR = "operator station"

_CONTROLLER_RE = re.compile(r"(?<![a-z])(plc|rtu|ied|dcs|sis|rtac)(?![a-z])")
_OPERATOR_RE = re.compile(r"(?<![a-z])(hmi|scada|historian|ews|engws|opc)(?![a-z])")

_PROTOCOL_RE = re.compile(
    r"(?<![a-z0-9])(modbus|dnp3|s7comm|iec[ -]?60870(-5)?(-104)?|iec[ -]?104|iec[ -]?61850|goose|"
    r"ethernet/ip|profinet|opc[ -]?ua|bacnet)(?![a-z0-9])")
OT_PORTS = {"502": "Modbus", "20000": "DNP3", "102": "S7comm", "44818": "EtherNet/IP",
            "2404": "IEC 60870-5-104", "4840": "OPC UA", "47808": "BACnet"}

# MITRE ATT&CK for ICS technique ids are T08xx
_ICS_TECHNIQUE_RE = re.compile(r"(?<![a-z0-9])t08\d\d(?![0-9])")

# What an OT monitor calls the events that matter. Only read as a signal when
# the alert is about an OT asset or an industrial protocol: "firmware update"
# on a laptop is patching, on a controller it is a change to the process.
TERMS = [
    "program download", "program upload", "logic download", "logic change", "firmware",
    "plc stop", "cpu stop", "controller stop", "stop command", "mode change",
    "cold restart", "warm restart", "restart command", "unauthorised command", "unauthorized command",
    "control command", "write to controller", "force", "setpoint", "set point", "safety system",
    "new engineering station", "purdue",
]
_TERM_RE = [(t, re.compile(r"(?<![a-z0-9])" + re.escape(t))) for t in TERMS]


def _get(alert, key):
    return alert.get(key) if isinstance(alert, dict) else getattr(alert, key, None)


def _listed(env_name):
    return [x.strip().lower() for x in os.environ.get(env_name, "").split(",") if x.strip()]


def _in_list(name, entries):
    return any(name == e or (e.endswith("*") and name.startswith(e[:-1])) for e in entries)


def asset_class(name):
    """controller / operator station / None for one asset name."""
    if not name:
        return None
    n = str(name).strip().lower()
    if _in_list(n, _listed("TRIAGLE_OT_CONTROLLERS")):
        return CONTROLLER
    if _in_list(n, _listed("TRIAGLE_OT_STATIONS")):
        return OPERATOR
    if _CONTROLLER_RE.search(n):
        return CONTROLLER
    if _OPERATOR_RE.search(n):
        return OPERATOR
    return None


def assets(alert):
    """{asset name: class} for every OT asset the alert names."""
    ind = _get(alert, "indicators") or {}
    out = {}
    for v in (_get(alert, "host"), _get(alert, "entity"), ind.get("ot_target"), ind.get("ot_source"),
              _get(alert, "src_ip"), _get(alert, "dst_ip")):
        c = asset_class(v)
        if c:
            out[str(v)] = c
    return out


def controllers(alert):
    return [name for name, c in assets(alert).items() if c == CONTROLLER]


def protocol(alert):
    """The industrial protocol the alert is about, if any."""
    ind = _get(alert, "indicators") or {}
    if ind.get("protocol"):
        return str(ind["protocol"])
    port = str(ind.get("dstport") or "")
    if port in OT_PORTS:
        return OT_PORTS[port]
    text = " ".join(str(x) for x in (_get(alert, "title"), _get(alert, "description"), ind.get("service")) if x).lower()
    m = _PROTOCOL_RE.search(text)
    return m.group(0) if m else None


def ics_technique(alert):
    ind = _get(alert, "indicators") or {}
    text = " ".join(str(x) for x in (ind.get("technique"), ind.get("mitre_ids")) if x).lower()
    m = _ICS_TECHNIQUE_RE.search(text)
    return m.group(0).upper() if m else None


def involved(alert):
    """Is this alert about operational technology at all?"""
    return bool(assets(alert) or protocol(alert) or ics_technique(alert))


def signals(alert):
    """Signals that force an alert to a person. Empty unless the alert is
    about OT."""
    if not involved(alert):
        return []
    out = []
    tech = ics_technique(alert)
    if tech:
        out.append(f"ICS technique {tech}")
    text = " ".join(str(x) for x in (_get(alert, "title"), _get(alert, "description")) if x).lower()
    out += [f"OT: {t}" for t, rx in _TERM_RE if rx.search(text)]
    return out


RECOMMENDED = [
    "Call the control room before anything is changed.",
    "Do not isolate, restart or reload the controller or the operator station.",
    "Contain on the IT side of the boundary, and keep the OT monitor's capture as evidence.",
]
