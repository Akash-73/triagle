"""The Triagle dashboard for the Wazuh dashboard (scripts/wazuh/triagle_dashboard.ndjson).

    python -m pytest -q tests/test_wazuh_dashboard.py

It cannot be imported into a real Wazuh from here, so these tests pin what can
be checked without one: the file is what the generator produces; every line
is a saved object in the shape OpenSearch Dashboards imports; every chart and
table reads only fields that exist (Wazuh's own, or ones the forwarder
writes); every reference points at something in the file; and the saved-object
versions are ones OpenSearch Dashboards 2.19 (which Wazuh 4.14 is built on)
accepts.
"""
import importlib.util
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(__file__))
FILE = os.path.join(ROOT, "scripts", "wazuh", "triagle_dashboard.ndjson")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


make = _load("make_dashboard", os.path.join(ROOT, "scripts", "wazuh", "make_dashboard.py"))
fw = _load("wazuh_forwarder_dash", os.path.join(ROOT, "scripts", "wazuh_forwarder.py"))

LINES = [json.loads(x) for x in open(FILE, encoding="utf-8").read().splitlines()]
OBJECTS = [o for o in LINES if "type" in o]

# what a chart may read: Wazuh's own fields, and what the forwarder writes under data.triagle
VERDICT_FIELDS = set(json.loads(fw.verdict_lines(
    [{"raw": {"id": "1", "rule": {"id": "1", "level": 3, "description": "x"}, "agent": {"name": "a"}}}],
    [{"id": "1", "verdict": "closed"}])[0])["triagle"])
KNOWN = {"timestamp", "rule.description", "rule.groups", "rule.level", "agent.name"} \
    | {"data.triagle." + f for f in VERDICT_FIELDS | set(fw.EVENT_FIELDS)}
# the newest saved-object version each type has in OpenSearch Dashboards 2.19
LATEST = {"visualization": "7.10.0", "search": "7.9.3", "dashboard": "7.9.3"}
SCHEMAS = {"metric": {"metric", "group"}, "pie": {"metric", "segment", "split"},
           "histogram": {"metric", "radius", "segment", "group", "split"}, "table": {"metric", "bucket", "split"}}


def test_the_file_is_what_the_generator_produces():
    assert open(FILE, encoding="utf-8").read() == make.ndjson(), "run scripts/wazuh/make_dashboard.py and commit the result"


def test_every_line_is_a_saved_object_the_importer_accepts():
    assert LINES[-1] == {"exportedCount": len(OBJECTS), "missingRefCount": 0, "missingReferences": []}
    assert len({(o["type"], o["id"]) for o in OBJECTS}) == len(OBJECTS)
    for o in OBJECTS:
        assert set(o) == {"attributes", "id", "migrationVersion", "references", "type", "updated_at"}
        assert o["type"] in LATEST and o["migrationVersion"] == {o["type"]: LATEST[o["type"]]}
        assert re.fullmatch(r"triagle-[a-z-]+", o["id"]), "fixed ids, so importing again replaces the earlier copy"
        assert o["attributes"]["title"] and isinstance(o["references"], list)
        for ref in o["references"]:
            assert set(ref) == {"name", "type", "id"}


def test_every_reference_points_at_the_wazuh_index_pattern_or_at_something_in_the_file():
    ids = {(o["type"], o["id"]) for o in OBJECTS}
    for o in OBJECTS:
        for ref in o["references"]:
            assert (ref["type"], ref["id"]) in ids or (ref["type"], ref["id"]) == ("index-pattern", "wazuh-alerts-*")
        if o["type"] in ("visualization", "search"):
            source = json.loads(o["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            assert source["indexRefName"] in {r["name"] for r in o["references"]} and "index" not in source
            assert source["query"]["language"] == "kuery" and "rule.groups:triagle" in source["query"]["query"]


def _fields_in_query(q):
    return set(re.findall(r"([a-z_]+(?:\.[a-z_]+)+):", q))


def test_charts_and_tables_read_only_fields_that_exist():
    for o in OBJECTS:
        a = o["attributes"]
        if o["type"] == "visualization":
            state = json.loads(a["visState"])
            assert state["title"] == a["title"] and state["type"] in SCHEMAS
            assert [g["id"] for g in state["aggs"]] == [str(i + 1) for i in range(len(state["aggs"]))]
            for agg in state["aggs"]:
                assert agg["schema"] in SCHEMAS[state["type"]], (a["title"], agg["schema"])
                if agg["type"] != "count":
                    assert agg["params"]["field"] in KNOWN, agg["params"]["field"]
        if o["type"] == "search":
            assert set(a["columns"]) <= KNOWN and a["sort"] == [["timestamp", "desc"]]
        if o["type"] in ("visualization", "search"):
            q = json.loads(a["kibanaSavedObjectMeta"]["searchSourceJSON"])["query"]["query"]
            assert _fields_in_query(q) <= KNOWN, q


def test_the_dashboard_lays_out_every_panel_inside_the_grid_without_overlap():
    (dash,) = [o for o in OBJECTS if o["type"] == "dashboard"]
    panels = json.loads(dash["attributes"]["panelsJSON"])
    assert [p["panelRefName"] for p in panels] == [r["name"] for r in dash["references"]]
    taken = set()
    for p in panels:
        g = p["gridData"]
        assert p["panelIndex"] == g["i"] and isinstance(g["i"], str) and p["embeddableConfig"] == {}
        assert g["x"] >= 0 and g["x"] + g["w"] <= 48 and g["w"] >= 10 and g["h"] >= 8
        cells = {(x, y) for x in range(g["x"], g["x"] + g["w"]) for y in range(g["y"], g["y"] + g["h"])}
        assert not cells & taken, "panels overlap"
        taken |= cells
    assert dash["attributes"]["timeRestore"] and dash["attributes"]["timeFrom"] == "now-24h"
    assert dash["attributes"]["refreshInterval"] == {"pause": False, "value": 30000}


def test_the_groups_the_dashboard_filters_on_are_the_ones_the_rules_set():
    import xml.etree.ElementTree as ET
    rules = ET.parse(os.path.join(ROOT, "scripts", "wazuh", "triagle_rules.xml")).getroot()
    groups = {g for r in rules.findall("rule") for g in (r.findtext("group") or "").split(",") if g} | {"triagle"}
    used = set()
    for o in OBJECTS:
        if o["type"] in ("visualization", "search"):
            q = json.loads(o["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])["query"]["query"]
            used |= set(re.findall(r"rule\.groups:([a-z_]+)", q))
    assert used and used <= groups, used - groups
