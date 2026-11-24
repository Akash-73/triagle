#!/usr/bin/env python3
"""
Builds triagle_dashboard.ndjson: a "Triagle" dashboard for the Wazuh dashboard.

    python3 scripts/wazuh/make_dashboard.py            # rewrites the .ndjson beside this file

Import it in the Wazuh dashboard: menu, Dashboards Management, Saved objects,
Import. It reads the entries triagle_rules.xml produces (rule.groups: triagle)
from the alerts index Wazuh already has, and shows:

  - how many alerts Triagle closed and how many it sent to a person
  - why it closed them
  - both over time
  - what Wazuh rated high or critical (level 12 and up) that Triagle closed
  - what it sent to a person, with the reason
  - what people then did: blocked an address, lifted a block, closed the alert

The file is plain saved objects in the format OpenSearch Dashboards 2.x
exports (the Wazuh dashboard 4.x is built on it), so it can be read, changed
and re-imported. Every object has a fixed id, so importing again replaces the
earlier copy instead of adding a second one.
"""
import json
import os

INDEX_PATTERN = "wazuh-alerts-*"          # the id the Wazuh dashboard gives its alerts index pattern
INDEX_REF = "kibanaSavedObjectMeta.searchSourceJSON.index"
UPDATED = "2026-11-24T00:00:00.000Z"
PANEL_VERSION = "2.19.0"

HIGH_LEVELS = ("12", "13", "14", "15")    # what the Wazuh dashboard calls high and critical


def _source(query):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [], "indexRefName": INDEX_REF},
                      separators=(",", ":"))


def _index_ref():
    return [{"name": INDEX_REF, "type": "index-pattern", "id": INDEX_PATTERN}]


def _count(label):
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": label}}


def _terms(agg_id, schema, field, label, size=10):
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size, "otherBucket": False,
                       "otherBucketLabel": "Other", "missingBucket": False, "missingBucketLabel": "Missing",
                       "customLabel": label}}


def visualization(vis_id, title, description, query, vis_type, params, aggs):
    state = {"title": title, "type": vis_type, "aggs": aggs, "params": params}
    return {
        "attributes": {
            "title": title, "description": description, "uiStateJSON": "{}", "version": 1,
            "visState": json.dumps(state, separators=(",", ":")),
            "kibanaSavedObjectMeta": {"searchSourceJSON": _source(query)},
        },
        "id": vis_id, "migrationVersion": {"visualization": "7.10.0"}, "references": _index_ref(),
        "type": "visualization", "updated_at": UPDATED,
    }


def saved_search(search_id, title, description, query, columns):
    source = json.loads(_source(query))
    source.update({"highlightAll": True, "version": True})
    return {
        "attributes": {
            "title": title, "description": description, "hits": 0, "columns": columns,
            "sort": [["timestamp", "desc"]], "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(source, separators=(",", ":"))},
        },
        "id": search_id, "migrationVersion": {"search": "7.9.3"}, "references": _index_ref(),
        "type": "search", "updated_at": UPDATED,
    }


def objects():
    verdicts = visualization(
        "triagle-vis-verdicts", "Triagle: decided",
        "Alerts Triagle closed with a reason, and alerts it sent to a person.",
        "rule.groups:triagle_closed or rule.groups:triagle_escalated", "metric",
        {"addTooltip": True, "addLegend": False, "type": "metric",
         "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                    "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}], "labels": {"show": True},
                    "invertColors": False,
                    "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 48}}},
        [_count("alerts"), _terms("2", "group", "data.triagle.verdict", "Verdict", 5)])

    why = visualization(
        "triagle-vis-closed-why", "Triagle: why it closed them",
        "The reason Triagle gave for each alert it closed.",
        "rule.groups:triagle_closed", "pie",
        {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True,
         "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
        [_count("alerts"), _terms("2", "segment", "data.triagle.closure", "Reason", 8)])

    over_time = visualization(
        "triagle-vis-over-time", "Triagle: closed and sent to a person, over time",
        "Verdicts as the alerts arrived.",
        "rule.groups:triagle_closed or rule.groups:triagle_escalated", "histogram",
        {"type": "histogram", "grid": {"categoryLines": False},
         "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {},
                           "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100},
                           "title": {}}],
         "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
                        "style": {}, "scale": {"type": "linear", "mode": "normal"},
                        "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                        "title": {"text": "Alerts"}}],
         "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Alerts", "id": "1"},
                           "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2,
                           "showCircles": True}],
         "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [], "addTimeMarker": False,
         "labels": {"show": False},
         "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}},
        [_count("Alerts"),
         {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
          "params": {"field": "timestamp", "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                     "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {},
                     "customLabel": "Time"}},
         _terms("3", "group", "data.triagle.verdict", "Verdict", 5)])

    levels = " or ".join(f'"{x}"' for x in HIGH_LEVELS)
    overrated = visualization(
        "triagle-vis-overrated", "Rated high or critical by Wazuh, closed by Triagle",
        "Alerts at Wazuh level 12 and up that Triagle closed, with what each one was.",
        f"rule.groups:triagle_closed and data.triagle.wazuh_rule_level:({levels})", "table",
        {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False,
         "totalFunc": "sum", "percentageCol": ""},
        [_count("Alerts"),
         _terms("2", "bucket", "data.triagle.use_case", "What it was", 20),
         _terms("3", "bucket", "data.triagle.agent", "Machine", 20),
         _terms("4", "bucket", "data.triagle.wazuh_rule_level", "Wazuh level", 5)])

    escalated = saved_search(
        "triagle-search-escalated", "Triagle: sent to a person",
        "Alerts Triagle did not close, and why.",
        "rule.groups:triagle_escalated",
        ["rule.description", "data.triagle.reason", "data.triagle.wazuh_rule_level", "data.triagle.url"])

    response = saved_search(
        "triagle-search-response", "Triagle: what people did",
        "Blocks, lifted blocks, approved and declined actions, alerts closed by an analyst and reports filed.",
        "rule.groups:triagle_response",
        ["rule.description", "data.triagle.note", "data.triagle.url"])

    everything = saved_search(
        "triagle-search-verdicts", "Triagle: every verdict",
        "One line per alert: what Triagle decided, on which machine, the level Wazuh gave it, and the reason.",
        "rule.groups:triagle_closed or rule.groups:triagle_escalated",
        ["rule.description", "data.triagle.agent", "data.triagle.wazuh_rule_level", "data.triagle.reason"])

    layout = [                                           # the grid is 48 wide
        (verdicts, 0, 0, 12, 9), (why, 12, 0, 14, 9), (over_time, 26, 0, 22, 9),
        (overrated, 0, 9, 24, 14), (escalated, 24, 9, 24, 14),
        (response, 0, 23, 48, 12),
    ]
    panels, refs = [], []
    for i, (obj, x, y, w, h) in enumerate(layout):
        panels.append({"version": PANEL_VERSION, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
                       "panelIndex": str(i + 1), "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": obj["type"], "id": obj["id"]})
    dashboard = {
        "attributes": {
            "title": "Triagle",
            "description": "What Triagle decided about the alerts in this Wazuh, and what people did next.",
            "hits": 0, "version": 1,
            "panelsJSON": json.dumps(panels, separators=(",", ":")),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}, separators=(",", ":")),
            "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 30000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"language": "kuery", "query": ""}, "filter": []}, separators=(",", ":"))},
        },
        "id": "triagle-dashboard", "migrationVersion": {"dashboard": "7.9.3"}, "references": refs,
        "type": "dashboard", "updated_at": UPDATED,
    }
    return [verdicts, why, over_time, overrated, escalated, response, everything, dashboard]


def ndjson():
    objs = objects()
    lines = [json.dumps(o, separators=(",", ":"), sort_keys=True) for o in objs]
    lines.append(json.dumps({"exportedCount": len(objs), "missingRefCount": 0, "missingReferences": []},
                            separators=(",", ":")))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "triagle_dashboard.ndjson")
    with open(out, "w", encoding="utf-8") as f:
        f.write(ndjson())
    print(f"wrote {out}")
