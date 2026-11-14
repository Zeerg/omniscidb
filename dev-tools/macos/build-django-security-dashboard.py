#!/usr/bin/env python3
"""Create a new native dashboard. Never replace an existing saved dashboard."""

import base64
from copy import deepcopy
import json
from pathlib import Path

from vulnerability_db import HeavyDB


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "build-macos/django-security"
TYPES = {0: "SMALLINT", 1: "INT", 2: "BIGINT", 6: "STR"}


def main():
    manifest = json.loads((DATA / "manifest.json").read_text())
    output = DATA / "dashboard.json"
    if output.exists():
        print("Dashboard already recorded; refusing to replace saved edits:", output.read_text())
        return
    template = json.loads((ROOT / "build-macos/vulnerability-data/immerse-template.json").read_text())
    seed_tab = next(iter(template["tabs"].values()))
    seed_chart = next(chart for chart in seed_tab["charts"].values() if chart["type"] == "number")
    title = f"Django Security Atlas | {manifest['snapshot']['release_name']}"
    notes = ("<p><strong>Static source review, not confirmed vulnerabilities.</strong> "
             "Sensitive operations, inputs, and protective controls are review signals. No taint flow or runtime path is proven. "
             "Snapshot KPIs cover all source; category filters apply to review signals. "
             '<a href="/heavyai/security-code">Open the source investigation view</a>.</p>')
    specs = [("text", "signals", notes, [], (0, 0, 30, 3))]
    specs += [("number", table, label, [], (i * 7, 3, 7, 4)) for i, (table, label) in enumerate([
        ("files", "Python source files"), ("nodes", "Named syntax nodes"),
        ("symbols", "Defined scopes"), ("signals", "Review signals, not findings")])]
    specs += [
        ("row", "signals", "Security review surfaces", ["category"], (0, 7, 10, 11)),
        ("pie", "signals", "Evidence roles", ["signal_role"], (10, 7, 10, 11)),
        ("row", "signals", "Packages with review signals", ["package_name"], (20, 7, 10, 11)),
        ("table", "signals", "Source evidence | open the investigation view for code", ["category", "signal_role", "source_path", "qualified_name", "start_line"], (0, 18, 30, 12))]
    with HeavyDB() as db:
        if any(item["1"] == title for item in db.call("get_dashboards", db.session)):
            raise RuntimeError("A dashboard with this title exists. Refusing to replace it.")
        tab = deepcopy(seed_tab)
        tab_id = "django-security-atlas"
        tab.update(tabId=tab_id, index=0, defaultTabIndex=0, charts={})
        dashboard = tab["dashboard"]
        dashboard.update(id=None, title=title, titleFormatted="", chartContainers=[], layout=[],
                         dataSources={}, currentDataSource=None, table=None, filtersId=[],
                         parameterContainers=[], streaming={"interval": 0, "request": False, "last_request": 0})
        checks = []
        for index, (kind, short, label, dimensions, box) in enumerate(specs, 1):
            table = "django_sec_" + short
            descriptor = db.call("get_table_details", db.session, table)["1"]
            metadata = {column["1"]: dict(table=table, type=TYPES[column["2"]["1"]],
                        precision=0, is_array=False, is_dict=column["2"].get("4") == 4,
                        is_join=False, name_is_ambiguous=False, label=column["1"], value=column["1"])
                        for column in descriptor}

            def selector(field, aggregate=None):
                result = dict(isRequired=True, isError=False, inactive=False, loading=False,
                    name="val" if aggregate else None, custom=False, axisLabel=None, minMax=None,
                    categories=None, colorType="quantitative", originIndex=0,
                    type="BIGINT", is_dict=False, is_array=False)
                result.update(metadata.get(field, {}))
                result.update(value=field, label="Review signals" if field == "*" else field, aggType=aggregate)
                return result

            chart = deepcopy(seed_chart)
            chart.update(type=kind, title=label, dataSource=table,
                         dimensions=[selector(field) for field in dimensions], measures=[selector("*", "Count")],
                         filters=[], rangeFilter=[], loading=False, hasError=False, dataError=None,
                         dcFlag=1000000 + index, dataSelections=[], selectedLayerId=None,
                         cap=20, showOther=False, showNullDimensions=False, autoSize=True, sortColumn=None)
            if kind == "text":
                chart.update(isNotDc=True, text=label, title="", color={"type": "none"}, measures=[])
            else:
                dashboard["dataSources"].setdefault(table, {"alias": chr(65 + len(dashboard["dataSources"])), "columnMetadata": list(metadata.values())})
            if kind in {"row", "pie"}:
                chart["color"] = {"type": "ordinal", "key": "mapD", "val": ["#7fa7cf", "#77b8a1", "#cfaa75", "#bb96cb", "#8799ac"]}
                chart["sortColumn"] = {"col": {"name": "val", "value": "*", "aggType": "Count"}, "index": len(dimensions), "order": "desc"}
            if kind == "number":
                checks.append(dict(chart_id=str(index), title=label, value=manifest["counts"][short]))
            if kind == "table":
                chart.update(cap=100, zebraStriping=True, showNullMeasures=True)
            tab["charts"][str(index)] = chart
            dashboard["chartContainers"].append({"id": str(index)})
            x, y, width, height = box
            dashboard["layout"].append(dict(i=str(index), x=x, y=y, w=width, h=height, minW=3, minH=2, moved=False, static=False))
        dashboard["currentDataSource"] = "django_sec_signals"
        state = deepcopy(template)
        state["tabs"] = {tab_id: tab}
        encoded = base64.b64encode(json.dumps(state, separators=(",", ":")).encode()).decode()
        identifier = db.call("create_dashboard", db.session, title, encoded, "", json.dumps({"table": ", ".join(dashboard["dataSources"]), "version": "v3"}))
    result = dict(id=identifier, title=title, kpi_checks=checks, chart_count=len(specs),
                  url=f"http://127.0.0.1:6273/heavyai/dashboard/{identifier}?tab={tab_id}",
                  investigation_url="http://127.0.0.1:6273/heavyai/security-code")
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
