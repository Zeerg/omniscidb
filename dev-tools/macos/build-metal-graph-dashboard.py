#!/usr/bin/env python3
"""Create a native dashboard from verified live Metal graph timings."""

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
import html
import json
import math
from pathlib import Path
import re
import statistics
import time

from vulnerability_db import HeavyDB


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "build-macos/metal-graph-performance"
TABLE = "metal_graph_benchmark_summary"
TITLE = "Metal Graph Performance | Django"
TAB = "metal-graph-performance"
RUNS = 9
TYPES = {1: "INT", 2: "BIGINT", 5: "DOUBLE", 6: "STR"}
SCHEMA = [
    ("source_count", "INT"), ("metric", "TEXT ENCODING DICT(32)"),
    ("median_ms", "DOUBLE"), ("minimum_ms", "DOUBLE"), ("maximum_ms", "DOUBLE"),
    ("sample_count", "INT"), ("node_count", "BIGINT"), ("edge_count", "BIGINT"),
    ("sink_count", "INT"), ("max_hops", "INT"), ("pair_count", "INT"),
    ("output_rows", "INT"), ("device", "TEXT ENCODING DICT(32)"),
    ("measured_utc", "TEXT ENCODING DICT(32)"),
]


def measure(db):
    sources = [row[0] for row in db.sql(
        "SELECT node_id FROM django_sec_value_nodes WHERE source_kind IS NOT NULL ORDER BY node_id")]
    chosen = db.sql("SELECT source_node FROM django_sec_graph_paths WHERE sink_node IS NOT NULL "
                    "GROUP BY source_node ORDER BY MAX(path_hops) DESC,source_node LIMIT 1")[0][0]
    assert chosen in sources and len(sources) >= 32
    ordered = [chosen] + [source for source in sources if source != chosen]
    node_count = db.sql("SELECT COUNT(*) FROM django_sec_value_nodes")[0][0]
    edge_count = db.sql("SELECT COUNT(*) FROM django_sec_value_edges")[0][0]
    sink_count = db.sql("SELECT COUNT(*) FROM django_sec_value_nodes WHERE sink_signal_id IS NOT NULL")[0][0]
    report = dict(measured_utc=datetime.now(timezone.utc).isoformat(), warm_runs=RUNS,
                  commit_sha=db.sql("SELECT commit_sha FROM django_sec_snapshot")[0][0],
                  node_count=node_count, edge_count=edge_count, sink_count=sink_count,
                  max_hops=64, cases=[])
    summaries = []
    log = ROOT / "build-macos/heavydb-console.log"
    for size in (1, 32, len(sources)):
        ids = ",".join(map(str, ordered[:size]))
        sql = ("SELECT * FROM TABLE(tf_metal_graph_paths("
               "CURSOR(SELECT edge_from,edge_to FROM django_sec_value_edges),"
               f"CURSOR(SELECT node_id FROM django_sec_value_nodes WHERE node_id IN ({ids})),"
               "CURSOR(SELECT node_id FROM django_sec_value_nodes WHERE sink_signal_id IS NOT NULL),64))")
        offset = log.stat().st_size
        db.sql(sql)
        samples = []
        for run in range(1, RUNS + 1):
            start = time.perf_counter()
            rows = db.sql(sql)
            samples.append(dict(run=run, sql_ms=(time.perf_counter() - start) * 1000))
        with log.open("rb") as stream:
            stream.seek(offset)
            records = [line for line in stream.read().decode("utf-8", errors="replace").splitlines()
                       if "Metal graph executed:" in line]
        assert len(records) == RUNS + 1, "Unexpected concurrent graph executions; refusing to mix measurements"
        metrics = [dict(re.findall(r"(sources|sinks|max_hops|rows|gpu_ms)=([^ ]+)", line)) for line in records]
        assert all(int(row["sources"]) == size and int(row["sinks"]) == sink_count for row in metrics)
        assert all(int(row["max_hops"]) == 64 and int(row["rows"]) == len(rows) for row in metrics)
        device = records[-1].split("device=", 1)[1]
        for sample, metric in zip(samples, metrics[1:]):
            sample["gpu_ms"] = float(metric["gpu_ms"])
            assert 0 <= sample["gpu_ms"] <= sample["sql_ms"]
        pairs = len({(row[0], row[1]) for row in rows if row[1] is not None})
        report["cases"].append(dict(source_count=size, source_ids=ordered[:size], sql=sql,
                                    pair_count=pairs, output_rows=len(rows), samples=samples,
                                    metal_execution_count=len(records)))
        for label, field in (("GPU command", "gpu_ms"), ("SQL round trip", "sql_ms")):
            values = [sample[field] for sample in samples]
            summaries.append(dict(source_count=size, metric=label, median_ms=statistics.median(values),
                minimum_ms=min(values), maximum_ms=max(values), sample_count=RUNS,
                node_count=node_count, edge_count=edge_count, sink_count=sink_count, max_hops=64,
                pair_count=pairs, output_rows=len(rows), device=device, measured_utc=report["measured_utc"]))
        print(f"Measured {size} sources: {pairs} pairs, {RUNS} live Metal runs", flush=True)
    report.update(device=device, summaries=summaries,
                  method="One warmup and nine timed SQL runs per workload. Nested source subsets. "
                         "Loopback HTTP JSON round trips. Fresh Metal execution logs verify every call.")
    return report


def verify():
    report = json.loads((DATA / "measurements.json").read_text())
    manifest = json.loads((DATA / "dashboard.json").read_text())
    baseline = json.loads((DATA / "dashboards-before.json").read_text())
    with HeavyDB() as db:
        for identifier, expected in baseline.items():
            assert db.call("get_dashboard", db.session, int(identifier)) == expected, identifier
        expected = [[row[key] for key, unused in SCHEMA] for row in report["summaries"]]
        actual = db.sql(f"SELECT * FROM {TABLE} ORDER BY source_count,metric")
        assert len(actual) == len(expected)
        for stored, measured in zip(actual, expected):
            assert all(math.isclose(value, target, rel_tol=1e-12, abs_tol=1e-8)
                       if isinstance(target, float) else value == target
                       for value, target in zip(stored, measured))
        for case in report["cases"]:
            assert len(case["samples"]) == RUNS and case["metal_execution_count"] == RUNS + 1
            for metric, field in (("GPU command", "gpu_ms"), ("SQL round trip", "sql_ms")):
                summary = next(row for row in report["summaries"]
                               if row["source_count"] == case["source_count"] and row["metric"] == metric)
                values = [sample[field] for sample in case["samples"]]
                assert (summary["minimum_ms"], summary["median_ms"], summary["maximum_ms"]) == (
                    min(values), statistics.median(values), max(values))
        assert db.call("get_dashboard", db.session, manifest["id"])["1"] == TITLE
    print("PASS: stored timing rows match measured samples; all prior saved dashboards remain unchanged")


def build():
    DATA.mkdir(parents=True, exist_ok=True)
    if (DATA / "dashboard.json").exists():
        print("Dashboard already exists. Refusing to replace saved edits.")
        print((DATA / "dashboard.json").read_text())
        return
    with HeavyDB() as db:
        dashboards = db.call("get_dashboards", db.session)
        if any(row["1"] == TITLE for row in dashboards) or TABLE in db.call("get_tables", db.session):
            raise RuntimeError("Benchmark data or dashboard already exists; refusing to replace it")
        baseline = {str(row["6"]): db.call("get_dashboard", db.session, row["6"]) for row in dashboards}
        (DATA / "dashboards-before.json").write_text(json.dumps(baseline, indent=2) + "\n")
        report = measure(db)
        (DATA / "measurements.json").write_text(json.dumps(report, indent=2) + "\n")
        db.sql(f"CREATE TABLE {TABLE} ({','.join(name + ' ' + kind for name, kind in SCHEMA)})")
        values = []
        for row in report["summaries"]:
            values.append("(" + ",".join("'" + row[key].replace("'", "''") + "'" if isinstance(row[key], str)
                                        else repr(row[key]) for key, unused in SCHEMA) + ")")
        db.sql(f"INSERT INTO {TABLE} VALUES " + ",".join(values))
        template = json.loads((ROOT / "build-macos/vulnerability-data/immerse-template.json").read_text())
        tab = deepcopy(next(iter(template["tabs"].values())))
        seed = deepcopy(next(chart for chart in tab["charts"].values() if chart["type"] == "number"))
        tab.update(tabId=TAB, index=0, defaultTabIndex=0, charts={})
        dashboard = tab["dashboard"]
        descriptor = db.call("get_table_details", db.session, TABLE)["1"]
        columns = {column["1"]: dict(table=TABLE, type=TYPES[column["2"]["1"]], precision=0,
                    is_array=False, is_dict=column["2"].get("4") == 4, is_join=False,
                    name_is_ambiguous=False, label=column["1"], value=column["1"]) for column in descriptor}
        dashboard.update(id=None, title=TITLE, titleFormatted="", chartContainers=[], layout=[],
            dataSources={TABLE: {"alias": "A", "columnMetadata": list(columns.values())}},
            currentDataSource=TABLE, table=None, filtersId=[], parameterContainers=[],
            streaming={"interval": 0, "request": False, "last_request": 0})

        def selector(field, label, aggregate=None, name=None):
            result = dict(isRequired=True, isError=False, inactive=False, loading=False, name=name,
                custom=False, axisLabel=label, minMax=None, categories=None, colorType="quantitative",
                originIndex=0, **columns[field])
            result.update(label=label, aggType=aggregate)
            return result

        notes = (f"<p><strong>Measured native Metal graph traversal on {html.escape(report['device'])}.</strong> "
                 f"{report['node_count']:,} value nodes, {report['edge_count']:,} directed edges, and a 64-hop search limit. "
                 f"Measured {html.escape(report['measured_utc'])}. "
                 '<a href="/heavyai/security-code">Inspect the source-to-sink mappings</a>.</p>')
        method = ("<p>Nine warm runs per workload, after one warmup. Every call executed Metal. "
                  "SQL round trip includes planning, ID preparation, GPU work, witness formatting, and loopback HTTP JSON transport. "
                  "Source subsets are nested. Lines connect measured workloads, not predicted scaling. "
                  "These are saved measurements. Dashboard refresh does not rerun the benchmark. "
                  "No optimized-CPU speedup or million-edge performance claim.</p>")
        specs = [("text", notes, [], [], (0, 0, 30, 3))]
        for index, (field, label) in enumerate((("source_count", "Sources tested"), ("sink_count", "Selected sinks"),
                                                ("pair_count", "Reachable source/sink pairs"), ("sample_count", "Warm runs per workload"))):
            specs.append(("number", label, [], [selector(field, label, "Max", "val")], (index * 7, 3, 7, 4)))
        x = selector("source_count", "Source count")
        x.update(isBinned=False, extract=False, autobin=False, timeBin=None, numOfBins=3,
                 currentLowValue=1, currentHighValue=max(row["source_count"] for row in report["summaries"]),
                 minMax=[1, max(row["source_count"] for row in report["summaries"])])
        specs += [
            ("line", "Live traversal latency | median milliseconds", [x, selector("metric", "Timing boundary")],
             [selector("median_ms", "Median latency (ms)", "Max", "series_1")], (0, 7, 30, 12)),
            ("table", "Measured latency ranges | milliseconds", [selector("source_count", "Sources"), selector("metric", "Timing boundary")],
             [selector("median_ms", "Median (ms)", "Max", "val"), selector("minimum_ms", "Minimum (ms)", "Min", "color"),
              selector("maximum_ms", "Maximum (ms)", "Max", "measure_2")], (0, 19, 30, 10)),
            ("text", method, [], [], (0, 29, 30, 4)),
        ]
        checks = []
        for index, (kind, label, dimensions, measures, box) in enumerate(specs, 1):
            chart = deepcopy(seed)
            chart.update(type=kind, title=label, dataSource=TABLE, dimensions=dimensions, measures=measures,
                filters=[], rangeFilter=[], loading=False, hasError=False, dataError=None,
                dcFlag=2000000 + index, dataSelections=[], selectedLayerId=None, autoSize=True,
                cap=100, showOther=False, showNullDimensions=False, sortColumn=None)
            if kind == "text":
                chart.update(isNotDc=True, text=label, title="", color={"type": "none"})
            if kind == "line":
                chart["color"] = dict(type="custom", key="custom", val=["#7fa7cf", "#cfaa75"],
                    customDomain=["GPU command", "SQL round trip"], customRange=["#7fa7cf", "#cfaa75"],
                    customKey="Timing boundary", defaultOtherRange="#929ba4", defaultOtherDomain="Other")
            if kind == "table":
                chart.update(zebraStriping=True, showNullMeasures=True)
            if kind == "number":
                checks.append(dict(chart_id=str(index), title=label,
                                   value=max(row[measures[0]["value"]] for row in report["summaries"])))
            identifier = str(index)
            tab["charts"][identifier] = chart
            dashboard["chartContainers"].append({"id": identifier})
            x, y, width, height = box
            dashboard["layout"].append(dict(i=identifier, x=x, y=y, w=width, h=height,
                                             minW=3, minH=2, moved=False, static=False))
        template["tabs"] = {TAB: tab}
        encoded = base64.b64encode(json.dumps(template, separators=(",", ":")).encode()).decode()
        identifier = db.call("create_dashboard", db.session, TITLE, encoded, "", json.dumps({"table": TABLE, "version": "v3"}))
        manifest = dict(id=identifier, title=TITLE, kpi_checks=checks, chart_count=len(specs),
                        url=f"http://127.0.0.1:6273/heavyai/dashboard/{identifier}?tab={TAB}",
                        measured_utc=report["measured_utc"], table=TABLE)
        (DATA / "dashboard.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps(manifest, indent=2))
    verify()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "verify"), default="build", nargs="?")
    {"build": build, "verify": verify}[parser.parse_args().action]()
