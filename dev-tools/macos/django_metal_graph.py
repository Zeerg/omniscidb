#!/usr/bin/env python3
"""Build graph facts. Compute source/sink mappings only through HeavyDB Metal SQL."""

import argparse
import ast
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import io
import itertools
import json
from pathlib import Path
import subprocess

from django_security import COMMIT, CSV_OPTIONS, DATA, NULL, RAW, SCHEMAS, SOURCE, TEXT
from vulnerability_db import HeavyDB


MODEL = "metal-value-graph-v1"
MAX_HOPS = 64
LIMITS = (
    "HeavyDB Metal computes bounded reachability over modeled value edges, not syntax containment. "
    "The initial graph covers function scopes with modeled sinks. Def-use edges are local to each function. "
    "Opaque call returns propagate value influence by assumption. Heap aliases and branch feasibility are not proven. "
    "The initial model skips propagation through comprehensions, generators, and lambdas. "
    "Caller parameters do not establish external attacker control. Controls are references, not proven guards. "
    "SQL text excludes bound parameter values. No runtime exposure or complete vulnerability coverage claim."
)
NODE_SCHEMA = [
    ("node_id", "BIGINT"), ("syntax_node_id", "BIGINT"), ("file_id", "INT"),
    ("symbol_id", "INT"), ("source_path", TEXT), ("package_name", TEXT),
    ("qualified_name", TEXT), ("start_line", "INT"), ("end_line", "INT"),
    ("node_kind", TEXT), ("evidence", RAW), ("source_kind", TEXT),
    ("sink_signal_id", "INT"), ("category", TEXT), ("sink_channel", TEXT),
]
EDGE_SCHEMA = [("edge_id", "INT"), ("edge_from", "BIGINT"), ("edge_to", "BIGINT"), ("edge_kind", TEXT)]
FLOW_SCHEMA = [
    ("flow_id", "INT"), ("file_id", "INT"), ("symbol_id", "INT"), ("sink_signal_id", "INT"),
    ("source_path", TEXT), ("package_name", TEXT), ("qualified_name", TEXT), ("source_kind", TEXT),
    ("source_line", "INT"), ("sink_line", "INT"), ("category", TEXT), ("sink_channel", TEXT),
    ("source_evidence", RAW), ("sink_evidence", RAW), ("trace_json", RAW), ("controls_json", RAW),
    ("rule_id", TEXT), ("sink_confidence", TEXT),
]
SNAPSHOT_SCHEMA = [
    ("commit_sha", TEXT), ("engine_version", TEXT), ("indexed_utc", TEXT), ("rules_sha256", TEXT),
    ("flow_count", "INT"), ("request_flow_count", "INT"), ("parameter_flow_count", "INT"),
    ("scanned_file_count", "INT"), ("unmapped_sink_count", "INT"), ("analysis_limits", RAW),
]


def read_rows(table, columns=None):
    with gzip.open(DATA / f"{table}.csv.gz", "rt", newline="") as stream:
        rows = list(csv.DictReader(stream, **CSV_OPTIONS))
    for row in rows:
        for key, kind in columns if columns is not None else SCHEMAS[table]:
            row[key] = None if row[key] == NULL else int(row[key]) if kind in {"INT", "BIGINT"} else row[key]
    return rows


def write_rows(name, columns, rows):
    with gzip.open(DATA / f"{name}.csv.gz", "wt", newline="") as stream:
        writer = csv.writer(stream, **CSV_OPTIONS)
        writer.writerow([key for key, unused in columns])
        writer.writerows([[NULL if row[key] is None else row[key] for key, unused in columns] for row in rows])


def binding_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = binding_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


class ValueGraph:
    """Extract lexical value edges, without propagating any source label to a sink."""

    def __init__(self, files, symbols, signals, spans):
        self.nodes, self.edges, self.unsupported = [], set(), Counter()
        self.files, self.symbols, self.signals, self.spans = files, symbols, signals, spans
        self.sink_scopes = {row["symbol_id"] for row in signals
                            if row["signal_role"] in {"boundary", "trust override"} and row["rule_id"] != "request-guard"}
        self.sink_calls = {row["node_id"]: row for row in signals
                           if row["symbol_id"] in self.sink_scopes and row["signal_role"] in {"boundary", "trust override"}
                           and row["rule_id"] != "request-guard"}
        self.inputs = {row["node_id"] for row in signals if row["signal_role"] == "input"}

    def node(self, value):
        if value in self.cache:
            return self.cache[value]
        start = self.offsets[value.lineno - 1] + value.col_offset
        end = self.offsets[value.end_lineno - 1] + value.end_col_offset
        syntax = self.file_spans.get((start, end), self.scope["node_id"])
        row = dict(node_id=len(self.nodes) + 1, syntax_node_id=syntax,
            file_id=self.file["file_id"], symbol_id=self.scope["symbol_id"], source_path=self.file["source_path"],
            package_name=self.file["package_name"], qualified_name=self.scope["qualified_name"],
            start_line=value.lineno, end_line=value.end_lineno, node_kind=type(value).__name__,
            evidence=(ast.get_source_segment(self.text, value) or "").replace("\n", " ")[:600],
            source_kind="HTTP request" if syntax in self.inputs else None,
            sink_signal_id=None, category=None, sink_channel=None)
        self.nodes.append(row)
        self.cache[value] = row["node_id"]
        return row["node_id"]

    def edge(self, source, target, kind="value"):
        if source and target and source != target:
            self.edges.add((source, target, kind))

    def assign(self, target, source, env):
        key = binding_name(target)
        if key:
            identifier = self.node(target)
            self.edge(source, identifier)
            env[key] = {identifier}
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.assign(item, source, env)
        else:
            self.unsupported["heap assignment"] += 1

    def expression(self, value, env):
        if value is None:
            return None
        identifier = self.node(value)
        key = binding_name(value)
        for previous in env.get(key, ()):
            self.edge(previous, identifier)
        if isinstance(value, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self.unsupported[type(value).__name__] += 1
            return identifier
        if isinstance(value, ast.NamedExpr):
            origin = self.expression(value.value, env)
            self.assign(value.target, origin, env)
            self.edge(origin, identifier)
        elif isinstance(value, ast.Call):
            arguments = [self.expression(item, env) for item in value.args]
            arguments += [self.expression(item.value, env) for item in value.keywords]
            if isinstance(value.func, ast.Attribute):
                arguments.append(self.expression(value.func.value, env))
            for argument in arguments:
                self.edge(argument, identifier, "assumed call return")
            signal = self.sink_calls.get(self.nodes[identifier - 1]["syntax_node_id"])
            if signal:
                focuses, channel = [], signal["category"]
                tail = value.func.attr if isinstance(value.func, ast.Attribute) else ""
                if signal["rule_id"] == "file-access" and tail in {"read_text", "write_text", "read_bytes", "write_bytes"}:
                    focuses, channel = [value.func.value], "Filesystem path"
                elif signal["rule_id"] == "sql-api" and tail == "extra":
                    focuses = [item.value for item in value.keywords if item.arg in {"select", "where", "tables", "order_by"}]
                    channel = "SQL text"
                else:
                    focuses = value.args[:1] or [item.value for item in value.keywords
                                                if item.arg in {"sql", "query", "raw_query", "file", "s", "to", "redirect_to", "source", "args"}]
                    channel = {"sql-api": "SQL text", "html-trust": "HTML trust override", "process": "Process command or argument",
                               "deserialize": "Serialized object input", "dynamic-code": "Python code input",
                               "file-access": "Filesystem path", "redirect": "Redirect target"}.get(signal["rule_id"], channel)
                for focus in focuses:
                    target = self.nodes[self.node(focus) - 1]
                    target.update(sink_signal_id=signal["signal_id"], category=signal["category"], sink_channel=channel)
        else:
            for child in ast.iter_child_nodes(value):
                if isinstance(child, ast.expr):
                    self.edge(self.expression(child, env), identifier)
        return identifier

    @staticmethod
    def merge(states):
        states = [state for state in states if state is not None]
        if not states:
            return None
        result = defaultdict(set)
        for state in states:
            for key, values in state.items():
                result[key].update(values)
        return dict(result)

    def block(self, body, env):
        for statement in body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                origin = self.expression(statement.value, env)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    self.assign(target, origin, env)
            elif isinstance(statement, ast.AugAssign):
                origin = self.expression(statement.value, env)
                target = self.node(statement.target)
                for previous in env.get(binding_name(statement.target), ()):
                    self.edge(previous, target)
                self.assign(statement.target, origin, env)
            elif isinstance(statement, ast.If):
                self.expression(statement.test, env)
                if isinstance(statement.test, ast.Constant) and isinstance(statement.test.value, bool):
                    env = self.block(statement.body if statement.test.value else statement.orelse, dict(env))
                else:
                    env = self.merge([self.block(statement.body, dict(env)), self.block(statement.orelse, dict(env))])
                if env is None:
                    return None
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                initial = dict(env)
                origin = self.expression(statement.test if isinstance(statement, ast.While) else statement.iter, env)
                if not isinstance(statement, ast.While):
                    self.assign(statement.target, origin, env)
                first = self.block(statement.body, dict(env))
                env = self.merge([initial, first])
                env = self.merge([env, self.block(statement.body, dict(env))])
                env = self.block(statement.orelse, env)
                if env is None:
                    return None
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    origin = self.expression(item.context_expr, env)
                    if item.optional_vars:
                        self.assign(item.optional_vars, origin, env)
                env = self.block(statement.body, env)
                if env is None:
                    return None
            elif isinstance(statement, (ast.Try, ast.TryStar)):
                initial = dict(env)
                normal = self.block(statement.body, dict(env))
                if normal is not None:
                    normal = self.block(statement.orelse, normal)
                env = self.merge([normal, *[self.block(handler.body, dict(initial)) for handler in statement.handlers]])
                if env is None:
                    return None
                env = self.block(statement.finalbody, env)
                if env is None:
                    return None
            elif isinstance(statement, (ast.Return, ast.Raise)):
                self.expression(statement.value if isinstance(statement, ast.Return) else statement.exc, env)
                return None
            elif isinstance(statement, ast.Expr):
                self.expression(statement.value, env)
            else:
                self.unsupported[type(statement).__name__] += 1
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.expr):
                        self.expression(child, env)
        return env

    def build(self):
        scopes = {(row["file_id"], row["start_line"]): row for row in self.symbols
                  if row["symbol_id"] in self.sink_scopes and row["symbol_kind"] in {"function", "async function"}}
        for file in self.files:
            if not any(key[0] == file["file_id"] for key in scopes):
                continue
            self.file, self.text = file, json.loads(file["source_json"])
            self.file_spans = self.spans.get(file["file_id"], {})
            self.offsets = [0]
            for line in self.text.encode().splitlines(keepends=True):
                self.offsets.append(self.offsets[-1] + len(line))
            for definition in ast.walk(ast.parse(self.text, filename=file["source_path"])):
                if not isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                self.scope = scopes.get((file["file_id"], definition.lineno))
                if not self.scope:
                    continue
                self.cache, env = {}, {}
                args = definition.args
                for parameter in [*args.posonlyargs, *args.args, *args.kwonlyargs,
                                  *[item for item in (args.vararg, args.kwarg) if item]]:
                    identifier = self.node(parameter)
                    env[parameter.arg] = {identifier}
                    if parameter.arg not in {"self", "cls"}:
                        self.nodes[identifier - 1]["source_kind"] = "Caller parameter"
                self.block(definition.body, env)
        return self


def facts():
    assert subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True).strip() == COMMIT
    assert not subprocess.check_output(["git", "-C", str(SOURCE), "status", "--porcelain", "--untracked-files=all"], text=True)
    files, symbols, signals = [read_rows(name) for name in ("files", "symbols", "signals")]
    spans = defaultdict(dict)
    selected_files = {row["file_id"] for row in signals if row["signal_role"] in {"boundary", "trust override"}}
    with gzip.open(DATA / "nodes.csv.gz", "rt", newline="") as stream:
        for row in csv.DictReader(stream, **CSV_OPTIONS):
            file_id = int(row["file_id"])
            if file_id in selected_files:
                spans[file_id][(int(row["start_byte"]), int(row["end_byte"]))] = int(row["node_id"])
    for row in files:
        assert hashlib.sha256((SOURCE / row["source_path"]).read_bytes()).hexdigest() == row["sha256"]
    graph = ValueGraph(files, symbols, signals, spans).build()
    edges = [dict(edge_id=index, edge_from=start, edge_to=end, edge_kind=kind)
             for index, (start, end, kind) in enumerate(sorted(graph.edges), 1)]
    write_rows("value_nodes", NODE_SCHEMA, graph.nodes)
    write_rows("value_edges", EDGE_SCHEMA, edges)
    manifest = dict(commit_sha=COMMIT, engine=MODEL, node_count=len(graph.nodes), edge_count=len(edges),
                    source_count=sum(bool(row["source_kind"]) for row in graph.nodes),
                    sink_count=sum(row["sink_signal_id"] is not None for row in graph.nodes),
                    unmapped_sink_count=len({row["signal_id"] for row in graph.sink_calls.values()} -
                                           {row["sink_signal_id"] for row in graph.nodes if row["sink_signal_id"] is not None}),
                    unsupported=dict(graph.unsupported), analysis_limits=LIMITS)
    (DATA / "metal-graph-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


def copy_table(db, table, schema):
    db.sql(f"CREATE TABLE django_sec_{table} ({', '.join(name + ' ' + kind for name, kind in schema)})")
    path = str((DATA / f"{table}.csv.gz").resolve()).replace("'", "''")
    db.sql(f"COPY django_sec_{table} FROM '{path}' WITH (header='true', nulls='{NULL}', "
           "quoted='false', delimiter='\x1f', quote='\x1e', escape='\x1d', trim_spaces='false', max_reject=0)")


def load():
    facts_manifest = json.loads((DATA / "metal-graph-manifest.json").read_text())
    with HeavyDB() as db:
        assert db.sql("SELECT commit_sha FROM django_sec_snapshot") == [[COMMIT]]
        existing = set(db.call("get_tables", db.session))
        if existing & {"django_sec_value_nodes", "django_sec_value_edges", "django_sec_graph_paths", "django_sec_flows", "django_sec_flow_snapshot"}:
            raise RuntimeError("Native graph tables already exist. Refusing to append or replace data.")
        copy_table(db, "value_nodes", NODE_SCHEMA)
        copy_table(db, "value_edges", EDGE_SCHEMA)
        db.sql("CREATE TABLE django_sec_graph_paths (source_node BIGINT,sink_node BIGINT,path_node BIGINT,path_step INT,path_hops INT,search_complete BOOLEAN)")
        sources = [row[0] for row in db.sql("SELECT node_id FROM django_sec_value_nodes WHERE source_kind IS NOT NULL ORDER BY node_id")]
        for offset in range(0, len(sources), 32):
            ids = ",".join(map(str, sources[offset:offset + 32]))
            db.sql(f"INSERT INTO django_sec_graph_paths SELECT * FROM TABLE(tf_metal_graph_paths("
                   "CURSOR(SELECT edge_from,edge_to FROM django_sec_value_edges),"
                   f"CURSOR(SELECT node_id FROM django_sec_value_nodes WHERE node_id IN ({ids})),"
                   f"CURSOR(SELECT node_id FROM django_sec_value_nodes WHERE sink_signal_id IS NOT NULL),{MAX_HOPS}))")
            print(f"Mapped source batch {offset // 32 + 1} through native HeavyDB Metal", flush=True)
        nodes = {row[0]: dict(zip([key for key, unused in NODE_SCHEMA], row))
                 for row in db.sql("SELECT * FROM django_sec_value_nodes ORDER BY node_id")}
        signals = {row["signal_id"]: row for row in read_rows("signals")}
        rows = db.sql("SELECT * FROM django_sec_graph_paths WHERE sink_node IS NOT NULL ORDER BY source_node,sink_node,path_step")
        flows = []
        for (start, end), values in itertools.groupby(rows, key=lambda row: (row[0], row[1])):
            path = list(values)
            source, sink = nodes[start], nodes[end]
            signal = signals[sink["sink_signal_id"]]
            steps = [dict(kind="source" if index == 0 else "sink" if index == len(path) - 1 else "value",
                          line=nodes[row[2]]["start_line"], end_line=nodes[row[2]]["end_line"], evidence=nodes[row[2]]["evidence"])
                     for index, row in enumerate(path)]
            if len(steps) == 1:
                steps[0]["kind"] = "source and sink"
            controls = [dict(signal_id=row["signal_id"], line=row["start_line"], title=row["rule_title"], evidence=row["evidence"])
                        for row in signals.values() if row["symbol_id"] == sink["symbol_id"] and row["signal_role"] == "control"]
            flows.append(dict(flow_id=len(flows) + 1, file_id=sink["file_id"], symbol_id=sink["symbol_id"],
                sink_signal_id=signal["signal_id"], source_path=sink["source_path"], package_name=sink["package_name"],
                qualified_name=sink["qualified_name"], source_kind=source["source_kind"], source_line=source["start_line"],
                sink_line=sink["start_line"], category=sink["category"], sink_channel=sink["sink_channel"],
                source_evidence=source["evidence"], sink_evidence=signal["evidence"], trace_json=json.dumps(steps),
                controls_json=json.dumps(controls), rule_id=signal["rule_id"], sink_confidence=signal["confidence"]))
        partial = db.sql("SELECT COUNT(DISTINCT source_node) FROM django_sec_graph_paths WHERE NOT search_complete")[0][0]
        counts = Counter(row["source_kind"] for row in flows)
        digest = hashlib.sha256(gzip.decompress((DATA / "value_edges.csv.gz").read_bytes())).hexdigest()
        snapshot = dict(commit_sha=COMMIT, engine_version=MODEL, indexed_utc=datetime.now(timezone.utc).isoformat(),
                        rules_sha256=digest, flow_count=len(flows), request_flow_count=counts["HTTP request"],
                        parameter_flow_count=counts["Caller parameter"], scanned_file_count=len({row["file_id"] for row in nodes.values()}),
                        unmapped_sink_count=facts_manifest["unmapped_sink_count"],
                        analysis_limits=f"{LIMITS} Source searches at the hop cutoff: {partial}. "
                                        f"Unmodeled sink signals: {facts_manifest['unmapped_sink_count']}.")
        write_rows("flows", FLOW_SCHEMA, flows)
        write_rows("flow_snapshot", SNAPSHOT_SCHEMA, [snapshot])
        copy_table(db, "flows", FLOW_SCHEMA)
        copy_table(db, "flow_snapshot", SNAPSHOT_SCHEMA)
    manifest = dict(snapshot=snapshot, counts={"flows": len(flows), "flow_snapshot": 1},
                    categories=dict(Counter(row["category"] for row in flows)))
    (DATA / "flow-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


def verify():
    spec = importlib.util.spec_from_file_location("verify_metal_graph", Path(__file__).with_name("verify-metal-graph.py"))
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    with HeavyDB() as db:
        for table, schema in (("value_nodes", NODE_SCHEMA), ("value_edges", EDGE_SCHEMA),
                              ("flows", FLOW_SCHEMA), ("flow_snapshot", SNAPSHOT_SCHEMA)):
            expected = [[row[key] for key, unused in schema] for row in read_rows(table, schema)]
            assert db.sql(f"SELECT * FROM django_sec_{table} ORDER BY {schema[0][0]}") == expected, table
        nodes = {row["node_id"]: row for row in read_rows("value_nodes", NODE_SCHEMA)}
        edges = [(row["edge_from"], row["edge_to"]) for row in read_rows("value_edges", EDGE_SCHEMA)]
        sources = [key for key, row in nodes.items() if row["source_kind"]]
        sinks = [key for key, row in nodes.items() if row["sink_signal_id"] is not None]
        paths = db.sql("SELECT * FROM django_sec_graph_paths ORDER BY source_node,sink_node,path_step")
        reference.check(paths, edges, sources, sinks, MAX_HOPS)
        assert db.sql("SELECT COUNT(*) FROM django_sec_value_nodes v LEFT JOIN django_sec_nodes n "
                      "ON v.syntax_node_id=n.node_id WHERE n.node_id IS NULL OR v.file_id<>n.file_id "
                      "OR v.start_line<n.start_line OR v.end_line>n.end_line") == [[0]]
        assert db.sql("SELECT COUNT(*) FROM django_sec_value_nodes v LEFT JOIN django_sec_symbols s "
                      "ON v.symbol_id=s.symbol_id WHERE s.symbol_id IS NULL OR v.file_id<>s.file_id "
                      "OR v.qualified_name<>s.qualified_name") == [[0]]
        for start, end in edges:
            assert nodes[start]["symbol_id"] == nodes[end]["symbol_id"]
        signals = {row["signal_id"]: row for row in read_rows("signals")}
        groups = [list(rows) for unused, rows in itertools.groupby(
            (row for row in paths if row[1] is not None), key=lambda row: (row[0], row[1]))]
        flows = read_rows("flows", FLOW_SCHEMA)
        assert len(flows) == len(groups)
        for flow, path in zip(flows, groups):
            source, sink = nodes[path[0][0]], nodes[path[0][1]]
            signal = signals[sink["sink_signal_id"]]
            assert source["symbol_id"] == sink["symbol_id"] == flow["symbol_id"]
            assert source["file_id"] == sink["file_id"] == flow["file_id"]
            assert flow["sink_signal_id"] == signal["signal_id"]
            assert flow["source_kind"] == source["source_kind"]
            assert flow["source_evidence"] == source["evidence"]
            assert flow["sink_evidence"] == signal["evidence"]
            steps = json.loads(flow["trace_json"])
            assert [(step["line"], step["end_line"], step["evidence"]) for step in steps] == [
                (nodes[row[2]]["start_line"], nodes[row[2]]["end_line"], nodes[row[2]]["evidence"]) for row in path]
            assert {item["signal_id"] for item in json.loads(flow["controls_json"])} == {
                row["signal_id"] for row in signals.values()
                if row["symbol_id"] == flow["symbol_id"] and row["signal_role"] == "control"}
        snapshot = read_rows("flow_snapshot", SNAPSHOT_SCHEMA)[0]
        assert snapshot["commit_sha"] == COMMIT and snapshot["engine_version"] == MODEL
        assert snapshot["rules_sha256"] == hashlib.sha256(gzip.decompress((DATA / "value_edges.csv.gz").read_bytes())).hexdigest()
        assert snapshot["flow_count"] == len(flows)
        assert snapshot["request_flow_count"] == sum(row["source_kind"] == "HTTP request" for row in flows)
        assert snapshot["parameter_flow_count"] == sum(row["source_kind"] == "Caller parameter" for row in flows)
    print(f"PASS: {len(nodes)} graph nodes, {len(edges)} edges, {len(sources)} sources, {len(sinks)} sinks, "
          f"{len(flows)} native mappings; exact stored rows, reference traversal, witnesses, syntax/scope references, and trace metadata")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("facts", "load", "verify"))
    {"facts": facts, "load": load, "verify": verify}[parser.parse_args().action]()
