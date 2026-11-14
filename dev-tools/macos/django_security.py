#!/usr/bin/env python3
"""Index Django source without executing it. Load only new project-owned tables."""

import argparse
import ast
import builtins
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import subprocess

from tree_sitter import Language, Parser
import tree_sitter_python

from vulnerability_db import HeavyDB


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "build-macos/django-security"
SOURCE = ROOT / "build-macos/django-source"
COMMIT = "f16e25dcb9fe55734ba4ea2b00ac34405b7df74a"
VERSION = "6.1.3"
REPO = "https://github.com/django/django"
NULL = "__DJANGO_NULL__"
CSV_OPTIONS = dict(delimiter="\x1f", quoting=csv.QUOTE_NONE, quotechar=None, lineterminator="\n")
TEXT = "TEXT ENCODING DICT(32)"
RAW = "TEXT ENCODING NONE"
SCHEMAS = {
    "files": [("file_id", "INT"), ("source_path", TEXT), ("module_name", TEXT),
              ("package_name", TEXT), ("sha256", TEXT), ("line_count", "INT"),
              ("source_json", RAW), ("node_count", "INT"), ("symbol_count", "INT"),
              ("signal_count", "INT")],
    "nodes": [("node_id", "BIGINT"), ("parent_id", "BIGINT"), ("file_id", "INT"),
              ("node_kind", TEXT), ("depth", "INT"), ("start_line", "INT"),
              ("end_line", "INT"), ("start_byte", "INT"), ("end_byte", "INT")],
    "symbols": [("symbol_id", "INT"), ("parent_id", "INT"), ("file_id", "INT"),
                ("node_id", "BIGINT"), ("source_path", TEXT), ("package_name", TEXT),
                ("qualified_name", TEXT), ("symbol_kind", TEXT), ("depth", "INT"),
                ("start_line", "INT"), ("end_line", "INT"), ("signature", RAW),
                ("signal_count", "INT"), ("boundary_count", "INT"), ("control_count", "INT")],
    "edges": [("edge_id", "INT"), ("source_id", "INT"), ("target_id", "INT"),
              ("node_id", "BIGINT"), ("file_id", "INT"), ("source_path", TEXT),
              ("start_line", "INT"), ("target_name", TEXT), ("edge_kind", TEXT),
              ("resolution", TEXT), ("evidence", RAW)],
    "signals": [("signal_id", "INT"), ("symbol_id", "INT"), ("file_id", "INT"),
                ("node_id", "BIGINT"), ("source_path", TEXT), ("package_name", TEXT),
                ("qualified_name", TEXT), ("start_line", "INT"), ("end_line", "INT"),
                ("category", TEXT), ("signal_role", TEXT), ("rule_id", TEXT),
                ("rule_title", TEXT), ("confidence", TEXT), ("evidence", RAW),
                ("explanation", RAW)],
    "snapshot": [("release_name", TEXT), ("commit_sha", TEXT), ("repository_url", RAW),
                 ("indexed_utc", TEXT), ("file_count", "INT"), ("node_count", "BIGINT"),
                 ("symbol_count", "INT"), ("edge_count", "INT"), ("signal_count", "INT"),
                 ("parse_errors", "INT"), ("parser_version", TEXT), ("analysis_limits", RAW)],
}
LIMITS = ("Static review signals, not confirmed vulnerabilities. Call links are candidates, not runtime traces. "
          "No taint analysis, application routes, settings, deployment exposure, or vulnerability coverage claim. "
          "Only Python files under django/ are indexed; tests and documentation are excluded.")


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def security_rule(name, decorator=False):
    """Return review evidence, not a vulnerability verdict or a taint assertion."""
    tail = name.rsplit(".", 1)[-1]
    if name in {"builtins.eval", "builtins.exec", "builtins.compile"}:
        return ("dynamic-code", "Dynamic code", "boundary", "Dynamic Python execution",
                "Check who controls the code input. This syntax alone does not establish unsafe input.")
    if tail in {"execute", "executemany", "raw", "extra", "RawSQL"}:
        return ("sql-api", "SQL", "boundary", "SQL or execution API candidate",
                "A method-name heuristic. Check receiver type, parameter binding, and SQL construction.")
    if name.startswith("subprocess.") or name in {"os.system", "os.popen"}:
        return ("process", "Process", "boundary", "Process execution API",
                "Check argument origin, shell use, executable selection, and environment.")
    if name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "yaml.load"}:
        return ("deserialize", "Deserialization", "boundary", "Object deserialization",
                "Check the serializer and trust of the input. A call is not proof of attacker control.")
    if name == "django.utils.safestring.mark_safe":
        return ("html-trust", "HTML", "trust override", "HTML marked safe",
                "Check the origin of this string and the escaping contract at its output context.")
    if name.startswith("django.utils.html.") and tail in {"escape", "conditional_escape", "format_html", "format_html_join"}:
        return ("html-control", "HTML", "control", "HTML escaping or formatting",
                "A protective API reference. Its presence does not prove that every input is escaped.")
    if name == "builtins.open" or tail in {"read_text", "write_text", "read_bytes", "write_bytes"}:
        return ("file-access", "Filesystem", "boundary", "File access candidate",
                "Check path origin, allowed roots, traversal, symlinks, and permissions.")
    if name == "django.utils._os.safe_join":
        return ("path-control", "Filesystem", "control", "Path containment helper",
                "Inspect this containment check and its callers. It does not cover filesystem races alone.")
    if name == "django.utils.http.url_has_allowed_host_and_scheme":
        return ("url-control", "URL trust", "control", "Redirect host and scheme check",
                "Inspect allowed hosts, scheme requirements, and normalization at the caller.")
    if name in {"django.shortcuts.redirect", "django.http.HttpResponseRedirect", "django.http.HttpResponsePermanentRedirect"}:
        return ("redirect", "URL trust", "boundary", "Redirect response",
                "Check the destination origin and host validation. Internal redirects can be legitimate.")
    if tail in {"csrf_exempt", "csrf_protect", "ensure_csrf_cookie", "login_required", "permission_required"} and name.startswith("django."):
        return ("request-guard", "Request trust", "trust override" if tail == "csrf_exempt" else "control",
                "Request protection reference", "Inspect decorator placement and request context. This is not a coverage guarantee.")
    if name.startswith("django.") and tail in {"authenticate", "login", "logout", "check_password", "constant_time_compare", "has_perm"}:
        return ("auth-control", "Authentication", "control", "Authentication or comparison API",
                "Inspect caller context, failure handling, and authorization. A control reference is not a proven guard.")
    if name.startswith("secrets.") or name in {"django.utils.crypto.get_random_string", "django.utils.crypto.salted_hmac"}:
        return ("crypto-control", "Cryptography", "control", "Security-related random or MAC API",
                "Inspect key material, entropy requirements, and the surrounding protocol.")
    return None


class Scope:
    def __init__(self, row, parent=None):
        self.row, self.parent = row, parent
        self.imports, self.defs = {}, defaultdict(list)
        self.bindings, self.globals = set(), set()


class SourceIndex(ast.NodeVisitor):
    def __init__(self):
        self.rows = {table: [] for table in SCHEMAS if table not in {"nodes", "snapshot"}}
        self.scopes, self.qualified, self.pending = {}, defaultdict(list), []
        self.next_node = 0

    def index_file(self, path, relative, parser, node_writer):
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        tree = parser.parse(raw)
        if tree.root_node.has_error:
            raise ValueError(f"Tree-sitter parse error: {relative}")
        parsed = ast.parse(text, filename=relative)
        file_id = len(self.rows["files"]) + 1
        parts = relative[:-3].split("/")
        if parts[-1] == "__init__":
            parts.pop()
        module = ".".join(parts)
        package = ".".join(relative.split("/")[1:3]) if relative.startswith("django/contrib/") else relative.split("/")[1]
        file = dict(file_id=file_id, source_path=relative, module_name=module,
                    package_name=package, sha256=hashlib.sha256(raw).hexdigest(),
                    line_count=len(text.splitlines()), source_json=json.dumps(text),
                    node_count=0, symbol_count=0, signal_count=0)
        self.rows["files"].append(file)
        spans = {}
        stack = [(tree.root_node, None, 0)]
        while stack:
            node, parent, depth = stack.pop()
            self.next_node += 1
            identifier = self.next_node
            spans[(node.start_byte, node.end_byte)] = identifier
            if node.type in {"function_definition", "class_definition"}:
                spans[("definition", node.start_byte)] = identifier
            node_writer.writerow([identifier, NULL if parent is None else parent, file_id, node.type,
                                  depth, node.start_point.row + 1, node.end_point.row + 1,
                                  node.start_byte, node.end_byte])
            file["node_count"] += 1
            stack.extend((child, identifier, depth + 1) for child in reversed(node.named_children))
        self.file, self.text, self.raw, self.spans = file, text, raw, spans
        self.offsets = [0]
        for line in raw.splitlines(keepends=True):
            self.offsets.append(self.offsets[-1] + len(line))
        self.scope = self.new_scope(module, "module", None, 1, file["line_count"], spans[(0, len(raw))], module)
        self.visit(parsed)

    def node_id(self, node):
        start = self.offsets[node.lineno - 1] + node.col_offset
        end = self.offsets[node.end_lineno - 1] + node.end_col_offset
        return self.spans.get((start, end), self.spans.get(("definition", start)))

    def new_scope(self, name, kind, parent, start, end, node_id, signature):
        row = dict(symbol_id=len(self.rows["symbols"]) + 1,
                   parent_id=parent.row["symbol_id"] if parent else None,
                   file_id=self.file["file_id"], node_id=node_id, source_path=self.file["source_path"],
                   package_name=self.file["package_name"], qualified_name=name, symbol_kind=kind,
                   depth=parent.row["depth"] + 1 if parent else 0, start_line=start, end_line=end,
                   signature=signature[:400], signal_count=0, boundary_count=0, control_count=0)
        scope = Scope(row, parent)
        self.rows["symbols"].append(row)
        self.scopes[row["symbol_id"]] = scope
        self.qualified[name].append(row["symbol_id"])
        self.file["symbol_count"] += 1
        if parent:
            self.edge(parent, row["symbol_id"], node_id, start, name, "contains", "syntax", signature)
        return scope

    def definition(self, node, kind):
        parent = self.scope
        qualified = f"{parent.row['qualified_name']}.{node.name}"
        scope = self.new_scope(qualified, kind, parent, node.lineno, node.end_lineno,
                               self.node_id(node), self.text.splitlines()[node.lineno - 1].strip())
        parent.defs[node.name].append(scope.row["symbol_id"])
        parent.bindings.add(node.name)
        self.scope = scope
        args = getattr(node, "args", None)
        if args:
            scope.bindings.update(arg.arg for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs])
            scope.bindings.update(arg.arg for arg in [args.vararg, args.kwarg] if arg)
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                self.remember(decorator, "decorator", dotted(decorator))
        self.generic_visit(node)
        self.scope = parent

    def visit_FunctionDef(self, node):
        self.definition(node, "function")

    def visit_AsyncFunctionDef(self, node):
        self.definition(node, "async function")

    def visit_ClassDef(self, node):
        self.definition(node, "class")

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.scope.bindings.add(node.id)

    def visit_Global(self, node):
        self.scope.globals.update(node.names)

    def visit_Import(self, node):
        for alias in node.names:
            self.scope.imports[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
            self.remember(node, "import", alias.name)

    def visit_ImportFrom(self, node):
        package = self.file["module_name"] if self.file["source_path"].endswith("__init__.py") else self.file["module_name"].rpartition(".")[0]
        module = importlib.util.resolve_name("." * node.level + (node.module or ""), package) if node.level else node.module or ""
        for alias in node.names:
            if alias.name != "*":
                self.scope.imports[alias.asname or alias.name] = f"{module}.{alias.name}"
                self.remember(node, "import", f"{module}.{alias.name}")

    def remember(self, node, kind, name):
        if name:
            evidence = (ast.get_source_segment(self.text, node) or name).replace("\n", " ")[:600]
            self.pending.append((self.scope, node, kind, name, self.node_id(node), evidence))

    def visit_Call(self, node):
        self.remember(node, "call", dotted(node.func) or "<dynamic-call>")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        name = dotted(node)
        if node.attr in {"GET", "POST", "COOKIES", "META", "headers", "body", "FILES"} and name.startswith(("request.", "self.request.")):
            self.remember(node, "input", name)
        self.generic_visit(node)

    def resolve(self, scope, name):
        first, dot, rest = name.partition(".")
        if first in {"self", "cls"}:
            parent = scope
            while parent and parent.row["symbol_kind"] != "class":
                parent = parent.parent
            return (parent.row["qualified_name"] + dot + rest, "receiver candidate") if parent else (name, "name heuristic")
        current = scope
        while current:
            if current is not scope and current.row["symbol_kind"] == "class":
                current = current.parent
                continue
            if first in current.globals and current.parent:
                while current.parent:
                    current = current.parent
            if first in current.imports and first not in current.bindings:
                return current.imports[first] + dot + rest, "import reference"
            if len(current.defs.get(first, [])) == 1:
                return self.scopes[current.defs[first][0]].row["qualified_name"] + dot + rest, "lexical candidate"
            if first in current.bindings:
                return "<local>." + name, "name heuristic"
            current = current.parent
        return ("builtins." + name, "builtin reference") if hasattr(builtins, first) else (name, "name heuristic")

    def edge(self, scope, target, node_id, line, name, kind, resolution, evidence):
        row = dict(edge_id=len(self.rows["edges"]) + 1, source_id=scope.row["symbol_id"],
                   target_id=target, node_id=node_id, file_id=scope.row["file_id"],
                   source_path=scope.row["source_path"], start_line=line, target_name=name,
                   edge_kind=kind, resolution=resolution, evidence=evidence)
        self.rows["edges"].append(row)

    def finish(self):
        for scope, node, kind, name, node_id, evidence in self.pending:
            resolved, confidence = (name, "import reference") if kind == "import" else self.resolve(scope, name)
            targets = self.qualified.get(resolved, [])
            target = targets[0] if len(targets) == 1 else None
            if kind != "input":
                self.edge(scope, target, node_id, node.lineno, resolved, kind,
                          "candidate" if target else "unresolved", evidence)
            rule = (("request-input", "Request trust", "input", "Request data reference",
                     "A syntactic request-data reference. No data flow to another operation has been established.")
                    if kind == "input" else security_rule(resolved, kind == "decorator") if kind in {"call", "decorator"} else None)
            if rule:
                rule_id, category, role, title, explanation = rule
                self.rows["signals"].append(dict(signal_id=len(self.rows["signals"]) + 1,
                    symbol_id=scope.row["symbol_id"], file_id=scope.row["file_id"], node_id=node_id,
                    source_path=scope.row["source_path"], package_name=scope.row["package_name"],
                    qualified_name=scope.row["qualified_name"], start_line=node.lineno,
                    end_line=node.end_lineno, category=category, signal_role=role, rule_id=rule_id,
                    rule_title=title, confidence=confidence, evidence=evidence, explanation=explanation))
                scope.row["signal_count"] += 1
                scope.row["control_count" if role == "control" else "boundary_count"] += 1
                self.rows["files"][scope.row["file_id"] - 1]["signal_count"] += 1


def index(source=SOURCE, output=DATA):
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if actual != COMMIT:
        raise RuntimeError(f"Expected pinned commit {COMMIT}, got {actual}")
    dirty = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"], text=True)
    if dirty:
        raise RuntimeError("The Django source checkout has changes. Refusing an unpinned snapshot.")
    output.mkdir(parents=True, exist_ok=True)
    parser = Parser(Language(tree_sitter_python.language()))
    result = SourceIndex()
    with gzip.open(output / "nodes.csv.gz", "wt", newline="", compresslevel=1) as stream:
        writer = csv.writer(stream, **CSV_OPTIONS)
        writer.writerow([key for key, unused in SCHEMAS["nodes"]])
        for path in sorted((source / "django").rglob("*.py")):
            result.index_file(path, path.relative_to(source).as_posix(), parser, writer)
    result.finish()
    snapshot = dict(release_name=VERSION, commit_sha=COMMIT, repository_url=REPO,
                    indexed_utc=datetime.now(timezone.utc).isoformat(), file_count=len(result.rows["files"]),
                    node_count=result.next_node, symbol_count=len(result.rows["symbols"]),
                    edge_count=len(result.rows["edges"]), signal_count=len(result.rows["signals"]),
                    parse_errors=0, parser_version=importlib.metadata.version("tree-sitter"), analysis_limits=LIMITS)
    result.rows["snapshot"] = [snapshot]
    counts = {name: len(rows) for name, rows in result.rows.items()}
    counts["nodes"] = result.next_node
    for name, rows in result.rows.items():
        with gzip.open(output / f"{name}.csv.gz", "wt", newline="", compresslevel=1) as stream:
            writer = csv.writer(stream, **CSV_OPTIONS)
            writer.writerow([key for key, unused in SCHEMAS[name]])
            for row in rows:
                writer.writerow([NULL if row[key] is None else row[key] for key, unused in SCHEMAS[name]])
    manifest = dict(snapshot=snapshot, counts=counts,
                    categories=dict(Counter(row["category"] for row in result.rows["signals"])),
                    roles=dict(Counter(row["signal_role"] for row in result.rows["signals"])))
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))
    return manifest


def load(replace=False):
    manifest = json.loads((DATA / "manifest.json").read_text())
    with HeavyDB() as db:
        existing = set(db.call("get_tables", db.session))
        owned = {"django_sec_" + table for table in SCHEMAS}
        if existing & owned and existing & owned != owned:
            raise RuntimeError("A partial dataset already exists. Refusing to replace or append data.")
        if owned <= existing:
            if db.sql("SELECT commit_sha FROM django_sec_snapshot") != [[COMMIT]]:
                raise RuntimeError("Existing tables do not identify the expected pinned commit")
            if replace:
                for table in reversed(SCHEMAS):
                    db.sql(f"DROP TABLE django_sec_{table}")
                existing -= owned
        if owned <= existing:
            print("Dataset already exists; verifying without changing it")
        else:
            for table, columns in SCHEMAS.items():
                definition = ", ".join(f"{name} {kind}" for name, kind in columns)
                db.sql(f"CREATE TABLE django_sec_{table} ({definition})")
                path = str((DATA / f"{table}.csv.gz").resolve()).replace("'", "''")
                db.sql(f"COPY django_sec_{table} FROM '{path}' WITH (header='true', nulls='{NULL}', "
                       "quoted='false', delimiter='\x1f', quote='\x1e', escape='\x1d', trim_spaces='false', max_reject=0)")
        for table, expected in manifest["counts"].items():
            actual = db.sql(f"SELECT COUNT(*) FROM django_sec_{table}")[0][0]
            assert actual == expected, (table, actual, expected)
            print(f"PASS: django_sec_{table}: {actual:,} rows")


def verify():
    manifest = json.loads((DATA / "manifest.json").read_text())
    with HeavyDB() as db:
        for table, expected in manifest["counts"].items():
            count, unique = db.sql(f"SELECT COUNT(*), COUNT(DISTINCT {SCHEMAS[table][0][0]}) FROM django_sec_{table}")[0]
            assert count == unique == expected, (table, count, unique, expected)
        for table, column, target, identifier in [
            ("nodes", "file_id", "files", "file_id"), ("nodes", "parent_id", "nodes", "node_id"),
            ("symbols", "file_id", "files", "file_id"), ("symbols", "node_id", "nodes", "node_id"),
            ("signals", "symbol_id", "symbols", "symbol_id"), ("signals", "node_id", "nodes", "node_id"),
            ("edges", "source_id", "symbols", "symbol_id"), ("edges", "target_id", "symbols", "symbol_id")]:
            count = db.sql(f"SELECT COUNT(*) FROM django_sec_{table} s LEFT JOIN django_sec_{target} t "
                           f"ON s.{column}=t.{identifier} WHERE s.{column} IS NOT NULL AND t.{identifier} IS NULL")[0][0]
            assert count == 0, (table, column, count)
        assert db.sql("SELECT COUNT(*) FROM django_sec_edges WHERE edge_kind='call' AND resolution NOT IN ('candidate','unresolved')")[0][0] == 0
        for path, digest, source_json in db.sql("SELECT source_path,sha256,source_json FROM django_sec_files"):
            source = json.loads(source_json)
            assert hashlib.sha256(source.encode()).hexdigest() == digest, path
            assert (SOURCE / path).read_text() == source, path
        assert dict(db.sql("SELECT category,COUNT(*) FROM django_sec_signals GROUP BY category")) == manifest["categories"]
        assert dict(db.sql("SELECT signal_role,COUNT(*) FROM django_sec_signals GROUP BY signal_role")) == manifest["roles"]
        assert db.sql("SELECT COUNT(*) FROM django_sec_signals WHERE node_id IS NULL")[0][0] == 0
        assert db.sql("SELECT COUNT(*) FROM django_sec_symbols WHERE node_id IS NULL")[0][0] == 0
        for table in ("symbols", "signals", "edges"):
            with gzip.open(DATA / f"{table}.csv.gz", "rt", newline="") as stream:
                expected = list(csv.reader(stream, **CSV_OPTIONS))[1:]
            actual = db.sql(f"SELECT * FROM django_sec_{table} ORDER BY {SCHEMAS[table][0][0]}")
            assert [[NULL if value is None else str(value) for value in row] for row in actual] == expected, table
    print("PASS: counts, unique IDs, source hashes, exact evidence, node references, rule totals, and explicit call uncertainty")


if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("action", choices=("index", "load", "reload", "verify"))
    action = args.parse_args().action
    {"index": index, "load": load, "reload": lambda: load(replace=True), "verify": verify}[action]()
