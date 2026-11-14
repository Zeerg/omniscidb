"""Check semantic graph facts. Production mappings execute through HeavyDB SQL."""

from collections import defaultdict, deque
import csv
import io
from pathlib import Path
import tempfile
import unittest

from tree_sitter import Language, Parser
import tree_sitter_python

from django_security import SourceIndex
from django_metal_graph import ValueGraph


def graph_for(source):
    base, node_csv = SourceIndex(), io.StringIO()
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "sample.py"
        path.write_text(source)
        base.index_file(path, "django/sample.py", Parser(Language(tree_sitter_python.language())), csv.writer(node_csv))
    base.finish()
    spans = {1: {(int(row[7]), int(row[8])): int(row[0]) for row in csv.reader(io.StringIO(node_csv.getvalue()))}}
    return ValueGraph(base.rows["files"], base.rows["symbols"], base.rows["signals"], spans).build()


def request_pairs(graph):
    adjacent = defaultdict(set)
    for start, end, unused in graph.edges:
        adjacent[start].add(end)
    pairs = []
    for source in graph.nodes:
        if source["source_kind"] != "HTTP request":
            continue
        seen, queue = {source["node_id"]}, deque([source["node_id"]])
        while queue:
            for target in adjacent[queue.popleft()]:
                if target not in seen:
                    seen.add(target)
                    queue.append(target)
        pairs += [(source, sink) for sink in graph.nodes if sink["sink_signal_id"] and sink["node_id"] in seen]
    return pairs


class ValueGraphTests(unittest.TestCase):
    def test_source_assignment_and_sql_text_have_value_edges(self):
        graph = graph_for('def run(request,cursor):\n x=request.GET["q"]\n sql="SELECT "+x\n cursor.execute(sql)\n')
        self.assertTrue(request_pairs(graph))
        self.assertEqual(request_pairs(graph)[0][1]["sink_channel"], "SQL text")
        self.assertTrue(all(row["syntax_node_id"] for row in graph.nodes))

    def test_sql_bound_values_are_not_sql_text(self):
        graph = graph_for('def run(request,cursor):\n cursor.execute("SELECT * FROM t WHERE x=%s",[request.GET["q"]])\n')
        self.assertEqual(request_pairs(graph), [])

    def test_reassignment_kills_the_old_definition(self):
        graph = graph_for('def run(request,cursor):\n sql=request.GET["q"]\n sql="SELECT 1"\n cursor.execute(sql)\n')
        self.assertEqual(request_pairs(graph), [])

    def test_same_scope_is_not_data_flow(self):
        graph = graph_for('def run(request,cursor,sql):\n x=request.GET["q"]\n cursor.execute(sql)\n')
        self.assertEqual(request_pairs(graph), [])

    def test_caller_parameters_have_unknown_trust(self):
        graph = graph_for('def run(sql,cursor):\n cursor.execute(sql)\n')
        self.assertTrue(any(row["source_kind"] == "Caller parameter" for row in graph.nodes))
        self.assertEqual(request_pairs(graph), [])

    def test_opaque_returns_are_explicit_edges(self):
        graph = graph_for('def run(request):\n value=convert(request.body)\n eval(value)\n')
        self.assertTrue(request_pairs(graph))
        self.assertTrue(any(kind == "assumed call return" for start, end, kind in graph.edges))

    def test_shadowed_execution_api_is_not_a_sink(self):
        graph = graph_for('def run(request,eval):\n eval(request.body)\n')
        self.assertEqual(request_pairs(graph), [])

    def test_branch_merge_preserves_possible_sources(self):
        graph = graph_for('def run(request,flag):\n value="1"\n if flag:\n  value=request.body\n eval(value)\n')
        self.assertTrue(request_pairs(graph))

    def test_unreachable_code_after_return_is_not_connected(self):
        graph = graph_for('def run(request):\n return None\n eval(request.body)\n')
        self.assertEqual(request_pairs(graph), [])

    def test_call_links_are_not_invented_data_flow(self):
        graph = graph_for('def run(request):\n helper(request.body)\ndef helper(value):\n eval(value)\n')
        self.assertEqual(request_pairs(graph), [])


if __name__ == "__main__":
    unittest.main()
