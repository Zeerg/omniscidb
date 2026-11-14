"""Check source evidence, conservative resolution, and security rule boundaries."""

import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from tree_sitter import Language, Parser
import tree_sitter_python

from django_security import SourceIndex


def parse(source):
    index = SourceIndex()
    with tempfile.TemporaryDirectory() as directory:
        file = Path(directory) / "sample.py"
        file.write_text(source)
        index.index_file(file, "django/sample.py", Parser(Language(tree_sitter_python.language())), csv.writer(io.StringIO()))
    index.finish()
    return index


class SourceIndexTests(unittest.TestCase):
    def test_import_alias_and_source_evidence(self):
        source = 'from django.utils.safestring import mark_safe as trusted\ndef render(value):\n    return trusted(value)\n'
        index = parse(source)
        signal, = index.rows["signals"]
        self.assertEqual(signal["rule_id"], "html-trust")
        self.assertEqual(signal["signal_role"], "trust override")
        self.assertEqual(signal["start_line"], 3)
        self.assertEqual(signal["evidence"], "trusted(value)")
        self.assertIsNotNone(signal["node_id"])
        self.assertEqual(signal["qualified_name"], "django.sample.render")

    def test_shadowed_imports_and_builtins_are_not_claimed(self):
        index = parse('import pickle as p\np = object()\ndef run(p, eval):\n    p.loads("text")\n    eval("text")\n')
        self.assertEqual(index.rows["signals"], [])

    def test_comments_and_strings_are_not_calls(self):
        index = parse('# eval(request.GET["x"])\ntext = "pickle.loads(value)"\n')
        self.assertEqual(index.rows["signals"], [])

    def test_controls_do_not_become_vulnerabilities(self):
        index = parse('from django.utils.html import escape\ndef render(value):\n    return escape(value)\n')
        signal, = index.rows["signals"]
        self.assertEqual(signal["signal_role"], "control")
        self.assertIn("does not prove", signal["explanation"])

    def test_request_reads_are_not_taint_paths(self):
        index = parse('def view(request):\n    return request.GET.get("name")\n')
        signal, = index.rows["signals"]
        self.assertEqual(signal["signal_role"], "input")
        self.assertIn("No data flow", signal["explanation"])

    def test_call_candidates_and_unknown_targets_stay_distinct(self):
        index = parse('class Service:\n    def start(self):\n        self.finish()\n        callback()\n    def finish(self):\n        pass\n')
        calls = [row for row in index.rows["edges"] if row["edge_kind"] == "call"]
        self.assertEqual(calls[0]["resolution"], "candidate")
        self.assertIsNotNone(calls[0]["target_id"])
        self.assertEqual(calls[1]["resolution"], "unresolved")
        self.assertIsNone(calls[1]["target_id"])

    def test_decorator_reference_and_unicode_round_trip(self):
        source = 'from django.views.decorators.csrf import csrf_exempt\n@csrf_exempt\ndef view(request):\n    return "caf\u00e9"\n'
        index = parse(source)
        signal, = index.rows["signals"]
        self.assertEqual(signal["signal_role"], "trust override")
        file, = index.rows["files"]
        self.assertEqual(json.loads(file["source_json"]), source)
        self.assertEqual(file["sha256"], hashlib.sha256(source.encode()).hexdigest())

    def test_syntax_error_stops_instead_of_silently_omitting_code(self):
        with self.assertRaises(ValueError):
            parse('def broken(:\n')

    def test_dynamic_calls_remain_visible_as_unresolved(self):
        index = parse('def run(factory):\n    return factory()()\n')
        calls = [row for row in index.rows["edges"] if row["edge_kind"] == "call"]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["target_name"], "<dynamic-call>")
        self.assertTrue(all(row["resolution"] == "unresolved" for row in calls))

    def test_function_with_trailing_comments_keeps_a_syntax_link(self):
        index = parse('def run():\n    pass\n    # trailing comment\n')
        function = next(row for row in index.rows["symbols"] if row["symbol_kind"] == "function")
        self.assertIsNotNone(function["node_id"])


if __name__ == "__main__":
    unittest.main()
