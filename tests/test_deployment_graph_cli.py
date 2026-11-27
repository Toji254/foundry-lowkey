"""CLI acceptance for evidence-backed dependency graph output."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lowkeycast_deployment_graph_cli", ROOT / "lowkey" / "lk.py")
lk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lk)


class DeploymentGraphCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "Widget.sol").write_text(
            "pragma solidity ^0.8.20; contract Widget {}",
            encoding="utf-8",
        )
        self.graph = {
            "root": str(self.root),
            "nodes": [],
            "edges": [],
            "unresolved": [],
            "typed_edges": [],
            "compiler_dependencies": {"available": True, "edges": [], "contracts": []},
            "deployment_graph": {
                "schema_version": 1,
                "planning_status": "REVIEW_REQUIRED",
                "execution_status": "NOT_EXECUTED",
                "network_identity": None,
                "nodes": [],
                "edges": [],
                "cycles": [],
                "library_deployment_order": [],
                "summary": {
                    "nodes": 3,
                    "edges": 2,
                    "unresolved_edges": 1,
                    "deployable_library_edges": 1,
                    "cycles": 0,
                },
                "warnings": [],
            },
            "summary": {"files": 1, "typed_dependency_nodes": 3},
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_deps_json_emits_machine_readable_graph_without_human_prefix(self):
        output = io.StringIO()
        with patch.object(
            lk.project_tools, "build_dependency_graph", return_value=self.graph
        ), contextlib.redirect_stdout(output):
            result = lk.run_deps([str(self.root), "--json"])

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["deployment_graph"]["schema_version"], 1)
        self.assertEqual(payload["deployment_graph"]["planning_status"], "REVIEW_REQUIRED")
        self.assertEqual(payload["deployment_graph"]["execution_status"], "NOT_EXECUTED")
        self.assertEqual(payload["deployment_graph"]["summary"]["nodes"], 3)
        self.assertNotIn("Dependency / inheritance map", output.getvalue())

    def test_deps_human_output_surfaces_graph_status_and_never_calls_it_executed(self):
        output = io.StringIO()
        with patch.object(
            lk.project_tools, "build_dependency_graph", return_value=self.graph
        ), contextlib.redirect_stdout(output):
            result = lk.run_deps([str(self.root)])

        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("Typed deployment graph: 3 node(s), 2 typed edge(s)", rendered)
        self.assertIn("planning REVIEW_REQUIRED", rendered)
        self.assertIn("execution NOT_EXECUTED", rendered)

    def test_deps_json_rejects_extra_positional_arguments_before_analysis(self):
        output = io.StringIO()
        with patch.object(
            lk.project_tools, "build_dependency_graph"
        ) as build, contextlib.redirect_stdout(output):
            result = lk.run_deps([str(self.root), "another-path", "--json"])

        self.assertNotEqual(result, 0)
        self.assertIn("Usage: lk deps", output.getvalue())
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
