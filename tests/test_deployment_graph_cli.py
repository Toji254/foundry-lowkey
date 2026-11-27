"""CLI acceptance for evidence-backed dependency graph output."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import Mock, patch

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
            "compiler_dependencies": {
                "available": True,
                "warnings": [],
                "contracts": [
                    {"id": "src/Math.sol:Math", "source": "src/Math.sol", "name": "Math", "contract_kind": "library", "compiler_build_info": "build.json", "declaration_id": 1},
                    {"id": "src/Widget.sol:Widget", "source": "src/Widget.sol", "name": "Widget", "contract_kind": "contract", "compiler_build_info": "build.json", "declaration_id": 2},
                    {"id": "src/IOracle.sol:IOracle", "source": "src/IOracle.sol", "name": "IOracle", "contract_kind": "interface", "compiler_build_info": "build.json", "declaration_id": 3},
                ],
                "edges": [
                    {
                        "from": "src/Widget.sol:Widget", "to": "src/Math.sol:Math",
                        "kind": "solidity-library-link", "confidence": "CONFIRMED",
                        "source": "solc-output:evm.bytecode.linkReferences",
                        "link_references": [[158, 20]], "requires_resolution": True,
                        "auto_deploy": True,
                        "evidence": {"build_info": "build.json", "source_path": "src/Widget.sol"},
                    },
                    {
                        "from": "src/Widget.sol:Widget", "to": "src/IOracle.sol:IOracle",
                        "kind": "typed-parameter-reference", "confidence": "INFERRED",
                        "source": "solc-ast:VariableDeclaration", "requires_resolution": True,
                        "auto_deploy": False,
                        "evidence": {"build_info": "build.json", "source_path": "src/Widget.sol"},
                    },
                ],
                "library_cycles": [],
                "library_deployment_order": ["src/Math.sol:Math"],
            },
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

    def _managed_session(self):
        genesis = "0x" + "ab" * 32
        return {
            "id": "session-a",
            "name": "dev-a",
            "project_id": "project-a",
            "rpc": "http://127.0.0.1:18545",
            "chain_id": 31337,
            "genesis_hash": genesis,
            "identity_block_hash": genesis,
            "identity_block_number": 0,
        }

    def _library_record(self, session):
        return {
            "role": "solidity_library",
            "qualified_identity": "src/Math.sol:Math",
            "address": "0x" + "11" * 20,
            "artifact": str(self.root / "out" / "Math.sol" / "Math.json"),
            "artifact_sha256": "artifact-sha",
            "runtime_verification": "MATCHED",
            "runtime_code_hash": "runtime-sha",
            "deployment_transaction": "0x" + "aa" * 32,
            "last_verified_at": "2026-11-27T10:00:00+00:00",
            "reuse_permitted": True,
            "network": {
                "project_id": session["project_id"],
                "network_session_id": session["id"],
                "chain_id": session["chain_id"],
                "genesis_hash": session["genesis_hash"],
                "identity_block_hash": session["identity_block_hash"],
            },
        }

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
        self.assertTrue(lk._machine_readable_stdout("deps", [str(self.root), "--json"]))
        self.assertFalse(lk._machine_readable_stdout("deps", [str(self.root)]))

    def test_deps_json_enriches_graph_from_matching_live_session_records(self):
        session = self._managed_session()
        manager = Mock()
        manager.list.return_value = [{**session, "process_owned": True, "status": "running"}]
        manager.get_deployments.return_value = {"math": self._library_record(session)}
        output = io.StringIO()
        with patch.object(
            lk.project_tools, "build_dependency_graph", return_value=self.graph
        ), patch.object(lk, "_project_network_manager", return_value=manager), patch.object(
            lk, "_artifact_file_sha256", return_value="artifact-sha"
        ), contextlib.redirect_stdout(output):
            result = lk.run_deps([str(self.root), "--json"], {"_active_network_session": session})

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["deployment_graph"]["network_identity"]["network_session_id"], "session-a")
        node = next(item for item in payload["deployment_graph"]["nodes"] if item["id"] == "src/Math.sol:Math")
        self.assertEqual(node["address"], "0x" + "11" * 20)
        self.assertEqual(node["deployment_status"], "DEPLOYED_RUNTIME_MATCHED_AT_LAST_CHECK")
        evidence = next(item for item in node["evidence"] if item.get("origin") == "managed-network-deployment-registry")
        self.assertEqual(evidence["deployment_transaction"], "0x" + "aa" * 32)
        self.assertEqual(evidence["artifact_current_match"], True)
        manager.get_deployments.assert_called_once_with("session-a")

    def test_deps_does_not_read_deployments_from_unowned_or_stale_session(self):
        session = self._managed_session()
        manager = Mock()
        manager.list.return_value = [{**session, "process_owned": False, "status": "stale-or-unowned"}]
        manager.get_deployments.return_value = {"math": self._library_record(session)}
        output = io.StringIO()
        with patch.object(
            lk.project_tools, "build_dependency_graph", return_value=self.graph
        ), patch.object(lk, "_project_network_manager", return_value=manager), contextlib.redirect_stdout(output):
            result = lk.run_deps([str(self.root), "--json"], {"_active_network_session": session})

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertIsNone(payload["deployment_graph"]["network_identity"])
        node = next(item for item in payload["deployment_graph"]["nodes"] if item["id"] == "src/Math.sol:Math")
        self.assertIsNone(node["address"])
        self.assertEqual(node["deployment_status"], "NOT_TESTED")
        self.assertTrue(any("process" in warning for warning in payload["deployment_graph"]["warnings"]))
        manager.get_deployments.assert_not_called()

    def test_deps_json_does_not_attach_deployment_when_artifact_hash_changed(self):
        session = self._managed_session()
        manager = Mock()
        manager.list.return_value = [{**session, "process_owned": True, "status": "running"}]
        manager.get_deployments.return_value = {"math": self._library_record(session)}
        output = io.StringIO()
        with patch.object(
            lk.project_tools, "build_dependency_graph", return_value=self.graph
        ), patch.object(lk, "_project_network_manager", return_value=manager), patch.object(
            lk, "_artifact_file_sha256", return_value="different-artifact-sha"
        ), contextlib.redirect_stdout(output):
            result = lk.run_deps([str(self.root), "--json"], {"_active_network_session": session})

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        node = next(item for item in payload["deployment_graph"]["nodes"] if item["id"] == "src/Math.sol:Math")
        self.assertIsNone(node["address"])
        self.assertEqual(node["deployment_status"], "DEPLOYED_ARTIFACT_UNVERIFIED")
        self.assertTrue(any(item.get("origin") == "managed-network-deployment-registry" for item in node["evidence"]))

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


    def test_deps_includes_project_manifest_external_infrastructure_declarations(self):
        session = self._managed_session()
        compiler = self.graph["compiler_dependencies"]
        consumer = "src/Widget.sol:Widget"
        compiler["edges"].append({
            "from": consumer,
            "to": f"{consumer}#constructor._vault",
            "kind": "constructor-input",
            "confidence": "CONFIRMED",
            "requires_resolution": True,
            "resolution_status": "ADDRESS_SEMANTICS_UNCLASSIFIED",
            "source": "solc-output:abi.constructor.inputs",
            "evidence": {"build_info": "build.json", "source_path": "src/Widget.sol"},
        })
        manifest_path = self.root / ".audit" / "dependencies.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps({
            "schema": "lowkey.external-dependencies.v1",
            "network_identity": {
                "project_id": session["project_id"],
                "network_session_id": session["id"],
                "chain_id": session["chain_id"],
                "genesis_hash": session["genesis_hash"],
                "identity_block_hash": session["identity_block_hash"],
            },
            "dependencies": [{
                "id": "widget-vault",
                "consumer": consumer,
                "parameter": "_vault",
                "kind": "vault",
                "address": "0x" + "11" * 20,
                "description": "Local Vault fixture",
            }],
        }), encoding="utf-8")

        manager = Mock()
        manager.list.return_value = [{**session, "process_owned": True, "status": "running"}]
        manager.get_deployments.return_value = {}
        output = io.StringIO()
        with patch.object(
            lk.project_tools, "build_dependency_graph", return_value=self.graph
        ), patch.object(
            lk, "_project_network_manager", return_value=manager
        ), contextlib.redirect_stdout(output):
            result = lk.run_deps([str(self.root), "--json"], {"_active_network_session": session})

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        node = next(item for item in payload["deployment_graph"]["nodes"] if item["id"] == "external:widget-vault")
        self.assertEqual(node["category"], "external-infrastructure:vault")
        self.assertEqual(node["resolution_status"], "DECLARED_UNVERIFIED")
        self.assertEqual(node["address"], "0x" + "11" * 20)
        edge = next(item for item in payload["deployment_graph"]["edges"] if item["kind"] == "external-infrastructure")
        self.assertFalse(edge["auto_deploy"])
        self.assertEqual(edge["origin"]["manifest_path"], ".audit/dependencies.json")
        self.assertEqual(payload["deployment_graph"]["external_manifest"]["status"], "VALID")

    def test_deps_json_rejects_extra_positional_arguments_before_analysis(self):
        output = io.StringIO()
        with patch.object(
            lk.project_tools, "build_dependency_graph"
        ) as build, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = lk.run_deps([str(self.root), "another-path", "--json"])

        self.assertNotEqual(result, 0)
        self.assertIn("Usage: lk deps", output.getvalue())
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
