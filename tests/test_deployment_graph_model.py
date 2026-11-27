import unittest

from lowkey.deployment_graph import build_dependency_graph


class DeploymentGraphModelTests(unittest.TestCase):
    def _report(self):
        return {
            "available": True,
            "contracts": [
                {"id": "src/Math.sol:Math", "source": "src/Math.sol", "name": "Math", "contract_kind": "library", "compiler_build_info": "build.json", "declaration_id": 1},
                {"id": "src/Widget.sol:Widget", "source": "src/Widget.sol", "name": "Widget", "contract_kind": "contract", "compiler_build_info": "build.json", "declaration_id": 2},
                {"id": "src/IOracle.sol:IOracle", "source": "src/IOracle.sol", "name": "IOracle", "contract_kind": "interface", "compiler_build_info": "build.json", "declaration_id": 3},
                {"id": "src/Helper.sol:Helper", "source": "src/Helper.sol", "name": "Helper", "contract_kind": "contract", "compiler_build_info": "build.json", "declaration_id": 4},
            ],
            "edges": [
                {
                    "from": "src/Widget.sol:Widget", "to": "src/Math.sol:Math",
                    "kind": "solidity-library-link", "confidence": "CONFIRMED",
                    "source": "solc-output:evm.bytecode.linkReferences",
                    "link_references": [(15857, 20), (16472, 20)],
                    "requires_resolution": True, "auto_deploy": True,
                    "evidence": {"build_info": "build.json", "source_path": "src/Widget.sol", "dependency_source": "src/Math.sol", "library_name": "Math"},
                },
                {
                    "from": "src/Widget.sol:Widget", "to": "src/Widget.sol:Widget#constructor.vault",
                    "kind": "constructor-input", "confidence": "CONFIRMED",
                    "source": "solc-output:abi.constructor.inputs",
                    "requires_resolution": True, "auto_deploy": False,
                    "resolution_status": "ADDRESS_SEMANTICS_UNCLASSIFIED",
                    "value_kind": "address-value-unclassified",
                    "evidence": {"build_info": "build.json", "source_path": "src/Widget.sol"},
                },
                {
                    "from": "src/Widget.sol:Widget", "to": "src/IOracle.sol:IOracle",
                    "kind": "typed-parameter-reference", "confidence": "INFERRED",
                    "source": "solc-ast:VariableDeclaration",
                    "requires_resolution": True, "auto_deploy": False,
                    "evidence": {"build_info": "build.json", "source_path": "src/Widget.sol", "declaration_id": 9},
                },
                {
                    "from": "src/Widget.sol:Widget", "to": "src/Helper.sol:Helper",
                    "kind": "creation-expression", "confidence": "CONFIRMED",
                    "source": "solc-ast:NewExpression", "function": "constructor",
                    "creation_phase": "deployment", "factory_created": True,
                    "requires_resolution": False, "auto_deploy": False,
                    "evidence": {"build_info": "build.json", "source_path": "src/Widget.sol"},
                },
                {
                    "from": "src/Widget.sol:Widget", "to": "src/Helper.sol:Helper",
                    "kind": "creation-expression", "confidence": "CONFIRMED",
                    "source": "solc-ast:NewExpression", "function": "createCache",
                    "creation_phase": "runtime", "factory_created": True,
                    "requires_resolution": False, "auto_deploy": False,
                    "evidence": {"build_info": "build.json", "source_path": "src/Widget.sol"},
                },
            ],
            "library_cycles": [],
            "library_deployment_order": ["src/Math.sol:Math", "src/Widget.sol:Widget"],
            "warnings": [],
        }

    def _network(self, session="session-a"):
        return {
            "project_id": "project-a",
            "project_root": "/tmp/example",
            "network_session_id": session,
            "chain_id": 31337,
            "genesis_hash": "0x" + "ab" * 32,
            "identity_block_hash": "0x" + "ab" * 32,
            "reuse_permitted": True,
        }

    def test_preserves_relationship_categories_provenance_and_exact_link_offsets(self):
        graph = build_dependency_graph(self._report()).to_dict()
        self.assertEqual(graph["schema_version"], 1)
        self.assertEqual(graph["planning_status"], "REVIEW_REQUIRED")
        library = next(edge for edge in graph["edges"] if edge["kind"] == "solidity-library-link")
        self.assertTrue(library["auto_deploy"])
        self.assertEqual(library["link_references"], [[15857, 20], [16472, 20]])
        self.assertEqual(library["origin"]["build_info"], "build.json")

        constructor = next(edge for edge in graph["edges"] if edge["kind"] == "constructor-input")
        self.assertFalse(constructor["auto_deploy"])
        self.assertEqual(constructor["resolution_status"], "ADDRESS_SEMANTICS_UNCLASSIFIED")

        creations = [edge for edge in graph["edges"] if edge["kind"] == "creation-expression"]
        self.assertEqual({edge["creation_phase"] for edge in creations}, {"deployment", "runtime"})
        self.assertTrue(all(not edge["auto_deploy"] for edge in creations))

    def test_network_matched_runtime_verified_library_is_the_only_reusable_address(self):
        address = "0x" + "11" * 20
        matching = {
            "role": "solidity_library",
            "qualified_identity": "src/Math.sol:Math",
            "address": address,
            "runtime_verification": "MATCHED",
            "reuse_permitted": True,
            "artifact_current_match": True,
            "deployment_transaction": "0x" + "aa" * 32,
            "last_verified_at": "2026-11-27T10:00:00+00:00",
            "network": self._network(),
        }
        graph = build_dependency_graph(
            self._report(), network_identity=self._network(), deployment_records=[matching],
        ).to_dict()
        library = next(node for node in graph["nodes"] if node["id"] == "src/Math.sol:Math")
        self.assertEqual(library["address"], address)
        self.assertEqual(library["deployment_status"], "DEPLOYED_RUNTIME_MATCHED_AT_LAST_CHECK")
        self.assertEqual(library["evidence"][-1]["origin"], "managed-network-deployment-registry")
        self.assertEqual(library["evidence"][-1]["deployment_transaction"], "0x" + "aa" * 32)
        self.assertEqual(library["evidence"][-1]["last_verified_at"], "2026-11-27T10:00:00+00:00")
        self.assertEqual(library["network_identity"]["network_session_id"], "session-a")

    def test_same_address_same_chain_and_genesis_in_another_session_is_not_reused(self):
        address = "0x" + "11" * 20
        foreign = {
            "role": "solidity_library",
            "qualified_identity": "src/Math.sol:Math",
            "address": address,
            "runtime_verification": "MATCHED",
            "reuse_permitted": True,
            "network": self._network("session-b"),
        }
        graph = build_dependency_graph(
            self._report(), network_identity=self._network("session-a"), deployment_records=[foreign],
        ).to_dict()
        library = next(node for node in graph["nodes"] if node["id"] == "src/Math.sol:Math")
        self.assertIsNone(library["address"])
        self.assertEqual(library["deployment_status"], "NOT_DEPLOYED")

    def test_incomplete_network_identity_cannot_authorize_reuse(self):
        address = "0x" + "11" * 20
        record = {
            "qualified_identity": "src/Math.sol:Math",
            "address": address,
            "runtime_verification": "MATCHED",
            "reuse_permitted": True,
            "network": {
                "network_session_id": "session-a", "chain_id": 31337,
                "genesis_hash": "0x" + "ab" * 32,
            },
        }
        graph = build_dependency_graph(
            self._report(), network_identity=self._network(), deployment_records=[record],
        ).to_dict()
        library = next(node for node in graph["nodes"] if node["id"] == "src/Math.sol:Math")
        self.assertIsNone(library["address"])
        self.assertEqual(library["deployment_status"], "NOT_DEPLOYED")

    def test_historical_runtime_match_does_not_attach_address_when_artifact_changed(self):
        address = "0x" + "11" * 20
        changed = {
            "role": "solidity_library",
            "qualified_identity": "src/Math.sol:Math",
            "address": address,
            "runtime_verification": "MATCHED",
            "reuse_permitted": True,
            "artifact_current_match": False,
            "network": self._network(),
        }
        graph = build_dependency_graph(
            self._report(), network_identity=self._network(), deployment_records=[changed],
        ).to_dict()
        library = next(node for node in graph["nodes"] if node["id"] == "src/Math.sol:Math")
        self.assertIsNone(library["address"])
        self.assertEqual(library["deployment_status"], "DEPLOYED_ARTIFACT_UNVERIFIED")
        self.assertTrue(any(item.get("origin") == "managed-network-deployment-registry" for item in library["evidence"]))

    def test_library_cycle_blocks_the_linear_deployment_plan(self):
        report = self._report()
        report["library_cycles"] = [["src/Math.sol:Math", "src/Other.sol:Other"]]
        report["library_deployment_order"] = []
        graph = build_dependency_graph(report).to_dict()
        self.assertEqual(graph["planning_status"], "BLOCKED")
        self.assertEqual(graph["library_deployment_order"], [])
        self.assertEqual(len(graph["cycles"]), 1)
        self.assertTrue(any("cycle blocks" in item.lower() for item in graph["warnings"]))

    def test_missing_compiler_evidence_is_blocked_not_an_empty_safe_graph(self):
        graph = build_dependency_graph({"available": False, "contracts": [], "edges": []}).to_dict()
        self.assertEqual(graph["planning_status"], "BLOCKED")
        self.assertTrue(any("unavailable" in item.lower() for item in graph["warnings"]))
        self.assertEqual(graph["execution_status"], "NOT_EXECUTED")


if __name__ == "__main__":
    unittest.main()
