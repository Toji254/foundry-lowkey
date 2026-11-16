import io
import json
import pathlib
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import capability_registry
import godmode


class CapabilityRegistryTests(unittest.TestCase):
    def test_all_44_capabilities_have_complete_contract_fields(self):
        specs = capability_registry.list_capabilities()
        self.assertEqual(len(specs), 44)
        self.assertEqual(len({item["name"] for item in specs}), 44)
        for item in specs:
            self.assertEqual(item["metadata_version"], 1)
            self.assertTrue(item["inputs"], item["name"])
            self.assertTrue(item["outputs"], item["name"])
            self.assertTrue(item["safety_requirements"], item["name"])
            self.assertIn(item["status"], {"implemented", "partial", "adapter-required"})

    def test_registry_legacy_inventory_and_help_router_are_derived_from_registry(self):
        self.assertEqual(godmode.CAPABILITIES, capability_registry.CAPABILITIES)
        self.assertEqual(godmode.ROUTED_COMMANDS, capability_registry.ROUTED_COMMANDS)
        self.assertTrue(capability_registry.RPC_CONTEXT_COMMANDS <= (
            set(capability_registry.ROUTED_COMMANDS) | set(capability_registry.SPECIALIZED_ALIAS_COMMANDS)
        ))

    def test_capability_detail_exposes_dependencies_without_claiming_runtime_readiness(self):
        result = capability_registry.dependency_plan("godmode")
        self.assertIsNotNone(result)
        self.assertEqual(result["capability"]["name"], "godmode")
        self.assertIn("cheat-fingerprint", result["transitive_capability_dependencies"])
        self.assertIn("anvil", result["external_tool_dependencies"])
        self.assertEqual(result["runtime_readiness"], "NOT_CHECKED")

    def test_unknown_capability_has_no_dependency_plan(self):
        self.assertIsNone(capability_registry.dependency_plan("made-up-capability"))

    def test_capabilities_json_cli_emits_44_machine_readable_contracts(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = godmode.main(["capabilities", "--json"])
        self.assertEqual(status, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(len(payload), 44)
        self.assertEqual(payload[0]["name"], "cheat-fingerprint")

    def test_capability_detail_cli_emits_transitive_plan(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = godmode.main(["capabilities", "--detail", "godmode"])
        self.assertEqual(status, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["capability"]["name"], "godmode")
        self.assertEqual(payload["runtime_readiness"], "NOT_CHECKED")

    def test_unknown_capability_detail_fails_closed(self):
        output = io.StringIO()
        with redirect_stderr(output):
            status = godmode.main(["capabilities", "--detail", "missing"])
        self.assertEqual(status, 2)
        self.assertIn("Unknown capability", output.getvalue())


if __name__ == "__main__":
    unittest.main()
