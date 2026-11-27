"""Unit tests for the native Foundry deployment acceptance output parser."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "lowkey_native_foundry_deployment_e2e",
    ROOT / "scripts" / "project-native-foundry-deployment-e2e.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NativeFoundryDeploymentAcceptanceTests(unittest.TestCase):
    def test_target_parser_accepts_lowkey_labelled_target_output(self):
        output = (
            "LOWKEY LOCAL AUDIT LAB\n"
            "Target  : NativeTarget -> NativeTarget "
            "(0xb9eb75A2093840aC1c65B6ba46C11deda9bF2Da6)\n"
        )
        match = MODULE.TARGET_LINE_RE.search(output)
        self.assertIsNotNone(match)
        self.assertEqual(
            match.group(1).lower(),
            "0xb9eb75a2093840ac1c65b6ba46c11deda9bf2da6",
        )

    def test_target_parser_accepts_address_only_legacy_format(self):
        address = "0x" + "12" * 20
        match = MODULE.TARGET_LINE_RE.search(f"Target: NativeTarget -> {address}\n")
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), address)

    def test_target_parser_does_not_match_a_supporting_contract_line(self):
        support = "0x" + "22" * 20
        output = f"Supporting: Helper -> {support}\n"
        self.assertIsNone(MODULE.TARGET_LINE_RE.search(output))


if __name__ == "__main__":
    unittest.main()
