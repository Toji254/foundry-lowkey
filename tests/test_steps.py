import json
import pathlib
import tempfile
import unittest

from lowkey.step_renderer import RefusalError, normalize_manifest, render_manifest


class StepRendererTests(unittest.TestCase):
    def _manifest(self):
        return {
            "schema_version": 1,
            "family": "reentrancy",
            "target_address": "0x1111111111111111111111111111111111111111",
            "contract_name": "ReentrancySteps",
            "steps": [
                {
                    "kind": "call",
                    "selector": "0x12345678",
                    "args": [
                        {"type": "address", "value": "0x2222222222222222222222222222222222222222"},
                        {"type": "uint256", "value": 1},
                    ],
                    "optional": True,
                },
                {
                    "kind": "read",
                    "selector": "0xabcdef01",
                    "args": [],
                },
                {
                    "kind": "expect",
                    "expect": {"count": 2, "must_revert": False},
                },
            ],
        }

    def test_normalizes_typed_calls_and_renders_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "steps.json").write_text(json.dumps(self._manifest()), encoding="utf-8")
            template = root / "templates"
            template.mkdir()
            # Render against the committed template without modifying it.
            module = pathlib.Path(__import__("lowkey.step_renderer", fromlist=["x"]).__file__)
            (template / "StepHarness.sol").write_text(
                (module.parent / "templates" / "StepHarness.sol").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            output, normalized = render_manifest(root, root / "steps.json")
            source = output.read_text(encoding="utf-8")
            self.assertEqual(normalized["contract_name"], "ReentrancySteps")
            self.assertLess(source.index("0x12345678"), source.index("0xabcdef01"))
            self.assertIn("abi.encode(address(0x2222222222222222222222222222222222222222), uint256(1))", source)
            self.assertIn("_stepCallCount == 2", source)
            self.assertIn("function run() external payable", source)

    def test_renderer_does_not_overwrite_existing_output_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "steps.json").write_text(json.dumps(self._manifest()), encoding="utf-8")
            template = root / "templates"
            template.mkdir()
            module = pathlib.Path(__import__("lowkey.step_renderer", fromlist=["x"]).__file__)
            (template / "StepHarness.sol").write_text(
                (module.parent / "templates" / "StepHarness.sol").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            target = root / "test/lowkey/ReentrancySteps.sol"
            target.parent.mkdir(parents=True)
            target.write_text("keep", encoding="utf-8")
            with self.assertRaises(RefusalError) as caught:
                render_manifest(root, root / "steps.json")
            self.assertEqual(caught.exception.refusal["reason"], "out_of_scope")
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_unsupported_step_kinds_fail_closed_with_machine_readable_reason(self):
        for kind, reason in (
            ("flash_borrow", "no_capability"),
            ("skew", "no_capability"),
            ("warp", "backend_unsupported"),
            ("roll", "backend_unsupported"),
            ("snapshot", "backend_unsupported"),
            ("revert", "backend_unsupported"),
            ("assert", "no_capability"),
        ):
            with self.subTest(kind=kind):
                manifest = self._manifest()
                manifest["steps"] = [{"kind": kind}]
                with self.assertRaises(RefusalError) as caught:
                    normalize_manifest(manifest)
                self.assertEqual(caught.exception.refusal["reason"], reason)

    def test_tuple_dynamic_bytes_and_nested_arrays_are_refused_by_name(self):
        for abi_type in ("tuple", "bytes", "string", "address[]", "uint256[][]"):
            with self.subTest(abi_type=abi_type):
                manifest = self._manifest()
                manifest["steps"][0]["args"] = [{"type": abi_type, "value": "x"}]
                with self.assertRaises(RefusalError) as caught:
                    normalize_manifest(manifest)
                self.assertEqual(caught.exception.refusal["reason"], "unsupported_abi")
                self.assertIn(abi_type, caught.exception.refusal["detail"])

    def test_read_cannot_transfer_eth_and_expect_revert_requires_optional(self):
        manifest = self._manifest()
        manifest["steps"][0]["value"] = "1"
        manifest["steps"][0]["kind"] = "read"
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)
        manifest = self._manifest()
        manifest["steps"][0]["expect"] = {"count": 1, "must_revert": True}
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)
        manifest["steps"][0]["optional"] = True
        self.assertTrue(normalize_manifest(manifest)["steps"][0]["expect"]["must_revert"])

    def test_unknown_fields_and_bad_selector_refuse(self):
        manifest = self._manifest()
        manifest["steps"][0]["surprise"] = True
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)
        manifest = self._manifest()
        manifest["steps"][0]["selector"] = "0x1234"
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)

    def test_fixed_width_values_are_range_checked(self):
        manifest = self._manifest()
        manifest["steps"][0]["args"] = [{"type": "uint8", "value": 256}]
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)
        manifest = self._manifest()
        manifest["steps"][0]["args"] = [{"type": "bytes4", "value": "0x1234"}]
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
