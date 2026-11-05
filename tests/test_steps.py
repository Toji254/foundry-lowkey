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
                {"kind":"call","selector":"0x12345678","args":[
                    {"type":"address","value":"0x2222222222222222222222222222222222222222"},
                    {"type":"uint256","value":1}]},
                {"kind":"read","selector":"0xabcdef01","args":[]},
                {"kind":"expect","target":"0x1111111111111111111111111111111111111111",
                 "selector":"0x12345678","expect":{"count":2,"must_revert":False}},
            ],
        }

    def _root_with_manifest(self, tmp):
        root = pathlib.Path(tmp)
        (root / "steps.json").write_text(json.dumps(self._manifest()), encoding="utf-8")
        return root

    def test_normalizes_typed_calls_and_exports_trace_only_expectations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root_with_manifest(tmp)
            output, normalized = render_manifest(root, root / "steps.json")
            source = output.read_text(encoding="utf-8")
            self.assertEqual(normalized["contract_name"], "ReentrancySteps")
            self.assertLess(source.index("0x12345678"), source.index("0xabcdef01"))
            self.assertIn("abi.encode(address(0x2222222222222222222222222222222222222222), uint256(1))", source)
            self.assertNotIn("_stepCallCount", source)
            expected = json.loads((root / ".audit/steps/ReentrancySteps.expectations.json").read_text())
            self.assertEqual(expected["trace_expectations"], [{
                "step": 3, "target": "0x1111111111111111111111111111111111111111",
                "selector": "0x12345678", "count": 2, "must_revert": False,
            }])
            self.assertIn("proves execution", expected["policy"])

    def test_reenter_is_a_one_shot_native_eth_callback_configuration(self):
        manifest = self._manifest()
        manifest["steps"] = [
            {"kind":"reenter","selector":"0xaabbccdd","args":[]},
            {"kind":"call","selector":"0x12345678","args":[]},
        ]
        normalized = normalize_manifest(manifest)
        body = __import__("lowkey.step_renderer", fromlist=["_step_body"])._step_body(normalized["steps"])
        self.assertIn("_lowkeyReenterTarget = address(", body)
        self.assertIn("_lowkeyReenterCalldata = stepCallback0", body)
        self.assertIn("_lowkeyReenterEnabled = true", body)

    def test_reenter_refuses_optional_multiple_and_untriggered_callbacks(self):
        manifest = self._manifest()
        manifest["steps"] = [
            {"kind":"reenter","selector":"0xaabbccdd","args":[],"optional":True},
            {"kind":"call","selector":"0x12345678","args":[]},
        ]
        with self.assertRaises(RefusalError) as caught:
            normalize_manifest(manifest)
        self.assertEqual(caught.exception.refusal["reason"], "no_capability")

        manifest["steps"] = [
            {"kind":"reenter","selector":"0xaabbccdd","args":[]},
            {"kind":"read","selector":"0x12345678","args":[]},
        ]
        with self.assertRaises(RefusalError) as caught:
            normalize_manifest(manifest)
        self.assertEqual(caught.exception.refusal["reason"], "no_capability")

        manifest["steps"] = [
            {"kind":"reenter","selector":"0xaabbccdd","args":[]},
            {"kind":"reenter","selector":"0x11223344","args":[]},
            {"kind":"call","selector":"0x12345678","args":[]},
        ]
        with self.assertRaises(RefusalError) as caught:
            normalize_manifest(manifest)
        self.assertEqual(caught.exception.refusal["reason"], "no_capability")

    def test_no_argument_selector_has_no_abi_zero_word_appended(self):
        manifest = self._manifest()
        manifest["steps"] = [{"kind":"call","selector":"0x12345678","args":[]}]
        normalized = normalize_manifest(manifest)
        renderer = __import__("lowkey.step_renderer", fromlist=["_step_body"])
        body = renderer._step_body(normalized["steps"])
        self.assertIn("abi.encodePacked(bytes4(0x12345678))", body)
        self.assertNotIn("abi.encode()", body)

    def test_renderer_does_not_overwrite_existing_output_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root_with_manifest(tmp)
            target = root / "test/lowkey/ReentrancySteps.sol"
            target.parent.mkdir(parents=True)
            target.write_text("keep", encoding="utf-8")
            with self.assertRaises(RefusalError) as caught:
                render_manifest(root, root / "steps.json")
            self.assertEqual(caught.exception.refusal["reason"], "out_of_scope")
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_unsupported_step_kinds_fail_closed_with_reason_codes(self):
        for kind, reason in (
            ("flash_borrow","no_capability"),("skew","no_capability"),("warp","backend_unsupported"),
            ("roll","backend_unsupported"),("snapshot","backend_unsupported"),
            ("revert","backend_unsupported"),("assert","no_capability"),
        ):
            with self.subTest(kind=kind):
                manifest = self._manifest()
                manifest["steps"] = [{"kind":kind}]
                with self.assertRaises(RefusalError) as caught:
                    normalize_manifest(manifest)
                self.assertEqual(caught.exception.refusal["reason"], reason)

    def test_tuple_dynamic_bytes_string_and_nested_arrays_refuse_by_name(self):
        for abi_type in ("tuple","bytes","string","address[]","uint256[][]"):
            with self.subTest(abi_type=abi_type):
                manifest = self._manifest()
                manifest["steps"][0]["args"] = [{"type":abi_type,"value":"x"}]
                with self.assertRaises(RefusalError) as caught:
                    normalize_manifest(manifest)
                self.assertEqual(caught.exception.refusal["reason"], "unsupported_abi")
                self.assertIn(abi_type, caught.exception.refusal["detail"])

    def test_malformed_integer_and_width_overflow_refuse(self):
        manifest = self._manifest()
        manifest["steps"][0]["args"] = [{"type":"uint256","value":"not-a-number"}]
        with self.assertRaises(RefusalError) as caught:
            normalize_manifest(manifest)
        self.assertEqual(caught.exception.refusal["reason"], "unsupported_abi")
        manifest["steps"][0]["args"] = [{"type":"uint8","value":256}]
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)

    def test_read_cannot_transfer_eth_and_expect_shape_is_strict(self):
        manifest = self._manifest()
        manifest["steps"][1]["value"] = "1"
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)
        manifest = self._manifest()
        manifest["steps"][2]["expect"]["must_revert"] = "yes"
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)

    def test_unknown_fields_and_bad_selectors_refuse(self):
        manifest = self._manifest()
        manifest["steps"][0]["surprise"] = True
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)
        manifest = self._manifest()
        manifest["steps"][0]["selector"] = "0x1234"
        with self.assertRaises(RefusalError):
            normalize_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
