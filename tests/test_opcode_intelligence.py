import importlib.util
import contextlib
import io
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
sys.path.insert(0, str(LOWKEY))
spec = importlib.util.spec_from_file_location("opcode_under_test", LOWKEY / "opcode_intelligence.py")
opcode = importlib.util.module_from_spec(spec)
spec.loader.exec_module(opcode)


class OpcodeIntelligenceTests(unittest.TestCase):
    def test_prague_pectra_profile_is_distinct_from_cancun(self):
        result = opcode.opcode_spec("PUSH0", fork="pectra")
        self.assertEqual(result["fork"], "prague")
        self.assertEqual(result["status"], "ACTIVE")
        self.assertEqual(opcode.opcode_spec("TLOAD", fork="prague")["fork"], "prague")

    def test_fusaka_alias_and_clz(self):
        result = opcode.opcode_spec(0x1E, fork="fusaka")
        self.assertEqual((result["mnemonic"], result["fork"], result["status"]), ("CLZ", "osaka", "ACTIVE"))
        self.assertEqual((result["pops"], result["pushes"]), (1, 1))

    def test_clz_not_active_before_osaka(self):
        self.assertEqual(opcode.opcode_spec("CLZ", fork="cancun")["status"], "NOT_ACTIVE_IN_FORK")

    def test_difficulty_name_changes_after_paris(self):
        self.assertEqual(opcode.opcode_spec(0x44, fork="london")["mnemonic"], "DIFFICULTY")
        self.assertEqual(opcode.opcode_spec(0x44, fork="paris")["mnemonic"], "PREVRANDAO")

    def test_push0_requires_shanghai(self):
        self.assertEqual(opcode.opcode_spec(0x5F, fork="london")["status"], "NOT_ACTIVE_IN_FORK")
        self.assertEqual(opcode.opcode_spec("PUSH0", fork="shanghai")["status"], "ACTIVE")
        self.assertEqual(opcode.opcode_spec("PUSH0", fork="cancun")["status"], "ACTIVE")

    def test_preview_opcodes_are_not_active_on_mainnet_profile(self):
        for byte in (0x4B, 0xE6, 0xE7, 0xE8):
            self.assertEqual(opcode.opcode_spec(byte, fork="osaka")["status"], "UNRECOGNIZED")

    def test_preview_profile_keeps_existing_opcodes_active(self):
        self.assertEqual(opcode.opcode_spec("SLOTNUM", fork="glamsterdam-preview")["status"], "PREVIEW_ONLY")
        self.assertEqual(opcode.opcode_spec("DUPN", fork="glamsterdam-preview")["status"], "PREVIEW_ONLY")
        self.assertEqual(opcode.opcode_spec("CLZ", fork="glamsterdam-preview")["status"], "ACTIVE")
        self.assertEqual(opcode.opcode_spec("ADD", fork="glamsterdam-preview")["status"], "ACTIVE")

    def test_dynamic_ranges_and_stack_effects(self):
        self.assertEqual((opcode.opcode_spec("PUSH32")["pops"], opcode.opcode_spec("PUSH32")["pushes"]), (0, 1))
        self.assertEqual((opcode.opcode_spec("DUP16")["pops"], opcode.opcode_spec("DUP16")["pushes"]), (16, 17))
        self.assertEqual((opcode.opcode_spec("SWAP16")["pops"], opcode.opcode_spec("SWAP16")["pushes"]), (17, 17))
        self.assertEqual((opcode.opcode_spec("LOG4")["pops"], opcode.opcode_spec("LOG4")["pushes"]), (6, 0))

    def test_unknown_opcode_stays_unrecognized(self):
        result = opcode.opcode_spec(0x0C)
        self.assertIsNone(result["mnemonic"])
        self.assertEqual(result["status"], "UNRECOGNIZED")

    def test_decoder_respects_push_and_jumpdest_boundaries(self):
        result = opcode.decode_bytecode("0x60015b5f")
        self.assertTrue(result["supported"])
        self.assertEqual([(x["pc"], x["opcode"]) for x in result["instructions"]],
                         [(0, "PUSH1"), (2, "JUMPDEST"), (3, "PUSH0")])
        self.assertEqual(result["jumpdest_positions"], [2])
        self.assertEqual(result["instructions"][0]["immediate_data"], "0x01")

    def test_truncated_push_is_not_zero_filled(self):
        result = opcode.decode_bytecode("0x61ff")
        row = result["instructions"][0]
        self.assertEqual(row["status"], "TRUNCATED_IMMEDIATE")
        self.assertEqual(row["immediate_data"], "0xff")
        self.assertFalse(row["immediate_complete"])
        self.assertNotIn("immediate_value", row)

    def test_preview_dupn_decodes_operand_and_jumpdest(self):
        result = opcode.decode_bytecode("0xe6805b", fork="glamsterdam-preview")
        self.assertEqual(result["instructions"][0]["opcode"], "DUPN")
        self.assertEqual(result["instructions"][0]["stack_depth_operand"], 17)
        self.assertEqual(result["instructions"][1]["opcode"], "JUMPDEST")
        self.assertEqual(result["jumpdest_positions"], [2])

    def test_invalid_preview_immediate_does_not_mask_jumpdest(self):
        result = opcode.decode_bytecode("0xe75b", fork="glamsterdam-preview")
        self.assertEqual(result["instructions"][0]["status"], "INVALID_IMMEDIATE")
        self.assertEqual(result["instructions"][0]["instruction_bytes"], 1)
        self.assertEqual(result["instructions"][1]["opcode"], "JUMPDEST")
        self.assertEqual(result["jumpdest_positions"], [1])

    def test_invalid_exchange_immediate_does_not_mask_following_opcode(self):
        result = opcode.decode_bytecode("0xe852", fork="glamsterdam-preview")
        self.assertEqual(result["instructions"][0]["status"], "INVALID_IMMEDIATE")
        self.assertEqual(result["instructions"][1]["opcode"], "MSTORE")

    def test_malformed_bytecode_is_rejected(self):
        for value in ("", "6000", "0x0", "0xgg", "0x600"):
            self.assertFalse(opcode.decode_bytecode(value)["supported"])

    def test_structlogs_create_separate_opcode_step_v1(self):
        logs = [
            {"pc": "0x0", "op": "PUSH1", "depth": 1, "gas": "0x64", "gasCost": "0x3", "stack": []},
            {"pc": "0x2", "op": "PUSH1", "depth": 1, "gas": 97, "gasCost": 3},
            {"pc": "0x4", "op": "ADD", "depth": 1, "gas": 94, "gasCost": 3, "stack": ["0x1", "0x2"]},
        ]
        result = opcode.normalize_struct_logs(logs, bytecode="0x6001600201", include_stack=True)
        self.assertTrue(result["supported"])
        self.assertEqual((result["schema"], result["schema_version"]), ("OpcodeTrace", 1))
        self.assertEqual(result["step_count"], 3)
        self.assertEqual(result["steps"][0]["schema"], "OpcodeStep")
        self.assertTrue(result["steps"][0]["stack_available"])
        self.assertEqual(result["steps"][0]["stack_depth"], 0)
        self.assertFalse(result["steps"][1]["stack_available"])
        self.assertIsNone(result["steps"][1]["stack_depth"])
        self.assertEqual(result["steps"][2]["stack_words"][0], "0x" + "0" * 63 + "1")
        self.assertIsNone(result["steps"][2]["call_frame_seq"])

    def test_missing_stack_differs_from_empty_stack(self):
        result = opcode.normalize_struct_logs([
            {"pc": 0, "op": "STOP", "depth": 1},
            {"pc": 1, "op": "STOP", "depth": 1, "stack": []},
        ])
        self.assertFalse(result["steps"][0]["stack_available"])
        self.assertTrue(result["steps"][1]["stack_available"])
        self.assertEqual(result["steps"][1]["stack_depth"], 0)

    def test_unknown_trace_opcode_is_preserved(self):
        result = opcode.normalize_struct_logs([{"pc": 0, "op": "FUTURE_OPCODE", "depth": 1}])
        self.assertEqual(result["steps"][0]["opcode"], "FUTURE_OPCODE")
        self.assertEqual(result["steps"][0]["opcode_status"], "UNRECOGNIZED")
        self.assertEqual(result["warning_count"], 1)

    def test_bytecode_opcode_mismatch_is_flagged(self):
        result = opcode.normalize_struct_logs(
            [{"pc": 0, "op": "ADD", "depth": 1}], bytecode="0x6001"
        )
        self.assertEqual(result["steps"][0]["opcode_status"], "BYTECODE_MISMATCH")

    def test_non_instruction_pc_is_flagged(self):
        result = opcode.normalize_struct_logs(
            [{"pc": 1, "op": "ADD", "depth": 1}], bytecode="0x6001"
        )
        self.assertEqual(result["steps"][0]["opcode_status"], "PC_NOT_INSTRUCTION_BOUNDARY")

    def test_malformed_stack_is_unavailable_not_fabricated(self):
        result = opcode.normalize_struct_logs([
            {"pc": 0, "op": "ADD", "depth": 1, "stack": ["not-a-word"]}
        ])
        self.assertTrue(result["supported"])
        self.assertFalse(result["steps"][0]["stack_available"])
        self.assertIsNone(result["steps"][0]["stack_words"])
        self.assertEqual(result["warnings"][0]["reason"], "MALFORMED_STACK")

    def test_invalid_pc_and_depth_fail_closed(self):
        for row in (
            {"pc": -1, "op": "STOP", "depth": 1},
            {"pc": 0, "op": "STOP", "depth": 1025},
            {"pc": "bad", "op": "STOP", "depth": 1},
        ):
            result = opcode.normalize_struct_logs([row])
            self.assertFalse(result["supported"])
            self.assertEqual(result["steps"], [])

    def test_step_limit_is_enforced(self):
        result = opcode.normalize_struct_logs(
            [{"pc": 0, "op": "STOP", "depth": 1}] * 2, max_steps=1
        )
        self.assertFalse(result["supported"])
        self.assertIn("safety limit", result["reason"])

    def test_stack_limit_is_enforced(self):
        result = opcode.normalize_struct_logs([
            {"pc": 0, "op": "STOP", "depth": 1, "stack": ["0x1"] * 1025}
        ])
        self.assertFalse(result["supported"])
        self.assertIn("stack bound", result["reason"])

    def test_memory_capture_is_bounded_and_missing_is_preserved(self):
        result = opcode.normalize_struct_logs([
            {"pc": 0, "op": "STOP", "depth": 1, "memory": ["0x1"] * 4097},
            {"pc": 1, "op": "STOP", "depth": 1},
        ], include_memory=True)
        self.assertEqual(result["steps"][0]["memory_capture_status"], "LIMIT_EXCEEDED")
        self.assertEqual(result["steps"][0]["memory_words"], 4097)
        self.assertFalse(result["steps"][1]["memory_available"])
        self.assertIsNone(result["steps"][1]["memory_words"])

    def test_cli_spec_and_bytecode_modes_are_explicit_and_read_only(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = opcode.run_cli(["--spec", "PUSH0", "--fork", "shanghai", "--learn"])
        self.assertEqual(code, 0)
        self.assertIn('"mnemonic": "PUSH0"', output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = opcode.run_cli(["--bytecode", "0x60015b", "--fork", "shanghai"])
        self.assertEqual(code, 0)
        self.assertIn('"jumpdest_positions": [\n    2', output.getvalue())

    def test_opcode_trace_is_not_traceevent_v2(self):
        result = opcode.normalize_struct_logs([{"pc": 0, "op": "STOP", "depth": 1}])
        self.assertEqual(result["schema"], "OpcodeTrace")
        self.assertEqual(result["steps"][0]["schema"], "OpcodeStep")
        self.assertNotIn("TraceEvent", result["steps"][0])


if __name__ == "__main__":
    unittest.main()
