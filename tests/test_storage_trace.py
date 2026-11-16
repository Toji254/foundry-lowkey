from __future__ import annotations

import unittest

from lowkey.storage_trace import normalize_struct_logs


A = "0x" + "11" * 20
B = "0x" + "22" * 20
C = "0x" + "33" * 20
SLOT_A = "0x" + "00" * 31 + "01"
SLOT_B = "0x" + "00" * 31 + "02"
VALUE_1 = "0x" + "00" * 31 + "07"
VALUE_2 = "0x" + "00" * 31 + "09"


def word(address: str) -> str:
    return "0x" + ("0" * 24) + address[2:]


def call_stack(target: str) -> list[str]:
    # CALL stack is shown bottom-to-top; target is the second word from top.
    return ["0x0", "0x0", "0x0", "0x0", "0x0", word(target), "0x0"]


class StorageTraceTests(unittest.TestCase):
    def test_attributes_sload_and_sstore_to_nested_call_frame(self):
        trace = {
            "type": "CALL", "from": A, "to": A, "input": "0x",
            "calls": [{
                "type": "CALL", "from": A, "to": B, "input": "0x",
                "calls": [],
            }],
        }
        logs = [
            {"depth": 1, "op": "SLOAD", "stack": [SLOT_A]},
            {"depth": 1, "op": "CALL", "stack": call_stack(B)},
            {"depth": 2, "op": "SLOAD", "stack": [SLOT_B]},
            {"depth": 2, "op": "POP", "stack": [SLOT_B, VALUE_1]},
            {"depth": 2, "op": "SSTORE", "stack": [VALUE_2, SLOT_B]},
            {"depth": 1, "op": "STOP", "stack": []},
        ]
        report = normalize_struct_logs(trace, logs)
        self.assertTrue(report["supported"], report)
        self.assertEqual(report["access_count"], 3)
        self.assertEqual(report["read_count"], 2)
        self.assertEqual(report["write_count"], 1)
        self.assertEqual(report["frame_storage"]["0"][0]["account"], A)
        self.assertEqual(report["frame_storage"]["1"][0]["account"], B)
        self.assertEqual(report["frame_storage"]["1"][1]["new_value"], VALUE_2)
        self.assertTrue(report["frame_storage"]["1"][1]["is_write"])

    def test_delegatecall_uses_callers_storage_context(self):
        trace = {
            "type": "CALL", "from": A, "to": A,
            "calls": [{"type": "DELEGATECALL", "from": A, "to": C, "calls": []}],
        }
        logs = [
            {"depth": 1, "op": "DELEGATECALL", "stack": call_stack(C)},
            {"depth": 2, "op": "SLOAD", "stack": [SLOT_A]},
            {"depth": 1, "op": "STOP", "stack": []},
        ]
        report = normalize_struct_logs(trace, logs)
        self.assertTrue(report["supported"], report)
        row = report["frame_storage"]["1"][0]
        self.assertEqual(row["account"], A)
        self.assertEqual(row["code_address"], C)
        self.assertEqual(row["frame_id"], "0.1")
        self.assertEqual(row["access_seq"], 0)
        self.assertEqual(row["opcode_index"], 2)

    def test_unmatched_storage_frame_fails_closed(self):
        trace = {"type": "CALL", "from": A, "to": A, "calls": []}
        logs = [
            {"depth": 1, "op": "CALL", "stack": call_stack(B)},
            {"depth": 2, "op": "SLOAD", "stack": [SLOT_B]},
        ]
        report = normalize_struct_logs(trace, logs)
        self.assertFalse(report["supported"])
        self.assertEqual(report["unmapped_storage_accesses"], 1)

    def test_missing_stack_fails_closed(self):
        trace = {"type": "CALL", "from": A, "to": A, "calls": []}
        report = normalize_struct_logs(trace, [{"depth": 1, "op": "SLOAD"}])
        self.assertFalse(report["supported"])
        self.assertEqual(report["unmapped_storage_accesses"], 1)

    def test_step_limit_fails_closed(self):
        trace = {"type": "CALL", "from": A, "to": A, "calls": []}
        report = normalize_struct_logs(
            trace, [{"depth": 1, "op": "STOP", "stack": []}],
            max_steps=1,
        )
        self.assertTrue(report["supported"])
        limited = normalize_struct_logs(
            trace,
            [{"depth": 1, "op": "STOP", "stack": []}, {"depth": 1, "op": "STOP", "stack": []}],
            max_steps=1,
        )
        self.assertFalse(limited["supported"])



    def test_transient_tload_tstore_are_kept_separate_from_persistent_slots(self):
        trace = {"type": "CALL", "from": A, "to": A, "calls": []}
        logs = [
            {"depth": 1, "op": "TSTORE", "stack": [VALUE_2, SLOT_B]},
            {"depth": 1, "op": "TLOAD", "stack": [SLOT_B]},
            {"depth": 1, "op": "POP", "stack": [SLOT_B, VALUE_2]},
            {"depth": 1, "op": "STOP", "stack": []},
        ]
        report = normalize_struct_logs(trace, logs)
        self.assertTrue(report["supported"], report)
        self.assertEqual(report["access_count"], 2)
        self.assertEqual(report["transient_read_count"], 1)
        self.assertEqual(report["transient_write_count"], 1)
        rows = report["frame_storage"]["0"]
        self.assertEqual([row["storage_kind"] for row in rows], ["transient", "transient"])
        self.assertEqual([row["access_type"] for row in rows], ["write", "read"])
        self.assertEqual(rows[0]["new_value"], VALUE_2)
        self.assertEqual(rows[1]["previous_value"], VALUE_2)

    def test_calltracer_child_without_opcode_frame_is_skipped_without_mislabeling_next_child(self):
        trace = {
            "type": "CALL", "from": A, "to": A,
            "calls": [
                {"type": "CALL", "from": A, "to": B, "error": "no executable code", "calls": []},
                {"type": "CALL", "from": A, "to": C, "calls": []},
            ],
        }
        logs = [
            {"depth": 1, "op": "CALL", "stack": call_stack(C)},
            {"depth": 2, "op": "SLOAD", "stack": [SLOT_A]},
            {"depth": 1, "op": "STOP", "stack": []},
        ]
        report = normalize_struct_logs(trace, logs)
        self.assertTrue(report["supported"], report)
        self.assertEqual(report["frame_storage"]["2"][0]["account"], C)

if __name__ == "__main__":
    unittest.main()
