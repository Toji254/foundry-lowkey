import unittest

from lowkey.trace_schema import (
    TRACE_FIELDS,
    TRACE_SCHEMA_VERSION,
    build_trace_event,
    from_legacy_event,
    normalize_calltracer,
    normalize_prestate_diff,
    normalize_opcode_storage,
    flatten_calltracer,
    normalize_forge_events,
)
from lowkey.trace_parity import compare_trace_events


A = "0x" + "1" * 40
B = "0x" + "2" * 40
SLOT = "0x" + "0" * 64
WORD1 = "0x" + "1" * 64
WORD2 = "0x" + "2" * 64


def forge_trace():
    return normalize_forge_events([
        {
            "kind": "Call", "accessor": A, "account": B, "depth": 0,
            "value": 0, "input": "0x12345678", "reverted": False,
            "storage": [{
                "account": B, "slot": SLOT, "previous_value": WORD1,
                "new_value": WORD2, "is_write": True, "reverted": False,
            }],
        },
        {
            "kind": "DelegateCall", "accessor": A, "account": A, "depth": 1,
            "value": 0, "input": "0xaabbccdd", "reverted": False,
            "storage": [],
        },
    ])


def anvil_trace():
    return normalize_calltracer([
        {
            "type": "CALL", "from": A, "to": B, "depth": 0,
            "value": "0x0", "input": "0x12345678",
        },
        {
            "type": "DELEGATECALL", "from": B, "to": A, "depth": 1,
            "value": "0x0", "input": "0xaabbccdd",
        },
    ])


class TraceSchemaV2Tests(unittest.TestCase):
    def test_trace_parity_imports_when_installed_as_standalone_sibling_modules(self):
        import os
        import pathlib
        import subprocess
        import sys
        import tempfile

        module_dir = pathlib.Path(__file__).resolve().parents[1] / "lowkey"
        with tempfile.TemporaryDirectory() as temporary:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(module_dir)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import trace_parity; assert callable(trace_parity.compare_trace_events)",
                ],
                cwd=temporary,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_canonical_event_has_exact_contract_fields(self):
        event = forge_trace()[0]
        self.assertEqual(tuple(event.keys()), TRACE_FIELDS)
        self.assertEqual(TRACE_SCHEMA_VERSION, 2)
        self.assertEqual(event["seq"], 0)
        self.assertEqual(event["backend"], "forge-state-diff")
        self.assertEqual(event["kind"], "Call")
        self.assertEqual(event["selector"], "0x12345678")
        self.assertEqual(event["calldata"], "0x12345678")
        self.assertEqual(event["storage_support"], "exact")

    def test_forge_depth_is_normalized_relative_to_root(self):
        events = normalize_forge_events([
            {"kind": "Call", "accessor": A, "account": B, "depth": 1,
             "value": 0, "input": "0x12345678", "reverted": False, "storage": []},
            {"kind": "DelegateCall", "accessor": B, "account": A, "depth": 2,
             "value": 0, "input": "0xaabbccdd", "reverted": False, "storage": []},
        ])
        self.assertEqual([event["depth"] for event in events], [0, 1])

    def test_missing_fields_stay_null_not_zero_or_false(self):
        event = build_trace_event(
            seq=0, backend="anvil-calltracer", kind="Call",
            accessor=None, account=None, depth=None, value=None,
            reverted=None, calldata=None, storage=None,
            storage_support="declared_only",
        )
        self.assertIsNone(event["accessor"])
        self.assertIsNone(event["account"])
        self.assertIsNone(event["depth"])
        self.assertIsNone(event["value"])
        self.assertIsNone(event["selector"])
        self.assertIsNone(event["calldata"])
        self.assertIsNone(event["reverted"])
        self.assertIsNone(event["storage"])

    def test_prestate_diff_normalizes_changed_slots_without_call_frame_claims(self):
        rows = normalize_prestate_diff({
            "pre": {B: {"storage": {SLOT: WORD1}}},
            "post": {B: {"storage": {SLOT: WORD2}}},
        })
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["account"], B)
        self.assertEqual(rows[0]["slot"], SLOT)
        self.assertEqual(rows[0]["previous_value"], WORD1)
        self.assertEqual(rows[0]["new_value"], WORD2)
        self.assertTrue(rows[0]["is_write"])
        events = normalize_calltracer(
            [
                {"type": "CALL", "from": A, "to": B, "depth": 0,
                 "value": "0x0", "input": "0x12345678"},
                {"type": "DELEGATECALL", "from": B, "to": A, "depth": 1,
                 "value": "0x0", "input": "0xaabbccdd"},
            ],
            storage_support="partial",
            partial_storage={0: rows},
        )
        self.assertEqual(events[0]["storage_support"], "partial")
        self.assertEqual(events[0]["storage"], rows)
        self.assertEqual(events[1]["storage_support"], "declared_only")
        self.assertIsNone(events[1]["storage"])

    def test_prestate_diff_does_not_invent_missing_zero_values(self):
        rows = normalize_prestate_diff({
            "pre": {B: {"storage": {SLOT: WORD1}}},
            "post": {B: {"storage": {}}},
        })
        self.assertEqual(rows[0]["previous_value"], WORD1)
        self.assertIsNone(rows[0]["new_value"])
        self.assertIsNone(rows[0]["is_write"])

    def test_calltracer_storage_is_declared_only_without_prestate(self):
        event = anvil_trace()[0]
        self.assertEqual(event["storage_support"], "declared_only")
        self.assertIsNone(event["storage"])

    def test_nested_calltracer_tree_flattens_preorder_with_depth(self):
        flattened = flatten_calltracer({
            "type": "CALL", "from": A, "to": B,
            "value": "0x0", "input": "0x12345678",
            "calls": [{
                "type": "DELEGATECALL", "from": B, "to": A,
                "input": "0xaabbccdd",
                "calls": [{
                    "type": "STATICCALL", "from": A, "to": B,
                    "input": "0xdeadbeef",
                }],
            }],
        })
        self.assertEqual([row["type"] for row in flattened], ["CALL", "DELEGATECALL", "STATICCALL"])
        self.assertEqual([row["depth"] for row in flattened], [0, 1, 2])
        normalized = normalize_calltracer({
            "type": "CALL", "from": A, "to": B,
            "value": "0x0", "input": "0x12345678",
            "calls": [{"type": "DELEGATECALL", "from": B, "to": A, "input": "0xaabbccdd"}],
        })
        self.assertEqual([row["seq"] for row in normalized], [0, 1])
        self.assertEqual(normalized[1]["depth"], 1)
        # callTracer.from is the proxy issuing DELEGATECALL, while the
        # implementation's Solidity msg.sender remains the root actor.
        self.assertEqual(normalized[1]["accessor"], A)

    def test_prestate_storage_is_explicitly_partial(self):
        rows = [{"account": B, "slot": SLOT, "value": WORD1, "post_value": WORD2}]
        events = normalize_calltracer(
            [{"type": "CALL", "from": A, "to": B, "depth": 0,
              "value": "0x0", "input": "0x12345678"}],
            storage_support="partial",
            partial_storage={0: rows},
        )
        self.assertEqual(events[0]["storage_support"], "partial")
        self.assertEqual(events[0]["storage"][0]["previous_value"], WORD1)
        self.assertEqual(events[0]["storage"][0]["new_value"], WORD2)

    def test_transaction_level_prestate_is_not_assigned_to_nested_frames(self):
        calls = [
            {"type": "CALL", "from": A, "to": B, "depth": 0,
             "value": "0x0", "input": "0x12345678"},
            {"type": "DELEGATECALL", "from": B, "to": A, "depth": 1,
             "value": "0x0", "input": "0xaabbccdd"},
        ]
        events = normalize_calltracer(
            calls,
            storage_support="partial",
            partial_storage={0: [{
                "account": B, "slot": SLOT, "value": WORD1, "post_value": WORD2
            }]},
        )
        self.assertEqual(events[0]["storage_support"], "partial")
        self.assertEqual(events[0]["storage"][0]["slot"], SLOT)
        self.assertEqual(events[1]["storage_support"], "declared_only")
        self.assertIsNone(events[1]["storage"])

    def test_legacy_event_adapter_preserves_unknowns(self):
        event = from_legacy_event({
            "index": 3, "kind": "Call", "accessor": A, "account": B,
            "depth": 0, "value": 0, "selector": "0x12345678",
            "input": "0x12345678", "reverted": False,
            "storage": None, "source_backend": "anvil-calltracer",
        }, seq=0)
        self.assertEqual(event["seq"], 0)
        self.assertEqual(event["calldata"], "0x12345678")
        self.assertEqual(event["storage_support"], "declared_only")
        self.assertIsNone(event["storage"])

    def test_unsupported_kinds_are_not_silently_remapped(self):
        with self.assertRaisesRegex(ValueError, "Unsupported trace kind"):
            build_trace_event(
                seq=0, backend="anvil-calltracer", kind="CALLCODE",
                calldata="0x12345678", storage=None,
                storage_support="declared_only",
            )

    def test_parity_matches_call_tree_but_reports_storage_degradation(self):
        report = compare_trace_events(forge_trace(), anvil_trace())
        self.assertEqual(report["status"], "MATCHED")
        self.assertTrue(report["call_tree_matched"])
        self.assertEqual(report["storage_parity"], "degraded")
        self.assertEqual(report["storage_support"]["forge"], ["exact"])
        self.assertEqual(report["storage_support"]["anvil"], ["declared_only"])

    def test_parity_does_not_treat_null_as_a_match(self):
        forge = forge_trace()
        anvil = anvil_trace()
        anvil[0]["depth"] = None
        report = compare_trace_events(forge, anvil)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["unknowns"][0]["dimension"], "depth")

    def test_parity_detects_real_calldata_mismatch(self):
        forge = forge_trace()
        anvil = anvil_trace()
        anvil[0]["calldata"] = "0x99999999"
        anvil[0]["selector"] = "0x99999999"
        report = compare_trace_events(forge, anvil)
        self.assertEqual(report["status"], "MISMATCH")
        self.assertEqual({x["dimension"] for x in report["mismatches"]}, {"selector", "calldata"})

    def test_empty_trace_pair_never_returns_a_match(self):
        report = compare_trace_events([], [])
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["unknowns"][0]["dimension"], "event_stream")

    def test_parity_rejects_wrong_backend_labels(self):
        forge = forge_trace()
        forge[0]["backend"] = "anvil-calltracer"
        with self.assertRaisesRegex(ValueError, "must come from forge-state-diff"):
            compare_trace_events(forge, anvil_trace())

    def test_parity_detects_event_count_mismatch(self):
        report = compare_trace_events(forge_trace(), anvil_trace()[:1])
        self.assertEqual(report["status"], "MISMATCH")
        self.assertEqual(report["mismatches"][0]["dimension"], "event_count")


    def test_opcode_logger_captures_ordered_root_reads_and_writes(self):
        call_trace = {
            "type": "CALL", "from": A, "to": B, "input": "0x12345678",
            "value": "0x0", "calls": [],
        }
        opcode_trace = {
            "failed": False,
            "structLogs": [
                {"depth": 1, "pc": 10, "op": "SLOAD", "stack": [SLOT]},
                {"depth": 1, "pc": 11, "op": "ADD", "stack": [WORD1]},
                {"depth": 1, "pc": 12, "op": "SSTORE", "stack": [WORD2, SLOT],
                 "storage": {SLOT[2:]: WORD1}},
                {"depth": 1, "pc": 13, "op": "STOP", "stack": []},
            ],
        }
        result = normalize_opcode_storage(opcode_trace, call_trace)
        self.assertTrue(result["supported"], result.get("reason"))
        self.assertEqual(result["access_count"], 2)
        reads, writes = result["by_frame_index"][0]
        self.assertEqual(reads["account"], B)
        self.assertEqual(reads["access_type"], "read")
        self.assertEqual(reads["read_value"], WORD1)
        self.assertEqual(writes["access_type"], "write")
        self.assertEqual(writes["previous_value"], WORD1)
        self.assertEqual(writes["new_value"], WORD2)
        self.assertEqual([row["access_seq"] for row in (reads, writes)], [0, 1])

        events = normalize_calltracer(
            call_trace, storage_support="exact",
            exact_storage=result["by_frame_index"],
        )
        self.assertEqual(events[0]["storage_support"], "exact")
        self.assertEqual(len(events[0]["storage"]), 2)

    def test_opcode_logger_attributes_delegatecall_to_proxy_storage_context(self):
        implementation = "0x" + "3" * 40
        call_trace = {
            "type": "CALL", "from": A, "to": B, "input": "0x12345678",
            "value": "0x0", "calls": [{
                "type": "DELEGATECALL", "from": B, "to": implementation,
                "input": "0xaabbccdd", "value": "0x0", "calls": [],
            }],
        }
        opcode_trace = {"structLogs": [
            {"depth": 1, "op": "DELEGATECALL",
             "stack": ["0x" + "0" * 24 + implementation[2:], "0x" + "0" * 64]},
            {"depth": 2, "pc": 7, "op": "SLOAD", "stack": [SLOT]},
            {"depth": 2, "op": "STOP", "stack": []},
            {"depth": 1, "op": "STOP", "stack": []},
        ]}
        result = normalize_opcode_storage(opcode_trace, call_trace)
        self.assertTrue(result["supported"], result.get("reason"))
        row = result["by_frame_index"][1][0]
        self.assertEqual(row["account"], B)
        self.assertEqual(row["code_address"], implementation)
        self.assertEqual(row["frame_id"], "0.0")

    def test_opcode_logger_consumes_no_code_sibling_before_nested_call(self):
        target = "0x" + "4" * 40
        no_code = "0x" + "5" * 40
        call_trace = {
            "type": "CALL", "from": A, "to": B, "calls": [
                {"type": "CALL", "from": B, "to": no_code, "calls": []},
                {"type": "CALL", "from": B, "to": target, "calls": []},
            ],
        }
        opcode_trace = {"structLogs": [
            {"depth": 1, "op": "CALL",
             "stack": ["0x" + "0" * 24 + no_code[2:], "0x" + "0" * 64]},
            {"depth": 1, "op": "POP", "stack": []},
            {"depth": 1, "op": "CALL",
             "stack": ["0x" + "0" * 24 + target[2:], "0x" + "0" * 64]},
            {"depth": 2, "op": "SLOAD", "stack": [SLOT]},
            {"depth": 1, "op": "STOP", "stack": []},
        ]}
        result = normalize_opcode_storage(opcode_trace, call_trace)
        self.assertTrue(result["supported"], result.get("reason"))
        self.assertEqual(result["by_frame_index"][1], [])
        self.assertEqual(result["by_frame_index"][2][0]["account"], target)

    def test_opcode_logger_marks_reverted_frame_accesses(self):
        call_trace = {
            "type": "CALL", "from": A, "to": B, "calls": [{
                "type": "CALL", "from": B, "to": "0x" + "6" * 40,
                "error": "execution reverted", "calls": [],
            }],
        }
        child = call_trace["calls"][0]["to"]
        opcode_trace = {"structLogs": [
            {"depth": 1, "op": "CALL",
             "stack": ["0x" + "0" * 24 + child[2:], "0x" + "0" * 64]},
            {"depth": 2, "op": "SSTORE", "stack": [WORD2, SLOT]},
            {"depth": 1, "op": "STOP", "stack": []},
        ]}
        result = normalize_opcode_storage(opcode_trace, call_trace)
        self.assertTrue(result["supported"], result.get("reason"))
        self.assertTrue(result["by_frame_index"][1][0]["reverted"])

    def test_opcode_logger_distinguishes_transient_storage(self):
        call_trace = {
            "type": "CALL", "from": A, "to": B, "calls": [],
        }
        opcode_trace = {"structLogs": [
            {"depth": 1, "op": "TSTORE", "stack": [WORD2, SLOT]},
            {"depth": 1, "op": "TLOAD", "stack": [SLOT]},
            {"depth": 1, "op": "ADD", "stack": [WORD2]},
            {"depth": 1, "op": "STOP", "stack": []},
        ]}
        result = normalize_opcode_storage(opcode_trace, call_trace)
        self.assertTrue(result["supported"], result.get("reason"))
        self.assertEqual(
            [row["storage_kind"] for row in result["by_frame_index"][0]],
            ["transient", "transient"],
        )

    def test_opcode_logger_refuses_unmatched_call_context_and_truncated_traces(self):
        child = "0x" + "7" * 40
        call_trace = {
            "type": "CALL", "from": A, "to": B, "calls": [{
                "type": "CALL", "from": B, "to": child, "calls": [],
            }],
        }
        wrong_target = "0x" + "8" * 40
        mismatch = normalize_opcode_storage({
            "structLogs": [{
                "depth": 1, "op": "CALL",
                "stack": ["0x" + "0" * 24 + wrong_target[2:], "0x" + "0" * 64],
            }],
        }, call_trace)
        self.assertFalse(mismatch["supported"])
        self.assertIn("does not match", mismatch["reason"])
        truncated = normalize_opcode_storage(
            {"structLogs": [{"depth": 1, "op": "STOP", "stack": []}]},
            {"type": "CALL", "from": A, "to": B, "calls": []},
            max_steps=1,
        )
        self.assertFalse(truncated["supported"])
        self.assertIn("step limit", truncated["reason"])

    def test_opcode_storage_can_match_forge_per_access_evidence(self):
        implementation = A
        call_trace = {
            "type": "CALL", "from": A, "to": B, "input": "0x12345678",
            "value": "0x0", "calls": [{
                "type": "DELEGATECALL", "from": B, "to": implementation,
                "input": "0xaabbccdd", "value": "0x0", "calls": [],
            }],
        }
        opcode_trace = {"structLogs": [
            {"depth": 1, "op": "SSTORE", "stack": [WORD2, SLOT],
             "storage": {SLOT[2:]: WORD1}},
            {"depth": 1, "op": "DELEGATECALL",
             "stack": ["0x" + "0" * 24 + implementation[2:], "0x" + "0" * 64]},
            {"depth": 2, "op": "STOP", "stack": []},
            {"depth": 1, "op": "STOP", "stack": []},
        ]}
        observed = normalize_opcode_storage(opcode_trace, call_trace)
        self.assertTrue(observed["supported"], observed.get("reason"))
        anvil = normalize_calltracer(
            call_trace, storage_support="exact",
            exact_storage=observed["by_frame_index"],
        )
        report = compare_trace_events(forge_trace(), anvil)
        self.assertEqual(report["status"], "MATCHED")
        self.assertEqual(report["storage_parity"], "exact_comparable")

    def test_storage_parity_rejects_different_slot_access_sequences(self):
        implementation = "0x" + "9" * 40
        call_trace = {
            "type": "CALL", "from": A, "to": B, "input": "0x12345678",
            "value": "0x0", "calls": [{
                "type": "DELEGATECALL", "from": B, "to": implementation,
                "input": "0xaabbccdd", "value": "0x0", "calls": [],
            }],
        }
        opcode_trace = {"structLogs": [
            {"depth": 1, "op": "SSTORE", "stack": [WORD2, WORD1]},
            {"depth": 1, "op": "DELEGATECALL",
             "stack": ["0x" + "0" * 24 + implementation[2:], "0x" + "0" * 64]},
            {"depth": 2, "op": "STOP", "stack": []},
            {"depth": 1, "op": "STOP", "stack": []},
        ]}
        observed = normalize_opcode_storage(opcode_trace, call_trace)
        self.assertTrue(observed["supported"], observed.get("reason"))
        anvil = normalize_calltracer(
            call_trace, storage_support="exact",
            exact_storage=observed["by_frame_index"],
        )
        report = compare_trace_events(forge_trace(), anvil)
        self.assertEqual(report["status"], "MISMATCH")
        self.assertEqual(report["storage_parity"], "mismatch")
        self.assertEqual(
            report["storage_access_mismatches"][0]["dimension"], "slot"
        )

    def test_storage_value_parity_is_separate_and_fail_closed(self):
        forge = forge_trace()
        anvil = anvil_trace()
        # Give both backends exact per-frame access evidence, but disagree on
        # the write result. A matching call tree must not hide that mismatch.
        anvil[0]["storage_support"] = "exact"
        anvil[0]["storage"] = [{
            "account": B, "slot": SLOT, "previous_value": WORD1,
            "new_value": "0x" + "3" * 64, "is_write": True, "reverted": False,
        }]
        anvil[1]["storage_support"] = "exact"
        anvil[1]["storage"] = []
        report = compare_trace_events(forge, anvil)
        self.assertEqual(report["call_tree_matched"], True)
        self.assertEqual(report["storage_value_parity"], "mismatch")
        self.assertEqual(report["status"], "MISMATCH")


    def test_structlogs_per_access_storage_becomes_exact_anvil_trace_events(self):
        calls = [{
            "type": "CALL", "from": A, "to": B, "depth": 1,
            "value": "0x0", "input": "0x12345678",
            "calls": [{
                "type": "DELEGATECALL", "from": B, "to": A, "depth": 2,
                "value": "0x0", "input": "0xaabbccdd", "calls": [],
            }],
        }]
        access = {
            "account": B, "slot": SLOT, "previous_value": WORD1,
            "new_value": WORD2, "is_write": True, "reverted": False,
            "storage_kind": "persistent", "access_type": "write",
            "opcode": "SSTORE", "frame_id": "0", "access_seq": 0,
            "opcode_index": 5, "pc": 12,
        }
        events = normalize_calltracer(
            calls, per_access_storage={0: [access], 1: []}
        )
        self.assertEqual([event["backend"] for event in events], [
            "anvil-structlog", "anvil-structlog"
        ])
        self.assertEqual([event["storage_support"] for event in events], [
            "exact", "exact"
        ])
        self.assertEqual(events[0]["storage"][0]["account"], B)
        self.assertEqual(events[0]["storage"][0]["opcode"], "SSTORE")
        self.assertEqual(events[1]["storage"], [])

    def test_structlogs_exact_storage_requires_an_explicit_array_for_every_frame(self):
        calls = [
            {"type": "CALL", "from": A, "to": B, "input": "0x12345678", "calls": [
                {"type": "DELEGATECALL", "from": B, "to": A, "input": "0xaabbccdd", "calls": []}
            ]}
        ]
        with self.assertRaisesRegex(ValueError, "every call frame"):
            normalize_calltracer(calls, per_access_storage={0: []})

    def test_exact_structlogs_storage_matches_forge_access_sequences(self):
        calls = [{
            "type": "CALL", "from": A, "to": B, "depth": 0,
            "value": "0x0", "input": "0x12345678",
            "calls": [{
                "type": "DELEGATECALL", "from": B, "to": A, "depth": 1,
                "value": "0x0", "input": "0xaabbccdd", "calls": [],
            }],
        }]
        access = {
            "account": B, "slot": SLOT, "previous_value": WORD1,
            "new_value": WORD2, "is_write": True, "reverted": False,
        }
        anvil = normalize_calltracer(calls, per_access_storage={0: [access], 1: []})
        report = compare_trace_events(forge_trace(), anvil)
        self.assertEqual(report["status"], "MATCHED")
        self.assertEqual(report["storage_parity"], "exact_comparable")
        self.assertEqual(report["storage_value_parity"], "matched")
        self.assertEqual(report["storage_access_mismatches"], [])

    def test_exact_structlogs_storage_rejects_a_different_slot(self):
        calls = [{
            "type": "CALL", "from": A, "to": B, "depth": 0,
            "value": "0x0", "input": "0x12345678",
            "calls": [{
                "type": "DELEGATECALL", "from": B, "to": A, "depth": 1,
                "value": "0x0", "input": "0xaabbccdd", "calls": [],
            }],
        }]
        access = {
            "account": B, "slot": WORD2, "previous_value": WORD1,
            "new_value": WORD2, "is_write": True, "reverted": False,
        }
        anvil = normalize_calltracer(calls, per_access_storage={0: [access], 1: []})
        report = compare_trace_events(forge_trace(), anvil)
        self.assertEqual(report["status"], "MISMATCH")
        self.assertEqual(report["storage_parity"], "mismatch")
        self.assertEqual(report["storage_access_mismatches"][0]["dimension"], "slot")

    def test_exact_storage_access_match_does_not_invent_missing_write_values(self):
        calls = [{
            "type": "CALL", "from": A, "to": B, "depth": 0,
            "value": "0x0", "input": "0x12345678",
            "calls": [{
                "type": "DELEGATECALL", "from": B, "to": A, "depth": 1,
                "value": "0x0", "input": "0xaabbccdd", "calls": [],
            }],
        }]
        access = {
            "account": B, "slot": SLOT, "previous_value": None,
            "new_value": None, "is_write": True, "reverted": False,
        }
        anvil = normalize_calltracer(calls, per_access_storage={0: [access], 1: []})
        report = compare_trace_events(forge_trace(), anvil)
        self.assertEqual(report["storage_parity"], "exact_comparable")
        self.assertEqual(report["storage_value_parity"], "incomplete")
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertTrue(report["storage_value_unknowns"])

if __name__ == "__main__":
    unittest.main()
