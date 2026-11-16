import unittest

from lowkey.trace_schema import (
    TRACE_FIELDS,
    TRACE_SCHEMA_VERSION,
    build_trace_event,
    from_legacy_event,
    normalize_calltracer,
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
            "kind": "DelegateCall", "accessor": B, "account": A, "depth": 1,
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

    def test_calltracer_storage_is_declared_only_without_prestate(self):
        event = anvil_trace()[0]
        self.assertEqual(event["storage_support"], "declared_only")
        self.assertIsNone(event["storage"])

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


if __name__ == "__main__":
    unittest.main()
