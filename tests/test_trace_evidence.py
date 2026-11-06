import unittest

from lowkey.trace_evidence import build_trace_event, normalize_rpc_trace_events


class TraceEvidenceTests(unittest.TestCase):
    def test_rpc_event_has_selector_and_explicit_unknown_storage(self):
        event = normalize_rpc_trace_events([{
            "type": "DELEGATECALL", "from": "0x" + "1" * 40,
            "to": "0x" + "2" * 40, "depth": 2, "value": "0x0",
            "input": "0xaabbccdd0102", "error": "",
        }])[0]
        self.assertEqual(event["kind"], "DelegateCall")
        self.assertEqual(event["selector"], "0xaabbccdd")
        self.assertEqual(event["value"], 0)
        self.assertFalse(event["reverted"])
        self.assertIsNone(event["storage"])

    def test_missing_fields_remain_null_instead_of_becoming_zero(self):
        event = build_trace_event(
            index=0, kind="CALL", accessor=None, account=None, depth=None,
            value=None, reverted=None, input_data=None, storage=None,
            source_backend="unknown-backend",
        )
        self.assertIsNone(event["accessor"])
        self.assertIsNone(event["account"])
        self.assertIsNone(event["depth"])
        self.assertIsNone(event["value"])
        self.assertIsNone(event["reverted"])
        self.assertIsNone(event["selector"])
        self.assertIsNone(event["input"])
        self.assertIsNone(event["storage"])

    def test_rejects_malformed_calldata_and_addresses(self):
        with self.assertRaisesRegex(ValueError, "calldata"):
            normalize_rpc_trace_events([{"input": "0x123"}])
        with self.assertRaisesRegex(ValueError, "accessor"):
            normalize_rpc_trace_events([{
                "from": "not-an-address", "to": "0x" + "2" * 40,
                "input": "0x12345678",
            }])


if __name__ == "__main__":
    unittest.main()
