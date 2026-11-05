import unittest

from lowkey.forge_state_diff import normalize_forge_state_diff


TARGET = "0x" + "1" * 40
ATTACKER = "0x" + "2" * 40
WRAPPER = "0x" + "3" * 40
CODE_HASH = "0x" + "a" * 64


def artifact():
    return {
        "schema_version": 1,
        "backend": "forge-state-diff",
        "chain_id": 1,
        "block_number": 20_000_000,
        "target_address": TARGET,
        "target_code_hash": CODE_HASH,
        "accesses": [
            {
                "kind": 0, "account": TARGET, "accessor": WRAPPER,
                "depth": 1, "value": 0, "data": "0x12345678",
                "old_balance": 1000, "new_balance": 900,
                "old_nonce": 1, "new_nonce": 1, "reverted": False,
                "storage_accesses": [{
                    "account": TARGET, "slot": 0,
                    "previous_value": 5, "new_value": 0,
                    "is_write": True, "reverted": False,
                }],
            },
            {
                "kind": 0, "account": WRAPPER, "accessor": ATTACKER,
                "depth": 0, "value": 0, "data": "0xabcdef01",
                "old_balance": 50, "new_balance": 150,
                "old_nonce": 1, "new_nonce": 1, "reverted": False,
                "storage_accesses": [],
            },
        ],
    }


class ForgeStateDiffTests(unittest.TestCase):
    def test_unwraps_foundry_serialize_object_keys(self):
        value = artifact()
        value["accesses"] = [
            {"lowkey.access.0": {
                **value["accesses"][0],
                "storage_accesses": [
                    {"lowkey.storage.0.0": value["accesses"][0]["storage_accesses"][0]}
                ],
            }},
            {"lowkey.access.1": value["accesses"][1]},
        ]
        wrapped = {"lowkey.root": {
            key: item for key, item in value.items() if key != "accesses"
        }}
        wrapped["lowkey.root"]["accesses"] = value["accesses"]
        result = normalize_forge_state_diff(wrapped, expected_target=TARGET)
        self.assertEqual(len(result["calls"]), 2)
        self.assertTrue(result["storage_accesses"][0]["is_write"])

    def test_normalizes_ordered_calls_and_storage_slots(self):
        result = normalize_forge_state_diff(artifact(), expected_target=TARGET)
        self.assertEqual(result["backend"], "forge-state-diff")
        self.assertEqual(result["chain_id"], 1)
        self.assertEqual(result["block_number"], 20_000_000)
        self.assertEqual(result["calls"][0]["to"], TARGET)
        self.assertEqual(result["calls"][0]["from"], WRAPPER)
        self.assertTrue(result["storage_accesses"][0]["is_write"])
        self.assertEqual(result["prestate"][0]["storage"][0]["slot"], "0x" + "0" * 64)

    def test_rejects_wrong_target(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            normalize_forge_state_diff(artifact(), expected_target=WRAPPER)

    def test_rejects_artifact_without_target_call(self):
        value = artifact()
        value["accesses"][0]["account"] = WRAPPER
        with self.assertRaisesRegex(ValueError, "never called"):
            normalize_forge_state_diff(value, expected_target=TARGET)

    def test_keeps_reverted_access_as_reverted_evidence(self):
        value = artifact()
        value["accesses"][0]["reverted"] = True
        result = normalize_forge_state_diff(value, expected_target=TARGET)
        self.assertTrue(result["calls"][0]["reverted"])
        self.assertEqual(result["calls"][0]["error"], "reverted")

    def test_rejects_missing_code_hash(self):
        value = artifact()
        value.pop("target_code_hash")
        with self.assertRaisesRegex(ValueError, "target_code_hash"):
            normalize_forge_state_diff(value, expected_target=TARGET)


if __name__ == "__main__":
    unittest.main()
