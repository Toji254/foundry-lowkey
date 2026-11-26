from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest.mock import patch

from lowkey import proxy_engine as pe


class FakeRpc:
    def __init__(self, *, slots=None, code=None, calls=None):
        self.slots = slots or {}
        self.codes = code or {}
        self.calls = calls or {}
        self.block_tag = "0x64"
        self.pinned = {
            "chain_id": 31337,
            "block_number": 100,
            "block_hash": "0x" + "a" * 64,
            "timestamp": 1234,
        }
        self.requested_calls = []

    def pin(self, requested_block=None):
        return dict(self.pinned)

    def code(self, address):
        if address not in self.codes:
            raise pe.ProxyError("missing test bytecode")
        return self.codes[address]

    def storage(self, address, slot):
        if slot not in self.slots:
            raise pe.ProxyError("missing test storage")
        return self.slots[slot]

    def call(self, to, data, caller=pe.SENTINEL_CALLERS[0]):
        self.requested_calls.append((to, data, caller))
        key = (to, data, caller)
        if key in self.calls:
            return self.calls[key]
        if (to, data) in self.calls:
            return self.calls[(to, data)]
        raise pe.ProxyError("call unavailable")

    def verify_snapshot(self):
        return True


def word_address(address):
    return "0x" + "0" * 24 + address[2:].lower()


def dynamic_array(items, address_items=False):
    words = []
    for item in items:
        if address_items:
            words.append("0" * 24 + item[2:].lower())
        else:
            words.append(item[2:].lower().ljust(64, "0"))
    return "0x" + "0" * 63 + "20" + format(len(items), "064x") + "".join(words)


class KeccakTests(unittest.TestCase):
    def test_ethereum_keccak_selectors(self):
        self.assertEqual(pe.function_selector("owner()"), "0x8da5cb5b")
        self.assertEqual(pe.function_selector("proxiableUUID()"), "0x52d1902d")
        self.assertEqual(pe.keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


class SlotAndBytecodeTests(unittest.TestCase):
    def test_slot_decoder_accepts_only_canonical_address_words(self):
        address = "0x" + "12" * 20
        decoded, reason = pe._decode_slot_address(word_address(address))
        self.assertEqual(decoded.lower(), address)
        self.assertIn("canonical", reason)
        decoded, reason = pe._decode_slot_address("0x" + "01" * 12 + address[2:])
        self.assertIsNone(decoded)
        self.assertIn("high", reason)
        self.assertIsNone(pe._decode_slot_address("0x1234")[0])

    def test_erc1167_exact_runtime_matches_and_near_match_does_not(self):
        implementation = "0x" + "34" * 20
        runtime = "0x363d3d373d3d3d363d73" + implementation[2:] + "5af43d82803e903d91602b57fd5bf3"
        self.assertEqual(pe._minimal_clone_implementation(runtime), implementation)
        self.assertIsNone(pe._minimal_clone_implementation(runtime + "00"))

    def test_opcode_scan_skips_push_payload(self):
        # PUSH4 payload contains f4 but the instruction stream has no DELEGATECALL.
        self.assertFalse(pe._has_opcode("0x63f40000000000", 0xF4))
        self.assertTrue(pe._has_opcode("0x6000f4", 0xF4))


class InspectionTests(unittest.TestCase):
    def _slots(self, implementation=None, beacon=None, admin=None):
        return {
            pe.EIP1967_IMPLEMENTATION_SLOT: word_address(implementation or pe.ZERO_ADDRESS),
            pe.EIP1967_BEACON_SLOT: word_address(beacon or pe.ZERO_ADDRESS),
            pe.EIP1967_ADMIN_SLOT: word_address(admin or pe.ZERO_ADDRESS),
        }

    def test_implementation_slot_is_not_mislabeled_as_uups(self):
        target = "0x" + "11" * 20
        implementation = "0x" + "22" * 20
        fake = FakeRpc(
            slots=self._slots(implementation=implementation),
            code={target: "0x6000", implementation: "0x6001"},
            calls={(implementation, pe.PROXIABLE_UUID_SELECTOR): "0x" + "00" * 32},
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["architecture"], "ERC1967_IMPLEMENTATION_PROXY")
        self.assertNotIn("UUPS_COMPATIBLE_IMPLEMENTATION", report["upgrade_mechanisms"])
        self.assertEqual(report["checks"]["proxiable_uuid"]["status"], "NO_MATCH")

    def test_uups_uuid_is_a_compatibility_signal_not_a_security_verdict(self):
        target = "0x" + "11" * 20
        implementation = "0x" + "22" * 20
        fake = FakeRpc(
            slots=self._slots(implementation=implementation),
            code={target: "0x6000", implementation: "0x6001"},
            calls={(implementation, pe.PROXIABLE_UUID_SELECTOR): pe.EIP1967_UUID},
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertIn("UUPS_COMPATIBLE_IMPLEMENTATION", report["upgrade_mechanisms"])
        self.assertIn("not proof", report["checks"]["proxiable_uuid"]["note"])

    def test_conflicting_implementation_and_beacon_slots_are_not_silently_resolved(self):
        target = "0x" + "11" * 20
        implementation = "0x" + "22" * 20
        beacon = "0x" + "33" * 20
        fake = FakeRpc(
            slots=self._slots(implementation=implementation, beacon=beacon),
            code={target: "0x6000"},
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["architecture"], "CONFLICTING_EIP1967_SLOTS")
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertEqual(report["slot_candidates"]["implementation"], implementation)
        self.assertTrue(any("no routing choice was guessed" in item for item in report["warnings"]))

    def test_slot_read_failure_is_unverified_not_a_direct_contract_verdict(self):
        target = "0x" + "11" * 20
        fake = FakeRpc(
            slots={
                pe.EIP1967_IMPLEMENTATION_SLOT: word_address(pe.ZERO_ADDRESS),
                # Beacon read deliberately missing.
                pe.EIP1967_ADMIN_SLOT: word_address(pe.ZERO_ADDRESS),
            },
            code={target: "0x6000"},
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["status"], "UNVERIFIED")
        self.assertEqual(report["architecture"], "UNVERIFIED_EIP1967")

    def test_beacon_caller_dependence_is_reported(self):
        target = "0x" + "11" * 20
        beacon = "0x" + "33" * 20
        impl_a = "0x" + "44" * 20
        impl_b = "0x" + "55" * 20
        selector = pe.function_selector("implementation()")
        fake = FakeRpc(
            slots=self._slots(beacon=beacon),
            code={target: "0x6000", beacon: "0x6001"},
            calls={
                (beacon, selector, pe.SENTINEL_CALLERS[0]): word_address(impl_a),
                (beacon, selector, pe.SENTINEL_CALLERS[1]): word_address(impl_b),
            },
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["architecture"], "ERC1967_BEACON_PROXY")
        self.assertEqual(report["checks"]["beacon_caller_independence"], "CALLER_DEPENDENT")
        self.assertEqual(report["status"], "REVIEW_REQUIRED")

    def test_coherent_diamond_loupe_is_distinguished_from_generic_delegatecall(self):
        target = "0x" + "11" * 20
        facet = "0x" + "22" * 20
        facet_selector = "0x12345678"
        fake = FakeRpc(
            slots=self._slots(),
            code={target: "0x6000", facet: "0x6001"},
            calls={
                (target, pe.DIAMOND_FACET_ADDRESSES): dynamic_array([facet], address_items=True),
                (target, pe.DIAMOND_FACET_SELECTORS + facet[2:].rjust(64, "0")): dynamic_array([facet_selector]),
            },
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["architecture"], "DIAMOND_LOUPE_CONFIRMED")
        self.assertEqual(report["checks"]["diamond_loupe"]["facet_count"], 1)

    def test_direct_contract_is_unclassified_not_proven_safe(self):
        target = "0x" + "11" * 20
        fake = FakeRpc(
            slots=self._slots(),
            code={target: "0x6000"},
        )
        with patch.object(pe, "_diamond_loupe", return_value=None), patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["architecture"], "DIRECT_OR_UNKNOWN")
        self.assertEqual(report["status"], "UNCLASSIFIED")
        self.assertTrue(any("does not exclude" in item for item in report["warnings"]))


class StorageLayoutTests(unittest.TestCase):
    def setUp(self):
        self.reference = {
            "storageLayout": {
                "storage": [
                    {"label": "owner", "slot": "0", "offset": 0, "type": "t_address"},
                    {"label": "balance", "slot": "1", "offset": 0, "type": "t_uint256"},
                ],
                "types": {
                    "t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"},
                    "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
                },
            }
        }

    def test_append_only_layout_is_compatible_candidate(self):
        candidate = {
            "storageLayout": {
                "storage": self.reference["storage"] + [
                    {"label": "nonce", "slot": "2", "offset": 0, "type": "t_uint256"}
                ],
                "types": self.reference["storageLayout"]["types"],
            }
        }
        report = pe.compare_storage_layouts(self.reference, candidate)
        self.assertEqual(report["status"], "COMPATIBLE_CANDIDATE")
        self.assertTrue(report["compatible_candidate"])
        self.assertEqual(len(report["additions"]), 1)

    def test_reordered_variables_are_incompatible(self):
        candidate = {
            "storageLayout": {
                "storage": [
                    {"label": "owner", "slot": "1", "offset": 0, "type": "t_address"},
                    {"label": "balance", "slot": "0", "offset": 0, "type": "t_uint256"},
                ],
                "types": self.reference["storageLayout"]["types"],
            }
        }
        report = pe.compare_storage_layouts(self.reference, candidate)
        self.assertEqual(report["status"], "INCOMPATIBLE")
        self.assertTrue(report["breaking"])

    def test_storage_gap_never_receives_an_automatic_green(self):
        reference = {
            "storageLayout": {
                "storage": [{"label": "__gap", "slot": "1", "offset": 0, "type": "t_gap"}],
                "types": {"t_gap": {"encoding": "inplace", "label": "uint256[50]", "numberOfBytes": "1600"}},
            }
        }
        candidate = reference
        report = pe.compare_storage_layouts(reference, candidate)
        self.assertEqual(report["status"], "INCONCLUSIVE")
        self.assertFalse(report["compatible_candidate"])

    def test_missing_layout_is_inconclusive(self):
        report = pe.compare_storage_layouts({}, {})
        self.assertEqual(report["status"], "INCONCLUSIVE")


class AuditPlanTests(unittest.TestCase):
    def test_attack_plan_never_claims_execution(self):
        report = {"target": "0x" + "11" * 20, "architecture": "ERC1967_IMPLEMENTATION_PROXY", "snapshot": {"block_number": 1}}
        plan = pe.build_attack_plan(report)
        self.assertEqual(plan["status"], "HYPOTHESES_ONLY")
        self.assertFalse(plan["executed"])
        self.assertTrue(all(item["status"] == "NOT_EXECUTED" for item in plan["scenarios"]))

    def test_source_scanner_emits_anchors_without_claiming_ast_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text(
                "contract Vault {\n function _authorizeUpgrade(address) internal {}\n }\n",
                encoding="utf-8",
            )
            findings = pe.scan_sources(root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["signal"], "uups_authorization_hook")
        self.assertEqual(findings[0]["evidence_type"], "SOURCE_PATTERN")


if __name__ == "__main__":
    unittest.main()
