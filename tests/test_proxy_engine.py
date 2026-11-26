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
        scoped = (address.lower(), slot.lower())
        if scoped in self.slots:
            return self.slots[scoped]
        if slot in self.slots:
            # Existing tests model the inspected target only. Unknown downstream
            # implementation addresses are direct contracts unless explicitly scoped.
            if address.lower() == ("0x" + "11" * 20).lower():
                return self.slots[slot]
            return word_address(pe.ZERO_ADDRESS)
        raise pe.ProxyError("missing test storage")

    def call(self, to, data, caller=pe.SENTINEL_CALLERS[0]):
        self.requested_calls.append((to, data, caller))
        key = (to, data, caller)
        if key in self.calls:
            value = self.calls[key]
            if isinstance(value, BaseException):
                raise value
            return value
        if (to, data) in self.calls:
            value = self.calls[(to, data)]
            if isinstance(value, BaseException):
                raise value
            return value
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
    return "0x" + "0" * 62 + "20" + format(len(items), "064x") + "".join(words)




class RpcSnapshotTests(unittest.TestCase):
    def test_rpc_reads_use_the_same_explicit_block_tag_and_recheck_hash(self):
        import json

        block_hash = "0x" + "a" * 64
        requests = []

        class Response:
            def __init__(self, payload):
                self.payload = payload
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return json.dumps(self.payload).encode()

        def fake_urlopen(request, timeout):
            payload = json.loads(request.data.decode())
            requests.append(payload)
            method = payload["method"]
            if method == "eth_chainId":
                result = "0x7a69"
            elif method == "eth_getBlockByNumber":
                result = {
                    "number": "0x64",
                    "hash": block_hash,
                    "timestamp": "0x1234",
                }
            elif method == "eth_getCode":
                result = "0x6000"
            elif method == "eth_getStorageAt":
                result = "0x" + "00" * 32
            else:
                raise AssertionError("unexpected JSON-RPC method: " + method)
            return Response({"jsonrpc": "2.0", "id": payload["id"], "result": result})

        client = pe.RpcClient("http://localhost:8545")
        with patch.object(pe.urllib.request, "urlopen", side_effect=fake_urlopen):
            snapshot = client.pin(requested_block=100)
            client.code("0x" + "11" * 20)
            client.storage("0x" + "11" * 20, pe.EIP1967_IMPLEMENTATION_SLOT)
            self.assertTrue(client.verify_snapshot())
        self.assertEqual(snapshot["block_number"], 100)
        self.assertEqual(snapshot["block_hash"], block_hash)
        code_request = next(item for item in requests if item["method"] == "eth_getCode")
        storage_request = next(item for item in requests if item["method"] == "eth_getStorageAt")
        self.assertEqual(code_request["params"][1], "0x64")
        self.assertEqual(storage_request["params"][2], "0x64")

    def test_block_hash_change_invalidates_snapshot(self):
        import json

        hashes = iter(["0x" + "a" * 64, "0x" + "b" * 64])

        class Response:
            def __init__(self, payload):
                self.payload = payload
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return json.dumps(self.payload).encode()

        def fake_urlopen(request, timeout):
            payload = json.loads(request.data.decode())
            if payload["method"] == "eth_chainId":
                result = "0x1"
            elif payload["method"] == "eth_getBlockByNumber":
                result = {"number": "0x64", "hash": next(hashes), "timestamp": "0x1"}
            else:
                raise AssertionError("unexpected JSON-RPC method")
            return Response({"jsonrpc": "2.0", "id": payload["id"], "result": result})

        client = pe.RpcClient("http://localhost:8545")
        with patch.object(pe.urllib.request, "urlopen", side_effect=fake_urlopen):
            client.pin(requested_block=100)
            self.assertFalse(client.verify_snapshot())


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

    def test_diamond_selector_array_respects_auditor_rpc_budget(self):
        selectors = ["0x" + format(index + 1, "08x") for index in range(pe.MAX_DIAMOND_SELECTORS + 1)]
        self.assertIsNone(
            pe._decode_dynamic_array(
                dynamic_array(selectors),
                32,
                address_items=False,
                max_items=pe.MAX_DIAMOND_SELECTORS,
            )
        )

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
        self.assertEqual(report["architecture"], "ERC1967_IMPLEMENTATION_SLOT_CANDIDATE")
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertFalse(report["checks"]["runtime_routing"]["delegatecall_opcode_observed"])
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

    def test_unreadable_admin_slot_is_not_reported_as_empty(self):
        target = "0x" + "11" * 20
        implementation = "0x" + "22" * 20
        fake = FakeRpc(
            slots={
                pe.EIP1967_IMPLEMENTATION_SLOT: word_address(implementation),
                pe.EIP1967_BEACON_SLOT: word_address(pe.ZERO_ADDRESS),
                # Deliberately omit EIP1967_ADMIN_SLOT.
            },
            code={target: "0x6000", implementation: "0x6001"},
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["checks"]["admin_slot_authority"]["status"], "UNVERIFIED")
        self.assertFalse(any("was successfully read as zero" in item for item in report["evidence"]))

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
        self.assertEqual(report["architecture"], "ERC1967_BEACON_SLOT_CANDIDATE")
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
                (target, pe.DIAMOND_FACET_ADDRESS + facet_selector[2:].ljust(64, "0")): word_address(facet),
            },
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["architecture"], "DIAMOND_LOUPE_INTERFACE_CANDIDATE")
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertEqual(report["checks"]["diamond_loupe"]["facet_count"], 1)
        self.assertEqual(report["checks"]["diamond_loupe"]["selector_count"], 1)
        self.assertEqual(
            report["checks"]["diamond_loupe"]["routing_cross_check"],
            "FACET_ADDRESS_MATCHES_EVERY_REPORTED_SELECTOR",
        )

    def test_diamond_loupe_is_rejected_when_facet_address_disagrees(self):
        target = "0x" + "11" * 20
        facet = "0x" + "22" * 20
        impostor = "0x" + "33" * 20
        facet_selector = "0x12345678"
        fake = FakeRpc(
            slots=self._slots(),
            code={target: "0x6000", facet: "0x6001"},
            calls={
                (target, pe.DIAMOND_FACET_ADDRESSES): dynamic_array([facet], address_items=True),
                (target, pe.DIAMOND_FACET_SELECTORS + facet[2:].rjust(64, "0")): dynamic_array([facet_selector]),
                (target, pe.DIAMOND_FACET_ADDRESS + facet_selector[2:].ljust(64, "0")): word_address(impostor),
            },
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertNotEqual(report["architecture"], "DIAMOND_LOUPE_CONFIRMED")
        self.assertEqual(report["status"], "UNCLASSIFIED")

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




class AuthorityAndLifecycleTests(unittest.TestCase):
    def _base_slots(self, implementation=None, beacon=None, admin=None):
        return {
            pe.EIP1967_IMPLEMENTATION_SLOT: word_address(implementation or pe.ZERO_ADDRESS),
            pe.EIP1967_BEACON_SLOT: word_address(beacon or pe.ZERO_ADDRESS),
            pe.EIP1967_ADMIN_SLOT: word_address(admin or pe.ZERO_ADDRESS),
        }

    def test_transparent_admin_routing_requires_differential_call_evidence(self):
        target = "0x" + "11" * 20
        implementation = "0x" + "22" * 20
        admin = "0x" + "33" * 20
        selector = pe.function_selector("totalSupply()")
        value = "0x" + "00" * 31 + "01"
        abi = [{
            "type": "function", "name": "totalSupply", "inputs": [],
            "outputs": [{"type": "uint256"}], "stateMutability": "view",
        }]
        fake = FakeRpc(
            slots=self._base_slots(implementation=implementation, admin=admin),
            code={target: "0x6000f4", implementation: "0x6001"},
            calls={
                (implementation, selector, admin): value,
                (implementation, selector, pe.SENTINEL_CALLERS[0]): value,
                (target, selector, admin): pe.RpcExecutionError("execution reverted"),
                (target, selector, pe.SENTINEL_CALLERS[0]): value,
            },
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target, abi=abi)
        probe = report["checks"]["transparent_admin_routing"]
        self.assertEqual(probe["status"], "TRANSPARENT_ROUTING_CANDIDATE")
        self.assertIn("TRANSPARENT_ADMIN_ROUTING_CANDIDATE", report["upgrade_mechanisms"])
        self.assertEqual(probe["matched_function"], "totalSupply()")

    def test_owner_getter_is_reported_as_candidate_not_proxy_authority(self):
        admin = "0x" + "33" * 20
        owner = "0x" + "44" * 20
        fake = FakeRpc(code={admin: "0x6001"})
        selector = pe.function_selector("owner()")
        fake.calls[(admin, selector, pe.SENTINEL_CALLERS[0])] = word_address(owner)
        fake.calls[(admin, selector, pe.SENTINEL_CALLERS[1])] = word_address(owner)
        result = pe._probe_owner_getter(fake, admin)
        self.assertEqual(result["status"], "OWNER_GETTER_VALUE_OBSERVED")
        self.assertEqual(result["owner_candidate"], owner)
        self.assertIn("does not by itself prove", result["limitation"])

    def test_zero_owner_getter_is_not_reported_as_an_authority_candidate(self):
        admin = "0x" + "33" * 20
        fake = FakeRpc(code={admin: "0x6001"})
        selector = pe.function_selector("owner()")
        fake.calls[(admin, selector, pe.SENTINEL_CALLERS[0])] = word_address(pe.ZERO_ADDRESS)
        fake.calls[(admin, selector, pe.SENTINEL_CALLERS[1])] = word_address(pe.ZERO_ADDRESS)
        result = pe._probe_owner_getter(fake, admin)
        self.assertEqual(result["status"], "ZERO_OWNER_VALUE_OBSERVED")
        self.assertNotIn("owner_candidate", result)

    def test_caller_dependent_owner_getter_is_not_trusted(self):
        admin = "0x" + "33" * 20
        owner_a = "0x" + "44" * 20
        owner_b = "0x" + "55" * 20
        fake = FakeRpc(code={admin: "0x6001"})
        selector = pe.function_selector("owner()")
        fake.calls[(admin, selector, pe.SENTINEL_CALLERS[0])] = word_address(owner_a)
        fake.calls[(admin, selector, pe.SENTINEL_CALLERS[1])] = word_address(owner_b)
        result = pe._probe_owner_getter(fake, admin)
        self.assertEqual(result["status"], "CALLER_DEPENDENT")
        self.assertNotIn("owner_candidate", result)

    def test_initializer_entrypoint_is_never_called_during_readiness_inspection(self):
        target = "0x" + "11" * 20
        implementation = "0x" + "22" * 20
        initialized_selector = pe.function_selector("initialized()")
        initialized_false = "0x" + "00" * 32
        abi = [
            {
                "type": "function", "name": "initialize",
                "inputs": [{"type": "address"}], "outputs": [],
                "stateMutability": "nonpayable",
            },
            {
                "type": "function", "name": "initialized",
                "inputs": [], "outputs": [{"type": "bool"}],
                "stateMutability": "view",
            },
        ]
        fake = FakeRpc(
            slots=self._base_slots(implementation=implementation),
            code={target: "0x6000", implementation: "0x6001"},
            calls={(target, initialized_selector): initialized_false},
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target, abi=abi)
        init = report["checks"]["initialization"]
        self.assertEqual(init["status"], "EXPLICIT_GETTER_VALUES_OBSERVED")
        self.assertEqual(init["initializer_entrypoints"][0]["signature"], "initialize(address)")
        self.assertFalse(init["mutating_entrypoints_called"])
        self.assertTrue(any(
            call[0] == target and call[1] == initialized_selector
            for call in fake.requested_calls
        ))
        initialize_selector = pe.function_selector("initialize(address)")
        self.assertFalse(any(call[1] == initialize_selector for call in fake.requested_calls))

    def test_nested_clone_to_erc1967_proxy_chain_is_followed_and_bounded(self):
        clone = "0x" + "11" * 20
        nested_proxy = "0x" + "22" * 20
        implementation = "0x" + "33" * 20
        clone_runtime = (
            "0x363d3d373d3d3d363d73" + nested_proxy[2:]
            + "5af43d82803e903d91602b57fd5bf3"
        )
        fake = FakeRpc(
            slots={
                pe.EIP1967_IMPLEMENTATION_SLOT: word_address(pe.ZERO_ADDRESS),
                pe.EIP1967_BEACON_SLOT: word_address(pe.ZERO_ADDRESS),
                pe.EIP1967_ADMIN_SLOT: word_address(pe.ZERO_ADDRESS),
                (nested_proxy, pe.EIP1967_IMPLEMENTATION_SLOT): word_address(implementation),
                (nested_proxy, pe.EIP1967_BEACON_SLOT): word_address(pe.ZERO_ADDRESS),
            },
            code={
                clone: clone_runtime,
                nested_proxy: "0x6000f4",
                implementation: "0x6001",
            },
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", clone)
        chain = report["nested_proxy_chain"]
        self.assertEqual(chain["status"], "TERMINAL_IMPLEMENTATION")
        self.assertEqual(
            [item["architecture"] for item in chain["hops"]],
            ["ERC1967_IMPLEMENTATION_PROXY", "TERMINAL_IMPLEMENTATION"],
        )
        self.assertEqual(chain["hops"][0]["address"], nested_proxy)
        self.assertEqual(chain["hops"][1]["address"], implementation)

    def test_nested_proxy_cycle_is_detected(self):
        proxy_a = "0x" + "11" * 20
        proxy_b = "0x" + "22" * 20
        fake = FakeRpc(
            slots={
                (proxy_a, pe.EIP1967_IMPLEMENTATION_SLOT): word_address(proxy_b),
                (proxy_a, pe.EIP1967_BEACON_SLOT): word_address(pe.ZERO_ADDRESS),
                (proxy_b, pe.EIP1967_IMPLEMENTATION_SLOT): word_address(proxy_a),
                (proxy_b, pe.EIP1967_BEACON_SLOT): word_address(pe.ZERO_ADDRESS),
            },
            code={proxy_a: "0x6000f4", proxy_b: "0x6000f4"},
        )
        result = pe._resolve_nested_proxy_chain(fake, proxy_a)
        self.assertEqual(result["status"], "CYCLE_DETECTED")
        self.assertEqual(len(result["hops"]), 3)

class FoundryBuildInfoLayoutTests(unittest.TestCase):
    def test_selects_contract_layout_from_multi_contract_build_info(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "build-info.json"
            vault_layout = {
                "storage": [{"label": "owner", "slot": "0", "offset": 0, "type": "t_address"}],
                "types": {"t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"}},
            }
            token_layout = {
                "storage": [{"label": "supply", "slot": "0", "offset": 0, "type": "t_uint256"}],
                "types": {"t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"}},
            }
            payload = {
                "output": {"contracts": {
                    "src/Vault.sol": {"Vault": {"storageLayout": vault_layout}},
                    "src/Token.sol": {"Token": {"storageLayout": token_layout}},
                }}
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            selected = pe._read_json_file(str(path), "src/Vault.sol:Vault")
            self.assertEqual(selected["storageLayout"], vault_layout)

    def test_multi_contract_build_info_requires_explicit_contract_selector(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "build-info.json"
            empty_layout = {"storage": [], "types": {}}
            path.write_text(json.dumps({
                "output": {"contracts": {
                    "src/A.sol": {"A": {"storageLayout": empty_layout}},
                    "src/B.sol": {"B": {"storageLayout": empty_layout}},
                }}
            }), encoding="utf-8")
            with self.assertRaisesRegex(pe.ProxyError, "contains 2 contract storage layouts"):
                pe._read_json_file(str(path))

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
                "storage": self.reference["storageLayout"]["storage"] + [
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


class Erc7201NamespaceTests(unittest.TestCase):
    def _source(self, root, path, body):
        file_path = pathlib.Path(root) / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(body, encoding="utf-8")
        return file_path

    def test_openzeppelin_initializable_namespace_root_matches_known_erc7201_slot(self):
        self.assertEqual(
            pe._erc7201_root_slot("openzeppelin.storage.Initializable"),
            "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00",
        )

    def test_scans_erc7201_annotations_and_members_in_dependency_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._source(
                root,
                "lib/openzeppelin/contracts/Initializable.sol",
                "/// @custom:storage-location erc7201:openzeppelin.storage.Initializable\n"
                "struct InitializableStorage {\n"
                "    uint64 _initialized;\n"
                "    bool _initializing;\n"
                "}\n",
            )
            result = pe.scan_erc7201_namespaces(root)
        self.assertEqual(result["status"], "SCANNED")
        self.assertEqual(len(result["namespaces"]), 1)
        item = result["namespaces"][0]
        self.assertEqual(item["namespace_id"], "openzeppelin.storage.Initializable")
        self.assertEqual(item["struct_name"], "InitializableStorage")
        self.assertEqual(item["members"], ["uint64 _initialized", "bool _initializing"])

    def test_namespace_pair_comparison_marks_identical_source_as_review_only(self):
        with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
            source = (
                "/// @custom:storage-location erc7201:example.storage.Vault\n"
                "struct VaultStorage {\n"
                "    address owner;\n"
                "    uint256 totalAssets;\n"
                "}\n"
            )
            self._source(left, "src/Vault.sol", source)
            self._source(right, "src/Vault.sol", source)
            result = pe.compare_erc7201_namespaces(left, right)
        self.assertEqual(result["status"], "IDS_AND_DECLARATIONS_MATCH")
        self.assertEqual(len(result["unchanged"]), 1)
        self.assertTrue(any("not a storage-compatibility proof" in item for item in result["warnings"]))

    def test_namespace_member_change_never_receives_green(self):
        with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
            self._source(
                left, "src/Vault.sol",
                "/// @custom:storage-location erc7201:example.storage.Vault\n"
                "struct VaultStorage { address owner; uint256 totalAssets; }\n",
            )
            self._source(
                right, "src/Vault.sol",
                "/// @custom:storage-location erc7201:example.storage.Vault\n"
                "struct VaultStorage { address owner; uint128 totalAssets; uint128 debt; }\n",
            )
            result = pe.compare_erc7201_namespaces(left, right)
        self.assertEqual(result["status"], "LAYOUT_CHANGE_REQUIRES_VALIDATION")
        self.assertEqual(len(result["changed"]), 1)

    def test_missing_reference_namespace_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
            self._source(
                left, "src/Vault.sol",
                "/// @custom:storage-location erc7201:example.storage.Vault\n"
                "struct VaultStorage { address owner; }\n",
            )
            self._source(right, "src/Vault.sol", "contract Vault {}\n")
            result = pe.compare_erc7201_namespaces(left, right)
        self.assertEqual(result["status"], "INCOMPATIBLE_CANDIDATE")
        self.assertEqual(len(result["removed"]), 1)


class AuditPlanTests(unittest.TestCase):
    def test_attack_plan_adds_namespaced_storage_scenario_only_when_observed(self):
        report = {
            "target": "0x" + "11" * 20,
            "architecture": "ERC1967_IMPLEMENTATION_PROXY",
            "erc7201_namespaces": {
                "namespaces": [{"namespace_id": "example.storage.Vault"}],
                "root_collisions": [],
            },
        }
        plan = pe.build_attack_plan(report)
        scenario = next(item for item in plan["scenarios"] if item["id"] == "PROXY-ERC7201-001")
        self.assertEqual(scenario["status"], "NOT_EXECUTED")
        self.assertIn("pre/post namespaced state snapshots", scenario["required_evidence"])


    def test_candidate_architecture_still_gets_uups_scenarios(self):
        report = {
            "target": "0x" + "11" * 20,
            "architecture": "ERC1967_IMPLEMENTATION_PROXY_CANDIDATE",
            "slot_candidates": {"implementation": "0x" + "22" * 20},
        }
        plan = pe.build_attack_plan(report)
        ids = {item["id"] for item in plan["scenarios"]}
        self.assertIn("PROXY-UUPS-001", ids)
        self.assertIn("PROXY-TRANSPARENT-001", ids)
        self.assertTrue(all(item["status"] == "NOT_EXECUTED" for item in plan["scenarios"]))

    def test_proxy_admin_graph_adds_owner_chain_hypothesis(self):
        report = {
            "target": "0x" + "11" * 20,
            "architecture": "ERC1967_IMPLEMENTATION_PROXY_CANDIDATE",
            "checks": {"upgrade_authority_graph": {"proxy_admin_candidate_count": 1}},
        }
        plan = pe.build_attack_plan(report)
        scenario = next(item for item in plan["scenarios"] if item["id"] == "PROXY-ADMIN-001")
        self.assertEqual(scenario["status"], "NOT_EXECUTED")
        self.assertIn("unprivileged negative-control and authorized positive-control attempts", scenario["required_evidence"])

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




class ProxyHistoryTests(unittest.TestCase):
    def test_upgrade_history_decodes_and_reconciles_standard_events(self):
        target = "0x" + "11" * 20
        implementation = "0x" + "22" * 20
        implementation_topic = "0x" + "0" * 24 + implementation[2:]
        topic = pe._event_topic("Upgraded(address)")

        class HistoryRpc:
            def __init__(self, url):
                self.calls = []
            def pin(self, requested_block=None):
                return {"chain_id": 31337, "block_number": 1002, "block_hash": "0x" + "a" * 64}
            def request(self, method, params):
                self.calls.append((method, params))
                if method == "eth_getLogs":
                    if params[0]["fromBlock"] != "0x3e9":
                        return []
                    return [{
                        "topics": [topic, implementation_topic],
                        "blockNumber": "0x3e9",
                        "blockHash": "0x" + "b" * 64,
                        "transactionHash": "0x" + "c" * 64,
                        "transactionIndex": "0x0",
                        "logIndex": "0x2",
                    }]
                raise AssertionError("unexpected RPC method")
            def storage(self, address, slot):
                if slot == pe.EIP1967_IMPLEMENTATION_SLOT:
                    return word_address(implementation)
                return word_address(pe.ZERO_ADDRESS)
            def verify_snapshot(self):
                return True

        with patch.object(pe, "RpcClient", HistoryRpc):
            report = pe.proxy_upgrade_history("http://rpc.invalid", target, 1001, 1002, chunk_size=1)
        self.assertEqual(report["event_count"], 1)
        self.assertEqual(report["events"][0]["event"], "Upgraded")
        self.assertEqual(report["events"][0]["implementation"], implementation)
        self.assertEqual(report["reconciliation"]["implementation"]["status"], "MATCH")


    def test_admin_changed_uses_non_indexed_event_data(self):
        target = "0x" + "11" * 20
        old_admin = "0x" + "22" * 20
        new_admin = "0x" + "33" * 20
        topic = pe._event_topic("AdminChanged(address,address)")
        data = word_address(old_admin)[2:] + word_address(new_admin)[2:]

        class HistoryRpc:
            def __init__(self, url):
                pass
            def pin(self, requested_block=None):
                return {"chain_id": 1, "block_number": 50, "block_hash": "0x" + "a" * 64}
            def request(self, method, params):
                if method == "eth_getLogs":
                    return [{
                        "topics": [topic], "data": "0x" + data,
                        "blockNumber": "0x32", "blockHash": "0x" + "b" * 64,
                        "transactionHash": "0x" + "c" * 64,
                        "transactionIndex": "0x0", "logIndex": "0x0",
                    }]
                raise AssertionError("unexpected RPC method")
            def storage(self, address, slot):
                if slot == pe.EIP1967_ADMIN_SLOT:
                    return word_address(new_admin)
                return word_address(pe.ZERO_ADDRESS)
            def verify_snapshot(self):
                return True

        with patch.object(pe, "RpcClient", HistoryRpc):
            report = pe.proxy_upgrade_history("http://rpc.invalid", target, 50, 50)
        admin_event = report["events"][0]
        self.assertEqual(admin_event["previous_admin"], old_admin)
        self.assertEqual(admin_event["new_admin"], new_admin)
        self.assertEqual(report["reconciliation"]["admin"]["status"], "MATCH")

    def test_history_rejects_unbounded_ranges(self):
        class TooManyHistoryRpc:
            def __init__(self, url):
                pass
            def pin(self, requested_block=None):
                return {"chain_id": 1, "block_number": requested_block, "block_hash": "0x" + "a" * 64}
        with patch.object(pe, "RpcClient", TooManyHistoryRpc):
            with self.assertRaisesRegex(pe.ProxyError, "100000 blocks"):
                pe.proxy_upgrade_history("http://rpc.invalid", "0x" + "11" * 20, 0, 100001)




    def test_nonzero_implementation_slot_with_delegatecall_remains_candidate(self):
        target = "0x" + "11" * 20
        implementation = "0x" + "22" * 20
        fake = FakeRpc(
            slots={
                pe.EIP1967_IMPLEMENTATION_SLOT: word_address(implementation),
                pe.EIP1967_BEACON_SLOT: word_address(pe.ZERO_ADDRESS),
                pe.EIP1967_ADMIN_SLOT: word_address(pe.ZERO_ADDRESS),
            },
            code={target: "0x6000f4", implementation: "0x6001"},
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["architecture"], "ERC1967_IMPLEMENTATION_PROXY_CANDIDATE")
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertEqual(report["confidence"], "MEDIUM")

    def test_malformed_implementation_slot_is_unverified_not_empty(self):
        target = "0x" + "11" * 20
        fake = FakeRpc(
            slots={
                pe.EIP1967_IMPLEMENTATION_SLOT: "0x" + "01" * 12 + "00" * 20,
                pe.EIP1967_BEACON_SLOT: word_address(pe.ZERO_ADDRESS),
                pe.EIP1967_ADMIN_SLOT: word_address(pe.ZERO_ADDRESS),
            },
            code={target: "0x6000f4"},
        )
        with patch.object(pe, "RpcClient", return_value=fake):
            report = pe.inspect_proxy("http://rpc.invalid", target)
        self.assertEqual(report["architecture"], "UNVERIFIED_EIP1967")
        self.assertEqual(report["checks"]["eip1967_slots"]["implementation"]["state"], "MALFORMED")

    def test_zero_admin_changed_event_reconciles_as_zero_not_missing(self):
        target = "0x" + "11" * 20
        zero_word = "0" * 64
        topic = pe._event_topic("AdminChanged(address,address)")

        class HistoryRpc:
            def __init__(self, url):
                pass
            def pin(self, requested_block=None):
                return {"chain_id": 1, "block_number": 51, "block_hash": "0x" + "a" * 64}
            def request(self, method, params):
                if method == "eth_getLogs":
                    return [{
                        "topics": [topic], "data": "0x" + zero_word + zero_word,
                        "blockNumber": "0x33", "blockHash": "0x" + "b" * 64,
                        "transactionHash": "0x" + "c" * 64,
                        "transactionIndex": "0x0", "logIndex": "0x0",
                    }]
                raise AssertionError("unexpected RPC method")
            def storage(self, address, slot):
                return "0x" + zero_word
            def verify_snapshot(self):
                return True

        with patch.object(pe, "RpcClient", HistoryRpc):
            report = pe.proxy_upgrade_history("http://rpc.invalid", target, 51, 51)
        self.assertEqual(report["reconciliation"]["admin"]["status"], "MATCH")

class RpcCallClassificationTests(unittest.TestCase):

    def test_nested_custom_delegatecall_is_not_called_terminal_implementation(self):
        implementation = "0x" + "22" * 20
        fake = FakeRpc(
            slots={
                pe.EIP1967_IMPLEMENTATION_SLOT: word_address(pe.ZERO_ADDRESS),
                pe.EIP1967_BEACON_SLOT: word_address(pe.ZERO_ADDRESS),
            },
            code={implementation: "0x6000f4"},
        )
        report = pe._resolve_nested_proxy_chain(fake, implementation)
        self.assertEqual(report["status"], "CUSTOM_DELEGATECALL_CANDIDATE")
        self.assertEqual(report["hops"][0]["architecture"], "CUSTOM_DELEGATECALL_CANDIDATE")

    def test_rpc_execution_revert_is_not_classified_as_provider_failure(self):
        class Client:
            def __init__(self, error):
                self.error = error
            def call(self, address, selector, caller=None):
                raise self.error
        reverted = pe._try_call_detailed(
            Client(pe.RpcExecutionError("execution reverted")), "0x" + "11" * 20, "0x12345678", pe.SENTINEL_CALLERS[0]
        )
        failed = pe._try_call_detailed(
            Client(pe.ProxyError("connection reset")), "0x" + "11" * 20, "0x12345678", pe.SENTINEL_CALLERS[0]
        )
        self.assertEqual(reverted["status"], "REVERT")
        self.assertEqual(failed["status"], "RPC_ERROR")

    def test_malformed_slot_is_not_treated_as_zero(self):
        state, address, note = pe._decode_slot_state("0x" + "01" * 12 + "00" * 20)
        self.assertEqual(state, "MALFORMED")
        self.assertIsNone(address)
        self.assertIn("non-zero high", note)



class UpgradeAuthorityGraphTests(unittest.TestCase):
    def test_discovers_oz5_proxy_admin_embedded_as_push20_and_safe_owner(self):
        proxy = "0x" + "11" * 20
        proxy_admin = "0x" + "22" * 20
        safe = "0x" + "33" * 20
        safe_owner = "0x" + "44" * 20
        sentinel = pe.SENTINEL_CALLERS[0]
        owner_selector = pe.function_selector("owner()")
        version_selector = pe.function_selector("UPGRADE_INTERFACE_VERSION()")
        owners_selector = pe.function_selector("getOwners()")
        threshold_selector = pe.function_selector("getThreshold()")
        version = "0x" + f"{32:064x}" + f"{5:064x}" + "352e302e30".ljust(64, "0")
        safe_owners = dynamic_array([safe_owner], address_items=True)
        fake = FakeRpc(
            code={
                proxy: "0x73" + proxy_admin[2:] + "f4",
                proxy_admin: "0x6000",
                safe: "0x6000",
            },
            calls={
                (proxy_admin, version_selector, sentinel): version,
                (proxy_admin, owner_selector, pe.SENTINEL_CALLERS[0]): word_address(safe),
                (proxy_admin, owner_selector, pe.SENTINEL_CALLERS[1]): word_address(safe),
                (safe, owners_selector, sentinel): safe_owners,
                (safe, threshold_selector, sentinel): "0x" + f"{1:064x}",
            },
        )
        graph = pe._inspect_upgrade_authority(fake, proxy, "0x73" + proxy_admin[2:] + "f4", None)
        self.assertEqual(graph["proxy_admin_candidate_count"], 1)
        candidate = graph["candidates"][0]
        self.assertEqual(candidate["origin"], "RUNTIME_PUSH20_IMMUTABLE_CANDIDATE")
        self.assertEqual(candidate["kind"], "OPENZEPPELIN_PROXY_ADMIN_V5_SIGNAL")
        self.assertEqual(candidate["owner_candidate"], safe)
        self.assertEqual(candidate["owner_contract"]["kind"], "SAFE_STYLE_MULTISIG_CANDIDATE")
        self.assertEqual(candidate["owner_contract"]["threshold"], 1)
        self.assertEqual(candidate["owner_contract"]["owners"], [safe_owner])

    def test_admin_slot_eoa_is_not_mislabeled_as_proxyadmin(self):
        proxy = "0x" + "11" * 20
        admin = "0x" + "22" * 20
        fake = FakeRpc(code={proxy: "0x6000", admin: "0x"})
        graph = pe._inspect_upgrade_authority(fake, proxy, "0x6000", admin)
        self.assertEqual(graph["candidate_count"], 1)
        self.assertEqual(graph["proxy_admin_candidate_count"], 0)
        self.assertEqual(graph["candidates"][0]["kind"], "EOA_OR_DESTROYED_ADMIN_CANDIDATE")

    def test_push20_scanner_skips_push_immediates_of_other_sizes(self):
        address = "0x" + "12" * 20
        runtime = "0x60" + "73" + address[2:] + "73" + address[2:]
        self.assertEqual(pe._embedded_code_addresses(runtime), [address])


if __name__ == "__main__":
    unittest.main()
