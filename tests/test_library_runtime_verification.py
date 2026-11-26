import unittest
from unittest.mock import patch

from lowkey.runtime_verification import contract_kind_from_build_info, resolve_keccak_provider, verify_runtime


ADDRESS = "0x5fbdb2315678afecb367f032d93f642f64180aa3"


def runtime_artifact(prefix=b"\x73" + b"\x00" * 20 + b"\x30\x14", tail=b"\x60\x00\x56"):
    raw = prefix + tail
    return {"deployedBytecode": {"object": "0x" + raw.hex(), "immutableReferences": {}}}


class RuntimeVerificationTests(unittest.TestCase):
    def test_compiler_ast_identifies_only_exact_source_qualified_library(self):
        build_info = {"output": {"sources": {"contracts/core/PositionUtils.sol": {"ast": {"nodes": [
            {"nodeType": "ContractDefinition", "name": "PositionUtils", "contractKind": "library"},
            {"nodeType": "ContractDefinition", "name": "PositionManager", "contractKind": "contract"},
        ]}}}}}
        self.assertEqual(contract_kind_from_build_info(build_info, "contracts/core/PositionUtils.sol", "PositionUtils"), "library")
        self.assertIsNone(contract_kind_from_build_info(build_info, "elsewhere/PositionUtils.sol", "PositionUtils"))
        self.assertIsNone(contract_kind_from_build_info(build_info, "contracts/core/PositionUtils.sol", "Missing"))

    def test_shared_keccak_provider_matches_ethereum_known_vector_when_available(self):
        provider = resolve_keccak_provider()
        if provider is None:
            self.skipTest("Lowkey proxy_engine, eth-hash, pycryptodome and cast are unavailable in this isolated kit.")
        self.assertEqual(provider(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_library_self_address_substitution_matches(self):
        artifact = runtime_artifact()
        expected = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
        actual = expected[:1] + bytes.fromhex(ADDRESS[2:]) + expected[21:]
        result = verify_runtime(artifact, "0x" + actual.hex(), ADDRESS, contract_kind="library", keccak_provider=lambda data: b"x" * 32)
        self.assertEqual(result.runtime_status, "DEPLOYED")
        self.assertEqual(result.verification, "MATCHED")
        self.assertTrue(result.normalized)

    def test_gmx_position_utils_2548_byte_runtime_normalizes_only_self_address(self):
        suffix = bytes((index % 251 for index in range(2548 - 23)))
        expected = b"\x73" + b"\x00" * 20 + b"\x30\x14" + suffix
        artifact = {"deployedBytecode": {"object": "0x" + expected.hex(), "immutableReferences": {}}}
        actual = expected[:1] + bytes.fromhex(ADDRESS[2:]) + expected[21:]
        result = verify_runtime(artifact, actual, ADDRESS, contract_kind="library", keccak_provider=lambda _data: b"q" * 32)
        self.assertEqual(len(expected), 2548)
        self.assertEqual(result.expected_size, 2548)
        self.assertEqual(result.actual_size, 2548)
        self.assertEqual(result.verification, "MATCHED")
        tampered = actual[:-1] + bytes([actual[-1] ^ 0x01])
        rejected = verify_runtime(artifact, tampered, ADDRESS, contract_kind="library", keccak_provider=lambda _data: b"q" * 32)
        self.assertEqual(rejected.verification, "MISMATCH")

    def test_malformed_immutable_reference_fails_unverified(self):
        artifact = {"deployedBytecode": {"object": "0x60016002", "immutableReferences": {"1": [{"start": -1, "length": 4}]}}}
        result = verify_runtime(artifact, "0x60016002", ADDRESS)
        self.assertEqual(result.verification, "UNVERIFIED")

    def test_wrong_embedded_self_address_is_mismatch(self):
        artifact = runtime_artifact()
        expected = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
        actual = expected[:1] + b"\x11" * 20 + expected[21:]
        result = verify_runtime(artifact, actual, ADDRESS, contract_kind="library")
        self.assertEqual(result.verification, "MISMATCH")
        self.assertIn("does not equal", result.reason)

    def test_change_outside_self_address_slot_is_mismatch(self):
        artifact = runtime_artifact()
        expected = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
        actual = expected[:1] + bytes.fromhex(ADDRESS[2:]) + expected[21:]
        actual = actual[:-1] + bytes([actual[-1] ^ 1])
        result = verify_runtime(artifact, actual, ADDRESS, contract_kind="library")
        self.assertEqual(result.verification, "MISMATCH")

    def test_ordinary_contract_push20_is_not_normalized(self):
        artifact = runtime_artifact()
        expected = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
        actual = expected[:1] + bytes.fromhex(ADDRESS[2:]) + expected[21:]
        result = verify_runtime(artifact, actual, ADDRESS, contract_kind="contract")
        self.assertEqual(result.verification, "MISMATCH")
        self.assertFalse(result.normalized)

    def test_library_looking_runtime_without_compiler_kind_is_unverified(self):
        artifact = runtime_artifact()
        expected = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
        actual = expected[:1] + bytes.fromhex(ADDRESS[2:]) + expected[21:]
        result = verify_runtime(artifact, actual, ADDRESS)
        self.assertEqual(result.verification, "UNVERIFIED")
        self.assertIn("compiler AST contractKind", result.reason)

    def test_boolean_library_hint_without_ast_is_not_authoritative(self):
        artifact = runtime_artifact()
        expected = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
        actual = expected[:1] + bytes.fromhex(ADDRESS[2:]) + expected[21:]
        result = verify_runtime(artifact, actual, ADDRESS, is_solidity_library=True)
        self.assertEqual(result.verification, "UNVERIFIED")

    def test_immutable_references_are_normalized(self):
        expected = b"\x60\x01" + b"\x00" * 32 + b"\x60\x02\x56"
        actual = b"\x60\x01" + b"\x77" * 32 + b"\x60\x02\x56"
        artifact = {"deployedBytecode": {"object": "0x" + expected.hex(), "immutableReferences": {"4": [{"start": 2, "length": 32}]}}}
        result = verify_runtime(artifact, actual, ADDRESS, keccak_provider=lambda data: b"k" * 32)
        self.assertEqual(result.verification, "MATCHED")
        self.assertFalse(result.normalized)  # immutable normalization is not library normalization

    def test_library_self_address_and_immutable_references_together(self):
        tail = b"\x60\x00" + b"\x00" * 32 + b"\x56"
        artifact = runtime_artifact(tail=tail)
        expected = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
        actual = expected[:1] + bytes.fromhex(ADDRESS[2:]) + expected[21:]
        immutable_start = 1 + 20 + 2 + 2
        actual = actual[:immutable_start] + b"\xab" * 32 + actual[immutable_start + 32:]
        artifact["deployedBytecode"]["immutableReferences"] = {"1": [{"start": immutable_start, "length": 32}]}
        result = verify_runtime(artifact, actual, ADDRESS, contract_kind="library", keccak_provider=lambda data: b"z" * 32)
        self.assertEqual(result.verification, "MATCHED")
        self.assertTrue(result.normalized)

    def test_missing_runtime_is_not_deployed(self):
        artifact = runtime_artifact()
        result = verify_runtime(artifact, "0x", ADDRESS, contract_kind="library")
        self.assertEqual(result.runtime_status, "NOT_DEPLOYED")
        self.assertEqual(result.verification, "UNVERIFIED")

    def test_malformed_runtime_is_unverified(self):
        artifact = runtime_artifact()
        result = verify_runtime(artifact, "0xzz", ADDRESS, contract_kind="library")
        self.assertEqual(result.verification, "UNVERIFIED")

    def test_hash_provider_unavailable_does_not_affect_bytecode_match(self):
        artifact = runtime_artifact()
        expected = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
        actual = expected[:1] + bytes.fromhex(ADDRESS[2:]) + expected[21:]
        with patch("lowkey.runtime_verification.resolve_keccak_provider", return_value=None):
            result = verify_runtime(artifact, actual, ADDRESS, contract_kind="library")
        self.assertEqual(result.verification, "MATCHED")
        self.assertEqual(result.keccak_status, "UNAVAILABLE")

    def test_invalid_hash_provider_is_reported_unavailable(self):
        artifact = runtime_artifact()
        expected = bytes.fromhex(artifact["deployedBytecode"]["object"][2:])
        actual = expected[:1] + bytes.fromhex(ADDRESS[2:]) + expected[21:]
        result = verify_runtime(artifact, actual, ADDRESS, contract_kind="library", keccak_provider=lambda _data: b"short")
        self.assertEqual(result.verification, "MATCHED")
        self.assertEqual(result.keccak_status, "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
