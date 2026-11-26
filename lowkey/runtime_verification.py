"""Strict EVM runtime comparison with Solidity-library self-address handling.

Library treatment is opt-in only after the caller has established the compiler
AST/source contract kind. The self-address slot is accepted only when the
expected runtime contains the Solidity library guard sequence:
PUSH20 <zero-address> ADDRESS EQ.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import subprocess
from typing import Any, Callable, Mapping

try:
    from . import library_linker as _library_linker
except ImportError:
    try:
        import library_linker as _library_linker
    except ImportError:
        _library_linker = None


@dataclass(frozen=True)
class RuntimeVerification:
    runtime_status: str
    verification: str
    expected_size: int | None
    actual_size: int | None
    normalized: bool
    reason: str | None
    keccak_status: str
    expected_keccak: str | None = None
    actual_keccak: str | None = None


def _bytes(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if raw.startswith(("0x", "0X")):
        raw = raw[2:]
    if not raw or len(raw) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", raw):
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return None


def contract_kind_from_build_info(
    build_info: Mapping[str, Any], source_name: str, contract_name: str
) -> str | None:
    """Return compiler AST contractKind for one exact source-qualified symbol.

    Supports the standard-json output shape used by solc, Foundry build-info,
    and Hardhat build-info. It deliberately does not infer library kind from a
    filename, artifact basename or symbol name.
    """
    output = build_info.get("output")
    if not isinstance(output, Mapping):
        return None
    sources = output.get("sources")
    if not isinstance(sources, Mapping):
        return None
    source = sources.get(source_name)
    if not isinstance(source, Mapping):
        return None
    ast = source.get("ast")
    if not isinstance(ast, Mapping):
        return None
    nodes = ast.get("nodes")
    if not isinstance(nodes, list):
        return None
    matches = [
        str(node.get("contractKind"))
        for node in nodes
        if isinstance(node, Mapping)
        and node.get("nodeType") == "ContractDefinition"
        and str(node.get("name") or "") == str(contract_name)
        and node.get("contractKind") in {"contract", "library", "interface"}
    ]
    return matches[0] if len(matches) == 1 else None


def _immutable_ranges(artifact: Mapping[str, Any]) -> tuple[tuple[int, int], ...]:
    value = artifact.get("deployedBytecode", artifact.get("deployed_bytecode", {}))
    refs = value.get("immutableReferences") if isinstance(value, Mapping) else None
    if refs is None:
        refs = artifact.get("immutableReferences") or artifact.get("immutable_references") or {}
    if not isinstance(refs, Mapping):
        raise ValueError("compiler immutableReferences metadata is malformed")
    ranges: list[tuple[int, int]] = []
    for entries in refs.values():
        if not isinstance(entries, list):
            raise ValueError("compiler immutableReferences entries must be arrays")
        for item in entries:
            if not isinstance(item, Mapping):
                raise ValueError("compiler immutable reference is not an object")
            start, length = item.get("start"), item.get("length")
            if (
                isinstance(start, bool) or not isinstance(start, int)
                or isinstance(length, bool) or not isinstance(length, int)
                or start < 0 or length <= 0
            ):
                raise ValueError("compiler immutable reference has an invalid offset or length")
            ranges.append((start, length))
    return tuple(sorted(set(ranges)))


def _library_self_address_ranges(expected: bytes) -> tuple[int, ...]:
    """Find PUSH20 zero slots followed by ADDRESS EQ, skipping PUSH payloads."""
    found: list[int] = []
    pc = 0
    while pc < len(expected):
        opcode = expected[pc]
        if opcode == 0x73 and pc + 23 <= len(expected):  # PUSH20
            slot_start = pc + 1
            slot = expected[slot_start:slot_start + 20]
            if slot == b"\x00" * 20 and expected[pc + 21:pc + 23] == b"\x30\x14":
                found.append(slot_start)
            pc += 21
            continue
        if 0x60 <= opcode <= 0x7F:
            pc += 1 + opcode - 0x5F
        else:
            pc += 1
    return tuple(found)


def _apply_ranges(data: bytes, ranges: tuple[tuple[int, int], ...], *, expected_length: int) -> bytes:
    output = bytearray(data)
    occupied: list[tuple[int, int]] = []
    for start, length in ranges:
        end = start + length
        if start < 0 or length <= 0 or end > expected_length:
            raise ValueError("compiler reference range is outside runtime bytecode")
        if any(start < old_end and old_start < end for old_start, old_end in occupied):
            raise ValueError("compiler reference ranges overlap")
        occupied.append((start, end))
        output[start:end] = b"\x00" * length
    return bytes(output)


def resolve_keccak_provider() -> Callable[[bytes], bytes] | None:
    """Prefer Lowkey's shared Ethereum Keccak; accept known Keccak packages/cast."""
    # The transferred Lowkey revision centralizes EVM hashing in break_engine.
    # Use that provider first; do not import a protocol- or tool-specific shim.
    try:
        try:
            from . import break_engine as _break_engine
        except ImportError:
            import break_engine as _break_engine
        provider = getattr(_break_engine, "_keccak256", None)
        if callable(provider):
            def _lowkey_provider(data: bytes) -> bytes:
                digest = provider(data)
                if not isinstance(digest, (bytes, bytearray)) or len(digest) != 32:
                    raise ValueError("Lowkey Keccak provider returned an invalid digest")
                return bytes(digest)
            return _lowkey_provider
    except Exception:
        pass
    try:
        from eth_hash.auto import keccak
        return keccak
    except Exception:
        pass
    try:
        from Crypto.Hash import keccak as crypto_keccak
        def _crypto(data: bytes) -> bytes:
            digest = crypto_keccak.new(digest_bits=256)
            digest.update(data)
            return digest.digest()
        return _crypto
    except Exception:
        pass
    if _cast_available():
        return _cast_keccak
    return None


def _cast_available() -> bool:
    from shutil import which
    return which("cast") is not None


def _cast_keccak(data: bytes) -> bytes:
    result = subprocess.run(
        ["cast", "keccak", "0x" + data.hex()],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "cast keccak failed").strip())
    value = (result.stdout or "").strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        raise ValueError("cast returned an invalid Keccak digest")
    return bytes.fromhex(value[2:])


def _digest(data: bytes, provider: Callable[[bytes], bytes] | None) -> str | None:
    if provider is None:
        return None
    try:
        value = provider(data)
    except Exception:
        return None
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        return None
    return "0x" + bytes(value).hex()


def verify_runtime(
    artifact: Mapping[str, Any],
    actual_runtime: str | bytes | None,
    deployed_address: str,
    *,
    is_solidity_library: bool = False,
    contract_kind: str | None = None,
    library_artifacts: Mapping[str, Mapping[str, Any]] | None = None,
    library_addresses: Mapping[str, str] | None = None,
    network_identity: Mapping[str, Any] | None = None,
    keccak_provider: Callable[[bytes], bytes] | None = None,
) -> RuntimeVerification:
    """Compare runtime bytes exactly after narrowly validated compiler slots.

    ``is_solidity_library`` must be derived from compiler AST/source provenance,
    not from an artifact filename or a caller's guess based only on the name.
    """
    artifact_for_check = dict(artifact)
    expected_obj = artifact_for_check.get("deployedBytecode", artifact_for_check.get("deployed_bytecode", ""))
    runtime_references = ()
    if _library_linker is not None:
        try:
            runtime_references = _library_linker.extract_link_references(artifact_for_check, "runtime")
        except _library_linker.LinkError as exc:
            return RuntimeVerification("UNVERIFIED", "UNVERIFIED", None, None, False, f"Compiler runtime link metadata is invalid: {exc}", "UNAVAILABLE")
    if runtime_references:
        if not isinstance(library_artifacts, Mapping) or not isinstance(library_addresses, Mapping):
            return RuntimeVerification("DEPLOYED", "UNVERIFIED", None, None, False, "Runtime contains compiler library references, but verified library artifacts/addresses were not supplied.", "PENDING")
        try:
            linked = _library_linker.link_bytecode(
                artifact_for_check, library_artifacts, library_addresses,
                kind="runtime", network_identity=network_identity,
            )
            if isinstance(expected_obj, Mapping):
                deployed_record = dict(expected_obj)
                deployed_record["object"] = linked.linked_bytecode
                artifact_for_check["deployedBytecode"] = deployed_record
            else:
                artifact_for_check["deployedBytecode"] = linked.linked_bytecode
            expected_obj = linked.linked_bytecode
        except Exception as exc:
            return RuntimeVerification("DEPLOYED", "UNVERIFIED", None, None, False, f"Runtime library linking could not be proven: {exc}", "PENDING")
    if isinstance(expected_obj, Mapping):
        expected_obj = expected_obj.get("object", "")
    expected = _bytes(expected_obj)
    if expected is None:
        return RuntimeVerification("UNVERIFIED", "UNVERIFIED", None, None, False, "Expected runtime artifact is missing or malformed.", "UNAVAILABLE")

    if isinstance(actual_runtime, bytes):
        actual = actual_runtime if actual_runtime else None
    else:
        actual = _bytes(actual_runtime)
    if actual is None:
        return RuntimeVerification("NOT_DEPLOYED", "UNVERIFIED", len(expected), None, False, "Runtime code is missing or malformed.", "UNAVAILABLE")
    if len(actual) != len(expected):
        return RuntimeVerification("DEPLOYED", "MISMATCH", len(expected), len(actual), False, "Runtime byte lengths differ.", "PENDING")

    address_match = re.fullmatch(r"0x[0-9a-fA-F]{40}", str(deployed_address or ""))
    if not address_match:
        return RuntimeVerification("DEPLOYED", "UNVERIFIED", len(expected), len(actual), False, "Deployment address is invalid; library self-address cannot be established.", "PENDING")
    address_bytes = bytes.fromhex(address_match.group(0)[2:])

    normalized_expected = expected
    normalized_actual = actual
    normalized = False
    proven_kind = contract_kind if contract_kind in {"contract", "library", "interface"} else None
    # A caller-provided boolean cannot replace compiler provenance. Retain the
    # legacy parameter for compatibility, but only AST contractKind is authority.
    if proven_kind == "library":
        is_solidity_library = True
    else:
        is_solidity_library = False
    try:
        immutable_ranges = _immutable_ranges(artifact_for_check)
        self_slots = _library_self_address_ranges(expected)
        if is_solidity_library:
            if len(self_slots) != 1:
                return RuntimeVerification("DEPLOYED", "UNVERIFIED", len(expected), len(actual), False, "Compiler library self-address guard was not uniquely established.", "PENDING")
            slot_start = self_slots[0]
            if any(slot_start < start + length and start < slot_start + 20 for start, length in immutable_ranges):
                return RuntimeVerification("DEPLOYED", "UNVERIFIED", len(expected), len(actual), False, "Library self-address and immutable compiler references overlap.", "PENDING")
            if actual[slot_start:slot_start + 20] != address_bytes:
                return RuntimeVerification("DEPLOYED", "MISMATCH", len(expected), len(actual), False, "Embedded library self-address does not equal the deployment address.", "PENDING")
            # The exact compiler guard sequence is required before this slot is masked.
            normalized_actual = normalized_actual[:slot_start] + b"\x00" * 20 + normalized_actual[slot_start + 20:]
            normalized = True
        elif proven_kind is None and len(self_slots) == 1:
            # The bytecode resembles solc's library guard, but source-qualified AST
            # evidence is absent. Do not call it a mismatch or silently normalize it.
            slot_start = self_slots[0]
            without_candidate_slot = (
                actual[:slot_start] + b"\x00" * 20 + actual[slot_start + 20:]
            )
            expected_without_slot = (
                expected[:slot_start] + b"\x00" * 20 + expected[slot_start + 20:]
            )
            if without_candidate_slot == expected_without_slot and actual[slot_start:slot_start + 20] == address_bytes:
                return RuntimeVerification("DEPLOYED", "UNVERIFIED", len(expected), len(actual), False, "Runtime contains a Solidity-library self-address pattern, but compiler AST contractKind evidence is unavailable.", "PENDING")
        normalized_expected = _apply_ranges(normalized_expected, immutable_ranges, expected_length=len(expected))
        normalized_actual = _apply_ranges(normalized_actual, immutable_ranges, expected_length=len(expected))
    except ValueError as exc:
        return RuntimeVerification("DEPLOYED", "UNVERIFIED", len(expected), len(actual), False, str(exc), "PENDING")

    matched = normalized_actual == normalized_expected
    provider = keccak_provider if keccak_provider is not None else resolve_keccak_provider()
    expected_hash = _digest(expected, provider)
    actual_hash = _digest(actual, provider)
    hash_status = "AVAILABLE" if expected_hash and actual_hash else "UNAVAILABLE"
    return RuntimeVerification(
        "DEPLOYED",
        "MATCHED" if matched else "MISMATCH",
        len(expected),
        len(actual),
        normalized,
        None if matched else "Runtime differs outside compiler-identified immutable/library self-address slots.",
        hash_status,
        expected_hash,
        actual_hash,
    )
