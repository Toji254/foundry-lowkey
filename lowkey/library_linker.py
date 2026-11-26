"""Compiler-reference-aware Solidity library linker for Lowkey.

This module is intentionally side-effect free: it never edits source artifacts,
never deploys a library, and never guesses an artifact when names are ambiguous.
The deployment layer supplies verified library addresses and persists LinkResult.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Mapping


class LinkError(ValueError):
    """A link operation failed closed with a machine-readable reason."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, order=True)
class ArtifactIdentity:
    source_name: str
    contract_name: str

    @property
    def qualified_name(self) -> str:
        return f"{self.source_name}:{self.contract_name}"


@dataclass(frozen=True)
class LinkReference:
    source_name: str
    library_name: str
    start: int
    length: int

    @property
    def identity(self) -> ArtifactIdentity:
        return ArtifactIdentity(self.source_name, self.library_name)


@dataclass(frozen=True)
class LinkRecord:
    library: str
    address: str
    start: int
    length: int
    source_name: str


@dataclass(frozen=True)
class LinkResult:
    identity: ArtifactIdentity
    original_artifact_sha256: str
    original_bytecode_template_sha256: str
    linked_bytecode_sha256: str
    linked_bytecode: str
    links: tuple[LinkRecord, ...]
    network_identity: Mapping[str, Any] | None = None

    def evidence(self) -> dict[str, Any]:
        return {
            "schema": "lowkey.library-link.v1",
            "contract": self.identity.qualified_name,
            "original_artifact_sha256": self.original_artifact_sha256,
            "original_bytecode_template_sha256": self.original_bytecode_template_sha256,
            "linked_bytecode_sha256": self.linked_bytecode_sha256,
            "network_identity": dict(self.network_identity or {}),
            "links": [
                {
                    "library": item.library,
                    "address": item.address,
                    "source_name": item.source_name,
                    "start": item.start,
                    "length": item.length,
                }
                for item in self.links
            ],
        }


def _artifact_identity(artifact: Mapping[str, Any], fallback: str | None = None) -> ArtifactIdentity:
    source = str(artifact.get("sourceName") or artifact.get("source_name") or "").strip()
    name = str(artifact.get("contractName") or artifact.get("contract_name") or "").strip()
    if not name and fallback:
        name = str(fallback).strip()
    if not source or not name:
        raise LinkError("ARTIFACT_IDENTITY_UNRESOLVED", "Artifact needs sourceName and contractName provenance.")
    return ArtifactIdentity(source.replace("\\", "/"), name)


def _bytecode_record(artifact: Mapping[str, Any], kind: str = "creation") -> tuple[str, Mapping[str, Any]]:
    if kind not in {"creation", "runtime"}:
        raise ValueError("kind must be 'creation' or 'runtime'")
    if kind == "creation":
        value = artifact.get("bytecode", "")
        top_refs = artifact.get("linkReferences")
    else:
        value = artifact.get("deployedBytecode", artifact.get("deployed_bytecode", ""))
        top_refs = artifact.get("deployedLinkReferences")
    if isinstance(value, Mapping):
        obj = value.get("object", "")
        refs = value.get("linkReferences") or top_refs or {}
    else:
        obj = value
        refs = top_refs or {}
    if not isinstance(obj, str) or not obj.strip():
        raise LinkError("BYTECODE_MISSING", f"Artifact has no {kind} bytecode object.")
    if not isinstance(refs, Mapping):
        raise LinkError("INVALID_LINK_REFERENCE", "Compiler linkReferences must be an object.")
    return obj.strip(), refs


def extract_link_references(artifact: Mapping[str, Any], kind: str = "creation") -> tuple[LinkReference, ...]:
    """Read Hardhat or Foundry linkReferences without interpreting imports."""
    _obj, refs = _bytecode_record(artifact, kind)
    found: list[LinkReference] = []
    for source_name, libraries in refs.items():
        if not isinstance(source_name, str) or not isinstance(libraries, Mapping):
            raise LinkError("INVALID_LINK_REFERENCE", "Malformed compiler linkReferences source entry.")
        for library_name, entries in libraries.items():
            if not isinstance(library_name, str) or not isinstance(entries, list):
                raise LinkError("INVALID_LINK_REFERENCE", "Malformed compiler library-reference entry.")
            for entry in entries:
                if not isinstance(entry, Mapping):
                    raise LinkError("INVALID_LINK_REFERENCE", "A compiler link reference is not an object.")
                start_value = entry.get("start")
                length_value = entry.get("length")
                # JSON compiler metadata specifies integer byte offsets. Reject
                # bools, floats and numeric strings instead of silently truncating
                # or coercing malformed compiler output.
                if (
                    isinstance(start_value, bool) or not isinstance(start_value, int)
                    or isinstance(length_value, bool) or not isinstance(length_value, int)
                ):
                    raise LinkError("INVALID_LINK_REFERENCE", "A compiler link reference must use integer start/length values.")
                start = start_value
                length = length_value
                if start < 0 or length != 20:
                    raise LinkError("INVALID_LINK_REFERENCE", f"Invalid library reference range start={start}, length={length}.")
                found.append(LinkReference(source_name.replace("\\", "/"), library_name, start, length))
    return tuple(sorted(found, key=lambda item: (item.start, item.source_name, item.library_name)))


def resolve_library_artifact(
    identity: ArtifactIdentity,
    artifacts: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    """Resolve a source-qualified artifact; refuse ambiguous unqualified matches."""
    exact = artifacts.get(identity.qualified_name)
    if exact is not None:
        candidate_identity = _artifact_identity(exact)
        if candidate_identity != identity:
            raise LinkError("ARTIFACT_PROVENANCE_MISMATCH", f"Artifact map key {identity.qualified_name} points to {candidate_identity.qualified_name}.")
        return exact
    matches = []
    for artifact in artifacts.values():
        if not isinstance(artifact, Mapping):
            continue
        try:
            candidate = _artifact_identity(artifact)
        except LinkError:
            continue
        if candidate.contract_name == identity.contract_name:
            matches.append((candidate, artifact))
    if len(matches) > 1:
        names = ", ".join(sorted(item[0].qualified_name for item in matches))
        raise LinkError("AMBIGUOUS_LIBRARY_ARTIFACT", f"Library {identity.contract_name} has multiple artifact matches: {names}.")
    if not matches:
        raise LinkError("UNRESOLVED_LIBRARY", f"No artifact found for {identity.qualified_name}.")
    # The fallback is safe only when the source identity also matches.
    if matches[0][0] != identity:
        raise LinkError("LIBRARY_SOURCE_MISMATCH", f"Found {matches[0][0].qualified_name}, expected {identity.qualified_name}.")
    return matches[0][1]


def _is_link_placeholder(value: str) -> bool:
    return (
        value == "0" * 40
        or (len(value) == 40 and "_" in value and all(ch.isalnum() or ch in "_$" for ch in value))
        or (len(value) == 40 and value.startswith("__") and value.endswith("__") and "$" in value)
    )


def _reject_remaining_placeholders(bytecode: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]+", bytecode):
        raise LinkError("UNRESOLVED_BYTECODE_PLACEHOLDER", "Creation bytecode still contains non-hex compiler placeholders or malformed data.")
    if len(bytecode) % 2:
        raise LinkError("INVALID_BYTECODE", "Creation bytecode has an odd number of hex characters.")


def link_creation_bytecode(
    artifact: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    library_addresses: Mapping[str, str],
    *,
    network_identity: Mapping[str, Any] | None = None,
) -> LinkResult:
    """Patch exactly compiler-provided byte offsets, preserving the input artifact.

    library_addresses keys must be fully-qualified ``source:Library`` identities.
    A reference already linked to the same address is idempotent; a different
    pre-linked address is rejected rather than silently overwritten.
    """
    if not isinstance(artifact, Mapping):
        raise LinkError("INVALID_ARTIFACT", "Artifact must be an object.")
    identity = _artifact_identity(artifact)
    original, _refs = _bytecode_record(artifact, "creation")
    body = original[2:] if original.startswith(("0x", "0X")) else original
    refs = extract_link_references(artifact, "creation")
    artifact_json = json.dumps(artifact, sort_keys=True, separators=(",", ":"), default=str).encode()
    original_hash = hashlib.sha256(artifact_json).hexdigest()
    original_bytecode_hash = hashlib.sha256(body.encode("ascii", errors="strict")).hexdigest()
    if len(body) % 2:
        raise LinkError("INVALID_BYTECODE", "Creation bytecode must contain complete bytes.")

    resolved: dict[str, str] = {}
    for ref in refs:
        qualified = ref.identity.qualified_name
        if qualified not in library_addresses:
            raise LinkError("UNRESOLVED_LIBRARY", f"No verified address supplied for {qualified}.")
        address = str(library_addresses[qualified]).strip()
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            raise LinkError("INVALID_LIBRARY_ADDRESS", f"Invalid address for {qualified}.")
        resolve_library_artifact(ref.identity, artifacts)
        resolved[qualified] = address[2:].lower()

    occupied: list[tuple[int, int]] = []
    linked = body
    records: list[LinkRecord] = []
    for ref in refs:
        start = ref.start * 2
        end = start + ref.length * 2
        if end > len(body):
            raise LinkError("INVALID_LINK_REFERENCE", f"Reference {ref.identity.qualified_name} exceeds bytecode bounds.")
        for old_start, old_end in occupied:
            if start < old_end and old_start < end:
                raise LinkError("INVALID_LINK_REFERENCE", "Compiler link references overlap.")
        occupied.append((start, end))
        current = linked[start:end]
        address = resolved[ref.identity.qualified_name]
        if current.lower() == address:
            pass  # already linked to the exact requested address
        elif _is_link_placeholder(current):
            linked = linked[:start] + address + linked[end:]
        elif re.fullmatch(r"[0-9a-fA-F]{40}", current):
            raise LinkError("LIBRARY_ALREADY_LINKED_DIFFERENT_ADDRESS", f"{ref.identity.qualified_name} is already linked to a different address.")
        else:
            raise LinkError("INVALID_LINK_REFERENCE", f"Reference bytes at offset {ref.start} are neither a valid placeholder nor hex.")
        records.append(LinkRecord(ref.identity.qualified_name, "0x" + address, ref.start, ref.length, ref.source_name))

    _reject_remaining_placeholders(linked)
    return LinkResult(
        identity=identity,
        original_artifact_sha256=original_hash,
        original_bytecode_template_sha256=original_bytecode_hash,
        linked_bytecode_sha256=hashlib.sha256(bytes.fromhex(linked)).hexdigest(),
        linked_bytecode="0x" + linked.lower(),
        links=tuple(records),
        network_identity=dict(network_identity or {}),
    )


def link_bytecode(
    artifact: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    library_addresses: Mapping[str, str],
    *,
    kind: str = "creation",
    network_identity: Mapping[str, Any] | None = None,
) -> LinkResult:
    """Link creation or deployed bytecode using compiler references only."""
    if kind == "creation":
        return link_creation_bytecode(
            artifact, artifacts, library_addresses, network_identity=network_identity
        )
    if kind != "runtime":
        raise ValueError("kind must be 'creation' or 'runtime'")
    raw, references = _bytecode_record(artifact, "runtime")
    runtime_artifact = dict(artifact)
    runtime_artifact["bytecode"] = {"object": raw, "linkReferences": references}
    runtime_artifact.pop("linkReferences", None)
    return link_creation_bytecode(
        runtime_artifact, artifacts, library_addresses, network_identity=network_identity
    )


def recursive_library_order(
    target: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
) -> tuple[ArtifactIdentity, ...]:
    """Return compiler-linked libraries in dependency-first order; cycles fail closed."""
    visiting: list[str] = []
    visited: set[str] = set()
    ordered: list[ArtifactIdentity] = []

    def visit(artifact: Mapping[str, Any]) -> None:
        refs = extract_link_references(artifact, "creation")
        for ref in refs:
            key = ref.identity.qualified_name
            if key in visiting:
                cycle = visiting[visiting.index(key):] + [key]
                raise LinkError("DEPENDENCY_CYCLE", "Library link cycle: " + " -> ".join(cycle))
            if key in visited:
                continue
            library = resolve_library_artifact(ref.identity, artifacts)
            visiting.append(key)
            visit(library)
            visiting.pop()
            visited.add(key)
            ordered.append(ref.identity)

    visit(target)
    return tuple(ordered)
