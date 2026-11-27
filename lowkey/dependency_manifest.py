"""Validated project-local external dependency declarations.

Declarations are planning evidence only. They never prove runtime code, contract
identity, authority, or deployment readiness.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

MANIFEST_RELATIVE_PATH = ".audit/dependencies.json"
MANIFEST_SCHEMA = "lowkey.external-dependencies.v1"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_DEPENDENCIES = 256

DEPENDENCY_KINDS = frozenset({
    "weth", "erc20-token", "chainlink-feed", "router", "vault", "factory",
    "oracle", "bridge", "proxy-admin", "beacon", "diamond-facet",
    "multisig", "timelock", "governance", "other-contract",
})
_ID_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_PARAMETER_PATTERN = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*(?:\[\d+\])*$"
)
_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class DependencyManifest:
    status: str
    path: str
    schema: str | None
    sha256: str | None
    network_identity: Mapping[str, Any] | None
    dependencies: tuple[Mapping[str, Any], ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "path": self.path,
            "schema": self.schema,
            "sha256": self.sha256,
            "network_identity": dict(self.network_identity) if self.network_identity is not None else None,
            "dependencies": [dict(item) for item in self.dependencies],
            "warnings": list(self.warnings),
        }


def _unique_json_object(pairs):
    """Reject duplicate JSON keys instead of accepting last-write-wins ambiguity."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _valid_chain_id(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    try:
        text = str(value).strip()
        parsed = int(text, 16) if text.lower().startswith("0x") else int(text)
        return parsed > 0
    except (TypeError, ValueError):
        return False


def _valid_network_identity(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if not isinstance(value.get("project_id"), str) or not value["project_id"].strip():
        return False
    if not isinstance(value.get("network_session_id"), str) or not value["network_session_id"].strip():
        return False
    if not _valid_chain_id(value.get("chain_id")):
        return False
    if not isinstance(value.get("genesis_hash"), str) or not _HASH_PATTERN.fullmatch(value["genesis_hash"]):
        return False
    identity_block = value.get("identity_block_hash")
    if not isinstance(identity_block, str) or not _HASH_PATTERN.fullmatch(identity_block):
        return False
    return True


def _blocked(path: str, warning: str, *, schema: str | None = None, digest: str | None = None) -> DependencyManifest:
    return DependencyManifest(
        status="BLOCKED", path=path, schema=schema, sha256=digest,
        network_identity=None, dependencies=(), warnings=(warning,),
    )


def load_dependency_manifest(project_root: str | Path) -> DependencyManifest:
    """Read .audit/dependencies.json without following links outside the project."""
    root = Path(project_root).expanduser().resolve()
    relative = MANIFEST_RELATIVE_PATH
    path = root / ".audit" / "dependencies.json"
    try:
        # Inspect the directory entry before resolving it. Path.exists() follows
        # symlinks and reports False for a self-referential link, which would
        # incorrectly downgrade an unsafe manifest to NOT_PRESENT.
        try:
            path.lstat()
        except FileNotFoundError:
            return DependencyManifest(
                status="NOT_PRESENT", path=relative, schema=None, sha256=None,
                network_identity=None, dependencies=(), warnings=(),
            )
        resolved_path = path.resolve(strict=True)
        if not resolved_path.is_relative_to(root):
            return _blocked(relative, "Dependency manifest resolves outside the selected project root.")
        if not resolved_path.is_file():
            return _blocked(relative, "Dependency manifest path is not a regular file.")
        if resolved_path.stat().st_size > MAX_MANIFEST_BYTES:
            return _blocked(relative, f"Dependency manifest exceeds the {MAX_MANIFEST_BYTES}-byte size limit.")
        raw = resolved_path.read_bytes()
    except (OSError, RuntimeError) as error:
        return _blocked(relative, f"Dependency manifest could not be read safely: {type(error).__name__}: {error}")

    digest = hashlib.sha256(raw).hexdigest()
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return _blocked(relative, f"Dependency manifest is not valid UTF-8 JSON: {error}", digest=digest)

    if not isinstance(payload, dict):
        return _blocked(relative, "Dependency manifest root must be a JSON object.", digest=digest)
    if payload.get("schema") != MANIFEST_SCHEMA:
        return _blocked(
            relative, f"Unsupported dependency manifest schema: {payload.get('schema')!r}.",
            schema=str(payload.get("schema")) if payload.get("schema") is not None else None,
            digest=digest,
        )
    unknown_top_level = sorted(set(payload) - {"schema", "network_identity", "dependencies"})
    if unknown_top_level:
        return _blocked(
            relative, "Dependency manifest contains unsupported top-level keys: " + ", ".join(unknown_top_level),
            schema=MANIFEST_SCHEMA, digest=digest,
        )

    network_identity = payload.get("network_identity")
    if network_identity is not None and not _valid_network_identity(network_identity):
        return _blocked(
            relative,
            "Manifest network_identity must include project_id, network_session_id, positive chain_id, a 32-byte genesis_hash and a 32-byte identity_block_hash.",
            schema=MANIFEST_SCHEMA, digest=digest,
        )
    raw_dependencies = payload.get("dependencies")
    if not isinstance(raw_dependencies, list):
        return _blocked(relative, "Dependency manifest 'dependencies' must be an array.", schema=MANIFEST_SCHEMA, digest=digest)
    if len(raw_dependencies) > MAX_DEPENDENCIES:
        return _blocked(relative, f"Dependency manifest exceeds the {MAX_DEPENDENCIES}-entry limit.", schema=MANIFEST_SCHEMA, digest=digest)

    entries: list[dict[str, Any]] = []
    ids: set[str] = set()
    bindings: set[tuple[str, str]] = set()
    for index, raw_entry in enumerate(raw_dependencies):
        prefix = f"Dependency manifest entry {index}"
        if not isinstance(raw_entry, dict):
            return _blocked(relative, f"{prefix} must be an object.", schema=MANIFEST_SCHEMA, digest=digest)
        allowed = {"id", "consumer", "parameter", "kind", "address", "description"}
        unknown = sorted(set(raw_entry) - allowed)
        if unknown:
            return _blocked(
                relative, f"{prefix} contains unsupported keys: " + ", ".join(unknown),
                schema=MANIFEST_SCHEMA, digest=digest,
            )
        identifier, consumer = raw_entry.get("id"), raw_entry.get("consumer")
        parameter, kind = raw_entry.get("parameter"), raw_entry.get("kind")
        if not isinstance(identifier, str) or not _ID_PATTERN.fullmatch(identifier):
            return _blocked(relative, f"{prefix} has an invalid stable id.", schema=MANIFEST_SCHEMA, digest=digest)
        if identifier in ids:
            return _blocked(relative, f"Duplicate dependency id: {identifier}.", schema=MANIFEST_SCHEMA, digest=digest)
        if not isinstance(consumer, str) or ":" not in consumer or len(consumer) > 512:
            return _blocked(relative, f"{prefix} consumer must be a source-qualified contract identity.", schema=MANIFEST_SCHEMA, digest=digest)
        source_name, contract_name = consumer.rsplit(":", 1)
        if not source_name.strip() or not contract_name.strip() or any(char.isspace() for char in contract_name):
            return _blocked(relative, f"{prefix} consumer has an invalid source-qualified identity.", schema=MANIFEST_SCHEMA, digest=digest)
        if not isinstance(parameter, str) or not _PARAMETER_PATTERN.fullmatch(parameter):
            return _blocked(relative, f"{prefix} parameter must be a Solidity constructor parameter path.", schema=MANIFEST_SCHEMA, digest=digest)
        if not isinstance(kind, str) or kind not in DEPENDENCY_KINDS:
            return _blocked(
                relative, f"{prefix} kind must be one of: " + ", ".join(sorted(DEPENDENCY_KINDS)),
                schema=MANIFEST_SCHEMA, digest=digest,
            )
        address = raw_entry.get("address")
        if address is not None and (not isinstance(address, str) or not _ADDRESS_PATTERN.fullmatch(address)):
            return _blocked(relative, f"{prefix} address must be a 20-byte hex address.", schema=MANIFEST_SCHEMA, digest=digest)
        if address is not None and network_identity is None:
            return _blocked(
                relative, f"{prefix} supplies an address but the manifest has no network_identity; address reuse is not permitted.",
                schema=MANIFEST_SCHEMA, digest=digest,
            )
        description = raw_entry.get("description", "")
        if not isinstance(description, str) or len(description) > 512:
            return _blocked(relative, f"{prefix} description must be a string of at most 512 characters.", schema=MANIFEST_SCHEMA, digest=digest)
        binding = (consumer, parameter)
        if binding in bindings:
            return _blocked(relative, f"Duplicate constructor binding: {consumer}#{parameter}.", schema=MANIFEST_SCHEMA, digest=digest)
        ids.add(identifier)
        bindings.add(binding)
        entries.append({
            "id": identifier, "consumer": consumer, "parameter": parameter,
            "kind": kind, "address": address, "description": description,
        })

    return DependencyManifest(
        status="VALID", path=relative, schema=MANIFEST_SCHEMA, sha256=digest,
        network_identity=dict(network_identity) if isinstance(network_identity, Mapping) else None,
        dependencies=tuple(entries), warnings=(),
    )
