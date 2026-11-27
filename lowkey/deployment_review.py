"""Fail-closed review snapshots for project-native Foundry deployment scripts."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit


REVIEW_SCHEMA = "lowkey.foundry-script-review.v1"
_SIDE_EFFECTS = (
    "The script is arbitrary project Solidity/Forge code. It may deploy contracts, "
    "call existing contracts, transfer native value, mutate storage, create clones, "
    "and write Foundry broadcast/artifact files. Static source scanning cannot prove "
    "the complete set of effects."
)


@dataclass(frozen=True)
class FileFingerprint:
    path: str
    exists: bool
    sha256: str | None
    size_bytes: int


@dataclass(frozen=True)
class FoundryScriptReview:
    schema: str
    status: str
    review_id: str
    project_root: str
    script_path: str
    script_sha256: str | None
    forge_version: str
    rpc_origin: str
    rpc_sha256: str
    network_identity: Mapping[str, Any]
    required_environment: tuple[str, ...]
    safe_default_environment: tuple[str, ...]
    unresolved_environment: tuple[str, ...]
    configuration_files: tuple[FileFingerprint, ...]
    expected_side_effects: str
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "status": self.status,
            "review_id": self.review_id,
            "project_root": self.project_root,
            "script_path": self.script_path,
            "script_sha256": self.script_sha256,
            "forge_version": self.forge_version,
            "rpc_origin": self.rpc_origin,
            "rpc_sha256": self.rpc_sha256,
            "network_identity": dict(self.network_identity),
            "required_environment": list(self.required_environment),
            "safe_default_environment": list(self.safe_default_environment),
            "unresolved_environment": list(self.unresolved_environment),
            "configuration_files": [
                {
                    "path": item.path,
                    "exists": item.exists,
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                }
                for item in self.configuration_files
            ],
            "expected_side_effects": self.expected_side_effects,
            "warnings": list(self.warnings),
        }


def _file_fingerprint(root: Path, candidate: str | Path, *, required: bool = False) -> FileFingerprint:
    raw_path = Path(candidate).expanduser()
    path = raw_path if raw_path.is_absolute() else root / raw_path
    resolved = path.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise ValueError(f"configuration file resolves outside project root: {candidate}")
    if not resolved.exists():
        if required:
            raise ValueError(f"required deployment configuration file is missing: {candidate}")
        return FileFingerprint(resolved.relative_to(root).as_posix(), False, None, 0)
    if not resolved.is_file():
        raise ValueError(f"deployment configuration path is not a regular file: {candidate}")
    raw = resolved.read_bytes()
    return FileFingerprint(
        path=resolved.relative_to(root).as_posix(),
        exists=True,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
    )


def _local_rpc_origin(rpc: str) -> str:
    parsed = urlsplit(str(rpc or "").strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or host not in {
        "127.0.0.1", "localhost", "::1"
    }:
        raise ValueError("native deployment scripts may only broadcast to a loopback Anvil RPC")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("native deployment RPC URL must not contain credentials, query strings or fragments")
    port = parsed.port
    if port is None or not 1 <= port <= 65535:
        raise ValueError("native deployment RPC URL must contain a valid local port")
    return f"{parsed.scheme}://{host}:{port}"


def _normalized_network_identity(identity: Mapping[str, Any] | None, rpc_origin: str) -> dict[str, Any]:
    source = identity if isinstance(identity, Mapping) else {}
    session_id = str(source.get("id") or source.get("network_session_id") or "").strip()
    chain_id = source.get("chain_id")
    if isinstance(chain_id, bool) or chain_id is None:
        raise ValueError("Lowkey could not establish the local Anvil chain ID for the deployment review")
    try:
        parsed_chain_id = int(str(chain_id), 0) if str(chain_id).lower().startswith("0x") else int(chain_id)
    except (TypeError, ValueError) as error:
        raise ValueError("Lowkey received a malformed local Anvil chain ID") from error
    if parsed_chain_id <= 0:
        raise ValueError("Lowkey received an invalid local Anvil chain ID")

    session_rpc = str(source.get("rpc") or "").strip()
    if session_id and session_rpc:
        if _local_rpc_origin(session_rpc) != rpc_origin:
            raise ValueError("selected managed session RPC changed before deployment review")
    if session_id:
        genesis = str(source.get("genesis_hash") or "")
        project_id = str(source.get("project_id") or "")
        if not project_id or len(genesis) != 66 or not genesis.startswith("0x"):
            raise ValueError("managed network identity is incomplete; refusing a native deployment")
        return {
            "kind": "managed-anvil",
            "project_id": project_id,
            "network_session_id": session_id,
            "name": str(source.get("name") or ""),
            "chain_id": parsed_chain_id,
            "genesis_hash": genesis.lower(),
            "rpc_origin": rpc_origin,
        }
    return {
        "kind": "unmanaged-local-anvil",
        "project_id": str(source.get("project_id") or ""),
        "network_session_id": None,
        "name": "",
        "chain_id": parsed_chain_id,
        "genesis_hash": None,
        "rpc_origin": rpc_origin,
    }


def build_foundry_script_review(
    project_root: str | Path,
    script_path: str | Path,
    *,
    rpc: str,
    forge_version: str,
    network_identity: Mapping[str, Any] | None,
    required_environment: tuple[str, ...] | list[str] = (),
    safe_default_environment: tuple[str, ...] | list[str] = (),
    unresolved_environment: tuple[str, ...] | list[str] = (),
    configuration_paths: tuple[str | Path, ...] | list[str | Path] = (),
) -> FoundryScriptReview:
    root = Path(project_root).expanduser().resolve(strict=True)
    script = Path(script_path).expanduser().resolve(strict=True)
    if not script.is_file() or not script.is_relative_to(root):
        raise ValueError("selected Foundry deployment script must be a file inside the current project")

    origin = _local_rpc_origin(rpc)
    network = _normalized_network_identity(network_identity, origin)
    toolchain = str(forge_version or "").strip()
    if not toolchain:
        raise ValueError("Forge toolchain version could not be established")
    unresolved = tuple(sorted({str(name).strip() for name in unresolved_environment if str(name).strip()}))
    required = tuple(sorted({str(name).strip() for name in required_environment if str(name).strip()}))
    safe_defaults = tuple(sorted({str(name).strip() for name in safe_default_environment if str(name).strip()}))
    if unresolved:
        raise ValueError(
            "required project deployment environment is unresolved: " + ", ".join(unresolved)
        )

    script_bytes = script.read_bytes()
    script_hash = hashlib.sha256(script_bytes).hexdigest()
    config_files = []
    seen = set()
    for candidate in configuration_paths:
        item = _file_fingerprint(root, candidate)
        if item.path not in seen:
            seen.add(item.path)
            config_files.append(item)
    config_files.sort(key=lambda item: item.path)

    review_payload = {
        "schema": REVIEW_SCHEMA,
        "project_root": str(root),
        "script_path": script.relative_to(root).as_posix(),
        "script_sha256": script_hash,
        "forge_version": toolchain,
        "rpc_origin": origin,
        "network_identity": network,
        "required_environment": list(required),
        "safe_default_environment": list(safe_defaults),
        "configuration_files": [
            {
                "path": item.path,
                "exists": item.exists,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
            }
            for item in config_files
        ],
        "expected_side_effects": _SIDE_EFFECTS,
    }
    review_id = hashlib.sha256(
        json.dumps(review_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    warnings = []
    if network["kind"] == "unmanaged-local-anvil":
        warnings.append(
            "No Lowkey-managed session identity was available; this is a loopback Anvil endpoint only."
        )
    warnings.append(
        "Review is a bounded pre-execution snapshot, not a proof that the script is safe or that all effects have been enumerated."
    )
    return FoundryScriptReview(
        schema=REVIEW_SCHEMA,
        status="REVIEW_REQUIRED",
        review_id=review_id,
        project_root=str(root),
        script_path=script.relative_to(root).as_posix(),
        script_sha256=script_hash,
        forge_version=toolchain,
        rpc_origin=origin,
        rpc_sha256=hashlib.sha256(origin.encode("utf-8")).hexdigest(),
        network_identity=network,
        required_environment=required,
        safe_default_environment=safe_defaults,
        unresolved_environment=unresolved,
        configuration_files=tuple(config_files),
        expected_side_effects=_SIDE_EFFECTS,
        warnings=tuple(warnings),
    )


def verify_foundry_script_review_current(
    review: FoundryScriptReview,
    project_root: str | Path,
    *,
    rpc: str,
    network_identity: Mapping[str, Any] | None,
) -> tuple[bool, str | None]:
    """Re-check script/config/network identity immediately before broadcast."""
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        if str(root) != review.project_root:
            return False, "project root changed after the deployment review"
        origin = _local_rpc_origin(rpc)
        if origin != review.rpc_origin:
            return False, "RPC endpoint changed after the deployment review"
        network = _normalized_network_identity(network_identity, origin)
        if network != dict(review.network_identity):
            return False, "network session identity changed after the deployment review"
        script = (root / review.script_path).resolve(strict=True)
        if not script.is_relative_to(root) or not script.is_file():
            return False, "deployment script path changed after the deployment review"
        if hashlib.sha256(script.read_bytes()).hexdigest() != review.script_sha256:
            return False, "deployment script content changed after the deployment review"
        for fingerprint in review.configuration_files:
            current = _file_fingerprint(root, fingerprint.path)
            if current != fingerprint:
                return False, f"deployment configuration changed after review: {fingerprint.path}"
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        return False, f"could not revalidate deployment review: {type(error).__name__}: {error}"
    return True, None


def render_foundry_script_review(review: FoundryScriptReview) -> str:
    identity = review.network_identity
    lines = [
        "PROJECT-NATIVE DEPLOYMENT REVIEW",
        "================================",
        f"Review ID       : {review.review_id}",
        f"Project         : {review.project_root}",
        f"Script          : {review.script_path}",
        f"Script SHA-256  : {review.script_sha256}",
        f"Forge           : {review.forge_version}",
        f"Network         : {identity.get('name') or identity.get('kind')}",
        f"Session ID      : {identity.get('network_session_id') or 'not available'}",
        f"Chain ID        : {identity.get('chain_id')}",
        f"Genesis hash    : {identity.get('genesis_hash') or 'not available'}",
        f"RPC origin      : {review.rpc_origin}",
        "Required env    : " + (", ".join(review.required_environment) or "none detected"),
        "Safe defaults   : " + (", ".join(review.safe_default_environment) or "none"),
        "Config files    : " + (
            ", ".join(
                f"{item.path} sha256={item.sha256 or 'absent'}"
                for item in review.configuration_files
            ) or "none found"
        ),
        "Side effects    : arbitrary local-chain deployments/calls/value transfers/storage writes; Foundry broadcast files",
        "Status          : REVIEW REQUIRED",
    ]
    for warning in review.warnings:
        lines.append("Warning         : " + warning)
    return "\n".join(lines)
