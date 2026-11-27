"""Fail-closed review snapshots for project-native Foundry deployment scripts."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import tempfile
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
    environment_fingerprints: tuple[Mapping[str, str], ...]
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
            "environment_fingerprints": [dict(item) for item in self.environment_fingerprints],
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


def _environment_fingerprints(values: Mapping[str, Any] | None) -> tuple[dict[str, str], ...]:
    """Fingerprint relevant environment values without retaining their contents."""
    if values is None:
        values = {}
    if not isinstance(values, Mapping):
        raise ValueError("deployment environment snapshot must be a mapping")
    fingerprints = []
    for raw_name, raw_value in values.items():
        name = str(raw_name).strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"invalid environment variable name in deployment review: {name!r}")
        value = "" if raw_value is None else (raw_value if isinstance(raw_value, str) else str(raw_value))
        digest = hashlib.sha256(
            b"LOWKEY_FOUNDRY_ENV\\0" + name.encode("utf-8") + b"\\0" + value.encode("utf-8")
        ).hexdigest()
        fingerprints.append({"name": name, "sha256": digest})
    fingerprints.sort(key=lambda item: item["name"])
    return tuple(fingerprints)


def _review_path(root: Path, review_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", str(review_id)):
        raise ValueError("invalid native deployment review id")
    directory = root / ".audit" / "deployment-reviews"
    resolved_directory = directory.resolve(strict=False)
    if not resolved_directory.is_relative_to(root):
        raise ValueError("native deployment review directory resolves outside project root")
    target = resolved_directory / f"{review_id}.json"
    if not target.resolve(strict=False).is_relative_to(root):
        raise ValueError("native deployment review evidence resolves outside project root")
    return target


def persist_foundry_script_review(
    review: FoundryScriptReview,
    project_root: str | Path,
    *,
    state: str,
    details: Mapping[str, Any] | None = None,
) -> str:
    """Atomically persist review/approval state without storing raw secrets or output."""
    allowed_states = {
        "REVIEW_REQUIRED", "BLOCKED", "DECLINED", "APPROVED", "STALE",
        "BROADCAST_STARTED", "FORGE_SUCCEEDED", "FORGE_FAILED",
    }
    normalized_state = str(state or "").upper()
    if normalized_state not in allowed_states:
        raise ValueError(f"unsupported Foundry review state: {state!r}")
    root = Path(project_root).expanduser().resolve(strict=True)
    if str(root) != review.project_root:
        raise ValueError("native deployment review project root changed before evidence persistence")
    path = _review_path(root, review.review_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = review.to_dict()
    previous_created = None
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(previous, dict):
                previous_created = previous.get("created_at")
        except (OSError, json.JSONDecodeError):
            previous_created = None
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload["approval_state"] = normalized_state
    payload["created_at"] = previous_created or now
    payload["updated_at"] = now

    safe_details: dict[str, Any] = {}
    if details is not None:
        if not isinstance(details, Mapping):
            raise ValueError("review outcome details must be an object")
        allowed_details = {
            "reason", "forge_exit_code", "output_sha256", "target_address",
            "transaction_hashes",
        }
        unknown = sorted(set(details) - allowed_details)
        if unknown:
            raise ValueError("unsupported review outcome detail(s): " + ", ".join(unknown))
        for key, value in details.items():
            if key == "reason":
                safe_details[key] = str(value)[:512]
            elif key == "forge_exit_code":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError("forge_exit_code must be an integer")
                safe_details[key] = value
            elif key == "output_sha256":
                digest = str(value)
                if not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ValueError("output_sha256 must be a lowercase SHA-256 digest")
                safe_details[key] = digest
            elif key == "target_address":
                address = str(value)
                if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
                    raise ValueError("target_address must be an EVM address")
                safe_details[key] = address
            elif key == "transaction_hashes":
                if not isinstance(value, (list, tuple)) or len(value) > 512:
                    raise ValueError("transaction_hashes must be a bounded sequence")
                hashes = [str(item) for item in value]
                if any(not re.fullmatch(r"0x[0-9a-fA-F]{64}", item) for item in hashes):
                    raise ValueError("transaction_hashes contains an invalid hash")
                safe_details[key] = hashes
    payload["outcome"] = safe_details

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{review.review_id}.", suffix=".tmp", delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
    return path.relative_to(root).as_posix()


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
        identity_block = str(source.get("identity_block_hash") or "")
        project_id = str(source.get("project_id") or "")
        if (
            not project_id
            or not re.fullmatch(r"0x[0-9a-fA-F]{64}", genesis)
            or not re.fullmatch(r"0x[0-9a-fA-F]{64}", identity_block)
        ):
            raise ValueError("managed network identity is incomplete; refusing a native deployment")
        return {
            "kind": "managed-anvil",
            "project_id": project_id,
            "network_session_id": session_id,
            "name": str(source.get("name") or ""),
            "chain_id": parsed_chain_id,
            "genesis_hash": genesis.lower(),
            "identity_block_hash": identity_block.lower(),
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
    environment_values: Mapping[str, Any] | None = None,
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
    environment_fingerprints = _environment_fingerprints(environment_values)
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
        "environment_fingerprints": [dict(item) for item in environment_fingerprints],
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
        environment_fingerprints=environment_fingerprints,
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
    forge_version: str | None = None,
    environment_values: Mapping[str, Any] | None = None,
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
        if str(forge_version or "").strip() != review.forge_version:
            return False, "Forge toolchain version changed after the deployment review"
        if _environment_fingerprints(environment_values) != review.environment_fingerprints:
            return False, "deployment environment values changed after the review"
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
        "Env fingerprints: " + (
            ", ".join(f"{item['name']} sha256={item['sha256'][:12]}…" for item in review.environment_fingerprints)
            or "none"
        ),
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

HARDHAT_REVIEW_SCHEMA = "lowkey.hardhat-script-review.v1"
_HARDHAT_SIDE_EFFECTS = (
    "The JavaScript/TypeScript script runs with the project's Node permissions. It may deploy "
    "contracts, call contracts, transfer native value, mutate storage, write artifacts/cache, "
    "and invoke arbitrary project modules. The selected HRE network is bound to the reviewed "
    "managed Anvil endpoint, but the script can still construct its own clients or access other "
    "services. Static inspection is not a sandbox and cannot prove the complete set of effects."
)


@dataclass(frozen=True)
class HardhatScriptReview:
    schema: str
    status: str
    review_id: str
    project_root: str
    script_path: str
    script_sha256: str
    hardhat_version: str
    node_version: str
    network_name: str
    network_type: str
    accounts_mode: str
    configured_from: str | None
    configured_chain_id: int | None
    rpc_origin: str
    network_identity: Mapping[str, Any]
    environment_fingerprints: tuple[Mapping[str, str], ...]
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
            "hardhat_version": self.hardhat_version,
            "node_version": self.node_version,
            "network_name": self.network_name,
            "network_type": self.network_type,
            "accounts_mode": self.accounts_mode,
            "configured_from": self.configured_from,
            "configured_chain_id": self.configured_chain_id,
            "rpc_origin": self.rpc_origin,
            "network_identity": dict(self.network_identity),
            "environment_fingerprints": [dict(item) for item in self.environment_fingerprints],
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


def _normalized_hardhat_network_config(
    network_config: Mapping[str, Any],
    *,
    network_name: str,
    rpc: str,
    chain_id: int,
    sender: str,
) -> dict[str, Any]:
    if not isinstance(network_config, Mapping):
        raise ValueError("Hardhat did not return a structured network configuration")
    name = str(network_name or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise ValueError("Hardhat network name must be an explicit valid project network name")
    network_type = str(network_config.get("type") or "").strip().lower()
    if network_type != "http":
        raise ValueError(
            "selected Hardhat network must be type 'http'; in-memory EDR networks are not managed Lowkey Anvil sessions"
        )
    configured_url = str(network_config.get("url") or "").strip()
    if not configured_url:
        raise ValueError("selected Hardhat HTTP network has no resolved URL")
    configured_origin = _local_rpc_origin(configured_url)
    selected_origin = _local_rpc_origin(rpc)
    if configured_origin != selected_origin:
        raise ValueError("selected Hardhat network URL does not resolve to the active managed Lowkey RPC")
    parsed_url = urlsplit(configured_url)
    if parsed_url.path not in {"", "/"}:
        raise ValueError("Hardhat network URL path must be empty; Lowkey Anvil uses the root JSON-RPC endpoint")
    if str(network_config.get("accounts_mode") or "").strip().lower() != "remote":
        raise ValueError(
            "selected Hardhat network must use accounts='remote'; local Hardhat private-key/HD-wallet signers are not accepted"
        )
    configured_from = network_config.get("from")
    normalized_from = str(configured_from).strip().lower() if configured_from else None
    if normalized_from is not None:
        if not re.fullmatch(r"0x[0-9a-f]{40}", normalized_from):
            raise ValueError("Hardhat network 'from' field is not a valid EVM address")
        if normalized_from != str(sender or "").strip().lower():
            raise ValueError("Hardhat network 'from' does not match this managed session's lab-deployer account")
    raw_chain = network_config.get("chain_id")
    configured_chain_id = None
    if raw_chain is not None:
        if isinstance(raw_chain, bool):
            raise ValueError("Hardhat network chainId is malformed")
        try:
            configured_chain_id = int(raw_chain)
        except (TypeError, ValueError) as error:
            raise ValueError("Hardhat network chainId is malformed") from error
        if configured_chain_id != int(chain_id):
            raise ValueError(
                f"Hardhat network chainId {configured_chain_id} does not match managed Anvil chain ID {chain_id}"
            )
    return {
        "network_name": name,
        "type": network_type,
        "accounts_mode": "remote",
        "from": normalized_from,
        "chain_id": configured_chain_id,
        "rpc_origin": configured_origin,
    }


def _version_pair(value: str, label: str) -> tuple[int, int, int]:
    match = re.search(r"(?:^|\s|v)(\d+)\.(\d+)\.(\d+)(?:\b|$)", str(value or ""))
    if not match:
        raise ValueError(f"{label} version could not be established")
    return tuple(int(part) for part in match.groups())

def build_hardhat_script_review(
    project_root: str | Path,
    script_path: str | Path,
    *,
    rpc: str,
    hardhat_version: str,
    node_version: str,
    network_name: str,
    network_config: Mapping[str, Any],
    network_identity: Mapping[str, Any] | None,
    sender: str,
    configuration_paths: tuple[str | Path, ...] | list[str | Path] = (),
    environment_values: Mapping[str, Any] | None = None,
) -> HardhatScriptReview:
    root = Path(project_root).expanduser().resolve(strict=True)
    script = Path(script_path).expanduser().resolve(strict=True)
    if not script.is_file() or not script.is_relative_to(root):
        raise ValueError("selected Hardhat deployment script must be a file inside the current project")
    if script.suffix.lower() not in {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts"}:
        raise ValueError("Hardhat deployment script must be JavaScript or TypeScript")

    origin = _local_rpc_origin(rpc)
    network = _normalized_network_identity(network_identity, origin)
    if network.get("kind") != "managed-anvil" or not network.get("network_session_id"):
        raise ValueError("Hardhat native deployment requires a process-owned Lowkey managed Anvil session")
    hardhat_toolchain = str(hardhat_version or "").strip()
    node_toolchain = str(node_version or "").strip()
    if _version_pair(hardhat_toolchain, "Hardhat")[0] != 3:
        raise ValueError("only the project-local Hardhat 3 toolchain is supported by this deployment adapter")
    node_major, node_minor, _ = _version_pair(node_toolchain, "Node.js")
    if (node_major, node_minor) < (22, 13):
        raise ValueError("Hardhat 3 deployment requires Node.js 22.13.0 or newer")

    normalized_network = _normalized_hardhat_network_config(
        network_config,
        network_name=network_name,
        rpc=rpc,
        chain_id=int(network["chain_id"]),
        sender=sender,
    )
    fingerprints = _environment_fingerprints(environment_values)
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
    if not any(Path(item.path).name.lower().startswith("hardhat.config.") and item.exists for item in config_files):
        raise ValueError("Hardhat config file was not included in the reviewed configuration snapshot")

    review_payload = {
        "schema": HARDHAT_REVIEW_SCHEMA,
        "project_root": str(root),
        "script_path": script.relative_to(root).as_posix(),
        "script_sha256": script_hash,
        "hardhat_version": hardhat_toolchain,
        "node_version": node_toolchain,
        "network": normalized_network,
        "network_identity": network,
        "environment_fingerprints": [dict(item) for item in fingerprints],
        "configuration_files": [
            {
                "path": item.path,
                "exists": item.exists,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
            }
            for item in config_files
        ],
        "expected_side_effects": _HARDHAT_SIDE_EFFECTS,
    }
    review_id = hashlib.sha256(
        json.dumps(review_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    warnings = (
        "The selected Hardhat HRE network is bound to this managed Anvil session; the script can still create direct clients or access other services.",
        "This review binds a source/config/toolchain snapshot. It does not sandbox project JavaScript or prove all runtime side effects.",
        "The adapter accepts only HTTP networks with remote node accounts; explicit project private-key and HD-wallet signer configurations are blocked.",
    )
    return HardhatScriptReview(
        schema=HARDHAT_REVIEW_SCHEMA,
        status="REVIEW_REQUIRED",
        review_id=review_id,
        project_root=str(root),
        script_path=script.relative_to(root).as_posix(),
        script_sha256=script_hash,
        hardhat_version=hardhat_toolchain,
        node_version=node_toolchain,
        network_name=normalized_network["network_name"],
        network_type=normalized_network["type"],
        accounts_mode=normalized_network["accounts_mode"],
        configured_from=normalized_network["from"],
        configured_chain_id=normalized_network["chain_id"],
        rpc_origin=origin,
        network_identity=network,
        environment_fingerprints=fingerprints,
        configuration_files=tuple(config_files),
        expected_side_effects=_HARDHAT_SIDE_EFFECTS,
        warnings=warnings,
    )


def render_hardhat_script_review(review: HardhatScriptReview) -> str:
    identity = review.network_identity
    lines = [
        "PROJECT-NATIVE HARDHAT DEPLOYMENT REVIEW",
        "========================================",
        f"Review ID       : {review.review_id}",
        f"Project         : {review.project_root}",
        f"Script          : {review.script_path}",
        f"Script SHA-256  : {review.script_sha256}",
        f"Hardhat         : {review.hardhat_version}",
        f"Node.js         : {review.node_version}",
        f"Network         : {review.network_name} ({review.network_type})",
        f"Accounts        : {review.accounts_mode}",
        f"From            : {review.configured_from or 'first remote Anvil account'}",
        f"Configured chain: {review.configured_chain_id or 'not pinned in Hardhat config'}",
        f"Session ID      : {identity.get('network_session_id')}",
        f"Chain ID        : {identity.get('chain_id')}",
        f"Genesis hash    : {identity.get('genesis_hash')}",
        f"RPC origin      : {review.rpc_origin}",
        "Env fingerprints: " + (
            ", ".join(f"{item['name']} sha256={item['sha256'][:12]}…" for item in review.environment_fingerprints)
            or "none detected"
        ),
        "Config files    : " + (
            ", ".join(f"{item.path} sha256={item.sha256 or 'absent'}" for item in review.configuration_files)
            or "none"
        ),
        "Side effects    : arbitrary project JavaScript/TypeScript; deployments, calls, value transfers, storage changes and build artifacts",
        "Status          : REVIEW REQUIRED",
    ]
    for warning in review.warnings:
        lines.append("Warning         : " + warning)
    return "\n".join(lines)


def persist_hardhat_script_review(
    review: HardhatScriptReview,
    project_root: str | Path,
    *,
    state: str,
    details: Mapping[str, Any] | None = None,
) -> str:
    allowed_states = {
        "REVIEW_REQUIRED", "BLOCKED", "DECLINED", "APPROVED", "STALE",
        "BROADCAST_STARTED", "HARDHAT_SUCCEEDED", "HARDHAT_FAILED",
    }
    normalized_state = str(state or "").upper()
    if normalized_state not in allowed_states:
        raise ValueError(f"unsupported Hardhat review state: {state!r}")
    root = Path(project_root).expanduser().resolve(strict=True)
    if str(root) != review.project_root:
        raise ValueError("Hardhat deployment review project root changed before evidence persistence")
    path = _review_path(root, review.review_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = review.to_dict()
    previous_created = None
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(previous, dict):
                previous_created = previous.get("created_at")
        except (OSError, json.JSONDecodeError):
            previous_created = None
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload["approval_state"] = normalized_state
    payload["created_at"] = previous_created or now
    payload["updated_at"] = now
    safe_details: dict[str, Any] = {}
    if details is not None:
        if not isinstance(details, Mapping):
            raise ValueError("Hardhat review outcome details must be an object")
        allowed_details = {"reason", "hardhat_exit_code", "output_sha256", "target_address", "transaction_hashes"}
        unknown = sorted(set(details) - allowed_details)
        if unknown:
            raise ValueError("unsupported Hardhat review detail(s): " + ", ".join(unknown))
        for key, value in details.items():
            if key == "reason":
                safe_details[key] = str(value)[:512]
            elif key == "hardhat_exit_code":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError("hardhat_exit_code must be an integer")
                safe_details[key] = value
            elif key == "output_sha256":
                digest = str(value)
                if not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ValueError("output_sha256 must be a lowercase SHA-256 digest")
                safe_details[key] = digest
            elif key == "target_address":
                address = str(value)
                if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
                    raise ValueError("target_address must be an EVM address")
                safe_details[key] = address
            elif key == "transaction_hashes":
                if not isinstance(value, (list, tuple)) or len(value) > 512:
                    raise ValueError("transaction_hashes must be a bounded sequence")
                hashes = [str(item) for item in value]
                if any(not re.fullmatch(r"0x[0-9a-fA-F]{64}", item) for item in hashes):
                    raise ValueError("transaction_hashes contains an invalid hash")
                safe_details[key] = hashes
    payload["outcome"] = safe_details
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{review.review_id}.", suffix=".tmp", delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
    return path.relative_to(root).as_posix()


def verify_hardhat_script_review_current(
    review: HardhatScriptReview,
    project_root: str | Path,
    *,
    rpc: str,
    hardhat_version: str,
    node_version: str,
    network_name: str,
    network_config: Mapping[str, Any],
    network_identity: Mapping[str, Any] | None,
    sender: str,
    environment_values: Mapping[str, Any] | None = None,
) -> tuple[bool, str | None]:
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        if str(root) != review.project_root:
            return False, "project root changed after the Hardhat deployment review"
        origin = _local_rpc_origin(rpc)
        if origin != review.rpc_origin:
            return False, "RPC endpoint changed after the Hardhat deployment review"
        network = _normalized_network_identity(network_identity, origin)
        if network != dict(review.network_identity):
            return False, "managed Anvil session identity changed after the Hardhat deployment review"
        if str(hardhat_version or "").strip() != review.hardhat_version:
            return False, "project-local Hardhat version changed after review"
        if str(node_version or "").strip() != review.node_version:
            return False, "project Node.js version changed after review"
        current_network = _normalized_hardhat_network_config(
            network_config,
            network_name=network_name,
            rpc=rpc,
            chain_id=int(network["chain_id"]),
            sender=sender,
        )
        expected_network = {
            "network_name": review.network_name,
            "type": review.network_type,
            "accounts_mode": review.accounts_mode,
            "from": review.configured_from,
            "chain_id": review.configured_chain_id,
            "rpc_origin": review.rpc_origin,
        }
        if current_network != expected_network:
            return False, "selected Hardhat network configuration changed after review"
        if _environment_fingerprints(environment_values) != review.environment_fingerprints:
            return False, "Hardhat deployment environment changed after review"
        script = (root / review.script_path).resolve(strict=True)
        if not script.is_relative_to(root) or not script.is_file():
            return False, "Hardhat deployment script path changed after review"
        if hashlib.sha256(script.read_bytes()).hexdigest() != review.script_sha256:
            return False, "Hardhat deployment script content changed after review"
        for fingerprint in review.configuration_files:
            current = _file_fingerprint(root, fingerprint.path)
            if current != fingerprint:
                return False, f"Hardhat deployment configuration changed after review: {fingerprint.path}"
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        return False, f"could not revalidate Hardhat deployment review: {type(error).__name__}: {error}"
    return True, None
