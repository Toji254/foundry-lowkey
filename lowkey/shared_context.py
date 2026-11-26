"""Project-scoped runtime context shared by Lowkey command handlers.

This module contains no command-specific behaviour. It resolves the current
project's remembered target, RPC and actor selection using explicit precedence
rules. Wallet profiles remain globally reusable; active actor selection is
project-scoped.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, Mapping

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _valid_address(value: Any) -> bool:
    return isinstance(value, str) and bool(_ADDRESS_RE.fullmatch(value.strip()))


def project_root(value: str | os.PathLike[str]) -> Path:
    root = Path(value).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Lowkey project root is not a directory: {root}")
    return root


def project_state_for_root(
    root: str | os.PathLike[str],
    state: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return state only when its recorded project identity matches root."""
    canonical = project_root(root)
    if not isinstance(state, Mapping):
        return {}
    result = dict(state)
    project = result.get("project")
    stored_root = project.get("root") if isinstance(project, Mapping) else None
    if stored_root:
        try:
            if Path(str(stored_root)).expanduser().resolve() != canonical:
                return {}
        except (OSError, TypeError, ValueError):
            return {}
    result["project"] = {"root": str(canonical), "name": canonical.name}
    return result


def target_owned_by_project(
    address: Any,
    config: Mapping[str, Any] | None,
    root: str | os.PathLike[str],
) -> bool:
    """Check explicit target ownership, not artifact-search/project_roots hints.

    project_roots may intentionally refer to a sibling dependency. target_owners
    is the authoritative ownership map for migrating a global selected target.
    """
    if not _valid_address(address) or not isinstance(config, Mapping):
        return False
    owners = config.get("target_owners")
    if not isinstance(owners, Mapping):
        return False
    owner = next(
        (
            value for key, value in owners.items()
            if isinstance(key, str) and key.lower() == str(address).lower()
        ),
        None,
    )
    if not isinstance(owner, str) or not owner.strip():
        return False
    try:
        return Path(owner).expanduser().resolve() == project_root(root)
    except (OSError, TypeError, ValueError):
        return False


def same_rpc_endpoint(left: Any, right: Any) -> bool:
    """Compare RPC endpoints without exposing credentials or query tokens."""
    first = _text(left)
    second = _text(right)
    if not first or not second:
        return False

    def identity(value: str) -> tuple[Any, ...]:
        try:
            parts = urlsplit(value)
            if not parts.scheme or not parts.hostname:
                return (value.rstrip("/"),)
            scheme = parts.scheme.lower()
            host = parts.hostname.rstrip(".").lower()
            port = parts.port
            if port is None:
                port = 443 if scheme == "https" else (80 if scheme == "http" else None)
            path = parts.path.rstrip("/")
            # Query strings can carry authentication tokens. Compare them
            # exactly, but never include them in error text or diagnostics.
            # Credentials are compared as identity material but never returned
            # or interpolated into diagnostics. A URL for another tenant/user
            # on the same RPC host must not inherit this session's actor/target.
            return (scheme, host, port, path, parts.query, parts.username, parts.password)
        except (TypeError, ValueError):
            return (value.rstrip("/"),)

    return identity(first) == identity(second)


def choose_rpc(
    explicit_rpc: Any = None,
    *,
    project_rpc: Any = None,
    fixture_rpc: Any = None,
    managed_rpc: Any = None,
    legacy_rpc: Any = None,
    environ: Mapping[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """Resolve RPC: explicit override, fixture, selected session, project, legacy, env."""
    for value, source in (
        (explicit_rpc, "command-line"),
        (fixture_rpc, "project-fixture"),
        (managed_rpc, "managed-network-session"),
        (project_rpc, "project"),
        (legacy_rpc, "legacy-project-owned"),
    ):
        selected = _text(value)
        if selected:
            return selected, source

    env = os.environ if environ is None else environ
    for name in ("FOUNDRY_ETH_RPC_URL", "ETH_RPC_URL", "LOWKEY_RPC_URL"):
        selected = _text(env.get(name))
        if selected:
            return selected, "environment"
    return None, None


def resolve_actor(
    project_state: Mapping[str, Any] | None,
    config: Mapping[str, Any] | None,
    *,
    legacy_target_is_project_owned: bool = False,
    explicit_actor: Any = None,
    network_actors: Mapping[str, Any] | None = None,
    session_actor: Any = None,
) -> tuple[str | None, str | None]:
    """Resolve an actor without allowing stale Anvil profiles to cross sessions.

    Invocation-local explicit wallet selections win. Session aliases win over
    same-named legacy Anvil profiles because each managed session has its own
    randomly generated accounts. Legacy deterministic Anvil profiles are never
    silently carried into a randomized managed network.
    """
    cfg = config if isinstance(config, Mapping) else {}
    wallets = cfg.get("wallets", {})
    if not isinstance(wallets, Mapping):
        wallets = {}
    session_actors = network_actors if isinstance(network_actors, Mapping) else {}

    def is_legacy_anvil_profile(name: str) -> bool:
        entry = wallets.get(name)
        return isinstance(entry, Mapping) and entry.get("source") == "anvil-default"

    # `lk as <actor> ...` and other explicit invocation-local choices must
    # override the active session actor, but may not use a stale deterministic
    # Anvil profile on a randomly-generated managed session.
    if explicit_actor is None and cfg.get("_ephemeral") is True:
        explicit_actor = cfg.get("actor")
    explicit = _text(explicit_actor)
    if explicit:
        if explicit in session_actors:
            return explicit, "managed-network-session"
        if explicit in wallets:
            if session_actors and is_legacy_anvil_profile(explicit):
                return None, "command-line-network-mismatch"
            return explicit, "command-line"
        return None, "command-line-invalid"

    selected_session_actor = _text(session_actor)
    if selected_session_actor in session_actors:
        return selected_session_actor, "managed-network-session"

    state = project_state if isinstance(project_state, Mapping) else {}
    if state.get("actor_scope_initialized") is True:
        profile = _text(state.get("actor_profile"))
        if profile in session_actors:
            return profile, "managed-network-session"
        if profile in wallets:
            if session_actors and is_legacy_anvil_profile(profile):
                return None, "project-network-mismatch"
            return profile, "project"
        return None, "project-cleared"

    # Migrate older context files which recorded a display string rather than
    # the wallet-profile key. Session aliases are authoritative when names
    # overlap with saved deterministic Anvil profiles.
    legacy_label = _text(state.get("actor"))
    if legacy_label:
        for name in session_actors:
            profile = str(name)
            if legacy_label == profile or legacy_label.startswith(profile + " "):
                return profile, "project-legacy-managed-session"
        for name in wallets:
            profile = str(name)
            if legacy_label == profile or legacy_label.startswith(profile + " "):
                if session_actors and is_legacy_anvil_profile(profile):
                    return None, "project-network-mismatch"
                return profile, "project-legacy"

    # Only migrate the old global actor when its target is project-owned.
    legacy_actor = _text(cfg.get("actor"))
    if legacy_actor in session_actors:
        return legacy_actor, "managed-network-session"
    if legacy_target_is_project_owned and legacy_actor in wallets:
        if session_actors and is_legacy_anvil_profile(legacy_actor):
            return None, "project-network-mismatch"
        return legacy_actor, "legacy-project-owned"
    if legacy_actor in wallets and session_actors and is_legacy_anvil_profile(legacy_actor):
        return None, "project-network-mismatch"

    # Fresh project default: session-local deployment account first, then a
    # non-session legacy internal account only when no managed session exists.
    if "lab-deployer" in session_actors:
        return "lab-deployer", "managed-network-session"
    if "lab-deployer" in wallets:
        return "lab-deployer", "project-default"
    return None, None


def resolve_runtime_context(
    root: str | os.PathLike[str],
    project_state: Mapping[str, Any] | None,
    config: Mapping[str, Any] | None,
    *,
    validated_target: Mapping[str, Any] | None = None,
    fixture_rpc: Any = None,
    managed_rpc: Any = None,
    network_actors: Mapping[str, Any] | None = None,
    session_actor: Any = None,
    explicit_target: Any = None,
    explicit_rpc: Any = None,
    explicit_actor: Any = None,
    allow_legacy_target: bool = True,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return the common project/target/RPC/actor snapshot for one CLI invocation."""
    canonical = project_root(root)
    state = project_state_for_root(canonical, project_state)
    cfg = config if isinstance(config, Mapping) else {}

    # A command-line RPC override may intentionally inspect another network.
    # In that case the project's target and session actors are not evidence
    # about that endpoint. Keep only identities explicitly supplied for this
    # invocation; never borrow the selected session's target or signer.
    explicit_rpc_text = _text(explicit_rpc)
    project_rpc_anchor = _text(state.get("rpc"))
    legacy_address_for_scope = _text(cfg.get("target"))
    legacy_owned_for_scope = bool(
        target_owned_by_project(legacy_address_for_scope, cfg, canonical)
    )
    legacy_rpc_anchor = None
    if legacy_owned_for_scope:
        legacy_rpc_anchor = _text(cfg.get("rpc") or cfg.get("rpc_url"))
    rpc_anchors = [
        _text(fixture_rpc), _text(managed_rpc), project_rpc_anchor, legacy_rpc_anchor,
    ]
    known_anchor = next((item for item in rpc_anchors if item), None)
    explicit_rpc_unscoped = bool(
        explicit_rpc_text
        and (
            (known_anchor and not same_rpc_endpoint(explicit_rpc_text, known_anchor))
            or (not known_anchor and (validated_target or network_actors or session_actor or legacy_owned_for_scope))
        )
    )
    if explicit_rpc_unscoped:
        state = dict(state)
        state["actor_scope_initialized"] = True
        state["actor_profile"] = None
        state["actor"] = None
        cfg = dict(cfg)
        cfg["actor"] = None
        network_actors = {}
        session_actor = None
        managed_rpc = None
        fixture_rpc = None
        validated_target = None
        allow_legacy_target = False

    target = None
    explicit_address = _text(explicit_target)
    if explicit_address and _valid_address(explicit_address):
        target = {"address": explicit_address, "source": "command-line"}
    elif isinstance(validated_target, Mapping):
        address = validated_target.get("address")
        if _valid_address(address):
            target = dict(validated_target)
    legacy_address = _text(cfg.get("target"))
    legacy_owned = bool(target_owned_by_project(legacy_address, cfg, canonical))
    if target is None and allow_legacy_target and legacy_owned:
        abi_paths = cfg.get("abi_paths") if isinstance(cfg.get("abi_paths"), Mapping) else {}
        target = {
            "address": legacy_address,
            "contract": cfg.get("target_contract"),
            "artifact": abi_paths.get(legacy_address),
            "source": "legacy-global-config",
        }

    # The global RPC and actor are project-scoped by ownership of the
    # globally remembered target. A different active target within this same
    # project must not force the operator to re-enter the project's RPC.
    legacy_rpc_allowed = legacy_owned
    project_rpc = _text(state.get("rpc"))
    legacy_rpc = None
    if legacy_rpc_allowed:
        legacy_rpc = cfg.get("rpc") or cfg.get("rpc_url")
    rpc, rpc_source = choose_rpc(
        explicit_rpc,
        project_rpc=project_rpc,
        fixture_rpc=fixture_rpc,
        managed_rpc=managed_rpc,
        legacy_rpc=legacy_rpc,
        environ=environ,
    )

    actor, actor_source = resolve_actor(
        state,
        cfg,
        legacy_target_is_project_owned=legacy_rpc_allowed,
        explicit_actor=explicit_actor,
        network_actors=network_actors,
        session_actor=session_actor,
    )
    return {
        "project_root": str(canonical),
        "project": state.get("project", {"root": str(canonical), "name": canonical.name}),
        "target": target,
        "rpc": rpc,
        "rpc_source": rpc_source,
        "actor": actor,
        "actor_source": actor_source,
        "network_actors": dict(network_actors or {}),
        "network_session_actor": session_actor,
        "legacy_target_owned": legacy_owned,
        "rpc_override_unscoped": explicit_rpc_unscoped,
        "network_identity_verified": not explicit_rpc_unscoped,
    }
