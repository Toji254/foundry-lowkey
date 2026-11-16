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


def choose_rpc(
    explicit_rpc: Any = None,
    *,
    project_rpc: Any = None,
    fixture_rpc: Any = None,
    legacy_rpc: Any = None,
    environ: Mapping[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """Resolve RPC: explicit override, active fixture, project, safe legacy, env."""
    for value, source in (
        (explicit_rpc, "command-line"),
        (fixture_rpc, "project-fixture"),
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
) -> tuple[str | None, str | None]:
    """Resolve the active actor profile without leaking it between projects."""
    wallets = config.get("wallets") if isinstance(config, Mapping) else {}
    if not isinstance(wallets, Mapping):
        wallets = {}

    explicit = _text(explicit_actor)
    if explicit:
        return (explicit, "command-line") if explicit in wallets else (None, None)

    state = project_state if isinstance(project_state, Mapping) else {}
    if state.get("actor_scope_initialized") is True:
        profile = _text(state.get("actor_profile"))
        return (profile, "project") if profile in wallets else (None, "project-cleared")

    # Migrate older context files which recorded a display string rather than
    # the wallet-profile key. Match only an exact profile name or its prefix.
    legacy_label = _text(state.get("actor"))
    if legacy_label:
        for name in wallets:
            profile = str(name)
            if legacy_label == profile or legacy_label.startswith(profile + " "):
                return profile, "project-legacy"

    # Only migrate the old global actor when its selected target is explicitly
    # registered as belonging to this same project.
    legacy_actor = _text(config.get("actor")) if isinstance(config, Mapping) else None
    if legacy_target_is_project_owned and legacy_actor in wallets:
        return legacy_actor, "legacy-project-owned"
    return None, None


def resolve_runtime_context(
    root: str | os.PathLike[str],
    project_state: Mapping[str, Any] | None,
    config: Mapping[str, Any] | None,
    *,
    validated_target: Mapping[str, Any] | None = None,
    fixture_rpc: Any = None,
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

    # A global RPC/actor is only project-owned when its associated selected
    # target is explicitly registered to this same project. A target override
    # does not erase a project RPC already stored in .audit/context.json.
    global_target_matches = (
        target is not None
        and _valid_address(legacy_address)
        and str(target.get("address")).lower() == legacy_address.lower()
    )
    legacy_rpc_allowed = legacy_owned and global_target_matches
    project_rpc = _text(state.get("rpc"))
    legacy_rpc = None
    if legacy_rpc_allowed:
        legacy_rpc = cfg.get("rpc") or cfg.get("rpc_url")
    rpc, rpc_source = choose_rpc(
        explicit_rpc,
        project_rpc=project_rpc,
        fixture_rpc=fixture_rpc,
        legacy_rpc=legacy_rpc,
        environ=environ,
    )

    actor, actor_source = resolve_actor(
        state,
        cfg,
        legacy_target_is_project_owned=legacy_rpc_allowed,
        explicit_actor=explicit_actor,
    )
    return {
        "project_root": str(canonical),
        "project": state.get("project", {"root": str(canonical), "name": canonical.name}),
        "target": target,
        "rpc": rpc,
        "rpc_source": rpc_source,
        "actor": actor,
        "actor_source": actor_source,
        "legacy_target_owned": legacy_owned,
    }
