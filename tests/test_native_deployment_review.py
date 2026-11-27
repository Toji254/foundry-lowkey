from __future__ import annotations

import tempfile
from pathlib import Path

from lowkey.deployment_review import (
    build_foundry_script_review,
    render_foundry_script_review,
    verify_foundry_script_review_current,
)


def _network():
    return {
        "id": "session-1",
        "name": "dev",
        "project_id": "project-1",
        "chain_id": 31337,
        "genesis_hash": "0x" + "ab" * 32,
        "rpc": "http://127.0.0.1:8545",
    }


def _build(root, *, rpc="http://127.0.0.1:8545", network=None, unresolved=()):
    script = root / "script" / "Deploy.s.sol"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("contract Deploy { function run() external {} }", encoding="utf-8")
    (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
    (root / ".env").write_text("PRIVATE_RPC_TOKEN=not-shown\n", encoding="utf-8")
    return build_foundry_script_review(
        root,
        script,
        rpc=rpc,
        forge_version="forge 1.0.0",
        network_identity=network if network is not None else _network(),
        required_environment=("EXTERNAL_REGISTRY", "OWNER"),
        safe_default_environment=("OWNER",),
        unresolved_environment=unresolved,
        configuration_paths=("foundry.toml", ".env"),
    )


def test_review_binds_script_config_toolchain_and_managed_session():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        review = _build(root)
        assert review.status == "REVIEW_REQUIRED"
        assert review.script_sha256
        assert review.network_identity["network_session_id"] == "session-1"
        assert "EXTERNAL_REGISTRY" in review.required_environment
        rendered = render_foundry_script_review(review)
        assert "Script SHA-256" in rendered
        assert "not-shown" not in rendered
        valid, error = verify_foundry_script_review_current(
            review, root, rpc="http://127.0.0.1:8545", network_identity=_network()
        )
        assert valid and error is None


def test_review_rejects_remote_rpc_and_unresolved_environment():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        try:
            _build(root, rpc="https://rpc.example.org")
        except ValueError as error:
            assert "loopback" in str(error)
        else:
            raise AssertionError("remote deployment RPC was accepted")

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        try:
            _build(root, unresolved=("EXTERNAL_REGISTRY",))
        except ValueError as error:
            assert "EXTERNAL_REGISTRY" in str(error)
        else:
            raise AssertionError("unresolved environment variable was accepted")


def test_review_rejects_script_symlink_outside_project():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "project"
        root.mkdir()
        outside = Path(temp) / "Deploy.s.sol"
        outside.write_text("contract Deploy {}", encoding="utf-8")
        (root / "script").mkdir()
        (root / "script" / "Deploy.s.sol").symlink_to(outside)
        try:
            build_foundry_script_review(
                root, root / "script" / "Deploy.s.sol",
                rpc="http://127.0.0.1:8545", forge_version="forge 1.0.0",
                network_identity=_network(),
            )
        except ValueError as error:
            assert "inside the current project" in str(error)
        else:
            raise AssertionError("out-of-project deployment script was accepted")


def test_review_revalidation_detects_script_and_configuration_changes():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        review = _build(root)
        (root / "script" / "Deploy.s.sol").write_text("contract Deploy { function run() external { selfdestruct(payable(msg.sender)); } }", encoding="utf-8")
        valid, error = verify_foundry_script_review_current(
            review, root, rpc="http://127.0.0.1:8545", network_identity=_network()
        )
        assert not valid and "script content changed" in error

        review = _build(root)
        (root / "foundry.toml").write_text('[profile.default]\nffi = true\n', encoding="utf-8")
        valid, error = verify_foundry_script_review_current(
            review, root, rpc="http://127.0.0.1:8545", network_identity=_network()
        )
        assert not valid and "configuration changed" in error


def test_review_rejects_changed_network_identity_and_allows_only_local_unmanaged_anvil():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        review = _build(root)
        changed = {**_network(), "id": "other-session"}
        valid, error = verify_foundry_script_review_current(
            review, root, rpc="http://127.0.0.1:8545", network_identity=changed
        )
        assert not valid and "network session identity changed" in error

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        unmanaged = {"chain_id": 31337}
        review = _build(root, network=unmanaged)
        assert review.network_identity["kind"] == "unmanaged-local-anvil"
