from __future__ import annotations

import json
from pathlib import Path
import tempfile

import pytest

from lowkey.deployment_review import (
    build_hardhat_script_review,
    persist_hardhat_script_review,
    verify_hardhat_script_review_current,
    _version_pair,
    render_hardhat_script_review,
)


def _network(rpc="http://127.0.0.1:18545"):
    return {
        "project_id": "project-hardhat-test",
        "project_root": "/tmp/project-hardhat-test",
        "network_session_id": "session-hardhat-test",
        "session_kind": "managed-anvil",
        "reuse_permitted": True,
        "chain_id": 31337,
        "genesis_hash": "0x" + "ab" * 32,
        "identity_block_hash": "0x" + "ab" * 32,
        "identity_block_number": 0,
        "rpc": rpc,
        "rpc_fingerprint": "sha256:test",
        "rpc_origin": "http://127.0.0.1:18545",
    }


def _fixture(root: Path):
    (root / "hardhat.config.ts").write_text(
        'import { defineConfig } from "hardhat/config";\n'
        'export default defineConfig({ networks: { localhost: { type: "http", url: process.env.LOWKEY_RPC_URL, accounts: "remote", chainId: 31337 } } });\n',
        encoding="utf-8",
    )
    (root / "package.json").write_text(
        '{"type":"module","devDependencies":{"hardhat":"^3.0.0"}}\n',
        encoding="utf-8",
    )
    (root / "package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")
    script = root / "scripts" / "Deploy.ts"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("export default async function main() {}\n", encoding="utf-8")
    return script


def _network_config(**updates):
    result = {
        "type": "http",
        "url": "http://127.0.0.1:18545",
        "accounts_mode": "remote",
        "from": "0x" + "11" * 20,
        "chain_id": 31337,
    }
    result.update(updates)
    return result


def _build(root, *, network=None, network_config=None, env=None, hardhat="3.0.8", node="v24.22.1"):
    script = _fixture(root)
    return build_hardhat_script_review(
        root,
        script,
        rpc="http://127.0.0.1:18545",
        hardhat_version=hardhat,
        node_version=node,
        network_name="localhost",
        network_config=network_config or _network_config(),
        network_identity=network or _network(),
        sender="0x" + "11" * 20,
        configuration_paths=("hardhat.config.ts", "package.json", "package-lock.json", ".env"),
        environment_values=env or {"LOWKEY_RPC_URL": "http://127.0.0.1:18545", "DEPLOY_TAG": "audit-lab"},
    )


def test_semver_parser_accepts_toolchain_versions():
    assert _version_pair("3.0.8", "Hardhat") == (3, 0, 8)
    assert _version_pair("v24.22.1", "Node.js") == (24, 22, 1)
    assert _version_pair("node v22.13.0", "Node.js") == (22, 13, 0)


def test_review_binds_script_toolchains_config_remote_network_and_managed_session():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        review = _build(root)
        assert review.schema == "lowkey.hardhat-script-review.v1"
        assert review.status == "REVIEW_REQUIRED"
        assert review.network_identity["network_session_id"] == "session-hardhat-test"
        assert review.accounts_mode == "remote"
        assert review.configured_from == "0x" + "11" * 20
        rendered = render_hardhat_script_review(review)
        assert "Session ID" in rendered
        assert "sandbox" in " ".join(review.warnings).lower()


def test_review_rejects_private_key_accounts_and_wrong_network_type():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        with pytest.raises(ValueError, match="accounts='remote'"):
            _build(root, network_config=_network_config(accounts_mode="private-key"))
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        with pytest.raises(ValueError, match="type 'http'"):
            _build(root, network_config=_network_config(type="edr-simulated"))


def test_review_rejects_remote_different_rpc_network_and_from_mismatch():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        with pytest.raises(ValueError, match="loopback"):
            build_hardhat_script_review(
                root, _fixture(root), rpc="https://rpc.example.org",
                hardhat_version="3.0.8", node_version="v24.22.1",
                network_name="localhost",
                network_config=_network_config(url="https://rpc.example.org"),
                network_identity=_network(), sender="0x" + "11" * 20,
                configuration_paths=("hardhat.config.ts",),
            )
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        with pytest.raises(ValueError, match="does not resolve to the active managed Lowkey RPC"):
            _build(root, network_config=_network_config(url="http://127.0.0.1:18546"))
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        with pytest.raises(ValueError, match="does not match this managed session"):
            _build(root, network_config=_network_config(**{"from": "0x" + "22" * 20}))


def test_review_requires_managed_network_hardhat3_and_supported_node():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        with pytest.raises(ValueError, match="managed Anvil"):
            _build(root, network={"chain_id": 31337})
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        with pytest.raises(ValueError, match="Hardhat 3"):
            _build(root, hardhat="2.22.0")
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        with pytest.raises(ValueError, match="Node.js 22.13.0"):
            _build(root, node="v20.12.0")


def test_review_requires_config_fingerprint_and_rejects_outside_script():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        script = _fixture(root)
        with pytest.raises(ValueError, match="config file"):
            build_hardhat_script_review(
                root, script, rpc="http://127.0.0.1:18545",
                hardhat_version="3.0.8", node_version="v24.22.1",
                network_name="localhost", network_config=_network_config(),
                network_identity=_network(), sender="0x" + "11" * 20,
                configuration_paths=("package.json",),
            )
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        outside = Path(temp).parent / "outside-hardhat-review.ts"
        outside.write_text("export default {}\n", encoding="utf-8")
        try:
            with pytest.raises(ValueError, match="inside the current project"):
                build_hardhat_script_review(
                    root, outside, rpc="http://127.0.0.1:18545",
                    hardhat_version="3.0.8", node_version="v24.22.1",
                    network_name="localhost", network_config=_network_config(),
                    network_identity=_network(), sender="0x" + "11" * 20,
                    configuration_paths=("hardhat.config.ts",),
                )
        finally:
            outside.unlink(missing_ok=True)


def test_review_revalidation_detects_script_config_network_and_environment_changes():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        review = _build(root)
        valid, error = verify_hardhat_script_review_current(
            review, root, rpc="http://127.0.0.1:18545",
            hardhat_version="3.0.8", node_version="v24.22.1",
            network_name="localhost", network_config=_network_config(),
            network_identity=_network(), sender="0x" + "11" * 20,
            environment_values={"LOWKEY_RPC_URL": "http://127.0.0.1:18545", "DEPLOY_TAG": "audit-lab"},
        )
        assert valid and error is None

        (root / "scripts" / "Deploy.ts").write_text(
            "export default async function main() { throw new Error('changed'); }\n",
            encoding="utf-8",
        )
        valid, error = verify_hardhat_script_review_current(
            review, root, rpc="http://127.0.0.1:18545",
            hardhat_version="3.0.8", node_version="v24.22.1",
            network_name="localhost", network_config=_network_config(),
            network_identity=_network(), sender="0x" + "11" * 20,
            environment_values={"LOWKEY_RPC_URL": "http://127.0.0.1:18545", "DEPLOY_TAG": "audit-lab"},
        )
        assert not valid and "script content changed" in error

        review = _build(root)
        (root / "hardhat.config.ts").write_text("// changed\n", encoding="utf-8")
        valid, error = verify_hardhat_script_review_current(
            review, root, rpc="http://127.0.0.1:18545",
            hardhat_version="3.0.8", node_version="v24.22.1",
            network_name="localhost", network_config=_network_config(),
            network_identity=_network(), sender="0x" + "11" * 20,
            environment_values={"LOWKEY_RPC_URL": "http://127.0.0.1:18545", "DEPLOY_TAG": "audit-lab"},
        )
        assert not valid and "configuration changed" in error


def test_review_persistence_is_atomic_and_does_not_store_environment_values():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        secret_value = "private-endpoint-token-that-must-not-be-stored"
        review = _build(root, env={"PRIVATE_RPC_TOKEN": secret_value, "LOWKEY_RPC_URL": "http://127.0.0.1:18545"})
        path = persist_hardhat_script_review(review, root, state="REVIEW_REQUIRED")
        evidence = root / path
        raw_evidence = evidence.read_bytes()
        assert raw_evidence.endswith(b"\n")
        assert not raw_evidence.endswith(b"\\n")
        payload = json.loads(raw_evidence)
        assert payload["approval_state"] == "REVIEW_REQUIRED"
        assert payload["review_id"] == review.review_id
        assert secret_value not in evidence.read_text(encoding="utf-8")
        persist_hardhat_script_review(review, root, state="APPROVED")
        updated = json.loads(evidence.read_text(encoding="utf-8"))
        assert updated["approval_state"] == "APPROVED"
        assert updated["created_at"] == payload["created_at"]
