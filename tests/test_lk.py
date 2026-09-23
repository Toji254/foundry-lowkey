import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkeycast", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


def test_address_validation():
    assert lk.is_address("0x" + "1" * 40)
    assert not lk.is_address("0x" + "1" * 64)
    assert not lk.is_address("not-an-address")


def test_tuple_canonicalization():
    assert lk.canonical_type({
        "type": "tuple",
        "components": [{"type": "address"}, {"type": "uint256"}],
    }) == "(address,uint256)"
    assert lk.canonical_type({
        "type": "tuple[]",
        "components": [{"type": "address"}, {"type": "uint256[]"}],
    }) == "(address,uint256[])[]"


def test_output_signature():
    item = {
        "name": "quote",
        "inputs": [{"type": "address"}],
        "outputs": [{"type": "uint256"}, {"type": "bool"}],
    }
    assert lk.format_output_signature(item) == "quote(address)(uint256,bool)"


def test_overload_matching_requires_full_signature():
    abi = [
        {"type": "function", "name": "foo", "inputs": [{"type": "uint256"}]},
        {"type": "function", "name": "foo", "inputs": [{"type": "address"}]},
    ]
    assert len(lk.matching_functions(abi, "foo")) == 2
    assert len(lk.matching_functions(abi, "foo(uint256)")) == 1


def test_target_resolution_by_alias_and_number():
    first = "0x" + "1" * 40
    second = "0x" + "2" * 40
    config = {"target": None, "aliases": {"alpha": first, "beta": second}, "targets": {}}
    assert lk.resolve_target_ref(config, "alpha") == first
    assert lk.resolve_target_ref(config, "1") == first


def test_secret_redaction():
    key = "0x" + "a" * 64
    assert "<redacted>" in lk.redact_secrets(f"--private-key {key}")
    assert key not in lk.redact_secrets(f"--private-key {key}")
    assert "<redacted>" in lk.redact_secrets("--jwt-secret supersecret")


def test_rpc_redaction():
    public = "https://example.com/sensitive-token"
    redacted = lk.redact_secrets(f"--rpc-url {public}")
    assert "sensitive-token" not in redacted
    assert "<redacted>" in redacted


def test_eth_humanization():
    assert "1.0000 ETH" in lk.humanize_value("1000000000000000000")


def test_private_key_normalization():
    raw = "b" * 64
    assert lk.normalize_private_key(raw) == "0x" + raw
    assert lk.normalize_private_key("bad-key") is None
