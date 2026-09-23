import json
from pathlib import Path

import audit_engine


def test_parse_slither_payload_normalizes_detector():
    payload = {
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "candidate",
                    "elements": [
                        {
                            "name": "withdraw()",
                            "type": "function",
                            "source_mapping": {
                                "filename_relative": "src/Vault.sol",
                                "lines": [42, 48],
                            },
                        }
                    ],
                }
            ]
        }
    }
    findings = audit_engine.parse_slither_payload(payload)
    assert findings[0]["check"] == "reentrancy-eth"
    assert findings[0]["impact"] == "high"
    assert findings[0]["confidence"] == "medium"
    assert findings[0]["locations"][0]["source"] == "src/Vault.sol"
    assert findings[0]["locations"][0]["start"] == 42


def test_generate_poc_uses_slither_evidence_and_matrix(tmp_path, monkeypatch):
    lowkey = tmp_path / ".lowkey"
    lowkey.mkdir()
    (lowkey / "config.json").write_text(
        json.dumps(
            {
                "target": "0x1111111111111111111111111111111111111111",
                "rpc": "http://127.0.0.1:8545",
                "last_tx": "0x" + "a" * 64,
                "abi_paths": {},
            }
        )
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    evidence = tmp_path / ".audit" / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "slither.json").write_text(
        json.dumps(
            {
                "data": {
                    "findings": [
                        {
                            "check": "reentrancy-eth",
                            "impact": "high",
                            "confidence": "high",
                            "description": "External call before effects.",
                            "locations": [
                                {
                                    "name": "withdraw",
                                    "source": "src/Vault.sol",
                                    "start": 42,
                                    "end": 48,
                                }
                            ],
                        }
                    ]
                }
            }
        )
    )

    code, files = audit_engine.generate_poc(str(tmp_path))
    assert code == 0
    assert len(files) == 2
    solidity = (tmp_path / ".audit" / "poc" / "Poc_reentrancy_eth.t.sol").read_text()
    assert "PocAttacker" in solidity
    assert "reentrancy-eth" in solidity
    brief = json.loads((tmp_path / ".audit" / "poc" / "Poc_reentrancy_eth.json").read_text())
    assert brief["candidate"]["mode"] == "reentrancy"
    assert brief["candidate"]["impact"] == "high"


def test_run_rg_treats_no_match_as_success(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_engine, "rg_available", lambda: True)

    def fake_run(command, root, timeout):
        return 1, "", ""

    monkeypatch.setattr(audit_engine, "run_command", fake_run)
    assert audit_engine.run_rg("does-not-exist", root=str(tmp_path)) == 0
    evidence = json.loads((tmp_path / ".audit" / "evidence" / "rg.json").read_text())
    assert evidence["data"]["hits"] == []
