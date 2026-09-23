import json
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("audit_engine", ROOT / "lowkey" / "audit_engine.py")
audit_engine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_engine)


class AuditEngineTests(unittest.TestCase):
    def test_parse_slither_payload_normalizes_detector(self):
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
        self.assertEqual(findings[0]["check"], "reentrancy-eth")
        self.assertEqual(findings[0]["impact"], "high")
        self.assertEqual(findings[0]["confidence"], "medium")
        self.assertEqual(findings[0]["locations"][0]["source"], "src/Vault.sol")
        self.assertEqual(findings[0]["locations"][0]["start"], 42)

    def test_generate_poc_uses_slither_evidence_and_matrix(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            lowkey = root / ".lowkey"
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
            evidence = root / ".audit" / "evidence"
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
                                            "name": "withdraw()",
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

            with patch.dict("os.environ", {"HOME": str(root)}, clear=False):
                code, files = audit_engine.generate_poc(str(root))

            self.assertEqual(code, 0)
            self.assertEqual(len(files), 2)
            solidity = (root / "test" / "Poc_reentrancy_eth.t.sol").read_text()
            self.assertIn("PocAttacker", solidity)
            self.assertIn("reentrancy-eth", solidity)
            brief = json.loads((root / ".audit" / "poc" / "Poc_reentrancy_eth.json").read_text())
            self.assertEqual(brief["candidate"]["mode"], "reentrancy")
            self.assertEqual(brief["candidate"]["impact"], "high")

    def test_run_source_triage_handles_relative_root(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            src = root / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { function f() external { tx.origin; } }",
                encoding="utf-8",
            )
            with patch.object(audit_engine, "record_evidence") as record:
                self.assertEqual(audit_engine.run_source_triage(str(root)), 0)
                payload = record.call_args.args[1]
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["markers"][0]["label"], "TX.ORIGIN")

    def test_run_rg_treats_no_match_as_success(self):
        with patch.object(audit_engine, "rg_available", return_value=True), patch.object(
            audit_engine, "run_command", return_value=(1, "", "")
        ):
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as raw:
                root = Path(raw)
                self.assertEqual(audit_engine.run_rg("does-not-exist", root=str(root)), 0)
                evidence = json.loads((root / ".audit" / "evidence" / "rg.json").read_text())
                self.assertEqual(evidence["data"]["hits"], [])


if __name__ == "__main__":
    unittest.main()
