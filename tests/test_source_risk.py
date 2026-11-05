from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import source_risk


class SourceRiskTests(unittest.TestCase):
    def test_source_pattern_matches_ignore_comments_and_are_not_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                """
                pragma solidity ^0.8.20;
                contract Vault {
                    // tx.origin; delegatecall; selfdestruct(address(0));
                    function withdraw(address target) external {
                        (bool ok,) = target.call("");
                        require(ok);
                        uint256 nowish = block.timestamp;
                    }
                }
                """,
                encoding="utf-8",
            )
            graph = {
                "nodes": [{"file": "src/Vault.sol", "declarations": [{"kind": "contract", "name": "Vault"}], "calls": []}],
            }

            matches = source_risk._source_matches(root, graph)

            patterns = {item["pattern"] for item in matches}
            self.assertEqual(patterns, {"low-level call", "block timestamp"})
            self.assertTrue(all(item["evidence_status"] == "syntax-match" for item in matches))
            self.assertTrue(all("not a vulnerability verdict" in item["verdict"] for item in matches))

    def test_runtime_mode_explains_missing_live_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            (root / "src").mkdir()
            with patch.object(source_risk, "_select_source_root", return_value=(root, None)), patch.object(
                source_risk.audit_context, "load", return_value={"target": {}, "rpc": None, "actor": None}
            ):
                result = source_risk.main(["--runtime"])
            self.assertEqual(result, 2)


if __name__ == "__main__":
    unittest.main()
