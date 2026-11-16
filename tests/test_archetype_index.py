from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))
from archetypes import _index  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "acceptance" / "p3-genericity"


class ArchetypeIndexTests(unittest.TestCase):
    def test_ten_data_driven_archetype_packs_validate(self):
        packs = _index.load_packs()
        self.assertEqual(
            {item["name"] for item in packs},
            {"vault4626", "lending", "amm_cp", "amm_concentrated", "staking",
             "bridge", "governance", "nft", "escrow", "proxy"},
        )
        for pack in packs:
            self.assertEqual(set(pack), _index.PACK_KEYS)
            for signal in pack["detect_signals"]:
                self.assertEqual(set(signal), _index.SIGNAL_KEYS)

    def test_vault_fixture_classifies_and_emits_resolvable_assumptions(self):
        report = _index.classify_project(FIXTURES / "vault")
        self.assertEqual(report["status"], "OBSERVED")
        self.assertEqual(report["archetype"], "vault4626")
        self.assertGreaterEqual(report["confidence"], _index.CONFIDENCE_FLOOR)
        self.assertTrue(report["assumptions"])
        self.assertTrue(report["citations_all_resolved"])
        self.assertTrue(all(item["verification_status"] == "unverified" for item in report["assumptions"]))
        self.assertIn("protocol-specific attack adapters", report["generic_mode"]["skip_list"])
        self.assertIn("archetype-specific invariant handlers", report["generic_mode"]["skip_list"])
        self.assertIn("asset-specific economic valuation", report["generic_mode"]["skip_list"])

    def test_amm_fixture_classifies_without_vault_false_positive(self):
        report = _index.classify_project(FIXTURES / "amm")
        self.assertEqual(report["status"], "OBSERVED")
        self.assertEqual(report["archetype"], "amm_cp")
        self.assertNotEqual(report["archetype"], "vault4626")

    def test_unknown_fixture_is_loudly_unclassified_with_generic_skip_list(self):
        report = _index.classify_project(FIXTURES / "unknown")
        self.assertEqual(report["status"], "UNCLASSIFIED")
        self.assertIsNone(report["archetype"])
        self.assertEqual(report["confidence"], 0.0)
        self.assertTrue(report["generic_mode"]["enabled"])
        self.assertTrue(report["generic_mode"]["skip_list"])

    def test_protocol_graph_records_import_and_typed_call_candidates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "IOracle.sol").write_text(
                "pragma solidity ^0.8.20; interface IOracle { function latestAnswer() external view returns (int256); }\n",
                encoding="utf-8",
            )
            (root / "src" / "Consumer.sol").write_text(
                'pragma solidity ^0.8.20; import "./IOracle.sol"; contract Consumer {\n'
                "IOracle public oracle; function read() external view returns (int256) { return oracle.latestAnswer(); }\n}\n",
                encoding="utf-8",
            )
            sources, hashes = _index._read_sources(root)
            graph = _index.build_protocol_graph(root, sources, hashes)
            kinds = {edge["kind"] for edge in graph["edges"]}
            self.assertIn("import", kinds)
            self.assertIn("typed_call_candidate", kinds)
            for edge in graph["edges"]:
                citation = edge["citation"]
                self.assertTrue((root / citation["file"]).read_text(encoding="utf-8").splitlines()[citation["line"] - 1].strip())

    def test_citation_verification_rejects_changed_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            shutil.copytree(FIXTURES / "vault", project)
            report = _index.classify_project(project)
            fingerprints = {}
            by_key = {(hit["kind"], hit["file"], hit["line"]): hit for hit in report["evidence"]}
            for item in report["assumptions"]:
                cite = item["citation"]
                hit = by_key[(item["class"], cite["file"], cite["line"])]
                fingerprints[item["id"]] = _index.sha256_text(hit["excerpt"].strip()[:240])
            output = project / ".audit" / "godmode" / "classification.json"
            output.parent.mkdir(parents=True)
            report["citation_fingerprints"] = fingerprints
            output.write_text(json.dumps(report), encoding="utf-8")
            self.assertEqual(_index.verify_report(project, ".audit/godmode/classification.json")["status"], "OBSERVED")
            cited_file = project / report["assumptions"][0]["citation"]["file"]
            lines = cited_file.read_text(encoding="utf-8").splitlines()
            line_index = report["assumptions"][0]["citation"]["line"] - 1
            lines[line_index] += " // changed after discovery"
            cited_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            failed = _index.verify_report(project, ".audit/godmode/classification.json")
            self.assertEqual(failed["status"], "UNRESOLVED")
            self.assertFalse(failed["citations_all_resolved"])

    def test_empty_assumption_ledger_is_not_a_successful_citation_check(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "Empty.sol").write_text(
                "pragma solidity ^0.8.20; contract Empty { function ping() external pure {} }\n",
                encoding="utf-8",
            )
            report = _index.classify_project(root)
            report["assumptions"] = []
            report["citation_fingerprints"] = {}
            output = root / ".audit" / "godmode" / "empty.json"
            output.parent.mkdir(parents=True)
            output.write_text(json.dumps(report), encoding="utf-8")
            verified = _index.verify_report(root, ".audit/godmode/empty.json")
            self.assertEqual(verified["status"], "UNRESOLVED")
            self.assertFalse(verified["citations_all_resolved"])

    def test_malformed_assumption_ledger_is_a_controlled_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { function deposit(uint256 assets) external pure returns(uint256) { return assets; } function totalAssets() external pure returns(uint256) { return 1; } }\n",
                encoding="utf-8",
            )
            report = _index.classify_project(root)
            report["assumptions"] = {"not": "a list"}
            report["citation_fingerprints"] = {}
            output = root / ".audit" / "godmode" / "malformed.json"
            output.parent.mkdir(parents=True)
            output.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(_index.ArchetypeError):
                _index.verify_report(root, ".audit/godmode/malformed.json")

    def test_cli_writes_a_reproducible_json_report(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "vault"
            shutil.copytree(FIXTURES / "vault", project)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = _index.main([
                    "--root", str(project),
                    "--output", ".audit/godmode/archetype-classification.json",
                    "--json",
                ])
            self.assertEqual(code, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["archetype"], "vault4626")
            self.assertTrue((project / report["report_path"]).is_file())


if __name__ == "__main__":
    unittest.main()
