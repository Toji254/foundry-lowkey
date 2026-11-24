from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import godmode


class Tier0FingerprintTests(unittest.TestCase):
    def _vault_source(self):
        return """// mapping(address => uint256) fake; msg.sender.call(); balances[msg.sender] = 0;
contract Vault {
    mapping(address => uint256) private balances;

    function withdraw() external {
        // This comment must not be included as a second mapping write.
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""

    def test_fingerprint_hashes_patterns_and_finds_ordered_mapping_call_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "Vault.sol").write_text(self._vault_source(), encoding="utf-8")

            first = godmode.cheat_fingerprints(root)
            second = godmode.cheat_fingerprints(root)

            self.assertEqual(first["schema_version"], 2)
            self.assertEqual(first["algorithm"], "Aho-Corasick over normalized Solidity tokens")
            self.assertGreater(first["patterns"], 0)
            self.assertEqual(first["pattern_hashes"], second["pattern_hashes"])
            self.assertTrue(all(len(row["pattern_id"]) == 20 for row in first["pattern_hashes"]))

            sequences = first["ordered_sequences"]
            self.assertTrue(sequences, "Expected mapping-read -> external-call -> mapping-write evidence")
            match = next(row for row in sequences if row["mapping"] == "balances")
            self.assertEqual(match["function"], "withdraw")
            self.assertEqual(match["key_expression"], "msg . sender")
            self.assertEqual(match["external_method"], "call")
            self.assertLess(match["read_line"], match["call_line"])
            self.assertLess(match["call_line"], match["write_line"])
            self.assertIn("unproven", match["meaning"].lower())

    def test_fingerprint_cli_writes_machine_readable_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "Vault.sol").write_text(self._vault_source(), encoding="utf-8")
            code = godmode.fingerprint(["--root", str(root), "--output", ".audit/fingerprints.json"])
            self.assertEqual(code, 0)
            report = json.loads((root / ".audit" / "fingerprints.json").read_text(encoding="utf-8"))
            self.assertIn("ordered_sequences", report)
            self.assertIn("pattern_hashes", report)

    def test_fingerprint_recognizes_safe_transfer_and_struct_field_write(self):
        source = """contract Vault {
    struct Account { uint256 balance; }
    mapping(address => Account) internal accounts;
    IERC20 token;
    function withdraw() external {
        uint256 amount = accounts[msg.sender].balance;
        token.safeTransfer(msg.sender, amount);
        accounts[msg.sender].balance = 0;
    }
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "Vault.sol").write_text(source, encoding="utf-8")
            sequences = godmode.cheat_fingerprints(root)["ordered_sequences"]
            match = next(row for row in sequences if row["mapping"] == "accounts")
            self.assertEqual(match["external_method"], "safetransfer")
            self.assertEqual(match["key_expression"], "msg . sender")
            self.assertLess(match["read_line"], match["call_line"])
            self.assertLess(match["call_line"], match["write_line"])

    def test_fingerprint_does_not_treat_local_assignment_as_mapping_write(self):
        source = """contract Vault {
    mapping(address => uint256) internal balances;
    IERC20 token;
    function inspect() external {
        uint256 amount = balances[msg.sender];
        token.transfer(msg.sender, amount);
        uint256 localCopy = amount;
    }
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "Vault.sol").write_text(source, encoding="utf-8")
            sequences = godmode.cheat_fingerprints(root)["ordered_sequences"]
            self.assertFalse(sequences)


class Tier0OrchestratorTests(unittest.TestCase):
    def test_godmode_writes_schema_valid_artifact_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir()
            source.write_text(
                "pragma solidity ^0.8.20; contract Vault { uint256 public value; }",
                encoding="utf-8",
            )

            code = godmode.godmode(["--root", str(root), "--plan-only"])
            self.assertEqual(code, 2)  # Required execution/control stages were intentionally skipped.
            latest = root / ".audit" / "godmode" / "latest.json"
            provenance = root / ".audit" / "godmode" / "provenance.json"
            report = json.loads(provenance.read_text(encoding="utf-8"))

            self.assertEqual(report["schema_version"], 2)
            self.assertEqual(report["signature"]["status"], "unsigned")
            self.assertEqual(len(report["artifacts"]), 1)
            artifact = report["artifacts"][0]
            self.assertEqual(artifact["path"], ".audit/godmode/latest.json")
            self.assertEqual(artifact["sha256"], godmode.sha(latest))
            self.assertEqual(artifact["bytes"], latest.stat().st_size)


class Tier0MutationTests(unittest.TestCase):
    def _run(self, report):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        manifest = {
            "family": "reentrancy",
            "command": [sys.executable, "-c", "print('baseline')"],
            "mutants": [
                {"id": f"reentrancy-{index}", "family": "reentrancy"}
                for index in range(len(report.get("mutants", [])))
            ],
        }
        (root / "mutations.json").write_text(json.dumps(manifest), encoding="utf-8")

        def fake_run_cli(args):
            output = pathlib.Path(args[args.index("--output") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report), encoding="utf-8")
            return 0

        module = types.SimpleNamespace(run_cli=fake_run_cli)
        return temporary, root, patch.dict(sys.modules, {"behavioral_validation": module})

    def test_mutation_gate_passes_only_when_every_mutant_is_scored(self):
        report = {
            "status": "completed",
            "baseline": {"status": "passed"},
            "summary": {"killed": 9, "survived": 1, "invalid": 0, "timeout": 0, "error": 0},
            "mutants": [{"id": f"m{index}", "status": "killed" if index < 9 else "survived"} for index in range(10)],
            "mutation_score": 0.9,
        }
        temporary, root, module_patch = self._run(report)
        try:
            with module_patch:
                code = godmode.mutation(["mutations.json", "--root", str(root), "--min-score", "0.9"])
            self.assertEqual(code, 0)
            saved = json.loads((root / ".audit" / "verification" / "mutation-score-report.json").read_text())
            self.assertTrue(saved["gate"]["passed"])
            self.assertEqual(saved["family"], "reentrancy")
            self.assertTrue(saved["gate"]["all_mutants_scored"])
        finally:
            temporary.cleanup()

    def test_mutation_gate_fails_if_invalid_mutant_is_excluded_from_score(self):
        report = {
            "status": "completed",
            "baseline": {"status": "passed"},
            "summary": {"killed": 9, "survived": 0, "invalid": 1, "timeout": 0, "error": 0},
            "mutants": [{"id": f"m{index}", "status": "killed"} for index in range(9)] + [{"id": "invalid", "status": "invalid"}],
            "mutation_score": 1.0,
        }
        temporary, root, module_patch = self._run(report)
        try:
            with module_patch:
                code = godmode.mutation(["mutations.json", "--root", str(root), "--min-score", "0.9"])
            self.assertEqual(code, 1)
            saved = json.loads((root / ".audit" / "verification" / "mutation-score-report.json").read_text())
            self.assertFalse(saved["gate"]["passed"])
            self.assertEqual(saved["gate"]["invalid"], 1)
            self.assertFalse(saved["gate"]["all_mutants_scored"])
        finally:
            temporary.cleanup()

    def test_mutation_gate_requires_one_declared_family(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "mutations.json").write_text(json.dumps({
                "command": ["true"], "mutants": [{"id": "m1"}]
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Declare one family"):
                godmode.mutation(["mutations.json", "--root", str(root)])

    def test_mutation_gate_rejects_summary_that_disagrees_with_mutant_rows(self):
        report = {
            "status": "completed",
            "baseline": {"status": "passed"},
            "summary": {"killed": 10, "survived": 0, "invalid": 0, "timeout": 0, "error": 0},
            "mutants": [
                {"id": f"m{index}", "status": "killed"} for index in range(9)
            ] + [{"id": "m-invalid", "status": "invalid"}],
            "mutation_score": 1.0,
        }
        temporary, root, module_patch = self._run(report)
        try:
            with module_patch:
                code = godmode.mutation(["mutations.json", "--root", str(root), "--min-score", "0.9"])
            self.assertEqual(code, 1)
            saved = json.loads((root / ".audit" / "verification" / "mutation-score-report.json").read_text())
            self.assertFalse(saved["gate"]["passed"])
            self.assertFalse(saved["gate"]["summary_matches_mutants"])
            self.assertFalse(saved["gate"]["all_mutants_scored"])
        finally:
            temporary.cleanup()


class Tier0CoverageTests(unittest.TestCase):
    def test_coverage_threshold_is_enforced_against_fresh_lcov(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir()
            source.write_text("contract Vault {\n    function withdraw() external {}\n}\n", encoding="utf-8")

            def fake_run(argv, cwd, timeout=300, env=None):
                (pathlib.Path(cwd) / "lcov.info").write_text(
                    f"SF:{source}\nDA:1,1\nDA:2,0\nend_of_record\n",
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(godmode.shutil, "which", return_value="/usr/bin/forge"), patch.object(godmode, "run", side_effect=fake_run):
                code = godmode.coverage([
                    "src/Vault.sol", "--root", str(root), "--min-percent", "75",
                    "--match-test", "test_reentrancy",
                ])
                self.assertEqual(code, 1)
                report = json.loads((root / ".audit" / "godmode" / "target-coverage.json").read_text())
                self.assertEqual(report["percent"], 50.0)
                self.assertEqual(report["minimum_percent"], 75.0)
                self.assertFalse(report["gate_passed"])
                self.assertIn("--match-test", report["command"])

                passed = godmode.coverage([
                    "src/Vault.sol", "--root", str(root), "--min-percent", "50",
                ])
                self.assertEqual(passed, 0)
                passed_report = json.loads((root / ".audit" / "godmode" / "target-coverage.json").read_text())
                self.assertTrue(passed_report["gate_passed"])


class Tier0ProvenanceTests(unittest.TestCase):
    def test_signed_provenance_verifies_signature_and_artifact_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = pathlib.Path(temporary)
            root = workspace / "project"
            root.mkdir()
            source = root / "Exploit.t.sol"
            source.write_text("contract Exploit {}", encoding="utf-8")
            key = workspace / "provenance-private.pem"

            openssl = godmode.shutil.which("openssl")
            if not openssl:
                self.skipTest("OpenSSL is unavailable")
            generated = subprocess.run(
                [openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
                capture_output=True, text=True, check=False,
            )
            if generated.returncode:
                self.skipTest("OpenSSL RSA key generation is unavailable: " + generated.stderr[-500:])

            code = godmode.provenance([
                "Exploit.t.sol", "--root", str(root), "--signing-key", str(key),
            ])
            self.assertEqual(code, 0)
            manifest = root / ".audit" / "godmode" / "provenance.json"
            signed = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(signed["signature"]["status"], "signed")
            self.assertTrue((root / signed["signature"]["signature_file"]).is_file())
            self.assertTrue((root / signed["signature"]["public_key_file"]).is_file())

            self.assertEqual(
                godmode.provenance([
                    "--root", str(root), "--verify", ".audit/godmode/provenance.json",
                ]),
                1,
                "A public key shipped beside a manifest must not be trusted automatically.",
            )
            trusted_key = workspace / "trusted-provenance-public.pem"
            trusted_key.write_bytes((root / signed["signature"]["public_key_file"]).read_bytes())
            with self.assertRaisesRegex(ValueError, "must be outside --root"):
                godmode.provenance([
                    "--root", str(root), "--verify", ".audit/godmode/provenance.json",
                    "--public-key", str(root / signed["signature"]["public_key_file"]),
                ])
            verified = godmode.provenance([
                "--root", str(root), "--verify", ".audit/godmode/provenance.json",
                "--public-key", str(trusted_key),
            ])
            self.assertEqual(verified, 0)

            source.write_text("contract Exploit { function changed() external {} }", encoding="utf-8")
            tampered = godmode.provenance([
                "--root", str(root), "--verify", ".audit/godmode/provenance.json",
                "--public-key", str(trusted_key),
            ])
            self.assertEqual(tampered, 1)

            # A correctly signed manifest with no artifacts must still fail:
            # signature validity alone is not proof that evidence was recorded.
            signed["artifacts"] = []
            manifest.write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
            signature_path = root / signed["signature"]["signature_file"]
            resigned = subprocess.run(
                [openssl, "dgst", "-sha256", "-sign", str(key), "-out", str(signature_path), str(manifest)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(resigned.returncode, 0, resigned.stderr)
            empty = godmode.provenance([
                "--root", str(root), "--verify", ".audit/godmode/provenance.json",
                "--public-key", str(trusted_key),
            ])
            self.assertEqual(empty, 1)

            signed["artifacts"] = 42
            manifest.write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
            resigned = subprocess.run(
                [openssl, "dgst", "-sha256", "-sign", str(key), "-out", str(signature_path), str(manifest)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(resigned.returncode, 0, resigned.stderr)
            malformed = godmode.provenance([
                "--root", str(root), "--verify", ".audit/godmode/provenance.json",
                "--public-key", str(trusted_key),
            ])
            self.assertEqual(malformed, 1)
