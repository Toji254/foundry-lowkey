"""Regression tests for Lowkey's beginner-first attack reference."""
from __future__ import annotations

import contextlib
import io
import pathlib
import re
import unittest

from lowkey import attack_library as attacks


ROOT = pathlib.Path(__file__).resolve().parents[1]


def capture(function, *args, **kwargs):
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        code = function(*args, **kwargs)
    return code, stream.getvalue()


class AttackLibraryTests(unittest.TestCase):
    def test_catalogue_integrity_and_scale(self):
        self.assertGreaterEqual(len(attacks.ATTACKS), 200)
        self.assertEqual(attacks.validate_catalogue(), [])
        identifiers = [item["id"] for item in attacks.ATTACKS]
        slugs = [item["slug"] for item in attacks.ATTACKS]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual(len(slugs), len(set(slugs)))

    def test_every_requested_severity_level_is_represented(self):
        actual = {item["severity"] for item in attacks.ATTACKS}
        self.assertEqual(actual, set(attacks.SEVERITIES))
        for level in attacks.SEVERITIES:
            rows = [item for item in attacks.ATTACKS if item["severity"] == level]
            self.assertTrue(rows, f"no entries are rated {level}")

    def test_severity_guide_explains_context_not_universal_rating(self):
        code, output = capture(attacks.render_severity)
        self.assertEqual(code, 0)
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            self.assertIn(level, output)
        self.assertIn("typical teaching estimates", output)
        self.assertIn("program's own rubric", output)

    def test_search_covers_evm_defi_account_abstraction_and_other_vms(self):
        cases = (
            ("single-function-reentrancy", "single-function-reentrancy"),
            ("share-inflation-donation", "share-inflation-donation"),
            ("eip7702-delegation-confusion", "eip7702-delegation-confusion"),
            ("nullifier-reuse", "nullifier-reuse"),
            ("paymaster-drain", "paymaster-drain"),
            ("solana-missing-signer", "solana-missing-signer"),
            ("move-capability-leak", "move-capability-leak"),
            ("ibc-packet-replay", "ibc-packet-replay"),
        )
        for query, expected_slug in cases:
            with self.subTest(query=query):
                rows = attacks.search_attacks(query)
                self.assertTrue(rows, f"no search result for {query}")
                self.assertIn(expected_slug, {row["entry"]["slug"] for row in rows})

    def test_lookup_accepts_catalogue_ids_slugs_and_human_terms(self):
        self.assertEqual(attacks.find_attack("EVM-001")["slug"], "single-function-reentrancy")
        self.assertEqual(attacks.find_attack("single-function-reentrancy")["id"], "EVM-001")
        self.assertEqual(attacks.find_attack("share inflation donation")["slug"], "share-inflation-donation")

    def test_attack_card_explains_pattern_audit_signal_and_mitigation(self):
        entry = attacks.find_attack("single-function-reentrancy")
        code, output = capture(attacks.render_card, entry)
        self.assertEqual(code, 0)
        for phrase in (
            "LOWKEY // ATTACK CARD",
            "Severity:",
            "PLAIN ENGLISH",
            "VULNERABLE SHAPE",
            "AUDIT SIGNAL",
            "LOCAL REPRODUCTION IDEA",
            "MITIGATION DIRECTION",
            "CROSS-REFERENCES",
        ):
            self.assertIn(phrase, output)

    def test_informational_entries_are_explicitly_non_findings_without_impact(self):
        code, output = capture(attacks.render_list, ["--severity", "Informational", "--all"])
        self.assertEqual(code, 0)
        self.assertIn("INFORMATIONAL", output)
        self.assertIn("insufficient-test-coverage", output)
        self.assertIn("event-observability-gap", output)
        entry = attacks.find_attack("insufficient-test-coverage")
        self.assertIn("not proof", entry["plain"].lower())

    def test_owasp_specific_weakness_ids_resolve_to_the_source_catalogue(self):
        entry = attacks.find_attack("incorrect-constructor-name")
        self.assertIn("OWASP-SCWE-070", entry["references"])
        code, output = capture(attacks._print_refs, entry)
        self.assertIsNone(code)
        self.assertIn("OWASP SCWE identifier: OWASP-SCWE-070", output)
        self.assertIn(attacks.REFERENCE_SOURCES["OWASP-SCWE"]["url"], output)

    def test_protocol_maps_reference_real_catalogue_entries(self):
        self.assertEqual(attacks.validate_catalogue(), [])
        for profile in ("general", "lending", "dex", "vault", "bridge", "governance",
                        "wallet", "account-abstraction", "solana", "move", "cosmos", "privacy"):
            with self.subTest(profile=profile):
                code, output = capture(attacks.render_map, profile)
                self.assertEqual(code, 0)
                self.assertIn("AUDIT ATTACK-SURFACE MAP", output)
                self.assertIn("These are hypotheses to investigate", output)

    def test_learning_lab_and_quiz_are_local_and_beginner_first(self):
        entry = attacks.find_attack("single-function-reentrancy")
        code, lesson = capture(attacks.render_learn, entry)
        self.assertEqual(code, 0)
        for phrase in ("THE SIMPLE EXPLANATION", "REPRODUCE IT STEP BY STEP",
                       "YOUR ATTACK-SPECIFIC EXPERIMENT", "WHAT COUNTS AS PROOF"):
            self.assertIn(phrase, lesson)

        code, lab = capture(attacks.render_lab, entry)
        self.assertEqual(code, 0)
        self.assertIn("LOCAL ATTACK LAB", lab)
        self.assertIn("local test networks only", lab)
        self.assertIn("ToyVault", lab)
        self.assertNotIn("https://", lab)

        code, quiz = capture(attacks.render_quiz, entry)
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY // ATTACK CHECK", quiz)
        self.assertIn("What exact precondition", quiz)

    def test_incident_and_source_indexes_are_available(self):
        code, incidents = capture(attacks.render_incidents, "")
        self.assertEqual(code, 0)
        self.assertIn("DOCUMENTED INCIDENT STARTING POINTS", incidents)
        self.assertIn("The DAO", incidents)
        code, sources = capture(attacks.render_sources)
        self.assertEqual(code, 0)
        self.assertIn("OWASP Smart Contract Weakness Enumeration", sources)
        self.assertIn("DeFiHackLabs", sources)

    def test_public_cli_check_and_help(self):
        code, output = capture(attacks.run, ["check"])
        self.assertEqual(code, 0)
        self.assertIn("Result    : PASS", output)
        code, help_text = capture(attacks.run, ["--help"])
        self.assertEqual(code, 0)
        self.assertIn("lk attack learn", help_text)
        self.assertIn("lk attack severity", help_text)
        self.assertIn("lk attack map", help_text)

    def test_launcher_routes_attack_before_generic_help_interception(self):
        source = (ROOT / "bin" / "lk").read_text(encoding="utf-8")
        route = source.index('if [[ "${1:-}" == "attack"')
        generic_help = source.index('for arg in "$@"')
        self.assertLess(route, generic_help)
        self.assertIn('attack_library.py', source)

    def test_installer_stages_compiles_publishes_and_hashes_both_modules(self):
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        for filename in ("attack_library.py", "attack_catalog.py"):
            with self.subTest(filename=filename):
                self.assertIn(filename, source)
                self.assertIn(f'"$STAGE_DIR/{filename}"', source)
                self.assertIn(f'"$TARGET_LOWKEY_DIR/{filename}"', source)
                self.assertIn(f'sha256(lowkey_dir / "{filename}")', source)

    def test_readme_documents_attack_library_quick_start_and_severity(self):
        source = (ROOT / "README.md").read_text(encoding="utf-8")
        for item in ("lk attack", "lk attack search", "lk attack learn",
                     "lk attack map lending", "Informational", "typical starting estimates"):
            self.assertIn(item, source)


if __name__ == "__main__":
    unittest.main()
