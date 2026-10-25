"""Contract tests for the external test-generation benchmark corpus."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "fixtures" / "test-generation-ecosystem.json"
REQUIRED_TYPES = {
    "unit", "fuzz", "invariant", "integration",
    "fork", "poc", "regression", "formal",
}


class TestGenerationEcosystemManifest(unittest.TestCase):
    def test_manifest_is_valid_and_covers_all_requested_categories(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 1)
        self.assertTrue(payload["policy"]["implementation_must_not_branch_on_repository_identity"])
        projects = payload["projects"]
        self.assertGreaterEqual(len(projects), 7)
        ids = [project["id"] for project in projects]
        self.assertEqual(len(ids), len(set(ids)))
        repositories = [project["repository"] for project in projects]
        self.assertEqual(len(repositories), len(set(repositories)))
        for project in projects:
            with self.subTest(project=project["id"]):
                self.assertTrue(project["repository"].startswith("https://github.com/"))
                self.assertRegex(project.get("revision", ""), r"^[0-9a-f]{40}$")
                self.assertTrue(project["target_candidates"])
                self.assertTrue(project["architectural_challenges"])
                self.assertTrue(project["required_evidence"])
                self.assertEqual(set(project["categories_to_evaluate"]), REQUIRED_TYPES)

    def test_corpus_spans_distinct_architectures_and_a_negative_control(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        challenges = {
            challenge.lower()
            for project in payload["projects"]
            for challenge in project["architectural_challenges"]
        }
        for expected in (
            "inheritance", "assembly-heavy code", "amm accounting",
            "lending accounting", "cross-chain message state",
            "singleton architecture", "test-only framework rather than a protocol",
        ):
            with self.subTest(challenge=expected):
                self.assertIn(expected, challenges)

        negative_controls = [
            project for project in payload["projects"]
            if project.get("expected_outcome")
        ]
        self.assertTrue(negative_controls)
        self.assertTrue(all("instead of inventing" in item["expected_outcome"] for item in negative_controls))


if __name__ == "__main__":
    unittest.main()
