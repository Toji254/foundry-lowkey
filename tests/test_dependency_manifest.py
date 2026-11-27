from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lowkey.dependency_manifest import MANIFEST_SCHEMA, load_dependency_manifest


class DependencyManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / ".audit").mkdir()
        self.path = self.root / ".audit" / "dependencies.json"

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, payload):
        self.path.write_text(json.dumps(payload), encoding="utf-8")

    def _entry(self, **overrides):
        entry = {
            "id": "positionmanager-vault",
            "consumer": "contracts/core/PositionManager.sol:PositionManager",
            "parameter": "_vault",
            "kind": "vault",
        }
        entry.update(overrides)
        return entry

    def _network(self):
        genesis = "0x" + "ab" * 32
        return {
            "project_id": "project-a",
            "network_session_id": "session-a",
            "chain_id": 31337,
            "genesis_hash": genesis,
            "identity_block_hash": genesis,
        }

    def test_absent_manifest_is_explicitly_not_present(self):
        result = load_dependency_manifest(self.root).to_dict()
        self.assertEqual(result["status"], "NOT_PRESENT")
        self.assertEqual(result["dependencies"], [])
        self.assertEqual(result["warnings"], [])

    def test_valid_manifest_preserves_schema_and_content_provenance(self):
        self._write({"schema": MANIFEST_SCHEMA, "dependencies": [self._entry()]})
        result = load_dependency_manifest(self.root).to_dict()
        self.assertEqual(result["status"], "VALID")
        self.assertEqual(result["schema"], MANIFEST_SCHEMA)
        self.assertEqual(len(result["sha256"]), 64)
        self.assertEqual(result["dependencies"][0]["kind"], "vault")
        self.assertIsNone(result["network_identity"])

    def test_address_requires_explicit_session_identity(self):
        self._write({
            "schema": MANIFEST_SCHEMA,
            "dependencies": [self._entry(address="0x" + "11" * 20)],
        })
        result = load_dependency_manifest(self.root).to_dict()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["dependencies"], [])
        self.assertIn("network_identity", result["warnings"][0])

    def test_bad_address_and_unknown_dependency_kind_fail_closed(self):
        for entry in (self._entry(address="0x1234"), self._entry(kind="magic-address")):
            self._write({
                "schema": MANIFEST_SCHEMA,
                "network_identity": self._network(),
                "dependencies": [entry],
            })
            result = load_dependency_manifest(self.root).to_dict()
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["dependencies"], [])

    def test_duplicate_id_or_constructor_binding_fails_closed(self):
        self._write({
            "schema": MANIFEST_SCHEMA,
            "dependencies": [self._entry(), self._entry(id="second-id")],
        })
        result = load_dependency_manifest(self.root).to_dict()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("Duplicate constructor binding", result["warnings"][0])

    def test_duplicate_json_object_keys_are_rejected(self):
        self.path.write_text(
            '{"schema":"lowkey.external-dependencies.v1","schema":"lowkey.external-dependencies.v1","dependencies":[]}',
            encoding="utf-8",
        )
        result = load_dependency_manifest(self.root).to_dict()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("Duplicate JSON object key", result["warnings"][0])

    def test_consumer_must_have_nonempty_source_and_contract_parts(self):
        self._write({
            "schema": MANIFEST_SCHEMA,
            "dependencies": [self._entry(consumer=":Widget")],
        })
        result = load_dependency_manifest(self.root).to_dict()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("source-qualified identity", result["warnings"][0])

    def test_manifest_symlink_cannot_escape_project_root(self):
        outside = Path(self.temp.name).parent / (Path(self.temp.name).name + "-outside.json")
        try:
            outside.write_text(json.dumps({"schema": MANIFEST_SCHEMA, "dependencies": []}), encoding="utf-8")
            self.path.symlink_to(outside)
            result = load_dependency_manifest(self.root).to_dict()
            self.assertEqual(result["status"], "BLOCKED")
            self.assertIn("outside", result["warnings"][0].lower())
        finally:
            try:
                outside.unlink()
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    unittest.main()
