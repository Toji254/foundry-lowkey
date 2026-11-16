import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"
if str(ROOT / "lowkey") not in sys.path:
    sys.path.insert(0, str(ROOT / "lowkey"))
spec = importlib.util.spec_from_file_location("lowkey_artifact_runtime_normalizer", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class ArtifactRuntimeNormalizerTests(unittest.TestCase):
    def setUp(self):
        self.expected = "0x6000" + "11" * 20 + "6000"
        self.live = "0x6000" + "22" * 20 + "6000"
        self.references = {"12345": [{"start": 2, "length": 20}]}

    def test_solc_nested_immutable_references_match_deployed_runtime(self):
        artifact = {
            "deployedBytecode": {
                "object": self.expected,
                "immutableReferences": self.references,
            }
        }
        normalize = lk._artifact_runtime_normalizer(artifact)
        self.assertIsNotNone(normalize)
        self.assertTrue(normalize(self.live))

    def test_flattened_foundry_immutable_references_match_deployed_runtime(self):
        artifact = {
            "deployedBytecode": self.expected,
            "deployedBytecodeImmutableReferences": self.references,
        }
        normalize = lk._artifact_runtime_normalizer(artifact)
        self.assertIsNotNone(normalize)
        self.assertTrue(normalize(self.live))

    def test_legacy_flat_immutable_references_match_deployed_runtime(self):
        artifact = {
            "deployedBytecode": self.expected,
            "immutableReferences": self.references,
        }
        normalize = lk._artifact_runtime_normalizer(artifact)
        self.assertIsNotNone(normalize)
        self.assertTrue(normalize(self.live))

    def test_non_immutable_bytecode_mismatch_is_not_masked(self):
        artifact = {
            "deployedBytecode": {
                "object": self.expected,
                "immutableReferences": self.references,
            }
        }
        normalize = lk._artifact_runtime_normalizer(artifact)
        tampered = "0x6100" + "22" * 20 + "6000"
        self.assertFalse(normalize(tampered))

    def test_missing_immutable_metadata_does_not_become_wildcard_match(self):
        artifact = {"deployedBytecode": self.expected}
        normalize = lk._artifact_runtime_normalizer(artifact)
        self.assertIsNotNone(normalize)
        self.assertFalse(normalize(self.live))


if __name__ == "__main__":
    unittest.main()
