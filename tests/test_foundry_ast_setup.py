import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

import foundry_ast_setup as ast_setup


class FoundryAstSetupTests(unittest.TestCase):
    def test_enables_missing_flags_in_active_profile_and_preserves_comments(self):
        original = (
            '[profile.default]\n'
            'src = "src"\n'
            'ast = false # keep the user's note\n'
            '\n'
            '[profile.default.fuzz]\n'
            'runs = 128\n'
        )

        updated, changed = ast_setup._patch_profile_settings(original, "default")

        self.assertTrue(changed)
        self.assertIn("ast = true # keep the user's note", updated)
        self.assertIn("build_info = true", updated)
        self.assertIn("runs = 128", updated)
        parsed = ast_setup._parse_toml(updated)
        self.assertIs(parsed["profile"]["default"]["ast"], True)
        self.assertIs(parsed["profile"]["default"]["build_info"], True)
        self.assertEqual(parsed["profile"]["default"]["fuzz"]["runs"], 128)

    def test_adds_active_parent_profile_before_existing_nested_table(self):
        original = '[profile.ci.fuzz]\nruns = 64\n'
        updated, changed = ast_setup._patch_profile_settings(original, "ci")

        self.assertTrue(changed)
        self.assertLess(updated.index("[profile.ci]"), updated.index("[profile.ci.fuzz]"))
        parsed = ast_setup._parse_toml(updated)
        self.assertIs(parsed["profile"]["ci"]["ast"], True)
        self.assertIs(parsed["profile"]["ci"]["build_info"], True)

    def test_custom_profile_change_does_not_modify_default_profile(self):
        original = (
            "[profile.default]\n"
            "ast = false\n"
            "build_info = false\n"
            "\n"
            "[profile.ci]\n"
            "optimizer = true\n"
        )
        updated, changed = ast_setup._patch_profile_settings(original, "ci")
        self.assertTrue(changed)
        parsed = ast_setup._parse_toml(updated)
        self.assertIs(parsed["profile"]["default"]["ast"], False)
        self.assertIs(parsed["profile"]["default"]["build_info"], False)
        self.assertIs(parsed["profile"]["ci"]["ast"], True)
        self.assertIs(parsed["profile"]["ci"]["build_info"], True)

    def test_is_idempotent_when_flags_are_already_enabled(self):
        original = "[profile.default]\nast = true\nbuild_info = true\n"
        updated, changed = ast_setup._patch_profile_settings(original, "default")
        self.assertFalse(changed)
        self.assertEqual(updated, original)

    def test_refuses_duplicate_settings(self):
        original = (
            "[profile.default]\n"
            "ast = false\n"
            "ast = true\n"
            "build_info = false\n"
        )
        with self.assertRaisesRegex(ast_setup.AstSetupError, "duplicate ast"):
            ast_setup._patch_profile_settings(original, "default")

    def test_refuses_non_boolean_setting_instead_of_overwriting_unknown_toml(self):
        original = '[profile.default]\nast = "false"\nbuild_info = false\n'
        with self.assertRaisesRegex(ast_setup.AstSetupError, "must be a TOML boolean"):
            ast_setup._patch_profile_settings(original, "default")

    def test_refuses_unsafe_profile_names(self):
        with self.assertRaisesRegex(ast_setup.AstSetupError, "Unsafe Foundry profile"):
            ast_setup._patch_profile_settings("[profile.default]\n", 'ci."unexpected"')

    def test_detects_false_environment_overrides(self):
        self.assertEqual(
            ast_setup._false_environment_overrides({
                "FOUNDRY_AST": "false",
                "DAPP_BUILD_INFO": "0",
                "FOUNDRY_OPTIMIZER": "false",
            }),
            ["FOUNDRY_AST", "DAPP_BUILD_INFO"],
        )

    def test_inspects_real_ast_nodes_and_ignores_metadata_only_build_info(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            (directory / "metadata.json").write_text(
                json.dumps({"id": "old", "language": "Solidity"}),
                encoding="utf-8",
            )
            (directory / "compiled.json").write_text(
                json.dumps({
                    "output": {
                        "sources": {
                            "src/A.sol": {"id": 0, "ast": {"nodeType": "SourceUnit"}},
                            "src/B.sol": {"id": 1},
                        }
                    }
                }),
                encoding="utf-8",
            )

            result = ast_setup._inspect_build_info(directory)

        self.assertEqual(result["files"], 2)
        self.assertEqual(result["source_units"], 2)
        self.assertEqual(result["with_ast"], 1)
        self.assertEqual(result["skipped"], 0)

    def test_readiness_rejects_configured_build_without_ast_nodes(self):
        ready, issues = ast_setup._readiness(
            {"ast": True, "build_info": True},
            {"files": 1, "source_units": 3, "with_ast": 0, "skipped": 0},
        )
        self.assertFalse(ready)
        self.assertTrue(any("none of its source units contains an AST" in item for item in issues))

    def test_backup_is_created_without_overwriting_previous_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = pathlib.Path(temporary) / "foundry.toml"
            config.write_text("[profile.default]\nast = false\n", encoding="utf-8")

            backup = ast_setup._write_config_with_backup(
                config, "[profile.default]\nast = true\n"
            )
            self.assertEqual(backup.read_text(encoding="utf-8"), "[profile.default]\nast = false\n")
            self.assertEqual(config.read_text(encoding="utf-8"), "[profile.default]\nast = true\n")

            second_backup = ast_setup._write_config_with_backup(
                config, "[profile.default]\nast = true\nbuild_info = true\n"
            )
            self.assertNotEqual(second_backup, backup)
            self.assertTrue(backup.exists())
            self.assertTrue(second_backup.exists())


if __name__ == "__main__":
    unittest.main()
