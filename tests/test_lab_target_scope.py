import importlib.util
import json
import pathlib
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
sys.path.insert(0, str(LOWKEY))

scope_spec = importlib.util.spec_from_file_location("lab_target_scope", LOWKEY / "lab_target_scope.py")
scope_module = importlib.util.module_from_spec(scope_spec)
scope_spec.loader.exec_module(scope_module)

lk_spec = importlib.util.spec_from_file_location("lab_scope_lk", LOWKEY / "lk.py")
lk = importlib.util.module_from_spec(lk_spec)
lk_spec.loader.exec_module(lk)


class LabTargetScopeTests(unittest.TestCase):
    def _project(self, tmp):
        root = Path(tmp) / "project"
        root.mkdir()
        (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
        return root

    def _artifact(self, root, source, name, source_text=None):
        source_path = root / source
        source_path.parent.mkdir(parents=True, exist_ok=True)
        if source_text is None:
            source_text = f"pragma solidity ^0.8.20; contract {name} {{}}"
        source_path.write_text(source_text, encoding="utf-8")
        artifact_path = root / "out" / Path(source).name / f"{name}.json"
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps({
            "contractName": name,
            "sourceName": source,
            "abi": [],
            "bytecode": {"object": "0x6000"},
        }), encoding="utf-8")
        return artifact_path

    def test_root_invocation_keeps_project_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            result = scope_module.resolve_target_scope(root, invocation_dir=root)
            self.assertEqual(result.target_scope, root)
            self.assertEqual(result.dependency_scope, root)
            self.assertEqual(result.mode, "project")

    def test_nested_application_invocation_scopes_target_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            nested = root / "contracts" / "core"
            nested.mkdir(parents=True)
            result = scope_module.resolve_target_scope(root, invocation_dir=nested)
            self.assertEqual(result.target_scope, nested)
            self.assertEqual(result.dependency_scope, root)
            self.assertEqual(result.mode, "invocation")

    def test_support_directory_requires_explicit_scope_or_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            tests = root / "test"
            tests.mkdir()
            with self.assertRaisesRegex(ValueError, "support area"):
                scope_module.resolve_target_scope(root, invocation_dir=tests)
            result = scope_module.resolve_target_scope(root, invocation_dir=tests, scope="project")
            self.assertEqual(result.target_scope, root)

    def test_explicit_scope_is_resolved_from_invocation_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            (root / "contracts" / "core").mkdir(parents=True)
            result = scope_module.resolve_target_scope(
                root, invocation_dir=root, scope="contracts/core"
            )
            self.assertEqual(result.target_scope, root / "contracts" / "core")
            self.assertEqual(result.mode, "explicit")

    def test_source_selection_resolves_file_and_scopes_to_its_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            nested = root / "contracts" / "core"
            nested.mkdir(parents=True)
            source = nested / "OrderBook.sol"
            source.write_text("contract OrderBook {}", encoding="utf-8")
            result = scope_module.resolve_target_scope(
                root, invocation_dir=nested, source="OrderBook.sol"
            )
            self.assertEqual(result.source_file, source)
            self.assertEqual(result.target_scope, nested)

    def test_scope_rejects_parent_traversal_and_symlinks_outside_project(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = self._project(tmp)
            with self.assertRaisesRegex(ValueError, "outside the selected project"):
                scope_module.resolve_target_scope(root, invocation_dir=root, scope=outside)
            outside_dir = Path(outside) / "external"
            outside_dir.mkdir()
            link = root / "external-link"
            try:
                link.symlink_to(outside_dir, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable")
            with self.assertRaisesRegex(ValueError, "outside the selected project"):
                scope_module.resolve_target_scope(root, invocation_dir=root, scope="external-link")

    def test_scope_parser_preserves_contract_selector_and_other_flags(self):
        args, scope, source = scope_module.parse_scope_options([
            "--generic", "OrderBook", "--scope", "contracts/core", "--ai-review",
            "--source=contracts/core/OrderBook.sol",
        ])
        self.assertEqual(args, ["--generic", "OrderBook", "--ai-review"])
        self.assertEqual(scope, "contracts/core")
        self.assertEqual(source, "contracts/core/OrderBook.sol")

    def test_scope_parser_rejects_missing_and_duplicate_options(self):
        for args in (["--scope"], ["--source"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                scope_module.parse_scope_options(args)
        with self.assertRaisesRegex(ValueError, "only once"):
            scope_module.parse_scope_options(["--scope", "project", "--scope=src"])

    def test_artifact_discovery_respects_nested_scope_but_dependencies_remain_project_wide(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            core = root / "contracts" / "core"
            core.mkdir(parents=True)
            self._artifact(root, "contracts/core/OrderBook.sol", "OrderBook")
            self._artifact(root, "contracts/shared/Token.sol", "Token")
            selected = lk.discover_artifact_lab_contract(root, "OrderBook", target_scope=core)
            self.assertIsNotNone(selected)
            self.assertIsNone(lk.discover_artifact_lab_contract(root, "Token", target_scope=core))
            self.assertIsNotNone(lk.discover_artifact_lab_contract(root, "Token"))

    def test_generic_auto_discovery_uses_nested_scope_not_project_heuristic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            core = root / "contracts" / "core"
            core.mkdir(parents=True)
            self._artifact(root, "contracts/core/OrderBook.sol", "OrderBook")
            self._artifact(root, "contracts/peripherals/GlpManager.sol", "GlpManager")
            with patch.object(lk, "discover_audit_target_contract", return_value="GlpManager"):
                selected = lk.discover_generic_lab_contract(root, target_scope=core)
            self.assertIsNotNone(selected)
            self.assertEqual(selected[1], "OrderBook")

    def test_source_file_filter_requires_explicit_contract_when_multiple_are_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            source = "contracts/core/OrderBook.sol"
            core = root / "contracts" / "core"
            core.mkdir(parents=True)
            source_text = "contract OrderBook {} contract OrderBookReader {}"
            self._artifact(root, source, "OrderBook", source_text)
            self._artifact(root, source, "OrderBookReader", source_text)
            self.assertIsNone(lk.discover_generic_lab_contract(
                root, target_scope=core, source_file=root / source
            ))
            self.assertIsNotNone(lk.discover_artifact_lab_contract(
                root, "OrderBookReader", target_scope=core, source_file=root / source
            ))

    def test_vyper_artifact_without_source_name_resolves_from_vyper_source_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            source = root / "src" / "Counter.vy"
            source.parent.mkdir(parents=True)
            source.write_text(
                "@external\ndef increment():\n    pass\n",
                encoding="utf-8",
            )
            artifact_path = root / ".audit" / "build" / "vyper" / "Counter.json"
            artifact_path.parent.mkdir(parents=True)
            artifact_path.write_text(json.dumps({
                "contractName": "Counter",
                "abi": [{"type": "function", "name": "increment", "inputs": [], "outputs": []}],
                "bytecode": {"object": "0x6000"},
            }), encoding="utf-8")
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            self.assertTrue(lk.artifact_is_project_application(root, artifact_path, artifact))
            selected = lk.discover_generic_lab_contract(root, target_scope=root)
            self.assertIsNotNone(selected)
            self.assertEqual(selected[1], "Counter")

    def _write_vyper_artifact(self, root, relative_output, bytecode="0x6000"):
        source = root / "contracts" / "Counter.vy"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "@external\ndef increment():\n    pass\n",
            encoding="utf-8",
        )
        artifact_path = root / relative_output
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps({
            "contractName": "Counter",
            "sourceName": "contracts/Counter.vy",
            "abi": [{
                "type": "function", "name": "increment",
                "inputs": [], "outputs": [],
            }],
            "bytecode": {"object": bytecode},
            "deployedBytecode": {"object": "0x6001"},
            "language": "Vyper",
        }), encoding="utf-8")
        return artifact_path

    def test_identical_vyper_artifacts_for_same_source_are_collapsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            build_artifact = self._write_vyper_artifact(
                root, ".audit/build/vyper/Counter.json"
            )
            self._write_vyper_artifact(
                root, ".audit/walkthrough/vyper/Counter.json"
            )
            selected = lk.discover_generic_lab_contract(root, "Counter")
            self.assertIsNotNone(selected)
            self.assertEqual(selected[1], "Counter")
            self.assertEqual(Path(selected[2]).resolve(), build_artifact.resolve())

    def test_conflicting_vyper_artifacts_for_same_source_remain_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._write_vyper_artifact(
                root, ".audit/build/vyper/Counter.json", bytecode="0x6000"
            )
            self._write_vyper_artifact(
                root, ".audit/walkthrough/vyper/Counter.json", bytecode="0x6002"
            )
            self.assertIsNone(lk.discover_generic_lab_contract(root, "Counter"))

    def test_same_named_contracts_from_different_sources_remain_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            first = self._write_vyper_artifact(
                root, ".audit/build/vyper/Counter.json"
            )
            second_source = root / "other" / "Counter.vy"
            second_source.parent.mkdir(parents=True)
            second_source.write_text(
                "@external\ndef increment():\n    pass\n",
                encoding="utf-8",
            )
            second_artifact = root / ".audit/walkthrough/vyper/OtherCounter.json"
            second_artifact.parent.mkdir(parents=True)
            second_artifact.write_text(json.dumps({
                "contractName": "Counter",
                "sourceName": "other/Counter.vy",
                "abi": [{
                    "type": "function", "name": "increment",
                    "inputs": [], "outputs": [],
                }],
                "bytecode": {"object": "0x6000"},
                "deployedBytecode": {"object": "0x6001"},
                "language": "Vyper",
            }), encoding="utf-8")
            self.assertNotEqual(first.resolve(), second_artifact.resolve())
            self.assertIsNone(lk.discover_generic_lab_contract(root, "Counter"))

    def test_explicit_missing_target_fails_closed_without_alternate_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            core = root / "contracts" / "core"
            core.mkdir(parents=True)
            output = []
            with patch.object(lk, "discover_audit_target_contract", return_value="GlpManager"), \
                 patch.object(lk, "discover_artifact_lab_contract", return_value=None), \
                 patch.object(lk, "discover_generic_lab_contract", return_value=None), \
                 patch.object(lk, "fail", side_effect=lambda message, code=2: output.append((message, code)) or code):
                code = lk.run_generic_lab(
                    {}, root, None, [], None, "OrderBook", mode="generic",
                    target_scope=core,
                )
            self.assertEqual(code, 2)
            self.assertIn("Requested contract 'OrderBook'", output[0][0])
            self.assertIn("No alternate target will be selected", output[0][0])

    def test_lab_help_documents_scope_and_source_options(self):
        output = []
        with patch.object(lk, "print", side_effect=lambda *args: output.append(" ".join(map(str, args))), create=True):
            lk.run_lab({}, ["--help"])
        rendered = "\n".join(output)
        self.assertIn("--scope project", rendered)
        self.assertIn("--source <file>", rendered)


    def test_cli_help_registry_exposes_lab_target_scope_controls(self):
        output = []
        with patch.object(
            lk, "print",
            side_effect=lambda *args: output.append(" ".join(map(str, args))),
            create=True,
        ):
            code = lk._render_command_help(["lab"])
        self.assertEqual(code, 0)
        rendered = "\\n".join(output)
        self.assertIn("--scope project --generic OrderBook", rendered)
        self.assertIn("--source contracts/core/OrderBook.sol --generic OrderBook", rendered)
        self.assertIn("project root", rendered.lower())
        self.assertIn("fails closed", rendered.lower())



    def test_missing_artifact_source_name_resolves_only_inside_invocation_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            core = root / "contracts" / "core"
            peripherals = root / "contracts" / "peripherals"
            core.mkdir(parents=True)
            peripherals.mkdir(parents=True)
            core_source = core / "OrderBook.sol"
            peripheral_source = peripherals / "OrderBook.sol"
            core_source.write_text("contract OrderBook {}", encoding="utf-8")
            peripheral_source.write_text("contract OrderBook {}", encoding="utf-8")

            self.assertIsNone(lk.source_contract_fallback(root, "OrderBook"))
            self.assertEqual(
                lk.source_contract_fallback(root, "OrderBook", target_scope=core),
                "contracts/core/OrderBook.sol",
            )
            self.assertEqual(
                lk.source_contract_fallback(root, "OrderBook", source_file=peripheral_source),
                "contracts/peripherals/OrderBook.sol",
            )


    def test_scoped_source_resolution_is_reused_by_application_provenance_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            core = root / "contracts" / "core"
            peripherals = root / "contracts" / "peripherals"
            core.mkdir(parents=True)
            peripherals.mkdir(parents=True)
            (core / "OrderBook.sol").write_text("contract OrderBook {}", encoding="utf-8")
            (peripherals / "OrderBook.sol").write_text("contract OrderBook {}", encoding="utf-8")
            artifact_path = root / "out" / "OrderBook.sol" / "OrderBook.json"
            artifact_path.parent.mkdir(parents=True)
            artifact = {
                "contractName": "OrderBook",
                "abi": [],
                "bytecode": {"object": "0x6000"},
            }
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")

            scoped_source = lk.source_contract_fallback(
                root, "OrderBook", target_scope=core
            )
            self.assertEqual(scoped_source, "contracts/core/OrderBook.sol")
            self.assertTrue(lk.artifact_is_project_application(
                root, artifact_path, artifact, resolved_source=scoped_source
            ))
            self.assertFalse(lk.artifact_is_project_application(
                root, artifact_path, artifact
            ))


    def test_scoped_contract_list_collapses_identical_artifact_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._write_vyper_artifact(root, ".audit/build/vyper/Counter.json")
            self._write_vyper_artifact(root, ".audit/walkthrough/vyper/Counter.json")
            self.assertEqual(
                lk._lab_scoped_contract_names(root, target_scope=root),
                ["Counter"],
            )


    def test_scoped_contract_list_keeps_conflicting_same_source_artifacts_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._write_vyper_artifact(
                root, ".audit/build/vyper/Counter.json", bytecode="0x6000"
            )
            self._write_vyper_artifact(
                root, ".audit/walkthrough/vyper/Counter.json", bytecode="0x6002"
            )
            self.assertEqual(lk._lab_scoped_contract_names(root, target_scope=root), [])


    def test_source_artifact_symlink_outside_project_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = self._project(tmp)
            outside_source = Path(outside) / "OrderBook.sol"
            outside_source.write_text("contract OrderBook {}", encoding="utf-8")
            link = root / "contracts" / "OrderBook.sol"
            link.parent.mkdir(parents=True)
            try:
                link.symlink_to(outside_source)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable")
            self.assertFalse(lk.lab_target_scope.artifact_source_in_scope(
                root, "contracts/OrderBook.sol", target_scope=link.parent
            ))

if __name__ == "__main__":
    unittest.main()
