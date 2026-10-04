import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

ROOT = Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

import lk


class ReliabilityRoutingTests(unittest.TestCase):
    def test_generic_project_never_falls_back_to_foundry_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                '[package]\nname = "demo"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            config = lk.fresh_config()
            config["target"] = "0x1111111111111111111111111111111111111111"

            with patch.object(lk, "detected_project_root", return_value=root), \
                 patch.object(lk, "detect_project", return_value={
                     "root": str(root),
                     "kind": "rust",
                     "backend": "cargo",
                     "stacks": ["cargo"],
                     "languages": {"rust": 1},
                 }), \
                 patch.object(lk.audit_context, "update"), \
                 patch.object(lk, "_sync_security_patterns"), \
                 patch.object(lk, "format_detection", return_value="PROJECT"), \
                 patch.object(lk, "run_native_audit", return_value=0) as native, \
                 patch.object(lk, "save_config"), \
                 patch.dict(sys.modules, {}, clear=False):
                # run_audit imports forge_tools only inside the Foundry branch;
                # reaching native proves stale target state did not route to Forge.
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = lk.run_audit(config, ["--no-checks"])
                self.assertEqual(code, 0)
                native.assert_called_once()
                self.assertNotIn("connected Foundry audit pipeline", output.getvalue())

    def test_unfamiliar_repository_shapes_never_crash_the_scan_entrypoint(self):
        fixtures = (
            ("cargo", "Cargo.toml", '[package]\nname = "demo"\nversion = "0.1.0"\n', "src/lib.rs", "pub fn execute() {}\n"),
            ("anchor", "Anchor.toml", '[provider]\ncluster = "localnet"\n', "programs/demo/src/lib.rs", "pub fn execute() { unsafe { let _ = 1u8; } }\n"),
            ("cairo", "Scarb.toml", '[package]\nname = "demo"\nversion = "0.1.0"\n', "src/lib.cairo", "fn execute() {}\n"),
            ("move", "Move.toml", '[package]\nname = "demo"\nversion = "0.0.0"\n', "sources/demo.move", "module demo::demo {}\n"),
            ("cosmwasm", "Cargo.toml", '[package]\nname = "demo"\nversion = "0.1.0"\n[dependencies]\ncosmwasm-std = "2"\n', "src/contract.rs", "pub fn execute() {}\n"),
        )
        for _label, manifest, manifest_text, source, source_text in fixtures:
            with self.subTest(project=_label):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / manifest).parent.mkdir(parents=True, exist_ok=True)
                    (root / manifest).write_text(manifest_text, encoding="utf-8")
                    source_path = root / source
                    source_path.parent.mkdir(parents=True, exist_ok=True)
                    source_path.write_text(source_text, encoding="utf-8")

                    with patch.object(lk, "sys", sys):
                        output = io.StringIO()
                        with patch.object(
                            sys, "argv", [str(ROOT / "lowkey" / "lk.py"), "scan", str(root)]
                        ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                            code = lk._safe_main()

                    self.assertEqual(code, 2)
                    rendered = output.getvalue()
                    self.assertNotIn("Traceback", rendered)
                    self.assertRegex(rendered, r"(Coverage|unsupported|partial|REVIEW NEEDED)")
                    self.assertTrue((root / ".audit" / "evidence" / "universal_analysis.json").is_file())

    def test_cli_failure_boundary_returns_review_needed_instead_of_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / ".audit" / "evidence" / "lk-runtime-error.json"
            with patch.object(lk, "main", side_effect=RuntimeError("adapter exploded")), \
                 patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk.sys, "argv", ["lk", "scan"]):
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    code = lk._safe_main()
            self.assertEqual(code, 2)
            rendered = err.getvalue()
            self.assertIn("LOWKEY RUNTIME ERROR", rendered)
            self.assertIn("REVIEW NEEDED", rendered)
            self.assertNotIn("Traceback", rendered)
            self.assertTrue(evidence.is_file())

    def test_lk_scan_propagates_runtime_review_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch(
                "analysis_adapters.scan_repository",
                return_value=2,
            ):
                output = io.StringIO()
                with patch.object(lk.audit_context, "foundry_project_root", return_value=root),                      contextlib.redirect_stdout(output):
                    code = lk.run_scan([str(root)])
            self.assertEqual(code, 2)

    def test_generic_source_project_has_explicit_partial_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                "pub fn call() { unsafe { let _ = 1u8; } }\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = lk.run_scan([str(root)])
            self.assertEqual(code, 2)
            rendered = output.getvalue()
            self.assertIn("Coverage", rendered)
            self.assertIn("partial", rendered.lower())
            self.assertIn("REVIEW NEEDED", rendered)


if __name__ == "__main__":
    unittest.main()
