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
            self.assertEqual(code, 0)
            rendered = output.getvalue()
            self.assertIn("Coverage", rendered)
            self.assertIn("partial", rendered.lower())
            self.assertIn("REVIEW NEEDED", rendered)


if __name__ == "__main__":
    unittest.main()
