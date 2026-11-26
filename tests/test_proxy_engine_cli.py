import contextlib
import importlib.util
import io
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
sys.path.insert(0, str(LOWKEY))
spec = importlib.util.spec_from_file_location("proxy_engine_cli_lk", LOWKEY / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class ProxyEngineCliTests(unittest.TestCase):
    def test_proxy_command_routes_to_proxy_engine_and_preserves_legacy_field_commands(self):
        with patch.object(lk, "activate_project_context"), patch.object(
            lk.proxy_engine, "run_cli", return_value=7
        ) as engine:
            result = lk._dispatch_command_impl("proxy", ["audit", "0x" + "1" * 40], {})
        self.assertEqual(result, 7)
        args, kwargs = engine.call_args
        self.assertEqual(args[1], ["audit", "0x" + "1" * 40])
        self.assertIs(kwargs["rpc_resolver"], lk.effective_rpc)
        self.assertIs(kwargs["abi_resolver"], lk.load_abi)

    def test_proxy_help_exposes_auditor_workflow(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = lk._render_command_help(["proxy"])
        self.assertEqual(result, 0)
        self.assertIn("proxy audit", output.getvalue())
        self.assertIn("proxy history", output.getvalue())

    def test_proxy_validate_help_exposes_build_info_and_namespace_inputs(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = lk._render_command_help(["proxy", "validate"])
        self.assertEqual(result, 0)
        rendered = output.getvalue()
        for option in (
            "--reference-contract", "--candidate-contract",
            "--reference-source", "--candidate-source",
        ):
            self.assertIn(option, rendered)

    def test_nested_proxy_audit_help_is_registered(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = lk._render_command_help(["proxy", "audit"])
        self.assertEqual(result, 0)
        self.assertIn("hypotheses", output.getvalue().lower())


    def test_validate_accepts_explicit_contract_selectors_for_build_info(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            layout = {
                "storage": [{"label": "owner", "slot": "0", "offset": 0, "type": "t_address"}],
                "types": {"t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"}},
            }
            build_info = {
                "output": {"contracts": {
                    "src/Vault.sol": {"Vault": {"storageLayout": layout}},
                    "src/Token.sol": {"Token": {"storageLayout": {
                        "storage": [{"label": "supply", "slot": "0", "offset": 0, "type": "t_uint256"}],
                        "types": {"t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"}},
                    }}},
                }}
            }
            reference = base / "V1-build-info.json"
            candidate = base / "V2-build-info.json"
            reference.write_text(json.dumps(build_info), encoding="utf-8")
            candidate.write_text(json.dumps(build_info), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = lk.proxy_engine.run_cli(
                    {},
                    [
                        "validate",
                        "--reference", str(reference),
                        "--candidate", str(candidate),
                        "--reference-contract", "Vault",
                        "--candidate-contract", "Vault",
                        "--json",
                    ],
                )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "COMPATIBLE_CANDIDATE")

    def test_validate_includes_erc7201_source_comparison_in_json(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            reference_artifact = base / "V1.json"
            candidate_artifact = base / "V2.json"
            layout = {
                "storageLayout": {
                    "storage": [{"label": "owner", "slot": "0", "offset": 0, "type": "t_address"}],
                    "types": {"t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"}},
                }
            }
            reference_artifact.write_text(json.dumps(layout), encoding="utf-8")
            candidate_artifact.write_text(json.dumps(layout), encoding="utf-8")
            reference_source = base / "reference"
            candidate_source = base / "candidate"
            for root in (reference_source, candidate_source):
                source = root / "src" / "Vault.sol"
                source.parent.mkdir(parents=True)
                source.write_text(
                    "/// @custom:storage-location erc7201:example.storage.Vault\n"
                    "struct VaultStorage { address owner; uint256 totalAssets; }\n",
                    encoding="utf-8",
                )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = lk.proxy_engine.run_cli(
                    {},
                    [
                        "validate",
                        "--reference", str(reference_artifact),
                        "--candidate", str(candidate_artifact),
                        "--reference-source", str(reference_source),
                        "--candidate-source", str(candidate_source),
                        "--json",
                    ],
                )
        self.assertEqual(code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "COMPATIBLE_CANDIDATE")
        self.assertEqual(payload["erc7201"]["status"], "IDS_AND_DECLARATIONS_MATCH")

    def test_validate_downgrades_storage_green_when_namespace_scan_is_not_clean(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            artifact = base / "V1.json"
            layout = {
                "storageLayout": {
                    "storage": [{"label": "owner", "slot": "0", "offset": 0, "type": "t_address"}],
                    "types": {"t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"}},
                }
            }
            artifact.write_text(json.dumps(layout), encoding="utf-8")
            reference_source = base / "reference"
            candidate_source = base / "candidate"
            for root in (reference_source, candidate_source):
                source = root / "src" / "Vault.sol"
                source.parent.mkdir(parents=True)
                source.write_text("contract Vault {}\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = lk.proxy_engine.run_cli(
                    {},
                    [
                        "validate",
                        "--reference", str(artifact),
                        "--candidate", str(artifact),
                        "--reference-source", str(reference_source),
                        "--candidate-source", str(candidate_source),
                        "--json",
                    ],
                )
        self.assertEqual(code, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "INCONCLUSIVE")
        self.assertEqual(payload["erc7201"]["status"], "NO_ERC7201_ANNOTATIONS")

    def test_json_proxy_commands_suppress_recommendation_footer(self):
        source = pathlib.Path(lk.__file__).read_text(encoding="utf-8")
        self.assertIn('_canonical_help_command(command) == "proxy"', source)
        self.assertIn('and "--json" in sys.argv[2:]', source)



    def test_proxy_history_cli_uses_explicit_block_range(self):
        import json
        address = "0x" + "11" * 20
        history = {
            "range": {"from_block": 10, "to_block": 20},
            "events": [],
            "event_count": 0,
            "reconciliation": {},
            "status": "OBSERVED",
        }
        output = io.StringIO()
        with patch.object(lk.proxy_engine, "proxy_upgrade_history", return_value=history) as run_history:
            with contextlib.redirect_stdout(output):
                code = lk.proxy_engine.run_cli(
                    {},
                    ["history", address, "--from-block", "10", "--to-block", "20", "--json"],
                    rpc_resolver=lambda config, **kwargs: "http://localhost:8545",
                    root_resolver=lambda: None,
                )
        self.assertEqual(code, 0)
        run_history.assert_called_once_with("http://localhost:8545", address, 10, 20)
        self.assertEqual(json.loads(output.getvalue())["event_count"], 0)

if __name__ == "__main__":
    unittest.main()
