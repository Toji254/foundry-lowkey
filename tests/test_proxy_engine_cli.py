import contextlib
import importlib.util
import json
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
        self.assertIn("proxy campaign", output.getvalue())

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
        self.assertTrue(lk._machine_readable_stdout("proxy", ["inspect", "--json"]))
        self.assertTrue(lk._machine_readable_stdout("deps", ["src", "--json"]))
        self.assertFalse(lk._machine_readable_stdout("deps", ["src"]))
        self.assertFalse(lk._machine_readable_stdout("proxy", ["inspect"]))



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


    def test_proxy_campaign_uses_existing_control_runner_and_requires_frozen_spec(self):
        import json
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "family": "proxy",
                "proxy_family": "beacon",
                "target_address": "0x" + "11" * 20,
                "same_calls_id": "beacon-pair-v1",
                "control": {"harness": "test/Pair.t.sol", "argv": ["forge", "test"]},
                "attack": {"harness": "test/Pair.t.sol", "argv": ["forge", "test"]},
            }
            (root / "beacon-control.json").write_text(json.dumps(manifest), encoding="utf-8")
            captured = {}

            def control(args):
                captured["args"] = list(args)
                output_index = args.index("--output") + 1
                report_path = (root / args[output_index]).resolve()
                self.assertFalse(report_path.exists(), "campaign output must be unique for this execution")
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(json.dumps({
                    "status": "SIMULATED_BREAK",
                    "proof_axes": {"fidelity": "simulated_caller"},
                    "target_authenticity": "fixture",
                    "runs": {"control": {"metric": 0}, "attack": {"metric": 1}},
                }), encoding="utf-8")
                return 0

            with patch.dict(sys.modules, {"godmode": SimpleNamespace(control=control)}):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = lk.proxy_engine.run_cli(
                        {}, ["campaign", "--manifest", "beacon-control.json"],
                        rpc_resolver=lambda config, **kwargs: "http://127.0.0.1:8545",
                        root_resolver=lambda: root,
                    )

            self.assertEqual(code, 0)
            self.assertIn("--require-frozen", captured["args"])
            self.assertIn("--rpc-url", captured["args"])
            self.assertIn("SIMULATED_BREAK", output.getvalue())
            self.assertIn("DECLARED FAM", output.getvalue())
            reports = list((root / ".audit" / "proxy" / ("0x" + "11" * 20)).glob("campaign-control-*.json"))
            self.assertEqual(len(reports), 1)
            saved = json.loads(reports[0].read_text(encoding="utf-8"))
            self.assertEqual(saved["declared_proxy_family"], "beacon")
            self.assertEqual(saved["runs"]["attack"]["metric"], 1)

    def test_proxy_campaign_freeze_is_a_nonexecuting_operation(self):
        import json
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "family": "proxy",
                "target_address": "0x" + "22" * 20,
                "same_calls_id": "diamond-pair-v1",
                "control": {"harness": "test/Pair.t.sol", "argv": ["forge", "test"]},
                "attack": {"harness": "test/Pair.t.sol", "argv": ["forge", "test"]},
            }
            (root / "diamond-control.json").write_text(json.dumps(manifest), encoding="utf-8")
            captured = {}
            def control(args):
                captured["args"] = list(args)
                return 0
            with patch.dict(sys.modules, {"godmode": SimpleNamespace(control=control)}):
                code = lk.proxy_engine.run_cli(
                    {}, ["campaign", "diamond-control.json", "--freeze"],
                    root_resolver=lambda: root,
                )
            self.assertEqual(code, 0)
            self.assertIn("--freeze", captured["args"])
            self.assertNotIn("--require-frozen", captured["args"])

    def test_proxy_campaign_rejects_a_manifest_outside_the_project_root(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            external = Path(outside) / "campaign.json"
            external.write_text(json.dumps({
                "family": "proxy", "target_address": "0x" + "11" * 20,
                "same_calls_id": "outside", "control": {}, "attack": {},
            }), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = lk.proxy_engine.run_cli(
                    {}, ["campaign", "--manifest", str(external)],
                    root_resolver=lambda: root,
                )
            self.assertEqual(code, 2)
            self.assertIn("inside the active project", output.getvalue())


    def test_proxy_campaign_rejects_unsupported_render_flags(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "m.json").write_text(json.dumps({
                "family": "proxy", "target_address": "0x" + "11" * 20,
                "same_calls_id": "x", "control": {}, "attack": {},
            }), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = lk.proxy_engine.run_cli(
                    {}, ["campaign", "--manifest", "m.json", "--json"],
                    root_resolver=lambda: root,
                )
            self.assertEqual(code, 2)
            self.assertIn("Unsupported campaign flag", output.getvalue())

    def test_proxy_campaign_uses_cwd_when_root_resolver_returns_none(self):
        import json
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "family": "proxy", "target_address": "0x" + "11" * 20,
                "same_calls_id": "cwd-root", "control": {"argv": ["forge", "test"]},
                "attack": {"argv": ["forge", "test"]},
            }
            (root / "m.json").write_text(json.dumps(manifest), encoding="utf-8")
            captured = {}
            def fake_control(args):
                captured["args"] = list(args)
                report = root / args[args.index("--output") + 1]
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps({"status": "OBSERVED", "proof_axes": {}, "runs": {}}), encoding="utf-8")
                return 0
            old_cwd = Path.cwd()
            try:
                import os
                os.chdir(root)
                with patch.dict(sys.modules, {"godmode": SimpleNamespace(control=fake_control)}):
                    code = lk.proxy_engine.run_cli(
                        {}, ["campaign", "--manifest", "m.json"],
                        root_resolver=lambda: None,
                    )
            finally:
                os.chdir(old_cwd)
            self.assertEqual(code, 0)
            self.assertTrue(Path(captured["args"][captured["args"].index("--root") + 1]).samefile(root))


    def test_proxy_inspect_rejects_remembered_target_after_foreign_rpc_detaches_context(self):
        address = "0x" + "11" * 20
        endpoint = "http://127.0.0.1:9545"
        config = {
            "target": address,
            "_active_network_session": {
                "id": "managed-session-a",
                "rpc": "http://127.0.0.1:8545",
                "actors": {"lab-deployer": "0x" + "22" * 20},
            },
        }
        output = io.StringIO()
        with patch.object(lk, "project_fixture_rpc_info", return_value=None), patch.object(
            lk.proxy_engine, "inspect_proxy"
        ) as inspect, contextlib.redirect_stdout(output):
            code = lk.proxy_engine.run_cli(
                config,
                ["inspect", "--rpc-url", endpoint],
                rpc_resolver=lk.effective_rpc,
                root_resolver=lambda: None,
            )
        self.assertEqual(code, 2)
        self.assertIn("pass the target address explicitly", output.getvalue().lower())
        inspect.assert_not_called()
        self.assertTrue(config.get("_explicit_rpc_unscoped"))
        self.assertNotIn("_active_network_session", config)

    def test_proxy_inspect_allows_explicit_target_with_foreign_rpc(self):
        remembered = "0x" + "11" * 20
        explicit_target = "0x" + "33" * 20
        endpoint = "http://127.0.0.1:9545"
        config = {
            "target": remembered,
            "_active_network_session": {
                "id": "managed-session-a",
                "rpc": "http://127.0.0.1:8545",
                "actors": {"lab-deployer": "0x" + "22" * 20},
            },
        }
        report = {"status": "OBSERVED", "target": explicit_target}
        output = io.StringIO()
        with patch.object(lk, "project_fixture_rpc_info", return_value=None), patch.object(
            lk.proxy_engine, "inspect_proxy", return_value=report
        ) as inspect, patch.object(lk.proxy_engine, "_save_report", return_value=None), contextlib.redirect_stdout(output):
            code = lk.proxy_engine.run_cli(
                config,
                ["inspect", explicit_target, "--rpc-url", endpoint, "--json"],
                rpc_resolver=lk.effective_rpc,
                abi_resolver=lambda address, _config: [],
                root_resolver=lambda: None,
            )
        self.assertEqual(code, 0)
        inspect.assert_called_once_with(endpoint, explicit_target, requested_block=None, abi=[])
        self.assertTrue(config.get("_explicit_rpc_unscoped"))
        self.assertEqual(json.loads(output.getvalue())["target"], explicit_target)

    def test_proxy_history_resolves_explicit_rpc_and_rejects_implicit_foreign_target(self):
        import json
        address = "0x" + "11" * 20
        endpoint = "http://127.0.0.1:9545"
        config = {
            "target": address,
            "_active_network_session": {
                "id": "managed-session-a",
                "rpc": "http://127.0.0.1:8545",
                "actors": {"lab-deployer": "0x" + "22" * 20},
            },
        }
        output = io.StringIO()
        with patch.object(lk, "project_fixture_rpc_info", return_value=None), patch.object(
            lk.proxy_engine, "proxy_upgrade_history"
        ) as history, contextlib.redirect_stdout(output):
            code = lk.proxy_engine.run_cli(
                config,
                ["history", "--from-block", "10", "--rpc-url", endpoint],
                rpc_resolver=lk.effective_rpc,
                root_resolver=lambda: None,
            )
        self.assertEqual(code, 2)
        self.assertIn("pass the target address explicitly", output.getvalue().lower())
        history.assert_not_called()
        self.assertTrue(config.get("_explicit_rpc_unscoped"))

    def test_proxy_campaign_validates_explicit_rpc_with_central_resolver(self):
        import json
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace

        endpoint = "http://127.0.0.1:9545"
        target = "0x" + "44" * 20
        captured = {}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "campaign.json").write_text(json.dumps({
                "family": "proxy",
                "target_address": target,
                "same_calls_id": "foreign-rpc-pair",
                "control": {"argv": ["forge", "test"]},
                "attack": {"argv": ["forge", "test"]},
            }), encoding="utf-8")

            def control(args):
                captured["args"] = list(args)
                return 0

            config = {
                "_active_network_session": {
                    "id": "managed-session-a",
                    "rpc": "http://127.0.0.1:8545",
                    "actors": {},
                },
            }
            with patch.object(lk, "project_fixture_rpc_info", return_value=None), patch.dict(
                sys.modules, {"godmode": SimpleNamespace(control=control)}
            ):
                code = lk.proxy_engine.run_cli(
                    config,
                    ["campaign", "--manifest", "campaign.json", "--freeze", "--rpc-url", endpoint],
                    rpc_resolver=lk.effective_rpc,
                    root_resolver=lambda: root,
                )
        self.assertEqual(code, 0)
        self.assertTrue(config.get("_explicit_rpc_unscoped"))
        self.assertIn("--rpc-url", captured["args"])
        self.assertEqual(captured["args"][captured["args"].index("--rpc-url") + 1], endpoint)

if __name__ == "__main__":
    unittest.main()
