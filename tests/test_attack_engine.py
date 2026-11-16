"""Unit and contract tests for Lowkey's evidence-gated attack/chain engine."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lowkey import attack_engine as engine


ADDR = "0x" + "11" * 20
CODE_SHA = "0x" + "22" * 32
TX_HASH = "0x" + "33" * 32
WORD = "0x" + "44" * 32
HASH = "a" * 64


class AttackEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lowkey-attack-engine-")
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "test").mkdir()
        (self.root / ".audit" / "lowkey").mkdir(parents=True)
        (self.root / ".audit" / "godmode").mkdir(parents=True)
        self.source = self.root / "src" / "Vault.sol"
        self.source.write_text(
            "pragma solidity ^0.8.20;\n"
            "contract Vault {\n"
            "    uint256 public totalAssets;\n"
            "    function withdraw(uint256 amount) external {\n"
            "        amount;\n"
            "    }\n"
            "    function borrow(uint256 amount) external { amount + totalAssets; }\n"
            "}\n",
            encoding="utf-8",
        )
        self.test_file = self.root / "test" / "Attack.t.sol"
        self.test_file.write_text("// target-specific Foundry adapter test fixture\n", encoding="utf-8")
        self.test_hash = hashlib.sha256(self.test_file.read_bytes()).hexdigest()
        self.source_hash = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.target = {
            "address": ADDR,
            "code_sha256": CODE_SHA,
            "chain_id": 1,
            "block_number": 100,
        }
        self.discovery = {
            "source_file": "src/Vault.sol",
            "source_sha256": self.source_hash,
            "source_line": 4,
            "entrypoint": "withdraw(uint256)",
        }
        self.reproof = self._write_reproof(semantic=True)

    def tearDown(self):
        self.temp.cleanup()

    def _write_reproof(self, *, semantic: bool, profitable: bool = False):
        payload = {
            "status": "PROFITABLE" if profitable else "SIMULATED_BREAK",
            "legacy_status": "PROFITABLE" if profitable else "FORK_REPRODUCED",
            "command_run": True,
            "target_address": ADDR,
            "chain_id": "0x1",
            "fork_parent_block": 100,
            "transaction_block": 101,
            "receipt_status": "0x1",
            "tx_hash": TX_HASH,
            "call_trace": [{"type": "CALL", "to": ADDR}],
            "semantic_invariant_verified": semantic,
            "net_profit_wei": 25 if profitable else 0,
            "gas_cost_wei": 5 if profitable else 0,
            "prior_cost_wei": 5 if profitable else 0,
            "total_cost_wei": 10 if profitable else 0,
            "source_fork_verification": {
                "verified": True,
                "source_chain_id": "0x1",
                "target_code_sha256": CODE_SHA[2:],
            },
            "storage_trace": {"supported": True, "slots": [{"address": ADDR, "slot": WORD}]},
            "derived_storage_slots": [{"address": ADDR, "slot": WORD, "value": WORD}],
        }
        path = self.root / ".audit" / "godmode" / "reprove.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return {"reproof_file": ".audit/godmode/reprove.json"}

    def _manifest(self, family="reentrancy", impact_mode="semantic"):
        spec = engine.FAMILIES[family]
        (self.source).write_text(self.source.read_text(encoding="utf-8"), encoding="utf-8")
        return {
            "schema_version": 1,
            "id": "vault-withdraw-001",
            "family": family,
            "target": dict(self.target),
            "discovery": dict(self.discovery),
            "impact_mode": impact_mode,
            "property_id": spec["property"],
            "attack": {
                "test_file": "test/Attack.t.sol",
                "test_name": "testAttack",
                "test_sha256": self.test_hash,
                "evidence_file": ".audit/lowkey/attack.json",
            },
            "control": {
                "test_file": "test/Attack.t.sol",
                "test_name": "testControl",
                "test_sha256": self.test_hash,
                "evidence_file": ".audit/lowkey/control.json",
            },
            "reproof": dict(self.reproof),
            "mutation": {
                "mutants": [{
                    "id": "kill-vulnerable-withdraw",
                    "file": "src/Vault.sol",
                    "before": "amount;",
                    "after": "amount; // mutation",
                }]
            },
            "timeout_seconds": 30,
        }

    def _trace_event(self, *, seq=0, depth=2, storage_support="exact"):
        return engine.build_trace_event(
            seq=seq,
            backend="forge-state-diff",
            kind="Call",
            accessor=ADDR,
            account=ADDR,
            depth=depth,
            value=0,
            calldata="0x12345678",
            reverted=False,
            storage=[{
                "account": ADDR,
                "slot": WORD,
                "previous_value": "0x" + "00" * 32,
                "new_value": WORD,
                "is_write": True,
                "reverted": False,
            }] if storage_support == "exact" else None,
            storage_support=storage_support,
        )

    def _evidence(self, role, family="reentrancy", *, observed=None, anchor=None, depth=2):
        spec = engine.FAMILIES[family]
        return {
            "schema_version": 1,
            "experiment_id": "vault-withdraw-001",
            "family": family,
            "role": role,
            "target": dict(self.target),
            "discovery_sha256": self.source_hash,
            "adapter_sha256": self.test_hash,
            "preconditions": {item: True for item in spec["preconditions"]},
            "pair_anchor": anchor or {
                "entry_selector": "0x12345678",
                "calldata_sha256": HASH,
                "prestate_sha256": "b" * 64,
                "setup_sha256": "c" * 64,
            },
            "predicate": {
                "id": spec["property"],
                "observed": (role == "attack") if observed is None else observed,
            },
            "trace_events": [
                self._trace_event(seq=0, depth=depth),
                self._trace_event(seq=1, depth=depth),
            ] if spec["min_events"] > 1 else [self._trace_event(depth=depth)],
        }

    def test_inventory_exposes_all_15_families_without_fake_acceptance(self):
        rows = engine.family_inventory()
        self.assertEqual({row["family"] for row in rows}, set(engine.FAMILIES))
        self.assertEqual(len(rows), 15)
        self.assertEqual(
            [row["family"] for row in rows if row["status"] == "fixture_accepted"],
            ["reentrancy"],
        )
        self.assertTrue(all(
            row["status"] == "adapter_required"
            for row in rows if row["family"] != "reentrancy"
        ))

    def test_discovery_returns_candidate_signals_not_verdicts(self):
        result = engine.discover_candidates(self.root, "reentrancy")
        self.assertEqual(result["status"], "CANDIDATES_ONLY")
        self.assertTrue(all(row["status"] == "CANDIDATE" for row in result["candidates"]))
        self.assertTrue(all("source_sha256" in row for row in result["candidates"]))
        self.assertIn("No exploitability or impact", result["candidates"][0]["interpretation"])

    def test_discovery_requires_exact_source_hash_and_entrypoint(self):
        value = self._manifest()
        parsed = engine.validate_experiment_manifest(value, self.root)
        self.assertEqual(parsed["discovery"]["entrypoint"], "withdraw(uint256)")
        changed = dict(value)
        changed["discovery"] = dict(value["discovery"], source_sha256="0" * 64)
        with self.assertRaisesRegex(engine.AttackEngineError, "source hash"):
            engine.validate_experiment_manifest(changed, self.root)
        changed = dict(value)
        changed["discovery"] = dict(value["discovery"], entrypoint="drain()")
        with self.assertRaisesRegex(engine.AttackEngineError, "not found"):
            engine.validate_experiment_manifest(changed, self.root)

    def test_experiment_manifest_rejects_unsafe_paths_and_missing_mutation(self):
        value = self._manifest()
        value["attack"] = dict(value["attack"], test_file="../outside.sol")
        with self.assertRaises(engine.AttackEngineError):
            engine.validate_experiment_manifest(value, self.root)
        value = self._manifest()
        value["mutation"] = {"mutants": []}
        with self.assertRaisesRegex(engine.AttackEngineError, "at least one"):
            engine.validate_experiment_manifest(value, self.root)

    def test_pair_requires_attack_control_same_target_entry_and_prestate(self):
        manifest = engine.validate_experiment_manifest(self._manifest(), self.root)
        attack = self._evidence("attack")
        control = self._evidence("control")
        result = engine.validate_evidence_pair(attack, control, manifest)
        self.assertEqual(result["status"], "PAIRED_OBSERVATION")
        self.assertTrue(result["independent_reproof"]["source_verified"])
        self.assertEqual(result["attack_trace_events"], 2)

        mismatched = self._evidence("control", anchor={
            "entry_selector": "0x87654321",
            "calldata_sha256": HASH,
            "prestate_sha256": "b" * 64,
            "setup_sha256": "c" * 64,
        })
        with self.assertRaisesRegex(engine.AttackEngineError, "same entry call"):
            engine.validate_evidence_pair(attack, mismatched, manifest)

    def test_manifest_pins_adapter_test_source_hash(self):
        value = self._manifest()
        value["attack"]["test_sha256"] = "0" * 64
        with self.assertRaisesRegex(engine.AttackEngineError, "adapter test source hash"):
            engine.validate_experiment_manifest(value, self.root)
    def test_pair_fails_closed_on_control_failure_and_false_preconditions(self):
        manifest = engine.validate_experiment_manifest(self._manifest(), self.root)
        with self.assertRaisesRegex(engine.AttackEngineError, "Control run"):
            engine.validate_evidence_pair(
                self._evidence("attack"),
                self._evidence("control", observed=True),
                manifest,
            )
        invalid = self._evidence("attack")
        invalid["preconditions"][next(iter(invalid["preconditions"]))] = False
        with self.assertRaisesRegex(engine.AttackEngineError, "did not establish"):
            engine.validate_evidence_pair(invalid, self._evidence("control"), manifest)

    def test_pair_requires_exact_forge_storage_for_reentrancy(self):
        manifest = engine.validate_experiment_manifest(self._manifest(), self.root)
        attack = self._evidence("attack")
        attack["trace_events"] = [
            engine.build_trace_event(
                seq=0, backend="anvil-calltracer", kind="Call",
                accessor=ADDR, account=ADDR, depth=2, value=0,
                calldata="0x12345678", reverted=False,
                storage=None, storage_support="declared_only",
            ),
            engine.build_trace_event(
                seq=1, backend="anvil-calltracer", kind="Call",
                accessor=ADDR, account=ADDR, depth=2, value=0,
                calldata="0x12345678", reverted=False,
                storage=None, storage_support="declared_only",
            ),
        ]
        with self.assertRaisesRegex(engine.AttackEngineError, "Forge exact"):
            engine.validate_evidence_pair(attack, self._evidence("control"), manifest)

    def test_independent_reproof_requires_source_identity_successful_receipt_and_trace(self):
        value = self._manifest()
        manifest = engine.validate_experiment_manifest(value, self.root)
        attack, control = self._evidence("attack"), self._evidence("control")
        payload = json.loads((self.root / ".audit/godmode/reprove.json").read_text())
        payload["source_fork_verification"]["verified"] = False
        (self.root / ".audit/godmode/reprove.json").write_text(json.dumps(payload))
        with self.assertRaisesRegex(engine.AttackEngineError, "source-verified"):
            engine.validate_evidence_pair(attack, control, manifest)

    def test_economic_mode_requires_verified_profitable_reproof(self):
        self._write_reproof(semantic=False, profitable=True)
        manifest = engine.validate_experiment_manifest(
            self._manifest(family="economic", impact_mode="economic"), self.root
        )
        self.assertEqual(manifest["impact_mode"], "economic")
        (self.root / ".audit/godmode/reprove.json").write_text(json.dumps({
            "status": "FORK_REPRODUCED",
            "legacy_status": "FORK_REPRODUCED",
            "command_run": True,
            "target_address": ADDR,
            "chain_id": "0x1",
            "fork_parent_block": 100,
            "receipt_status": "0x1",
            "tx_hash": TX_HASH,
            "call_trace": [{"type": "CALL"}],
            "source_fork_verification": {
                "verified": True,
                "source_chain_id": "0x1",
                "target_code_sha256": CODE_SHA[2:],
            },
        }))
        with self.assertRaisesRegex(engine.AttackEngineError, "PROFITABLE"):
            engine.validate_evidence_pair(
                self._evidence("attack", family="economic"),
                self._evidence("control", family="economic"),
                manifest,
            )

    def _chain_manifest(self, *, impact_mode="semantic"):
        stages = [
            {
                "id": "borrow",
                "family": "reentrancy",
                "discovery": dict(self.discovery),
                "preconditions": list(engine.FAMILIES["reentrancy"]["preconditions"]),
                "depends_on": [],
                "consumes": [],
                "produces": ["borrowed-liquidity"],
                "on_failure": "abort",
                "rollback": "evm_transaction_revert",
            },
            {
                "id": "repay",
                "family": "accounting",
                "discovery": dict(self.discovery),
                "preconditions": list(engine.FAMILIES["accounting"]["preconditions"]),
                "depends_on": ["borrow"],
                "consumes": ["borrowed-liquidity"],
                "produces": ["repaid-position"],
                "on_failure": "abort",
                "rollback": "evm_transaction_revert",
            },
        ]
        return {
            "schema_version": 1,
            "id": "two-stage-chain-001",
            "target": dict(self.target),
            "property_id": "composed-chain-impact",
            "impact_mode": impact_mode,
            "mode": "single_transaction",
            "stages": stages,
            "attack": {
                "test_file": "test/Attack.t.sol", "test_name": "testChainAttack",
                "evidence_file": ".audit/lowkey/chain-attack.json",
            },
            "control": {
                "test_file": "test/Attack.t.sol", "test_name": "testChainControl",
                "evidence_file": ".audit/lowkey/chain-control.json",
            },
            "failure": {
                "test_file": "test/Attack.t.sol", "test_name": "testChainFailure",
                "evidence_file": ".audit/lowkey/chain-failure.json",
            },
            "reproof": dict(self.reproof),
            "mutation": {"mutants": [{
                "id": "kill-chain-predicate", "file": "src/Vault.sol",
                "before": "amount;", "after": "amount; // chain mutation",
            }]},
            "timeout_seconds": 60,
        }

    def test_chain_manifest_validates_artifact_dependencies_and_order(self):
        result = engine.validate_chain_manifest(self._chain_manifest(), self.root)
        self.assertEqual(result["stages"][1]["consumes"], ["borrowed-liquidity"])
        self.assertEqual(result["stages"][1]["depends_on"], ["borrow"])

    def test_chain_rejects_missing_dependency_and_unavailable_rollback(self):
        value = self._chain_manifest()
        value["stages"][1]["depends_on"] = []
        with self.assertRaisesRegex(engine.AttackEngineError, "explicitly depend"):
            engine.validate_chain_manifest(value, self.root)
        value = self._chain_manifest()
        value["stages"][0]["rollback"] = "none"
        with self.assertRaisesRegex(engine.AttackEngineError, "rollback"):
            engine.validate_chain_manifest(value, self.root)

    def test_chain_rejects_incomplete_target_specific_preconditions(self):
        value = self._chain_manifest()
        value["stages"][0]["preconditions"] = ["reachable external call"]
        with self.assertRaisesRegex(engine.AttackEngineError, "preconditions"):
            engine.validate_chain_manifest(value, self.root)


    def _chain_evidence(self, role):
        manifest = engine.validate_chain_manifest(self._chain_manifest(), self.root)
        anchor = {
            "entry_selector": "0x12345678",
            "calldata_sha256": HASH,
            "prestate_sha256": "b" * 64,
            "setup_sha256": "c" * 64,
        }
        observed = role == "attack"
        stage_results = [
            {
                "id": "borrow",
                "family": "reentrancy",
                "status": "completed",
                "prestate_sha256": "b" * 64,
                "poststate_sha256": "c" * 64,
                "consumed": [],
                "produced": ["borrowed-liquidity"],
                "discovery_sha256": self.source_hash,
                "preconditions": {item: True for item in engine.FAMILIES["reentrancy"]["preconditions"]},
                "predicate": {"id": engine.FAMILIES["reentrancy"]["property"], "observed": observed},
                "trace_events": [self._trace_event(seq=0), self._trace_event(seq=1)],
                "tx_hash": TX_HASH,
                "block_number": 101,
            },
            {
                "id": "repay",
                "family": "accounting",
                "status": "completed",
                "prestate_sha256": "c" * 64,
                "poststate_sha256": "d" * 64,
                "consumed": ["borrowed-liquidity"],
                "produced": ["repaid-position"],
                "discovery_sha256": self.source_hash,
                "preconditions": {item: True for item in engine.FAMILIES["accounting"]["preconditions"]},
                "predicate": {"id": engine.FAMILIES["accounting"]["property"], "observed": observed},
                "trace_events": [self._trace_event(seq=0)],
                "tx_hash": TX_HASH,
                "block_number": 101,
            },
        ]
        return {
            "schema_version": 1,
            "experiment_id": manifest["id"],
            "role": role,
            "target": dict(self.target),
            "adapter_sha256": self.test_hash,
            "pair_anchor": anchor,
            "predicate": {"id": manifest["property_id"], "observed": observed},
            "execution": {
                "mode": "single_transaction",
                "status": "passed",
                "atomic": True,
                "tx_hash": TX_HASH,
                "receipt_status": 1,
                "block_number": 101,
            },
            "stage_results": stage_results,
        }

    def test_chain_attack_control_evidence_requires_stage_predicates_and_continuity(self):
        manifest = engine.validate_chain_manifest(self._chain_manifest(), self.root)
        attack = self._chain_evidence("attack")
        control = self._chain_evidence("control")
        result = engine.validate_chain_evidence_pair(attack, control, manifest)
        self.assertEqual(result["status"], "CHAIN_PAIRED")
        self.assertEqual(result["stage_count"], 2)
        self.assertEqual(result["attack_stages"][1]["prestate_sha256"], "c" * 64)

        broken = self._chain_evidence("attack")
        broken["stage_results"][1]["prestate_sha256"] = "f" * 64
        with self.assertRaisesRegex(engine.AttackEngineError, "state continuity"):
            engine.validate_chain_evidence_pair(broken, control, manifest)

        wrong_stage_property = self._chain_evidence("attack")
        wrong_stage_property["stage_results"][0]["predicate"]["observed"] = False
        with self.assertRaisesRegex(engine.AttackEngineError, "wrong attack/control predicate"):
            engine.validate_chain_evidence_pair(wrong_stage_property, control, manifest)

    def test_failure_rollback_must_restore_the_exact_prestate(self):
        manifest = engine.validate_chain_manifest(self._chain_manifest(), self.root)
        evidence = {
            "schema_version": 1,
            "experiment_id": manifest["id"],
            "role": "failure",
            "target": dict(self.target),
            "adapter_sha256": self.test_hash,
            "failure_injection": {
                "executed": True,
                "failed_stage": "repay",
                "on_failure": "abort",
                "rollback_strategy": "evm_transaction_revert",
                "prestate_sha256": "d" * 64,
                "poststate_sha256": "d" * 64,
                "transaction_reverted": True,
            },
        }
        self.assertEqual(engine.validate_failure_rollback(evidence, manifest)["status"], "ROLLBACK_VERIFIED")
        evidence["failure_injection"]["poststate_sha256"] = "e" * 64
        with self.assertRaisesRegex(engine.AttackEngineError, "did not revert"):
            engine.validate_failure_rollback(evidence, manifest)

    def test_cli_inventory_is_json_and_lists_all_family_contracts(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = engine.main(["engines", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(stream.getvalue())
        self.assertEqual(len(payload["families"]), 15)

    def test_cli_validate_chain_does_not_execute_anything(self):
        path = self.root / "chain.json"
        path.write_text(json.dumps(self._chain_manifest()), encoding="utf-8")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = engine.main(["chain", "validate", "chain.json", "--root", str(self.root)])
        self.assertEqual(code, 0)
        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["status"], "VALIDATED_NOT_EXECUTED")
        self.assertIn("No commands", payload["execution"])


if __name__ == "__main__":
    unittest.main()
