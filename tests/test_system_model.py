import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "lowkey"))
import system_model


class SystemModelTests(unittest.TestCase):
    def test_manifest_collects_deployment_script_and_test_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "script").mkdir()
            (root / "test").mkdir()
            (root / "out").mkdir()
            (root / "broadcast" / "Deploy" / "31337").mkdir(parents=True)

            (root / "src" / "Vault.sol").write_text(
                """
                contract Vault {
                    address public token;
                    function deposit(address asset, uint256 amount) external {
                        token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), amount));
                    }
                }
                """,
                encoding="utf-8",
            )
            (root / "script" / "Deploy.s.sol").write_text(
                """
                contract Deploy {
                    function run() external {
                        vm.startBroadcast();
                        Example a = new Example(token);
                        a.initialize();
                        a.transferOwnership(manager);
                        a.grantRole(ROLE, manager);
                        token.mint(user, 100);
                        token.approve(address(a), 100);
                    }
                }
                """,
                encoding="utf-8",
            )
            (root / "test" / "Vault.t.sol").write_text(
                """
                contract VaultTest {
                    function setUp() public { new Vault(); }
                }
                """,
                encoding="utf-8",
            )

            contract_address = "0x" + "1" * 40
            constructor_address = "0x" + "2" * 40
            broadcast = {
                "transactions": [
                    {
                        "transactionType": "CREATE",
                        "contractName": "Example",
                        "contractAddress": contract_address,
                        "hash": "0x" + "a" * 64,
                        "args": [constructor_address],
                    }
                ]
            }
            (root / "broadcast" / "Deploy" / "31337" / "run-latest.json").write_text(
                json.dumps(broadcast), encoding="utf-8"
            )
            (root / "out" / "Example.json").write_text(
                json.dumps({
                    "contractName": "Example",
                    "abi": [
                        {
                            "type": "function",
                            "name": "initialize",
                            "inputs": [],
                            "outputs": [],
                            "stateMutability": "nonpayable",
                        }
                    ],
                }),
                encoding="utf-8",
            )

            manifest = system_model.build_manifest(
                root,
                rpc="http://127.0.0.1:8545",
                config={"aliases": {"alice": "0x" + "3" * 40}},
            )

        self.assertEqual(manifest["schema"], "lowkey.system-bootstrap.v1")
        self.assertEqual(len(manifest["deployments"]), 1)
        self.assertEqual(manifest["deployments"][0]["contract"], "Example")
        self.assertEqual(manifest["scripts"][0]["path"], "script/Deploy.s.sol")
        self.assertEqual(manifest["tests"][0]["path"], "test/Vault.t.sol")
        self.assertTrue(any(x["kind"] == "initialize" for x in manifest["initialization"]))
        self.assertTrue(any(x["kind"] == "role_grant" for x in manifest["roles"]))
        self.assertEqual(manifest["actors"]["actors"][0]["name"], "alice")
        self.assertIn("audit_evidence", manifest)


    def test_manifest_promotes_audit_evidence_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            evidence = root / ".audit" / "evidence"
            evidence.mkdir(parents=True)
            target = "0x" + "1" * 40
            (evidence / "context.json").write_text(
                json.dumps({
                    "kind": "context",
                    "data": {"target": target},
                }),
                encoding="utf-8",
            )
            (evidence / "audit_start.json").write_text(
                json.dumps({
                    "kind": "audit_start",
                    "data": {"target": target},
                }),
                encoding="utf-8",
            )

            manifest = system_model.build_manifest(root)

        self.assertEqual(
            manifest["audit_targets"],
            [{"target": target, "source": "audit_start.json"}],
        )

    def test_manifest_links_deployment_arguments_to_known_contracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "broadcast" / "Deploy" / "31337").mkdir(parents=True)
            dep_a = "0x" + "1" * 40
            dep_b = "0x" + "2" * 40
            payload = {
                "transactions": [
                    {
                        "transactionType": "CREATE",
                        "contractName": "Dependency",
                        "contractAddress": dep_b,
                    },
                    {
                        "transactionType": "CREATE",
                        "contractName": "Main",
                        "contractAddress": dep_a,
                        "args": [dep_b],
                    },
                ]
            }
            (root / "broadcast" / "Deploy" / "31337" / "run-latest.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )

            with patch.object(system_model, "_code_size", return_value=123):
                manifest = system_model.build_manifest(root, rpc="http://127.0.0.1:8545")

        edges = manifest["relationships"]
        self.assertTrue(
            any(
                e["from"] == "Main"
                and e["to"] == "Dependency"
                and e["kind"] == "constructor-arg"
                for e in edges
            )
        )

    def test_refresh_manifest_writes_project_local_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with patch.object(system_model, "_code_size", return_value=0):
                manifest, path = system_model.refresh_manifest(root, reason="test")
            self.assertTrue(path.exists())
            self.assertEqual(path, root / ".audit" / "evidence" / "system_bootstrap.json")
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["updated_reason"], "test")
            self.assertEqual(loaded["schema"], "lowkey.system-bootstrap.v1")


if __name__ == "__main__":
    unittest.main()
