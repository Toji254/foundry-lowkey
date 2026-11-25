import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

from eth_flow import main


class EthFlowReconTests(unittest.TestCase):
    def workspace(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "packages"\n',
            encoding="utf-8",
        )
        vault = root / "packages" / "vault" / "src" / "Vault.sol"
        vault.parent.mkdir(parents=True)
        vault.write_text(
            """
            pragma solidity ^0.8.20;
            import "../../treasury/src/Treasury.sol";
            contract Vault {
                Treasury public treasury;
                mapping(address => uint256) public balances;

                constructor(address treasury_) {
                    treasury = Treasury(treasury_);
                }

                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                }

                function withdraw(uint256 amount, address payable recipient) external {
                    require(balances[msg.sender] >= amount);
                    balances[msg.sender] -= amount;
                    treasury.pay{value: amount}(recipient);
                }
            }
            """,
            encoding="utf-8",
        )
        treasury = root / "packages" / "treasury" / "src" / "Treasury.sol"
        treasury.parent.mkdir(parents=True)
        treasury.write_text(
            """
            pragma solidity ^0.8.20;
            contract Treasury {
                function pay(address payable recipient) external payable {
                    recipient.transfer(msg.value);
                }
            }
            """,
            encoding="utf-8",
        )
        return temporary, root

    def test_maps_payable_ingress_cross_package_value_call_and_exit(self):
        temporary, root = self.workspace()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["--root", str(root), "--depth", "5"])
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("ETH ENTERS", rendered)
        self.assertIn("Vault.deposit()", rendered)
        self.assertIn("ETH EXIT SITES", rendered)
        self.assertIn("Treasury.pay(", rendered)
        self.assertIn("CALL PATHS TO ETH EXITS", rendered)
        self.assertIn("Vault.withdraw(", rendered)
        self.assertIn("runtime implementation/address unresolved", rendered)
        self.assertIn("ACCOUNTING TOUCHPOINTS", rendered)
        self.assertIn("balances[msg.sender]", rendered)

    def test_contract_filter_still_follows_declared_external_package_target(self):
        temporary, root = self.workspace()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["--root", str(root), "--contract", "Vault"])
        finally:
            temporary.cleanup()

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("FILTER    contract=Vault", rendered)
        self.assertIn("Vault.withdraw(", rendered)
        self.assertIn("Treasury.pay(", rendered)

    def test_json_mode_emits_paths_and_coverage_metadata(self):
        temporary, root = self.workspace()
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["--root", str(root), "--json"])
        finally:
            temporary.cleanup()

        payload = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(payload["kind"], "static-eth-flow-recon")
        self.assertGreaterEqual(payload["summary"]["entry_points"], 1)
        self.assertIn("paths", payload)
        self.assertIn("coverage", payload)

    def test_help_aliases_follow_send_style_and_explain_evidence_limits(self):
        for flag in ("--h", "--help", "-h", "help"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([flag])
            rendered = output.getvalue()
            self.assertEqual(status, 0)
            for section in (
                "LOWKEY HELP  •  lk flow eth",
                "What it does:",
                "When to use:",
                "Usage:",
                "Example:",
                "COMMAND VARIATIONS",
                "OPTIONS / MODES",
                "RELATED COMMANDS",
                "HELP TIP",
                "--contract <NAME>",
                "--depth <N>",
                "--json",
                "runtime address",
            ):
                self.assertIn(section, rendered)

    def test_unknown_contract_is_a_clear_error(self):
        temporary, root = self.workspace()
        try:
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                status = main(["--root", str(root), "--contract", "DoesNotExist"])
        finally:
            temporary.cleanup()

        self.assertEqual(status, 2)
        self.assertIn("No contract named", output.getvalue())


if __name__ == "__main__":
    unittest.main()
