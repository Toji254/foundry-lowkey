import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "break_engine.py"
spec = importlib.util.spec_from_file_location("lowkey_break_engine_compile", MODULE)
break_engine = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = break_engine
spec.loader.exec_module(break_engine)


class BreakHarnessCompileTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("forge"), "Foundry is not installed")
    def test_generated_harness_families_compile(self):
        target = break_engine.Target(
            "CompileFixture",
            "0x1111111111111111111111111111111111111111",
        )
        withdraw = {
            "name": "withdraw",
            "inputs": [],
            "stateMutability": "nonpayable",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "test" / "lowkey").mkdir(parents=True)
            std = root / "lib" / "forge-std" / "src"
            std.mkdir(parents=True)

            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\ntest = "test"\n'
                'remappings = ["forge-std/=lib/forge-std/src/"]\n',
                encoding="utf-8",
            )
            (std / "Test.sol").write_text(
                """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface Vm {
    function deal(address who, uint256 amount) external;
    function deal(address token, address who, uint256 amount) external;
    function prank(address who) external;
    function snapshotState() external returns (uint256);
    function revertToState(uint256 snapshotId) external returns (bool);
    function warp(uint256 timestamp) external;
}
abstract contract Test {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function deal(address token, address who, uint256 amount) internal {
        vm.deal(token, who, amount);
    }
}
""",
                encoding="utf-8",
            )
            (std / "console2.sol").write_text(
                """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library console2 {
    function log(string memory) internal pure {}
    function log(string memory, string memory) internal pure {}
    function log(string memory, bool) internal pure {}
    function log(string memory, uint256) internal pure {}
    function logBytes(bytes memory) internal pure {}
}
""",
                encoding="utf-8",
            )

            renderers = {
                "reentrancy": break_engine._render_reentrancy_test(
                    target,
                    withdraw,
                    "withdraw()",
                    [],
                    3,
                    setup_signature="deposit()",
                    seed_fund="1ether",
                    entitlement_signature="balances(address)",
                    call_value="0",
                ),
                "replay": break_engine._render_repeat_test(
                    target,
                    withdraw,
                    "withdraw()",
                    [],
                    "0",
                    "replay",
                    "1ether",
                    setup_signature="deposit()",
                    entitlement_signature="balances(address)",
                ),
                "accounting": break_engine._render_repeat_test(
                    target,
                    withdraw,
                    "withdraw()",
                    [],
                    "0",
                    "accounting",
                    "1ether",
                    setup_signature="deposit()",
                    entitlement_signature="balances(address)",
                ),
                "access": break_engine._render_access_test(
                    target, "withdraw()", "0x12345678", "0"
                ),
                "upgrade": break_engine._render_access_test(
                    target, "upgradeTo(address)", "0x12345678", "0", False
                ),
                "boundary": break_engine._render_boundary_test(
                    target, "withdraw()", "0x12345678", "0x12345678", "0"
                ),
                "time": break_engine._render_time_test(
                    target, "withdraw()", "0x12345678", "0"
                ),
            }
            for family in (
                "callback", "signature", "dos", "oracle",
                "economic", "erc20", "proxy", "storage",
            ):
                renderers[family] = break_engine._render_access_test(
                    target, "withdraw()", "0x12345678", "0", break_on_success=False
                )
            for family, source in renderers.items():
                (root / "test" / "lowkey" / f"{family}.t.sol").write_text(
                    source, encoding="utf-8"
                )

            command = ["forge", "build", "--root", str(root)]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120,
            )
            compile_route = "default"
            if result.returncode != 0 and "Stack too deep" in (result.stdout + result.stderr):
                compile_route = "via-ir fallback"
                result = subprocess.run(
                    command + ["--via-ir", "--optimize"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            self.assertEqual(
                result.returncode,
                0,
                msg=f"Generated harness compilation failed ({compile_route}):\n"
                + result.stdout[-12000:]
                + "\n"
                + result.stderr[-12000:],
            )

if __name__ == "__main__":
    unittest.main()
