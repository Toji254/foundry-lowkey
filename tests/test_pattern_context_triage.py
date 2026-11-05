from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest

from lowkey import walkthrough_finding_patterns as patterns


class ContextAwarePatternTriageTests(unittest.TestCase):
    def model(self, source: str, functions: list[str], arrays: list[str] | None = None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "src").mkdir()
        (root / "src" / "Vault.sol").write_text(source, encoding="utf-8")
        abi = [
            {"type": "function", "name": name, "stateMutability": "nonpayable"}
            for name in functions
        ]
        model = SimpleNamespace(
            name="Vault",
            source="src/Vault.sol",
            abi=abi,
            arrays=[{"name": name} for name in (arrays or [])],
            kind="contract",
        )
        return root, model

    def matches(self, root, model, pattern_id):
        return [item for item in patterns.scan_model(root, model) if item.pattern_id == pattern_id]

    def test_direct_caller_check_suppresses_auth_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                mapping(address => bool) guardian;
                function setGuardian(address user, bool enabled) external {
                    require(guardian[msg.sender]);
                    guardian[user] = enabled;
                }
            }
            """,
            ["setGuardian"],
        )
        self.assertEqual(self.matches(root, model, "AUTH-001"), [])

    def test_reachable_helper_authorization_suppresses_auth_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                mapping(address => bool) guardian;
                function _requireGuardian() internal view {
                    require(guardian[msg.sender]);
                }
                function pause() external {
                    _requireGuardian();
                    paused = true;
                }
                bool public paused;
            }
            """,
            ["pause"],
        )
        self.assertEqual(self.matches(root, model, "AUTH-001"), [])

    def test_inherited_modifier_suppresses_auth_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            abstract contract AuthBase {
                mapping(address => bool) guardian;
                modifier onlyGuardian() {
                    require(guardian[msg.sender]);
                    _;
                }
            }
            contract Vault is AuthBase {
                bool public paused;
                function setPaused(bool value) external onlyGuardian {
                    paused = value;
                }
            }
            """,
            ["setPaused"],
        )
        self.assertEqual(self.matches(root, model, "AUTH-001"), [])

    def test_trusted_self_call_helper_suppresses_auth_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                function _onlySelfCall() internal view {
                    require(msg.sender == address(this));
                }
                function executeRecovery() external {
                    _onlySelfCall();
                    recovered = true;
                }
                bool public recovered;
            }
            """,
            ["executeRecovery"],
        )
        self.assertEqual(self.matches(root, model, "AUTH-001"), [])

    def test_documented_permissionless_settlement_is_not_flagged(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                uint256 public epoch;
                /// @notice Permissionless; any keeper may call after the epoch closes.
                function settleLpEpoch() external {
                    epoch += 1;
                }
            }
            """,
            ["settleLpEpoch"],
        )
        self.assertEqual(self.matches(root, model, "AUTH-001"), [])

    def test_true_unguarded_sensitive_state_change_remains_a_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                mapping(address => bool) guardian;
                function setGuardian(address user, bool enabled) external {
                    guardian[user] = enabled;
                }
            }
            """,
            ["setGuardian"],
        )
        matches = self.matches(root, model, "AUTH-001")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].evidence_status, "needs-investigation")

    def test_fixed_constructor_configured_array_is_not_unbounded_dos_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                bytes32[3] public pythFeedIds;
                function settle() external {
                    for (uint256 i; i < pythFeedIds.length; ++i) {}
                }
            }
            """,
            ["settle"],
            ["pythFeedIds"],
        )
        self.assertEqual(self.matches(root, model, "DOS-001"), [])

    def test_dynamic_array_without_attacker_mutator_is_not_unbounded_dos_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                bytes32[] public pythFeedIds;
                constructor() {
                    pythFeedIds.push(bytes32(uint256(1)));
                    pythFeedIds.push(bytes32(uint256(2)));
                }
                function settle() external {
                    for (uint256 i; i < pythFeedIds.length; ++i) {}
                }
            }
            """,
            ["settle"],
            ["pythFeedIds"],
        )
        self.assertEqual(self.matches(root, model, "DOS-001"), [])

    def test_attacker_growable_dynamic_array_on_critical_path_remains_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                bytes32[] public queue;
                function add(bytes32 value) external {
                    queue.push(value);
                }
                function settle() external {
                    for (uint256 i; i < queue.length; ++i) {}
                }
            }
            """,
            ["add", "settle"],
            ["queue"],
        )
        matches = self.matches(root, model, "DOS-001")
        self.assertEqual(len(matches), 1)
        self.assertIn("unguarded external mutator", matches[0].evidence[0])

    def test_claim_consumes_entitlement_before_payout(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                mapping(address => uint256) remaining;
                function claim() external {
                    uint256 amount = remaining[msg.sender];
                    require(amount > 0);
                    remaining[msg.sender] = 0;
                    (bool ok,) = payable(msg.sender).call{value: amount}("");
                    require(ok);
                }
            }
            """,
            ["claim"],
        )
        self.assertEqual(self.matches(root, model, "REPLAY-001"), [])

    def test_unprotected_claim_payout_remains_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                function claim() external {
                    (bool ok,) = payable(msg.sender).call{value: 1}("");
                    require(ok);
                }
            }
            """,
            ["claim"],
        )
        matches = self.matches(root, model, "REPLAY-001")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].evidence_status, "needs-investigation")

    def test_async_partial_claim_zero_share_helper_guard_suppresses_rounding_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                error ZeroShares();
                function claimDeposit(uint256 assets) external {
                    uint256 shares = convertToShares(assets);
                    _claimDeposit(assets, shares);
                }
                function _claimDeposit(uint256 assets, uint256 shares) internal {
                    if (shares == 0) revert ZeroShares();
                    remaining[msg.sender] -= assets;
                }
                function convertToShares(uint256 assets) internal pure returns (uint256) {
                    return assets / 1000;
                }
                mapping(address => uint256) remaining;
            }
            """,
            ["claimDeposit"],
        )
        self.assertEqual(self.matches(root, model, "ROUND-001"), [])


if __name__ == "__main__":
    unittest.main()
