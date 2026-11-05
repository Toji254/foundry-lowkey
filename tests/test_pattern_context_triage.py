from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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


    def test_noop_only_modifier_does_not_suppress_auth_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                modifier onlyGuardian() { _; }
                bool public paused;
                function pause() external onlyGuardian { paused = true; }
            }
            """,
            ["pause"],
        )
        matches = self.matches(root, model, "AUTH-001")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].evidence_status, "context-checked")


    def test_sender_comparison_without_enforcement_does_not_suppress_auth_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                address public owner;
                bool public paused;
                function pause() external {
                    bool callerIsOwner = msg.sender == owner;
                    paused = true;
                }
            }
            """,
            ["pause"],
        )
        self.assertEqual(len(self.matches(root, model, "AUTH-001")), 1)

    def test_same_named_guard_in_unimported_sibling_does_not_suppress_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                bool public paused;
                function pause() external { _requireGuardian(); paused = true; }
            }
            """,
            ["pause"],
        )
        sibling = root / "src" / "Unrelated.sol"
        sibling.write_text(
            "contract Unrelated { function _requireGuardian() internal view { require(msg.sender == address(this)); } }",
            encoding="utf-8",
        )
        matches = self.matches(root, model, "AUTH-001")
        self.assertEqual(len(matches), 1)


    def test_noop_require_helper_does_not_suppress_auth_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                bool public paused;
                function _requireGuardian() internal view {}
                function pause() external {
                    _requireGuardian();
                    paused = true;
                }
            }
            """,
            ["pause"],
        )
        self.assertEqual(len(self.matches(root, model, "AUTH-001")), 1)

    def test_always_true_has_role_helper_does_not_suppress_auth_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                bytes32 constant OPERATOR = keccak256("OPERATOR");
                bool public paused;
                function hasRole(bytes32, address) internal pure returns (bool) {
                    return true;
                }
                function pause() external {
                    require(hasRole(OPERATOR, msg.sender));
                    paused = true;
                }
            }
            """,
            ["pause"],
        )
        self.assertEqual(len(self.matches(root, model, "AUTH-001")), 1)

    def test_role_predicate_helper_is_resolved_and_caller_argument_is_traced(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                bytes32 constant OPERATOR = keccak256("OPERATOR");
                mapping(bytes32 => mapping(address => bool)) roleMembers;
                bool public paused;
                function hasRole(bytes32 role, address account) internal view returns (bool) {
                    return roleMembers[role][account];
                }
                function pause() external {
                    require(hasRole(OPERATOR, msg.sender));
                    paused = true;
                }
            }
            """,
            ["pause"],
        )
        self.assertEqual(self.matches(root, model, "AUTH-001"), [])

    def test_imported_inherited_modifier_is_resolved(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            import "./AuthBase.sol";
            contract Vault is AuthBase {
                bool public paused;
                function setPaused(bool value) external onlyGuardian { paused = value; }
            }
            """,
            ["setPaused"],
        )
        (root / "src" / "AuthBase.sol").write_text(
            "pragma solidity ^0.8.20; abstract contract AuthBase { "
            "mapping(address => bool) guardian; "
            "modifier onlyGuardian() { require(guardian[msg.sender]); _; } }",
            encoding="utf-8",
        )
        self.assertEqual(self.matches(root, model, "AUTH-001"), [])

    def test_inherited_noop_modifier_does_not_suppress_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            abstract contract AuthBase { modifier onlyGuardian() { _; } }
            contract Vault is AuthBase {
                bool public paused;
                function setPaused(bool value) external onlyGuardian { paused = value; }
            }
            """,
            ["setPaused"],
        )
        self.assertEqual(len(self.matches(root, model, "AUTH-001")), 1)


    def test_imported_first_party_workspace_base_is_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "pnpm-workspace.yaml").write_text("packages:\n  - packages/*\n", encoding="utf-8")
            package = workspace / "packages" / "perps"
            (package / "src").mkdir(parents=True)
            shared = workspace / "packages" / "shared" / "src"
            shared.mkdir(parents=True)
            (package / "foundry.toml").write_text(
                '[profile.default]\nremappings = ["@shared/=../shared/src/"]\n',
                encoding="utf-8",
            )
            (package / "src" / "Vault.sol").write_text(
                'pragma solidity ^0.8.20; import "@shared/AuthBase.sol"; '
                'contract Vault is AuthBase { bool public paused; '
                'function setPaused(bool value) external onlyGuardian { paused = value; } }',
                encoding="utf-8",
            )
            (shared / "AuthBase.sol").write_text(
                'pragma solidity ^0.8.20; abstract contract AuthBase { '
                'mapping(address => bool) internal guardian; '
                'modifier onlyGuardian() { require(guardian[msg.sender]); _; } }',
                encoding="utf-8",
            )
            model = SimpleNamespace(
                name="Vault", source="src/Vault.sol",
                abi=[{"type": "function", "name": "setPaused", "stateMutability": "nonpayable"}],
                arrays=[], kind="contract",
            )
            self.assertEqual(self.matches(package, model, "AUTH-001"), [])

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
        self.assertEqual(matches[0].evidence_status, "context-checked")

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


    def test_claim_guard_without_pre_payout_consumption_does_not_hide_replay_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                mapping(address => bool) claimed;
                function claim() external {
                    require(!claimed[msg.sender]);
                    (bool ok,) = payable(msg.sender).call{value: 1}("");
                    require(ok);
                }
            }
            """,
            ["claim"],
        )
        self.assertEqual(len(self.matches(root, model, "REPLAY-001")), 1)

    def test_unrelated_contract_mutator_in_same_file_does_not_grow_selected_array(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                address[] public members;
                function withdrawAll() external {
                    for (uint256 i; i < members.length; ++i) {
                        payable(msg.sender).transfer(1);
                    }
                }
            }
            contract Other {
                address[] public members;
                function addMember(address who) external { members.push(who); }
            }
            """,
            ["withdrawAll"],
            arrays=["members"],
        )
        self.assertEqual(self.matches(root, model, "DOS-001"), [])

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


    def test_unimported_sibling_claim_helper_does_not_hide_replay_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                function claim() external {
                    _consumeClaim();
                    (bool ok,) = payable(msg.sender).call{value: 1}("");
                    require(ok);
                }
            }
            """,
            ["claim"],
        )
        (root / "src" / "Unrelated.sol").write_text(
            "contract Other { mapping(address => bool) claimed; "
            "function _consumeClaim() internal { claimed[msg.sender] = true; } }",
            encoding="utf-8",
        )
        matches = self.matches(root, model, "REPLAY-001")
        self.assertEqual(len(matches), 1)

    def test_inherited_claim_helper_consumption_suppresses_replay_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            abstract contract ClaimBase {
                mapping(address => bool) claimed;
                function _consumeClaim() internal {
                    require(!claimed[msg.sender]);
                    claimed[msg.sender] = true;
                }
            }
            contract Vault is ClaimBase {
                function claim() external {
                    _consumeClaim();
                    (bool ok,) = payable(msg.sender).call{value: 1}("");
                    require(ok);
                }
            }
            """,
            ["claim"],
        )
        self.assertEqual(self.matches(root, model, "REPLAY-001"), [])

    def test_unimported_sibling_zero_share_helper_does_not_hide_rounding_candidate(self):
        root, model = self.model(
            """
            pragma solidity ^0.8.20;
            contract Vault {
                function claimDeposit(uint256 assets) external {
                    uint256 shares = assets / 1000;
                    _claimDeposit(assets, shares);
                }
                function _claimDeposit(uint256 assets, uint256 shares) internal {
                    remaining[msg.sender] -= assets;
                }
                mapping(address => uint256) remaining;
            }
            """,
            ["claimDeposit"],
        )
        (root / "src" / "Unrelated.sol").write_text(
            "contract Other { error ZeroShares(); "
            "function _claimDeposit(uint256 assets, uint256 shares) internal { "
            "if (shares == 0) revert ZeroShares(); } }",
            encoding="utf-8",
        )
        matches = self.matches(root, model, "ROUND-001")
        self.assertEqual(len(matches), 1)

    def test_scan_project_deduplicates_repeated_alerts_but_keeps_distinct_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repeated = patterns.PatternObservation(
                pattern_id="AUTH-001",
                title="Authorization candidate",
                status="candidate",
                contract="Vault",
                function="withdraw",
                source="src/Vault.sol",
                line=20,
                evidence=["The caller boundary is not obvious.", "No helper guard was found."],
                provenance=["fixture A"],
                evidence_status="needs-investigation",
            )
            same_issue_nearby = patterns.PatternObservation(
                pattern_id="AUTH-001",
                title="Authorization candidate",
                status="candidate",
                contract="Vault",
                function="withdraw",
                source="src/Vault.sol",
                line=34,
                evidence=["The caller boundary is not obvious.", "No helper guard was found."],
                provenance=["fixture B"],
                evidence_status="needs-investigation",
            )
            independent_path = patterns.PatternObservation(
                pattern_id="AUTH-001",
                title="Authorization candidate",
                status="candidate",
                contract="Vault",
                function="withdraw",
                source="src/Vault.sol",
                line=48,
                evidence=["The caller boundary is not obvious.", "The second overload reaches an unguarded admin write."],
                provenance=["fixture C"],
                evidence_status="needs-investigation",
            )
            models = [
                SimpleNamespace(name="Vault", kind="contract"),
                SimpleNamespace(name="Vault", kind="contract"),
                SimpleNamespace(name="Vault", kind="contract"),
            ]
            with patch.object(
                patterns,
                "scan_model",
                side_effect=[[repeated], [same_issue_nearby], [independent_path]],
            ):
                findings = patterns.scan_project(root, models)

            self.assertEqual(len(findings), 2)
            self.assertEqual(findings[0].line, 20)
            self.assertEqual(findings[0].provenance, ["fixture A", "fixture B"])
            self.assertEqual(findings[1].line, 48)
            self.assertIn("second overload", findings[1].evidence[1])


if __name__ == "__main__":
    unittest.main()
