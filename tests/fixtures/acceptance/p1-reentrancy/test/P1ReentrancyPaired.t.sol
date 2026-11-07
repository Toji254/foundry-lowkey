// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ReentrancyVault, ReentrancyActor} from "../src/ReentrancyFixture.sol";
import {LowkeyForgeStateDiffRecorder} from "../src/LowkeyForgeStateDiffRecorder.sol";

/// @dev Executes both scenarios against the same forked deployments. The only
/// difference is the actor's mode, set outside each measured trace window.
contract P1ReentrancyPairedTest is LowkeyForgeStateDiffRecorder {
    function test_paired_reentrancy() external {
        ReentrancyVault vault = ReentrancyVault(payable(vm.envAddress("P1_VAULT")));
        ReentrancyActor actor = ReentrancyActor(payable(vm.envAddress("P1_ACTOR")));
        address owner = vm.envAddress("P1_OWNER");

        uint256 baseline = vm.snapshot();
        // Explicit artifact paths keep vulnerable and mutation evidence separate.
        // Defaults preserve the ordinary standalone fixture invocation.
        string memory controlTracePath = ".audit/godmode/control-state-diff.json";
        if (vm.envExists("P1_CONTROL_TRACE_PATH")) {
            controlTracePath = vm.envString("P1_CONTROL_TRACE_PATH");
        }
        string memory attackTracePath = ".audit/godmode/attack-state-diff.json";
        if (vm.envExists("P1_ATTACK_TRACE_PATH")) {
            attackTracePath = vm.envString("P1_ATTACK_TRACE_PATH");
        }

        // Across the measured pair the vault must receive exactly three
        // withdraw() calls: one sequential control and two attack-path calls.
        vm.expectCall(
            address(vault),
            abi.encodeWithSelector(ReentrancyVault.withdraw.selector),
            3
        );

        vm.prank(owner);
        actor.setMode(1);
        _lowkeyStartTrace(address(vault));
        actor.execute();
        uint256 controlSuccessfulReentries = actor.successfulReentries();
        uint256 controlObservedReentries = actor.observedReentryCount();
        require(controlSuccessfulReentries == 0, "CONTROL_REENTERED");
        require(controlObservedReentries == controlSuccessfulReentries, "CONTROL_METRIC_MISMATCH");
        _lowkeyWriteTrace(controlTracePath);

        require(vault.credit(address(actor)) == 0, "CONTROL_DID_NOT_CLEAR_CREDIT");
        require(vm.revertTo(baseline), "BASELINE_REVERT_FAILED");
        require(actor.mode() == 2, "BASELINE_MODE_NOT_RESTORED");

        vm.prank(owner);
        actor.setMode(2);
        _lowkeyStartTrace(address(vault));
        actor.execute();
        // Reading the counter while recording guarantees an observable final
        // value even when the CEI mutation correctly prevents every increment.
        uint256 expectedAttackReentries = vm.envOr("P1_EXPECT_ATTACK_REENTRIES", uint256(1));
        uint256 actualAttackReentries = actor.successfulReentries();
        uint256 observedAttackReentries = actor.observedReentryCount();
        require(
            actualAttackReentries == expectedAttackReentries,
            "ATTACK_SUCCESSFUL_REENTRY_COUNT_MISMATCH"
        );
        require(
            observedAttackReentries == actualAttackReentries,
            "ATTACK_METRIC_MISMATCH"
        );
        _lowkeyWriteTrace(attackTracePath);

        require(vault.credit(address(actor)) == 0, "ATTACK_DID_NOT_CLEAR_CREDIT");
        require(!actor.entered(), "CALLBACK_GUARD_NOT_CLEARED");
    }
}
