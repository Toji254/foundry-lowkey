// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ReentrancyVault, ReentrancyActor} from "../src/ReentrancyFixture.sol";
import {LowkeyForgeStateDiffRecorder} from "../src/LowkeyForgeStateDiffRecorder.sol";

/// @dev Executes both scenarios against the same forked deployments. The only
/// difference is the actor's mode, set outside each measured trace window.
contract P1ReentrancyPairedTest is Test, LowkeyForgeStateDiffRecorder {
    function test_paired_reentrancy() external {
        ReentrancyVault vault = ReentrancyVault(payable(vm.envAddress("P1_VAULT")));
        ReentrancyActor actor = ReentrancyActor(payable(vm.envAddress("P1_ACTOR")));
        address owner = vm.envAddress("P1_OWNER");

        uint256 baseline = vm.snapshot();

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
        _lowkeyWriteTrace(".audit/godmode/control-state-diff.json");

        require(vault.credit(address(actor)) == 0, "CONTROL_DID_NOT_CLEAR_CREDIT");
        require(vm.revertTo(baseline), "BASELINE_REVERT_FAILED");
        require(actor.mode() == 2, "BASELINE_MODE_NOT_RESTORED");

        vm.prank(owner);
        actor.setMode(2);
        _lowkeyStartTrace(address(vault));
        actor.execute();
        _lowkeyWriteTrace(".audit/godmode/attack-state-diff.json");

        require(vault.credit(address(actor)) == 0, "ATTACK_DID_NOT_CLEAR_CREDIT");
        require(!actor.entered(), "CALLBACK_GUARD_NOT_CLEARED");
    }
}
