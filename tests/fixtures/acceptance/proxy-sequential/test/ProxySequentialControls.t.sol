// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LowkeyForgeStateDiffRecorder} from "../src/LowkeyForgeStateDiffRecorder.sol";
import {
    VulnerableUUPSImplementation,
    SecureUUPSImplementation,
    LowkeyUUPSProxy,
    LowkeyProxyReplacement,
    PairedProxyAdmin,
    LowkeyTransparentProxy,
    ProxyUpgradeActor
} from "../src/ProxySequentialFixtures.sol";

contract ProxySequentialControlsTest is LowkeyForgeStateDiffRecorder {
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    address private constant ATTACKER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    function test_paired_uups_upgrade() external {
        address owner = vm.envAddress("P0_OWNER");
        LowkeyUUPSProxy proxy = LowkeyUUPSProxy(payable(vm.envAddress("P0_UUPS_PROXY")));
        address secureImplementation = vm.envAddress("P0_SECURE_IMPLEMENTATION");
        address vulnerableImplementation = vm.envAddress("P0_VULNERABLE_IMPLEMENTATION");
        ProxyUpgradeActor actor = ProxyUpgradeActor(vm.envAddress("P0_ACTOR"));
        LowkeyProxyReplacement replacement = new LowkeyProxyReplacement();
        bytes memory upgradeCall = abi.encodeWithSignature("upgradeTo(address)", address(replacement));
        uint256 baseline = vm.snapshot();

        vm.prank(owner);
        proxy.setImplementationForLab(secureImplementation);
        _lowkeyStartTrace(address(proxy));
        // Record the same owner slot in both paired scenarios. The secure
        // implementation reads it for authorization; the vulnerable one does not.
        require(vm.load(address(proxy), bytes32(0)) == bytes32(uint256(uint160(owner))), "CONTROL_OWNER_PRESTATE_MISMATCH");
        require(vm.load(address(proxy), IMPLEMENTATION_SLOT) == bytes32(uint256(uint160(secureImplementation))), "CONTROL_START_IMPLEMENTATION_MISMATCH");
        vm.prank(ATTACKER);
        bool controlCallSucceeded = actor.execute(address(proxy), upgradeCall);
        require(!controlCallSucceeded, "SECURE_UUPS_ACCEPTED_UNAUTHORIZED_CALL");
        require(actor.successfulCalls() == 0, "SECURE_UUPS_METRIC_CHANGED");
        require(proxy.implementation() == secureImplementation, "SECURE_UUPS_SLOT_CHANGED");
        _lowkeyWriteTrace(".audit/godmode/control-uups-state-diff.json");

        require(vm.revertTo(baseline), "UUPS_BASELINE_REVERT_FAILED");
        vm.prank(owner);
        proxy.setImplementationForLab(vulnerableImplementation);
        _lowkeyStartTrace(address(proxy));
        require(vm.load(address(proxy), bytes32(0)) == bytes32(uint256(uint160(owner))), "ATTACK_OWNER_PRESTATE_MISMATCH");
        require(vm.load(address(proxy), IMPLEMENTATION_SLOT) == bytes32(uint256(uint160(vulnerableImplementation))), "ATTACK_START_IMPLEMENTATION_MISMATCH");
        vm.prank(ATTACKER);
        bool attackCallSucceeded = actor.execute(address(proxy), upgradeCall);
        require(attackCallSucceeded, "VULNERABLE_UUPS_REJECTED_ATTACK");
        require(actor.successfulCalls() == 1, "VULNERABLE_UUPS_METRIC_MISSING");
        require(proxy.implementation() == address(replacement), "VULNERABLE_UUPS_SLOT_NOT_REPLACED");
        _lowkeyWriteTrace(".audit/godmode/attack-uups-state-diff.json");

        (bool markerOk, bytes memory markerData) = address(proxy).staticcall(abi.encodeWithSignature("lowkeyProxyMarker()"));
        require(markerOk && markerData.length == 32 && abi.decode(markerData, (bytes32)) == keccak256("LOWKEY_PROXY_SEQUENTIAL_REPLACEMENT"), "UUPS_DELEGATE_ROUTE_NOT_CONFIRMED");
    }

    function test_paired_proxy_admin_upgrade() external {
        address owner = vm.envAddress("P0_OWNER");
        PairedProxyAdmin admin = PairedProxyAdmin(vm.envAddress("P0_PROXY_ADMIN"));
        LowkeyTransparentProxy proxy = LowkeyTransparentProxy(payable(vm.envAddress("P0_TRANSPARENT_PROXY")));
        ProxyUpgradeActor actor = ProxyUpgradeActor(vm.envAddress("P0_ACTOR"));
        LowkeyProxyReplacement replacement = new LowkeyProxyReplacement();
        bytes memory upgradeCall = abi.encodeWithSignature("upgradeAndCall(address,address,bytes)", address(proxy), address(replacement), bytes(""));
        uint256 baseline = vm.snapshot();
        address originalImplementation = proxy.implementation();

        vm.prank(owner);
        admin.setSecureMode(true);
        _lowkeyStartTrace(address(admin));
        require(vm.load(address(admin), bytes32(0)) == bytes32(uint256(1)), "ADMIN_CONTROL_MODE_MISMATCH");
        // Make the transparent proxy's implementation slot part of the
        // observed pre-state even though the secure admin rejects before
        // forwarding the measured upgrade call.
        require(proxy.implementation() == originalImplementation, "ADMIN_PROXY_PRESTATE_MISMATCH");
        vm.prank(ATTACKER);
        bool controlCallSucceeded = actor.execute(address(admin), upgradeCall);
        require(!controlCallSucceeded, "SECURE_PROXY_ADMIN_ACCEPTED_UNAUTHORIZED_CALL");
        require(actor.successfulCalls() == 0, "SECURE_PROXY_ADMIN_METRIC_CHANGED");
        require(proxy.implementation() == originalImplementation, "SECURE_PROXY_ADMIN_SLOT_CHANGED");
        _lowkeyWriteTrace(".audit/godmode/control-proxy-admin-state-diff.json");

        require(vm.revertTo(baseline), "PROXY_ADMIN_BASELINE_REVERT_FAILED");
        vm.prank(owner);
        admin.setSecureMode(false);
        _lowkeyStartTrace(address(admin));
        require(vm.load(address(admin), bytes32(0)) == bytes32(uint256(0)), "ADMIN_ATTACK_MODE_MISMATCH");
        require(proxy.implementation() == originalImplementation, "ADMIN_ATTACK_PROXY_PRESTATE_MISMATCH");
        vm.prank(ATTACKER);
        bool attackCallSucceeded = actor.execute(address(admin), upgradeCall);
        require(attackCallSucceeded, "VULNERABLE_PROXY_ADMIN_REJECTED_ATTACK");
        require(actor.successfulCalls() == 1, "VULNERABLE_PROXY_ADMIN_METRIC_MISSING");
        require(proxy.implementation() == address(replacement), "VULNERABLE_PROXY_ADMIN_SLOT_NOT_REPLACED");
        _lowkeyWriteTrace(".audit/godmode/attack-proxy-admin-state-diff.json");

        (bool markerOk, bytes memory markerData) = address(proxy).staticcall(abi.encodeWithSignature("lowkeyProxyMarker()"));
        require(markerOk && markerData.length == 32 && abi.decode(markerData, (bytes32)) == keccak256("LOWKEY_PROXY_SEQUENTIAL_REPLACEMENT"), "PROXY_ADMIN_DELEGATE_ROUTE_NOT_CONFIRMED");
    }
}
