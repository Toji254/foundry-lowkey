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
    ProxyUpgradeActor,
    UUPSUUIDSecureImplementation,
    UUPSUUIDVulnerableImplementation,
    WrongUUIDProxyReplacement,
    LowkeyUUPSLockoutProxy,
    UUPSLockoutActor
} from "../src/ProxySequentialFixtures.sol";

interface ILowkeyTransparentOwner {
    function owner() external view returns (address);
}

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
        // Execute the public getter in both scenarios so the owner's slot is
        // observed by the EVM trace (vm.load is a test-cheatcode read, not an SLOAD).
        require(ILowkeyTransparentOwner(address(proxy)).owner() == owner, "CONTROL_OWNER_PRESTATE_MISMATCH");
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
        require(ILowkeyTransparentOwner(address(proxy)).owner() == owner, "ATTACK_OWNER_PRESTATE_MISMATCH");
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

    function test_transparent_admin_non_admin_selector_routing() external {
        address owner = vm.envAddress("P0_OWNER");
        PairedProxyAdmin admin = PairedProxyAdmin(vm.envAddress("P0_PROXY_ADMIN"));
        LowkeyTransparentProxy proxy = LowkeyTransparentProxy(payable(vm.envAddress("P0_TRANSPARENT_PROXY")));

        // The ProxyAdmin contract is the immutable Transparent admin. Its
        // non-upgrade selector must be rejected by the proxy's admin branch.
        vm.prank(owner);
        (bool adminOwnerSucceeded,) = admin.callProxy(
            address(proxy),
            abi.encodeWithSignature("owner()")
        );
        require(!adminOwnerSucceeded, "TRANSPARENT_ADMIN_REACHED_IMPLEMENTATION_GETTER");

        // The same selector from an ordinary caller must delegate to the
        // implementation and read the proxy's application storage.
        (bool userOwnerSucceeded, bytes memory ownerData) = address(proxy).staticcall(
            abi.encodeWithSignature("owner()")
        );
        require(userOwnerSucceeded, "TRANSPARENT_NON_ADMIN_DID_NOT_DELEGATE");
        require(ownerData.length == 32 && abi.decode(ownerData, (address)) == owner,
            "TRANSPARENT_NON_ADMIN_OWNER_VALUE_MISMATCH");

        // An admin call using the UUPS selector is not the Transparent
        // upgrade interface and must not fall through to UUPS implementation logic.
        vm.prank(owner);
        (bool adminUupsSucceeded,) = admin.callProxy(
            address(proxy),
            abi.encodeWithSignature("upgradeTo(address)", vm.envAddress("P0_VULNERABLE_IMPLEMENTATION"))
        );
        require(!adminUupsSucceeded, "TRANSPARENT_ADMIN_REACHED_UUPS_SELECTOR");
        require(
            proxy.implementation() == vm.envAddress("P0_SECURE_IMPLEMENTATION"),
            "TRANSPARENT_ADMIN_PROBE_CHANGED_IMPLEMENTATION"
        );
    }

    function test_paired_transparent_uups_second_surface() external {
        address owner = vm.envAddress("P0_OWNER");
        PairedProxyAdmin admin = PairedProxyAdmin(vm.envAddress("P0_PROXY_ADMIN"));
        LowkeyTransparentProxy proxy = LowkeyTransparentProxy(payable(vm.envAddress("P0_TRANSPARENT_PROXY")));
        ProxyUpgradeActor actor = ProxyUpgradeActor(vm.envAddress("P0_ACTOR"));
        address secureImplementation = vm.envAddress("P0_SECURE_IMPLEMENTATION");
        address vulnerableImplementation = vm.envAddress("P0_VULNERABLE_IMPLEMENTATION");
        LowkeyProxyReplacement replacement = new LowkeyProxyReplacement();
        bytes memory upgradeCall = abi.encodeWithSignature("upgradeTo(address)", address(replacement));
        // Keep the ProxyAdmin control secure so this experiment isolates the
        // independent UUPS route exposed to a non-admin implementation caller.
        vm.prank(owner);
        admin.setSecureMode(true);
        require(admin.secureMode(), "TRANSPARENT_HYBRID_PROXY_ADMIN_NOT_SECURE");
        uint256 baseline = vm.snapshot();

        // Control: the Transparent admin installs the secure UUPS-compatible
        // implementation through its own selector. A normal actor then reaches
        // the implementation's UUPS selector, but authorization must reject it.
        vm.prank(owner);
        admin.upgradeAndCall(address(proxy), secureImplementation, bytes(""));
        _lowkeyStartTrace(address(proxy));
        require(ILowkeyTransparentOwner(address(proxy)).owner() == owner, "TRANSPARENT_CONTROL_OWNER_PRESTATE_MISMATCH");
        require(proxy.implementation() == secureImplementation, "TRANSPARENT_CONTROL_IMPLEMENTATION_MISMATCH");
        require(actor.successfulCalls() == 0, "TRANSPARENT_CONTROL_METRIC_PRESTATE_MISMATCH");
        vm.prank(ATTACKER);
        bool controlSucceeded = actor.execute(address(proxy), upgradeCall);
        require(!controlSucceeded, "SECURE_UUPS_SECOND_SURFACE_ACCEPTED_UNAUTHORIZED_CALL");
        require(actor.successfulCalls() == 0, "SECURE_UUPS_SECOND_SURFACE_METRIC_CHANGED");
        require(proxy.implementation() == secureImplementation, "SECURE_UUPS_SECOND_SURFACE_SLOT_CHANGED");
        _lowkeyWriteTrace(".audit/godmode/control-transparent-hybrid-state-diff.json");

        require(vm.revertTo(baseline), "TRANSPARENT_HYBRID_BASELINE_REVERT_FAILED");

        // Attack: keep the same Transparent proxy, actor and exact calldata,
        // but let the authorized setup step install the deliberately vulnerable
        // UUPS-compatible implementation. The later ordinary actor call still
        // traverses the Transparent fallback and reaches UUPS upgradeTo(address).
        vm.prank(owner);
        admin.upgradeAndCall(address(proxy), vulnerableImplementation, bytes(""));
        _lowkeyStartTrace(address(proxy));
        require(ILowkeyTransparentOwner(address(proxy)).owner() == owner, "TRANSPARENT_ATTACK_OWNER_PRESTATE_MISMATCH");
        require(proxy.implementation() == vulnerableImplementation, "TRANSPARENT_ATTACK_IMPLEMENTATION_MISMATCH");
        require(actor.successfulCalls() == 0, "TRANSPARENT_ATTACK_METRIC_PRESTATE_MISMATCH");
        vm.prank(ATTACKER);
        bool attackSucceeded = actor.execute(address(proxy), upgradeCall);
        require(attackSucceeded, "VULNERABLE_UUPS_SECOND_SURFACE_REJECTED_ATTACK");
        require(actor.successfulCalls() == 1, "VULNERABLE_UUPS_SECOND_SURFACE_METRIC_MISSING");
        require(proxy.implementation() == address(replacement), "VULNERABLE_UUPS_SECOND_SURFACE_SLOT_NOT_REPLACED");
        _lowkeyWriteTrace(".audit/godmode/attack-transparent-hybrid-state-diff.json");

        (bool markerOk, bytes memory markerData) = address(proxy).staticcall(
            abi.encodeWithSignature("lowkeyProxyMarker()")
        );
        require(markerOk && markerData.length == 32
            && abi.decode(markerData, (bytes32)) == keccak256("LOWKEY_PROXY_SEQUENTIAL_REPLACEMENT"),
            "TRANSPARENT_HYBRID_DELEGATE_ROUTE_NOT_CONFIRMED");
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
        require(admin.secureMode(), "ADMIN_CONTROL_MODE_MISMATCH");
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
        require(!admin.secureMode(), "ADMIN_ATTACK_MODE_MISMATCH");
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

    function test_paired_uups_uuid_mismatch_prevents_upgrade_lockout() external {
        LowkeyUUPSLockoutProxy proxy = LowkeyUUPSLockoutProxy(
            payable(vm.envAddress("P0_UUPS_UUID_PROXY"))
        );
        UUPSLockoutActor actor = UUPSLockoutActor(vm.envAddress("P0_UUPS_LOCKOUT_ACTOR"));
        address secureImplementation = vm.envAddress("P0_UUPS_UUID_SECURE_IMPLEMENTATION");
        address vulnerableImplementation = vm.envAddress("P0_UUPS_UUID_VULNERABLE_IMPLEMENTATION");

        // Deploy candidates before snapshot so both scenarios use identical
        // candidate addresses and application prestate.
        WrongUUIDProxyReplacement wrongCandidate = new WrongUUIDProxyReplacement();
        UUPSUUIDSecureImplementation recoveryImplementation = new UUPSUUIDSecureImplementation();
        uint256 baseline = vm.snapshot();

        // Secure control rejects the mismatched UUID, preserving a usable route.
        vm.store(address(proxy), IMPLEMENTATION_SLOT, bytes32(uint256(uint160(secureImplementation))));
        _lowkeyStartTrace(address(proxy));
        require(proxy.owner() == address(actor), "UUID_CONTROL_OWNER_PRESTATE_MISMATCH");
        require(proxy.implementation() == secureImplementation, "UUID_CONTROL_IMPLEMENTATION_PRESTATE_MISMATCH");
        require(actor.invalidUuidUpgradeAccepted() == 0, "UUID_CONTROL_METRIC_PRESTATE_MISMATCH");
        require(actor.recoverySucceeded() == 0, "UUID_CONTROL_RECOVERY_PRESTATE_MISMATCH");
        bool controlAccepted = actor.attemptInvalidUpgrade(address(proxy), address(wrongCandidate));
        require(!controlAccepted, "SECURE_UUPS_ACCEPTED_MISMATCHED_UUID");
        require(actor.invalidUuidUpgradeAccepted() == 0, "SECURE_UUID_METRIC_CHANGED");
        require(proxy.implementation() == secureImplementation, "SECURE_UUID_SLOT_CHANGED");
        _lowkeyWriteTrace(".audit/godmode/control-uups-uuid-lockout-state-diff.json");

        bool controlRecovered = actor.attemptRecovery(address(proxy), address(recoveryImplementation));
        require(controlRecovered, "SECURE_UUPS_VALID_RECOVERY_REJECTED");
        require(proxy.implementation() == address(recoveryImplementation), "SECURE_UUPS_RECOVERY_SLOT_NOT_UPDATED");
        require(actor.recoverySucceeded() == 1, "SECURE_UUPS_RECOVERY_METRIC_MISSING");

        require(vm.revertTo(baseline), "UUID_LOCKOUT_BASELINE_REVERT_FAILED");

        // Vulnerable branch changes only the implementation under test. The
        // actor, proxy, candidate and encoded upgradeTo(address) call are fixed.
        vm.store(address(proxy), IMPLEMENTATION_SLOT, bytes32(uint256(uint160(vulnerableImplementation))));
        _lowkeyStartTrace(address(proxy));
        require(proxy.owner() == address(actor), "UUID_ATTACK_OWNER_PRESTATE_MISMATCH");
        require(proxy.implementation() == vulnerableImplementation, "UUID_ATTACK_IMPLEMENTATION_PRESTATE_MISMATCH");
        require(actor.invalidUuidUpgradeAccepted() == 0, "UUID_ATTACK_METRIC_PRESTATE_MISMATCH");
        require(actor.recoverySucceeded() == 0, "UUID_ATTACK_RECOVERY_PRESTATE_MISMATCH");
        bool attackAccepted = actor.attemptInvalidUpgrade(address(proxy), address(wrongCandidate));
        require(attackAccepted, "VULNERABLE_UUPS_REJECTED_MISMATCHED_UUID");
        require(actor.invalidUuidUpgradeAccepted() == 1, "VULNERABLE_UUID_METRIC_MISSING");
        require(proxy.implementation() == address(wrongCandidate), "VULNERABLE_UUID_SLOT_NOT_REPLACED");
        _lowkeyWriteTrace(".audit/godmode/attack-uups-uuid-lockout-state-diff.json");

        // The wrong-UUID implementation has no upgradeTo entrypoint. The same
        // authorized actor can no longer restore a valid UUPS implementation.
        bool attackRecovered = actor.attemptRecovery(address(proxy), address(recoveryImplementation));
        require(!attackRecovered, "UUID_LOCKOUT_RECOVERY_UNEXPECTEDLY_SUCCEEDED");
        require(actor.recoverySucceeded() == 0, "UUID_LOCKOUT_RECOVERY_METRIC_CHANGED");
        require(proxy.implementation() == address(wrongCandidate), "UUID_LOCKOUT_IMPLEMENTATION_CHANGED");
        (bool markerOk, bytes memory markerData) = address(proxy).staticcall(
            abi.encodeWithSignature("lowkeyProxyMarker()")
        );
        require(
            markerOk && markerData.length == 32
                && abi.decode(markerData, (bytes32)) == keccak256("LOWKEY_UUPS_UUID_LOCKOUT"),
            "UUID_LOCKOUT_DELEGATE_ROUTE_NOT_CONFIRMED"
        );
    }

}
