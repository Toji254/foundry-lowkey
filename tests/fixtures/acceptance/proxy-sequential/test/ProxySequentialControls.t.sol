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
    UUPSLockoutActor,
    UUPSImplementationInitializationFixture,
    ImplementationInitializationActor,
    UUPSReinitializerSecureImplementation,
    UUPSReinitializerVulnerableImplementation,
    UUPSInitializationOrderImplementation,
    LowkeyInitializationOrderProxy,
    LowkeyAtomicInitializationProxy
} from "../src/ProxySequentialFixtures.sol";

interface ILowkeyTransparentOwner {
    function owner() external view returns (address);
}

interface ILowkeyReinitializerState {
    function initializedVersion() external view returns (uint8);
    function migrationOwner() external view returns (address);
}

interface ILowkeyInitializationOrderState {
    function owner() external view returns (address);
    function initializedVersion() external view returns (uint8);
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


    function test_paired_implementation_initializer_lock_prevents_takeover() external {
        UUPSImplementationInitializationFixture implementation =
            UUPSImplementationInitializationFixture(
                vm.envAddress("P0_IMPLEMENTATION_INITIALIZER_TARGET")
            );
        ImplementationInitializationActor actor = ImplementationInitializationActor(
            vm.envAddress("P0_IMPLEMENTATION_INITIALIZER_ACTOR")
        );
        uint256 baseline = vm.snapshot();

        // Control: the constructor has already disabled initialization on
        // the direct implementation before any untrusted caller can initialize.
        _lowkeyStartTrace(address(implementation));
        require(implementation.initializedVersion() == type(uint8).max,
            "INITIALIZER_CONTROL_NOT_LOCKED");
        require(implementation.owner() == address(0), "INITIALIZER_CONTROL_OWNER_PRESET");
        require(actor.takeoverAccepted() == 0, "INITIALIZER_CONTROL_METRIC_PRESET");
        bool controlAccepted = actor.attemptInitialize(address(implementation), address(actor));
        require(!controlAccepted, "LOCKED_IMPLEMENTATION_ACCEPTED_INITIALIZER");
        require(actor.takeoverAccepted() == 0, "LOCKED_IMPLEMENTATION_METRIC_CHANGED");
        require(implementation.owner() == address(0), "LOCKED_IMPLEMENTATION_OWNER_CHANGED");
        _lowkeyWriteTrace(".audit/godmode/control-implementation-initializer-state-diff.json");

        // Attack: revert to the exact deployment baseline and model the
        // missing constructor _disableInitializers() call by clearing only its
        // initialized-version slot inside this disposable Forge fork.
        require(vm.revertTo(baseline), "IMPLEMENTATION_INITIALIZER_BASELINE_REVERT_FAILED");
        vm.store(address(implementation), bytes32(uint256(0)), bytes32(uint256(0)));
        _lowkeyStartTrace(address(implementation));
        require(implementation.initializedVersion() == 0, "INITIALIZER_ATTACK_VERSION_PRESTATE_MISMATCH");
        require(implementation.owner() == address(0), "INITIALIZER_ATTACK_OWNER_PRESTATE_MISMATCH");
        require(actor.takeoverAccepted() == 0, "INITIALIZER_ATTACK_METRIC_PRESTATE_MISMATCH");
        bool attackAccepted = actor.attemptInitialize(address(implementation), address(actor));
        require(attackAccepted, "UNLOCKED_IMPLEMENTATION_REJECTED_TAKEOVER");
        require(actor.takeoverAccepted() == 1, "IMPLEMENTATION_TAKEOVER_METRIC_MISSING");
        require(implementation.initializedVersion() == 1, "IMPLEMENTATION_INITIALIZER_VERSION_NOT_SET");
        require(implementation.owner() == address(actor), "IMPLEMENTATION_TAKEOVER_OWNER_MISMATCH");
        _lowkeyWriteTrace(".audit/godmode/attack-implementation-initializer-state-diff.json");
    }



    function _prepareReinitializerProxy(
        address owner,
        LowkeyUUPSProxy proxy,
        address implementation_
    ) private {
        vm.prank(owner);
        proxy.setImplementationForLab(implementation_);

        (bool initialized, ) = address(proxy).call(
            abi.encodeWithSignature("initializeV1(address)", owner)
        );
        require(initialized, "REINITIALIZER_V1_SETUP_FAILED");
        (bool migrated, ) = address(proxy).call(
            abi.encodeWithSignature("reinitializeV2(address)", owner)
        );
        require(migrated, "REINITIALIZER_V2_SETUP_FAILED");

        ILowkeyReinitializerState state = ILowkeyReinitializerState(address(proxy));
        require(state.initializedVersion() == 2, "REINITIALIZER_VERSION_NOT_PRIMED");
        require(state.migrationOwner() == owner, "REINITIALIZER_OWNER_NOT_PRIMED");
    }

    function test_paired_uups_reinitializer_replay() external {
        address owner = vm.envAddress("P0_OWNER");
        LowkeyUUPSProxy proxy = LowkeyUUPSProxy(
            payable(vm.envAddress("P0_UUPS_REINITIALIZER_PROXY"))
        );
        address secureImplementation = vm.envAddress("P0_UUPS_REINITIALIZER_SECURE_IMPLEMENTATION");
        address vulnerableImplementation = vm.envAddress("P0_UUPS_REINITIALIZER_VULNERABLE_IMPLEMENTATION");
        ProxyUpgradeActor actor = ProxyUpgradeActor(
            vm.envAddress("P0_UUPS_REINITIALIZER_ACTOR")
        );
        ILowkeyReinitializerState state = ILowkeyReinitializerState(address(proxy));
        bytes memory replayCall = abi.encodeWithSignature(
            "reinitializeV2(address)", ATTACKER
        );
        uint256 baseline = vm.snapshot();

        // Secure control: both branches receive the same completed V1/V2
        // setup before the replay call is measured.
        _prepareReinitializerProxy(owner, proxy, secureImplementation);
        _lowkeyStartTrace(address(proxy));
        require(proxy.implementation() == secureImplementation, "REINITIALIZER_CONTROL_IMPLEMENTATION_MISMATCH");
        require(state.initializedVersion() == 2, "REINITIALIZER_CONTROL_VERSION_MISMATCH");
        require(state.migrationOwner() == owner, "REINITIALIZER_CONTROL_OWNER_MISMATCH");
        require(actor.successfulCalls() == 0, "REINITIALIZER_CONTROL_METRIC_PRESTATE");
        vm.prank(ATTACKER);
        bool controlAccepted = actor.execute(address(proxy), replayCall);
        require(!controlAccepted, "SECURE_REINITIALIZER_ACCEPTED_REPLAY");
        require(actor.successfulCalls() == 0, "SECURE_REINITIALIZER_METRIC_CHANGED");
        require(state.initializedVersion() == 2, "SECURE_REINITIALIZER_VERSION_CHANGED");
        require(state.migrationOwner() == owner, "SECURE_REINITIALIZER_OWNER_CHANGED");
        _lowkeyWriteTrace(".audit/godmode/control-uups-reinitializer-replay-state-diff.json");

        require(vm.revertTo(baseline), "REINITIALIZER_REPLAY_BASELINE_REVERT_FAILED");

        // Attack: only the implementation changes. The actor, proxy and exact
        // replay calldata are identical to the secure control.
        _prepareReinitializerProxy(owner, proxy, vulnerableImplementation);
        _lowkeyStartTrace(address(proxy));
        require(proxy.implementation() == vulnerableImplementation, "REINITIALIZER_ATTACK_IMPLEMENTATION_MISMATCH");
        require(state.initializedVersion() == 2, "REINITIALIZER_ATTACK_VERSION_MISMATCH");
        require(state.migrationOwner() == owner, "REINITIALIZER_ATTACK_OWNER_MISMATCH");
        require(actor.successfulCalls() == 0, "REINITIALIZER_ATTACK_METRIC_PRESTATE");
        vm.prank(ATTACKER);
        bool attackAccepted = actor.execute(address(proxy), replayCall);
        require(attackAccepted, "VULNERABLE_REINITIALIZER_REJECTED_REPLAY");
        require(actor.successfulCalls() == 1, "VULNERABLE_REINITIALIZER_METRIC_MISSING");
        require(state.initializedVersion() == 2, "VULNERABLE_REINITIALIZER_VERSION_MISMATCH");
        require(state.migrationOwner() == ATTACKER, "VULNERABLE_REINITIALIZER_REPLAY_NOT_APPLIED");
        _lowkeyWriteTrace(".audit/godmode/attack-uups-reinitializer-replay-state-diff.json");
    }



    function test_paired_proxy_initialization_ordering() external {
        address owner = vm.envAddress("P0_OWNER");
        UUPSInitializationOrderImplementation implementation =
            UUPSInitializationOrderImplementation(
                vm.envAddress("P0_INITIALIZATION_ORDER_IMPLEMENTATION")
            );
        LowkeyInitializationOrderProxy proxy =
            LowkeyInitializationOrderProxy(
                payable(vm.envAddress("P0_INITIALIZATION_ORDER_PROXY"))
            );
        ImplementationInitializationActor actor =
            ImplementationInitializationActor(
                vm.envAddress("P0_INITIALIZATION_ORDER_ACTOR")
            );
        ILowkeyInitializationOrderState state =
            ILowkeyInitializationOrderState(address(proxy));

        // The implementation's own storage is locked, but the proxy's storage
        // is separate and starts uninitialized unless deployment supplies data.
        require(implementation.initializedVersion() == type(uint8).max,
            "INITIALIZATION_ORDER_IMPLEMENTATION_NOT_LOCKED");
        require(implementation.owner() == address(0),
            "INITIALIZATION_ORDER_IMPLEMENTATION_OWNER_NOT_EMPTY");
        require(state.initializedVersion() == 0, "INITIALIZATION_ORDER_PROXY_PREINITIALIZED");
        require(state.owner() == address(0), "INITIALIZATION_ORDER_PROXY_OWNER_PRESET");

        vm.prank(ATTACKER);
        bool directAccepted = actor.attemptInitialize(address(implementation), ATTACKER);
        require(!directAccepted, "LOCKED_IMPLEMENTATION_ACCEPTED_DIRECT_INITIALIZATION");
        require(actor.takeoverAccepted() == 0, "DIRECT_IMPLEMENTATION_METRIC_CHANGED");
        uint256 baseline = vm.snapshot();

        // Control: the intended owner initializes the proxy before an
        // untrusted caller submits the same initialize(address) calldata.
        vm.prank(owner);
        (bool ownerInitialized, ) = address(proxy).call(
            abi.encodeWithSignature("initialize(address)", owner)
        );
        require(ownerInitialized, "OWNER_FIRST_PROXY_INITIALIZATION_FAILED");
        _lowkeyStartTrace(address(proxy));
        require(proxy.implementation() == address(implementation),
            "INITIALIZATION_ORDER_CONTROL_IMPLEMENTATION_CHANGED");
        require(implementation.initializedVersion() == type(uint8).max,
            "INITIALIZATION_ORDER_CONTROL_IMPLEMENTATION_UNLOCKED");
        require(state.initializedVersion() == 1, "INITIALIZATION_ORDER_CONTROL_VERSION_MISMATCH");
        require(state.owner() == owner, "INITIALIZATION_ORDER_CONTROL_OWNER_MISMATCH");
        require(actor.takeoverAccepted() == 0, "INITIALIZATION_ORDER_CONTROL_METRIC_PRESTATE");
        bool controlAccepted = actor.attemptInitialize(address(proxy), ATTACKER);
        require(!controlAccepted, "INITIALIZED_PROXY_ACCEPTED_ATTACKER");
        require(actor.takeoverAccepted() == 0, "INITIALIZATION_ORDER_CONTROL_METRIC_CHANGED");
        require(state.initializedVersion() == 1, "INITIALIZATION_ORDER_CONTROL_VERSION_CHANGED");
        require(state.owner() == owner, "INITIALIZATION_ORDER_CONTROL_OWNER_CHANGED");
        _lowkeyWriteTrace(".audit/godmode/control-proxy-initialization-order-state-diff.json");

        require(vm.revertTo(baseline), "INITIALIZATION_ORDER_BASELINE_REVERT_FAILED");

        // Attack: the same proxy and actor are restored to the uninitialized
        // prestate. The attacker reaches initialize(address) before the
        // intended owner and takes control of the proxy's application state.
        _lowkeyStartTrace(address(proxy));
        require(proxy.implementation() == address(implementation),
            "INITIALIZATION_ORDER_ATTACK_IMPLEMENTATION_CHANGED");
        require(implementation.initializedVersion() == type(uint8).max,
            "INITIALIZATION_ORDER_ATTACK_IMPLEMENTATION_UNLOCKED");
        require(state.initializedVersion() == 0, "INITIALIZATION_ORDER_ATTACK_VERSION_PRESTATE");
        require(state.owner() == address(0), "INITIALIZATION_ORDER_ATTACK_OWNER_PRESTATE");
        require(actor.takeoverAccepted() == 0, "INITIALIZATION_ORDER_ATTACK_METRIC_PRESTATE");
        bool attackAccepted = actor.attemptInitialize(address(proxy), ATTACKER);
        require(attackAccepted, "UNINITIALIZED_PROXY_REJECTED_FRONT_RUN");
        require(actor.takeoverAccepted() == 1, "INITIALIZATION_ORDER_TAKEOVER_METRIC_MISSING");
        require(state.initializedVersion() == 1, "INITIALIZATION_ORDER_ATTACK_VERSION_NOT_SET");
        require(state.owner() == ATTACKER, "INITIALIZATION_ORDER_ATTACK_OWNER_MISMATCH");
        _lowkeyWriteTrace(".audit/godmode/attack-proxy-initialization-order-state-diff.json");
    }

    function test_proxy_constructor_initialization_is_atomic_and_implementation_stays_locked() external {
        address owner = vm.envAddress("P0_OWNER");
        UUPSInitializationOrderImplementation implementation =
            UUPSInitializationOrderImplementation(
                vm.envAddress("P0_INITIALIZATION_ORDER_IMPLEMENTATION")
            );
        bytes memory initializationCall = abi.encodeWithSignature("initialize(address)", owner);
        LowkeyAtomicInitializationProxy proxy =
            new LowkeyAtomicInitializationProxy(address(implementation), initializationCall);
        ILowkeyInitializationOrderState state =
            ILowkeyInitializationOrderState(address(proxy));

        require(proxy.implementation() == address(implementation),
            "ATOMIC_PROXY_IMPLEMENTATION_MISMATCH");
        require(state.initializedVersion() == 1, "ATOMIC_PROXY_NOT_INITIALIZED");
        require(state.owner() == owner, "ATOMIC_PROXY_OWNER_MISMATCH");
        require(implementation.initializedVersion() == type(uint8).max,
            "ATOMIC_PROXY_UNLOCKED_IMPLEMENTATION");
        require(implementation.owner() == address(0),
            "ATOMIC_PROXY_CHANGED_IMPLEMENTATION_STORAGE");

        vm.prank(ATTACKER);
        (bool replayAccepted, ) = address(proxy).call(
            abi.encodeWithSignature("initialize(address)", ATTACKER)
        );
        require(!replayAccepted, "ATOMIC_PROXY_ACCEPTED_REINITIALIZATION");
        require(state.initializedVersion() == 1, "ATOMIC_PROXY_VERSION_CHANGED");
        require(state.owner() == owner, "ATOMIC_PROXY_OWNER_CHANGED");

        vm.prank(ATTACKER);
        (bool directAccepted, ) = address(implementation).call(initializationCall);
        require(!directAccepted, "ATOMIC_PROXY_IMPLEMENTATION_INITIALIZED_DIRECTLY");
        require(implementation.initializedVersion() == type(uint8).max,
            "ATOMIC_PROXY_IMPLEMENTATION_LOCK_CHANGED");
    }

}
