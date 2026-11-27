// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vm} from "forge-std/Vm.sol";
import {LowkeyForgeStateDiffRecorder} from "../src/LowkeyForgeStateDiffRecorder.sol";
import {
    PairedBeacon,
    BeaconProxyFixture,
    BeaconLogicV1,
    BeaconLogicV2,
    CallerDependentBeacon,
    BeaconUpgradeActor,
    IBeaconProxyLogic
} from "../src/BeaconFixtures.sol";

contract BeaconControlsTest is LowkeyForgeStateDiffRecorder {
    bytes32 private constant BEACON_SLOT =
        0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    function test_paired_beacon_upgrade() external {
        PairedBeacon beacon = PairedBeacon(vm.envAddress("BEACON_ADDRESS"));
        BeaconProxyFixture proxyA = BeaconProxyFixture(payable(vm.envAddress("BEACON_PROXY_A")));
        BeaconProxyFixture proxyB = BeaconProxyFixture(payable(vm.envAddress("BEACON_PROXY_B")));
        BeaconUpgradeActor actor = BeaconUpgradeActor(vm.envAddress("BEACON_ACTOR"));
        address owner = vm.envAddress("BEACON_OWNER");
        address attacker = vm.envAddress("BEACON_ATTACKER");
        address implementationV1 = vm.envAddress("BEACON_IMPLEMENTATION_V1");
        address implementationV2 = vm.envAddress("BEACON_IMPLEMENTATION_V2");

        require(beacon.owner() == owner, "BEACON_OWNER_PRESTATE_MISMATCH");
        require(beacon.implementation() == implementationV1, "BEACON_IMPLEMENTATION_PRESTATE_MISMATCH");
        require(proxyA.beacon() == address(beacon) && proxyB.beacon() == address(beacon), "PROXIES_DO_NOT_SHARE_BEACON");
        require(IBeaconProxyLogic(address(proxyA)).version() == 1 && IBeaconProxyLogic(address(proxyB)).version() == 1, "PROXY_V1_ROUTE_MISMATCH");
        require(IBeaconProxyLogic(address(proxyA)).value() == 111 && IBeaconProxyLogic(address(proxyB)).value() == 222, "PROXY_STORAGE_PRESTATE_MISMATCH");
        require(actor.successfulCalls() == 0, "ACTOR_METRIC_PRESTATE_MISMATCH");

        bytes memory upgradeCall = abi.encodeWithSelector(PairedBeacon.upgradeTo.selector, implementationV2);
        uint256 baseline = vm.snapshot();

        // Secure control: the attacker executes the exact same beacon call,
        // but the owner-controlled authorization switch is enabled.
        vm.prank(owner);
        beacon.setSecureMode(1);
        require(beacon.secureMode() == 1, "SECURE_BEACON_MODE_MISMATCH");
        _lowkeyStartTrace(address(beacon));
        vm.recordLogs();
        vm.prank(attacker);
        bool controlSucceeded = actor.execute(address(beacon), upgradeCall);
        Vm.Log[] memory controlEvents = vm.getRecordedLogs();
        require(!controlSucceeded, "SECURE_BEACON_ACCEPTED_UNAUTHORIZED_UPGRADE");
        require(actor.successfulCalls() == 0, "SECURE_BEACON_METRIC_CHANGED");
        require(beacon.implementation() == implementationV1, "SECURE_BEACON_IMPLEMENTATION_CHANGED");
        require(IBeaconProxyLogic(address(proxyA)).version() == 1 && IBeaconProxyLogic(address(proxyB)).version() == 1, "SECURE_BEACON_CHANGED_PROXY_ROUTE");
        require(IBeaconProxyLogic(address(proxyA)).value() == 111 && IBeaconProxyLogic(address(proxyB)).value() == 222, "SECURE_BEACON_CHANGED_PROXY_STORAGE");
        require(controlEvents.length == 0, "SECURE_BEACON_EMITTED_UPGRADE_EVENT");
        _lowkeyWriteTrace(".audit/godmode/control-beacon-state-diff.json", controlEvents);

        require(vm.revertTo(baseline), "BEACON_BASELINE_REVERT_FAILED");

        // Vulnerable scenario: same beacon, proxies, actor, calldata and fork
        // snapshot; only the fixture's secureMode parameter changes.
        vm.prank(owner);
        beacon.setSecureMode(0);
        require(beacon.secureMode() == 0, "VULNERABLE_BEACON_MODE_MISMATCH");
        _lowkeyStartTrace(address(beacon));
        vm.recordLogs();
        vm.prank(attacker);
        bool attackSucceeded = actor.execute(address(beacon), upgradeCall);
        Vm.Log[] memory attackEvents = vm.getRecordedLogs();
        require(attackSucceeded, "VULNERABLE_BEACON_REJECTED_UNAUTHORIZED_UPGRADE");
        require(actor.successfulCalls() == 1, "VULNERABLE_BEACON_METRIC_MISSING");
        require(beacon.implementation() == implementationV2, "BEACON_IMPLEMENTATION_NOT_REPLACED");
        require(IBeaconProxyLogic(address(proxyA)).version() == 2 && IBeaconProxyLogic(address(proxyB)).version() == 2, "SHARED_BEACON_DID_NOT_UPDATE_BOTH_PROXIES");
        require(IBeaconProxyLogic(address(proxyA)).value() == 111 && IBeaconProxyLogic(address(proxyB)).value() == 222, "BEACON_UPGRADE_DID_NOT_PRESERVE_PROXY_STORAGE");
        require(attackEvents.length == 1, "BEACON_UPGRADED_EVENT_MISSING");
        require(attackEvents[0].emitter == address(beacon), "BEACON_EVENT_EMITTER_MISMATCH");
        require(
            attackEvents[0].topics.length == 2
                && attackEvents[0].topics[0] == keccak256("Upgraded(address)")
                && address(uint160(uint256(attackEvents[0].topics[1]))) == implementationV2,
            "BEACON_UPGRADED_EVENT_DATA_MISMATCH"
        );
        _lowkeyWriteTrace(".audit/godmode/attack-beacon-state-diff.json", attackEvents);

        // A beacon upgrade changes the implementation resolved by each proxy;
        // it does not change either proxy's EIP-1967 beacon slot.
        require(_slotAddress(address(proxyA), BEACON_SLOT) == address(beacon), "PROXY_A_BEACON_SLOT_CHANGED");
        require(_slotAddress(address(proxyB), BEACON_SLOT) == address(beacon), "PROXY_B_BEACON_SLOT_CHANGED");
    }

    function test_caller_dependent_beacon_returns_distinct_implementations() external {
        CallerDependentBeacon beacon = CallerDependentBeacon(
            vm.envAddress("CALLER_DEPENDENT_BEACON")
        );
        address implementationV1 = vm.envAddress("BEACON_IMPLEMENTATION_V1");
        address implementationV2 = vm.envAddress("BEACON_IMPLEMENTATION_V2");

        vm.prank(address(1));
        address first = beacon.implementation();
        vm.prank(address(2));
        address second = beacon.implementation();

        require(first == implementationV1, "CALLER_ONE_IMPLEMENTATION_MISMATCH");
        require(second == implementationV2, "CALLER_TWO_IMPLEMENTATION_MISMATCH");
        require(first != second, "CALLER_DEPENDENT_BEACON_NOT_DISTINCT");
        require(first.code.length > 0 && second.code.length > 0, "IMPLEMENTATION_CODE_MISSING");
    }

    function test_beacon_rejects_an_address_without_implementation_code() external {
        PairedBeacon beacon = PairedBeacon(vm.envAddress("BEACON_ADDRESS"));
        address attacker = vm.envAddress("BEACON_ATTACKER");
        vm.prank(attacker);
        (bool success,) = address(beacon).call(
            abi.encodeWithSelector(PairedBeacon.upgradeTo.selector, attacker)
        );
        require(!success, "BEACON_ACCEPTED_IMPLEMENTATION_WITHOUT_CODE");
    }

    function test_beacon_owner_can_perform_authorized_upgrade() external {
        PairedBeacon beacon = PairedBeacon(vm.envAddress("BEACON_ADDRESS"));
        BeaconProxyFixture proxyA = BeaconProxyFixture(payable(vm.envAddress("BEACON_PROXY_A")));
        BeaconProxyFixture proxyB = BeaconProxyFixture(payable(vm.envAddress("BEACON_PROXY_B")));
        address owner = vm.envAddress("BEACON_OWNER");
        address implementationV2 = vm.envAddress("BEACON_IMPLEMENTATION_V2");

        vm.prank(owner);
        beacon.setSecureMode(1);
        vm.prank(owner);
        beacon.upgradeTo(implementationV2);

        require(beacon.implementation() == implementationV2, "AUTHORIZED_BEACON_UPGRADE_FAILED");
        require(IBeaconProxyLogic(address(proxyA)).version() == 2 && IBeaconProxyLogic(address(proxyB)).version() == 2, "AUTHORIZED_SHARED_BEACON_UPGRADE_FAILED");
        require(IBeaconProxyLogic(address(proxyA)).value() == 111 && IBeaconProxyLogic(address(proxyB)).value() == 222, "AUTHORIZED_BEACON_UPGRADE_CORRUPTED_STORAGE");
    }

    function _slotAddress(address target, bytes32 slot) private view returns (address value) {
        bytes32 word = vm.load(target, slot);
        value = address(uint160(uint256(word)));
    }
}
