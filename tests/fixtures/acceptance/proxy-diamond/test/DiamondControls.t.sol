// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vm} from "forge-std/Vm.sol";
import {LowkeyForgeStateDiffRecorder} from "../src/LowkeyForgeStateDiffRecorder.sol";
import {
    IDiamondCut,
    IDiamondLoupe,
    DiamondCutFacet,
    DiamondProxy,
    DiamondAppFacetV2,
    DiamondAppFacetV3,
    DiamondAppFacetCorrupt,
    DiamondInitTakeover,
    DiamondMigrationInitV2,
    DiamondUpgradeActor
} from "../src/DiamondFixtures.sol";

interface IDiamondAppView {
    function setValue(uint256 nextValue) external;
    function value() external view returns (uint256);
    function version() external view returns (uint256);
    function ping() external view returns (bytes32);
    function newFeature() external view returns (bytes32);
    function storageSchema() external view returns (bytes32);
}

contract DiamondControlsTest is LowkeyForgeStateDiffRecorder {
    bytes32 private constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");
    bytes32 private constant APP_V1_STORAGE_POSITION = keccak256("lowkey.diamond.app.storage.v1");
    bytes32 private constant APP_V2_STORAGE_POSITION = keccak256("lowkey.diamond.app.storage.v2");
    bytes4 private constant CUT_SELECTOR = bytes4(keccak256("diamondCut((address,uint8,bytes4[])[],address,bytes)"));
    bytes4 private constant VERSION_SELECTOR = bytes4(keccak256("version()"));
    bytes4 private constant VALUE_SELECTOR = bytes4(keccak256("value()"));
    bytes4 private constant PING_SELECTOR = bytes4(keccak256("ping()"));
    bytes4 private constant NEW_FEATURE_SELECTOR = bytes4(keccak256("newFeature()"));
    bytes32 private constant CUT_EVENT = keccak256("DiamondCut((address,uint8,bytes4[])[],address,bytes)");

    function test_paired_diamond_cut() external {
        DiamondProxy diamond = DiamondProxy(payable(vm.envAddress("DIAMOND_ADDRESS")));
        DiamondUpgradeActor actor = DiamondUpgradeActor(vm.envAddress("DIAMOND_ACTOR"));
        address owner = vm.envAddress("DIAMOND_OWNER");
        address attacker = vm.envAddress("DIAMOND_ATTACKER");
        address facetV1 = vm.envAddress("DIAMOND_FACET_V1");
        address facetV2 = vm.envAddress("DIAMOND_FACET_V2");
        IDiamondLoupe loupe = IDiamondLoupe(address(diamond));
        IDiamondAppView app = IDiamondAppView(address(diamond));

        require(DiamondCutFacet(address(diamond)).owner() == owner, "DIAMOND_OWNER_PRESTATE_MISMATCH");
        require(loupe.facetAddress(VERSION_SELECTOR) == facetV1, "DIAMOND_V1_ROUTE_PRESTATE_MISMATCH");
        require(app.version() == 1 && app.value() == 4242, "DIAMOND_APP_PRESTATE_MISMATCH");
        require(app.storageSchema() == keccak256("lowkey.diamond.app.storage.v1"), "DIAMOND_SCHEMA_PRESTATE_MISMATCH");
        require(actor.successfulCalls() == 0, "DIAMOND_ACTOR_METRIC_PRESTATE_MISMATCH");

        IDiamondCut.FacetCut[] memory cuts = _replace(facetV2, VERSION_SELECTOR);
        bytes memory cutCall = abi.encodeWithSelector(IDiamondCut.diamondCut.selector, cuts, address(0), bytes(""));
        uint256 baseline = vm.snapshot();

        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(1);
        _lowkeyStartTrace(address(diamond));
        vm.recordLogs();
        vm.prank(attacker);
        bool controlSucceeded = actor.execute(address(diamond), cutCall);
        Vm.Log[] memory controlEvents = vm.getRecordedLogs();

        require(!controlSucceeded, "SECURE_DIAMOND_ACCEPTED_UNAUTHORIZED_CUT");
        require(actor.successfulCalls() == 0, "SECURE_DIAMOND_METRIC_CHANGED");
        require(loupe.facetAddress(VERSION_SELECTOR) == facetV1, "SECURE_DIAMOND_SELECTOR_MAP_CHANGED");
        require(app.version() == 1 && app.value() == 4242, "SECURE_DIAMOND_APP_STATE_CHANGED");
        require(app.ping() == keccak256("LOWKEY_DIAMOND_PING"), "SECURE_DIAMOND_UNRELATED_FUNCTION_CHANGED");
        require(controlEvents.length == 0, "SECURE_DIAMOND_EMITTED_CUT_EVENT");
        _lowkeyWriteTrace(".audit/godmode/control-diamond-cut-state-diff.json", controlEvents);
        require(vm.revertTo(baseline), "DIAMOND_CUT_BASELINE_REVERT_FAILED");

        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(0);
        _lowkeyStartTrace(address(diamond));
        vm.recordLogs();
        vm.prank(attacker);
        bool attackSucceeded = actor.execute(address(diamond), cutCall);
        Vm.Log[] memory attackEvents = vm.getRecordedLogs();

        require(attackSucceeded, "VULNERABLE_DIAMOND_REJECTED_UNAUTHORIZED_CUT");
        require(actor.successfulCalls() == 1, "VULNERABLE_DIAMOND_METRIC_MISSING");
        require(loupe.facetAddress(VERSION_SELECTOR) == facetV2, "DIAMOND_SELECTOR_NOT_REPLACED");
        require(app.version() == 2 && app.value() == 4242, "COMPATIBLE_FACET_REPLACEMENT_FAILED");
        require(app.storageSchema() == keccak256("lowkey.diamond.app.storage.v1"), "COMPATIBLE_FACET_SCHEMA_CHANGED");
        require(app.ping() == keccak256("LOWKEY_DIAMOND_PING"), "VULNERABLE_DIAMOND_BROKE_UNRELATED_FUNCTION");
        require(attackEvents.length == 1, "DIAMOND_CUT_EVENT_MISSING");
        require(attackEvents[0].emitter == address(diamond), "DIAMOND_CUT_EVENT_EMITTER_MISMATCH");
        require(attackEvents[0].topics.length == 1 && attackEvents[0].topics[0] == CUT_EVENT, "DIAMOND_CUT_EVENT_SIGNATURE_MISMATCH");
        _lowkeyWriteTrace(".audit/godmode/attack-diamond-cut-state-diff.json", attackEvents);
    }

    function test_paired_diamond_remove_selector() external {
        DiamondProxy diamond = DiamondProxy(payable(vm.envAddress("DIAMOND_ADDRESS")));
        DiamondUpgradeActor actor = DiamondUpgradeActor(vm.envAddress("DIAMOND_ACTOR"));
        address owner = vm.envAddress("DIAMOND_OWNER");
        address attacker = vm.envAddress("DIAMOND_ATTACKER");
        address facetV1 = vm.envAddress("DIAMOND_FACET_V1");
        IDiamondLoupe loupe = IDiamondLoupe(address(diamond));
        IDiamondAppView app = IDiamondAppView(address(diamond));

        require(loupe.facetAddress(VERSION_SELECTOR) == facetV1, "DIAMOND_REMOVE_PRESTATE_MISMATCH");
        IDiamondCut.FacetCut[] memory cuts = _remove(VERSION_SELECTOR);
        bytes memory removeCall = abi.encodeWithSelector(IDiamondCut.diamondCut.selector, cuts, address(0), bytes(""));
        uint256 baseline = vm.snapshot();

        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(1);
        _lowkeyStartTrace(address(diamond));
        vm.recordLogs();
        vm.prank(attacker);
        bool controlSucceeded = actor.execute(address(diamond), removeCall);
        Vm.Log[] memory controlEvents = vm.getRecordedLogs();
        require(!controlSucceeded, "SECURE_DIAMOND_ALLOWED_UNAUTHORIZED_SELECTOR_REMOVAL");
        require(loupe.facetAddress(VERSION_SELECTOR) == facetV1, "SECURE_DIAMOND_SELECTOR_WAS_REMOVED");
        require(app.value() == 4242 && app.ping() == keccak256("LOWKEY_DIAMOND_PING"), "SECURE_DIAMOND_REMOVAL_CHANGED_OTHER_FUNCTIONS");
        require(controlEvents.length == 0, "SECURE_DIAMOND_REMOVAL_EMITTED_EVENT");
        _lowkeyWriteTrace(".audit/godmode/control-diamond-remove-state-diff.json", controlEvents);
        require(vm.revertTo(baseline), "DIAMOND_REMOVE_BASELINE_REVERT_FAILED");

        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(0);
        _lowkeyStartTrace(address(diamond));
        vm.recordLogs();
        vm.prank(attacker);
        bool attackSucceeded = actor.execute(address(diamond), removeCall);
        Vm.Log[] memory attackEvents = vm.getRecordedLogs();
        require(attackSucceeded, "VULNERABLE_DIAMOND_BLOCKED_UNAUTHORIZED_SELECTOR_REMOVAL");
        require(loupe.facetAddress(VERSION_SELECTOR) == address(0), "VULNERABLE_DIAMOND_SELECTOR_NOT_REMOVED");
        require(app.value() == 4242 && app.ping() == keccak256("LOWKEY_DIAMOND_PING"), "SELECTOR_REMOVAL_BROKE_UNRELATED_FUNCTIONS");
        require(attackEvents.length == 1 && attackEvents[0].emitter == address(diamond), "DIAMOND_REMOVE_EVENT_MISSING");
        require(attackEvents[0].topics.length == 1 && attackEvents[0].topics[0] == CUT_EVENT, "DIAMOND_REMOVE_EVENT_SIGNATURE_MISMATCH");
        _lowkeyWriteTrace(".audit/godmode/attack-diamond-remove-state-diff.json", attackEvents);
    }

    function test_paired_diamond_initializer_takeover() external {
        DiamondProxy diamond = DiamondProxy(payable(vm.envAddress("DIAMOND_ADDRESS")));
        DiamondUpgradeActor actor = DiamondUpgradeActor(vm.envAddress("DIAMOND_ACTOR"));
        address owner = vm.envAddress("DIAMOND_OWNER");
        address attacker = vm.envAddress("DIAMOND_ATTACKER");
        address init = vm.envAddress("DIAMOND_INIT");
        IDiamondCut.FacetCut[] memory emptyCuts = new IDiamondCut.FacetCut[](0);
        bytes memory initData = abi.encodeWithSelector(DiamondInitTakeover.initialize.selector, attacker);
        bytes memory takeoverCall = abi.encodeWithSelector(
            IDiamondCut.diamondCut.selector, emptyCuts, init, initData
        );
        require(DiamondCutFacet(address(diamond)).owner() == owner, "DIAMOND_INIT_OWNER_PRESTATE_MISMATCH");
        uint256 baseline = vm.snapshot();

        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(1);
        _lowkeyStartTrace(address(diamond));
        vm.recordLogs();
        vm.prank(attacker);
        bool controlSucceeded = actor.execute(address(diamond), takeoverCall);
        Vm.Log[] memory controlEvents = vm.getRecordedLogs();
        require(!controlSucceeded, "SECURE_DIAMOND_ALLOWED_MALICIOUS_INITIALIZER");
        require(DiamondCutFacet(address(diamond)).owner() == owner, "SECURE_DIAMOND_OWNER_CHANGED");
        require(controlEvents.length == 0, "SECURE_DIAMOND_INIT_EMITTED_CUT_EVENT");
        _lowkeyWriteTrace(".audit/godmode/control-diamond-init-state-diff.json", controlEvents);
        require(vm.revertTo(baseline), "DIAMOND_INIT_BASELINE_REVERT_FAILED");

        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(0);
        _lowkeyStartTrace(address(diamond));
        vm.recordLogs();
        vm.prank(attacker);
        bool attackSucceeded = actor.execute(address(diamond), takeoverCall);
        Vm.Log[] memory attackEvents = vm.getRecordedLogs();
        require(attackSucceeded, "VULNERABLE_DIAMOND_BLOCKED_MALICIOUS_INITIALIZER");
        require(DiamondCutFacet(address(diamond)).owner() == attacker, "MALICIOUS_INITIALIZER_DID_NOT_CHANGE_OWNER");
        require(attackEvents.length == 1 && attackEvents[0].emitter == address(diamond), "DIAMOND_INIT_EVENT_MISSING");
        _lowkeyWriteTrace(".audit/godmode/attack-diamond-init-state-diff.json", attackEvents);
    }

    function test_owner_can_execute_authorized_facet_replacement() external {
        DiamondProxy diamond = DiamondProxy(payable(vm.envAddress("DIAMOND_ADDRESS")));
        address owner = vm.envAddress("DIAMOND_OWNER");
        address facetV2 = vm.envAddress("DIAMOND_FACET_V2");
        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(1);
        vm.prank(owner);
        DiamondCutFacet(address(diamond)).diamondCut(_replace(facetV2, VERSION_SELECTOR), address(0), bytes(""));
        require(IDiamondLoupe(address(diamond)).facetAddress(VERSION_SELECTOR) == facetV2, "AUTHORIZED_DIAMOND_CUT_FAILED");
        require(IDiamondAppView(address(diamond)).version() == 2, "AUTHORIZED_FACET_NOT_ACTIVE");
        require(IDiamondAppView(address(diamond)).value() == 4242, "AUTHORIZED_UPGRADE_CORRUPTED_STORAGE");
    }

    function test_selector_add_collision_remove_and_unrelated_functionality() external {
        DiamondProxy diamond = DiamondProxy(payable(vm.envAddress("DIAMOND_ADDRESS")));
        address owner = vm.envAddress("DIAMOND_OWNER");
        address facetV2 = vm.envAddress("DIAMOND_FACET_V2");
        IDiamondLoupe loupe = IDiamondLoupe(address(diamond));
        IDiamondAppView app = IDiamondAppView(address(diamond));
        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(1);

        vm.prank(owner);
        (bool collision,) = address(diamond).call(
            abi.encodeWithSelector(
                IDiamondCut.diamondCut.selector,
                _add(facetV2, VERSION_SELECTOR),
                address(0),
                bytes("")
            )
        );
        require(!collision, "DIAMOND_ACCEPTED_SELECTOR_COLLISION");
        require(loupe.facetAddress(VERSION_SELECTOR) != address(0), "COLLISION_REMOVED_EXISTING_SELECTOR");

        vm.prank(owner);
        DiamondCutFacet(address(diamond)).diamondCut(_add(facetV2, NEW_FEATURE_SELECTOR), address(0), bytes(""));
        require(loupe.facetAddress(NEW_FEATURE_SELECTOR) == facetV2, "DIAMOND_ADD_SELECTOR_FAILED");
        require(app.newFeature() == keccak256("LOWKEY_DIAMOND_V2_FEATURE"), "DIAMOND_ADDED_FACET_NOT_CALLABLE");

        vm.prank(owner);
        DiamondCutFacet(address(diamond)).diamondCut(_remove(NEW_FEATURE_SELECTOR), address(0), bytes(""));
        require(loupe.facetAddress(NEW_FEATURE_SELECTOR) == address(0), "DIAMOND_SELECTOR_REMOVE_FAILED");
        (bool stillCallable,) = address(diamond).staticcall(abi.encodeWithSelector(NEW_FEATURE_SELECTOR));
        require(!stillCallable, "REMOVED_DIAMOND_SELECTOR_STILL_CALLABLE");
        require(app.value() == 4242 && app.ping() == keccak256("LOWKEY_DIAMOND_PING"), "DIAMOND_ADD_REMOVE_BROKE_UNRELATED_FUNCTIONS");

        vm.prank(owner);
        (bool invalidFacet,) = address(diamond).call(
            abi.encodeWithSelector(
                IDiamondCut.diamondCut.selector,
                _add(address(0x1234), bytes4(keccak256("invalidFacetCall()"))),
                address(0),
                bytes("")
            )
        );
        require(!invalidFacet, "DIAMOND_ACCEPTED_FACET_WITHOUT_CODE");
    }

    function test_storage_migration_initializer_preserves_application_value() external {
        DiamondProxy diamond = DiamondProxy(payable(vm.envAddress("DIAMOND_ADDRESS")));
        address owner = vm.envAddress("DIAMOND_OWNER");
        address facetV3 = vm.envAddress("DIAMOND_FACET_V3");
        address migrationInit = vm.envAddress("DIAMOND_MIGRATION_INIT");
        IDiamondAppView app = IDiamondAppView(address(diamond));

        require(app.value() == 4242 && app.version() == 1, "DIAMOND_MIGRATION_PRESTATE_MISMATCH");
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](3);
        cuts[0] = _replaceOne(facetV3, VALUE_SELECTOR);
        cuts[1] = _replaceOne(facetV3, VERSION_SELECTOR);
        cuts[2] = _replaceOne(facetV3, bytes4(keccak256("setValue(uint256)")));
        bytes memory migrationData = abi.encodeWithSelector(DiamondMigrationInitV2.migrate.selector);

        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(1);
        vm.prank(owner);
        DiamondCutFacet(address(diamond)).diamondCut(cuts, migrationInit, migrationData);

        require(app.version() == 3, "DIAMOND_MIGRATION_V3_NOT_ACTIVE");
        require(app.value() == 4242, "DIAMOND_MIGRATION_DID_NOT_PRESERVE_VALUE");
        require(app.ping() == keccak256("LOWKEY_DIAMOND_PING"), "DIAMOND_MIGRATION_BROKE_UNRELATED_FACET");
        require(vm.load(address(diamond), APP_V1_STORAGE_POSITION) == bytes32(uint256(4242)), "DIAMOND_OLD_STORAGE_WAS_NOT_PRESERVED");
        require(vm.load(address(diamond), APP_V2_STORAGE_POSITION) == bytes32(uint256(4242)), "DIAMOND_NEW_STORAGE_WAS_NOT_MIGRATED");
    }

    function test_incompatible_facet_storage_layout_is_detectable() external {
        DiamondProxy diamond = DiamondProxy(payable(vm.envAddress("DIAMOND_ADDRESS")));
        address owner = vm.envAddress("DIAMOND_OWNER");
        address corruptFacet = vm.envAddress("DIAMOND_CORRUPT_FACET");
        IDiamondAppView app = IDiamondAppView(address(diamond));

        require(app.value() == 4242, "DIAMOND_STORAGE_LAYOUT_PRESTATE_MISMATCH");
        vm.prank(owner);
        DiamondCutFacet(address(diamond)).setSecureMode(1);
        vm.prank(owner);
        DiamondCutFacet(address(diamond)).diamondCut(_replace(corruptFacet, VALUE_SELECTOR), address(0), bytes(""));
        require(app.value() == 0, "INCOMPATIBLE_FACET_DID_NOT_EXPOSE_STORAGE_MISMATCH");
        require(vm.load(address(diamond), APP_V1_STORAGE_POSITION) == bytes32(uint256(4242)), "INCOMPATIBLE_FACET_OVERWROTE_ORIGINAL_STORAGE");
        require(app.ping() == keccak256("LOWKEY_DIAMOND_PING"), "INCOMPATIBLE_FACET_BROKE_UNRELATED_FUNCTION");
    }

    function test_loupe_reports_facet_selector_relationships() external view {
        DiamondProxy diamond = DiamondProxy(payable(vm.envAddress("DIAMOND_ADDRESS")));
        IDiamondLoupe loupe = IDiamondLoupe(address(diamond));
        IDiamondLoupe.Facet[] memory allFacets = loupe.facets();
        address[] memory addresses = loupe.facetAddresses();
        require(allFacets.length == 3 && addresses.length == 3, "DIAMOND_LOUPE_FACET_COUNT_MISMATCH");
        require(loupe.facetAddress(CUT_SELECTOR) == vm.envAddress("DIAMOND_CUT_FACET"), "DIAMOND_LOUPE_CUT_ROUTE_MISMATCH");
        require(loupe.facetAddress(VERSION_SELECTOR) == vm.envAddress("DIAMOND_FACET_V1"), "DIAMOND_LOUPE_VERSION_ROUTE_MISMATCH");
        require(loupe.facetAddress(VALUE_SELECTOR) == vm.envAddress("DIAMOND_FACET_V1"), "DIAMOND_LOUPE_VALUE_ROUTE_MISMATCH");
        require(loupe.facetAddress(PING_SELECTOR) == vm.envAddress("DIAMOND_FACET_V1"), "DIAMOND_LOUPE_PING_ROUTE_MISMATCH");
        require(loupe.supportsInterface(0x48e2b093), "DIAMOND_LOUPE_INTERFACE_ID_MISSING");
        require(loupe.facetFunctionSelectors(vm.envAddress("DIAMOND_FACET_V1")).length == 5, "DIAMOND_LOUPE_SELECTOR_LIST_MISMATCH");
    }

    function _replace(address facet, bytes4 selector) private pure returns (IDiamondCut.FacetCut[] memory cuts) {
        cuts = new IDiamondCut.FacetCut[](1);
        cuts[0] = _replaceOne(facet, selector);
    }

    function _replaceOne(address facet, bytes4 selector) private pure returns (IDiamondCut.FacetCut memory cut) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = selector;
        cut = IDiamondCut.FacetCut(facet, IDiamondCut.FacetCutAction.Replace, selectors);
    }

    function _add(address facet, bytes4 selector) private pure returns (IDiamondCut.FacetCut[] memory cuts) {
        cuts = new IDiamondCut.FacetCut[](1);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = selector;
        cuts[0] = IDiamondCut.FacetCut(facet, IDiamondCut.FacetCutAction.Add, selectors);
    }

    function _remove(bytes4 selector) private pure returns (IDiamondCut.FacetCut[] memory cuts) {
        cuts = new IDiamondCut.FacetCut[](1);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = selector;
        cuts[0] = IDiamondCut.FacetCut(address(0), IDiamondCut.FacetCutAction.Remove, selectors);
    }
}
