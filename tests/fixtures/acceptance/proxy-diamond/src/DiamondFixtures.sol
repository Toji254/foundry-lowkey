// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDiamondCut {
    enum FacetCutAction { Add, Replace, Remove }

    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }

    event DiamondCut(FacetCut[] diamondCut, address init, bytes initCalldata);

    function diamondCut(
        FacetCut[] calldata diamondCut_,
        address init,
        bytes calldata initCalldata
    ) external;
}

interface IDiamondLoupe {
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    function facets() external view returns (Facet[] memory);
    function facetFunctionSelectors(address facet) external view returns (bytes4[] memory);
    function facetAddresses() external view returns (address[] memory);
    function facetAddress(bytes4 selector) external view returns (address);
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

library LibDiamondStorage {
    bytes32 internal constant STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    struct Layout {
        address contractOwner; // slot 0 in the namespaced layout
        uint256 secureMode; // slot 1; zero deliberately models the vulnerable fixture
        mapping(bytes4 => address) selectorToFacet;
        mapping(address => bytes4[]) facetFunctionSelectors;
        address[] facetAddresses;
        mapping(address => uint256) facetAddressIndexPlusOne;
        bytes4[] allSelectors;
        mapping(bytes4 => uint256) selectorIndexPlusOne;
    }

    function layout() internal pure returns (Layout storage ds) {
        bytes32 position = STORAGE_POSITION;
        assembly { ds.slot := position }
    }

    function initialize(address initialOwner) internal {
        require(initialOwner != address(0), "ZERO_DIAMOND_OWNER");
        layout().contractOwner = initialOwner;
    }

    function addSelector(Layout storage ds, address facet, bytes4 selector) internal {
        require(facet != address(0) && facet.code.length > 0, "INVALID_ADD_FACET");
        require(selector != bytes4(0), "ZERO_SELECTOR");
        require(ds.selectorToFacet[selector] == address(0), "SELECTOR_ALREADY_EXISTS");
        _addFacetAddress(ds, facet);
        ds.selectorToFacet[selector] = facet;
        ds.facetFunctionSelectors[facet].push(selector);
        ds.allSelectors.push(selector);
        ds.selectorIndexPlusOne[selector] = ds.allSelectors.length;
    }

    function replaceSelector(Layout storage ds, address facet, bytes4 selector) internal {
        require(facet != address(0) && facet.code.length > 0, "INVALID_REPLACE_FACET");
        address oldFacet = ds.selectorToFacet[selector];
        require(oldFacet != address(0), "SELECTOR_DOES_NOT_EXIST");
        require(oldFacet != facet, "SELECTOR_ALREADY_ON_FACET");
        _removeFacetSelector(ds, oldFacet, selector);
        _addFacetAddress(ds, facet);
        ds.selectorToFacet[selector] = facet;
        ds.facetFunctionSelectors[facet].push(selector);
    }

    function removeSelector(Layout storage ds, bytes4 selector) internal {
        address oldFacet = ds.selectorToFacet[selector];
        require(oldFacet != address(0), "SELECTOR_DOES_NOT_EXIST");
        delete ds.selectorToFacet[selector];
        _removeFacetSelector(ds, oldFacet, selector);

        uint256 indexPlusOne = ds.selectorIndexPlusOne[selector];
        if (indexPlusOne != 0) {
            uint256 index = indexPlusOne - 1;
            uint256 lastIndex = ds.allSelectors.length - 1;
            if (index != lastIndex) {
                bytes4 moved = ds.allSelectors[lastIndex];
                ds.allSelectors[index] = moved;
                ds.selectorIndexPlusOne[moved] = index + 1;
            }
            ds.allSelectors.pop();
            delete ds.selectorIndexPlusOne[selector];
        }
    }

    function _addFacetAddress(Layout storage ds, address facet) private {
        if (ds.facetAddressIndexPlusOne[facet] == 0) {
            ds.facetAddresses.push(facet);
            ds.facetAddressIndexPlusOne[facet] = ds.facetAddresses.length;
        }
    }

    function _removeFacetSelector(Layout storage ds, address facet, bytes4 selector) private {
        bytes4[] storage selectors = ds.facetFunctionSelectors[facet];
        for (uint256 i; i < selectors.length; ++i) {
            if (selectors[i] == selector) {
                uint256 lastIndex = selectors.length - 1;
                if (i != lastIndex) selectors[i] = selectors[lastIndex];
                selectors.pop();
                break;
            }
        }
        if (selectors.length == 0) _removeFacetAddress(ds, facet);
    }

    function _removeFacetAddress(Layout storage ds, address facet) private {
        uint256 indexPlusOne = ds.facetAddressIndexPlusOne[facet];
        if (indexPlusOne == 0) return;
        uint256 index = indexPlusOne - 1;
        uint256 lastIndex = ds.facetAddresses.length - 1;
        if (index != lastIndex) {
            address moved = ds.facetAddresses[lastIndex];
            ds.facetAddresses[index] = moved;
            ds.facetAddressIndexPlusOne[moved] = index + 1;
        }
        ds.facetAddresses.pop();
        delete ds.facetAddressIndexPlusOne[facet];
    }
}

library LibDiamondAppStorageV1 {
    bytes32 internal constant STORAGE_POSITION = keccak256("lowkey.diamond.app.storage.v1");

    struct Layout {
        uint256 value;
    }

    function layout() internal pure returns (Layout storage ds) {
        bytes32 position = STORAGE_POSITION;
        assembly { ds.slot := position }
    }
}

library LibDiamondAppStorageV2 {
    bytes32 internal constant STORAGE_POSITION = keccak256("lowkey.diamond.app.storage.v2");

    struct Layout {
        uint256 value;
    }

    function layout() internal pure returns (Layout storage ds) {
        bytes32 position = STORAGE_POSITION;
        assembly { ds.slot := position }
    }
}

library LibDiamondBadAppStorage {
    // Deliberately incompatible namespace for the negative storage-layout fixture.
    bytes32 internal constant STORAGE_POSITION = keccak256("lowkey.diamond.app.storage.incompatible");

    struct Layout {
        uint256 value;
    }

    function layout() internal pure returns (Layout storage ds) {
        bytes32 position = STORAGE_POSITION;
        assembly { ds.slot := position }
    }
}

contract DiamondCutFacet is IDiamondCut {
    function owner() external view returns (address) {
        return LibDiamondStorage.layout().contractOwner;
    }

    function setSecureMode(uint256 enabled) external {
        LibDiamondStorage.Layout storage ds = LibDiamondStorage.layout();
        require(msg.sender == ds.contractOwner, "ONLY_DIAMOND_OWNER");
        require(enabled <= 1, "INVALID_SECURE_MODE");
        ds.secureMode = enabled;
    }

    function diamondCut(FacetCut[] calldata diamondCut_, address init, bytes calldata initCalldata) external {
        LibDiamondStorage.Layout storage ds = LibDiamondStorage.layout();

        // Non-short-circuit arithmetic deliberately reads both authorization
        // inputs in every scenario, allowing the control gate to compare owner
        // and mode prestate independently. Mode zero remains intentionally open.
        uint256 authorization = (ds.secureMode == 0 ? 1 : 0)
            + (msg.sender == ds.contractOwner ? 1 : 0);
        require(authorization > 0, "ONLY_DIAMOND_OWNER");

        for (uint256 i; i < diamondCut_.length; ++i) {
            FacetCut calldata cut = diamondCut_[i];
            if (cut.action == FacetCutAction.Add) {
                for (uint256 j; j < cut.functionSelectors.length; ++j) {
                    LibDiamondStorage.addSelector(ds, cut.facetAddress, cut.functionSelectors[j]);
                }
            } else if (cut.action == FacetCutAction.Replace) {
                for (uint256 j; j < cut.functionSelectors.length; ++j) {
                    LibDiamondStorage.replaceSelector(ds, cut.facetAddress, cut.functionSelectors[j]);
                }
            } else if (cut.action == FacetCutAction.Remove) {
                require(cut.facetAddress == address(0), "REMOVE_FACET_MUST_BE_ZERO");
                for (uint256 j; j < cut.functionSelectors.length; ++j) {
                    LibDiamondStorage.removeSelector(ds, cut.functionSelectors[j]);
                }
            } else {
                revert("INVALID_DIAMOND_CUT_ACTION");
            }
        }

        if (init != address(0)) {
            require(init.code.length > 0, "INIT_HAS_NO_CODE");
            (bool success, bytes memory result) = init.delegatecall(initCalldata);
            if (!success) {
                assembly { revert(add(result, 32), mload(result)) }
            }
        } else {
            require(initCalldata.length == 0, "INIT_DATA_WITHOUT_TARGET");
        }

        emit DiamondCut(diamondCut_, init, initCalldata);
    }
}

contract DiamondLoupeFacet is IDiamondLoupe {
    function facets() external view returns (Facet[] memory result) {
        LibDiamondStorage.Layout storage ds = LibDiamondStorage.layout();
        result = new Facet[](ds.facetAddresses.length);
        for (uint256 i; i < ds.facetAddresses.length; ++i) {
            address facet = ds.facetAddresses[i];
            result[i] = Facet(facet, ds.facetFunctionSelectors[facet]);
        }
    }

    function facetFunctionSelectors(address facet) external view returns (bytes4[] memory) {
        return LibDiamondStorage.layout().facetFunctionSelectors[facet];
    }

    function facetAddresses() external view returns (address[] memory) {
        return LibDiamondStorage.layout().facetAddresses;
    }

    function facetAddress(bytes4 selector) external view returns (address) {
        return LibDiamondStorage.layout().selectorToFacet[selector];
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 || interfaceId == 0x48e2b093 || interfaceId == 0x1f931c1c;
    }
}

contract DiamondAppFacetV1 {
    function setValue(uint256 nextValue) external {
        LibDiamondAppStorageV1.layout().value = nextValue;
    }

    function value() external view returns (uint256) {
        return LibDiamondAppStorageV1.layout().value;
    }

    function version() external pure returns (uint256) {
        return 1;
    }

    function ping() external pure returns (bytes32) {
        return keccak256("LOWKEY_DIAMOND_PING");
    }

    function storageSchema() external pure returns (bytes32) {
        return keccak256("lowkey.diamond.app.storage.v1");
    }
}

contract DiamondAppFacetV2 {
    // V2 intentionally retains the V1 namespace and slot layout.
    function setValue(uint256 nextValue) external {
        LibDiamondAppStorageV1.layout().value = nextValue;
    }

    function value() external view returns (uint256) {
        return LibDiamondAppStorageV1.layout().value;
    }

    function version() external pure returns (uint256) {
        return 2;
    }

    function ping() external pure returns (bytes32) {
        return keccak256("LOWKEY_DIAMOND_PING");
    }

    function newFeature() external pure returns (bytes32) {
        return keccak256("LOWKEY_DIAMOND_V2_FEATURE");
    }

    function storageSchema() external pure returns (bytes32) {
        return keccak256("lowkey.diamond.app.storage.v1");
    }
}

contract DiamondAppFacetV3 {
    // V3 reads the new namespace populated by DiamondMigrationInitV2.
    function setValue(uint256 nextValue) external {
        LibDiamondAppStorageV2.layout().value = nextValue;
    }

    function value() external view returns (uint256) {
        return LibDiamondAppStorageV2.layout().value;
    }

    function version() external pure returns (uint256) {
        return 3;
    }

    function storageSchema() external pure returns (bytes32) {
        return keccak256("lowkey.diamond.app.storage.v2");
    }
}

contract DiamondAppFacetCorrupt {
    // This facet compiles but reads a different namespace from the existing V1 data.
    function setValue(uint256 nextValue) external {
        LibDiamondBadAppStorage.layout().value = nextValue;
    }

    function value() external view returns (uint256) {
        return LibDiamondBadAppStorage.layout().value;
    }
}

contract DiamondInitTakeover {
    function initialize(address nextOwner) external {
        require(nextOwner != address(0), "ZERO_NEW_OWNER");
        LibDiamondStorage.layout().contractOwner = nextOwner;
    }
}

contract DiamondMigrationInitV2 {
    function migrate() external {
        uint256 previousValue = LibDiamondAppStorageV1.layout().value;
        LibDiamondAppStorageV2.layout().value = previousValue;
    }
}

contract DiamondUpgradeActor {
    uint256 public successfulCalls;
    uint256 public attempts;

    function execute(address target, bytes calldata data) external returns (bool success) {
        attempts += 1;
        (success,) = target.call(data);
        successfulCalls = successfulCalls + (success ? 1 : 0);
    }
}

contract DiamondProxy {
    constructor(address initialOwner, address cutFacet, address loupeFacet, address applicationFacet) {
        require(cutFacet.code.length > 0, "CUT_FACET_HAS_NO_CODE");
        require(loupeFacet.code.length > 0, "LOUPE_FACET_HAS_NO_CODE");
        require(applicationFacet.code.length > 0, "APP_FACET_HAS_NO_CODE");
        LibDiamondStorage.initialize(initialOwner);

        bytes4[] memory cutSelectors = new bytes4[](3);
        cutSelectors[0] = IDiamondCut.diamondCut.selector;
        cutSelectors[1] = bytes4(keccak256("setSecureMode(uint256)"));
        cutSelectors[2] = bytes4(keccak256("owner()"));
        _install(cutFacet, cutSelectors);

        bytes4[] memory loupeSelectors = new bytes4[](5);
        loupeSelectors[0] = IDiamondLoupe.facets.selector;
        loupeSelectors[1] = IDiamondLoupe.facetFunctionSelectors.selector;
        loupeSelectors[2] = IDiamondLoupe.facetAddresses.selector;
        loupeSelectors[3] = IDiamondLoupe.facetAddress.selector;
        loupeSelectors[4] = IDiamondLoupe.supportsInterface.selector;
        _install(loupeFacet, loupeSelectors);

        bytes4[] memory appSelectors = new bytes4[](5);
        appSelectors[0] = bytes4(keccak256("setValue(uint256)"));
        appSelectors[1] = bytes4(keccak256("value()"));
        appSelectors[2] = bytes4(keccak256("version()"));
        appSelectors[3] = bytes4(keccak256("ping()"));
        appSelectors[4] = bytes4(keccak256("storageSchema()"));
        _install(applicationFacet, appSelectors);
    }

    function _install(address facet, bytes4[] memory selectors) private {
        LibDiamondStorage.Layout storage ds = LibDiamondStorage.layout();
        for (uint256 i; i < selectors.length; ++i) {
            LibDiamondStorage.addSelector(ds, facet, selectors[i]);
        }
    }

    fallback() external payable {
        _delegate();
    }

    receive() external payable {
        _delegate();
    }

    function _delegate() private {
        address facet = LibDiamondStorage.layout().selectorToFacet[msg.sig];
        require(facet != address(0), "FUNCTION_NOT_FOUND");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
