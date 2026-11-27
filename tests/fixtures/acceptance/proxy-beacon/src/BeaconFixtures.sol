// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBeaconImplementation {
    function implementation() external view returns (address);
}

interface IBeaconProxyLogic {
    function value() external view returns (uint256);
    function version() external view returns (uint256);
}

contract BeaconLogicV1 {
    uint256 public value;

    function setValue(uint256 nextValue) external {
        value = nextValue;
    }

    function version() external pure returns (uint256) {
        return 1;
    }
}

contract BeaconLogicV2 {
    // This slot intentionally matches BeaconLogicV1 so proxy state is preserved.
    uint256 public value;

    function setValue(uint256 nextValue) external {
        value = nextValue;
    }

    function version() external pure returns (uint256) {
        return 2;
    }
}

contract PairedBeacon {
    // Deliberately simple local fixture with a runtime-toggleable authorization
    // control. The only scenario difference is secureMode (slot 2).
    address public implementation; // slot 0
    address public owner; // slot 1
    uint256 public secureMode; // slot 2; kept in its own slot for exact manifests

    event Upgraded(address indexed implementation);

    constructor(address initialImplementation, address initialOwner) {
        require(initialImplementation.code.length > 0, "NO_IMPLEMENTATION_CODE");
        require(initialOwner != address(0), "ZERO_OWNER");
        implementation = initialImplementation;
        owner = initialOwner;
        emit Upgraded(initialImplementation);
    }

    function setSecureMode(uint256 enabled) external {
        require(msg.sender == owner, "ONLY_OWNER");
        require(enabled <= 1, "INVALID_MODE");
        secureMode = enabled;
    }

    function upgradeTo(address nextImplementation) external {
        // Evaluate both inputs on every branch so the initial owner slot is
        // independently observable in the secure and vulnerable traces.
        // secureMode == 0 deliberately disables the check; secureMode == 1
        // still requires the original owner.
        uint256 authorization = (secureMode == 0 ? 1 : 0)
            + (msg.sender == owner ? 1 : 0);
        require(authorization > 0, "ONLY_OWNER");
        require(nextImplementation.code.length > 0, "NO_IMPLEMENTATION_CODE");
        implementation = nextImplementation;
        emit Upgraded(nextImplementation);
    }
}

contract BeaconProxyFixture {
    bytes32 internal constant BEACON_SLOT =
        0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    constructor(address beacon_) {
        require(beacon_.code.length > 0, "NO_BEACON_CODE");
        (bool ok, bytes memory result) = beacon_.staticcall(
            abi.encodeWithSelector(IBeaconImplementation.implementation.selector)
        );
        require(ok && result.length == 32, "INVALID_BEACON");
        address implementation_ = abi.decode(result, (address));
        require(implementation_.code.length > 0, "NO_IMPLEMENTATION_CODE");
        bytes32 slot = BEACON_SLOT;
        assembly {
            sstore(slot, beacon_)
        }
    }

    function beacon() external view returns (address value) {
        bytes32 slot = BEACON_SLOT;
        assembly {
            value := sload(slot)
        }
    }

    function _implementation() private view returns (address implementation_) {
        address beacon_;
        bytes32 slot = BEACON_SLOT;
        assembly {
            beacon_ := sload(slot)
        }
        (bool ok, bytes memory result) = beacon_.staticcall(
            abi.encodeWithSelector(IBeaconImplementation.implementation.selector)
        );
        require(ok && result.length == 32, "BEACON_LOOKUP_FAILED");
        implementation_ = abi.decode(result, (address));
        require(implementation_.code.length > 0, "BEACON_IMPLEMENTATION_HAS_NO_CODE");
    }

    fallback() external payable {
        _delegate();
    }

    receive() external payable {
        _delegate();
    }

    function _delegate() private {
        address implementation_ = _implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), implementation_, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }
}

contract CallerDependentBeacon {
    address public immutable implementationForCallerOne;
    address public immutable implementationForCallerTwo;

    constructor(address first, address second) {
        require(first.code.length > 0 && second.code.length > 0, "NO_IMPLEMENTATION_CODE");
        implementationForCallerOne = first;
        implementationForCallerTwo = second;
    }

    // Deliberately violates the Beacon caller-independence requirement.
    function implementation() external view returns (address) {
        if (msg.sender == address(1)) return implementationForCallerOne;
        if (msg.sender == address(2)) return implementationForCallerTwo;
        return implementationForCallerOne;
    }
}

contract BeaconUpgradeActor {
    // Slot zero is the paired metric consumed by Lowkey's control manifest.
    uint256 public successfulCalls;
    uint256 public attempts;

    function execute(address target, bytes calldata data) external returns (bool success) {
        attempts += 1;
        (success,) = target.call(data);
        // Always write the metric, including a zero delta for rejected control calls.
        successfulCalls = successfulCalls + (success ? 1 : 0);
    }
}
