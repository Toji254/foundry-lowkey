// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Deliberately vulnerable fixture: effects are applied after the external call.
contract ReentrancyVault {
    mapping(address => uint256) public credit;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    function deposit() external payable {
        require(msg.value != 0, "ZERO_DEPOSIT");
        credit[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @dev Funds the vault without creating a withdrawable entitlement.
    function seed() external payable {
        require(msg.value != 0, "ZERO_SEED");
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        require(amount != 0, "NO_CREDIT");

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "PAYOUT_FAILED");

        // Vulnerability: this write happens after the untrusted external call.
        credit[msg.sender] = 0;
        emit Withdrawn(msg.sender, amount);
    }
}

/// @dev Callback actor used by both the sequential control and reentrancy attack.
contract ReentrancyActor {
    ReentrancyVault public immutable vault;
    address public immutable owner;

    // These deliberately occupy slots 0 and 1. The paired runner excludes only
    // slot 0 (the declared scenario parameter) when comparing control prestate.
    uint256 public mode = 2;
    bool public entered;
    uint256 public successfulReentries;

    constructor(address vault_) {
        require(vault_ != address(0), "ZERO_VAULT");
        vault = ReentrancyVault(payable(vault_));
        owner = msg.sender;
    }

    function setMode(uint256 nextMode) external {
        require(msg.sender == owner, "NOT_OWNER");
        require(nextMode == 1 || nextMode == 2, "INVALID_MODE");
        mode = nextMode;
    }

    function deposit() external payable {
        vault.deposit{value: msg.value}();
    }

    function execute() external {
        vault.withdraw();
    }

    receive() external payable {
        // Read the callback guard in both control and attack so the paired
        // pre-state comparison observes the same declared storage surface.
        bool alreadyEntered = entered;
        if (mode == 2 && !alreadyEntered) {
            entered = true;
            (bool nestedSuccess,) = address(vault).call(
                abi.encodeWithSelector(ReentrancyVault.withdraw.selector)
            );
            if (!nestedSuccess) {
                // A checks-effects-interactions mutation rejects the nested call.
                entered = false;
                return;
            }
            // Count successful nested withdrawals, not merely attempted callbacks.
            successfulReentries += 1;
            entered = false;
        }
    }
}
