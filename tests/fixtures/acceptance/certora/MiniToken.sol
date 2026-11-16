// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Small, stateful token model for an authenticated Certora acceptance.
/// This is a formal-verification fixture, not a production token.
contract MiniToken {
    mapping(address => uint256) private balances;
    uint256 private supply;

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    function totalSupply() external view returns (uint256) {
        return supply;
    }

    function mint(address recipient, uint256 amount) external {
        balances[recipient] += amount;
        supply += amount;
    }

    function burn(address account, uint256 amount) external {
        require(balances[account] >= amount, "insufficient balance");
        balances[account] -= amount;
        supply -= amount;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        balances[recipient] += amount;
        return true;
    }
}
