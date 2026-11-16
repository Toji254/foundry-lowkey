// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ChainVault {
    uint256 public totalAssets;

    function deposit(uint256 amount) external {
        totalAssets += amount;
    }

    function withdraw(uint256 amount) external {
        totalAssets = totalAssets - amount;
    }
}
