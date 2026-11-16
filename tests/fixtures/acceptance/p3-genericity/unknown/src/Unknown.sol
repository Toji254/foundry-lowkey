// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Unknown {
    uint256 public value;
    function setValue(uint256 nextValue) external { value = nextValue; }
    function readValue() external view returns (uint256) { return value; }
}