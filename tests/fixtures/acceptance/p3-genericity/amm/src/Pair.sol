// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Pair {
    uint112 public reserve0;
    uint112 public reserve1;
    function getReserves() external view returns (uint112, uint112) { return (reserve0, reserve1); }
    function swap(uint256 amount0Out, uint256 amount1Out) external pure returns (uint256) {
        amount0Out; return amount1Out;
    }
    function mint(address to) external pure returns (uint256) { to; return 1; }
}