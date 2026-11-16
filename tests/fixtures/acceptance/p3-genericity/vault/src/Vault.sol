// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC4626 {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function convertToShares(uint256 assets) external view returns (uint256);
}
contract Vault is IERC4626 {
    function totalAssets() external view returns (uint256) { return 1; }
    function previewWithdraw(uint256 assets) external pure returns (uint256) { return assets; }
    function deposit(uint256 assets, address receiver) external pure returns (uint256) {
        receiver; return assets;
    }
    function convertToShares(uint256 assets) external pure returns (uint256) { return assets; }
}