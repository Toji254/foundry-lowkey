methods {
    function balanceOf(address) external returns (uint256) envfree;
    function totalSupply() external returns (uint256) envfree;
}

invariant balance_never_exceeds_total_supply(address account)
    balanceOf(account) <= totalSupply();
