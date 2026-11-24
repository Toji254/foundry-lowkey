# Token-denominated reproof economics

lk reprove can optionally measure a declared token portfolio alongside native ETH. This path is opt-in: without --portfolio-manifest, legacy native-ETH accounting remains unchanged and the report explicitly says token assets were not measured.

## Manifest

Create a project-relative JSON file, for example .audit/portfolio.json:

```json
{
  "schema_version": 1,
  "quote_currency": "USD",
  "max_price_age_seconds": 3600,
  "native": {
    "oracle": "0x1111111111111111111111111111111111111111"
  },
  "tokens": [
    {
      "kind": "erc20",
      "address": "0x2222222222222222222222222222222222222222",
      "symbol": "USDC",
      "expected_decimals": 6,
      "oracle": "0x3333333333333333333333333333333333333333"
    },
    {
      "kind": "erc4626",
      "address": "0x4444444444444444444444444444444444444444",
      "asset": "0x5555555555555555555555555555555555555555",
      "symbol": "yvUSDC",
      "asset_oracle": "0x3333333333333333333333333333333333333333"
    }
  ]
}
```

The addresses above are schema examples only; replace every address with the intended chain deployment. Every price feed must implement the Chainlink AggregatorV3 decimals() and latestRoundData() read interface and quote USD. ERC-20 entries use `oracle` to price the token itself; ERC-4626 entries use `asset_oracle` to price the declared underlying asset, never the vault share token. A token/vault without a defensible USD feed is refused. The feed is an auditor-supplied trust assumption; Lowkey verifies its code and pinned round against the independent source RPC but does not decide whether the feed is economically appropriate.

Run the existing source-verified reproof with the additional option:

```bash
lk reprove test/Exploit.t.sol \
  --root . \
  --rpc-url http://127.0.0.1:8545 \
  --source-rpc-url "$SOURCE_ARCHIVE_RPC_URL" \
  --fork-block 21000000 \
  --target-address 0x6666666666666666666666666666666666666666 \
  --profit-address 0x7777777777777777777777777777777777777777 \
  --prior-cost-wei 1000000000000000 \
  --portfolio-manifest .audit/portfolio.json \
  --argv-json '["forge","test","--match-test","testExploit"]'
```

## Measurement policy

- ERC-20 balances are read with balanceOf before and after the single measured transaction. The observed balance delta captures fee-on-transfer effects and balance changes visible at those block boundaries; it does not assume the requested transfer amount.
- ERC-4626 shares are read per profit account and valued using previewRedeem per account at the pre-attack and post-transaction block. The underlying asset address must match asset(), and the underlying token's actual decimals are queried. This respects vault preview/rounding semantics exposed by that implementation; it is not a guarantee of secondary-market liquidity.
- Token, vault, underlying-asset and oracle runtime code are compared with the independent source RPC at the pinned pre-attack block. Prestate calls (decimals, balances, vault asset, preview and price round) must agree between local fork and source.
- Price is fixed to the latest complete Chainlink USD round at the pinned pre-attack block. Feed decimals, positive answer, answeredInRound, timestamps and configured freshness bound are checked. The attack cannot improve its measured profit by manipulating a price used only after the attack.
- Native ETH, token deltas, actual gas cost and declared prior setup cost are normalized to USD 1e-18 using the same pinned native/USD round. Costs are rounded conservatively; negative asset deltas round away from zero.
- Missing code, unsupported ABI, decimals above the supported range, stale/incomplete oracle rounds, source mismatches or malformed return data fail closed. No price, decimal or balance fallback is invented.

The report retains the manifest hash, per-account balances, token/vault/underlying code hashes, oracle round data, value deltas, native gas/setup costs and the final USD 1e-18 metric. Portfolio PROFITABLE promotion is accepted by the attack-chain evidence validator only when independent source verification included every declared asset and feed and the native/token/gas/setup arithmetic reconciles.

## Scope boundary

This is explicit-portfolio accounting, not automatic discovery of every asset owned by an attacker. Rebasing and fee-on-transfer effects are included only to the extent they appear in balanceOf or previewRedeem at the measured block boundaries. It does not infer unlisted LP positions, derivatives, debt liabilities, MEV, off-chain hedges, taxes or exit liquidity. Oracle trust and market suitability remain an auditor decision. If those assumptions cannot be defended, do not declare the asset in the portfolio manifest.
