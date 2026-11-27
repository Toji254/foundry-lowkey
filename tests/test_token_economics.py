import unittest

from lowkey.token_economics import (
    TokenEconomicsError,
    load_portfolio_manifest,
    measure_token_portfolio,
    net_portfolio_profit_usd_18,
)

ACTOR = "0x" + "1" * 40
TOKEN = "0x" + "2" * 40
VAULT = "0x" + "3" * 40
UNDERLYING = "0x" + "4" * 40
NATIVE_FEED = "0x" + "5" * 40
TOKEN_FEED = "0x" + "6" * 40
USD_FEED = "0x" + "7" * 40
BEACON = "0x" + "8" * 40
BEACON_IMPL = "0x" + "9" * 40
BEACON_IMPL_ALT = "0x" + "a" * 40
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
BEACON_IMPLEMENTATION = "0x5c60da1b"


def word(value):
    return "0x" + format(value, "064x")


def round_data(answer, *, updated=9990, answered_round=5):
    return "0x" + "".join(
        format(value, "064x")
        for value in (5, answer, 9900, updated, answered_round)
    )


class RpcFixture:
    def __init__(
        self, *, stale=False, incomplete=False, source_code_mismatch=False,
        proxy_identity_mismatch=False, proxy_implementation=False,
        proxy_implementation_code_mismatch=False, changed_proxy_implementation=False,
        proxy_beacon=False, proxy_beacon_code_mismatch=False,
        proxy_beacon_implementation_mismatch=False,
        proxy_beacon_implementation_code_mismatch=False,
        changed_beacon_implementation=False,
        unsupported_delegatecall=False, wrong_vault_asset=False,
        changed_decimals=False, changed_vault_asset=False,
    ):
        self.stale = stale
        self.incomplete = incomplete
        self.source_code_mismatch = source_code_mismatch
        self.proxy_identity_mismatch = proxy_identity_mismatch
        self.proxy_implementation = proxy_implementation
        self.proxy_implementation_code_mismatch = proxy_implementation_code_mismatch
        self.changed_proxy_implementation = changed_proxy_implementation
        self.proxy_beacon = proxy_beacon
        self.proxy_beacon_code_mismatch = proxy_beacon_code_mismatch
        self.proxy_beacon_implementation_mismatch = proxy_beacon_implementation_mismatch
        self.proxy_beacon_implementation_code_mismatch = proxy_beacon_implementation_code_mismatch
        self.changed_beacon_implementation = changed_beacon_implementation
        self.unsupported_delegatecall = unsupported_delegatecall
        self.wrong_vault_asset = wrong_vault_asset
        self.changed_decimals = changed_decimals
        self.changed_vault_asset = changed_vault_asset

    def __call__(self, url, method, params, timeout=30):
        if method == "eth_getStorageAt":
            address, slot, block_tag = params
            if address.lower() == TOKEN and slot.lower() == IMPLEMENTATION_SLOT:
                block = int(block_tag, 16)
                if self.proxy_identity_mismatch and url == "source":
                    return word(int("8" * 40, 16))
                if self.proxy_implementation:
                    implementation = 8
                    if self.proxy_identity_mismatch and url == "source":
                        implementation = 9
                    if self.changed_proxy_implementation and block > 100:
                        implementation = 9
                    return word(int(str(implementation) * 40, 16))
            if address.lower() == TOKEN and slot.lower() == BEACON_SLOT and self.proxy_beacon:
                return word(int(BEACON[2:], 16))
            return word(0)
        if method == "eth_getCode":
            address = params[0].lower()
            if url == "source" and self.source_code_mismatch and address == TOKEN:
                return "0x60026002"
            if self.unsupported_delegatecall and address == TOKEN:
                return "0x6000f4"
            if self.proxy_beacon and address == BEACON:
                if url == "source" and self.proxy_beacon_code_mismatch:
                    return "0x60026002"
                return "0x60016001"
            if self.proxy_beacon and address in {BEACON_IMPL, BEACON_IMPL_ALT}:
                if url == "source" and self.proxy_beacon_implementation_code_mismatch and address == BEACON_IMPL:
                    return "0x60026002"
                return "0x60016001"
            if url == "source" and self.proxy_implementation_code_mismatch and address == "0x" + "8" * 40:
                return "0x60026002"
            return "0x60016001"
        if method == "eth_call":
            tx, block_tag = params
            target = tx["to"].lower()
            data = tx["data"].lower()
            block = int(block_tag, 16)
            if data == BEACON_IMPLEMENTATION and target == BEACON and self.proxy_beacon:
                implementation = BEACON_IMPL
                if url == "source" and self.proxy_beacon_implementation_mismatch:
                    implementation = BEACON_IMPL_ALT
                if self.changed_beacon_implementation and block > 100:
                    implementation = BEACON_IMPL_ALT
                return "0x" + "0" * 24 + implementation[2:]
            if data == "0x313ce567":
                if target == TOKEN:
                    return word(7 if self.changed_decimals and block > 100 else 6)
                if target == VAULT:
                    return word(18)
                if target == UNDERLYING:
                    return word(7 if self.changed_decimals and block > 100 else 6)
                if target in {NATIVE_FEED, TOKEN_FEED, USD_FEED}:
                    return word(8)
            if data == "0xfeaf968c":
                updated = 9000 if self.stale else 9990
                answered = 4 if self.incomplete else 5
                answer = 200_000_000 if target == NATIVE_FEED else 100_000_000
                return round_data(answer, updated=updated, answered_round=answered)
            if data == "0x38d52e0f":
                asset = ("0x" + "8" * 40) if (self.wrong_vault_asset or (self.changed_vault_asset and block > 100)) else UNDERLYING
                return "0x" + "0" * 24 + asset[2:]
            if data.startswith("0x70a08231"):
                address = "0x" + data[-40:]
                if target == TOKEN:
                    return word(1_000_000 if block == 100 else 2_500_000)
                if target == VAULT:
                    return word(10 * 10**18 if block == 100 else 12 * 10**18)
                if target == UNDERLYING:
                    return word(0)
            if data.startswith("0x4cdad506"):
                shares = int(data[-64:], 16)
                # One vault share redeems for 1.5 underlying tokens.
                return word((shares // 10**12) * 3 // 2)
            raise AssertionError(f"Unexpected eth_call: {target} {data}")
        raise AssertionError(f"Unexpected RPC method: {method}")


def manifest(*, kind="erc20"):
    if kind == "erc4626":
        token = {
            "kind": "erc4626",
            "address": VAULT,
            "asset": UNDERLYING,
            "symbol": "VSHARE",
            "asset_oracle": TOKEN_FEED,
        }
    else:
        token = {
            "kind": "erc20",
            "address": TOKEN,
            "symbol": "USDC",
            "oracle": TOKEN_FEED,
            "expected_decimals": 6,
        }
    return {
        "schema_version": 1,
        "quote_currency": "USD",
        "max_price_age_seconds": 100,
        "native": {"oracle": NATIVE_FEED},
        "tokens": [token],
    }


class TokenEconomicsTests(unittest.TestCase):
    def test_boolean_schema_version_is_rejected(self):
        with self.assertRaisesRegex(TokenEconomicsError, "integer 1"):
            load_portfolio_manifest({**manifest(), "schema_version": True})

    def test_manifest_requires_explicit_usd_feeds_and_assets(self):
        spec = load_portfolio_manifest(manifest())
        self.assertEqual(spec["quote_currency"], "USD")
        self.assertEqual(spec["tokens"][0]["expected_decimals"], 6)
        self.assertEqual(spec["tokens"][0]["price_subject"], "token")
        with self.assertRaisesRegex(TokenEconomicsError, "quote_currency"):
            load_portfolio_manifest({**manifest(), "quote_currency": "ETH"})

    def test_erc20_balance_delta_uses_actual_decimals_and_pinned_usd_price(self):
        result = measure_token_portfolio(
            RpcFixture(), local_url="local", source_url="source",
            manifest=manifest(), accounts=[ACTOR], before_block=100,
            after_block=101, block_timestamp=10_000,
        )
        token = result["tokens"][0]
        self.assertEqual(token["token_decimals"], 6)
        self.assertEqual(token["share_or_token_delta"], 1_500_000)
        # 1.5 USDC-equivalent tokens at $1 per token.
        self.assertEqual(token["value_delta_usd_18"], 1_500_000_000_000_000_000)
        self.assertTrue(result["source_state_verified"])

    def test_fee_on_transfer_style_actual_balance_delta_is_what_is_valued(self):
        # The observed amount is the recipient balance delta, not the requested
        # transfer amount supplied by a caller or transaction argument.
        result = measure_token_portfolio(
            RpcFixture(), local_url="local", source_url=None,
            manifest=manifest(), accounts=[ACTOR], before_block=100,
            after_block=101, block_timestamp=10_000,
        )
        self.assertEqual(result["tokens"][0]["balances"][0]["balance_delta"], 1_500_000)
        self.assertFalse(result["source_state_verified"])

    def test_erc4626_requires_a_distinct_underlying_asset_price_feed(self):
        ambiguous = manifest(kind="erc4626")
        ambiguous["tokens"][0]["oracle"] = TOKEN_FEED
        ambiguous["tokens"][0].pop("asset_oracle")
        with self.assertRaisesRegex(TokenEconomicsError, "asset_oracle"):
            load_portfolio_manifest(ambiguous)
        normalized = load_portfolio_manifest(manifest(kind="erc4626"))
        self.assertEqual(normalized["tokens"][0]["price_subject"], "underlying_asset")
        self.assertIn("asset_oracle", normalized["tokens"][0])
        self.assertNotIn("oracle", normalized["tokens"][0])
        self.assertEqual(load_portfolio_manifest(normalized), normalized)

    def test_erc4626_preview_redeem_values_underlying_assets_not_share_units(self):
        result = measure_token_portfolio(
            RpcFixture(), local_url="local", source_url="source",
            manifest=manifest(kind="erc4626"), accounts=[ACTOR],
            before_block=100, after_block=101, block_timestamp=10_000,
        )
        vault = result["tokens"][0]
        self.assertEqual(vault["token_decimals"], 18)
        self.assertEqual(vault["asset_decimals"], 6)
        self.assertEqual(vault["price_subject"], "underlying_asset")
        self.assertEqual(vault["share_or_token_delta"], 2 * 10**18)
        self.assertEqual(vault["underlying_asset_delta"], 3_000_000)
        self.assertEqual(vault["value_delta_usd_18"], 3 * 10**18)

    def test_stale_and_incomplete_oracle_rounds_are_refused(self):
        for fixture, message in (
            (RpcFixture(stale=True), "stale"),
            (RpcFixture(incomplete=True), "incomplete"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(TokenEconomicsError, message):
                    measure_token_portfolio(
                        fixture, local_url="local", source_url=None,
                        manifest=manifest(), accounts=[ACTOR], before_block=100,
                        after_block=101, block_timestamp=10_000,
                    )

    def test_token_decimals_mutation_during_measurement_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "decimals changed"):
            measure_token_portfolio(
                RpcFixture(changed_decimals=True), local_url="local", source_url=None,
                manifest=manifest(), accounts=[ACTOR], before_block=100,
                after_block=101, block_timestamp=10_000,
            )

    def test_erc4626_asset_change_during_measurement_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "asset"):
            measure_token_portfolio(
                RpcFixture(changed_vault_asset=True), local_url="local", source_url=None,
                manifest=manifest(kind="erc4626"), accounts=[ACTOR],
                before_block=100, after_block=101, block_timestamp=10_000,
            )

    def test_same_proxy_runtime_with_different_implementation_slot_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "implementation/beacon identity differs"):
            measure_token_portfolio(
                RpcFixture(proxy_identity_mismatch=True), local_url="local", source_url="source",
                manifest=manifest(), accounts=[ACTOR], before_block=100,
                after_block=101, block_timestamp=10_000,
            )

    def test_unsupported_delegatecall_proxy_fails_closed(self):
        with self.assertRaisesRegex(TokenEconomicsError, "unsupported proxy identity"):
            measure_token_portfolio(
                RpcFixture(unsupported_delegatecall=True), local_url="local",
                source_url="source", manifest=manifest(), accounts=[ACTOR],
                before_block=100, after_block=101, block_timestamp=10_000,
            )

    def test_proxy_implementation_bytecode_mismatch_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "implementation bytecode differs"):
            measure_token_portfolio(
                RpcFixture(proxy_implementation=True, proxy_implementation_code_mismatch=True),
                local_url="local", source_url="source", manifest=manifest(),
                accounts=[ACTOR], before_block=100, after_block=101,
                block_timestamp=10_000,
            )

    def test_proxy_implementation_change_during_transaction_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "implementation identity changed"):
            measure_token_portfolio(
                RpcFixture(proxy_implementation=True, changed_proxy_implementation=True),
                local_url="local", source_url=None, manifest=manifest(),
                accounts=[ACTOR], before_block=100, after_block=101,
                block_timestamp=10_000,
            )

    def test_eip1967_beacon_proxy_identity_is_source_verified_at_both_blocks(self):
        result = measure_token_portfolio(
            RpcFixture(proxy_beacon=True), local_url="local", source_url="source",
            manifest=manifest(), accounts=[ACTOR], before_block=100,
            after_block=101, block_timestamp=10_000,
        )
        token = result["tokens"][0]
        self.assertTrue(result["source_state_verified"])
        self.assertNotEqual(token["token_code_sha256"], token["token_identity_sha256"])
        self.assertEqual(token["token_code_sha256"], token["token_code_sha256"])
        self.assertEqual(token["share_or_token_delta"], 1_500_000)

    def test_beacon_runtime_code_mismatch_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "beacon bytecode differs"):
            measure_token_portfolio(
                RpcFixture(proxy_beacon=True, proxy_beacon_code_mismatch=True),
                local_url="local", source_url="source", manifest=manifest(),
                accounts=[ACTOR], before_block=100, after_block=101,
                block_timestamp=10_000,
            )

    def test_beacon_implementation_address_mismatch_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "beacon implementation differs"):
            measure_token_portfolio(
                RpcFixture(proxy_beacon=True, proxy_beacon_implementation_mismatch=True),
                local_url="local", source_url="source", manifest=manifest(),
                accounts=[ACTOR], before_block=100, after_block=101,
                block_timestamp=10_000,
            )

    def test_beacon_implementation_bytecode_mismatch_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "beacon implementation bytecode differs"):
            measure_token_portfolio(
                RpcFixture(proxy_beacon=True, proxy_beacon_implementation_code_mismatch=True),
                local_url="local", source_url="source", manifest=manifest(),
                accounts=[ACTOR], before_block=100, after_block=101,
                block_timestamp=10_000,
            )

    def test_beacon_implementation_change_during_transaction_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "proxy implementation identity changed"):
            measure_token_portfolio(
                RpcFixture(proxy_beacon=True, changed_beacon_implementation=True),
                local_url="local", source_url=None, manifest=manifest(),
                accounts=[ACTOR], before_block=100, after_block=101,
                block_timestamp=10_000,
            )

    def test_source_code_mismatch_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "bytecode differs"):
            measure_token_portfolio(
                RpcFixture(source_code_mismatch=True), local_url="local", source_url="source",
                manifest=manifest(), accounts=[ACTOR], before_block=100,
                after_block=101, block_timestamp=10_000,
            )

    def test_erc4626_noncanonical_address_word_is_rejected(self):
        class NonCanonicalAddressRpc(RpcFixture):
            def __call__(self, url, method, params, timeout=30):
                if method == "eth_call" and params[0]["data"].lower() == "0x38d52e0f":
                    return "0x" + "1" * 24 + UNDERLYING[2:]
                return super().__call__(url, method, params, timeout)
        with self.assertRaisesRegex(TokenEconomicsError, "non-canonical"):
            measure_token_portfolio(
                NonCanonicalAddressRpc(), local_url="local", source_url=None,
                manifest=manifest(kind="erc4626"), accounts=[ACTOR],
                before_block=100, after_block=101, block_timestamp=10_000,
            )

    def test_erc4626_asset_mismatch_is_refused(self):
        with self.assertRaisesRegex(TokenEconomicsError, "asset"):
            measure_token_portfolio(
                RpcFixture(wrong_vault_asset=True), local_url="local", source_url=None,
                manifest=manifest(kind="erc4626"), accounts=[ACTOR],
                before_block=100, after_block=101, block_timestamp=10_000,
            )

    def test_usd_valuation_subtracts_gas_and_prior_setup_costs_in_native_price(self):
        summary = net_portfolio_profit_usd_18(
            native_delta_wei=0,
            token_value_delta_usd_18=10 * 10**18,
            native_price={"price_usd_18": 2_000 * 10**18},
            external_gas_cost_wei=2 * 10**16,  # 0.02 ETH = $40
            prior_cost_wei=1 * 10**16,        # 0.01 ETH = $20
        )
        self.assertEqual(summary["token_delta_usd_18"], 10 * 10**18)
        self.assertEqual(summary["external_gas_cost_usd_18"], 40 * 10**18)
        self.assertEqual(summary["prior_cost_usd_18"], 20 * 10**18)
        self.assertEqual(summary["net_profit_usd_18"], -50 * 10**18)


if __name__ == "__main__":
    unittest.main()
