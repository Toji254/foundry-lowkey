"""Conservative, block-pinned ERC-20/ERC-4626 portfolio valuation.

The module reads actual token balances and uses user-declared Chainlink
AggregatorV3 USD feeds at the pinned pre-attack block. It never falls back to
symbols, off-chain prices, decimals=18, or a protocol's potentially manipulated
spot price. Every missing or stale datum is a hard refusal.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Mapping

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_HEX_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})+\Z")
_WORD_RE = re.compile(r"0x[0-9a-fA-F]{64}\Z")
_BALANCE_OF = "0x70a08231"
_DECIMALS = "0x313ce567"
_ERC4626_ASSET = "0x38d52e0f"
_ERC4626_PREVIEW_REDEEM = "0x4cdad506"
_AGGREGATOR_ROUND_DATA = "0xfeaf968c"


class TokenEconomicsError(ValueError):
    """A reasoned refusal when token valuation cannot be defended."""


def _address(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise TokenEconomicsError(f"{label} must be a 20-byte EVM address.")
    normalized = value.lower()
    if normalized == "0x" + "0" * 40:
        raise TokenEconomicsError(f"{label} cannot be the zero address.")
    return normalized


def _uint(value: Any, label: str, *, minimum: int = 0, maximum: int = (1 << 256) - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TokenEconomicsError(f"{label} must be an integer from {minimum} to {maximum}.")
    return value


def _word(value: Any, label: str) -> int:
    if not isinstance(value, str) or not _WORD_RE.fullmatch(value):
        raise TokenEconomicsError(f"{label} must be exactly one ABI uint256 word.")
    return int(value, 16)


def _decode_words(value: Any, count: int, label: str) -> list[int]:
    if not isinstance(value, str) or not _HEX_RE.fullmatch(value):
        raise TokenEconomicsError(f"{label} returned malformed ABI hex.")
    raw = value[2:]
    if len(raw) != count * 64:
        raise TokenEconomicsError(f"{label} returned {len(raw) // 64} ABI words; expected {count}.")
    return [int(raw[index * 64:(index + 1) * 64], 16) for index in range(count)]


def _encode_address_argument(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def _encode_uint_argument(value: int) -> str:
    return format(value, "064x")


def _call(rpc: Callable[..., Any], url: str, target: str, data: str, block: int, label: str) -> str:
    result = rpc(url, "eth_call", [{"to": target, "data": data}, hex(block)], 30)
    if not isinstance(result, str) or not _HEX_RE.fullmatch(result):
        raise TokenEconomicsError(f"{label} eth_call returned malformed or empty data.")
    return result.lower()


def _code(rpc: Callable[..., Any], url: str, address: str, block: int, label: str) -> str:
    result = rpc(url, "eth_getCode", [address, hex(block)], 30)
    if not isinstance(result, str) or not _HEX_RE.fullmatch(result) or result in {"0x", "0x0"}:
        raise TokenEconomicsError(f"{label} has no runtime bytecode at the pinned fork block.")
    return result.lower()


def _verify_code_source(
    rpc: Callable[..., Any], local_url: str, source_url: str | None,
    address: str, block: int, label: str,
) -> tuple[str, bool]:
    local_code = _code(rpc, local_url, address, block, label)
    digest = hashlib.sha256(bytes.fromhex(local_code[2:])).hexdigest()
    if source_url is None:
        return digest, False
    source_code = _code(rpc, source_url, address, block, label + " source")
    if source_code != local_code:
        raise TokenEconomicsError(f"{label} runtime bytecode differs between the local fork and source RPC.")
    return digest, True


def _read_uint_call(
    rpc: Callable[..., Any], local_url: str, source_url: str | None,
    target: str, calldata: str, block: int, label: str,
) -> tuple[int, bool]:
    local_raw = _call(rpc, local_url, target, calldata, block, label)
    local_value = _word(local_raw, label)
    if source_url is None:
        return local_value, False
    source_raw = _call(rpc, source_url, target, calldata, block, label + " source")
    if source_raw != local_raw:
        raise TokenEconomicsError(f"{label} value differs between the local fork and independent source RPC.")
    return local_value, True


def _price_round(
    rpc: Callable[..., Any], local_url: str, source_url: str | None,
    feed: str, block: int, block_timestamp: int, max_age_seconds: int,
) -> dict[str, Any]:
    code_hash, code_verified = _verify_code_source(
        rpc, local_url, source_url, feed, block, "USD price feed"
    )
    feed_decimals, decimals_verified = _read_uint_call(
        rpc, local_url, source_url, feed, _DECIMALS, block, "price feed decimals"
    )
    if feed_decimals > 18:
        raise TokenEconomicsError("Price feed decimals above 18 are unsupported for conservative USD normalization.")
    local_raw = _call(rpc, local_url, feed, _AGGREGATOR_ROUND_DATA, block, "latestRoundData")
    values = _decode_words(local_raw, 5, "latestRoundData")
    source_verified = False
    if source_url is not None:
        source_raw = _call(rpc, source_url, feed, _AGGREGATOR_ROUND_DATA, block, "latestRoundData source")
        if source_raw != local_raw:
            raise TokenEconomicsError("Pinned USD price round differs between local fork and independent source RPC.")
        source_verified = True
    round_id, answer_word, started_at, updated_at, answered_in_round = values
    answer = answer_word - (1 << 256) if answer_word >= (1 << 255) else answer_word
    if round_id <= 0 or answer <= 0:
        raise TokenEconomicsError("USD price feed round ID and answer must be positive.")
    if answered_in_round < round_id:
        raise TokenEconomicsError("USD price feed round is incomplete (answeredInRound < roundId).")
    if started_at <= 0 or updated_at <= 0 or updated_at > block_timestamp:
        raise TokenEconomicsError("USD price feed timestamps are missing or after the pinned block.")
    age = block_timestamp - updated_at
    if age > max_age_seconds:
        raise TokenEconomicsError(
            f"USD price feed is stale: age {age}s exceeds configured maximum {max_age_seconds}s."
        )
    price_usd_18 = answer * (10 ** (18 - feed_decimals))
    return {
        "feed": feed,
        "feed_code_sha256": code_hash,
        "feed_code_source_verified": code_verified,
        "feed_decimals": feed_decimals,
        "decimals_source_verified": decimals_verified,
        "round_id": round_id,
        "answer": answer,
        "updated_at": updated_at,
        "age_seconds": age,
        "max_age_seconds": max_age_seconds,
        "price_usd_18": price_usd_18,
        "source_round_verified": source_verified,
    }


def _value_delta_usd_18(delta_raw: int, decimals: int, price_usd_18: int) -> int:
    numerator = delta_raw * price_usd_18
    denominator = 10 ** decimals
    if numerator >= 0:
        return numerator // denominator
    return -((-numerator + denominator - 1) // denominator)


def value_native_delta_usd_18(delta_wei: int, native_price: Mapping[str, Any]) -> int:
    """Value native ETH/asset delta with conservative rounding in USD 1e-18."""
    price = native_price.get("price_usd_18")
    if type(price) is not int or price <= 0:
        raise TokenEconomicsError("Native asset USD price is unavailable.")
    numerator = delta_wei * price
    denominator = 10 ** 18
    if numerator >= 0:
        return numerator // denominator
    return -((-numerator + denominator - 1) // denominator)


def load_portfolio_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise TokenEconomicsError("Portfolio manifest schema_version must be 1.")
    if value.get("quote_currency") != "USD":
        raise TokenEconomicsError("Portfolio manifest quote_currency must be USD.")
    default_age = _uint(value.get("max_price_age_seconds"), "max_price_age_seconds", minimum=1, maximum=31_536_000)
    native = value.get("native")
    if not isinstance(native, dict):
        raise TokenEconomicsError("Portfolio manifest requires a native USD price feed.")
    normalized_native = {
        "oracle": _address(native.get("oracle"), "native.oracle"),
        "max_price_age_seconds": _uint(
            native.get("max_price_age_seconds", default_age), "native.max_price_age_seconds",
            minimum=1, maximum=31_536_000,
        ),
    }
    tokens = value.get("tokens")
    if not isinstance(tokens, list) or not tokens:
        raise TokenEconomicsError("Portfolio manifest tokens must be a non-empty array.")
    normalized_tokens = []
    seen: set[str] = set()
    for index, item in enumerate(tokens):
        label = f"tokens[{index}]"
        if not isinstance(item, dict):
            raise TokenEconomicsError(f"{label} must be an object.")
        kind = item.get("kind")
        if kind not in {"erc20", "erc4626"}:
            raise TokenEconomicsError(f"{label}.kind must be erc20 or erc4626.")
        address = _address(item.get("address"), f"{label}.address")
        if address in seen:
            raise TokenEconomicsError(f"{label}.address duplicates an earlier portfolio asset.")
        seen.add(address)
        symbol = item.get("symbol")
        if not isinstance(symbol, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,24}", symbol):
            raise TokenEconomicsError(f"{label}.symbol must be 1-24 simple identifier characters.")
        normalized = {
            "kind": kind,
            "address": address,
            "symbol": symbol,
            "oracle": _address(item.get("oracle"), f"{label}.oracle"),
            "max_price_age_seconds": _uint(
                item.get("max_price_age_seconds", default_age),
                f"{label}.max_price_age_seconds", minimum=1, maximum=31_536_000,
            ),
            "expected_decimals": None,
        }
        if item.get("expected_decimals") is not None:
            normalized["expected_decimals"] = _uint(
                item["expected_decimals"], f"{label}.expected_decimals", maximum=36,
            )
        if kind == "erc4626":
            normalized["asset"] = _address(item.get("asset"), f"{label}.asset")
        normalized_tokens.append(normalized)
    return {
        "schema_version": 1,
        "quote_currency": "USD",
        "max_price_age_seconds": default_age,
        "native": normalized_native,
        "tokens": normalized_tokens,
    }


def measure_token_portfolio(
    rpc: Callable[..., Any], *, local_url: str, source_url: str | None,
    manifest: Mapping[str, Any], accounts: list[str], before_block: int,
    after_block: int, block_timestamp: int,
) -> dict[str, Any]:
    """Measure/price ERC20 and ERC4626 portfolio deltas; source-verify prestate when available."""
    spec = load_portfolio_manifest(dict(manifest))
    normalized_accounts = sorted({_address(account, "profit account") for account in accounts})
    if not normalized_accounts:
        raise TokenEconomicsError("At least one profit account is required.")
    native_price = _price_round(
        rpc, local_url, source_url, spec["native"]["oracle"], before_block,
        block_timestamp, spec["native"]["max_price_age_seconds"],
    )
    results = []
    all_source_verified = source_url is not None and bool(
        native_price["feed_code_source_verified"] and native_price["source_round_verified"]
    )
    for token in spec["tokens"]:
        address = token["address"]
        code_hash, code_verified = _verify_code_source(
            rpc, local_url, source_url, address, before_block, token["symbol"]
        )
        all_source_verified = all_source_verified and code_verified
        decimals_target = token["address"]
        decimals, decimals_verified = _read_uint_call(
            rpc, local_url, source_url, decimals_target, _DECIMALS,
            before_block, token["symbol"] + " decimals",
        )
        if decimals > 36:
            raise TokenEconomicsError(f"{token['symbol']} decimals above 36 are unsupported.")
        after_code = _code(rpc, local_url, address, after_block, token["symbol"] + " post-state")
        if hashlib.sha256(bytes.fromhex(after_code[2:])).hexdigest() != code_hash:
            raise TokenEconomicsError(
                f"{token['symbol']} runtime bytecode changed during the measured transaction; token valuation is refused."
            )
        decimals_after = _word(
            _call(rpc, local_url, address, _DECIMALS, after_block,
                  token["symbol"] + " post-state decimals"),
            token["symbol"] + " post-state decimals",
        )
        if decimals_after != decimals:
            raise TokenEconomicsError(
                f"{token['symbol']} decimals changed during the measured transaction."
            )
        if token["expected_decimals"] is not None and decimals != token["expected_decimals"]:
            raise TokenEconomicsError(
                f"{token['symbol']} decimals mismatch: expected {token['expected_decimals']}, observed {decimals}."
            )
        all_source_verified = all_source_verified and decimals_verified

        if token["kind"] == "erc4626":
            asset = token["asset"]
            asset_code_hash, asset_code_verified = _verify_code_source(
                rpc, local_url, source_url, asset, before_block,
                token["symbol"] + " underlying asset",
            )
            asset_decimals, asset_decimals_verified = _read_uint_call(
                rpc, local_url, source_url, asset, _DECIMALS,
                before_block, token["symbol"] + " underlying decimals",
            )
            if asset_decimals > 36:
                raise TokenEconomicsError(f"{token['symbol']} underlying decimals above 36 are unsupported.")
            asset_after_code = _code(
                rpc, local_url, asset, after_block,
                token["symbol"] + " post-state underlying asset",
            )
            if hashlib.sha256(bytes.fromhex(asset_after_code[2:])).hexdigest() != asset_code_hash:
                raise TokenEconomicsError(
                    f"{token['symbol']} underlying asset runtime bytecode changed during the measured transaction."
                )
            asset_decimals_after = _word(
                _call(rpc, local_url, asset, _DECIMALS, after_block,
                      token["symbol"] + " post-state underlying decimals"),
                token["symbol"] + " post-state underlying decimals",
            )
            if asset_decimals_after != asset_decimals:
                raise TokenEconomicsError(
                    f"{token['symbol']} underlying decimals changed during the measured transaction."
                )
            asset_call, asset_call_verified = _read_uint_call(
                rpc, local_url, source_url, address, _ERC4626_ASSET,
                before_block, token["symbol"] + " asset()",
            )
            # ABI address return occupies the low 160 bits of one word.
            if "0x" + format(asset_call & ((1 << 160) - 1), "040x") != asset:
                raise TokenEconomicsError(f"{token['symbol']} ERC-4626 asset() does not match the declared underlying asset.")
            vault_asset_after = _word(
                _call(rpc, local_url, address, _ERC4626_ASSET, after_block,
                      token["symbol"] + " post-state asset()"),
                token["symbol"] + " post-state asset()",
            ) & ((1 << 160) - 1)
            if "0x" + format(vault_asset_after, "040x") != asset:
                raise TokenEconomicsError(
                    f"{token['symbol']} ERC-4626 asset() changed during the measured transaction."
                )
            if not asset_code_verified:
                all_source_verified = False
            if not asset_decimals_verified or not asset_call_verified:
                all_source_verified = False
            value_decimals = asset_decimals
            value_asset = asset
        else:
            asset_code_hash = None
            asset_decimals = decimals
            all_source_verified = all_source_verified and decimals_verified
            value_decimals = decimals
            value_asset = address

        price = _price_round(
            rpc, local_url, source_url, token["oracle"], before_block,
            block_timestamp, token["max_price_age_seconds"],
        )
        all_source_verified = all_source_verified and bool(
            price["feed_code_source_verified"] and price["source_round_verified"]
        )
        balance_rows = []
        gross_raw_delta = 0
        gross_underlying_delta = 0
        value_usd_18 = 0
        for account in normalized_accounts:
            calldata = _BALANCE_OF + _encode_address_argument(account)
            before_raw, before_verified = _read_uint_call(
                rpc, local_url, source_url, address, calldata, before_block,
                token["symbol"] + " balanceOf before",
            )
            after_raw = _word(
                _call(rpc, local_url, address, calldata, after_block,
                      token["symbol"] + " balanceOf after"),
                token["symbol"] + " balanceOf after",
            )
            all_source_verified = all_source_verified and before_verified
            if token["kind"] == "erc4626":
                before_assets = _word(
                    _call(rpc, local_url, address,
                          _ERC4626_PREVIEW_REDEEM + _encode_uint_argument(before_raw),
                          before_block, token["symbol"] + " previewRedeem before"),
                    token["symbol"] + " previewRedeem before",
                )
                after_assets = _word(
                    _call(rpc, local_url, address,
                          _ERC4626_PREVIEW_REDEEM + _encode_uint_argument(after_raw),
                          after_block, token["symbol"] + " previewRedeem after"),
                    token["symbol"] + " previewRedeem after",
                )
                before_underlying = _read_uint_call(
                    rpc, local_url, source_url, address,
                    _ERC4626_PREVIEW_REDEEM + _encode_uint_argument(before_raw),
                    before_block, token["symbol"] + " previewRedeem source check",
                )[0] if source_url is not None else before_assets
                if before_underlying != before_assets:
                    raise TokenEconomicsError(
                        f"{token['symbol']} previewRedeem differs between local fork and source RPC."
                    )
                account_delta = after_assets - before_assets
                account_share_delta = after_raw - before_raw
                gross_underlying_delta += account_delta
                gross_raw_delta += account_share_delta
                account_value = _value_delta_usd_18(account_delta, value_decimals, price["price_usd_18"])
                balance_rows.append({
                    "account": account,
                    "shares_before": before_raw,
                    "shares_after": after_raw,
                    "shares_delta": account_share_delta,
                    "assets_before": before_assets,
                    "assets_after": after_assets,
                    "assets_delta": account_delta,
                    "value_delta_usd_18": account_value,
                })
            else:
                account_delta = after_raw - before_raw
                gross_raw_delta += account_delta
                account_value = _value_delta_usd_18(account_delta, value_decimals, price["price_usd_18"])
                balance_rows.append({
                    "account": account,
                    "balance_before": before_raw,
                    "balance_after": after_raw,
                    "balance_delta": account_delta,
                    "value_delta_usd_18": account_value,
                })
            value_usd_18 += account_value
        results.append({
            "kind": token["kind"],
            "symbol": token["symbol"],
            "token": address,
            "token_code_sha256": code_hash,
            "asset": value_asset,
            "asset_code_sha256": asset_code_hash,
            "token_decimals": decimals,
            "asset_decimals": asset_decimals,
            "oracle": price,
            "balances": balance_rows,
            "share_or_token_delta": gross_raw_delta,
            "underlying_asset_delta": gross_underlying_delta if token["kind"] == "erc4626" else None,
            "value_delta_usd_18": value_usd_18,
        })
    return {
        "quote_currency": "USD",
        "quote_decimals": 18,
        "valuation_block": before_block,
        "valuation_timestamp": block_timestamp,
        "native_price": native_price,
        "tokens": results,
        "token_value_delta_usd_18": sum(item["value_delta_usd_18"] for item in results),
        "source_state_verified": bool(all_source_verified),
        "valuation_policy": (
            "Pinned pre-attack Chainlink AggregatorV3 USD round; ERC20 balanceOf deltas; "
            "ERC4626 previewRedeem deltas; actual decimals; conservative integer rounding; "
            "native gas and prior setup costs valued using the same pinned native/USD round."
        ),
        "limitations": [
            "Only explicitly declared ERC20 and ERC4626 assets are measured; undeclared portfolio assets are not included.",
            "Rebasing and fee-on-transfer effects are reflected only insofar as they change the observed balance or previewRedeem result.",
            "Liquidity, slippage beyond ERC4626 previewRedeem, MEV, off-chain hedges and taxes are not inferred.",
            "Price feed trust and economic suitability remain an auditor-supplied assumption even when the pinned contract state is source-verified.",
        ],
    }


def net_portfolio_profit_usd_18(
    *, native_delta_wei: int, token_value_delta_usd_18: int,
    native_price: Mapping[str, Any], external_gas_cost_wei: int = 0,
    prior_cost_wei: int = 0,
) -> dict[str, int]:
    """Combine native and token deltas in USD 1e-18, subtracting non-portfolio costs."""
    gas = _uint(external_gas_cost_wei, "external_gas_cost_wei")
    prior = _uint(prior_cost_wei, "prior_cost_wei")
    native_value = value_native_delta_usd_18(native_delta_wei, native_price)
    gas_value = value_native_delta_usd_18(-gas, native_price)
    prior_value = value_native_delta_usd_18(-prior, native_price)
    net = native_value + token_value_delta_usd_18 + gas_value + prior_value
    return {
        "native_delta_usd_18": native_value,
        "token_delta_usd_18": token_value_delta_usd_18,
        "external_gas_cost_usd_18": -gas_value,
        "prior_cost_usd_18": -prior_value,
        "net_profit_usd_18": net,
    }
