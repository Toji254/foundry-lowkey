#!/usr/bin/env python3
"""Send exactly one real Anvil transaction for the P1 local reproof."""
from __future__ import annotations

import json
import re
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: p1_replay_attack.py ACTOR RPC_URL PRIVATE_KEY")
    actor, rpc_url, private_key = sys.argv[1:]
    result = subprocess.run(
        [
            "cast", "send", actor, "execute()",
            "--rpc-url", rpc_url,
            "--private-key", private_key,
            "--gas-limit", "800000",
            "--gas-price", "1000000000",
            "--legacy",
            "--json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            "cast send failed with exit "
            + str(result.returncode)
            + "\n"
            + result.stdout[-4000:]
            + "\n"
            + result.stderr[-4000:]
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit("cast send did not return JSON: " + str(error) + "\n" + result.stdout[-2000:])
    tx_hash = payload.get("transactionHash") or payload.get("hash")
    if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
        raise SystemExit("cast send JSON omitted a valid transactionHash: " + json.dumps(payload))
    print("LOWKEY_TRACE_TX_HASH " + tx_hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
