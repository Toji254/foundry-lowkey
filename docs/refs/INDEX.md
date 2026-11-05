# Lowkey reference index

This index records primary standards and implementation references used by the attack generators. A reference is research input, not proof that a target implements the standard correctly.

| url | class | gives | phase | fetched_at |
|---|---|---|---|---|
| https://eips.ethereum.org/EIPS/eip-20 | token-standard | ERC-20 transfer, allowance, optional return-value compatibility context | P0 | 2026-11-05 |
| https://eips.ethereum.org/EIPS/eip-777 | token-standard | ERC-777 recipient hook name and callback parameters (`tokensReceived`) | P0 | 2026-11-05 |
| https://eips.ethereum.org/EIPS/eip-1820 | registry-standard | ERC-777 interface implementer registration | P0 | 2026-11-05 |
| https://eips.ethereum.org/EIPS/eip-721 | token-standard | ERC-721 safe-transfer recipient callback | P0 | 2026-11-05 |
| https://eips.ethereum.org/EIPS/eip-1155 | token-standard | ERC-1155 single and batch receiver callbacks | P0 | 2026-11-05 |
| https://eips.ethereum.org/EIPS/eip-165 | interface-standard | ERC-165 interface detection | P0 | 2026-11-05 |
| https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol | implementation-reference | Optional-return ERC-20 calls and allowance-reset patterns | P0 | 2026-11-05 |
| https://book.getfoundry.sh/cheatcodes/etch | testing-reference | Runtime-code installation in isolated Foundry tests | P0 | 2026-11-05 |

## Feeding rules

- Prefer primary EIPs and upstream source code.
- Record the precise URL, source class, the claim it supports, phase and fetch date.
- Target-specific claims must still resolve to audited source `file:line` or a bytecode offset.
- Do not promote an assumption because it appears in this index.
- For library behavior, pin the actual dependency version and inspect its installed source before relying on an implementation detail.
