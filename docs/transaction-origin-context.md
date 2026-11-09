# Transaction origin and call context

`lk tx [hash]` shows `tx.origin` from the mined transaction's top-level
`from` field. For a direct call to the selected target, the same address is
also the target function's `msg.sender`.

When the selected target differs from the transaction recipient, Lowkey makes
a best-effort `debug_traceTransaction` request using Geth's `callTracer`.
It reports the caller from the matching target call frame. For
`DELEGATECALL`, it preserves the parent's `msg.sender` rather than treating
the proxy/implementation address as the caller.

Some RPC providers do not support call tracing, and traces can be unavailable
for pending, pruned, or otherwise inaccessible transactions. In those cases
Lowkey labels the nested target caller as **not resolved** and points to
`lk trace <tx-hash>`; it does not substitute `tx.origin` or the top-level
sender for a nested `msg.sender`.

`tx.origin` is an EVM transaction-context value, not proof that the account
directly called every contract in the call chain. It should not be used as a
substitute for `msg.sender` in authorization checks.
