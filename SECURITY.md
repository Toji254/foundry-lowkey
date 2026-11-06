# Security Notes

LowkeyCast is an auditor helper, not a key-management system.

- Prefer `lk wallet set-env <name> <ENV_VAR>` so signing keys stay outside the LowkeyCast config.
- `lk wallet set` stores a private key in `~/.lowkey/config.json`. The file is restricted to mode 0600, but the key is still plaintext on disk.
- Use local Anvil/test keys for learning and testing. Do not put a production/private wallet key into LowkeyCast.
- Session logs redact `--private-key`, JWT secrets, and remote RPC URLs, but you should still inspect generated audit artifacts before sharing them.
- Treat `lk scan`, `lk risk`, and other heuristic commands as review aids, not vulnerability verdicts.
