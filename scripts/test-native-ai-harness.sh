#!/usr/bin/env bash
set -euo pipefail

# Verify the installed AI/memory command routes without contacting an AI provider.
# The fixture is deliberately disposable and contains no credentials or live RPC config.

if [[ -n "${LK_BIN:-}" ]]; then
    LK="${LK_BIN}"
elif command -v lk >/dev/null 2>&1; then
    LK="$(command -v lk)"
elif [[ -x "$HOME/.foundry/bin/lk" ]]; then
    LK="$HOME/.foundry/bin/lk"
else
    echo "ERROR: Lowkey is not installed or not on PATH. Run bash install.sh first." >&2
    exit 2
fi

if [[ ! -x "$LK" ]]; then
    echo "ERROR: configured Lowkey executable is not executable: $LK" >&2
    exit 2
fi

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/lowkey-ai-memory-smoke.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT
PROJECT="$TMP_ROOT/project"
mkdir -p "$PROJECT/src" "$PROJECT/test" "$PROJECT/lib/example/src"

python3 - "$PROJECT" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
(root / "foundry.toml").write_text(
    '[profile.default]\nsrc = "src"\ntest = "test"\nlibs = ["lib"]\n',
    encoding="utf-8",
)
(root / "src" / "Vault.sol").write_text(
    'pragma solidity ^0.8.20;\n'
    'contract Vault {\n'
    '    string private apiKey = "AI_PREVIEW_SECRET_SENTINEL";\n'
    '    uint256 public totalAssets;\n'
    '}\n',
    encoding="utf-8",
)
(root / "test" / "Vault.t.sol").write_text(
    'contract TestVault { string constant MARKER = "AI_PREVIEW_TEST_SOURCE_SENTINEL"; }\n',
    encoding="utf-8",
)
(root / "lib" / "example" / "src" / "Dependency.sol").write_text(
    'contract Dependency { string constant MARKER = "AI_PREVIEW_DEPENDENCY_SENTINEL"; }\n',
    encoding="utf-8",
)
PY

echo "Checking AI provider status (read-only)..."
"$LK" ai status >/dev/null

echo "Checking native experience-memory status (read-only)..."
(
    cd "$PROJECT"
    "$LK" memory status >/dev/null
)

echo "Checking user-facing AI preview (this must not contact a provider)..."
SUMMARY="$("$LK" ai preview --root "$PROJECT" --contract Vault)"
printf '%s\n' "$SUMMARY"
grep -Fq 'no provider request made' <<<"$SUMMARY"
grep -Fq 'src/Vault.sol' <<<"$SUMMARY"
! grep -Fq 'AI_PREVIEW_SECRET_SENTINEL' <<<"$SUMMARY"
! grep -Fq 'Vault.t.sol' <<<"$SUMMARY"
! grep -Fq 'AI_PREVIEW_DEPENDENCY_SENTINEL' <<<"$SUMMARY"

echo "Checking complete redacted payload..."
"$LK" ai preview --root "$PROJECT" --contract Vault --show-context > "$TMP_ROOT/context.json"
python3 - "$TMP_ROOT/context.json" <<'PY'
import json
import sys
from pathlib import Path

preview = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert preview.get("preview_only") is True, preview
assert preview.get("provider_request_made") is False, preview
assert preview.get("context_bytes", 10**9) <= preview.get("context_limit_bytes", 0), preview
context = preview.get("context")
assert isinstance(context, dict), preview
sources = context.get("source_files")
assert isinstance(sources, list) and sources, preview
paths = [item.get("path") for item in sources if isinstance(item, dict)]
assert "src/Vault.sol" in paths, paths
assert not any("Vault.t.sol" in str(path) for path in paths), paths
assert not any(str(path).startswith("lib/") for path in paths), paths
serialized = json.dumps(context, ensure_ascii=False)
assert "AI_PREVIEW_SECRET_SENTINEL" not in serialized
assert "AI_PREVIEW_TEST_SOURCE_SENTINEL" not in serialized
assert "AI_PREVIEW_DEPENDENCY_SENTINEL" not in serialized
assert "[REDACTED]" in serialized
print("PASS: the installed preview is local-only, size-bounded, redacts the test secret,")
print("      and excludes test/dependency source from the provider payload.")
PY

echo "PASS: installed Lowkey AI and experience-memory CLI smoke checks."
