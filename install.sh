#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_LOWKEY_DIR="$HOME/.lowkey"
TARGET_BIN_DIR="$HOME/.foundry/bin"

mkdir -p "$TARGET_LOWKEY_DIR" "$TARGET_BIN_DIR"

cp "$REPO_DIR/lowkey/lk.py" "$TARGET_LOWKEY_DIR/lk.py"
cp "$REPO_DIR/bin/lk" "$TARGET_BIN_DIR/lk"
chmod +x "$TARGET_BIN_DIR/lk"

cat <<EOF
LowkeyCast installed successfully.

Files copied:
  - $TARGET_LOWKEY_DIR/lk.py
  - $TARGET_BIN_DIR/lk

Run:
  lk --help
EOF
