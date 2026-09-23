#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_LOWKEY_DIR="$HOME/.lowkey"
TARGET_BIN_DIR="$HOME/.foundry/bin"

mkdir -p "$TARGET_LOWKEY_DIR" "$TARGET_BIN_DIR"

copy_if_needed() {
  local source="$1"
  local destination="$2"

  # Avoid GNU cp's "same file" failure when a previous install used symlinks.
  if [ -e "$destination" ] && [ "$source" -ef "$destination" ]; then
    return 0
  fi

  cp "$source" "$destination"
}

copy_if_needed "$REPO_DIR/lowkey/lk.py" "$TARGET_LOWKEY_DIR/lk.py"
copy_if_needed "$REPO_DIR/lowkey/forge_tools.py" "$TARGET_LOWKEY_DIR/forge_tools.py"
copy_if_needed "$REPO_DIR/lowkey/audit_engine.py" "$TARGET_LOWKEY_DIR/audit_engine.py"
copy_if_needed "$REPO_DIR/lowkey/clone_tools.py" "$TARGET_LOWKEY_DIR/clone_tools.py"
copy_if_needed "$REPO_DIR/bin/lk" "$TARGET_BIN_DIR/lk"
chmod +x "$TARGET_BIN_DIR/lk"

cat <<EOF
LowkeyCast installed successfully.

Files copied:
  - $TARGET_LOWKEY_DIR/lk.py
  - $TARGET_LOWKEY_DIR/forge_tools.py
  - $TARGET_LOWKEY_DIR/audit_engine.py
  - $TARGET_LOWKEY_DIR/clone_tools.py
  - $TARGET_BIN_DIR/lk

Run:
  lk --help
  lk forge --help
EOF
