#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_LOWKEY_DIR="$HOME/.lowkey"
TARGET_BIN_DIR="$HOME/.foundry/bin"

mkdir -p "$TARGET_LOWKEY_DIR" "$TARGET_BIN_DIR"

copy_or_skip_same() {
    local source="$1"
    local destination="$2"

    if [[ -e "$destination" || -L "$destination" ]]; then
        if [[ "$(readlink -f "$source")" == "$(readlink -f "$destination")" ]]; then
            echo "Already installed: $destination"
            return
        fi
    fi

    cp "$source" "$destination"
}

copy_or_skip_same "$REPO_DIR/lowkey/lk.py" "$TARGET_LOWKEY_DIR/lk.py"
copy_or_skip_same "$REPO_DIR/lowkey/forge_tools.py" "$TARGET_LOWKEY_DIR/forge_tools.py"
copy_or_skip_same "$REPO_DIR/lowkey/generator.py" "$TARGET_LOWKEY_DIR/generator.py"
copy_or_skip_same "$REPO_DIR/bin/lk" "$TARGET_BIN_DIR/lk"
chmod +x "$TARGET_BIN_DIR/lk"

cat <<EOF
LowkeyCast installed successfully.

Files copied:
  - $TARGET_LOWKEY_DIR/lk.py
  - $TARGET_LOWKEY_DIR/forge_tools.py
  - $TARGET_LOWKEY_DIR/generator.py
  - $TARGET_BIN_DIR/lk

Run:
  lk -h
  lk doctor
  lk forge --help
EOF
