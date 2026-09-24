#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_LOWKEY_DIR="$HOME/.lowkey"
TARGET_BIN_DIR="$HOME/.foundry/bin"
STAGE_DIR="$TARGET_LOWKEY_DIR/.install-stage"

mkdir -p "$TARGET_LOWKEY_DIR" "$TARGET_BIN_DIR"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

copy_if_needed() {
  local source="$1"
  local destination="$2"

  # Avoid GNU cp's "same file" failure when a previous install used symlinks.
  if [ -e "$destination" ] && [ "$source" -ef "$destination" ]; then
    return 0
  fi

  cp "$source" "$destination"
}

# Stage and compile the Python runtime first. Do not publish an install manifest
# until every runtime module passes syntax validation.
for file in lk.py forge_tools.py audit_engine.py clone_tools.py walkthrough.py system_model.py; do
  cp "$REPO_DIR/lowkey/$file" "$STAGE_DIR/$file"
done

cp "$REPO_DIR/bin/lk" "$STAGE_DIR/bin-lk"
python3 -m py_compile \
  "$STAGE_DIR/lk.py" \
  "$STAGE_DIR/forge_tools.py" \
  "$STAGE_DIR/audit_engine.py" \
  "$STAGE_DIR/clone_tools.py" \
  "$STAGE_DIR/walkthrough.py" \
  "$STAGE_DIR/system_model.py"
bash -n "$STAGE_DIR/bin-lk"

# Publish exactly the validated stage so the manifest always describes the
# code that was syntax-checked.
cp "$STAGE_DIR/lk.py" "$TARGET_LOWKEY_DIR/lk.py"
cp "$STAGE_DIR/forge_tools.py" "$TARGET_LOWKEY_DIR/forge_tools.py"
cp "$STAGE_DIR/audit_engine.py" "$TARGET_LOWKEY_DIR/audit_engine.py"
cp "$STAGE_DIR/clone_tools.py" "$TARGET_LOWKEY_DIR/clone_tools.py"
cp "$STAGE_DIR/walkthrough.py" "$TARGET_LOWKEY_DIR/walkthrough.py"
cp "$STAGE_DIR/system_model.py" "$TARGET_LOWKEY_DIR/system_model.py"
cp "$STAGE_DIR/bin-lk" "$TARGET_BIN_DIR/lk"
chmod +x "$TARGET_BIN_DIR/lk"

python3 - "$REPO_DIR" "$TARGET_LOWKEY_DIR" "$TARGET_BIN_DIR" <<'PY'
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

repo = Path(sys.argv[1]).resolve()
lowkey_dir = Path(sys.argv[2]).resolve()
bin_dir = Path(sys.argv[3]).resolve()

try:
    git_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
    ).strip()
except (OSError, subprocess.CalledProcessError):
    git_sha = None

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

installed = {
    str(lowkey_dir / "lk.py"): sha256(lowkey_dir / "lk.py"),
    str(lowkey_dir / "forge_tools.py"): sha256(lowkey_dir / "forge_tools.py"),
    str(lowkey_dir / "audit_engine.py"): sha256(lowkey_dir / "audit_engine.py"),
    str(lowkey_dir / "clone_tools.py"): sha256(lowkey_dir / "clone_tools.py"),
    str(lowkey_dir / "walkthrough.py"): sha256(lowkey_dir / "walkthrough.py"),
    str(lowkey_dir / "system_model.py"): sha256(lowkey_dir / "system_model.py"),
    str(bin_dir / "lk"): sha256(bin_dir / "lk"),
}

manifest = {
    "version": 1,
    "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "source_repo": str(repo),
    "git_sha": git_sha,
    "files": installed,
}
(lowkey_dir / "install-manifest.json").write_text(
    json.dumps(manifest, indent=2) + "\n",
    encoding="utf-8",
)
PY

rm -rf "$STAGE_DIR"

cat <<EOF
LowkeyCast installed successfully.

Files copied:
  - $TARGET_LOWKEY_DIR/lk.py
  - $TARGET_LOWKEY_DIR/forge_tools.py
  - $TARGET_LOWKEY_DIR/audit_engine.py
  - $TARGET_LOWKEY_DIR/clone_tools.py
  - $TARGET_LOWKEY_DIR/walkthrough.py
  - $TARGET_LOWKEY_DIR/system_model.py
  - $TARGET_BIN_DIR/lk
  - $TARGET_LOWKEY_DIR/install-manifest.json

Run:
  lk --version
  lk doctor
  lk --help
EOF
