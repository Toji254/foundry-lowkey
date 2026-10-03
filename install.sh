#!/usr/bin/env bash
set -euo pipefail

# "$0" is always defined under Bash, including when the script is piped
# through stdin. Avoid BASH_SOURCE here because indexed array elements can still
# trigger nounset failures when no script file is attached to stdin.
case "${0##*/}" in
  bash|sh)
    # curl | bash has no script file. In that mode the installer operates on the
    # current working directory, but only after verifying it is a Lowkey checkout.
    INSTALLER_DIR="$PWD"
    ;;
  *)
    if [ -f "$0" ]; then
      INSTALLER_DIR="$(cd "$(dirname "$0")" && pwd)"
    else
      INSTALLER_DIR="$PWD"
    fi
    ;;
esac

REPO_DIR="$(cd "$INSTALLER_DIR" && pwd)"
if [ ! -f "$REPO_DIR/lowkey/lk.py" ] || [ ! -f "$REPO_DIR/bin/lk" ]; then
  echo "Error: Lowkey installer could not locate the repository checkout." >&2
  echo "Run it from the foundry-lowkey repository root, or use: bash install.sh" >&2
  exit 1
fi

TARGET_LOWKEY_DIR="$HOME/.lowkey"
TARGET_BIN_DIR="$HOME/.foundry/bin"
LEGACY_BIN="$HOME/bin/lk"
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
for file in bootstrap.py lk.py forge_tools.py generator.py slither_tools.py audit_context.py project_detection.py clone_tools.py walkthrough.py walkthrough_benchmarks.py walkthrough_finding_patterns.py break_playbook.py break_engine.py audit_engine.py system_model.py project_tools.py question_engine.py import_helper.py solidity_cheatsheet.py; do
  cp "$REPO_DIR/lowkey/$file" "$STAGE_DIR/$file"
done

cp "$REPO_DIR/bin/lk" "$STAGE_DIR/bin-lk"

python3 -m py_compile   "$STAGE_DIR/bootstrap.py"   "$STAGE_DIR/lk.py"   "$STAGE_DIR/forge_tools.py"   "$STAGE_DIR/generator.py"   "$STAGE_DIR/slither_tools.py"   "$STAGE_DIR/audit_context.py"   "$STAGE_DIR/project_detection.py"   "$STAGE_DIR/clone_tools.py"   "$STAGE_DIR/break_playbook.py" "$STAGE_DIR/break_engine.py"   "$STAGE_DIR/audit_engine.py"   "$STAGE_DIR/system_model.py"   "$STAGE_DIR/project_tools.py"   "$STAGE_DIR/question_engine.py"   "$STAGE_DIR/import_helper.py"   "$STAGE_DIR/solidity_cheatsheet.py"
bash -n "$REPO_DIR/bin/lk"

# Publish exactly the validated stage so the manifest always describes the
# code that was syntax-checked.
cp "$STAGE_DIR/bootstrap.py" "$TARGET_LOWKEY_DIR/bootstrap.py"
cp "$STAGE_DIR/lk.py" "$TARGET_LOWKEY_DIR/lk.py"
cp "$STAGE_DIR/forge_tools.py" "$TARGET_LOWKEY_DIR/forge_tools.py"
cp "$STAGE_DIR/generator.py" "$TARGET_LOWKEY_DIR/generator.py"
cp "$STAGE_DIR/slither_tools.py" "$TARGET_LOWKEY_DIR/slither_tools.py"
cp "$STAGE_DIR/audit_context.py" "$TARGET_LOWKEY_DIR/audit_context.py"
cp "$STAGE_DIR/project_detection.py" "$TARGET_LOWKEY_DIR/project_detection.py"
cp "$STAGE_DIR/clone_tools.py" "$TARGET_LOWKEY_DIR/clone_tools.py"
cp "$STAGE_DIR/audit_engine.py" "$TARGET_LOWKEY_DIR/audit_engine.py"
cp "$STAGE_DIR/system_model.py" "$TARGET_LOWKEY_DIR/system_model.py"
cp "$STAGE_DIR/project_tools.py" "$TARGET_LOWKEY_DIR/project_tools.py"
cp "$STAGE_DIR/question_engine.py" "$TARGET_LOWKEY_DIR/question_engine.py"
cp "$STAGE_DIR/import_helper.py" "$TARGET_LOWKEY_DIR/import_helper.py"
cp "$STAGE_DIR/solidity_cheatsheet.py" "$TARGET_LOWKEY_DIR/solidity_cheatsheet.py"
cp "$STAGE_DIR/walkthrough.py" "$TARGET_LOWKEY_DIR/walkthrough.py"
cp "$STAGE_DIR/walkthrough_benchmarks.py" "$TARGET_LOWKEY_DIR/walkthrough_benchmarks.py"
cp "$STAGE_DIR/walkthrough_finding_patterns.py" "$TARGET_LOWKEY_DIR/walkthrough_finding_patterns.py"
cp "$STAGE_DIR/break_playbook.py" "$TARGET_LOWKEY_DIR/break_playbook.py"
cp "$STAGE_DIR/break_engine.py" "$TARGET_LOWKEY_DIR/break_engine.py"
cp "$STAGE_DIR/bin-lk" "$TARGET_BIN_DIR/lk"
chmod +x "$TARGET_BIN_DIR/lk"

# Reconcile the legacy ~/bin/lk location when it is an existing Lowkey install
# or symlink, preventing PATH shadowing of the canonical ~/.foundry/bin/lk.
if [ -L "$LEGACY_BIN" ] || { [ -f "$LEGACY_BIN" ] && grep -qE '.lowkey/(lk|forge_tools|generator)|foundry-lowkey' "$LEGACY_BIN" 2>/dev/null; }; then
  cp "$STAGE_DIR/bin-lk" "$LEGACY_BIN"
  chmod +x "$LEGACY_BIN"
fi

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
    str(lowkey_dir / "bootstrap.py"): sha256(lowkey_dir / "bootstrap.py"),
    str(lowkey_dir / "lk.py"): sha256(lowkey_dir / "lk.py"),
    str(lowkey_dir / "forge_tools.py"): sha256(lowkey_dir / "forge_tools.py"),
    str(lowkey_dir / "generator.py"): sha256(lowkey_dir / "generator.py"),
    str(lowkey_dir / "slither_tools.py"): sha256(lowkey_dir / "slither_tools.py"),
    str(lowkey_dir / "audit_context.py"): sha256(lowkey_dir / "audit_context.py"),
    str(lowkey_dir / "project_detection.py"): sha256(lowkey_dir / "project_detection.py"),
    str(lowkey_dir / "clone_tools.py"): sha256(lowkey_dir / "clone_tools.py"),
    str(lowkey_dir / "audit_engine.py"): sha256(lowkey_dir / "audit_engine.py"),
    str(lowkey_dir / "system_model.py"): sha256(lowkey_dir / "system_model.py"),
    str(lowkey_dir / "project_tools.py"): sha256(lowkey_dir / "project_tools.py"),
    str(lowkey_dir / "question_engine.py"): sha256(lowkey_dir / "question_engine.py"),
    str(lowkey_dir / "import_helper.py"): sha256(lowkey_dir / "import_helper.py"),
    str(lowkey_dir / "solidity_cheatsheet.py"): sha256(lowkey_dir / "solidity_cheatsheet.py"),
    str(lowkey_dir / "walkthrough.py"): sha256(lowkey_dir / "walkthrough.py"),
    str(lowkey_dir / "walkthrough_benchmarks.py"): sha256(lowkey_dir / "walkthrough_benchmarks.py"),
    str(lowkey_dir / "walkthrough_finding_patterns.py"): sha256(lowkey_dir / "walkthrough_finding_patterns.py"),
    str(lowkey_dir / "break_playbook.py"): sha256(lowkey_dir / "break_playbook.py"),
    str(lowkey_dir / "break_engine.py"): sha256(lowkey_dir / "break_engine.py"),
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
  - $TARGET_LOWKEY_DIR/bootstrap.py
  - $TARGET_LOWKEY_DIR/lk.py
  - $TARGET_LOWKEY_DIR/forge_tools.py
  - $TARGET_LOWKEY_DIR/generator.py
  - $TARGET_LOWKEY_DIR/slither_tools.py
  - $TARGET_LOWKEY_DIR/audit_context.py
  - $TARGET_LOWKEY_DIR/project_detection.py
  - $TARGET_LOWKEY_DIR/clone_tools.py
  - $TARGET_LOWKEY_DIR/audit_engine.py
  - $TARGET_LOWKEY_DIR/system_model.py
  - $TARGET_LOWKEY_DIR/project_tools.py
  - $TARGET_LOWKEY_DIR/question_engine.py
  - $TARGET_LOWKEY_DIR/import_helper.py
  - $TARGET_LOWKEY_DIR/solidity_cheatsheet.py
  - $TARGET_LOWKEY_DIR/walkthrough.py
  - $TARGET_LOWKEY_DIR/walkthrough_benchmarks.py
  - $TARGET_LOWKEY_DIR/walkthrough_finding_patterns.py
  - $TARGET_LOWKEY_DIR/break_playbook.py
  - $TARGET_LOWKEY_DIR/break_engine.py
  - $TARGET_BIN_DIR/lk
  - $TARGET_LOWKEY_DIR/install-manifest.json

Run:
  lk --version
  lk doctor
  lk --help
EOF
