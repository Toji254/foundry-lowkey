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

# Detect the Jev CLI/server name collision before publishing any files.
# Never overwrite an unrelated executable named "jev".
if [ -e "$TARGET_BIN_DIR/jev" ] && ! grep -Fq "LOWKEY JEV ORCHESTRATOR" "$TARGET_BIN_DIR/jev" 2>/dev/null; then
  echo "Error: preserving existing $TARGET_BIN_DIR/jev; it is not the Lowkey Jev launcher." >&2
  echo "Set JEVOS_BIN to your Jevos server executable and resolve this name collision before reinstalling." >&2
  exit 1
fi

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
for file in bootstrap.py lk.py forge_tools.py generator.py slither_tools.py audit_context.py project_detection.py clone_tools.py walkthrough.py walkthrough_benchmarks.py walkthrough_finding_patterns.py break_playbook.py break_engine.py audit_engine.py benchmark.py system_model.py project_tools.py question_engine.py analysis_adapters.py verification_adapters.py test_generation.py test_generation_analysis.py generation_plugins.py behavioral_validation.py verification_benchmark.py verification_cli.py signal_investigation.py import_helper.py solidity_cheatsheet.py solidity_cheat_topics.py solidity_cheat_data.py solidity_connect_data.py ai_harness.py provider_adapters.py agent_runtime.py evidence_ledger.py security_review.py error_context.py error_advisor.py test_planner.py experience_memory.py ai_workflow.py jev_engine.py jev_orchestrator.py; do
  cp "$REPO_DIR/lowkey/$file" "$STAGE_DIR/$file"
done

cp "$REPO_DIR/bin/lk" "$STAGE_DIR/bin-lk"
cp "$REPO_DIR/bin/jev" "$STAGE_DIR/bin-jev"
cp "$REPO_DIR/bin/jev-ask" "$STAGE_DIR/bin-jev-ask"
bash -n "$REPO_DIR/bin/jev" "$REPO_DIR/bin/jev-ask"

python3 -m py_compile   "$STAGE_DIR/bootstrap.py"   "$STAGE_DIR/lk.py"   "$STAGE_DIR/forge_tools.py"   "$STAGE_DIR/generator.py"   "$STAGE_DIR/slither_tools.py"   "$STAGE_DIR/audit_context.py"   "$STAGE_DIR/project_detection.py"   "$STAGE_DIR/clone_tools.py"   "$STAGE_DIR/break_playbook.py" "$STAGE_DIR/break_engine.py"   "$STAGE_DIR/audit_engine.py"   "$STAGE_DIR/benchmark.py"   "$STAGE_DIR/system_model.py"   "$STAGE_DIR/project_tools.py"   "$STAGE_DIR/question_engine.py"   "$STAGE_DIR/analysis_adapters.py"   "$STAGE_DIR/verification_adapters.py"   "$STAGE_DIR/test_generation.py" "$STAGE_DIR/test_generation_analysis.py"   "$STAGE_DIR/generation_plugins.py"   "$STAGE_DIR/behavioral_validation.py"   "$STAGE_DIR/verification_benchmark.py"   "$STAGE_DIR/verification_cli.py"   "$STAGE_DIR/signal_investigation.py"   "$STAGE_DIR/import_helper.py"   "$STAGE_DIR/solidity_cheatsheet.py"   "$STAGE_DIR/solidity_cheat_topics.py"   "$STAGE_DIR/solidity_cheat_data.py"   "$STAGE_DIR/solidity_connect_data.py" "$STAGE_DIR/ai_harness.py" "$STAGE_DIR/provider_adapters.py" "$STAGE_DIR/agent_runtime.py" "$STAGE_DIR/evidence_ledger.py" "$STAGE_DIR/security_review.py" "$STAGE_DIR/error_context.py" "$STAGE_DIR/error_advisor.py" "$STAGE_DIR/test_planner.py" "$STAGE_DIR/experience_memory.py" "$STAGE_DIR/ai_workflow.py" "$STAGE_DIR/jev_engine.py" "$STAGE_DIR/jev_orchestrator.py"
bash -n "$REPO_DIR/bin/lk"
bash -n "$REPO_DIR/bin/jev"
bash -n "$REPO_DIR/bin/jev-ask"

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
cp "$STAGE_DIR/benchmark.py" "$TARGET_LOWKEY_DIR/benchmark.py"
cp "$STAGE_DIR/system_model.py" "$TARGET_LOWKEY_DIR/system_model.py"
cp "$STAGE_DIR/project_tools.py" "$TARGET_LOWKEY_DIR/project_tools.py"
cp "$STAGE_DIR/question_engine.py" "$TARGET_LOWKEY_DIR/question_engine.py"
cp "$STAGE_DIR/analysis_adapters.py" "$TARGET_LOWKEY_DIR/analysis_adapters.py"
cp "$STAGE_DIR/verification_adapters.py" "$TARGET_LOWKEY_DIR/verification_adapters.py"
cp "$STAGE_DIR/test_generation.py" "$TARGET_LOWKEY_DIR/test_generation.py"
cp "$STAGE_DIR/test_generation_analysis.py" "$TARGET_LOWKEY_DIR/test_generation_analysis.py"
cp "$STAGE_DIR/generation_plugins.py" "$TARGET_LOWKEY_DIR/generation_plugins.py"
cp "$STAGE_DIR/behavioral_validation.py" "$TARGET_LOWKEY_DIR/behavioral_validation.py"
cp "$STAGE_DIR/verification_benchmark.py" "$TARGET_LOWKEY_DIR/verification_benchmark.py"
cp "$STAGE_DIR/verification_cli.py" "$TARGET_LOWKEY_DIR/verification_cli.py"
cp "$STAGE_DIR/signal_investigation.py" "$TARGET_LOWKEY_DIR/signal_investigation.py"
cp "$STAGE_DIR/import_helper.py" "$TARGET_LOWKEY_DIR/import_helper.py"
cp "$STAGE_DIR/solidity_cheatsheet.py" "$TARGET_LOWKEY_DIR/solidity_cheatsheet.py"
cp "$STAGE_DIR/solidity_cheat_topics.py" "$TARGET_LOWKEY_DIR/solidity_cheat_topics.py"
cp "$STAGE_DIR/solidity_cheat_data.py" "$TARGET_LOWKEY_DIR/solidity_cheat_data.py"
cp "$STAGE_DIR/solidity_connect_data.py" "$TARGET_LOWKEY_DIR/solidity_connect_data.py"
cp "$STAGE_DIR/ai_harness.py" "$TARGET_LOWKEY_DIR/ai_harness.py"
cp "$STAGE_DIR/ai_workflow.py" "$TARGET_LOWKEY_DIR/ai_workflow.py"
cp "$STAGE_DIR/jev_engine.py" "$TARGET_LOWKEY_DIR/jev_engine.py"
cp "$STAGE_DIR/jev_orchestrator.py" "$TARGET_LOWKEY_DIR/jev_orchestrator.py"
cp "$STAGE_DIR/provider_adapters.py" "$TARGET_LOWKEY_DIR/provider_adapters.py"
cp "$STAGE_DIR/agent_runtime.py" "$TARGET_LOWKEY_DIR/agent_runtime.py"
cp "$STAGE_DIR/evidence_ledger.py" "$TARGET_LOWKEY_DIR/evidence_ledger.py"
cp "$STAGE_DIR/security_review.py" "$TARGET_LOWKEY_DIR/security_review.py"
cp "$STAGE_DIR/error_context.py" "$TARGET_LOWKEY_DIR/error_context.py"
cp "$STAGE_DIR/error_advisor.py" "$TARGET_LOWKEY_DIR/error_advisor.py"
cp "$STAGE_DIR/test_planner.py" "$TARGET_LOWKEY_DIR/test_planner.py"
cp "$STAGE_DIR/experience_memory.py" "$TARGET_LOWKEY_DIR/experience_memory.py"
cp "$STAGE_DIR/walkthrough.py" "$TARGET_LOWKEY_DIR/walkthrough.py"
cp "$STAGE_DIR/walkthrough_benchmarks.py" "$TARGET_LOWKEY_DIR/walkthrough_benchmarks.py"
cp "$STAGE_DIR/walkthrough_finding_patterns.py" "$TARGET_LOWKEY_DIR/walkthrough_finding_patterns.py"
cp "$STAGE_DIR/break_playbook.py" "$TARGET_LOWKEY_DIR/break_playbook.py"
cp "$STAGE_DIR/break_engine.py" "$TARGET_LOWKEY_DIR/break_engine.py"
cp "$STAGE_DIR/bin-lk" "$TARGET_BIN_DIR/lk"
chmod +x "$TARGET_BIN_DIR/lk"

# Jevos discovery skips this marked launcher if it sees it on PATH.
cp "$STAGE_DIR/bin-jev" "$TARGET_BIN_DIR/jev"
cp "$STAGE_DIR/bin-jev-ask" "$TARGET_BIN_DIR/jev-ask"
chmod +x "$TARGET_BIN_DIR/jev" "$TARGET_BIN_DIR/jev-ask"

# Replace only the known legacy Noul-classifier wrapper; preserve unrelated files.
TARGET_LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$TARGET_LOCAL_BIN"
LOCAL_JEV_ASK="$TARGET_LOCAL_BIN/jev-ask"
if [ -f "$LOCAL_JEV_ASK" ]; then
  if grep -Fq "jev_orchestrator.py" "$LOCAL_JEV_ASK"; then
    cp "$STAGE_DIR/bin-jev-ask" "$LOCAL_JEV_ASK"
    chmod +x "$LOCAL_JEV_ASK"
  elif grep -Fq "127.0.0.1:8017/v1/systemone" "$LOCAL_JEV_ASK"; then
    cp -p "$LOCAL_JEV_ASK" "$LOCAL_JEV_ASK.backup-jev-orchestrator-$STAMP"
    cp "$STAGE_DIR/bin-jev-ask" "$LOCAL_JEV_ASK"
    chmod +x "$LOCAL_JEV_ASK"
    printf 'Backed up and replaced the legacy Jev classifier wrapper: %s\\n' "$LOCAL_JEV_ASK"
  else
    printf 'Preserved unrelated existing command: %s\\n' "$LOCAL_JEV_ASK"
  fi
else
  cp "$STAGE_DIR/bin-jev-ask" "$LOCAL_JEV_ASK"
  chmod +x "$LOCAL_JEV_ASK"
fi

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
    str(lowkey_dir / "benchmark.py"): sha256(lowkey_dir / "benchmark.py"),
    str(lowkey_dir / "system_model.py"): sha256(lowkey_dir / "system_model.py"),
    str(lowkey_dir / "project_tools.py"): sha256(lowkey_dir / "project_tools.py"),
    str(lowkey_dir / "question_engine.py"): sha256(lowkey_dir / "question_engine.py"),
    str(lowkey_dir / "analysis_adapters.py"): sha256(lowkey_dir / "analysis_adapters.py"),
    str(lowkey_dir / "verification_adapters.py"): sha256(lowkey_dir / "verification_adapters.py"),
    str(lowkey_dir / "test_generation.py"): sha256(lowkey_dir / "test_generation.py"),
    str(lowkey_dir / "test_generation_analysis.py"): sha256(lowkey_dir / "test_generation_analysis.py"),
    str(lowkey_dir / "generation_plugins.py"): sha256(lowkey_dir / "generation_plugins.py"),
    str(lowkey_dir / "behavioral_validation.py"): sha256(lowkey_dir / "behavioral_validation.py"),
    str(lowkey_dir / "verification_benchmark.py"): sha256(lowkey_dir / "verification_benchmark.py"),
    str(lowkey_dir / "verification_cli.py"): sha256(lowkey_dir / "verification_cli.py"),
    str(lowkey_dir / "import_helper.py"): sha256(lowkey_dir / "import_helper.py"),
    str(lowkey_dir / "solidity_cheatsheet.py"): sha256(lowkey_dir / "solidity_cheatsheet.py"),
    str(lowkey_dir / "solidity_cheat_topics.py"): sha256(lowkey_dir / "solidity_cheat_topics.py"),
    str(lowkey_dir / "solidity_cheat_data.py"): sha256(lowkey_dir / "solidity_cheat_data.py"),
    str(lowkey_dir / "solidity_connect_data.py"): sha256(lowkey_dir / "solidity_connect_data.py"),
    str(lowkey_dir / "walkthrough.py"): sha256(lowkey_dir / "walkthrough.py"),
    str(lowkey_dir / "walkthrough_benchmarks.py"): sha256(lowkey_dir / "walkthrough_benchmarks.py"),
    str(lowkey_dir / "walkthrough_finding_patterns.py"): sha256(lowkey_dir / "walkthrough_finding_patterns.py"),
    str(lowkey_dir / "break_playbook.py"): sha256(lowkey_dir / "break_playbook.py"),
    str(lowkey_dir / "break_engine.py"): sha256(lowkey_dir / "break_engine.py"),
    str(lowkey_dir / "ai_harness.py"): sha256(lowkey_dir / "ai_harness.py"),
    str(lowkey_dir / "ai_workflow.py"): sha256(lowkey_dir / "ai_workflow.py"),
    str(lowkey_dir / "jev_engine.py"): sha256(lowkey_dir / "jev_engine.py"),
    str(lowkey_dir / "jev_orchestrator.py"): sha256(lowkey_dir / "jev_orchestrator.py"),
    str(bin_dir / "jev"): sha256(bin_dir / "jev"),
    str(bin_dir / "jev-ask"): sha256(bin_dir / "jev-ask"),
    str(lowkey_dir / "provider_adapters.py"): sha256(lowkey_dir / "provider_adapters.py"),
    str(lowkey_dir / "agent_runtime.py"): sha256(lowkey_dir / "agent_runtime.py"),
    str(lowkey_dir / "evidence_ledger.py"): sha256(lowkey_dir / "evidence_ledger.py"),
    str(lowkey_dir / "security_review.py"): sha256(lowkey_dir / "security_review.py"),
    str(lowkey_dir / "error_context.py"): sha256(lowkey_dir / "error_context.py"),
    str(lowkey_dir / "error_advisor.py"): sha256(lowkey_dir / "error_advisor.py"),
    str(lowkey_dir / "test_planner.py"): sha256(lowkey_dir / "test_planner.py"),
    str(lowkey_dir / "experience_memory.py"): sha256(lowkey_dir / "experience_memory.py"),
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
  - $TARGET_LOWKEY_DIR/benchmark.py
  - $TARGET_LOWKEY_DIR/system_model.py
  - $TARGET_LOWKEY_DIR/project_tools.py
  - $TARGET_LOWKEY_DIR/question_engine.py
  - $TARGET_LOWKEY_DIR/analysis_adapters.py
  - $TARGET_LOWKEY_DIR/verification_adapters.py
  - $TARGET_LOWKEY_DIR/test_generation.py
  - $TARGET_LOWKEY_DIR/test_generation_analysis.py
  - $TARGET_LOWKEY_DIR/generation_plugins.py
  - $TARGET_LOWKEY_DIR/behavioral_validation.py
  - $TARGET_LOWKEY_DIR/verification_benchmark.py
  - $TARGET_LOWKEY_DIR/verification_cli.py
  - $TARGET_LOWKEY_DIR/import_helper.py
  - $TARGET_LOWKEY_DIR/solidity_cheatsheet.py
  - $TARGET_LOWKEY_DIR/solidity_cheat_topics.py
  - $TARGET_LOWKEY_DIR/solidity_cheat_data.py
  - $TARGET_LOWKEY_DIR/solidity_connect_data.py
  - $TARGET_LOWKEY_DIR/ai_harness.py
  - $TARGET_LOWKEY_DIR/ai_workflow.py
  - $TARGET_LOWKEY_DIR/jev_engine.py
  - $TARGET_LOWKEY_DIR/jev_orchestrator.py
  - $TARGET_BIN_DIR/jev
  - $TARGET_BIN_DIR/jev-ask
  - $TARGET_LOWKEY_DIR/experience_memory.py
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
