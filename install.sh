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
for file in bootstrap.py lk.py command_wrapper.py capability_registry.py forge_tools.py generator.py slither_tools.py audit_context.py shared_context.py fixture_context.py project_detection.py clone_tools.py walkthrough.py walkthrough_benchmarks.py walkthrough_finding_patterns.py break_playbook.py break_engine.py library_linker.py network_manager.py runtime_verification.py audit_engine.py benchmark.py system_model.py project_tools.py lab_target_scope.py source_index.py source_ast.py source_link.py source_graph.py source_explorer.py eth_flow.py question_engine.py workflow_engine.py analysis_adapters.py verification_adapters.py test_generation.py test_generation_analysis.py generation_plugins.py behavioral_validation.py verification_benchmark.py verification_cli.py signal_investigation.py import_helper.py solidity_cheatsheet.py solidity_cheat_topics.py solidity_cheat_data.py solidity_connect_data.py ai_harness.py test_repair.py provider_adapters.py agent_runtime.py evidence_ledger.py security_review.py error_context.py error_advisor.py test_planner.py experience_memory.py ai_workflow.py jev_engine.py attack_library.py attack_catalog.py attack_engine.py attack_research.py attack_synthesis.py protocol_graph.py multiwave_audit.py godmode.py arithmetic_review.py proof_evidence.py forge_state_diff.py trace_evidence.py trace_schema.py trace_parity.py storage_trace.py abi_support.py setup_reasoner.py foundry_ast_setup.py foundry_build.py hardhat_tools.py workspace_tools.py source_risk.py finding_explainer.py block_tools.py proxy_engine.py opcode_intelligence.py token_economics.py; do
  cp "$REPO_DIR/lowkey/$file" "$STAGE_DIR/$file"
done

# Keep non-Python runtime assets beside the installed Godmode module.
mkdir -p "$STAGE_DIR/templates"
cp "$REPO_DIR/lowkey/templates/step_harness.sol.tmpl" "$STAGE_DIR/templates/step_harness.sol.tmpl"

mkdir -p "$STAGE_DIR/archetypes"
cp "$REPO_DIR/lowkey/archetypes/__init__.py" "$STAGE_DIR/archetypes/__init__.py"
cp "$REPO_DIR/lowkey/archetypes/_index.py" "$STAGE_DIR/archetypes/_index.py"
cp "$REPO_DIR/lowkey/archetypes/"*.json "$STAGE_DIR/archetypes/"

cp "$REPO_DIR/bin/lk" "$STAGE_DIR/bin-lk"

python3 -m py_compile   "$STAGE_DIR/bootstrap.py"   "$STAGE_DIR/lk.py" "$STAGE_DIR/command_wrapper.py" "$STAGE_DIR/capability_registry.py"   "$STAGE_DIR/forge_tools.py"   "$STAGE_DIR/generator.py"   "$STAGE_DIR/slither_tools.py"   "$STAGE_DIR/audit_context.py" "$STAGE_DIR/shared_context.py" "$STAGE_DIR/fixture_context.py"   "$STAGE_DIR/project_detection.py"   "$STAGE_DIR/clone_tools.py"   "$STAGE_DIR/break_playbook.py" "$STAGE_DIR/break_engine.py" "$STAGE_DIR/library_linker.py" "$STAGE_DIR/network_manager.py" "$STAGE_DIR/runtime_verification.py"   "$STAGE_DIR/audit_engine.py"   "$STAGE_DIR/benchmark.py"   "$STAGE_DIR/system_model.py"   "$STAGE_DIR/project_tools.py" "$STAGE_DIR/lab_target_scope.py" "$STAGE_DIR/source_index.py" "$STAGE_DIR/source_ast.py" "$STAGE_DIR/source_link.py" "$STAGE_DIR/source_graph.py" "$STAGE_DIR/source_explorer.py" "$STAGE_DIR/eth_flow.py" "$STAGE_DIR/question_engine.py" "$STAGE_DIR/workflow_engine.py"   "$STAGE_DIR/analysis_adapters.py"   "$STAGE_DIR/verification_adapters.py"   "$STAGE_DIR/test_generation.py" "$STAGE_DIR/test_generation_analysis.py"   "$STAGE_DIR/generation_plugins.py"   "$STAGE_DIR/behavioral_validation.py"   "$STAGE_DIR/verification_benchmark.py"   "$STAGE_DIR/verification_cli.py"   "$STAGE_DIR/signal_investigation.py"   "$STAGE_DIR/import_helper.py"   "$STAGE_DIR/solidity_cheatsheet.py"   "$STAGE_DIR/solidity_cheat_topics.py"   "$STAGE_DIR/solidity_cheat_data.py"   "$STAGE_DIR/solidity_connect_data.py" "$STAGE_DIR/ai_harness.py" "$STAGE_DIR/test_repair.py" "$STAGE_DIR/provider_adapters.py" "$STAGE_DIR/agent_runtime.py" "$STAGE_DIR/evidence_ledger.py" "$STAGE_DIR/security_review.py" "$STAGE_DIR/error_context.py" "$STAGE_DIR/error_advisor.py" "$STAGE_DIR/test_planner.py" "$STAGE_DIR/experience_memory.py" "$STAGE_DIR/ai_workflow.py" "$STAGE_DIR/jev_engine.py" "$STAGE_DIR/attack_library.py" "$STAGE_DIR/attack_catalog.py" "$STAGE_DIR/attack_engine.py" "$STAGE_DIR/attack_research.py" "$STAGE_DIR/attack_synthesis.py" "$STAGE_DIR/protocol_graph.py" "$STAGE_DIR/multiwave_audit.py" "$STAGE_DIR/godmode.py" "$STAGE_DIR/arithmetic_review.py" "$STAGE_DIR/proof_evidence.py" "$STAGE_DIR/forge_state_diff.py" "$STAGE_DIR/trace_evidence.py" "$STAGE_DIR/trace_schema.py" "$STAGE_DIR/trace_parity.py" "$STAGE_DIR/storage_trace.py" "$STAGE_DIR/abi_support.py" "$STAGE_DIR/setup_reasoner.py" "$STAGE_DIR/foundry_ast_setup.py" "$STAGE_DIR/foundry_build.py" "$STAGE_DIR/hardhat_tools.py" "$STAGE_DIR/workspace_tools.py" "$STAGE_DIR/source_risk.py" "$STAGE_DIR/finding_explainer.py" "$STAGE_DIR/block_tools.py" "$STAGE_DIR/proxy_engine.py" "$STAGE_DIR/opcode_intelligence.py" "$STAGE_DIR/token_economics.py" "$STAGE_DIR/archetypes/__init__.py" "$STAGE_DIR/archetypes/_index.py"
bash -n "$REPO_DIR/bin/lk"

# Publish exactly the validated stage so the manifest always describes the
# code that was syntax-checked.
cp "$STAGE_DIR/bootstrap.py" "$TARGET_LOWKEY_DIR/bootstrap.py"
cp "$STAGE_DIR/lk.py" "$TARGET_LOWKEY_DIR/lk.py"
cp "$STAGE_DIR/command_wrapper.py" "$TARGET_LOWKEY_DIR/command_wrapper.py"
cp "$STAGE_DIR/capability_registry.py" "$TARGET_LOWKEY_DIR/capability_registry.py"
cp "$STAGE_DIR/forge_tools.py" "$TARGET_LOWKEY_DIR/forge_tools.py"
cp "$STAGE_DIR/generator.py" "$TARGET_LOWKEY_DIR/generator.py"
cp "$STAGE_DIR/slither_tools.py" "$TARGET_LOWKEY_DIR/slither_tools.py"
cp "$STAGE_DIR/audit_context.py" "$TARGET_LOWKEY_DIR/audit_context.py"
cp "$STAGE_DIR/shared_context.py" "$TARGET_LOWKEY_DIR/shared_context.py"
cp "$STAGE_DIR/fixture_context.py" "$TARGET_LOWKEY_DIR/fixture_context.py"
cp "$STAGE_DIR/project_detection.py" "$TARGET_LOWKEY_DIR/project_detection.py"
cp "$STAGE_DIR/clone_tools.py" "$TARGET_LOWKEY_DIR/clone_tools.py"
cp "$STAGE_DIR/audit_engine.py" "$TARGET_LOWKEY_DIR/audit_engine.py"
cp "$STAGE_DIR/benchmark.py" "$TARGET_LOWKEY_DIR/benchmark.py"
cp "$STAGE_DIR/system_model.py" "$TARGET_LOWKEY_DIR/system_model.py"
cp "$STAGE_DIR/project_tools.py" "$TARGET_LOWKEY_DIR/project_tools.py"
cp "$STAGE_DIR/lab_target_scope.py" "$TARGET_LOWKEY_DIR/lab_target_scope.py"
cp "$STAGE_DIR/source_index.py" "$TARGET_LOWKEY_DIR/source_index.py"
cp "$STAGE_DIR/source_ast.py" "$TARGET_LOWKEY_DIR/source_ast.py"
cp "$STAGE_DIR/source_link.py" "$TARGET_LOWKEY_DIR/source_link.py"
cp "$STAGE_DIR/source_graph.py" "$TARGET_LOWKEY_DIR/source_graph.py"
cp "$STAGE_DIR/source_explorer.py" "$TARGET_LOWKEY_DIR/source_explorer.py"
cp "$STAGE_DIR/eth_flow.py" "$TARGET_LOWKEY_DIR/eth_flow.py"
cp "$STAGE_DIR/question_engine.py" "$TARGET_LOWKEY_DIR/question_engine.py"
cp "$STAGE_DIR/workflow_engine.py" "$TARGET_LOWKEY_DIR/workflow_engine.py"
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
cp "$STAGE_DIR/library_linker.py" "$TARGET_LOWKEY_DIR/library_linker.py"
cp "$STAGE_DIR/network_manager.py" "$TARGET_LOWKEY_DIR/network_manager.py"
cp "$STAGE_DIR/runtime_verification.py" "$TARGET_LOWKEY_DIR/runtime_verification.py"
cp "$STAGE_DIR/attack_library.py" "$TARGET_LOWKEY_DIR/attack_library.py"
cp "$STAGE_DIR/attack_catalog.py" "$TARGET_LOWKEY_DIR/attack_catalog.py"
cp "$STAGE_DIR/attack_engine.py" "$TARGET_LOWKEY_DIR/attack_engine.py"
cp "$STAGE_DIR/attack_research.py" "$TARGET_LOWKEY_DIR/attack_research.py"
cp "$STAGE_DIR/attack_synthesis.py" "$TARGET_LOWKEY_DIR/attack_synthesis.py"
cp "$STAGE_DIR/protocol_graph.py" "$TARGET_LOWKEY_DIR/protocol_graph.py"
cp "$STAGE_DIR/godmode.py" "$TARGET_LOWKEY_DIR/godmode.py"
cp "$STAGE_DIR/multiwave_audit.py" "$TARGET_LOWKEY_DIR/multiwave_audit.py"
cp "$STAGE_DIR/arithmetic_review.py" "$TARGET_LOWKEY_DIR/arithmetic_review.py"
cp "$STAGE_DIR/proof_evidence.py" "$TARGET_LOWKEY_DIR/proof_evidence.py"
cp "$STAGE_DIR/forge_state_diff.py" "$TARGET_LOWKEY_DIR/forge_state_diff.py"
cp "$STAGE_DIR/trace_evidence.py" "$TARGET_LOWKEY_DIR/trace_evidence.py"
cp "$STAGE_DIR/trace_schema.py" "$TARGET_LOWKEY_DIR/trace_schema.py"
cp "$STAGE_DIR/trace_parity.py" "$TARGET_LOWKEY_DIR/trace_parity.py"
cp "$STAGE_DIR/storage_trace.py" "$TARGET_LOWKEY_DIR/storage_trace.py"
cp "$STAGE_DIR/abi_support.py" "$TARGET_LOWKEY_DIR/abi_support.py"
cp "$STAGE_DIR/setup_reasoner.py" "$TARGET_LOWKEY_DIR/setup_reasoner.py"
cp "$STAGE_DIR/foundry_ast_setup.py" "$TARGET_LOWKEY_DIR/foundry_ast_setup.py"
cp "$STAGE_DIR/foundry_build.py" "$TARGET_LOWKEY_DIR/foundry_build.py"
cp "$STAGE_DIR/hardhat_tools.py" "$TARGET_LOWKEY_DIR/hardhat_tools.py"
cp "$STAGE_DIR/workspace_tools.py" "$TARGET_LOWKEY_DIR/workspace_tools.py"
cp "$STAGE_DIR/source_risk.py" "$TARGET_LOWKEY_DIR/source_risk.py"
cp "$STAGE_DIR/finding_explainer.py" "$TARGET_LOWKEY_DIR/finding_explainer.py"
cp "$STAGE_DIR/block_tools.py" "$TARGET_LOWKEY_DIR/block_tools.py"
cp "$STAGE_DIR/opcode_intelligence.py" "$TARGET_LOWKEY_DIR/opcode_intelligence.py"
cp "$STAGE_DIR/token_economics.py" "$TARGET_LOWKEY_DIR/token_economics.py"
cp "$STAGE_DIR/proxy_engine.py" "$TARGET_LOWKEY_DIR/proxy_engine.py"
mkdir -p "$TARGET_LOWKEY_DIR/templates"
cp "$STAGE_DIR/templates/step_harness.sol.tmpl" "$TARGET_LOWKEY_DIR/templates/step_harness.sol.tmpl"
mkdir -p "$TARGET_LOWKEY_DIR/archetypes"
cp "$STAGE_DIR/archetypes/__init__.py" "$TARGET_LOWKEY_DIR/archetypes/__init__.py"
cp "$STAGE_DIR/archetypes/_index.py" "$TARGET_LOWKEY_DIR/archetypes/_index.py"
cp "$STAGE_DIR/archetypes/"*.json "$TARGET_LOWKEY_DIR/archetypes/"
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
    str(lowkey_dir / "command_wrapper.py"): sha256(lowkey_dir / "command_wrapper.py"),
    str(lowkey_dir / "capability_registry.py"): sha256(lowkey_dir / "capability_registry.py"),
    str(lowkey_dir / "forge_tools.py"): sha256(lowkey_dir / "forge_tools.py"),
    str(lowkey_dir / "generator.py"): sha256(lowkey_dir / "generator.py"),
    str(lowkey_dir / "slither_tools.py"): sha256(lowkey_dir / "slither_tools.py"),
    str(lowkey_dir / "audit_context.py"): sha256(lowkey_dir / "audit_context.py"),
    str(lowkey_dir / "shared_context.py"): sha256(lowkey_dir / "shared_context.py"),
    str(lowkey_dir / "fixture_context.py"): sha256(lowkey_dir / "fixture_context.py"),
    str(lowkey_dir / "project_detection.py"): sha256(lowkey_dir / "project_detection.py"),
    str(lowkey_dir / "clone_tools.py"): sha256(lowkey_dir / "clone_tools.py"),
    str(lowkey_dir / "audit_engine.py"): sha256(lowkey_dir / "audit_engine.py"),
    str(lowkey_dir / "benchmark.py"): sha256(lowkey_dir / "benchmark.py"),
    str(lowkey_dir / "system_model.py"): sha256(lowkey_dir / "system_model.py"),
    str(lowkey_dir / "project_tools.py"): sha256(lowkey_dir / "project_tools.py"),
    str(lowkey_dir / "lab_target_scope.py"): sha256(lowkey_dir / "lab_target_scope.py"),
    str(lowkey_dir / "source_index.py"): sha256(lowkey_dir / "source_index.py"),
    str(lowkey_dir / "source_ast.py"): sha256(lowkey_dir / "source_ast.py"),
    str(lowkey_dir / "source_link.py"): sha256(lowkey_dir / "source_link.py"),
    str(lowkey_dir / "source_explorer.py"): sha256(lowkey_dir / "source_explorer.py"),
    str(lowkey_dir / "eth_flow.py"): sha256(lowkey_dir / "eth_flow.py"),
    str(lowkey_dir / "question_engine.py"): sha256(lowkey_dir / "question_engine.py"),
    str(lowkey_dir / "workflow_engine.py"): sha256(lowkey_dir / "workflow_engine.py"),
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
    str(lowkey_dir / "library_linker.py"): sha256(lowkey_dir / "library_linker.py"),
    str(lowkey_dir / "network_manager.py"): sha256(lowkey_dir / "network_manager.py"),
    str(lowkey_dir / "runtime_verification.py"): sha256(lowkey_dir / "runtime_verification.py"),
    str(lowkey_dir / "ai_harness.py"): sha256(lowkey_dir / "ai_harness.py"),
    str(lowkey_dir / "ai_workflow.py"): sha256(lowkey_dir / "ai_workflow.py"),
    str(lowkey_dir / "jev_engine.py"): sha256(lowkey_dir / "jev_engine.py"),
    str(lowkey_dir / "provider_adapters.py"): sha256(lowkey_dir / "provider_adapters.py"),
    str(lowkey_dir / "agent_runtime.py"): sha256(lowkey_dir / "agent_runtime.py"),
    str(lowkey_dir / "evidence_ledger.py"): sha256(lowkey_dir / "evidence_ledger.py"),
    str(lowkey_dir / "security_review.py"): sha256(lowkey_dir / "security_review.py"),
    str(lowkey_dir / "error_context.py"): sha256(lowkey_dir / "error_context.py"),
    str(lowkey_dir / "error_advisor.py"): sha256(lowkey_dir / "error_advisor.py"),
    str(lowkey_dir / "test_planner.py"): sha256(lowkey_dir / "test_planner.py"),
    str(lowkey_dir / "experience_memory.py"): sha256(lowkey_dir / "experience_memory.py"),
    str(lowkey_dir / "attack_library.py"): sha256(lowkey_dir / "attack_library.py"),
    str(lowkey_dir / "attack_catalog.py"): sha256(lowkey_dir / "attack_catalog.py"),
    str(lowkey_dir / "attack_engine.py"): sha256(lowkey_dir / "attack_engine.py"),
    str(lowkey_dir / "attack_research.py"): sha256(lowkey_dir / "attack_research.py"),
    str(lowkey_dir / "attack_synthesis.py"): sha256(lowkey_dir / "attack_synthesis.py"),
    str(lowkey_dir / "protocol_graph.py"): sha256(lowkey_dir / "protocol_graph.py"),
    str(lowkey_dir / "godmode.py"): sha256(lowkey_dir / "godmode.py"),
    str(lowkey_dir / "multiwave_audit.py"): sha256(lowkey_dir / "multiwave_audit.py"),
    str(lowkey_dir / "arithmetic_review.py"): sha256(lowkey_dir / "arithmetic_review.py"),
    str(lowkey_dir / "templates" / "step_harness.sol.tmpl"): sha256(lowkey_dir / "templates" / "step_harness.sol.tmpl"),
    str(lowkey_dir / "proof_evidence.py"): sha256(lowkey_dir / "proof_evidence.py"),
    str(lowkey_dir / "forge_state_diff.py"): sha256(lowkey_dir / "forge_state_diff.py"),
    str(lowkey_dir / "trace_evidence.py"): sha256(lowkey_dir / "trace_evidence.py"),
    str(lowkey_dir / "trace_schema.py"): sha256(lowkey_dir / "trace_schema.py"),
    str(lowkey_dir / "trace_parity.py"): sha256(lowkey_dir / "trace_parity.py"),
    str(lowkey_dir / "storage_trace.py"): sha256(lowkey_dir / "storage_trace.py"),
    str(lowkey_dir / "abi_support.py"): sha256(lowkey_dir / "abi_support.py"),
    str(lowkey_dir / "setup_reasoner.py"): sha256(lowkey_dir / "setup_reasoner.py"),
    str(lowkey_dir / "foundry_ast_setup.py"): sha256(lowkey_dir / "foundry_ast_setup.py"),
    str(lowkey_dir / "foundry_build.py"): sha256(lowkey_dir / "foundry_build.py"),
    str(lowkey_dir / "hardhat_tools.py"): sha256(lowkey_dir / "hardhat_tools.py"),
    str(lowkey_dir / "workspace_tools.py"): sha256(lowkey_dir / "workspace_tools.py"),
    str(lowkey_dir / "source_risk.py"): sha256(lowkey_dir / "source_risk.py"),
    str(lowkey_dir / "finding_explainer.py"): sha256(lowkey_dir / "finding_explainer.py"),
    str(lowkey_dir / "block_tools.py"): sha256(lowkey_dir / "block_tools.py"),
    str(lowkey_dir / "opcode_intelligence.py"): sha256(lowkey_dir / "opcode_intelligence.py"),
    str(lowkey_dir / "token_economics.py"): sha256(lowkey_dir / "token_economics.py"),
    str(lowkey_dir / "proxy_engine.py"): sha256(lowkey_dir / "proxy_engine.py"),
    str(lowkey_dir / "archetypes" / "__init__.py"): sha256(lowkey_dir / "archetypes" / "__init__.py"),
    str(lowkey_dir / "archetypes" / "_index.py"): sha256(lowkey_dir / "archetypes" / "_index.py"),
    str(lowkey_dir / "archetypes" / "vault4626.json"): sha256(lowkey_dir / "archetypes" / "vault4626.json"),
    str(lowkey_dir / "archetypes" / "lending.json"): sha256(lowkey_dir / "archetypes" / "lending.json"),
    str(lowkey_dir / "archetypes" / "amm_cp.json"): sha256(lowkey_dir / "archetypes" / "amm_cp.json"),
    str(lowkey_dir / "archetypes" / "amm_concentrated.json"): sha256(lowkey_dir / "archetypes" / "amm_concentrated.json"),
    str(lowkey_dir / "archetypes" / "staking.json"): sha256(lowkey_dir / "archetypes" / "staking.json"),
    str(lowkey_dir / "archetypes" / "bridge.json"): sha256(lowkey_dir / "archetypes" / "bridge.json"),
    str(lowkey_dir / "archetypes" / "governance.json"): sha256(lowkey_dir / "archetypes" / "governance.json"),
    str(lowkey_dir / "archetypes" / "nft.json"): sha256(lowkey_dir / "archetypes" / "nft.json"),
    str(lowkey_dir / "archetypes" / "escrow.json"): sha256(lowkey_dir / "archetypes" / "escrow.json"),
    str(lowkey_dir / "archetypes" / "proxy.json"): sha256(lowkey_dir / "archetypes" / "proxy.json"),
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
  - $TARGET_LOWKEY_DIR/shared_context.py
  - $TARGET_LOWKEY_DIR/fixture_context.py
  - $TARGET_LOWKEY_DIR/project_detection.py
  - $TARGET_LOWKEY_DIR/clone_tools.py
  - $TARGET_LOWKEY_DIR/audit_engine.py
  - $TARGET_LOWKEY_DIR/benchmark.py
  - $TARGET_LOWKEY_DIR/system_model.py
  - $TARGET_LOWKEY_DIR/project_tools.py
  - $TARGET_LOWKEY_DIR/lab_target_scope.py
  - $TARGET_LOWKEY_DIR/question_engine.py
  - $TARGET_LOWKEY_DIR/workflow_engine.py
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
  - $TARGET_LOWKEY_DIR/experience_memory.py
  - $TARGET_LOWKEY_DIR/walkthrough.py
  - $TARGET_LOWKEY_DIR/walkthrough_benchmarks.py
  - $TARGET_LOWKEY_DIR/walkthrough_finding_patterns.py
  - $TARGET_LOWKEY_DIR/break_playbook.py
  - $TARGET_LOWKEY_DIR/break_engine.py
  - $TARGET_LOWKEY_DIR/library_linker.py
  - $TARGET_LOWKEY_DIR/network_manager.py
  - $TARGET_LOWKEY_DIR/runtime_verification.py
  - $TARGET_LOWKEY_DIR/attack_library.py
  - $TARGET_LOWKEY_DIR/attack_catalog.py
  - $TARGET_LOWKEY_DIR/attack_engine.py
  - $TARGET_LOWKEY_DIR/attack_research.py
  - $TARGET_LOWKEY_DIR/attack_synthesis.py
  - $TARGET_LOWKEY_DIR/protocol_graph.py
  - $TARGET_LOWKEY_DIR/godmode.py
  - $TARGET_LOWKEY_DIR/multiwave_audit.py
  - $TARGET_LOWKEY_DIR/arithmetic_review.py
  - $TARGET_LOWKEY_DIR/templates/step_harness.sol.tmpl
  - $TARGET_LOWKEY_DIR/proof_evidence.py
  - $TARGET_LOWKEY_DIR/forge_state_diff.py
  - $TARGET_LOWKEY_DIR/trace_evidence.py
  - $TARGET_LOWKEY_DIR/trace_schema.py
  - $TARGET_LOWKEY_DIR/trace_parity.py
  - $TARGET_LOWKEY_DIR/storage_trace.py
  - $TARGET_LOWKEY_DIR/abi_support.py
  - $TARGET_LOWKEY_DIR/setup_reasoner.py
  - $TARGET_LOWKEY_DIR/foundry_ast_setup.py
  - $TARGET_LOWKEY_DIR/foundry_build.py
  - $TARGET_LOWKEY_DIR/workspace_tools.py
  - $TARGET_LOWKEY_DIR/source_risk.py
  - $TARGET_LOWKEY_DIR/finding_explainer.py
  - $TARGET_LOWKEY_DIR/block_tools.py
  - $TARGET_LOWKEY_DIR/opcode_intelligence.py
  - $TARGET_LOWKEY_DIR/token_economics.py
  - $TARGET_LOWKEY_DIR/proxy_engine.py
  - $TARGET_LOWKEY_DIR/eth_flow.py
  - $TARGET_LOWKEY_DIR/archetypes/__init__.py
  - $TARGET_LOWKEY_DIR/archetypes/_index.py
  - $TARGET_LOWKEY_DIR/archetypes/*.json
  - $TARGET_BIN_DIR/lk
  - $TARGET_LOWKEY_DIR/install-manifest.json

Run:
  lk --version
  lk doctor
  lk --help
EOF
