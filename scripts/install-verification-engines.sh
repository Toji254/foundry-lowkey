#!/usr/bin/env bash
set -euo pipefail

# Install the exact external-engine versions exercised by Lowkey's CI.
# Foundry is intentionally not installed or modified by this script.
# Supported target: Linux x86_64 (Fedora/Ubuntu and similar).

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "Error: this installer currently supports Linux x86_64 only." >&2
  exit 1
fi

for command_name in curl tar install find; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Error: required system command is missing: $command_name" >&2
    exit 1
  fi
done

LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"

# uv manages an isolated Python 3.12 runtime and keeps each Python tool's
# dependencies out of Lowkey's own runtime and Fedora's system Python.
if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv for the current user..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$LOCAL_BIN:$HOME/.cargo/bin:$PATH"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\\n' "$LOCAL_BIN" >> "${GITHUB_PATH}"
fi
if ! command -v uv >/dev/null 2>&1; then
  echo "Error: uv installation finished but 'uv' is not on PATH." >&2
  exit 1
fi

uv python install 3.12
uv tool install --python 3.12 --force slither-analyzer==0.11.6 --with crytic-compile==0.4.2
uv tool install --python 3.12 --force solc-select==1.2.0
uv tool install --python 3.12 --force halmos==0.3.3
uv tool install --python 3.12 --force certora-cli==8.20.2

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "Installing Echidna 2.3.3..."
curl -fL --retry 3 \
  https://github.com/crytic/echidna/releases/download/v2.3.3/echidna-2.3.3-x86_64-linux.tar.gz \
  -o "$tmp_dir/echidna.tar.gz"
mkdir -p "$tmp_dir/echidna"
tar -xzf "$tmp_dir/echidna.tar.gz" -C "$tmp_dir/echidna"
echidna_bin="$(find "$tmp_dir/echidna" -type f -name echidna -print -quit)"
if [[ -z "$echidna_bin" ]]; then
  echo "Error: Echidna archive did not contain the expected executable." >&2
  exit 1
fi
install -m 0755 "$echidna_bin" "$LOCAL_BIN/echidna"

echo "Installing Medusa 1.5.1..."
curl -fL --retry 3 \
  https://github.com/crytic/medusa/releases/download/v1.5.1/medusa-linux-x64.tar.gz \
  -o "$tmp_dir/medusa.tar.gz"
mkdir -p "$tmp_dir/medusa"
tar -xzf "$tmp_dir/medusa.tar.gz" -C "$tmp_dir/medusa"
medusa_bin="$(find "$tmp_dir/medusa" -type f -name medusa -print -quit)"
if [[ -z "$medusa_bin" ]]; then
  echo "Error: Medusa archive did not contain the expected executable." >&2
  exit 1
fi
install -m 0755 "$medusa_bin" "$LOCAL_BIN/medusa"

# Keep the compiler version used by the external-engine fixture available.
solc-select install 0.8.20
solc-select use 0.8.20

# Persist the local executable directory for new interactive Bash sessions.
bashrc="$HOME/.bashrc"
: >> "$bashrc"
marker="# Lowkey verification engines"
if [[ -f "$bashrc" ]] && ! grep -Fq "$marker" "$bashrc"; then
  {
    printf '\n%s\n' "$marker"
    printf '%s\n' 'export PATH="$HOME/.local/bin:$PATH"'
  } >> "$bashrc"
fi

export PATH="$LOCAL_BIN:$PATH"
echo
echo "Installed / validated pinned Lowkey verification tools:"
slither --version
solc-select --version
echidna --version
medusa --help >/dev/null
echo "Medusa: command starts successfully"
halmos --help >/dev/null
echo "Halmos: command starts successfully"
certoraRun --help >/dev/null
echo "Certora CLI: command starts successfully"
uv tool list

cat <<'EOF'

Setup note:
- Run 'lk verification engines --json' inside a Solidity/Foundry project to
  inspect which engines are available and compatible.
- Certora proof submission requires a Certora account/key exported as
  CERTORAKEY; installing the CLI does not itself run or prove a specification.
- For an 8 GB machine, start with the light profile. Halmos uses the deep
  profile and can consume substantially more memory.
EOF
