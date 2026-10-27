#!/usr/bin/env bash
set -euo pipefail

# Optional per-user integration for the custom lh shell toolbox.
# This does not run during Lowkey installation; the user opts in by invoking it.
RC_FILE="${HOME}/.bashrc"
if [[ ! -f "$RC_FILE" ]]; then
  touch "$RC_FILE"
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
MENU_FILE=""

# Search common Bash config locations for the distinctive Lowkey toolbox menu line.
CANDIDATES=(
  "$RC_FILE"
  "$HOME/.bash_aliases"
  "$HOME/.bash_functions"
  "$HOME/.config/lowkey/shell-toolbox.sh"
  "$HOME/.config/lowkey/lh.sh"
)
for candidate in "${CANDIDATES[@]}"; do
  if [[ -f "$candidate" ]] && grep -Fq "solfind PATTERN [DIR]" "$candidate"; then
    MENU_FILE="$candidate"
    break
  fi
done

if [[ -n "$MENU_FILE" ]]; then
  cp -p "$MENU_FILE" "${MENU_FILE}.backup-jev-${STAMP}"
  python3 - "$MENU_FILE" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
content = path.read_text(encoding="utf-8")
if "jevup          Start Jevos-v5 in the background through Lowkey" not in content:
    lines = content.splitlines()
    marker_index = next((i for i, line in enumerate(lines) if "solfind PATTERN [DIR]" in line), None)
    if marker_index is None:
        raise SystemExit("Found the shell menu file but could not locate its Development section.")
    lines[marker_index + 1:marker_index + 1] = [
        "  jevup          Start Jevos-v5 in the background through Lowkey",
        "  jevdn          Stop Lowkey-managed Jevos-v5",
        "  jevrestart     Restart Lowkey-managed Jevos-v5",
        "  jevstat        Show Jev provider and local server status",
    ]
    path.write_text("\n".join(lines) + ("\n" if content.endswith("\n") else ""), encoding="utf-8")
PY
  printf 'Updated your lh menu in: %s\n' "$MENU_FILE"
  printf 'Backup: %s.backup-jev-%s\n' "$MENU_FILE" "$STAMP"
else
  printf 'Could not locate the lh menu text in common Bash config files.\n'
  printf 'The shell shortcuts will still be installed; menu entries need to be added manually to the file defining lh.\n'
fi

MARKER="# >>> Lowkey Jevos shell shortcuts >>>"
if ! grep -Fq "$MARKER" "$RC_FILE"; then
  cp -p "$RC_FILE" "${RC_FILE}.backup-jev-${STAMP}"
  cat >> "$RC_FILE" <<'EOF'

# >>> Lowkey Jevos shell shortcuts >>>
jevup() { lk ai jev start "$@"; }
jevdn() { lk ai jev stop "$@"; }
jevrestart() { lk ai jev restart "$@"; }
jevstat() { lk ai jev status "$@"; }
# <<< Lowkey Jevos shell shortcuts <<<
EOF
  printf 'Installed Jevos shell shortcuts in %s\n' "$RC_FILE"
else
  printf 'Jevos shell shortcuts already exist in %s\n' "$RC_FILE"
fi

printf '\nReload your shell settings with: source ~/.bashrc\n'
printf 'Then use: jevup | jevstat | jevrestart | jevdn\n'
