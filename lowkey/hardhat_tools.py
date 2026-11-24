#!/usr/bin/env python3
"""Hardhat lifecycle integration for Lowkey.

Hardhat remains project-local. This module only initializes a project and
routes operations that need Hardhat-specific handling; build/test continue
through Lowkey's existing repository-native project planner.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import bootstrap
import forge_tools
import project_detection

MIN_NODE = (22, 13, 0)
CONFIG_NAMES = tuple(getattr(bootstrap, "HARDHAT_CONFIG_NAMES", (
    "hardhat.config.js",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
    "hardhat.config.ts",
)))
IGNORED_JS_DIRS = {
    ".git", ".lowkey", ".audit", ".venv", "venv", "node_modules",
    "artifacts", "cache", "out", "dist", "build",
}


def _parse_version(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)", str(value or ""))
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _node_context(root: Path) -> tuple[dict[str, str] | None, str | None]:
    """Resolve an already-installed Node runtime and enforce Hardhat 3's floor."""
    try:
        env, _required = bootstrap.runtime_environment(root)
    except Exception as exc:
        return None, f"Could not resolve this project's Node environment: {exc}"

    node = shutil.which("node", path=env.get("PATH"))
    if not node:
        return None, "Node.js was not found in this project's environment. Install Node.js 22.13.0 or newer."
    try:
        result = subprocess.run(
            [node, "--version"],
            capture_output=True,
            text=True,
            timeout=8,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"Could not inspect Node.js at {node}: {exc}"
    version = _parse_version(result.stdout or result.stderr)
    if result.returncode != 0 or version is None:
        return None, f"Could not determine the Node.js version from {node}."
    if version < MIN_NODE:
        actual = ".".join(map(str, version))
        return None, (
            f"Hardhat 3 requires Node.js 22.13.0 or newer; this project resolves to Node.js {actual}.\n"
            "Switch to an installed compatible runtime (for example: nvm install 24 && nvm use 24), "
            "then rerun the LK command. Lowkey will not download or switch Node versions automatically."
        )

    try:
        status = bootstrap.node_runtime_status(root)
    except Exception:
        status = {"matched": True}
    if not status.get("matched", True):
        required = status.get("required") or "the declared project version"
        return None, (
            f"Project runtime pin {required} cannot be satisfied by an already-installed Node runtime. "
            "Lowkey will not install a runtime or ignore the pin."
        )
    return env, None


def _package_data(root: Path) -> tuple[dict, str | None]:
    path = root / "package.json"
    if not path.is_file():
        return {}, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, f"Cannot safely read {path}: {exc}"
    if not isinstance(data, dict):
        return {}, f"{path} must contain a JSON object."
    return data, None


def _backup_and_enable_esm(root: Path) -> tuple[bool, str | None]:
    """Make the required ESM migration only after preserving the original file."""
    package_path = root / "package.json"
    if not package_path.is_file():
        return True, None
    data, error = _package_data(root)
    if error:
        return False, error
    if data.get("type") == "module":
        return True, None

    backup = root / ".package.json.lowkey-pre-hardhat-esm"
    if backup.exists():
        return False, (
            f"Refusing to overwrite the existing backup {backup}. "
            "Review it before retrying the ESM migration."
        )
    try:
        original = package_path.read_bytes()
        # Exclusive creation protects an existing user file from overwrite.
        with backup.open("xb") as handle:
            handle.write(original)
        data["type"] = "module"
        payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        fd, temporary = tempfile.mkstemp(
            prefix=".package.json.lowkey-",
            suffix=".tmp",
            dir=str(root),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, package_path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    except OSError as exc:
        return False, f"Could not prepare the ESM package configuration: {exc}"
    print(f"ESM enabled in {package_path}")
    print(f"Original package.json backed up to {backup}")
    print("Review existing .js scripts: CommonJS files may need the .cjs extension.")
    return True, None


def _local_hardhat(root: Path) -> Path | None:
    try:
        return bootstrap._local_hardhat_binary(root)
    except Exception:
        return None


def _command_prefix(root: Path, env: dict[str, str]) -> tuple[list[str] | None, str | None]:
    """Use the project's manager for ephemeral Hardhat bootstrap, never a global binary."""
    local = _local_hardhat(root)
    if local is not None:
        try:
            result = subprocess.run(
                [str(local), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, f"Could not inspect the local Hardhat installation: {exc}"
        version = _parse_version(result.stdout or result.stderr)
        if result.returncode != 0 or version is None or version[0] < 3:
            found = (result.stdout or result.stderr or "unknown version").strip()
            return None, (
                f"Project-local Hardhat is not a working Hardhat 3 installation ({found}). "
                "Upgrade it deliberately with your project's package manager before initializing."
            )
        return [str(local)], None

    package, error = _package_data(root)
    if error:
        return None, error
    package_manager = str(package.get("packageManager") or "").lower()
    if package_manager.startswith("pnpm@") or (root / "pnpm-lock.yaml").is_file():
        executable = shutil.which("pnpm", path=env.get("PATH"))
        if not executable:
            return None, "This project declares pnpm, but pnpm is not available in the resolved environment."
        return [executable, "dlx", "hardhat@^3"], None
    if package_manager.startswith("yarn@") or (root / "yarn.lock").is_file():
        executable = shutil.which("yarn", path=env.get("PATH"))
        if not executable:
            return None, "This project declares Yarn, but yarn is not available in the resolved environment."
        try:
            version_result = subprocess.run(
                [executable, "--version"],
                capture_output=True,
                text=True,
                timeout=8,
                env=env,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, f"Could not inspect the Yarn version: {exc}"
        yarn_version = _parse_version(version_result.stdout or version_result.stderr)
        if version_result.returncode != 0 or yarn_version is None or yarn_version[0] < 2:
            return None, (
                "Yarn Classic does not provide 'yarn dlx'. Use npm for this project "
                "or upgrade the declared package manager to Yarn 2+ before initializing."
            )
        return [executable, "dlx", "hardhat@^3"], None
    if (root / "bun.lock").is_file() or (root / "bun.lockb").is_file():
        executable = shutil.which("bunx", path=env.get("PATH"))
        if not executable:
            return None, "This project declares Bun, but bunx is not available in the resolved environment."
        return [executable, "--yes", "hardhat@^3"], None

    executable = shutil.which("npx", path=env.get("PATH"))
    if not executable:
        return None, "npx was not found. Install npm with Node.js 22.13.0 or newer."
    return [executable, "--yes", "--package=hardhat@^3", "hardhat"], None


def _run(command: Sequence[str], root: Path, env: dict[str, str]) -> int:
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(root),
            env=env,
            check=False,
        )
    except OSError as exc:
        print(f"Could not execute {' '.join(map(str, command))}: {exc}", file=sys.stderr)
        return 1
    return int(completed.returncode or 0)


def _render_help() -> str:
    return "\n".join([
        "LOWKEY HELP  •  lk hardhat",
        "=" * 64,
        "",
        "  lk hardhat init [--template NAME] [--esm]",
        "  lk hardhat init --templates",
        "",
        "Initializes Hardhat 3 in the current directory. The default template is",
        "'minimal'. Hardhat remains a project-local dependency; Lowkey does not",
        "install a global Hardhat executable.",
        "",
        "--esm  Explicitly migrate an existing package.json to ESM. Lowkey first",
        "       preserves the original as .package.json.lowkey-pre-hardhat-esm.",
        "       Review existing .js files because CommonJS scripts may need .cjs.",
        "",
        "After initialization, use the normal Lowkey commands:",
        "  lk build",
        "  lk test",
        "  lk clean",
    ])


def run_init(argv: Sequence[str]) -> int:
    root = Path.cwd().resolve()
    values = list(argv)
    if any(value in {"-h", "--help", "--h"} for value in values):
        print(_render_help())
        return 0

    allow_esm = "--esm" in values
    values = [value for value in values if value != "--esm"]
    list_templates = "--templates" in values
    if list_templates:
        if len(values) != 1:
            print("Usage: lk hardhat init --templates", file=sys.stderr)
            return 2
    else:
        template = "minimal"
        if "--template" in values:
            index = values.index("--template")
            if index + 1 >= len(values):
                print("Missing template name after --template.", file=sys.stderr)
                return 2
            template = values[index + 1]
            values[index:index + 2] = []
        elif any(value.startswith("--template=") for value in values):
            selected = next(value for value in values if value.startswith("--template="))
            template = selected.split("=", 1)[1]
            values.remove(selected)
        if values:
            print("Unsupported LK initializer arguments: " + " ".join(values), file=sys.stderr)
            print("Use: lk hardhat init [--template NAME] [--esm]", file=sys.stderr)
            return 2

    if not list_templates and bootstrap._hardhat_config_present(root):
        print(f"Hardhat is already configured in {root}. Use lk build, lk test, or lk clean.", file=sys.stderr)
        return 2

    env, error = _node_context(root)
    if error:
        print(error, file=sys.stderr)
        return 2
    assert env is not None

    if not list_templates:
        package, package_error = _package_data(root)
        if package_error:
            print(package_error, file=sys.stderr)
            return 2
        if (root / "package.json").is_file() and package.get("type") != "module":
            if not allow_esm:
                current = package.get("type") or "not declared"
                print(
                    f"Hardhat 3 requires an ESM project, but package.json has type={current!r}.",
                    file=sys.stderr,
                )
                print(
                    "Review your existing Node.js scripts, then rerun 'lk hardhat init --esm' "
                    "to back up package.json and enable ESM, or set type=module yourself.",
                    file=sys.stderr,
                )
                return 2
            changed, migration_error = _backup_and_enable_esm(root)
            if not changed:
                print(migration_error, file=sys.stderr)
                return 2

    prefix, error = _command_prefix(root, env)
    if error:
        print(error, file=sys.stderr)
        return 2
    assert prefix is not None

    init_args = ["--init", "--templates"] if list_templates else [
        "--init", "--template", template,
    ]
    command = [*prefix, *init_args]
    print("LOWKEY HARDHAT INITIALIZATION")
    print("============================")
    print(f"Project  : {root}")
    print(f"Runtime  : {shutil.which('node', path=env.get('PATH'))}")
    print(f"Template : {'list available templates' if list_templates else template}")
    print(f"Command  : {' '.join(command)}")
    code = _run(command, root, env)
    if code != 0 or list_templates:
        return code

    local = _local_hardhat(root)
    if not bootstrap._hardhat_config_present(root) or local is None:
        print(
            "Hardhat's initializer returned success, but Lowkey could not verify both "
            "a Hardhat config file and the project-local Hardhat executable.",
            file=sys.stderr,
        )
        print("RESULT: REVIEW NEEDED — initialization is incomplete.", file=sys.stderr)
        return 2

    print("\nHARDHAT INITIALIZED")
    print("Backend : Hardhat 3 (project-local)")
    print("Next    : lk build | lk test | lk clean")
    return 0


def _selected_project() -> tuple[Path, dict]:
    start = Path.cwd().resolve()
    try:
        info = project_detection.detect_project(start)
    except Exception:
        info = {}
    root_value = info.get("root") if isinstance(info, dict) else None
    if root_value:
        root = Path(root_value).expanduser().resolve()
    else:
        root = project_detection.project_root(start).resolve()
    if not isinstance(info, dict):
        info = {}
    info = dict(info)
    info["root"] = str(root)
    return root, info


def _ensure_hardhat_binary(
    root: Path,
    info: dict,
    *,
    reason: str,
) -> tuple[Path, dict, Path | None, int]:
    """Prepare repository-declared dependencies once when local Hardhat is absent."""
    binary = _local_hardhat(root)
    if binary is not None:
        return root, info, binary, 0

    print(
        f"Hardhat was detected for {root}, but its project-local executable is missing."
    )
    print(
        "Lowkey is preparing the dependencies declared by this project. "
        "An existing lockfile is honored; without one, the package manager "
        "will resolve package.json ranges and create the initial lockfile."
    )
    code = project_detection.bootstrap_project(info, reason=reason)
    if code != 0:
        return root, info, None, code

    root, info = _selected_project()
    binary = _local_hardhat(root)
    if binary is None:
        print(
            "REVIEW NEEDED: dependency preparation completed, but the "
            "repository-local Hardhat executable is still missing.",
            file=sys.stderr,
        )
        return root, info, None, 2
    return root, info, binary, 0


def run_prepare(argv: Sequence[str] = (), *, reason: str = "test") -> int:
    """Ensure a Hardhat project is ready before delegating to Lowkey's native router.

    Exit code 3 means this is not a Hardhat project; the launcher should keep
    using its existing native command router.
    """
    if any(str(value).lower() in {"-h", "--h", "--help", "help"} for value in argv):
        print("Usage: lk hardhat prepare")
        print("Prepares declared project dependencies only when the local Hardhat binary is missing.")
        return 0

    root, info = _selected_project()
    try:
        hardhat_scope = bootstrap._is_hardhat_scope(info, root)
    except Exception:
        hardhat_scope = False
    if not hardhat_scope:
        return 3

    _root, _info, _binary, code = _ensure_hardhat_binary(root, info, reason=reason)
    return code


def _execution_environment(root: Path) -> tuple[dict[str, str] | None, str | None]:
    """Resolve the project's declared Node runtime without imposing Hardhat 3's floor."""
    try:
        env, pin = bootstrap.runtime_environment(root)
        status = bootstrap.node_runtime_status(root)
    except Exception as exc:
        return None, f"Could not resolve this project's Node environment: {exc}"
    if not status.get("matched", True):
        required = status.get("required") or pin or "the declared project Node version"
        return None, (
            f"Project runtime pin {required} cannot be satisfied by an already-installed Node runtime. "
            "Lowkey will not install or switch Node versions automatically."
        )
    return env, None


def run_clean(argv: Sequence[str]) -> int:
    root, info = _selected_project()
    backend = str(info.get("backend") or info.get("kind") or "").lower()
    stacks = {str(value).lower() for value in (info.get("stacks") or [])}
    foundry_scope = (
        (root / "foundry.toml").is_file()
        or backend in {"foundry", "mixed-foundry-vyper"}
        or "foundry" in stacks
    )

    # Foundry keeps its existing implementation and precedence in mixed repos.
    if foundry_scope:
        return forge_tools.main(["clean", *list(argv)])

    try:
        hardhat_scope = bootstrap._is_hardhat_scope(info, root)
    except Exception:
        hardhat_scope = False
    if not hardhat_scope:
        return forge_tools.main(["clean", *list(argv)])

    root, info, binary, prepare_code = _ensure_hardhat_binary(
        root, info, reason="clean"
    )
    if prepare_code != 0:
        return prepare_code
    assert binary is not None

    env, error = _execution_environment(root)
    if error:
        print(error, file=sys.stderr)
        return 2
    assert env is not None
    command = [str(binary), "clean", *list(argv)]
    print("LOWKEY NATIVE COMMAND")
    print("=====================")
    print(f"Project : {root}")
    print(f"Backend : Hardhat")
    print(f"Command : {' '.join(command)}")
    return _run(command, root, env)


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if not values or values[0] in {"-h", "--help", "--h", "help"}:
        print(_render_help())
        return 0
    command, rest = values[0], values[1:]
    if command == "init":
        return run_init(rest)
    if command == "clean":
        return run_clean(rest)
    if command == "prepare":
        return run_prepare(rest)
    print(f"Unknown lk hardhat command: {command}", file=sys.stderr)
    print(_render_help(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
