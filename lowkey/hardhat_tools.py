#!/usr/bin/env python3
"""Hardhat lifecycle integration and project readiness checks for Lowkey.

Hardhat remains project-local. Build, test, and clean share the same safe
preflight for repository dependencies, local config, and runtime compatibility.
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


def _render_help(command: str | None = None) -> str:
    """Render actionable help for the Hardhat lifecycle commands."""
    pages = {
        "hardhat": {
            "what": "Initialize a Hardhat project or inspect/prepare an existing project's local Hardhat toolchain.",
            "when": "Use this for a repository that actually uses Hardhat. Normal build, test, and clean commands remain lk build, lk test, and lk clean.",
            "usage": "lk hardhat <init|doctor|prepare|deploy|clean>",
            "example": "lk hardhat doctor",
            "forms": [
                ("lk hardhat init", "Create a new Hardhat project with the minimal template. Refuses to overwrite an existing Hardhat config.", "lk hardhat init"),
                ("lk hardhat init --templates", "List initializer templates supported by the installed Hardhat initializer.", "lk hardhat init --templates"),
                ("lk hardhat doctor", "Show a read-only report of dependencies, local config, project Node pins, and Hardhat's Node engine range.", "lk hardhat doctor"),
                ("lk hardhat prepare", "Prepare repository-declared dependencies when the project-local Hardhat executable is missing. May create the initial lockfile when none exists.", "lk hardhat prepare"),
                ("lk hardhat deploy <script> --network <name> --target <Contract>", "Review and execute one direct-creation Hardhat 3 script against the selected managed Anvil network. Factory and proxy topologies remain blocked.", "lk hardhat deploy scripts/Deploy.mjs --network localhost --target Vault"),
                ("lk clean", "Clean generated build artifacts using the selected native cleaner. Foundry takes precedence in mixed Foundry/Hardhat projects.", "lk clean"),
            ],
            "options": [
                ("--template <NAME>", "Choose an initializer template. The default is minimal; use --templates to list available choices.", "lk hardhat init --template minimal"),
                ("--templates", "List available initializer templates without initializing the project.", "lk hardhat init --templates"),
                ("--esm", "Explicitly migrate an existing package.json to ESM. Lowkey first saves the original as .package.json.lowkey-pre-hardhat-esm; review existing JavaScript scripts because CommonJS files may need .cjs.", "lk hardhat init --esm"),
            ],
            "related": ("lk hardhat doctor", "lk build", "lk test", "lk clean", "lk project"),
            "notes": [
                "Hardhat remains a project-local dependency. Lowkey does not install a global Hardhat executable.",
                "Initialization is for a new Hardhat project. Existing hardhat.config.* files are not overwritten.",
                "Doctor is read-only. Prepare/build/test may install only dependencies declared by the repository and honor its lockfile.",
                "Hardhat deploy requires a local Hardhat 3 binary, a selected managed Anvil session, an HTTP network with remote accounts, and explicit PROBE and DEPLOY approval.",
            ],
        },
        "init": {
            "what": "Initialize a new Hardhat project through Hardhat's project initializer. The default template is minimal.",
            "when": "Use it once when starting a new Hardhat project that does not already have a hardhat.config.* file.",
            "usage": "lk hardhat init [--template NAME] [--esm]  |  lk hardhat init --templates",
            "example": "lk hardhat init --template minimal",
            "forms": [
                ("lk hardhat init", "Create a new project using the minimal template.", "lk hardhat init"),
                ("lk hardhat init --template <NAME>", "Create a project from a selected template.", "lk hardhat init --template minimal"),
                ("lk hardhat init --templates", "List available templates. Does not create the project.", "lk hardhat init --templates"),
            ],
            "options": [
                ("--template <NAME>", "Initializer template name. Defaults to minimal.", "lk hardhat init --template minimal"),
                ("--templates", "Show the template catalogue instead of creating a project.", "lk hardhat init --templates"),
                ("--esm", "Explicitly set an existing package.json to ESM after preserving its original contents in .package.json.lowkey-pre-hardhat-esm. This can affect existing .js scripts.", "lk hardhat init --esm"),
            ],
            "related": ("lk hardhat doctor", "lk build", "lk test"),
            "notes": [
                "Lowkey refuses to initialize over an existing Hardhat config.",
                "Hardhat is installed project-locally; Lowkey does not install a global Hardhat binary.",
                "If package.json is CommonJS, Hardhat 3 requires an explicit ESM migration decision. Lowkey does not silently change it.",
            ],
        },
        "doctor": {
            "what": "Inspect Hardhat project readiness without installing packages or changing project files.",
            "when": "Run it before your first build/test, after changing Node versions, or when a Hardhat command fails during setup.",
            "usage": "lk hardhat doctor",
            "example": "lk hardhat doctor",
            "forms": [
                ("lk hardhat doctor", "Report whether local Hardhat is present, required local config files exist, the project Node pin is met, and the installed Hardhat package's Node engine range is satisfied.", "lk hardhat doctor"),
            ],
            "options": [],
            "related": ("lk hardhat prepare", "lk build", "lk test", "lk clean"),
            "notes": [
                "Doctor is read-only: it does not create env.json, install dependencies, edit package.json, or switch Node versions.",
                "A Hardhat engine mismatch is reported as a warning; a project-declared Node pin that cannot be satisfied is a review blocker.",
                "The report checks only statically identifiable relative config imports. It cannot infer runtime-generated config requirements or supply secrets.",
            ],
        },
        "prepare": {
            "what": "Ensure a detected Hardhat project has its repository-local Hardhat executable and pass the shared readiness checks.",
            "when": "Use it explicitly when you want to prepare dependencies before running a build/test. lk build and lk test do this automatically.",
            "usage": "lk hardhat prepare",
            "example": "lk hardhat prepare",
            "forms": [
                ("lk hardhat prepare", "Check the project-local binary; if it is missing, prepare dependencies from the package manager and lockfile declared by the project.", "lk hardhat prepare"),
            ],
            "options": [],
            "related": ("lk hardhat doctor", "lk build", "lk test"),
            "notes": [
                "If package-lock.json exists, Lowkey uses the lockfile-based install. If no lockfile exists, it generates the initial lockfile before installing.",
                "This command may modify node_modules and create the initial lockfile when missing. It does not rewrite package.json or change dependency versions.",
                "If the project is not detected as Hardhat, Lowkey leaves the normal native command route unchanged.",
            ],
        },
        "clean": {
            "what": "Remove generated build artifacts using the native cleaner selected for the current project.",
            "when": "Run it from the selected project/package directory when you need to remove stale build artifacts before rebuilding. In a workspace, enter the member you intend to clean first.",
            "usage": "lk clean [NATIVE CLEANER OPTIONS]",
            "example": "lk clean",
            "forms": [
                ("lk clean", "Run the selected native cleaner. Hardhat projects use their project-local Hardhat binary; Foundry projects use Forge.", "lk clean"),
            ],
            "options": [
                ("[NATIVE CLEANER OPTIONS]", "No Lowkey-specific clean flags are defined. Extra arguments are passed unchanged to the selected native cleaner; use only flags supported by that tool.", "cd packages/protocol && lk clean"),
            ],
            "related": ("lk build", "lk test", "lk hardhat doctor", "lk project"),
            "notes": [
                "In a mixed Foundry/Hardhat repository, Foundry has cleaning precedence.",
                "On Hardhat projects, Lowkey may prepare missing declared dependencies and create the initial lockfile before cleaning. It may also copy a required example config only when Git ignores the destination.",
                "The native cleaner removes its generated artifacts/cache. Lowkey does not delete Solidity source files, package manifests, lockfiles, or existing local credentials/config.",
            ],
        },
    }
    page = pages.get(command or "hardhat", pages["hardhat"])
    title = "lk hardhat" if command is None or command == "hardhat" else (
        "lk clean" if command == "clean" else f"lk hardhat {command}"
    )
    lines = [
        f"LOWKEY HELP  •  {title}",
        "=" * 72,
        f"What it does: {page['what']}",
        f"When to use: {page['when']}",
        f"Usage: {page['usage']}",
        f"Example: {page['example']}",
        "",
        "COMMAND VARIATIONS",
        "------------------",
    ]
    for invocation, description, sample in page["forms"]:
        lines.extend([f"  {invocation}", f"      {description}", f"      Example: {sample}"])
    lines.extend(["", "OPTIONS / MODES", "---------------"])
    if page["options"]:
        for flag, description, sample in page["options"]:
            lines.extend([f"  {flag}", f"      {description}", f"      Example: {sample}"])
    else:
        lines.append("  No command-specific options. Only the standard help flags are accepted.")
    lines.extend(["", "RELATED COMMANDS", "----------------"])
    lines.extend(f"  {item}" for item in page["related"])
    lines.extend(["", "IMPORTANT NOTES", "---------------"])
    lines.extend(f"  {item}" for item in page["notes"])
    lines.extend([
        "",
        "HELP TIP",
        "  Help is read-only. It does not initialize, install, clean, deploy, or send transactions.",
        "  Accepted forms: --h, --help, -h, help.",
    ])
    return "\n".join(lines)


def run_init(argv: Sequence[str]) -> int:
    root = Path.cwd().resolve()
    values = list(argv)
    if any(str(value).lower() in {"-h", "--help", "--h", "help"} for value in values):
        print(_render_help("init"))
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
    code = project_detection.bootstrap_project(
        info, reason=reason, safe_node_install=True
    )
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



SENSITIVE_LOCAL_CONFIG_NAMES = {
    ".env",
    ".env.local",
    "env.json",
    "secrets.json",
    "credentials.json",
}
LOCAL_CONFIG_IMPORT_RE = re.compile(
    r"""(?:require\s*\(\s*|from\s+|import\s*)["'](\.{1,2}/[^"']+)["']"""
)


def _hardhat_config_paths(root: Path) -> list[Path]:
    return [root / name for name in CONFIG_NAMES if (root / name).is_file()]


def _sensitive_local_config(target: Path) -> bool:
    name = target.name.lower()
    return (
        name in SENSITIVE_LOCAL_CONFIG_NAMES
        or name.endswith((".local.json", ".local.env"))
    )


def _git_ignores_target(root: Path, target: Path) -> bool:
    """Only copy private config templates to a destination Git already ignores."""
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        if top.returncode != 0 or not top.stdout.strip():
            return False
        repository = Path(top.stdout.strip()).resolve()
        relative = target.resolve().relative_to(repository)
        ignored = subprocess.run(
            ["git", "-C", str(repository), "check-ignore", "-q", "--", relative.as_posix()],
            cwd=str(repository),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        return ignored.returncode == 0
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def _config_template_candidates(target: Path) -> list[Path]:
    if target.name.startswith("."):
        return [
            target.with_name(target.name + ".example"),
            target.with_name(target.name + ".sample"),
        ]
    return [
        target.with_name(f"{target.stem}.example{target.suffix}"),
        target.with_name(f"{target.stem}.sample{target.suffix}"),
        target.with_name(target.name + ".example"),
        target.with_name(target.name + ".sample"),
    ]


def _inspect_local_configuration(
    root: Path,
    *,
    create_ignored_templates: bool,
) -> tuple[bool, list[dict[str, str]]]:
    """Inspect static sensitive config imports; optionally copy safe ignored templates.

    The copy is exclusive, mode 0600, and never replaces an existing file.
    Lowkey does not synthesize values or print configuration contents.
    """
    findings: list[dict[str, str]] = []
    seen: set[Path] = set()
    for config in _hardhat_config_paths(root):
        try:
            source = config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in LOCAL_CONFIG_IMPORT_RE.finditer(source):
            imported = match.group(1)
            if not imported.lower().endswith((".json", ".env")):
                continue
            target = (config.parent / imported).resolve()
            try:
                target.relative_to(root.resolve())
            except ValueError:
                continue
            if not _sensitive_local_config(target) or target in seen:
                continue
            seen.add(target)

            if target.is_file():
                if target.suffix.lower() == ".json":
                    try:
                        json.loads(target.read_text(encoding="utf-8"))
                    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                        findings.append({
                            "status": "invalid",
                            "target": str(target.relative_to(root)),
                            "message": f"local config exists but is not valid JSON: {exc}",
                        })
                        continue
                findings.append({
                    "status": "existing",
                    "target": str(target.relative_to(root)),
                    "message": "required local configuration is present",
                })
                continue

            template = next(
                (
                    candidate for candidate in _config_template_candidates(target)
                    if candidate.is_file() and not candidate.is_symlink()
                ),
                None,
            )
            if template is None:
                findings.append({
                    "status": "missing",
                    "target": str(target.relative_to(root)),
                    "message": "required local configuration is missing and no example template was found",
                })
                continue

            if template.suffix.lower() == ".json":
                try:
                    payload = template.read_bytes()
                    json.loads(payload.decode("utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    findings.append({
                        "status": "invalid_template",
                        "target": str(target.relative_to(root)),
                        "template": str(template.relative_to(root)),
                        "message": f"example template is not valid JSON: {exc}",
                    })
                    continue
            else:
                try:
                    payload = template.read_bytes()
                except OSError as exc:
                    findings.append({
                        "status": "template_unreadable",
                        "target": str(target.relative_to(root)),
                        "template": str(template.relative_to(root)),
                        "message": f"cannot read example template: {exc}",
                    })
                    continue

            if not create_ignored_templates:
                findings.append({
                    "status": "template_available",
                    "target": str(target.relative_to(root)),
                    "template": str(template.relative_to(root)),
                    "message": "a matching example exists; the build path can copy it only if Git ignores the destination",
                })
                continue

            if not _git_ignores_target(root, target):
                findings.append({
                    "status": "not_ignored",
                    "target": str(target.relative_to(root)),
                    "template": str(template.relative_to(root)),
                    "message": "refusing to create local credentials/config because Git does not ignore the destination",
                })
                continue

            descriptor = None
            try:
                descriptor = os.open(
                    str(target),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = None
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                findings.append({
                    "status": "copied",
                    "target": str(target.relative_to(root)),
                    "template": str(template.relative_to(root)),
                    "message": "copied example to Git-ignored local config with mode 0600; review placeholders before network/deployment actions",
                })
            except FileExistsError:
                findings.append({
                    "status": "existing",
                    "target": str(target.relative_to(root)),
                    "message": "local configuration appeared during preparation; it was not overwritten",
                })
            except OSError as exc:
                findings.append({
                    "status": "copy_failed",
                    "target": str(target.relative_to(root)),
                    "template": str(template.relative_to(root)),
                    "message": f"could not create local config safely: {exc}",
                })
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    ready = all(item["status"] in {"existing", "copied"} for item in findings)
    return ready, findings


def _hardhat_package_metadata(root: Path, binary: Path | None) -> dict | None:
    candidates: list[Path] = []
    if binary is not None:
        try:
            candidates.extend(parent / "package.json" for parent in binary.resolve().parents)
        except OSError:
            pass
    boundary = bootstrap.dependency_boundary(root)
    candidates.extend([
        boundary / "node_modules" / "hardhat" / "package.json",
        root / "node_modules" / "hardhat" / "package.json",
    ])
    seen: set[Path] = set()
    for candidate in candidates:
        candidate = candidate.resolve()
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("name") == "hardhat":
            return data
    return None


def _hardhat_runtime_status(root: Path, binary: Path | None) -> dict:
    """Compare the active Node runtime with the installed Hardhat package's engines."""
    package = _hardhat_package_metadata(root, binary)
    if package is None:
        return {"status": "unknown", "message": "installed Hardhat package metadata could not be located"}
    engines = package.get("engines") if isinstance(package.get("engines"), dict) else {}
    required = engines.get("node")
    if not required:
        return {
            "status": "unknown",
            "hardhat_version": package.get("version"),
            "message": "this Hardhat package does not declare a Node engine range",
        }

    try:
        env, _pin = bootstrap.runtime_environment(root)
        node = shutil.which("node", path=env.get("PATH"))
        if not node:
            return {"status": "unknown", "message": "Node.js executable could not be resolved"}
        result = subprocess.run(
            [node, "--version"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=8,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "unknown", "message": f"could not inspect Node.js runtime: {exc}"}

    actual_text = (result.stdout or result.stderr).strip()
    actual = _parse_version(actual_text)
    if result.returncode != 0 or actual is None:
        return {"status": "unknown", "message": "Node.js version could not be determined"}
    compatible = bootstrap._node_satisfies(actual_text, str(required))
    version = str(package.get("version") or "unknown")
    if compatible:
        return {
            "status": "compatible",
            "node": actual_text,
            "hardhat_version": version,
            "engine": str(required),
            "message": f"Node {actual_text} satisfies Hardhat {version} engine range {required}",
        }
    return {
        "status": "warning",
        "node": actual_text,
        "hardhat_version": version,
        "engine": str(required),
        "message": (
            f"Node {actual_text} is outside Hardhat {version}'s declared Node range {required}. "
            "This is a compatibility warning, not proof that compilation will fail. "
            "Lowkey will not downgrade or switch Node automatically."
        ),
    }


def prepare_readiness(root: Path, binary: Path) -> int:
    """Run safe Hardhat preflight checks shared by build, test, and clean."""
    root = root.expanduser().resolve()
    print("\nLOWKEY PROJECT READINESS")
    print("========================")
    print(f"Project : {root}")
    # An explicit project Node pin is a hard project requirement. Hardhat's
    # own engines.node range is checked separately below and remains advisory
    # so historical audit toolchains are not silently replaced or blocked.
    try:
        pin_status = bootstrap.node_runtime_status(root)
    except Exception as exc:
        print(f"REVIEW NEEDED: could not inspect the project's declared Node pin: {exc}", file=sys.stderr)
        return 2
    if not pin_status.get("matched", True):
        required = pin_status.get("required") or "the declared Node runtime"
        print(
            f"REVIEW NEEDED: project Node requirement {required} cannot be satisfied by an already-installed runtime. "
            "Lowkey will not download or switch Node versions automatically.",
            file=sys.stderr,
        )
        return 2

    ready, findings = _inspect_local_configuration(
        root, create_ignored_templates=True
    )
    for item in findings:
        status = {
            "existing": "PASS",
            "copied": "PREPARED",
            "template_available": "READY TO PREPARE",
        }.get(item["status"], "REVIEW NEEDED")
        print(f"{status:<16} {item['target']}: {item['message']}")
        if item.get("template"):
            print(f"                 template: {item['template']}")
    if not findings:
        print("PASS             no missing sensitive local config imports detected")

    runtime = _hardhat_runtime_status(root, binary)
    if runtime["status"] == "warning":
        print(f"WARN             {runtime['message']}", file=sys.stderr)
    elif runtime["status"] == "compatible":
        print(f"PASS             {runtime['message']}")
    else:
        print(f"WARN             {runtime['message']}", file=sys.stderr)

    if not ready:
        print(
            "REVIEW NEEDED: Hardhat configuration prerequisites are incomplete. "
            "No existing local file was overwritten and no credentials were invented.",
            file=sys.stderr,
        )
        return 2
    return 0


def run_doctor(argv: Sequence[str] = ()) -> int:
    """Read-only Hardhat readiness report; never installs or writes project files."""
    if any(str(value).lower() in {"-h", "--h", "--help", "help"} for value in argv):
        print(_render_help("doctor"))
        return 0
    if argv:
        print("Usage: lk hardhat doctor", file=sys.stderr)
        return 2

    root, info = _selected_project()
    try:
        is_hardhat = bootstrap._is_hardhat_scope(info, root)
    except Exception:
        is_hardhat = False
    if not is_hardhat:
        print("This directory is not detected as a Hardhat project.", file=sys.stderr)
        return 3

    print("\nLOWKEY HARDHAT DOCTOR")
    print("====================")
    print(f"Project : {root}")
    binary = _local_hardhat(root)
    if binary is None:
        print("MISSING  project-local Hardhat executable")
        plan = bootstrap.bootstrap_status(info, root)
        for action in plan.get("actions", []):
            print(f"PLAN     {' '.join(str(part) for part in action.get('command', []))}")
            print(f"         {action.get('evidence', '')}")
    else:
        print(f"PASS     project-local Hardhat: {binary}")

    _config_ready, findings = _inspect_local_configuration(
        root, create_ignored_templates=False
    )
    for item in findings:
        status = "PASS" if item["status"] == "existing" else (
            "REPAIRABLE" if item["status"] == "template_available" else "REVIEW"
        )
        print(f"{status:<10} {item['target']}: {item['message']}")
        if item.get("template"):
            print(f"           template: {item['template']}")
    if not findings:
        print("PASS     no missing sensitive local config imports detected")

    try:
        pin_status = bootstrap.node_runtime_status(root)
    except Exception as exc:
        pin_status = {"matched": False, "required": "declared runtime", "error": str(exc)}
    if not pin_status.get("matched", True):
        print(
            f"REVIEW     project Node pin {pin_status.get('required') or 'declared runtime'} "
            "is not satisfied by an installed Node runtime"
        )

    runtime = _hardhat_runtime_status(root, binary) if binary is not None else {
        "status": "unknown",
        "message": "runtime compatibility cannot be checked until local Hardhat is installed",
    }
    print(f"{'WARN' if runtime['status'] in {'warning', 'unknown'} else 'PASS'}     {runtime['message']}")
    print("\nNo files were changed. Run 'lk build' or 'lk test' for safe automatic preparation.")
    return 0

def run_prepare(argv: Sequence[str] = (), *, reason: str = "test") -> int:
    """Ensure a Hardhat project is ready before delegating to Lowkey's native router.

    Exit code 3 means this is not a Hardhat project; the launcher should keep
    using its existing native command router.
    """
    if any(str(value).lower() in {"-h", "--h", "--help", "help"} for value in argv):
        print(_render_help("prepare"))
        return 0
    if argv:
        print("lk hardhat prepare does not accept command-specific options.", file=sys.stderr)
        print("Usage: lk hardhat prepare", file=sys.stderr)
        return 2

    root, info = _selected_project()
    try:
        hardhat_scope = bootstrap._is_hardhat_scope(info, root)
    except Exception:
        hardhat_scope = False
    if not hardhat_scope:
        return 3

    _root, _info, _binary, code = _ensure_hardhat_binary(root, info, reason=reason)
    if code != 0 or _binary is None:
        return code or 2
    return prepare_readiness(_root, _binary)


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
    if any(str(value).lower() in {"-h", "--help", "--h", "help"} for value in argv):
        print(_render_help("clean"))
        return 0
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

    readiness_code = prepare_readiness(root, binary)
    if readiness_code != 0:
        return readiness_code

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
    if command == "deploy":
        from hardhat_deployment import run_deploy_cli
        return run_deploy_cli(rest, hardhat_tools=sys.modules[__name__])
    if command == "init":
        return run_init(rest)
    if command == "clean":
        return run_clean(rest)
    if command == "prepare":
        return run_prepare(rest)
    if command == "doctor":
        return run_doctor(rest)
    print(f"Unknown lk hardhat command: {command}", file=sys.stderr)
    print(_render_help(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
