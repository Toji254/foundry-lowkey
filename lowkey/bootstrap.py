"""Repository-aware bootstrap, dependency repair, and build diagnostics.

Lowkey uses this layer before mutating a project. The layer deliberately separates:
  * where a project belongs to a workspace/package-manager boundary,
  * what dependency mechanism the repository itself declares,
  * whether a build failure is repairable as a dependency/tooling problem.

It never invents a new dependency or writes system-wide configuration.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Sequence


WORKSPACE_MARKERS = {
    "pnpm-workspace.yaml",
    "go.work",
}

PYTHON_LOCKS = {
    "uv.lock": "uv",
    "poetry.lock": "poetry",
    "Pipfile.lock": "pipenv",
}

RUNTIME_FILES = (
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".ruby-version",
    ".tool-versions",
    "rust-toolchain",
    "rust-toolchain.toml",
)

DEPENDENCY_FAILURE_PATTERNS = (
    r"node_modules[/\\]",
    r"\\b(?:@openzeppelin|@(?:nomicfoundation|chainlink|aave|uniswap|balancer)[^\\s]*)/",
    r"library .* not found",
    r"import .* not found",
    r"cannot find module",
    r"cannot find package",
    r"module .* not found",
    r"package .* not found",
    r"unresolved import",
    r"unresolved external",
    r"missing .* dependency",
    r"dependency .* missing",
    r"error while loading .* module",
    r"err_pnpm_",
    r"npm err!",
    r"yarn error",
    r"bun error",
)

TOOLCHAIN_FAILURE_PATTERNS = (
    r"unsupported .* version",
    r"requires? (?:python|node|rust|cairo|scarb|solidity)",
    r"minimum .* version",
    r"maximum .* version",
    r"engine .* incompatible",
    r"unsupported engine",
    r"incompatible .* version",
    r"version .* does not satisfy",
    r"compiler version",
    r"wrong compiler",
    r"rustc .* version",
    r"node.js .* version",
    r"python .* version",
    r"scarb .* version",
    r"cairo .* version",
)

CONFIG_FAILURE_PATTERNS = (
    r"invalid .* config",
    r"configuration .* error",
    r"config .* error",
    r"malformed .* config",
    r"parse error",
    r"toml .* error",
    r"yaml .* error",
    r"json .* error",
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _package_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_read(path / "package.json"))
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _has_workspace_config(root: Path) -> bool:
    if (root / "pnpm-workspace.yaml").is_file() or (root / "go.work").is_file():
        return True

    package = _package_json(root)
    if package.get("workspaces"):
        return True

    cargo = _read(root / "Cargo.toml")
    if re.search(r"(?m)^\s*\[workspace(?:\.[^]]+)?\]", cargo):
        return True

    pyproject = _read(root / "pyproject.toml")
    if re.search(r"(?m)^\s*\[tool\.uv\.workspace\]", pyproject):
        return True

    scarb = _read(root / "Scarb.toml")
    if re.search(r"(?m)^\s*\[workspace\]", scarb):
        return True

    return False


def workspace_root(start: str | os.PathLike[str] = ".") -> Path:
    """Find an explicit workspace root without promoting every nested project."""
    path = Path(start).expanduser().resolve()
    if path.is_file():
        path = path.parent

    current = path
    candidates = [current, *current.parents]
    nearest = path
    for candidate in candidates:
        if _has_workspace_config(candidate):
            nearest = candidate
            break
    return nearest


def _nearest_manifest(start: Path, names: Sequence[str]) -> Path | None:
    path = start.resolve()
    for candidate in (path, *path.parents):
        if any((candidate / name).is_file() for name in names):
            return candidate
    return None


def dependency_boundary(start: str | os.PathLike[str] = ".") -> Path:
    """Return the package/dependency installation boundary for a selected project.

    Explicit workspace roots win. Otherwise the project itself is the boundary.
    """
    path = Path(start).expanduser().resolve()
    if path.is_file():
        path = path.parent

    workspace = workspace_root(path)
    if workspace != path and _is_workspace_project(path, workspace):
        return workspace
    if workspace == path and _has_workspace_config(path):
        return path
    return path


def _is_workspace_project(project: Path, workspace: Path) -> bool:
    if project == workspace:
        return False

    package = _package_json(workspace)
    if package.get("workspaces") and (project / "package.json").is_file():
        return True

    if (workspace / "pnpm-workspace.yaml").is_file() and (
        (project / "package.json").is_file()
        or (project / "foundry.toml").is_file()
        or (project / "Scarb.toml").is_file()
        or (project / "Cargo.toml").is_file()
    ):
        return True

    cargo = _read(workspace / "Cargo.toml")
    if re.search(r"(?m)^\s*\[workspace(?:\.[^]]+)?\]", cargo):
        return (project / "Cargo.toml").is_file()

    go_work = workspace / "go.work"
    if go_work.is_file():
        return (project / "go.mod").is_file()

    uv = _read(workspace / "pyproject.toml")
    if re.search(r"(?m)^\s*\[tool\.uv\.workspace\]", uv):
        return (project / "pyproject.toml").is_file()

    scarb = _read(workspace / "Scarb.toml")
    if re.search(r"(?m)^\s*\[workspace\]", scarb):
        return (project / "Scarb.toml").is_file()

    return False


def _git_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return start.resolve()


def _declared_submodules(root: Path) -> list[tuple[str, str | None]]:
    text = _read(root / ".gitmodules")
    if not text:
        return []

    entries: list[tuple[str, str | None]] = []
    current: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[submodule "):
            if current.get("path"):
                entries.append((current["path"], current.get("url")))
            current = {}
            continue
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in {"path", "url"}:
            current[key] = value
    if current.get("path"):
        entries.append((current["path"], current.get("url")))
    return entries


def _tracked_gitlink(root: Path, relative: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--stage", "--", relative],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    return any(
        line.split(maxsplit=1)[0] == "160000"
        for line in result.stdout.splitlines()
        if line.strip()
    )


def _submodule_state(root: Path) -> dict[str, Any]:
    missing: list[str] = []
    orphaned: list[tuple[str, str]] = []
    entries = _declared_submodules(root)
    for relative, url in entries:
        path = root / relative
        try:
            initialized = path.is_dir() and any(path.iterdir())
        except OSError:
            initialized = False
        if not initialized:
            missing.append(relative)
        if url and not _tracked_gitlink(root, relative) and not initialized:
            orphaned.append((relative, url))
    return {
        "declared": len(entries),
        "missing": missing,
        "orphaned": orphaned,
    }


def _pnpm_major(lock_text: str) -> int | None:
    match = re.search(
        r"(?m)^\s*lockfileVersion\s*:\s*[\"']?([0-9]+)(?:\.[0-9]+)?",
        lock_text,
    )
    return int(match.group(1)) if match else None


def _node_install_command(root: Path) -> tuple[Path, list[str], str] | None:
    """Return install cwd, command, and evidence string."""
    boundary = dependency_boundary(root)
    package_path = boundary / "package.json"
    if not package_path.is_file():
        package_path = root / "package.json"
        boundary = root
    if not package_path.is_file():
        return None

    package = _package_json(boundary)
    declared = str(package.get("packageManager") or "").strip()

    def exact_manager(prefix: str) -> list[str] | None:
        match = re.match(rf"{re.escape(prefix)}@([0-9]+(?:\.[0-9]+){{0,2}})", declared.lower())
        if not match:
            return None
        version = match.group(1)
        if shutil.which("corepack"):
            return ["corepack", f"{prefix}@{version}", "install", "--frozen-lockfile"]
        return None

    if declared.lower().startswith("pnpm@"):
        command = exact_manager("pnpm")
        if command:
            return boundary, command, f"packageManager={declared}"
        return boundary, [], f"packageManager={declared}; Corepack is required to enforce this pin"
    if declared.lower().startswith("yarn@"):
        command = exact_manager("yarn")
        if command:
            return boundary, command, f"packageManager={declared}"
        return boundary, [], f"packageManager={declared}; Corepack is required to enforce this pin"
    if declared.lower().startswith("bun@"):
        if shutil.which("bun"):
            return boundary, ["bun", "install", "--frozen-lockfile"], f"packageManager={declared}"
        return boundary, [], f"packageManager={declared}; Bun is not installed"

    pnpm_lock = boundary / "pnpm-lock.yaml"
    if pnpm_lock.is_file():
        major = _pnpm_major(_read(pnpm_lock))
        if shutil.which("corepack"):
            if major == 6:
                return boundary, ["corepack", "pnpm@8", "install", "--frozen-lockfile"], "pnpm-lockfile v6"
            if major in {7, 8, 9, 10, 11}:
                return boundary, ["corepack", f"pnpm@{major}", "install", "--frozen-lockfile"], f"pnpm-lockfile v{major}"
        if shutil.which("pnpm"):
            return boundary, ["pnpm", "install", "--frozen-lockfile"], f"pnpm-lockfile v{major or 'unknown'}"

    yarn_lock = boundary / "yarn.lock"
    if yarn_lock.is_file():
        yarn_text = _read(yarn_lock)
        if shutil.which("yarn"):
            if re.search(r"^# yarn lockfile v1", yarn_text):
                return boundary, ["yarn", "install", "--frozen-lockfile"], "Yarn classic lockfile"
            return boundary, ["yarn", "install", "--immutable"], "Yarn modern lockfile"

    if (boundary / "bun.lockb").is_file() or (boundary / "bun.lock").is_file():
        if shutil.which("bun"):
            return boundary, ["bun", "install", "--frozen-lockfile"], "Bun lockfile"

    if (boundary / "package-lock.json").is_file() and shutil.which("npm"):
        return boundary, ["npm", "ci"], "package-lock.json"

    if shutil.which("npm"):
        return boundary, ["npm", "install"], "package.json without a lockfile"

    return boundary, [], "package.json found but no compatible package manager"


def _python_plan(root: Path) -> list[tuple[Path, list[str], str]]:
    plans: list[tuple[Path, list[str], str]] = []
    boundary = root
    pyproject = boundary / "pyproject.toml"
    if not pyproject.is_file():
        workspace = workspace_root(root)
        candidate = workspace / "pyproject.toml"
        if candidate.is_file() and re.search(r"(?m)^\s*\[tool\.uv\.workspace\]", _read(candidate)):
            boundary = workspace
            pyproject = candidate

    if pyproject.is_file():
        text = _read(pyproject)
        if (boundary / "uv.lock").is_file() or re.search(r"(?m)^\s*\[tool\.uv(?:\.|\])", text):
            if shutil.which("uv"):
                plans.append((boundary, ["uv", "sync", "--all-extras", "--dev"], "uv lock/configuration"))
                return plans
        if (boundary / "poetry.lock").is_file() and shutil.which("poetry"):
            plans.append((boundary, ["poetry", "install"], "poetry.lock"))
            return plans
        if (boundary / "Pipfile").is_file() and shutil.which("pipenv"):
            command = ["pipenv", "sync", "--dev"] if (boundary / "Pipfile.lock").is_file() else ["pipenv", "install", "--dev"]
            plans.append((boundary, command, "Pipfile"))
            return plans
        return plans

    requirement_files = [
        name for name in ("requirements.txt", "requirements-dev.txt")
        if (boundary / name).is_file()
    ]
    if not requirement_files:
        return plans

    venv = boundary / ".venv"
    python = venv / "bin" / "python"
    if not python.is_file():
        if shutil.which("python3"):
            plans.append((boundary, ["python3", "-m", "venv", str(venv)], "requirements -> project .venv"))
            # Installation follows in the same bootstrap run once the venv exists.
            pip = venv / "bin" / "python"
            commands = [str(pip), "-m", "pip", "install"]
        else:
            return [(boundary, [], "requirements found but python3 is unavailable")]
    else:
        commands = [str(python), "-m", "pip", "install"]

    for requirement in requirement_files:
        commands.extend(["-r", requirement])
    plans.append((boundary, commands, "requirements files -> project .venv"))
    return plans


def _workspace_commands(
    root: Path,
    info: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Plan only dependency systems relevant to the selected project."""
    actions: list[dict[str, Any]] = []
    backend = str((info or {}).get("backend") or "").lower()
    build_backend = str((info or {}).get("build_backend") or "").lower()
    languages = (info or {}).get("languages") or {}
    rust_relevant = backend in {"cargo", "rust"} or build_backend == "cargo" or bool(languages.get("rust"))
    go_relevant = backend == "go" or build_backend == "go" or bool(languages.get("go"))
    mix_relevant = backend in {"mix", "elixir"} or build_backend == "mix"
    maven_relevant = backend == "maven" or build_backend == "maven"
    gradle_relevant = backend == "gradle" or build_backend == "gradle"
    swift_relevant = backend == "swift" or build_backend == "swift"

    if rust_relevant:
        cargo_manifest = _nearest_manifest(root, ("Cargo.toml",))
        if cargo_manifest and (cargo_manifest / "Cargo.toml").is_file() and shutil.which("cargo"):
            actions.append({
                "kind": "cargo",
                "cwd": cargo_manifest,
                "command": (
                    ["cargo", "fetch", "--locked"]
                    if (cargo_manifest / "Cargo.lock").is_file()
                    else ["cargo", "fetch"]
                ),
                "evidence": "Cargo workspace/manifest",
            })

    if go_relevant:
        go_root = workspace_root(root)
        if (go_root / "go.work").is_file() and shutil.which("go"):
            actions.append({
                "kind": "go",
                "cwd": go_root,
                "command": ["go", "work", "sync"],
                "evidence": "go.work",
            })
        elif (root / "go.mod").is_file() and shutil.which("go"):
            actions.append({
                "kind": "go",
                "cwd": root,
                "command": ["go", "mod", "download"],
                "evidence": "go.mod",
            })

    if mix_relevant and (root / "mix.exs").is_file() and shutil.which("mix"):
        actions.append({
            "kind": "mix",
            "cwd": root,
            "command": ["mix", "deps.get"],
            "evidence": "mix.exs",
        })

    if maven_relevant or gradle_relevant or swift_relevant:
        # These ecosystems normally resolve dependencies as part of their
        # declared build command. Do not invent a separate package install.
        pass

    return actions

def runtime_requirements(root: str | os.PathLike[str] = ".") -> dict[str, str]:
    """Read project-declared runtime pins without changing the environment."""
    path = Path(root).expanduser().resolve()
    requirements: dict[str, str] = {}
    for filename in RUNTIME_FILES:
        value = _read(path / filename).strip()
        if value:
            requirements[filename] = value

    package = _package_json(path)
    engines = package.get("engines") if isinstance(package, dict) else None
    if isinstance(engines, dict):
        for key in ("node", "npm", "pnpm", "yarn"):
            if key in engines:
                requirements[f"package.engines.{key}"] = str(engines[key])

    pyproject = _read(path / "pyproject.toml")
    match = re.search(r"(?im)^\s*requires-python\s*=\s*[\"']([^\"']+)[\"']", pyproject)
    if match:
        requirements["pyproject.requires-python"] = match.group(1)

    return requirements



def _node_run_command(root: Path, script: str) -> list[str] | None:
    boundary = dependency_boundary(root)
    package = _package_json(root)
    manager_root = boundary if (boundary / "package.json").is_file() else root
    if not (manager_root / "package.json").is_file():
        return None
    declared = str(_package_json(manager_root).get("packageManager") or "").strip().lower()
    if declared.startswith(("pnpm@", "yarn@")):
        if shutil.which("corepack"):
            manager = declared.split("@", 1)[0]
            version = declared.split("@", 1)[1]
            return ["corepack", f"{manager}@{version}", "run", script]
        return None
    if (manager_root / "pnpm-lock.yaml").is_file() and shutil.which("pnpm"):
        return ["pnpm", "run", script]
    if (manager_root / "yarn.lock").is_file() and shutil.which("yarn"):
        return ["yarn", script]
    if ((manager_root / "bun.lockb").is_file() or (manager_root / "bun.lock").is_file()) and shutil.which("bun"):
        return ["bun", "run", script]
    if shutil.which("npm"):
        return ["npm", "run", script]
    return None


def project_build_command(
    info: dict[str, Any] | None = None,
    root: str | os.PathLike[str] = ".",
) -> tuple[Path, list[str], str] | None:
    """Select a native build command from the project's own manifests."""
    project = Path((info or {}).get("root") or root).expanduser().resolve()
    package = _package_json(project)
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    if isinstance(scripts, dict) and scripts.get("build"):
        command = _node_run_command(project, "build")
        if command:
            return project, command, "package.json scripts.build"

    backend = str((info or {}).get("backend") or (info or {}).get("kind") or "").lower()
    if backend in {"foundry", "multi-stack"} and (project / "foundry.toml").is_file():
        return project, ["forge", "build"], "foundry.toml"
    if backend in {"hardhat", "node"} or any(
        (project / name).is_file()
        for name in ("hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs", "hardhat.config.ts")
    ):
        boundary = dependency_boundary(project)
        binary = boundary / "node_modules" / ".bin" / "hardhat"
        if os.name == "nt":
            binary = binary.with_suffix(".cmd")
        if binary.is_file():
            return project, [str(binary), "compile"], "local Hardhat binary"
        return None
    if backend in {"cairo", "cairo-starknet"} and (project / "Scarb.toml").is_file():
        if shutil.which("scarb"):
            return project, ["scarb", "build"], "Scarb.toml"
        return None
    if backend in {"cargo", "rust"} and (project / "Cargo.toml").is_file() and shutil.which("cargo"):
        return project, ["cargo", "build", "--manifest-path", str(project / "Cargo.toml")], "Cargo.toml"
    if backend == "go" and ((project / "go.mod").is_file() or (project / "go.work").is_file()) and shutil.which("go"):
        return project, ["go", "build", "./..."], "Go workspace/module"
    if backend == "move":
        if shutil.which("aptos") and (project / "Move.toml").is_file():
            return project, ["aptos", "move", "compile"], "Aptos Move.toml"
        if shutil.which("sui") and (project / "Move.toml").is_file():
            return project, ["sui", "move", "build"], "Sui Move.toml"
        return None
    if backend == "solana-anchor" and shutil.which("anchor"):
        return project, ["anchor", "build"], "Anchor.toml"
    if backend == "brownie" and shutil.which("brownie"):
        return project, ["brownie", "compile"], "Brownie"
    if backend in {"mix", "elixir"} and (project / "mix.exs").is_file() and shutil.which("mix"):
        return project, ["mix", "compile"], "mix.exs"
    if (project / "mvnw").is_file() or (project / "pom.xml").is_file():
        executable = project / "mvnw" if (project / "mvnw").is_file() else shutil.which("mvn")
        if executable:
            return project, [str(executable), "test"], "Maven project"
    if (project / "gradlew").is_file() or (project / "build.gradle").is_file() or (project / "build.gradle.kts").is_file():
        executable = project / "gradlew" if (project / "gradlew").is_file() else shutil.which("gradle")
        if executable:
            return project, [str(executable), "build"], "Gradle project"
    if (project / "Package.swift").is_file() and shutil.which("swift"):
        return project, ["swift", "build"], "Package.swift"
    if (project / "Makefile").is_file():
        make_text = _read(project / "Makefile")
        if re.search(r"(?m)^\s*build\s*:", make_text) and shutil.which("make"):
            return project, ["make", "build"], "Makefile build target"
    return None

def bootstrap_plan(
    info: dict[str, Any] | None = None,
    root: str | os.PathLike[str] = ".",
    *,
    force: bool = False,
    reason: str = "prepare",
) -> dict[str, Any]:
    """Build a safe, repository-derived repair plan without executing it."""
    selected_root = Path((info or {}).get("root") or root).expanduser().resolve()
    dep_root = dependency_boundary(selected_root)
    repo_root = _git_root(selected_root)
    actions: list[dict[str, Any]] = []

    submodules = _submodule_state(repo_root) if (repo_root / ".gitmodules").is_file() else {
        "declared": 0,
        "missing": [],
        "orphaned": [],
    }
    if submodules["missing"]:
        if shutil.which("git"):
            actions.append({
                "kind": "git-submodule",
                "cwd": repo_root,
                "command": ["git", "submodule", "sync", "--recursive"],
                "evidence": f"{len(submodules['missing'])} incomplete declared submodule(s)",
            })
            actions.append({
                "kind": "git-submodule",
                "cwd": repo_root,
                "command": ["git", "submodule", "update", "--init", "--recursive", "--force"],
                "evidence": f"{len(submodules['missing'])} incomplete declared submodule(s)",
            })
        for relative, url in submodules["orphaned"]:
            actions.append({
                "kind": "git-submodule-recovery",
                "cwd": repo_root,
                "command": ["git", "clone", "--depth", "1", url, relative],
                "evidence": f"orphaned .gitmodules entry: {relative}",
            })

    node = _node_install_command(selected_root)
    if node:
        cwd, command, evidence = node
        if command and (force or not (cwd / "node_modules").is_dir()):
            actions.append({
                "kind": "node",
                "cwd": cwd,
                "command": command,
                "evidence": evidence,
            })

    for cwd, command, evidence in _python_plan(selected_root):
        if command and (force or not (cwd / ".venv").is_dir() or reason in {"dependency", "workspace"}):
            actions.append({
                "kind": "python",
                "cwd": cwd,
                "command": command,
                "evidence": evidence,
            })

    actions.extend(_workspace_commands(selected_root, info))

    return {
        "project_root": str(selected_root),
        "workspace_root": str(workspace_root(selected_root)),
        "dependency_root": str(dep_root),
        "repository_root": str(repo_root),
        "reason": reason,
        "runtime_requirements": runtime_requirements(selected_root),
        "actions": actions,
    }


def classify_build_failure(output: str | None, command: Sequence[str] = ()) -> dict[str, Any]:
    """Classify a failed build without claiming a source bug is a dependency bug."""
    text = str(output or "")
    lowered = text.lower()
    command_text = " ".join(str(item) for item in command)

    if any(re.search(pattern, lowered) for pattern in TOOLCHAIN_FAILURE_PATTERNS):
        return {
            "category": "toolchain_mismatch",
            "repairable": False,
            "reason": "The diagnostics indicate a runtime/compiler/tool version mismatch.",
        }
    if any(re.search(pattern, lowered) for pattern in CONFIG_FAILURE_PATTERNS):
        return {
            "category": "configuration",
            "repairable": False,
            "reason": "The diagnostics indicate an invalid or incompatible project configuration.",
        }
    if any(re.search(pattern, lowered) for pattern in DEPENDENCY_FAILURE_PATTERNS):
        return {
            "category": "dependency",
            "repairable": True,
            "reason": "The diagnostics indicate a missing or incomplete dependency/tooling tree.",
        }
    if re.search(r"(command not found|no such file|executable file not found)", lowered):
        return {
            "category": "missing_tool",
            "repairable": False,
            "reason": f"The build command itself is unavailable: {command_text or 'unknown command'}.",
        }
    if re.search(r"(workspace|workspaces|lockfile).*(root|boundary|member|package)", lowered):
        return {
            "category": "workspace_boundary",
            "repairable": True,
            "reason": "The diagnostics reference a workspace/package boundary.",
        }
    return {
        "category": "source_or_build_error",
        "repairable": False,
        "reason": "No repository-safe dependency repair signal was found.",
    }


def run_bootstrap(
    info: dict[str, Any] | None = None,
    root: str | os.PathLike[str] = ".",
    *,
    force: bool = False,
    reason: str = "prepare",
    timeout: int = 900,
) -> int:
    """Execute a previously reasoned repair plan."""
    plan = bootstrap_plan(info, root, force=force, reason=reason)
    actions = plan["actions"]

    print("\nLOWKEY PROJECT BOOTSTRAP")
    print("========================")
    print(f"Project          : {plan['project_root']}")
    print(f"Workspace root   : {plan['workspace_root']}")
    print(f"Dependency root  : {plan['dependency_root']}")
    if plan["runtime_requirements"]:
        print("Runtime pins     : " + ", ".join(
            f"{key}={value}" for key, value in plan["runtime_requirements"].items()
        ))

    if not actions:
        print("Status           : no repository-declared repair needed")
        return 0

    failures = 0
    for action in actions:
        command = action["command"]
        cwd = Path(action["cwd"])
        print(f"INFO  {action['kind']}: {' '.join(command)}")
        print(f"      evidence: {action['evidence']}")
        try:
            result = subprocess.run(
                command,
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                text=True,
                env={**os.environ, "CI": "1"},
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"FAIL  {action['kind']}: timed out after {timeout}s")
            failures = failures or 1
            continue
        except OSError as error:
            print(f"FAIL  {action['kind']}: {error}")
            failures = failures or 1
            continue

        if result.returncode != 0:
            print(f"FAIL  {action['kind']}: exit {result.returncode}")
            failures = failures or result.returncode or 1
        else:
            print(f"PASS  {action['kind']}")

    return failures


def bootstrap_status(
    info: dict[str, Any] | None = None,
    root: str | os.PathLike[str] = ".",
) -> dict[str, Any]:
    """Diagnostics-only view used by lk doctor."""
    plan = bootstrap_plan(info, root)
    return {
        **plan,
        "ready": not bool(plan["actions"]),
        "repairable": bool(plan["actions"]),
    }


__all__ = [
    "bootstrap_plan",
    "bootstrap_status",
    "classify_build_failure",
    "dependency_boundary",
    "run_bootstrap",
    "runtime_requirements",
    "workspace_root",
]
