#!/usr/bin/env python3
"""Fast, cache-aware Git cloning for Lowkey audit workspaces."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse

CONFIG_DIR = Path(os.path.expanduser("~/.lowkey"))
CACHE_DIR = CONFIG_DIR / "cache"
REPO_CACHE_DIR = CACHE_DIR / "repos"


def die(message: str, code: int = 2) -> int:
    print(f"LowkeyClone: {message}", file=sys.stderr)
    return code


def git_path() -> str | None:
    return shutil.which("git")


def run_git(
    args: Sequence[str],
    cwd: str | Path | None = None,
    *,
    capture: bool = False,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    binary = git_path()
    if not binary:
        raise RuntimeError("git was not found on PATH.")
    # Preserve the HTTP/1.1 transport workaround used by the feature-complete
    # clone path; it applies harmlessly to local Git commands too.
    return subprocess.run(
        [binary, "-c", "http.version=HTTP/1.1", *args],
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=capture,
        check=check,
    )


def repo_name_from_url(url: str) -> str:
    clean = url.rstrip("/")
    parsed = urlparse(clean)
    if parsed.scheme and parsed.path:
        candidate = Path(parsed.path).name
    elif ":" in clean and "/" in clean.rsplit(":", 1)[-1]:
        candidate = clean.rsplit(":", 1)[-1].rstrip("/").rsplit("/", 1)[-1]
    else:
        candidate = Path(clean).name
    if candidate.endswith(".git"):
        candidate = candidate[:-4]
    if not candidate:
        raise ValueError("Could not derive a repository name from the URL.")
    return candidate


def parse_clone_args(args: Sequence[str]) -> tuple[str, str | None, int, int, bool]:
    args = list(args)
    if not args or args[0] in {"-h", "--help", "help"}:
        print_help()
        raise SystemExit(0)

    positionals: list[str] = []
    depth = 1
    jobs = max(2, min(8, os.cpu_count() or 4))
    use_cache = True

    index = 0
    while index < len(args):
        value = args[index]
        if value in {"--no-cache", "--no-cache-deps"}:
            use_cache = False
        elif value == "--full":
            depth = 0
        elif value == "--depth":
            index += 1
            if index >= len(args):
                raise ValueError("--depth requires a number.")
            depth = int(args[index])
            if depth < 1:
                raise ValueError("--depth must be >= 1 (use --full for full history).")
        elif value.startswith("--depth="):
            depth = int(value.split("=", 1)[1])
            if depth < 1:
                raise ValueError("--depth must be >= 1 (use --full for full history).")
        elif value == "--jobs":
            index += 1
            if index >= len(args):
                raise ValueError("--jobs requires a number.")
            jobs = int(args[index])
            if jobs < 1:
                raise ValueError("--jobs must be >= 1.")
        elif value.startswith("--jobs="):
            jobs = int(value.split("=", 1)[1])
            if jobs < 1:
                raise ValueError("--jobs must be >= 1.")
        elif value.startswith("-"):
            raise ValueError(f"Unknown lk clone option: {value}")
        else:
            positionals.append(value)
        index += 1

    if not positionals:
        raise ValueError(
            "Usage: lk clone <repository-url> [directory] "
            "[--jobs N] [--depth N|--full] [--no-cache]"
        )
    if len(positionals) > 2:
        raise ValueError("Too many positional arguments.")
    return (
        positionals[0],
        positionals[1] if len(positionals) == 2 else None,
        depth,
        jobs,
        use_cache,
    )


def resolve_destination(url: str, destination: str | None) -> Path:
    if destination:
        return Path(destination).expanduser().resolve()
    return (Path.cwd() / repo_name_from_url(url)).resolve()


def cache_key(url: str) -> str:
    normalized = normalize_repo_url(url)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]


def cache_path_for_url(url: str) -> Path:
    REPO_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return REPO_CACHE_DIR / f"{cache_key(url)}.git"


def ensure_cache_repo(url: str) -> Path:
    path = cache_path_for_url(url)
    if (path / "HEAD").exists():
        return path
    result = run_git(["init", "--bare", str(path)], capture=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Could not create dependency cache {path}: "
            f"{result.stderr or result.stdout or 'unknown git error'}"
        )
    return path


def cache_has_commit(path: Path, commit: str) -> bool:
    result = run_git(
        ["-C", str(path), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture=True,
    )
    return result.returncode == 0


def cache_submodule(url: str, worktree: Path, commit: str) -> bool:
    try:
        cache = ensure_cache_repo(url)
    except RuntimeError as exc:
        print(f"[CACHE] Warning: {exc}", file=sys.stderr)
        return False

    if cache_has_commit(cache, commit):
        return True

    result = run_git(
        ["-C", str(cache), "fetch", "--no-tags", "--quiet", str(worktree), commit],
        capture=True,
    )
    if result.returncode != 0:
        print(
            f"[CACHE] Warning: could not cache {normalize_repo_url(url)} "
            f"at {commit[:12]}: {result.stderr.strip() or result.stdout.strip()}",
            file=sys.stderr,
        )
        return False
    return True


def node_package_manager(path: Path) -> tuple[list[str], str] | None:
    """Return an available package-manager command and a human-readable name."""
    package_json = path / "package.json"
    if not package_json.is_file():
        return None

    if (path / "pnpm-lock.yaml").is_file():
        if shutil.which("pnpm"):
            return (["pnpm", "install", "--frozen-lockfile"], "pnpm")
        if shutil.which("corepack"):
            return (["corepack", "pnpm", "install", "--frozen-lockfile"], "corepack/pnpm")
        return (["npm", "install"], "npm fallback (pnpm unavailable)")

    if (path / "yarn.lock").is_file():
        if shutil.which("yarn"):
            return (["yarn", "install", "--frozen-lockfile"], "yarn")
        if shutil.which("corepack"):
            return (["corepack", "yarn", "install", "--frozen-lockfile"], "corepack/yarn")
        return (["npm", "install"], "npm fallback (yarn unavailable)")

    if (path / "package-lock.json").is_file():
        return (["npm", "ci"], "npm ci")

    return (["npm", "install"], "npm")


def install_node_dependencies(path: Path) -> int:
    """Materialize JavaScript dependencies required by Foundry/Hardhat projects."""
    manager = node_package_manager(path)
    if not manager:
        return 0

    command, manager_name = manager
    node_modules = path / "node_modules"
    if node_modules.is_dir() and any(node_modules.iterdir()):
        print(f"[NODE] READY: {path}")
        return 0

    if "fallback" in manager_name:
        print(f"[NODE] WARNING: {path}")
        print(f"       {manager_name}; using npm install instead.")
    print(f"[NODE] Installing dependencies ({manager_name}): {path}")
    result = subprocess.run(command, cwd=str(path), text=True)
    if result.returncode != 0:
        return die(
            f"Node dependency installation failed in {path}. "
            "Re-run the same lk clone command to resume.",
            result.returncode,
        )
    return 0


def git_repo_ready(path: Path) -> bool:
    result = run_git(
        ["-C", str(path), "rev-parse", "--is-inside-work-tree"],
        capture=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def origin_url(path: Path) -> str | None:
    result = run_git(
        ["-C", str(path), "remote", "get-url", "origin"],
        capture=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def normalize_repo_url(value: str | None) -> str:
    if not value:
        return ""
    clean = value.rstrip("/")
    if clean.endswith(".git"):
        clean = clean[:-4]
    return clean.lower()


def initialize_main_repo(url: str, destination: Path, depth: int) -> int:
    if destination.exists():
        if not destination.is_dir():
            return die(f"Destination exists but is not a directory: {destination}")
        if git_repo_ready(destination):
            remote = origin_url(destination)
            if normalize_repo_url(remote) == normalize_repo_url(url):
                print(f"[RESUME] Existing repository: {destination}")
                return 0
            if not remote:
                return die(
                    f"{destination} is a Git repository but has no origin remote."
                )
            return die(
                "Destination already contains a different Git repository:\\n"
                f"  Existing origin: {remote}\\n"
                f"  Requested URL : {url}\\n"
                "Choose another directory or remove the existing checkout."
            )
        try:
            if any(destination.iterdir()):
                return die(
                    f"Destination exists and is not an initialized Git repository: "
                    f"{destination}\\n"
                    "Remove it or choose another directory."
                )
        except OSError as exc:
            return die(f"Could not inspect destination: {exc}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    command = ["clone"]
    if depth:
        command += ["--depth", str(depth)]
    command += [url, str(destination)]

    print(f"[CLONE] {url}")
    print(f"[DIR]   {destination}")
    return run_git(command).returncode


def sync_submodules(destination: Path) -> int:
    return run_git(
        ["-C", str(destination), "submodule", "sync", "--recursive"]
    ).returncode


def gitmodules_entries(repo: Path) -> dict[str, tuple[str, str]]:
    """Read declared submodules directly from the repository's .gitmodules."""
    gitmodules = repo / ".gitmodules"
    if not gitmodules.is_file():
        return {}

    result = run_git(
        [
            "-C", str(repo), "config", "--file", str(gitmodules),
            "--get-regexp", r"^submodule\..*\.path$"
        ],
        capture=True,
    )
    if result.returncode != 0:
        return {}

    entries: dict[str, tuple[str, str]] = {}
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, path = parts
        prefix = "submodule."
        suffix = ".path"
        if not key.startswith(prefix) or not key.endswith(suffix):
            continue
        name = key[len(prefix):-len(suffix)]
        url_result = run_git(
            [
                "-C", str(repo), "config", "--file", str(gitmodules),
                "--get", f"submodule.{name}.url"
            ],
            capture=True,
        )
        url = url_result.stdout.strip() if url_result.returncode == 0 else ""
        if url:
            entries[name] = (path.strip(), url)
    return entries


def declared_submodules(repo: Path) -> list[tuple[str, str, Path]]:
    """Return dependencies declared by .gitmodules, including unlocked ones."""
    configured = gitmodules_entries(repo)
    return [(url, path, repo / path) for path, url in configured.values()]


def gitlink_commits(repo: Path) -> dict[str, str]:
    """Return committed gitlink revisions keyed by path."""
    result = run_git(["-C", str(repo), "ls-tree", "-r", "-z", "HEAD"], capture=True)
    commits: dict[str, str] = {}
    if result.returncode != 0:
        return commits
    for entry in result.stdout.split("\0"):
        if not entry:
            continue
        meta, sep, path = entry.partition("\t")
        if not sep:
            continue
        fields = meta.split()
        if len(fields) == 3 and fields[0] == "160000" and fields[1] == "commit":
            if re.fullmatch(r"[0-9a-fA-F]{40}", fields[2]):
                commits[path] = fields[2]
    return commits


def materialize_declared_submodule(
    repo: Path,
    url: str,
    path: Path,
    *,
    depth: int,
) -> int:
    """Clone a declared dependency when its Git tree has no gitlink."""
    if path.exists():
        if git_repo_ready(path):
            remote = origin_url(path)
            if normalize_repo_url(remote) == normalize_repo_url(url):
                print(f"[DEPS] READY (UNPINNED): {path.relative_to(repo)}")
                return 0
            return die(f"Dependency path belongs to a different Git repository: {path}")
        try:
            if any(path.iterdir()):
                return die(f"Dependency path exists but is not a Git repository: {path}")
        except OSError as exc:
            return die(f"Could not inspect dependency path {path}: {exc}")

    path.parent.mkdir(parents=True, exist_ok=True)
    command = ["clone"]
    if depth:
        command += ["--depth", str(depth)]
    command += [url, str(path)]
    print(f"[DEPS] Materializing UNPINNED dependency: {path.relative_to(repo)}")
    print(f"       URL: {url}")
    result = run_git(command, capture=True)
    if result.returncode != 0:
        print(result.stderr or result.stdout, file=sys.stderr, end="")
        return result.returncode
    return 0


def immediate_submodules(repo: Path) -> list[tuple[str, str, Path]]:
    """Return immediate submodules from committed gitlink entries."""
    configured = gitmodules_entries(repo)
    if not configured:
        return []

    by_path = {path: url for _, (path, url) in configured.items()}
    result = run_git(["-C", str(repo), "ls-tree", "-r", "-z", "HEAD"], capture=True)
    records: list[tuple[str, str, Path]] = []

    if result.returncode == 0:
        for entry in result.stdout.split("\0"):
            if not entry:
                continue
            meta, sep, path = entry.partition("\t")
            if not sep:
                continue
            fields = meta.split()
            if len(fields) != 3:
                continue
            mode, object_type, commit = fields
            if mode != "160000" or object_type != "commit":
                continue
            url = by_path.get(path)
            if url and re.fullmatch(r"[0-9a-fA-F]{40}", commit):
                records.append((url, commit, repo / path))
        if records:
            return records

    status = run_git(
        ["-C", str(repo), "submodule", "status", "--cached"],
        capture=True,
    )
    if status.returncode != 0:
        return records

    for line in status.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped[0] in "+-U":
            stripped = stripped[1:].lstrip()
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        commit, rest = parts
        path = rest.split(None, 1)[0]
        url = by_path.get(path)
        if url and re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            records.append((url, commit, repo / path))
    return records


def update_one_level(
    repo: Path,
    entries: list[tuple[str, str, Path]],
    *,
    depth: int,
    jobs: int,
    use_cache: bool,
) -> int:
    groups: dict[str, list[tuple[str, str, Path]]] = {}
    for url, commit, path in entries:
        key = normalize_repo_url(url) if use_cache else "__no_cache__"
        groups.setdefault(key, []).append((url, commit, path))

    for key, group in groups.items():
        command = [
            "-C", str(repo),
            "submodule", "update", "--init",
            "--jobs", str(jobs),
        ]
        if depth:
            command.extend(["--depth", str(depth)])

        if use_cache and key != "__no_cache__":
            cache = ensure_cache_repo(group[0][0])
            if all(cache_has_commit(cache, commit) for _, commit, _ in group):
                command.extend(["--reference", str(cache)])

        command.extend(["--", *[str(path.relative_to(repo)) for _, _, path in group]])

        result = run_git(command)
        if result.returncode != 0:
            return result.returncode
    return 0


def populate_level_cache(
    entries: list[tuple[str, str, Path]],
    *,
    use_cache: bool,
) -> None:
    if not use_cache:
        return

    unique: dict[str, tuple[str, str, Path]] = {}
    for url, commit, path in entries:
        if git_repo_ready(path):
            unique[f"{normalize_repo_url(url)}:{commit}"] = (url, commit, path)

    warmed = 0
    for url, commit, path in unique.values():
        if cache_submodule(url, path, commit):
            warmed += 1

    if unique:
        print(f"[CACHE] Warmed {warmed}/{len(unique)} dependency object sets")


def walk_submodules(
    root: Path,
    *,
    depth: int,
    jobs: int,
    use_cache: bool,
) -> int:
    queue: list[Path] = [root]
    visited: set[Path] = set()
    total = 0
    levels = 0

    while queue:
        repo = queue.pop(0).resolve()
        if repo in visited:
            continue
        visited.add(repo)

        # Package-manager dependencies are independent of Git submodules.
        # Install them for every discovered repository, even when it has no
        # .gitmodules of its own.
        code = install_node_dependencies(repo)
        if code != 0:
            return code

        configured = gitmodules_entries(repo)
        if not configured:
            continue

        gitlinks = gitlink_commits(repo)
        pinned: list[tuple[str, str, Path]] = []
        unlocked: list[tuple[str, str, Path]] = []

        for _, (path, url) in configured.items():
            commit = gitlinks.get(path)
            if commit:
                pinned.append((url, commit, repo / path))
            else:
                unlocked.append((url, path, repo / path))

        if unlocked:
            print("[DEPS] Dependency metadata detected")
            print(f"       Declared dependencies : {len(configured)}")
            print(f"       Gitlink entries       : {len(gitlinks)}")
            print(f"       Pinned                : {len(pinned)}")
            print(f"       Unpinned              : {len(unlocked)}")
            if repo == root:
                print("[DEPS] WARNING: .gitmodules declares dependencies without matching")
                print("       Gitlinks. Exact dependency revisions cannot be reproduced.")

        if pinned:
            total += len(pinned)
            code = update_one_level(
                repo, pinned, depth=depth, jobs=jobs, use_cache=use_cache
            )
            if code != 0:
                return code
            populate_level_cache(pinned, use_cache=use_cache)

        for url, _, path in unlocked:
            total += 1
            code = materialize_declared_submodule(repo, url, path, depth=depth)
            if code != 0:
                return code

        levels += 1
        for _, _, path in pinned:
            if git_repo_ready(path):
                queue.append(path)
        for _, _, path in unlocked:
            if git_repo_ready(path):
                queue.append(path)

    print(f"[DEPS] Processed {total} declared dependency entries across {levels} levels")
    return 0


def run_clone(args: Sequence[str]) -> int:
    try:
        url, destination_arg, depth, jobs, use_cache = parse_clone_args(args)
        destination = resolve_destination(url, destination_arg)
    except (ValueError, SystemExit) as exc:
        if isinstance(exc, SystemExit):
            return 0
        return die(str(exc))

    if not git_path():
        return die("git was not found on PATH. Install Git first.", 127)

    print("LOWKEY PROJECT ONBOARDING")
    print("=========================")
    print(f"Repository : {url}")
    print(f"Directory  : {destination}")
    print(f"Mode       : {'shallow' if depth else 'full'}")
    print(f"Submodules : parallel ({jobs} jobs)")
    print(f"Cache      : {'enabled' if use_cache else 'disabled'}")
    print("Strategy   : on-the-fly per-repository cache reuse")
    print()

    code = initialize_main_repo(url, destination, depth)
    if code != 0:
        return code

    code = sync_submodules(destination)
    if code != 0:
        return die("Failed to synchronize Git submodule URLs.", code)

    print(
        f"[DEPS] Walking submodules incrementally "
        f"(parallel={jobs}, depth={depth or 'full'})..."
    )
    code = walk_submodules(
        destination,
        depth=depth,
        jobs=jobs,
        use_cache=use_cache,
    )
    if code != 0:
        return die(
            "Submodule initialization failed. Re-run the same command to resume.",
            code,
        )

    print()
    print("LOWKEY CLONE COMPLETE")
    print("=====================")
    print(f"Project : {destination}")
    print("Next    : cd into the project and run `lk audit`")
    return 0


def print_help() -> None:
    print("""Lowkey clone - fast, cache-aware Git project onboarding

Usage:
  lk clone <repository-url> [directory] [options]

Options:
  --jobs N          Clone submodules in parallel (default: up to 8)
  --depth N         Shallow clone depth (default: 1)
  --full            Keep full Git history
  --no-cache        Disable Lowkey's reusable dependency cache

Behavior:
  - keeps the root repository shallow by default
  - initializes nested submodules in parallel
  - reuses ~/.lowkey/cache/submodule-reference.git on later projects
  - resumes an existing partial checkout instead of rejecting it
  - keeps existing repositories independent with --dissociate
""")


__all__ = ["run_clone", "print_help"]
