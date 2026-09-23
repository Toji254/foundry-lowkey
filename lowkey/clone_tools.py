#!/usr/bin/env python3
"""Fast, cache-aware Git cloning for Lowkey audit workspaces."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse

CONFIG_DIR = Path(os.path.expanduser("~/.lowkey"))
CACHE_DIR = CONFIG_DIR / "cache"
CACHE_REPO = CACHE_DIR / "submodule-reference.git"


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
    return subprocess.run(
        [binary, *args],
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


def ensure_cache_repo() -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if (CACHE_REPO / "HEAD").exists():
        return CACHE_REPO

    result = run_git(["init", "--bare", str(CACHE_REPO)], capture=True)
    if result.returncode != 0:
        raise RuntimeError(
            "Could not create dependency cache:\\n"
            + (result.stderr or result.stdout or "unknown git error")
        )
    return CACHE_REPO


def cache_has_objects(repo: Path) -> bool:
    result = run_git(["-C", str(repo), "count-objects", "-v"], capture=True)
    if result.returncode != 0:
        return False
    values = {}
    for line in result.stdout.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    try:
        return int(values.get("count", "0")) > 0 or int(values.get("in-pack", "0")) > 0
    except ValueError:
        return False


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


def update_submodules(
    destination: Path,
    *,
    depth: int,
    jobs: int,
    use_cache: bool,
) -> int:
    command = [
        "-C",
        str(destination),
        "submodule",
        "update",
        "--init",
        "--recursive",
        "--jobs",
        str(jobs),
    ]
    if depth:
        command += ["--depth", str(depth), "--shallow-submodules"]
    if use_cache:
        cache = ensure_cache_repo()
        if cache_has_objects(cache):
            command += ["--reference-if-able", str(cache), "--dissociate"]
    return run_git(command).returncode


def populate_cache(destination: Path) -> int:
    try:
        cache = ensure_cache_repo()
    except RuntimeError as exc:
        print(f"[CACHE] Warning: {exc}", file=sys.stderr)
        return 0

    # Import objects from the local submodules into one shared bare repository.
    # This is local-only: no network call is made while populating the cache.
    probe = run_git(
        [
            "-C",
            str(destination),
            "submodule",
            "foreach",
            "--recursive",
            'printf "%s\\t%s\\t%s\\n" "$path" "$sha1" "$PWD"',
        ],
        capture=True,
    )
    if probe.returncode != 0:
        print(
            "[CACHE] Warning: could not enumerate submodules; "
            "checkout itself completed.",
            file=sys.stderr,
        )
        return 0

    records = []
    for line in probe.stdout.splitlines():
        parts = line.split("\\t", 2)
        if len(parts) == 3 and parts[1]:
            records.append((parts[1], parts[2]))

    if not records:
        print("[CACHE] No submodules to cache.")
        return 0

    print(f"[CACHE] Updating dependency cache ({len(records)} repositories)...")
    failures = 0
    for sha, worktree in records:
        result = run_git(
            ["-C", str(cache), "fetch", "--no-tags", "--quiet", worktree, sha],
            capture=True,
        )
        if result.returncode != 0:
            failures += 1
            if result.stderr:
                print(f"[CACHE] Warning: {result.stderr.strip()}", file=sys.stderr)

    if failures:
        print(f"[CACHE] {failures} cache entries could not be updated.", file=sys.stderr)
    else:
        print(f"[CACHE] Ready: {cache}")
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
    print()

    code = initialize_main_repo(url, destination, depth)
    if code != 0:
        return code

    code = sync_submodules(destination)
    if code != 0:
        return die("Failed to synchronize Git submodule URLs.", code)

    if use_cache:
        try:
            cache = ensure_cache_repo()
            if cache_has_objects(cache):
                print(f"[CACHE] Reusing: {cache}")
            else:
                print(f"[CACHE] Initializing: {cache}")
        except RuntimeError as exc:
            print(f"[CACHE] Warning: {exc}", file=sys.stderr)

    print(
        f"[DEPS] Initializing submodules recursively "
        f"(parallel={jobs}, depth={depth or 'full'})..."
    )
    code = update_submodules(
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

    if use_cache:
        populate_cache(destination)

    print()
    print("LOWKEY CLONE COMPLETE")
    print("=====================")
    print(f"Project : {destination}")
    print("Next    : cd into the project and run `lk audit\`")
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
