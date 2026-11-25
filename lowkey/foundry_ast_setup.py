#!/usr/bin/env python3
"""Prepare and verify Foundry compiler AST evidence for Lowkey."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


MAX_BUILD_INFO_FILES = 24
MAX_BUILD_INFO_FILE_BYTES = 64 * 1024 * 1024
MAX_BUILD_INFO_TOTAL_BYTES = 128 * 1024 * 1024
FALSE_VALUES = {"0", "false", "no", "off"}
TRUE_VALUES = {"1", "true", "yes", "on"}
PROFILE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
TABLE_RE = re.compile(r"^\s*\[\s*([^\]]+?)\s*\]\s*(?:#.*)?(?:\r?\n)?$")
ASSIGNMENT_RE = re.compile(
    r"^(?P<indent>\s*)(?P<key>ast|build_info|build_info_without_ast)(?P<separator>\s*=\s*)(?P<rhs>.*?)(?P<ending>\r?\n)?$"
)


class AstSetupError(RuntimeError):
    """A safe AST setup or verification step could not be completed."""


def _toml_parser():
    try:
        import tomllib  # type: ignore[import-not-found]
        return tomllib
    except ImportError:
        try:
            import tomli  # type: ignore[import-not-found]
            return tomli
        except ImportError:
            return None


def _parse_toml(text: str) -> dict[str, Any] | None:
    parser = _toml_parser()
    if parser is None:
        return None
    try:
        data = parser.loads(text)
    except Exception as error:
        raise AstSetupError(f"foundry.toml is not valid TOML: {error}") from error
    if not isinstance(data, dict):
        raise AstSetupError("foundry.toml did not parse to a TOML table")
    return data


def _active_profile(env: dict[str, str]) -> str:
    profile = (env.get("FOUNDRY_PROFILE") or "default").strip() or "default"
    if not PROFILE_RE.fullmatch(profile):
        raise AstSetupError(
            f"Unsupported FOUNDRY_PROFILE value {profile!r}; "
            "Lowkey will not guess how to quote or rewrite that TOML table name."
        )
    return profile


def _find_config(cwd: Path, env: dict[str, str]) -> Path:
    configured = env.get("FOUNDRY_CONFIG")
    if configured:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        if not candidate.is_file():
            raise AstSetupError(
                f"FOUNDRY_CONFIG points to a missing file: {candidate}"
            )
        return candidate.resolve()

    for parent in (cwd, *cwd.parents):
        candidate = parent / "foundry.toml"
        if candidate.is_file():
            return candidate.resolve()

    raise AstSetupError(
        "No project foundry.toml was found from the current directory. "
        "Lowkey will not modify your global Foundry config automatically. "
        "Create a project foundry.toml or set FOUNDRY_CONFIG to the intended file."
    )


def _forge_config(cwd: Path, env: dict[str, str]) -> dict[str, Any]:
    if shutil.which("forge", path=env.get("PATH")) is None:
        raise AstSetupError("Foundry's forge executable is not available on PATH.")

    result = subprocess.run(
        ["forge", "config", "--json"],
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise AstSetupError(
            "Could not read the active Foundry configuration"
            + (f":\n{detail}" if detail else ".")
        )

    output = result.stdout.strip()
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        parsed = None
        for offset, character in enumerate(output):
            if character != "{":
                continue
            try:
                candidate, _end = decoder.raw_decode(output[offset:])
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict):
                parsed = candidate
                break
        if parsed is None:
            raise AstSetupError(
                "forge config --json did not return a JSON object."
            )
    if not isinstance(parsed, dict):
        raise AstSetupError("forge config --json returned an unexpected value.")
    return parsed


def _blocking_environment_overrides(
    env: dict[str, str],
    required_settings: dict[str, bool],
) -> list[str]:
    blocked: list[str] = []
    for key, required in required_settings.items():
        env_key = key.upper()
        for prefix in ("FOUNDRY", "DAPP"):
            name = f"{prefix}_{env_key}"
            value = env.get(name)
            if value is None:
                continue
            normalized = value.strip().lower()
            if required and normalized in FALSE_VALUES:
                blocked.append(name)
            elif not required and normalized in TRUE_VALUES:
                blocked.append(name)
    return blocked


def _patch_profile_settings(
    text: str,
    profile: str,
    settings: dict[str, bool] | None = None,
) -> tuple[str, bool]:
    """Set only requested compiler-output flags in one profile."""
    if not PROFILE_RE.fullmatch(profile):
        raise AstSetupError(f"Unsafe Foundry profile name: {profile!r}")
    desired = settings or {"ast": True, "build_info": True}
    allowed = {"ast", "build_info", "build_info_without_ast"}
    if not desired or any(key not in allowed or not isinstance(value, bool) for key, value in desired.items()):
        raise AstSetupError("Unsupported compiler-output settings requested.")

    parsed_before = _parse_toml(text)
    lines = text.splitlines(keepends=True)
    newline = "\r\n" if "\r\n" in text else "\n"
    target = f"profile.{profile}"

    headers: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = TABLE_RE.match(line)
        if match:
            headers.append((index, match.group(1).strip()))

    matching = [index for index, name in headers if name == target]
    if len(matching) > 1:
        raise AstSetupError(
            f"foundry.toml declares [{target}] more than once; refusing an ambiguous edit."
        )

    changed = False
    if matching:
        start = matching[0]
        end = next(
            (index for index, _name in headers if index > start),
            len(lines),
        )
        seen: dict[str, int] = {}
        for index in range(start + 1, end):
            match = ASSIGNMENT_RE.match(lines[index])
            if not match:
                continue
            key = match.group("key")
            if key in seen:
                raise AstSetupError(
                    f"[{target}] contains duplicate {key} settings; "
                    "Lowkey will not guess which value Foundry should use."
                )
            seen[key] = index

            rhs = match.group("rhs")
            comment_match = re.search(r"\s+#.*$", rhs)
            comment = comment_match.group(0) if comment_match else ""
            raw_value = rhs[:comment_match.start()] if comment_match else rhs
            value = raw_value.strip()
            if value not in {"true", "false"}:
                raise AstSetupError(
                    f"[{target}] {key} must be a TOML boolean; found {value!r}."
                )
            expected = str(desired[key]).lower()
            if value != expected:
                lines[index] = (
                    match.group("indent")
                    + key
                    + match.group("separator")
                    + expected
                    + comment
                    + (match.group("ending") or "")
                )
                changed = True

        missing = [key for key in desired if key not in seen]
        if missing:
            additions = [
                f"{key} = {str(desired[key]).lower()}{newline}"
                for key in missing
            ]
            if end > 0 and lines[end - 1] and not lines[end - 1].endswith(("\n", "\r")):
                lines[end - 1] += newline
            lines[end:end] = additions
            changed = True
    else:
        # If a nested profile table already exists, define its parent first.
        nested = next(
            (
                index
                for index, name in headers
                if name.startswith(target + ".")
            ),
            len(lines),
        )
        block = [f"[{target}]{newline}"] + [
            f"{key} = {str(value).lower()}{newline}"
            for key, value in desired.items()
        ]
        if nested < len(lines):
            block.append(newline)
        elif lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += newline
        lines[nested:nested] = block
        changed = True

    updated = "".join(lines)
    parsed_after = _parse_toml(updated)
    if parsed_after is not None:
        profile_data = (parsed_after.get("profile") or {}).get(profile) or {}
        for key, value in desired.items():
            if profile_data.get(key) is not value:
                raise AstSetupError(
                    f"Could not validate {key}={str(value).lower()} in [{target}]."
                )
    elif parsed_before is None:
        # The line editor still validates the targeted boolean values, but
        # cannot claim full TOML validation without tomllib/tomli installed.
        pass
    return updated, changed


def _write_config_with_backup(path: Path, content: str) -> Path:
    backup = path.with_name(path.name + ".lowkey.bak")
    suffix = 1
    while backup.exists():
        backup = path.with_name(path.name + f".lowkey.{suffix}.bak")
        suffix += 1

    shutil.copy2(path, backup)
    original_mode = path.stat().st_mode
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.lowkey-",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(original_mode))
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return backup


def _build_info_directory(config: dict[str, Any], config_path: Path, cwd: Path) -> Path:
    root_value = config.get("root")
    root = Path(str(root_value)).expanduser() if root_value else config_path.parent
    if not root.is_absolute():
        root = (cwd / root).resolve()

    build_info_value = config.get("build_info_path")
    if build_info_value:
        directory = Path(str(build_info_value)).expanduser()
        return (directory if directory.is_absolute() else root / directory).resolve()

    out_value = config.get("out") or "out"
    out = Path(str(out_value)).expanduser()
    if not out.is_absolute():
        out = root / out
    return (out / "build-info").resolve()


def _inspect_build_info(directory: Path) -> dict[str, int]:
    if not directory.is_dir():
        return {"files": 0, "source_units": 0, "with_ast": 0, "skipped": 0}

    files = sorted(
        (item for item in directory.glob("*.json") if item.is_file()),
        key=lambda item: item.name,
    )
    source_units = 0
    with_ast = 0
    skipped = 0
    bytes_read = 0
    inspected_files = 0

    for path in files:
        if inspected_files >= MAX_BUILD_INFO_FILES:
            skipped += 1
            continue
        try:
            size = path.stat().st_size
            if size > MAX_BUILD_INFO_FILE_BYTES or bytes_read + size > MAX_BUILD_INFO_TOTAL_BYTES:
                skipped += 1
                continue
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError):
            skipped += 1
            continue

        inspected_files += 1
        bytes_read += size
        output = payload.get("output") if isinstance(payload, dict) else None
        sources = output.get("sources") if isinstance(output, dict) else None
        if not isinstance(sources, dict):
            continue
        source_units += len(sources)
        with_ast += sum(
            1
            for source in sources.values()
            if isinstance(source, dict) and isinstance(source.get("ast"), dict)
        )

    return {
        "files": len(files),
        "source_units": source_units,
        "with_ast": with_ast,
        "skipped": skipped,
    }


def _readiness(config: dict[str, Any], build_info: dict[str, int]) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if config.get("ast") is not True:
        issues.append("Foundry compiler AST output is disabled (ast=false).")
    if config.get("build_info") is not True:
        issues.append("Foundry build-info generation is disabled (build_info=false).")
    if config.get("build_info_without_ast") is True:
        issues.append("Foundry is configured to omit AST nodes from build-info (build_info_without_ast=true).")
    if build_info["source_units"] == 0:
        issues.append("No compiler source units were found in build-info output.")
    elif build_info["with_ast"] == 0:
        issues.append("Build-info exists, but none of its source units contains an AST.")
    if build_info["skipped"]:
        issues.append(
            f"{build_info['skipped']} build-info file(s) were skipped by Lowkey's "
            "bounded inspection limits."
        )
    return not issues, issues


def _doctor(cwd: Path, env: dict[str, str], quiet_if_ready: bool = False) -> int:
    config_path = _find_config(cwd, env)
    config = _forge_config(cwd, env)
    directory = _build_info_directory(config, config_path, cwd)
    build_info = _inspect_build_info(directory)
    ready, issues = _readiness(config, build_info)

    if ready and quiet_if_ready:
        return 0

    profile = _active_profile(env)
    print("LOWKEY / COMPILER AST READINESS")
    print(f"  Config       : {config_path}")
    print(f"  Profile      : {profile}")
    print(f"  AST          : {config.get('ast')}")
    print(f"  Build info   : {config.get('build_info')}")
    print(f"  Omit AST     : {config.get('build_info_without_ast', False)}")
    print(f"  Build files  : {build_info['files']}")
    print(f"  Source units : {build_info['source_units']}")
    print(f"  With AST     : {build_info['with_ast']}")
    if ready:
        print("  Status       : READY")
    else:
        print("  Status       : NEEDS SETUP")
        for issue in issues:
            print(f"  - {issue}")
        print("  Repair       : run 'lk ast setup'")
    return 0 if ready else 1


def _setup(cwd: Path, env: dict[str, str]) -> int:
    config_path = _find_config(cwd, env)
    profile = _active_profile(env)
    current = _forge_config(cwd, env)
    desired_settings = {"ast": True, "build_info": True}
    if current.get("build_info_without_ast") is True:
        desired_settings["build_info_without_ast"] = False

    blockers = _blocking_environment_overrides(env, desired_settings)
    if blockers:
        raise AstSetupError(
            "Environment variables override required compiler-output settings: "
            + ", ".join(blockers)
            + ". Remove or change those overrides, then rerun 'lk ast setup'. "
            "No project files were changed."
        )

    original = config_path.read_text(encoding="utf-8")
    updated, changed = _patch_profile_settings(original, profile, desired_settings)
    if changed:
        backup = _write_config_with_backup(config_path, updated)
        print(f"Updated active profile [profile.{profile}] in {config_path}")
        print(f"Backup      : {backup}")
    else:
        print(f"Found required compiler-output flags in [profile.{profile}].")

    resolved = _forge_config(cwd, env)
    if any(resolved.get(key) is not value for key, value in desired_settings.items()):
        raise AstSetupError(
            "Foundry still resolves ast/build_info to false after the profile update. "
            "Another configuration source may be overriding the TOML values. "
            "Run 'lk ast doctor' for the active settings."
        )

    print("\nBuilding with compiler AST enabled...")
    build = subprocess.run(
        ["forge", "build", "--force"],
        cwd=str(cwd),
        env=env,
        check=False,
    )
    if build.returncode != 0:
        raise AstSetupError(
            f"'forge build --force' failed with exit code {build.returncode}. "
            "The AST settings were retained so the next build can use them."
        )

    final_config = _forge_config(cwd, env)
    directory = _build_info_directory(final_config, config_path, cwd)
    evidence = _inspect_build_info(directory)
    ready, issues = _readiness(final_config, evidence)
    if not ready:
        raise AstSetupError(
            "The build completed, but compiler AST evidence was not verified:\n"
            + "\n".join(f"  - {issue}" for issue in issues)
            + f"\nBuild-info directory: {directory}"
        )

    print("\nLOWKEY / COMPILER AST READY")
    print(f"  Profile      : {profile}")
    print(f"  Build info   : {directory}")
    print(f"  Build files  : {evidence['files']}")
    print(f"  Source units : {evidence['source_units']}")
    print(f"  With AST     : {evidence['with_ast']}")
    print("  Verification : PASS — compiler AST nodes were found.")
    print("\nNEXT")
    print("  lk fn -v")
    print("  Review AST coverage and declaration matching in the report.")
    return 0


def _usage() -> None:
    print(
        "LOWKEY / COMPILER AST\n"
        "\n"
        "  lk ast doctor   Read-only check of active Foundry AST readiness\n"
        "  lk ast setup    Safely enable AST/build-info, rebuild and verify\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "help"}:
        _usage()
        return 0

    cwd = Path.cwd().resolve()
    env = dict(os.environ)
    command = args[0]
    try:
        if command in {"doctor", "status"}:
            if len(args) > 2 or (len(args) == 2 and args[1] != "--quiet-if-ready"):
                _usage()
                return 2
            return _doctor(
                cwd,
                env,
                quiet_if_ready=len(args) == 2,
            )
        if command == "setup":
            if len(args) != 1:
                _usage()
                return 2
            return _setup(cwd, env)
        _usage()
        print(f"Unknown AST command: {command}", file=sys.stderr)
        return 2
    except (AstSetupError, OSError) as error:
        if command in {"doctor", "status"} and args[1:] == ["--quiet-if-ready"]:
            return 0
        print(f"LOWKEY AST SETUP FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
