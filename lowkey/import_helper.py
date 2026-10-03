#!/usr/bin/env python3
"""Standalone Solidity import browser for Lowkey."""
from __future__ import annotations

import difflib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


HELP = """
LOWKEY // IMPORT HELPER
=======================

Browse Solidity things you can import from the current Foundry project.

Usage:
  lk import
  lk import packages
  lk import contracts
  lk import interfaces
  lk import libraries
  lk import types
  lk import files
  lk import mappings
  lk import common
  lk import <symbol>
  lk import "<import declaration>"
  lk import "<import/path.sol>"
  lk import --h

The helper is standalone: it does not select targets, change RPC/ABI/audit
state, send transactions, or write project files.
"""

COMMON = {
    "Ownable": ("Single-owner access control.", "Use for simple owner-only administration.", "@openzeppelin/contracts/access/Ownable.sol"),
    "Ownable2Step": ("Two-step ownership transfer.", "Use when ownership handover should require explicit acceptance.", "@openzeppelin/contracts/access/Ownable2Step.sol"),
    "AccessControl": ("Role-based access control.", "Use when a contract needs multiple permissions/roles.", "@openzeppelin/contracts/access/AccessControl.sol"),
    "ReentrancyGuard": ("Reentrancy protection helper.", "Use for sensitive functions that make external calls and need a reentrancy guard.", "@openzeppelin/contracts/utils/ReentrancyGuard.sol"),
    "Pausable": ("Pause/unpause building block.", "Use when an authorized account should be able to stop selected operations.", "@openzeppelin/contracts/utils/Pausable.sol"),
    "ERC20": ("Reusable ERC20 token implementation.", "Use when building a fungible token.", "@openzeppelin/contracts/token/ERC20/ERC20.sol"),
    "IERC20": ("ERC20 interface.", "Use when interacting with an existing ERC20 without inheriting its implementation.", "@openzeppelin/contracts/token/ERC20/IERC20.sol"),
    "SafeERC20": ("ERC20 safety wrappers.", "Use when making ERC20 operations safer across token implementations.", "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol"),
    "ERC721": ("Reusable ERC721 NFT implementation.", "Use when building an NFT contract.", "@openzeppelin/contracts/token/ERC721/ERC721.sol"),
    "IERC721": ("ERC721 interface.", "Use when interacting with an existing NFT.", "@openzeppelin/contracts/token/ERC721/IERC721.sol"),
    "ERC721URIStorage": ("ERC721 metadata extension.", "Use when storing per-token URI metadata on-chain.", "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol"),
    "ERC1155": ("Reusable ERC1155 multi-token implementation.", "Use for collections containing fungible and/or non-fungible token IDs.", "@openzeppelin/contracts/token/ERC1155/ERC1155.sol"),
    "AggregatorV3Interface": ("Chainlink price-feed interface.", "Use when reading data from an AggregatorV3-compatible price feed.", "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol"),
    "Test": ("Foundry Std test base.", "Use in Foundry tests for assertions, cheatcodes, and the vm interface.", "forge-std/Test.sol"),
    "Script": ("Foundry Std script base.", "Use for Foundry deployment/interaction scripts.", "forge-std/Script.sol"),
}

@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str
    source: Path
    import_path: str
    line: int

    @property
    def import_stmt(self) -> str:
        return f'import {{{self.name}}} from "{self.import_path}";'

@dataclass(frozen=True)
class Package:
    name: str
    path: Path
    prefix: str | None


def root_for(start: Path | None = None) -> Path:
    p = (start or Path.cwd()).resolve()
    for candidate in (p, *p.parents):
        if (candidate / "foundry.toml").is_file():
            return candidate
    return p


def remappings(root: Path) -> list[tuple[str, Path]]:
    raw: list[str] = []
    f = root / "remappings.txt"
    if f.is_file():
        try:
            raw += f.read_text(encoding="utf-8").splitlines()
        except OSError:
            pass
    try:
        r = subprocess.run(["forge", "remappings"], cwd=root, capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            raw += r.stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        pass
    out: dict[str, Path] = {}
    for line in raw:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        prefix, target = (x.strip() for x in line.split("=", 1))
        if prefix and target:
            path = Path(target)
            out[prefix] = (root / path).resolve() if not path.is_absolute() else path.resolve()
    return sorted(out.items(), key=lambda x: (-len(x[0]), x[0]))


def usable_prefix(prefix: str) -> bool:
    # Forge can expose nested dependency remappings such as
    # "lib/openzeppelin-contracts/:forge-std/". Those are useful to Forge
    # internally but are not normal user-facing import paths.
    return not prefix.startswith("lib/") and "/:" not in prefix and not prefix.startswith(":")


def import_path(path: Path, root: Path, maps: list[tuple[str, Path]]) -> str:
    resolved = path.resolve()
    for prefix, target in maps:
        if not usable_prefix(prefix):
            continue
        try:
            return prefix + resolved.relative_to(target).as_posix()
        except ValueError:
            pass
    try:
        return "./" + resolved.relative_to((root / "src").resolve()).as_posix()
    except ValueError:
        try:
            return "../lib/" + resolved.relative_to((root / "lib").resolve()).as_posix()
        except ValueError:
            return resolved.as_posix()


def sol_files(base: Path):
    if not base.is_dir():
        return
    skip = {
        ".git", "node_modules", "out", "cache", "broadcast",
        "test", "tests", "script", "scripts", "mocks", "mock",
        "fixtures", "examples", "lib", "fv", "docs", "certora",
    }
    for p in base.rglob("*.sol"):
        try:
            rel_parts = p.relative_to(base).parts
        except ValueError:
            continue
        if p.is_file() and not any(part in skip for part in rel_parts[:-1]):
            yield p


def extract(path: Path, root: Path, maps: list[tuple[str, Path]]) -> list[Symbol]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    depth = 0
    found: list[Symbol] = []
    patterns = [
        ("contract", r"^(?:abstract\s+)?contract\s+([A-Za-z_]\w*)"),
        ("interface", r"^interface\s+([A-Za-z_]\w*)"),
        ("library", r"^library\s+([A-Za-z_]\w*)"),
        ("struct", r"^struct\s+([A-Za-z_]\w*)"),
        ("enum", r"^enum\s+([A-Za-z_]\w*)"),
        ("error", r"^error\s+([A-Za-z_]\w*)"),
        ("type", r"^type\s+([A-Za-z_]\w*)\s+is\b"),
        ("function", r"^function\s+([A-Za-z_]\w*)\s*\("),
        ("constant", r"^[A-Za-z_][\w\[\]]*(?:\s+[^\s]+)*\s+constant\s+([A-Za-z_]\w*)\b"),
    ]
    compiled = [(k, re.compile(p)) for k, p in patterns]
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if depth == 0 and line:
            for kind, pat in compiled:
                m = pat.match(line)
                if m:
                    found.append(Symbol(m.group(1), kind, path, import_path(path, root, maps), n))
                    break
        depth += line.count("{") - line.count("}")
        depth = max(depth, 0)
    unique = {(s.kind, s.name, s.import_path): s for s in found}
    return sorted(unique.values(), key=lambda s: (s.name.lower(), s.kind, str(s.source)))


def all_symbols(root: Path, maps: list[tuple[str, Path]]) -> list[Symbol]:
    files = list(sol_files(root / "src")) + list(sol_files(root / "lib"))
    out: list[Symbol] = []
    for p in files:
        out += extract(p, root, maps)
    return out


def explain(s: Symbol) -> tuple[str, str]:
    if s.name in COMMON:
        return COMMON[s.name][0], COMMON[s.name][1]
    if s.kind == "interface":
        return f"Interface {s.name} describes an external contract's callable surface.", "Use it when your contract needs typed interaction with an existing contract."
    if s.kind == "library":
        return f"Library {s.name} contains reusable helper logic.", "Use it when you need the helper behavior exposed by this library."
    if s.kind == "contract":
        return f"Contract {s.name} is a reusable implementation.", "Use it when you want to inherit from or instantiate this component."
    if s.kind == "struct":
        return f"Struct {s.name} defines reusable structured data.", "Use it when multiple files need the same data shape."
    if s.kind == "enum":
        return f"Enum {s.name} defines named states or choices.", "Use it for state machines or fixed sets of options."
    if s.kind == "type":
        return f"User-defined value type {s.name} gives a primitive its own type identity.", "Use it when stronger type separation is useful."
    if s.kind == "error":
        return f"Custom error {s.name} represents a reusable revert condition.", "Use it when several files need the same error definition."
    if s.kind == "function":
        return f"File-level function {s.name} is directly importable.", "Use it when the source exposes a reusable file-level helper."
    if s.kind == "constant":
        return f"File-level constant {s.name} is directly importable.", "Use it when several files need the same constant."
    return f"Importable {s.kind} {s.name}.", "Read its source/API before using it."


def package_prefix(package: Path, maps: list[tuple[str, Path]]) -> str | None:
    candidates = []
    package = package.resolve()
    for prefix, target in maps:
        if not usable_prefix(prefix):
            continue
        target = target.resolve()
        if target != package and package not in target.parents:
            continue
        try:
            depth = len(target.relative_to(package).parts)
        except ValueError:
            continue
        # Prefer mappings aimed closest to the package root. This prevents a
        # nested dependency mapping from masquerading as the package prefix.
        candidates.append((
            depth,
            0 if prefix.startswith("@") else 1,
            -len(prefix),
            prefix,
        ))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][3]


def packages(root: Path, maps: list[tuple[str, Path]]) -> list[Package]:
    lib = root / "lib"
    if not lib.is_dir():
        return []
    out = []
    for p in sorted(lib.iterdir(), key=lambda x: x.name.lower()):
        if not p.is_dir() or p.name.startswith("."):
            continue
        out.append(Package(p.name, p, package_prefix(p, maps)))
    return out


def header(title: str):
    print()
    print(f"LOWKEY // IMPORT  •  {title}")
    print("=" * 76)


def search_tokens(query: str) -> list[str]:
    """
    Normalize human Solidity import searches.

    Examples:
      ERC721URIStorage,
      import {ERC721URIStorage, ERC721} from "...";
      @openzeppelin/contracts/token/ERC721/ERC721.sol
    """
    q = query.strip()
    brace = re.search(r"\{(.*?)\}", q, flags=re.S)
    if brace:
        return [x.lower() for x in re.findall(r"\b[A-Za-z_]\w*\b", brace.group(1))]
    q = re.sub(r"^\s*import\s+", "", q, flags=re.I).strip()
    q = q.strip().strip(";").strip().strip('"').strip("'")
    q = re.sub(r"[,;]+$", "", q).strip()
    if not q:
        return []
    q = re.sub(r"[^A-Za-z0-9_@./:-]", "", q)
    return [q.lower()] if q else []


def choose(items, renderer, label):
    if not items:
        print(f"No {label} found.")
        return None
    current = items
    while True:
        for i, item in enumerate(current, 1):
            print(renderer(i, item))
        try:
            a = input("\nSelect number, /search, b=back, q=quit: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if a.lower() == "q":
            raise SystemExit(0)
        if a.lower() == "b":
            return None
        if a.startswith("/"):
            tokens = search_tokens(a[1:])
            if not tokens:
                print("Enter a symbol, import path, or Solidity import declaration after '/'.")
                continue
            rendered = [renderer(0, x).lower() for x in current]
            matches = [
                x for x, text in zip(current, rendered)
                if any(token in text for token in tokens)
            ]
            if not matches:
                print(f"No matches for '{a[1:].strip()}'.")
                continue
            exact_symbols = [
                x for x in matches
                if isinstance(x, Symbol) and any(token == x.name.lower() for token in tokens)
            ]
            if len(exact_symbols) == 1:
                return exact_symbols[0]
            current = matches
            continue
        try:
            return current[int(a) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")


def sym_render(i, s):
    why, when = explain(s)
    p = f"{i:>2}. " if i else ""
    return f"{p}{s.name} [{s.kind}]\n    import: {s.import_stmt}\n    why: {why}\n    when: {when}\n"


def pkg_render(i, p):
    lead = f"{i:>2}. " if i else ""
    return f"{lead}{p.name}\n    path: {p.path}\n    prefix: {p.prefix or '(no remapping detected)'}\n"


def file_render(i, item):
    path, syms = item
    lead = f"{i:>2}. " if i else ""
    names = ", ".join(s.name for s in syms[:10])
    if len(syms) > 10:
        names += " ..."
    return f"{lead}{path}\n    import: {syms[0].import_path}\n    exports: {names}\n"


def combined_import(symbols: list[Symbol], aliases: dict[str, str] | None = None) -> list[str]:
    """Build copy-ready imports, grouping symbols by their verified source."""
    groups: dict[str, list[Symbol]] = {}
    aliases = aliases or {}
    for symbol in symbols:
        groups.setdefault(symbol.import_path, []).append(symbol)

    lines = []
    for path, grouped in groups.items():
        names = ", ".join(
            f"{symbol.name} as {aliases[symbol.name]}" if symbol.name in aliases else symbol.name
            for symbol in grouped
        )
        lines.append(f'import {{{names}}} from "{path}";')
    return lines


def show_copy_imports(
    symbols: list[Symbol],
    requested_path: str | None = None,
    aliases: dict[str, str] | None = None,
):
    print("\nCOPY:")
    for stmt in combined_import(symbols, aliases=aliases):
        print(f"  {stmt}")
    if requested_path:
        actual = sorted({s.import_path for s in symbols})
        if requested_path not in actual:
            print()
            print(f"NOTE: requested path was not the defining source: {requested_path}")
            print("      Lowkey used the verified source path(s) above.")

def show_symbol(s: Symbol):
    why, when = explain(s)
    print()
    print(f"NAME:   {s.name}")
    print(f"TYPE:   {s.kind}")
    print(f"SOURCE: {s.source}")
    print(f"IMPORT: {s.import_stmt}")
    print(f"WHY:    {why}")
    print(f"WHEN:   {when}")
    print(f"LINE:   {s.line}")
    show_copy_imports([s])


def show_file(item):
    path, syms = item
    print()
    print(f"SOURCE:      {path}")
    print(f"IMPORT FILE: {syms[0].import_path}")
    print("IMPORTABLE SYMBOLS:")
    for s in syms:
        print(f"  {s.name} [{s.kind}]")
        print(f"    {s.import_stmt}")


def browse_package(p: Package, root: Path, maps):
    while True:
        header(f"PACKAGE • {p.name}")
        print(f"Path: {p.path}")
        print(f"Import prefix: {p.prefix or '(none detected)'}")
        print()
        print("  1. Contracts / abstract contracts")
        print("  2. Interfaces")
        print("  3. Libraries")
        print("  4. Structs / enums / types / errors / constants")
        print("  5. Source files")
        print("  b. Back")
        a = input("\nSelect: ").strip().lower()
        if a == "b":
            return
        kinds = {
            "1": {"contract"}, "2": {"interface"}, "3": {"library"},
            "4": {"struct", "enum", "type", "error", "constant"},
        }
        if a == "5":
            items = [(x, extract(x, root, maps)) for x in sol_files(p.path)]
            items = [x for x in items if x[1]]
            s = choose(items, file_render, "source files")
            if s:
                show_file(s)
        elif a in kinds:
            syms = []
            for source in sol_files(p.path):
                syms += [s for s in extract(source, root, maps) if s.kind in kinds[a]]
            syms = sorted({(s.kind, s.name, s.import_path): s for s in syms}.values(),
                          key=lambda s: (s.name.lower(), s.kind, str(s.source)))
            s = choose(syms, sym_render, "symbols")
            if s:
                show_symbol(s)
        else:
            print("Pick 1-5 or b.")


def common():
    header("COMMON REFERENCE IMPORTS")
    print("These reference the conventional package import names; the package must")
    print("exist in your project and its remapping must match the path.")
    print()
    for i, (name, (why, when, path)) in enumerate(COMMON.items(), 1):
        print(f"{i:>2}. {name}")
        print(f"    import: import {{{name}}} from \"{path}\";")
        print(f"    why:    {why}")
        print(f"    when:   {when}")
        print()


def parse_import_query(
    query: str,
) -> tuple[list[tuple[str, str | None]], str | None, str, str | None]:
    """Parse a pasted Solidity import declaration."""
    q = query.strip()

    match = re.fullmatch(
        r'\s*import\s*\{(.*?)\}\s*from\s*["\']([^"\']+)["\']\s*;?\s*',
        q,
        flags=re.I | re.S,
    )
    if match:
        imports = []
        for item in match.group(1).split(','):
            item = item.strip()
            if not item:
                continue
            parts = re.split(r'\s+as\s+', item, maxsplit=1, flags=re.I)
            name = parts[0].strip()
            alias = parts[1].strip() if len(parts) == 2 else None
            if not re.fullmatch(r'[A-Za-z_]\w*', name):
                continue
            if alias and not re.fullmatch(r'[A-Za-z_]\w*', alias):
                alias = None
            imports.append((name, alias))
        return imports, match.group(2), 'symbols', None

    match = re.fullmatch(
        r'\s*import\s*\*\s*as\s+([A-Za-z_]\w*)\s*from\s*["\']([^"\']+)["\']\s*;?\s*',
        q,
        flags=re.I | re.S,
    )
    if match:
        return [], match.group(2), 'namespace', match.group(1)

    match = re.fullmatch(
        r'\s*import\s*["\']([^"\']+)["\']\s*;?\s*',
        q,
        flags=re.I | re.S,
    )
    if match:
        return [], match.group(1), 'file', None

    return [], None, 'search', None

def importable_files(root: Path, maps) -> list[tuple[Path, str]]:
    files = list(sol_files(root / 'src')) + list(sol_files(root / 'lib'))
    return [(path, import_path(path, root, maps)) for path in files]


def find_import_path(path_query: str, root: Path, maps):
    target = path_query.strip().strip('"').strip("'")
    for source, resolved in importable_files(root, maps):
        if resolved == target or resolved.lower() == target.lower():
            return source, resolved
    return None


def print_import_file(
    path: str,
    root: Path,
    maps,
    mode: str,
    namespace_alias: str | None = None,
) -> int:
    resolved = find_import_path(path, root, maps)
    if not resolved:
        print(f"No Solidity source file resolves to import path '{path}'.")
        return 2
    source, import_name = resolved
    print()
    print(f"SOURCE:      {source}")
    print(f"IMPORT FILE: {import_name}")
    print("COPY:")
    if mode == 'namespace':
        alias = namespace_alias or 'Lib'
        print(f'  import * as {alias} from "{import_name}";')
    else:
        print(f'  import "{import_name}";')
    return 0


def import_query(query: str, root: Path, maps) -> int:
    requested_imports, requested_path, mode, namespace_alias = parse_import_query(query)
    tokens = [name for name, _alias in requested_imports]

    if mode in {'file', 'namespace'}:
        return print_import_file(requested_path, root, maps, mode, namespace_alias)

    if mode == 'symbols':
        if not tokens:
            print('No imported symbols found inside the declaration.')
            return 2

        syms = all_symbols(root, maps)
        by_name: dict[str, list[Symbol]] = {}
        for symbol in syms:
            by_name.setdefault(symbol.name.lower(), []).append(symbol)

        found = []
        missing = []
        aliases: dict[str, str] = {}
        for name, alias in requested_imports:
            candidates = by_name.get(name.lower(), [])
            if requested_path:
                same_file = [s for s in candidates if s.import_path == requested_path]
                if same_file:
                    candidates = same_file
            if candidates:
                found.append(candidates[0])
                if alias:
                    aliases[candidates[0].name] = alias
            else:
                missing.append(name)

        unique_found = []
        seen = set()
        for symbol in found:
            key = (symbol.name.lower(), symbol.import_path)
            if key not in seen:
                seen.add(key)
                unique_found.append(symbol)

        if missing:
            print('UNRESOLVED SYMBOLS:')
            for name in missing:
                print(f'  - {name}')
            if unique_found:
                print()
                print('RESOLVED SYMBOLS:')
                for symbol in unique_found:
                    print(f'  - {symbol.name} -> {symbol.import_path}')
            return 2

        print()
        print(f'RESOLVED {len(unique_found)} SYMBOL(S)')
        for symbol in unique_found:
            print(f'  {symbol.name} [{symbol.kind}] -> {symbol.import_path}')
        show_copy_imports(unique_found, requested_path=requested_path, aliases=aliases)
        if len({s.import_path for s in unique_found}) > 1:
            print()
            print('NOTE: symbols came from different source files, so Lowkey emitted separate valid imports.')
        return 0

    if not tokens:
        tokens = search_tokens(query)

    if not tokens:
        path_match = find_import_path(query, root, maps)
        if path_match:
            source, import_name = path_match
            symbols = [s for s in all_symbols(root, maps) if s.import_path == import_name]
            if symbols:
                show_file((source, symbols))
            else:
                print()
                print(f'SOURCE:      {source}')
                print(f'IMPORT FILE: {import_name}')
                print('COPY:')
                print(f'  import "{import_name}";')
            return 0
        print('No import query provided.')
        return 2

    syms = all_symbols(root, maps)
    exact = [s for s in syms if s.name.lower() in tokens or s.import_path.lower() in tokens]
    if len(exact) == 1:
        show_symbol(exact[0])
        return 0

    matches = [
        s for s in syms
        if any(token in s.name.lower() or token in s.import_path.lower() for token in tokens)
    ]
    if not matches:
        choices = sorted(
            {s.name for s in syms},
            key=lambda name: difflib.SequenceMatcher(None, tokens[0], name.lower()).ratio(),
            reverse=True,
        )[:3]
        print(f"No importable symbol or source file matches '{query.strip()}'.")
        if choices and difflib.SequenceMatcher(None, tokens[0], choices[0].lower()).ratio() >= 0.45:
            print('Did you mean:')
            for name in choices:
                print(f'  - {name}')
        print('Try: lk import /<symbol>, lk import <symbol>, or lk import files')
        return 2

    s = choose(matches, sym_render, 'matching importable symbols')
    if s:
        show_symbol(s)
    return 0

def run_category(category: str, root: Path, maps) -> int:
    cat = category.lower()
    if cat in {"packages", "package", "deps"}:
        header("INSTALLED PACKAGES")
        p = choose(packages(root, maps), pkg_render, "installed packages")
        if p:
            browse_package(p, root, maps)
        return 0

    if cat in {"contracts", "contract"}:
        header("CONTRACTS / ABSTRACT CONTRACTS")
        s = choose([x for x in all_symbols(root, maps) if x.kind == "contract"], sym_render, "contracts")
        if s:
            show_symbol(s)
        return 0

    if cat in {"interfaces", "interface"}:
        header("INTERFACES")
        s = choose([x for x in all_symbols(root, maps) if x.kind == "interface"], sym_render, "interfaces")
        if s:
            show_symbol(s)
        return 0

    if cat in {"libraries", "library"}:
        header("SOLIDITY LIBRARIES")
        s = choose([x for x in all_symbols(root, maps) if x.kind == "library"], sym_render, "libraries")
        if s:
            show_symbol(s)
        return 0

    if cat in {"types", "structs", "errors", "type"}:
        header("STRUCTS / ENUMS / TYPES / ERRORS / CONSTANTS")
        s = choose([x for x in all_symbols(root, maps) if x.kind in {"struct", "enum", "type", "error", "constant"}], sym_render, "types")
        if s:
            show_symbol(s)
        return 0

    if cat in {"files", "file", "source", "sources"}:
        header("IMPORTABLE SOURCE FILES")
        items = [(p, extract(p, root, maps)) for p in list(sol_files(root / "src")) + list(sol_files(root / "lib"))]
        items = [x for x in items if x[1]]
        s = choose(items, file_render, "source files")
        if s:
            show_file(s)
        return 0

    if cat in {"mappings", "mapping", "remappings"}:
        header("FORGE IMPORT MAPPINGS")
        if not maps:
            print("No remappings detected.")
        else:
            for prefix, target in maps:
                print(f"{prefix}= {target}")
        return 0

    if cat in {"common", "known"}:
        common()
        return 0

    return import_query(category, root, maps)


def interactive(root: Path, maps) -> int:
    header("IMPORT BROWSER")
    print("A standalone learning lookup. It does not touch audit/target/RPC state.\n")
    print("  1. Installed packages")
    print("  2. Contracts / abstract contracts")
    print("  3. Interfaces")
    print("  4. Solidity libraries")
    print("  5. Structs / enums / types / errors / constants")
    print("  6. Source files")
    print("  7. Forge import mappings")
    print("  8. Common reference imports")
    print("  q. Quit")
    while True:
        a = input("\nSelect: ").strip().lower()
        if a == "q":
            return 0
        cat = {"1":"packages","2":"contracts","3":"interfaces","4":"libraries","5":"types","6":"files","7":"mappings","8":"common"}.get(a)
        if not cat:
            print("Pick 1-8 or q.")
            continue
        run_category(cat, root, maps)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0].lower() in {"--h", "--help", "-h", "help"}:
        print(HELP.strip())
        return 0
    root = root_for()
    maps = remappings(root)
    if not args:
        try:
            return interactive(root, maps)
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
    return run_category(" ".join(args), root, maps)


if __name__ == "__main__":
    raise SystemExit(main())
