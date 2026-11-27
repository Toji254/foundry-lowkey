#!/usr/bin/env python3
"""Safe, real-binary CLI acceptance for Lowkey's source relationship commands.

All writes occur in temporary project/output directories and all network
interaction is limited to a loopback-only workspace server. No public RPC,
remote clone, deployment or transaction command is invoked.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


def fixture(root: pathlib.Path, contracts: int = 30) -> None:
    (root / "src").mkdir(parents=True)
    (root / "interfaces").mkdir()
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nlibs = ["lib"]\n',
        encoding="utf-8",
    )
    (root / "interfaces" / "IRouter.sol").write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IRouter {
    function route(address receiver, uint256 amount) external;
}
""",
        encoding="utf-8",
    )
    rows = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.20;",
        'import "../interfaces/IRouter.sol";',
        "",
        "library MathLib {",
        "    function double(uint256 value) internal pure returns (uint256) {",
        "        return value * 2;",
        "    }",
        "}",
        "",
    ]
    for index in range(contracts):
        name = f"Vault{index:03d}"
        rows.extend([
            f"contract {name} {{",
            "    using MathLib for uint256;",
            "    IRouter public immutable router;",
            "    address public owner;",
            "    mapping(address => uint256) public balances;",
            "    uint256 public totalDeposited;",
            "",
            "    modifier onlyOwner() { require(msg.sender == owner, \"owner\"); _; }",
            "    constructor(address target) { owner = msg.sender; router = IRouter(target); }",
            "    function deposit(uint256 amount) external {",
            "        balances[msg.sender] += amount;",
            "        totalDeposited += amount;",
            "        _credit(amount);",
            "    }",
            "    function _credit(uint256 amount) internal {",
            "        totalDeposited += amount;",
            "    }",
            "    function withdraw(uint256 amount) public onlyOwner {",
            "        require(balances[msg.sender] >= amount, \"balance\");",
            "        balances[msg.sender] -= amount;",
            "        router.route(msg.sender, amount);",
            "    }",
            "    function balanceOf(address account) external view returns (uint256) {",
            "        return balances[account];",
            "    }",
            "    function doubled(uint256 value) external pure returns (uint256) {",
            "        return value.double();",
            "    }",
            "}",
            "",
        ])
    (root / "src" / "Vaults.sol").write_text("\n".join(rows), encoding="utf-8")


class Cli:
    def __init__(self, executable: str, env: dict[str, str]):
        self.executable = executable
        self.env = env
        self.invocations = 0

    def run(
        self, *args: str, root: pathlib.Path | None = None,
        expected: int = 0, timeout: int = 40,
    ) -> subprocess.CompletedProcess[str]:
        argv = [self.executable, *map(str, args)]
        if root is not None:
            argv.extend(["--root", str(root)])
        result = subprocess.run(
            argv, text=True, capture_output=True, env=self.env,
            timeout=timeout, check=False,
        )
        self.invocations += 1
        if result.returncode != expected:
            raise AssertionError(
                "CLI exit mismatch\n"
                f"expected={expected}, actual={result.returncode}\n"
                f"command={argv!r}\nstdout:\n{result.stdout[-5000:]}\n"
                f"stderr:\n{result.stderr[-5000:]}"
            )
        return result


def check_json(result: subprocess.CompletedProcess[str]) -> dict:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"Expected JSON output, received: {result.stdout[:2000]!r}\n{result.stderr}"
        ) from error
    if not isinstance(payload, dict):
        raise AssertionError("Expected a JSON object from lk link.")
    return payload


def check_loopback_server(cli: Cli, project: pathlib.Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen(
        [cli.executable, "link", "--root", str(project), "--serve", "--port", str(port)],
        cwd=project, env=cli.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        ready = False
        last_error: Exception | None = None
        for _ in range(80):
            if process.poll() is not None:
                captured = process.stdout.read() if process.stdout else ""
                raise AssertionError(f"lk link --serve exited early ({process.returncode}):\n{captured}")
            try:
                with urllib.request.urlopen(base + "/health", timeout=1) as response:
                    health = json.loads(response.read())
                    if response.status == 200 and health.get("ok") is True:
                        ready = True
                        break
            except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
                last_error = error
                time.sleep(0.125)
        if not ready:
            raise AssertionError(f"loopback workspace did not become healthy: {last_error}")

        with urllib.request.urlopen(base + "/", timeout=3) as response:
            html = response.read().decode("utf-8")
            assert response.status == 200 and "LOWKEY" in html

        source_url = base + "/api/source?" + urllib.parse.urlencode({"path": "src/Vaults.sol"})
        with urllib.request.urlopen(source_url, timeout=3) as response:
            source = json.loads(response.read())
            assert response.status == 200
            assert source["path"] == "src/Vaults.sol"
            assert "contract Vault000" in source["content"]

        traversal = base + "/api/source?" + urllib.parse.urlencode({"path": "../foundry.toml"})
        try:
            urllib.request.urlopen(traversal, timeout=3)
        except urllib.error.HTTPError as error:
            assert error.code == 400, f"traversal returned unexpected HTTP {error.code}"
        else:
            raise AssertionError("loopback source API accepted a traversal path")

        hostile = urllib.request.Request(base + "/health", headers={"Host": "example.invalid"})
        try:
            urllib.request.urlopen(hostile, timeout=3)
        except urllib.error.HTTPError as error:
            assert error.code == 421, f"non-loopback Host returned unexpected HTTP {error.code}"
        else:
            raise AssertionError("loopback server accepted a non-loopback Host header")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lk", default=os.environ.get("LOWKEY_BIN") or shutil.which("lk"))
    args = parser.parse_args()
    if not args.lk:
        parser.error("Provide --lk or place the installed lk executable on PATH.")
    executable = str(pathlib.Path(args.lk).expanduser().resolve())
    if not pathlib.Path(executable).is_file():
        parser.error(f"Lowkey executable does not exist: {executable}")

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["BROWSER"] = "true"
    cli = Cli(executable, env)

    with tempfile.TemporaryDirectory(prefix="lowkey-link-cli-") as temporary:
        base = pathlib.Path(temporary)
        project = base / "fixture"
        fixture(project)
        output = base / "protocol.html"

        # Help and basic project graph modes.
        help_result = cli.run("link", "--help")
        for expected in ("--format", "--serve", "--only", "--depth", "--archive", "--search"):
            assert expected in help_result.stdout, f"link help omitted {expected}"
        short_help = cli.run("link", "--h")
        assert "STATIC SOURCE EVIDENCE" in short_help.stdout or "Static source" in short_help.stdout

        terminal = cli.run("link", root=project)
        assert "PROTOCOL GRAPH" in terminal.stdout or "RELATIONSHIP" in terminal.stdout
        for kind in ("calls", "storage", "reads", "writes", "imports", "assets", "all"):
            result = cli.run("link", "--only", kind, root=project)
            assert result.stdout.strip(), f"--only {kind} emitted no terminal output"
        cli.run("link", "--depth", "3", "--limit", "1", root=project)
        cli.run("link", "--depth", "10", "--limit", "500", root=project)
        cli.run("link", "--include-third-party", root=project)

        # Structured graph and offline HTML outputs.
        graph = check_json(cli.run("link", "--format", "json", root=project))
        assert graph.get("nodes"), "JSON graph contains no nodes"
        assert any("Vault000" in str(item) for item in graph["nodes"])
        html_result = cli.run(
            "link", "--format", "html", "--output", str(output), root=project
        )
        assert "GRAPH SAVED" in html_result.stdout and output.is_file()
        html = output.read_text(encoding="utf-8")
        assert "Lowkey" in html and "graph-data" in html
        cli.run("link", "--format", "html", "--include-third-party", "--output", str(base / "third-party.html"), root=project)

        # Contract/function detail mode and individual supported views.
        for detail in ("summary", "calls", "storage", "external", "all"):
            detail_result = cli.run(
                "link", "Vault000.withdraw(uint256)", "--detail", detail, root=project
            )
            assert detail_result.stdout.strip(), f"--detail {detail} emitted no output"

        # Inventory modes, output formats, paging and search/type combinations.
        listing = check_json(cli.run("link", "--list", "--json", root=project))
        assert listing["total_contracts"] >= 31
        assert any(item["name"] == "Vault000" for item in listing["contracts"])
        search = check_json(cli.run("link", "--search", "Vault000", "--json", root=project))
        assert search["filtered_contracts"] == 1
        interfaces = check_json(cli.run("link", "--type", "interface", "--all", "--json", root=project))
        assert any(item["name"] == "IRouter" for item in interfaces["contracts"])
        page_two = check_json(cli.run("link", "--page", "2", "--json", root=project))
        assert page_two["page"] == 2 and page_two["shown"] > 0
        all_rows = check_json(cli.run("link", "--all", "--json", root=project))
        assert all_rows["page"] == 1 and all_rows["shown"] == all_rows["filtered_contracts"]

        # Expected validation failures: no project mutation should occur.
        for argv in (
            ("link", "--depth", "0"),
            ("link", "--depth", "11"),
            ("link", "--limit", "0"),
            ("link", "--limit", "501"),
            ("link", "--port", "0"),
            ("link", "--page", "0"),
            ("link", "--detail", "calls"),
            ("link", "--output", str(base / "bad.html")),
            ("link", "--ref", "main"),
            ("link", "Vault000", "--search", "Vault"),
            ("link", "--list", "--only", "calls"),
            ("link", "--format", "html", "--list"),
            ("link", "--format", "html", "--json"),
            ("link", "--github", "https://example.invalid/org/repo"),
            ("link", "--github", "https://github.com/owner/repo", "--archive", "bad.zip"),
            ("link", "Vault000", "--serve"),
            ("link", "--serve", "--format", "json"),
        ):
            cli.run(*argv, root=project, expected=2)

        # A valid but out-of-range inventory page has a deliberate non-zero result.
        cli.run("link", "--page", "99", root=project, expected=2)

        # Archive import is isolated and local. A traversal member must fail closed.
        archive = base / "fixture.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
            for source in (project / "foundry.toml", project / "src" / "Vaults.sol", project / "interfaces" / "IRouter.sol"):
                handle.write(source, source.relative_to(project).as_posix())
        archive_html = base / "archive.html"
        result = cli.run(
            "link", "--archive", str(archive), "--format", "html",
            "--output", str(archive_html), root=project,
        )
        assert "GRAPH SAVED" in result.stdout and archive_html.is_file()

        malicious = base / "malicious.zip"
        with zipfile.ZipFile(malicious, "w") as handle:
            handle.writestr("../escape.sol", "contract Escape {}")
        cli.run("link", "--archive", str(malicious), "--format", "html",
                "--output", str(base / "malicious.html"), root=project, expected=2)
        assert not (base / "escape.sol").exists()

        # Check an actual local server process and its loopback/source path guards.
        check_loopback_server(cli, project)

        print(
            "PROTOCOL GRAPH CLI ACCEPTANCE: PASS "
            f"({cli.invocations} real lk invocations; graph, filters, output, "
            "inventory, detail, archive, invalid inputs and loopback server)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
