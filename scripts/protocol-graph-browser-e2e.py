#!/usr/bin/env python3
"""Real-browser acceptance for Lowkey's local protocol graph workspace.

The test generates generic Solidity fixtures, builds the real Lowkey source
index/model, serves the emitted HTML on loopback, and exercises the shipped UI
with Chromium. It does not access a chain or upload target source.
"""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

from source_explorer import build_explorer_model, render_explorer_document
from source_index import build_source_index
from playwright.sync_api import sync_playwright


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


def write_project(root: pathlib.Path, contract_count: int = 1) -> None:
    (root / "src").mkdir(parents=True)
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nlibs = ["lib"]\n',
        encoding="utf-8",
    )
    if contract_count == 1:
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    uint256 private total;

    function deposit(uint256 amount) external payable {
        total += amount;
        _credit(amount);
    }

    function _credit(uint256 amount) internal {
        total += amount;
    }

    function balance() external view returns (uint256) {
        return total;
    }
}
"""
    else:
        rows = ["// SPDX-License-Identifier: MIT", "pragma solidity ^0.8.20;", ""]
        for index in range(contract_count):
            rows.extend([
                f"contract Vault{index:03d} {{",
                "    uint256 private total;",
                "    function deposit(uint256 amount) external {",
                "        total += _credit(amount);",
                "    }",
                "    function _credit(uint256 amount) internal returns (uint256) {",
                "        return _normalize(amount);",
                "    }",
                "    function _normalize(uint256 amount) internal pure returns (uint256) {",
                "        return _scale(amount);",
                "    }",
                "    function _scale(uint256 amount) internal pure returns (uint256) {",
                "        return amount * 2;",
                "    }",
                "    function withdraw(uint256 amount) external {",
                "        _settle(amount);",
                "    }",
                "    function _settle(uint256 amount) internal {",
                "        total -= _normalize(amount);",
                "    }",
                "    function balance() external view returns (uint256) {",
                "        return total;",
                "    }",
                "}",
                "",
            ])
        source = "\n".join(rows)
    (root / "src" / "Vaults.sol").write_text(source, encoding="utf-8")


def write_graph(project: pathlib.Path, destination: pathlib.Path, contract_count: int) -> None:
    write_project(project, contract_count=contract_count)
    index = build_source_index(project, use_cache=False)
    model = build_explorer_model(index, root=project)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "index.html").write_text(
        render_explorer_document(model), encoding="utf-8"
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="lowkey-graph-browser-") as temporary:
        base = pathlib.Path(temporary)
        web_root = base / "www"
        write_graph(base / "small-project", web_root / "small", 1)
        write_graph(base / "large-project", web_root / "large", 200)

        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            partial(QuietHandler, directory=str(web_root)),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        screenshots = pathlib.Path(os.environ.get("RUNNER_TEMP", "/tmp"))

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 960})
                page_errors: list[str] = []
                console_errors: list[str] = []
                request_failures: list[str] = []
                page.on("pageerror", lambda error: page_errors.append(str(error)))
                page.on(
                    "console",
                    lambda message: console_errors.append(message.text)
                    if message.type == "error" else None,
                )
                page.on(
                    "requestfailed",
                    lambda request: request_failures.append(
                        f"{request.method} {request.url}: {request.failure}"
                    ),
                )

                base_url = f"http://127.0.0.1:{server.server_port}"
                response = page.goto(base_url + "/small/", wait_until="networkidle")
                assert response and response.status == 200, "small graph did not load"
                assert page.title() == "Lowkey · Protocol Graph"
                assert page.locator("#graph .graph-node").count() >= 1
                assert page.locator(".entrypoint-row").filter(has_text="deposit").count() == 1

                # Entry-point focus remains inside the graph and exposes a real call edge.
                page.locator(".entrypoint-row").filter(has_text="deposit").click()
                call_edge = page.locator("#graph-edges .edge.CALLS")
                assert call_edge.count() >= 1, "entrypoint focus did not render its internal call"
                page.locator("#inspector").get_by_role(
                    "button", name="Bookmark", exact=True
                ).click()
                page.locator("#inspector").get_by_role(
                    "button", name="Mark investigated", exact=True
                ).click()
                assert page.locator("#bookmark-explorer").get_by_text(
                    "Vault.deposit(uint256)", exact=False
                ).count() >= 1

                # A call edge opens the exact local Solidity call-site window.
                call_edge.first.click()
                drawer = page.locator("#source-drawer")
                assert drawer.evaluate("(element) => !element.hidden")
                assert page.locator("#source-view .source-line.selected").count() == 1
                assert page.locator("#source-meta").inner_text().startswith("src/Vaults.sol")
                page.locator("#source-close").click()
                assert drawer.evaluate("(element) => element.hidden")

                # Global search navigates back into the same protocol graph.
                search = page.locator("#global-search")
                search.fill("balance")
                result = page.locator("#search-results .search-result").filter(
                    has_text="balance"
                ).first
                result.click()
                assert page.locator("#inspector .entity-name").inner_text().startswith(
                    "Vault.balance"
                )
                page.locator("#fit-graph").click()
                page.locator("#zoom-in").click()

                # Relationship filters actually remove and restore their own layer.
                calls_filter = page.locator('[data-edge="CALLS"]')
                calls_filter.uncheck()
                assert page.locator("#graph-edges .edge.CALLS").count() == 0
                calls_filter.check()
                search.fill("")
                # Move focus off the search input before testing the global
                # slash shortcut; otherwise "/" is typed into the input.
                page.locator("#inspector .entity-name").click()
                page.keyboard.press("/")
                assert page.evaluate(
                    "document.activeElement && document.activeElement.id"
                ) == "global-search"
                page.keyboard.press("Escape")

                # Local workspace state survives a page reload.
                page.reload(wait_until="networkidle")
                assert page.locator("#bookmark-explorer").get_by_text(
                    "Vault.deposit(uint256)", exact=False
                ).count() >= 1

                page.screenshot(
                    path=str(screenshots / "lowkey-protocol-graph-desktop.png"),
                    full_page=True,
                )

                # The graph and inspector remain usable at a narrower viewport.
                page.set_viewport_size({"width": 768, "height": 900})
                page.wait_for_timeout(150)
                graph_box = page.locator("#graph-stage").bounding_box()
                assert graph_box and graph_box["width"] > 250
                assert page.locator("#inspector").is_visible()
                page.screenshot(
                    path=str(screenshots / "lowkey-protocol-graph-narrow.png"),
                    full_page=True,
                )

                # Expand a larger generated protocol cluster and check responsiveness.
                large = browser.new_page(viewport={"width": 1440, "height": 960})
                large.on("pageerror", lambda error: page_errors.append(str(error)))
                large.on(
                    "console",
                    lambda message: console_errors.append(message.text)
                    if message.type == "error" else None,
                )
                response = large.goto(base_url + "/large/", wait_until="networkidle")
                assert response and response.status == 200, "large graph did not load"
                group = large.locator("#graph .graph-node.group").first
                assert group.count() == 1, "large fixture did not form a single source cluster"
                started = time.monotonic()
                group.click()
                large.wait_for_function(
                    "document.querySelectorAll('#graph .graph-node').length >= 1400"
                    timeout=60000,
                )
                large.locator("#fit-graph").click()
                expansion_seconds = time.monotonic() - started
                node_count = large.locator("#graph .graph-node").count()
                assert node_count >= 1400, f"expanded graph too small: {node_count} nodes"
                assert expansion_seconds < 25, (
                    f"large graph interaction took {expansion_seconds:.2f}s"
                )
                large.screenshot(
                    path=str(screenshots / "lowkey-protocol-graph-large.png"),
                    full_page=True,
                )

                browser.close()

                assert not page_errors, "browser page errors: " + "; ".join(page_errors)
                assert not console_errors, "browser console errors: " + "; ".join(console_errors)
                assert not request_failures, "failed browser requests: " + "; ".join(request_failures)
                print(
                    "PROTOCOL GRAPH BROWSER ACCEPTANCE: PASS "
                    f"(small workflows, 768px layout, {node_count} nodes from 200 contracts / 1,200 functions, "
                    f"large expansion {expansion_seconds:.2f}s)"
                )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
