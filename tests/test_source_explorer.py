import json
import pathlib
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

from source_index import build_source_index
from source_explorer import (
    build_explorer_model,
    create_explorer_server,
    extract_source_archive,
    render_explorer_html,
    validate_github_url,
    write_uploaded_files,
)


class ProtocolExplorerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        (self.root / "src").mkdir()
        (self.root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\nlibs = ["lib"]\n',
            encoding="utf-8",
        )
        (self.root / "src" / "Math.sol").write_text(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            library Math {
                function add(uint256 value, uint256 amount) internal pure returns (uint256) {
                    return value + amount;
                }
            }
            """,
            encoding="utf-8",
        )
        (self.root / "src" / "IRouter.sol").write_text(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            interface IRouter {
                function pluginTransfer(address account, address token, uint256 amount) external;
            }
            """,
            encoding="utf-8",
        )
        (self.root / "src" / "Protocol.sol").write_text(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            import "./Math.sol";
            import "./IRouter.sol";

            contract Protocol {
                using Math for uint256;
                IRouter public router;
                mapping(address => uint256) public balances;
                uint256 public totalDeposited;

                function calculate(uint256 value) external pure returns (uint256) {
                    return value.add(1);
                }

                function route(address account, address token, uint256 amount) external {
                    router.pluginTransfer(account, token, amount);
                }

                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                    totalDeposited += msg.value;
                }

                function withdraw(uint256 amount) external {
                    require(balances[msg.sender] >= amount, "insufficient");
                    balances[msg.sender] -= amount;
                    (bool ok,) = payable(msg.sender).call{value: amount}("");
                    require(ok, "transfer failed");
                }
            }
            """,
            encoding="utf-8",
        )
        self.index = build_source_index(self.root, use_cache=False)
        self.model = build_explorer_model(self.index, root=self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_model_preserves_all_declaration_kinds_and_function_ownership(self):
        declarations = [n for n in self.model["nodes"] if n["type"] == "declaration"]
        by_label = {n["label"]: n for n in declarations}
        self.assertIn("Protocol", by_label)
        self.assertIn("IRouter", by_label)
        self.assertIn("Math", by_label)
        self.assertEqual(by_label["IRouter"]["declaration_kind"], "interface")
        self.assertEqual(by_label["Math"]["declaration_kind"], "library")

        interface_methods = [
            n for n in self.model["nodes"]
            if n["type"] == "function" and n["label"].startswith("IRouter.pluginTransfer")
        ]
        self.assertEqual(len(interface_methods), 1)
        self.assertEqual(interface_methods[0]["contract_id"], by_label["IRouter"]["id"])
        self.assertEqual(self.model["schema_version"], 2)

    def test_model_preserves_library_calls_and_declared_interface_calls(self):
        library_edges = [e for e in self.model["edges"] if e["kind"] == "LIBRARY_CALL"]
        interface_edges = [
            e for e in self.model["edges"]
            if e["kind"] == "EXTERNAL_CALL" and "pluginTransfer" in e["label"]
        ]
        self.assertTrue(library_edges, "using-for library calls should remain visible as separate edges")
        self.assertTrue(interface_edges, "typed interface calls should remain visible as external-call edges")
        self.assertTrue(any(e.get("implementation_resolution") == "UNRESOLVED" for e in interface_edges))

    def test_model_preserves_function_to_storage_and_asset_relationships(self):
        kinds = {edge["kind"] for edge in self.model["edges"]}
        self.assertTrue(kinds & {"READS", "WRITES", "MUTATES"})
        self.assertIn("ASSET_FLOW", kinds)
        self.assertTrue(any(node["kind"] == "mapping" for node in self.model["nodes"]))
        self.assertEqual(self.model["summary"]["declarations"], 3)

    def test_every_indexed_declaration_is_present_in_directory_groups(self):
        declarations = {
            node["id"] for node in self.model["nodes"] if node["type"] == "declaration"
        }
        grouped = {
            declaration_id
            for group in self.model["groups"]
            for declaration_id in group.get("declarations", [])
        }
        self.assertSetEqual(declarations, grouped)
        self.assertTrue(any(node["label"] == "Protocol" for node in self.model["nodes"]))

    def test_html_is_a_self_contained_interactive_graph(self):
        output = self.root / ".lowkey" / "link-graph.html"
        path = render_explorer_html(self.index, root=self.root, output=output)
        document = path.read_text(encoding="utf-8")
        self.assertIn('id="graph"', document)
        self.assertIn("Architecture", document)
        self.assertIn("Function flow", document)
        self.assertIn("Storage", document)
        self.assertIn("Asset flow", document)
        self.assertIn('data-filter="interface"', document)
        self.assertIn('data-filter="library"', document)
        self.assertIn("search-results", document)
        self.assertIn("STATIC_SOURCE", document)
        self.assertNotIn("__GRAPH_DATA__", document)
        self.assertNotIn("__SERVER_MODE__", document)
        self.assertNotIn('<script src="https://', document)

    def test_uploaded_files_keep_project_paths_and_reject_traversal(self):
        destination = self.root / "uploaded"
        write_uploaded_files(
            [
                {"path": "example/foundry.toml", "content": '[profile.default]\nsrc = "src"\n'},
                {"path": "example/src/Sample.sol", "content": "pragma solidity ^0.8.20; contract Sample {}"},
            ],
            destination,
        )
        self.assertTrue((destination / "foundry.toml").is_file())
        self.assertTrue((destination / "src" / "Sample.sol").is_file())
        with self.assertRaises(ValueError):
            write_uploaded_files(
                [{"path": "../outside.sol", "content": "contract Bad {}"}],
                destination / "bad",
            )

    def test_zip_import_skips_docs_but_rejects_traversal(self):
        archive = self.root / "good.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("example/README.md", "# Example")
            bundle.writestr("example/.github/workflows/ci.yml", "name: CI")
            bundle.writestr("example/foundry.toml", '[profile.default]\nsrc = "src"\n')
            bundle.writestr("example/src/Sample.sol", "pragma solidity ^0.8.20; contract Sample {}")
        destination = self.root / "unzipped"
        extract_source_archive(archive, destination)
        self.assertTrue((destination / "foundry.toml").is_file())
        self.assertTrue((destination / "src" / "Sample.sol").is_file())
        self.assertFalse((destination / "README.md").exists())

        malicious = self.root / "bad.zip"
        with zipfile.ZipFile(malicious, "w") as bundle:
            bundle.writestr("../escape.sol", "contract Escape {}")
        with self.assertRaises(ValueError):
            extract_source_archive(malicious, self.root / "bad-extract")

    def test_github_url_validation_is_strict(self):
        self.assertEqual(
            validate_github_url("https://github.com/gmx-io/gmx-contracts"),
            "https://github.com/gmx-io/gmx-contracts.git",
        )
        for invalid in (
            "http://github.com/owner/repo",
            "https://github.com.evil.example/owner/repo",
            "https://user:pass@github.com/owner/repo",
            "https://github.com/owner/repo?token=secret",
            "https://github.com/owner",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_github_url(invalid)

    def test_local_workspace_server_health_and_file_import_api(self):
        server = create_explorer_server(self.index, root=self.root, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            base = f"http://{host}:{port}"
            with urllib.request.urlopen(base + "/health", timeout=5) as response:
                self.assertEqual(json.loads(response.read())["service"], "lowkey-local-source-workspace")

            body = json.dumps({
                "name": "Uploaded",
                "files": [{
                    "path": "Sample.sol",
                    "content": "pragma solidity ^0.8.20; contract Sample { uint256 public value; }",
                }],
            }).encode("utf-8")
            request = urllib.request.Request(
                base + "/api/import",
                data=body,
                headers={"Content-Type": "application/json", "Origin": base},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read())
            self.assertEqual(payload["graph"]["schema_version"], 2)
            self.assertTrue(any(n["label"] == "Sample" for n in payload["graph"]["nodes"]))
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
