import hashlib
import io
import json
import pathlib
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import unittest
import unittest.mock
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

from source_index import build_source_index
from source_link import main
import source_explorer
import protocol_graph
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

    def test_source_index_keeps_excluded_dependency_directory_coverage(self):
        self.assertIn("excluded_directories", self.index["inventory"])
        self.assertIsInstance(self.index["inventory"]["excluded_directories"], list)
        self.assertEqual(self.model["inventory"]["excluded_directories"], self.index["inventory"]["excluded_directories"])

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
            if e["kind"] == "EXTERNAL_CALL" and e.get("details", {}).get("method") == "pluginTransfer"
        ]
        self.assertTrue(library_edges, "using-for library calls should remain visible as separate edges")
        self.assertTrue(interface_edges, "typed interface calls should remain visible as external-call edges")
        self.assertTrue(any(e.get("implementation_resolution") == "UNRESOLVED" for e in interface_edges))

    def test_model_embeds_full_source_with_relative_path_hash_and_line_metadata(self):
        sources = {item["path"]: item for item in self.model["sources"]}
        source = sources["src/Protocol.sol"]
        expected = (self.root / "src" / "Protocol.sol").read_bytes()
        self.assertEqual(source["status"], "EMBEDDED")
        self.assertEqual(source["content"], expected.decode("utf-8-sig"))
        self.assertEqual(source["sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(source["line_count"], len(source["content"].splitlines()))
        self.assertNotIn(str(self.root), source["path"])
        self.assertLessEqual(self.model["source_inventory"]["embedded_bytes"], 8 * 1024 * 1024)
        self.assertRegex(self.model["workspace_key"], r"^[0-9a-f]{32}$")
        self.assertEqual(build_explorer_model(self.index, root=self.root)["workspace_key"], self.model["workspace_key"])

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
        self.assertIn('id="entrypoint-explorer"', document)
        self.assertIn("focus_group_ids", document)
        self.assertIn("incidentEdgesByNode", document)
        self.assertIn("function edgeGeometry(edge)", document)
        self.assertIn('id="source-drawer"', document)
        self.assertIn("Open full Solidity source", document)
        self.assertIn("function renderSourceWindow(source)", document)
        self.assertIn("NESTED TYPES & DECLARATIONS", document)
        self.assertIn("function renderTypeInspector(parent,selected)", document)
        self.assertIn("INHERITANCE / C3 LINEARIZATION", document)
        self.assertIn("COMPILER DISPATCH FACTS", document)
        self.assertIn("INTERFACE IMPLEMENTATION BINDING", document)
        self.assertIn("ASSERTED ASSUMPTION", document)
        self.assertIn("function manualBindingEdges(sourceEdges)", document)
        self.assertIn('id="bookmark-explorer"', document)
        self.assertIn('id="scope-inline-libraries"', document)
        self.assertIn('id="scope-excluded-paths"', document)
        self.assertIn('id="scope-apply-paths"', document)
        self.assertIn("Exclude contract from scope", document)
        self.assertIn("function renderScopePanel()", document)
        self.assertIn("function saveWorkspaceState()", document)
        self.assertIn("function loadWorkspaceState()", document)
        self.assertIn("manual_positions", document)
        self.assertIn("Mark investigated", document)
        self.assertNotIn("__GRAPH_DATA__", document)
        self.assertNotIn("__SERVER_MODE__", document)
        self.assertNotIn('<script src="https://', document)

    def test_entrypoint_model_includes_receive_fallback_and_excludes_constructor(self):
        (self.root / "src" / "Entrypoints.sol").write_text(
            """
            pragma solidity ^0.8.20;
            contract Entrypoints {
                constructor() {}
                receive() external payable {}
                fallback() external payable {}
                function execute() external {}
                function inspect() external view returns (uint256) { return 1; }
            }
            """,
            encoding="utf-8",
        )
        index = build_source_index(self.root, use_cache=False)
        model = build_explorer_model(index, root=self.root)
        functions = {
            item["name"]: item
            for item in model["nodes"]
            if item.get("contract") == "Entrypoints" and item["type"] == "function"
        }
        self.assertTrue(functions["receive"]["entrypoint"])
        self.assertEqual(functions["receive"]["entrypoint_kind"], "receive")
        self.assertTrue(functions["fallback"]["entrypoint"])
        self.assertEqual(functions["fallback"]["entrypoint_kind"], "fallback")
        self.assertTrue(functions["execute"]["entrypoint"])
        self.assertEqual(functions["execute"]["entrypoint_kind"], "function")
        self.assertTrue(functions["inspect"]["entrypoint"])
        self.assertFalse(functions["constructor"]["entrypoint"])
        self.assertIsNone(functions["constructor"]["entrypoint_kind"])

    def test_nested_struct_enum_udvt_parameter_return_and_state_types_are_navigable(self):
        source = """
        pragma solidity ^0.8.20;
        type Wad is uint256;
        contract TypeInspector {
            struct Inner { Wad amount; }
            struct Outer { Inner inner; }
            enum Status { Pending, Complete }
            struct Receipt { Status status; Outer data; }
            Outer private cached;
            function submit(Outer calldata request) external returns (Receipt memory result) {
                return result;
            }
        }
        """
        (self.root / "src" / "Types.sol").write_text(source, encoding="utf-8")
        index = build_source_index(self.root, use_cache=False)
        model = build_explorer_model(index, root=self.root)

        by_name = {
            (item["kind"], item["name"], item.get("contract") or ""): item
            for item in model["nodes"]
        }
        wad = by_name[("user_defined_value_type", "Wad", "")]
        inner = by_name[("struct", "Inner", "TypeInspector")]
        outer = by_name[("struct", "Outer", "TypeInspector")]
        status = by_name[("enum", "Status", "TypeInspector")]
        receipt = by_name[("struct", "Receipt", "TypeInspector")]

        def has_type_edge(source_node, target_node, **detail):
            return any(
                edge["kind"] == "USES_TYPE"
                and edge["source"] == source_node["id"]
                and edge["target"] == target_node["id"]
                and all(edge["details"].get(key) == value for key, value in detail.items())
                for edge in model["edges"]
            )

        inner_amount = next(
            item for item in model["nodes"]
            if item["kind"] == "struct_field" and item["name"] == "amount" and item.get("struct") == "Inner"
        )
        outer_inner = next(
            item for item in model["nodes"]
            if item["kind"] == "struct_field" and item["name"] == "inner" and item.get("struct") == "Outer"
        )
        receipt_status = next(
            item for item in model["nodes"]
            if item["kind"] == "struct_field" and item["name"] == "status" and item.get("struct") == "Receipt"
        )
        cached = next(
            item for item in model["nodes"]
            if item["kind"] == "state_variable" and item["name"] == "cached"
        )
        submit = next(
            item for item in model["nodes"]
            if item["kind"] == "function" and item.get("contract") == "TypeInspector" and item["name"] == "submit"
        )

        self.assertEqual(wad["underlying_type"], "uint256")
        self.assertEqual(inner_amount["type_text"], "Wad")
        self.assertEqual(outer_inner["type_text"], "Inner")
        self.assertEqual(receipt_status["type_text"], "Status")
        self.assertTrue(has_type_edge(inner_amount, wad))
        self.assertTrue(has_type_edge(outer_inner, inner))
        self.assertTrue(has_type_edge(receipt_status, status))
        self.assertTrue(has_type_edge(cached, outer))
        self.assertTrue(has_type_edge(submit, outer, parameter="request"))
        self.assertTrue(has_type_edge(submit, receipt, return_index=1))
        self.assertEqual(submit["return_parameters"][0]["declared_type"], "Receipt memory")
        self.assertTrue(any(item["type"] == "enum_value" and item["name"] == "Complete" for item in model["nodes"]))

    def test_compiler_c3_linearization_and_override_facts_are_exposed_without_guessing(self):
        source = """
        pragma solidity ^0.8.20;
        contract DispatchBase {
            function run(uint256 value) public virtual {}
        }
        contract DispatchLeft is DispatchBase {
            function run(uint256 value) public virtual override {}
        }
        contract DispatchRight is DispatchBase {
            function run(uint256 value) public virtual override {}
        }
        contract DispatchFinal is DispatchLeft, DispatchRight {
            function run(uint256 value) public override(DispatchLeft, DispatchRight) {}
        }
        """
        path = self.root / "src" / "Dispatch.sol"
        path.write_text(source, encoding="utf-8")
        index = build_source_index(self.root, use_cache=False)

        contract_ids = {
            name: "ast-contract:" + name
            for name in ("DispatchBase", "DispatchLeft", "DispatchRight", "DispatchFinal")
        }
        expected_order = {
            "DispatchBase": ["DispatchBase"],
            "DispatchLeft": ["DispatchLeft", "DispatchBase"],
            "DispatchRight": ["DispatchRight", "DispatchBase"],
            "DispatchFinal": ["DispatchFinal", "DispatchRight", "DispatchLeft", "DispatchBase"],
        }
        compiler_nodes = []
        for name, order in expected_order.items():
            compiler_nodes.append({
                "id": contract_ids[name],
                "kind": "contract",
                "name": name,
                "source": "src/Dispatch.sol",
                "linearized_base_ids": list(range(len(order))),
                "linearized_base_contracts": [contract_ids[item] for item in order],
            })

        function_ids = {
            name: "ast-function:" + name
            for name in ("DispatchBase", "DispatchLeft", "DispatchRight", "DispatchFinal")
        }
        for index_number, name in enumerate(function_ids):
            signature_start = source.index("function run", source.index("contract " + name))
            compiler_nodes.append({
                "id": function_ids[name],
                "compiler_id": 100 + index_number,
                "kind": "function",
                "name": "run",
                "signature": "run(uint256)",
                "contract": contract_ids[name],
                "source": "src/Dispatch.sol",
                "source_span": str(len(source[:signature_start].encode("utf-8"))) + ":40:0",
                "is_virtual": name != "DispatchFinal",
                "has_override_specifier": name != "DispatchBase",
                "base_function_ids": [function_ids["DispatchBase"]] if name != "DispatchBase" else [],
            })

        final_function_start = source.index("function run", source.index("contract DispatchFinal"))
        compiler_graph = {
            "status": "AST_OBSERVED",
            "accepted_builds": 1,
            "compiler_versions": ["0.8.20"],
            "limitations": [],
            "nodes": compiler_nodes,
            "edges": [{
                "kind": "compiler_override_candidate",
                "source": function_ids["DispatchFinal"],
                "target": function_ids["DispatchBase"],
                "source_span": str(len(source[:final_function_start].encode("utf-8"))) + ":40:0",
                "certainty": "compiler_declared_base_function",
            }],
        }
        with unittest.mock.patch.object(protocol_graph, "compiler_ast_graph", return_value=compiler_graph):
            model = build_explorer_model(index, root=self.root)

        declarations = {
            item["name"]: item for item in model["nodes"] if item["type"] == "declaration"
        }
        final = declarations["DispatchFinal"]
        self.assertEqual(final["c3_status"], "COMPILER_AST")
        self.assertEqual(
            [item["name"] for item in final["c3_linearization"]],
            expected_order["DispatchFinal"],
        )
        self.assertEqual(
            [item["rank"] for item in final["c3_linearization"]],
            [1, 2, 3, 4],
        )

        final_function = next(
            item for item in model["nodes"]
            if item["type"] == "function" and item["contract"] == "DispatchFinal"
        )
        self.assertIn("compiler_dispatch", final_function)
        self.assertFalse(final_function["compiler_dispatch"]["is_virtual"])
        self.assertTrue(final_function["compiler_dispatch"]["has_override_specifier"])
        override = next(
            edge for edge in model["edges"]
            if edge["kind"] == "OVERRIDES" and edge["source"] == final_function["id"]
        )
        self.assertEqual(override["evidence"], "COMPILER_AST")
        self.assertEqual(override["file"], "src/Dispatch.sol")
        self.assertEqual(override["line"], source[:final_function_start].count("\n") + 1)

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

    def test_upload_does_not_strip_real_src_directory(self):
        destination = self.root / "src-root-upload"
        write_uploaded_files(
            [{"path": "src/OnlySource.sol", "content": "pragma solidity ^0.8.20; contract OnlySource {}"}],
            destination,
        )
        self.assertTrue((destination / "src" / "OnlySource.sol").is_file())
        self.assertFalse((destination / "OnlySource.sol").exists())

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

    def test_archive_cli_exports_the_same_explorer_graph(self):
        archive = self.root / "cli-project.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("project/foundry.toml", '[profile.default]\nsrc = "src"\n')
            bundle.writestr("project/src/Imported.sol", "pragma solidity ^0.8.20; contract Imported {}")
            bundle.writestr("project/README.md", "Project documentation")
        output = self.root / "imported-graph.html"
        import io
        from contextlib import redirect_stdout
        capture = io.StringIO()
        with redirect_stdout(capture):
            status = main(["link", "--archive", str(archive), "--format", "html", "--output", str(output)])
        self.assertEqual(status, 0, capture.getvalue())
        self.assertTrue(output.is_file())
        document = output.read_text(encoding="utf-8")
        self.assertIn("PROTOCOL GRAPH", document)
        self.assertIn("Imported", document)

    def test_zip_import_checks_actual_decompressed_length(self):
        class FakeInfo:
            filename = "src/Mismatch.sol"
            external_attr = 0
            file_size = 3

            @staticmethod
            def is_dir():
                return False

        class FakeZip:
            def __init__(self, _path):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            @staticmethod
            def infolist():
                return [FakeInfo()]

            @staticmethod
            def open(_info):
                return io.BytesIO(b"longer than metadata")

        with unittest.mock.patch.object(source_explorer.zipfile, "ZipFile", FakeZip):
            with self.assertRaisesRegex(ValueError, "inconsistent ZIP size metadata"):
                extract_source_archive(self.root / "unused.zip", self.root / "mismatch")

    def test_local_source_api_serves_only_contained_solidity_paths(self):
        server = create_explorer_server(self.index, root=self.root, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            base = f"http://{host}:{port}"
            with urllib.request.urlopen(base + "/api/source?path=src%2FProtocol.sol", timeout=5) as response:
                source = json.loads(response.read())
            self.assertEqual(source["path"], "src/Protocol.sol")
            self.assertEqual(source["status"], "SERVED_LOCAL")
            self.assertIn("contract Protocol", source["content"])
            self.assertEqual(source["sha256"], hashlib.sha256((self.root / "src" / "Protocol.sol").read_bytes()).hexdigest())

            outside = self.root.parent / "lowkey-outside-source.sol"
            outside.write_text("contract Outside {}", encoding="utf-8")
            escaped = self.root / "src" / "Escaped.sol"
            escaped.symlink_to(outside)
            for unsafe in ("../outside.sol", "/etc/passwd.sol", "src\\\\..\\\\outside.sol", "foundry.toml", "src/Escaped.sol"):
                with self.subTest(unsafe=unsafe):
                    url = base + "/api/source?path=" + urllib.parse.quote(unsafe, safe="")
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(url, timeout=5)
                    self.assertEqual(error.exception.code, 400)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_project_workspace_api_persists_interface_assumptions_merge_safely(self):
        interface = next(
            item for item in self.model["nodes"]
            if item["type"] == "declaration" and item["declaration_kind"] == "interface"
        )
        implementation = next(
            item for item in self.model["nodes"]
            if item["type"] == "declaration" and item["declaration_kind"] == "contract"
        )
        audit = self.root / ".audit"
        audit.mkdir()
        context_path = audit / "context.json"
        context_path.write_text(json.dumps({
            "schema_version": 1,
            "project": {"root": str(self.root), "name": self.root.name},
            "target": {"address": "0x" + "1" * 40, "contract": "Protocol", "artifact": None},
            "custom_preserved_marker": {"keep": True},
        }), encoding="utf-8")

        server = create_explorer_server(self.index, root=self.root, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            base = f"http://{host}:{port}"
            payload = {
                "version": 1,
                "workspace_key": self.model["workspace_key"],
                "interface_bindings": [[interface["id"], implementation["id"]]],
                "scope_preferences": {
                    "include_support_sources": True,
                    "inline_libraries": False,
                    "excluded_contract_ids": [implementation["id"]],
                    "excluded_path_prefixes": ["test/fixtures"],
                },
            }
            request = urllib.request.Request(
                base + "/api/workspace",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                saved = json.loads(response.read())
            self.assertTrue(saved["ok"])
            self.assertTrue(saved["persisted"])
            self.assertEqual(saved["workspace"]["interface_bindings"], [[interface["id"], implementation["id"]]])
            self.assertEqual(saved["workspace"]["scope_preferences"], {
                "include_support_sources": True,
                "inline_libraries": False,
                "excluded_contract_ids": [implementation["id"]],
                "excluded_path_prefixes": ["test/fixtures"],
            })

            with urllib.request.urlopen(base + "/api/workspace", timeout=5) as response:
                loaded = json.loads(response.read())
            self.assertEqual(loaded["interface_bindings"], [[interface["id"], implementation["id"]]])
            self.assertFalse(loaded["scope_preferences"]["inline_libraries"])
            self.assertEqual(loaded["scope_preferences"]["excluded_path_prefixes"], ["test/fixtures"])

            persisted = json.loads(context_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["target"]["address"], "0x" + "1" * 40)
            self.assertEqual(persisted["custom_preserved_marker"], {"keep": True})
            self.assertEqual(persisted["protocol_graph_workspace"]["interface_bindings"], [[interface["id"], implementation["id"]]])
            self.assertEqual(persisted["protocol_graph_workspace"]["scope_preferences"]["excluded_contract_ids"], [implementation["id"]])
            self.assertFalse(persisted["protocol_graph_workspace"]["scope_preferences"]["inline_libraries"])

            invalid = dict(payload)
            invalid["interface_bindings"] = [[interface["id"], interface["id"]]]
            request = urllib.request.Request(
                base + "/api/workspace",
                data=json.dumps(invalid).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(error.exception.code, 400)

            invalid_scope = dict(payload)
            invalid_scope["scope_preferences"] = {
                "include_support_sources": False,
                "inline_libraries": True,
                "excluded_contract_ids": [implementation["id"]],
                "excluded_path_prefixes": ["../outside"],
            }
            request = urllib.request.Request(
                base + "/api/workspace",
                data=json.dumps(invalid_scope).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as scope_error:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(scope_error.exception.code, 400)

            invalid_contract_scope = dict(payload)
            invalid_contract_scope["scope_preferences"] = {
                "include_support_sources": False,
                "inline_libraries": True,
                "excluded_contract_ids": [interface["id"]],
                "excluded_path_prefixes": ["test/fixtures"],
            }
            request = urllib.request.Request(
                base + "/api/workspace",
                data=json.dumps(invalid_contract_scope).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as contract_scope_error:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(contract_scope_error.exception.code, 400)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

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
            imported_source = next(item for item in payload["graph"]["sources"] if item["path"] == "Sample.sol")
            self.assertEqual(imported_source["status"], "EMBEDDED")
            self.assertIn("contract Sample", imported_source["content"])
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
