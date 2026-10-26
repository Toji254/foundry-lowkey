import json
import tempfile
import unittest
from pathlib import Path

from lowkey.agent_runtime import (
    AgentPlan, AgentRegistry, AgentRuntime, AgentRuntimeError, AgentSpec, ToolRegistry, ToolSpec,
)


class AgentRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runtime = AgentRuntime(self.root)

    def test_agent_plan_can_only_contain_registered_capabilities(self):
        plan = self.runtime.plan("security-review", ["read_source", "provider_request"])
        self.assertEqual(set(plan.actions), {"read_source", "provider_request"})
        with self.assertRaisesRegex(AgentRuntimeError, "cannot plan"):
            self.runtime.plan("security-review", ["deploy_contract"])

    def test_execution_requires_plan_and_permission(self):
        plan = self.runtime.plan("security-review", ["read_source"])
        with self.assertRaisesRegex(AgentRuntimeError, "was not granted"):
            self.runtime.run_action(plan, "read_source", lambda: "source", granted_permissions=set())
        with self.assertRaisesRegex(AgentRuntimeError, "not included in plan"):
            self.runtime.run_action(plan, "provider_request", lambda: "provider", granted_permissions={"provider_request"})

    def test_only_explicitly_registered_tools_can_execute(self):
        registry = ToolRegistry()
        with self.assertRaisesRegex(AgentRuntimeError, "not registered"):
            registry.invoke("arbitrary-shell", root=self.root, arguments={"command": "id"},
                            granted_permissions={"shell"}, approved=True, runtime=self.runtime)

    def test_high_impact_tool_requires_explicit_approval(self):
        registry = ToolRegistry()
        registry.register(ToolSpec("safe-fixture", "fixture-write", lambda **kwargs: {"status": "passed"},
                                   requires_explicit_approval=True))
        with self.assertRaisesRegex(AgentRuntimeError, "explicit user-approved"):
            registry.invoke("safe-fixture", root=self.root, arguments={},
                            granted_permissions={"fixture-write"}, approved=False, runtime=self.runtime)

    def test_delegation_is_allowlisted_and_bounded(self):
        plan = self.runtime.plan("security-review", ["read_source"])
        result = self.runtime.delegate(
            plan, "source-evidence-checker", ["source_quote_check"],
            lambda: {"matched": True}, granted_permissions={"source_quote_check"},
        )
        self.assertEqual(result, {"matched": True})
        with self.assertRaisesRegex(AgentRuntimeError, "cannot delegate"):
            self.runtime.delegate(
                plan, "native-test-verifier", ["run_native_test"],
                lambda: {}, granted_permissions={"run_native_test"},
            )

    def test_runtime_log_records_actions_but_not_raw_secrets(self):
        plan = self.runtime.plan("security-review", ["read_source"])
        secret = "PRIVATE_SENTINEL_NOT_FOR_LOGS"
        self.runtime.run_action(
            plan, "read_source", lambda: {"payload": secret},
            granted_permissions={"read_source"},
        )
        events = [json.loads(line) for line in self.runtime.event_path.read_text().splitlines()]
        self.assertTrue(any(event["action"] == "read_source" and event["status"] == "completed" for event in events))
        self.assertNotIn(secret, self.runtime.event_path.read_text())


if __name__ == "__main__":
    unittest.main()
