from __future__ import annotations

import json
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import error_context


class ErrorContextHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = pathlib.Path(self.temp.name)
        self.project = base / "ETH Escrow"
        self.project.mkdir()
        self.state_root = base / "state" / "lowkey"
        self.state_patch = patch.object(error_context, "state_dir", return_value=self.state_root)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)

    def test_missing_project_has_empty_context_and_is_not_written(self):
        self.assertIsNone(error_context.record_command_event(
            project_root=None,
            command=["build"],
            exit_code=0,
            output="Compiler run successful.",
        ))
        result = error_context.read_project_context(None)
        self.assertEqual(result["events"], [])
        self.assertEqual(result["project_knowledge"], {})
        self.assertFalse(self.state_root.exists())

    def test_build_warning_is_reusable_by_a_later_lab_failure(self):
        build_output = """Compiler run successful with warnings:
Warning (6321): Unnamed return variable can remain unassigned.
 --> script/EthEscrow.s.sol:9:38:
Warning (2072): Unused local variable.
 --> script/EthEscrow.s.sol:12:9:
"""
        lab_output = (
            "Error: local project deployment ran, but Lowkey could not identify "
            "a deployed application target."
        )

        build_event = error_context.record_command_event(
            project_root=self.project,
            command=["build"],
            exit_code=0,
            output=build_output,
        )
        lab_event = error_context.record_command_event(
            project_root=self.project,
            command=["lab"],
            exit_code=2,
            output=lab_output,
        )

        self.assertEqual(build_event["status"], "completed")
        self.assertEqual(lab_event["status"], "failed")
        shared = error_context.read_project_context(self.project)
        self.assertEqual([event["command"] for event in shared["events"]], ["build", "lab"])
        self.assertIn("Unnamed return variable", shared["events"][0]["diagnostic_excerpt"])
        self.assertTrue(any("Compiler warning" in signal for signal in shared["events"][0]["signals"]))
        self.assertTrue(any("target discovery failed" in signal.lower() for signal in shared["events"][1]["signals"]))
        self.assertNotIn(str(self.project), json.dumps(shared))

    def test_history_is_bounded_and_recent_events_are_returned_in_order(self):
        for index in range(35):
            error_context.record_command_event(
                project_root=self.project,
                command=["probe", str(index)],
                exit_code=0 if index % 2 == 0 else 1,
                output=f"Probe {index} completed.",
            )

        history_path, _ = error_context._project_context_path(self.project)
        stored = json.loads(history_path.read_text(encoding="utf-8"))
        self.assertEqual(len(stored["events"]), 30)
        self.assertEqual(stored["events"][0]["command"], "probe 5")
        self.assertEqual(stored["events"][-1]["command"], "probe 34")

        recent = error_context.read_project_context(self.project, max_events=3)
        self.assertEqual([event["command"] for event in recent["events"]], ["probe 32", "probe 33", "probe 34"])

    def test_secrets_and_absolute_project_paths_are_not_exposed_to_readers(self):
        api_key = "sk-" + "A" * 28
        private_key = "0x" + "1" * 64
        output = (
            "Warning (6321): Unnamed return variable can remain unassigned.\n"
            + "OPENAI_API_KEY=" + api_key + "\n"
            + "--private-key " + private_key + "\n"
            + str(self.project) + "/script/Deploy.s.sol:9:38"
        )
        error_context.record_command_event(
            project_root=self.project,
            command=["build"],
            exit_code=0,
            output=output,
        )

        history_path, _ = error_context._project_context_path(self.project)
        saved = history_path.read_text(encoding="utf-8")
        returned = json.dumps(error_context.read_project_context(self.project))
        self.assertNotIn(api_key, saved)
        self.assertNotIn(private_key, saved)
        self.assertNotIn(str(self.project), returned)
        self.assertIn("[REDACTED", saved)

    def test_project_histories_are_isolated_and_files_are_private(self):
        second_project = pathlib.Path(self.temp.name) / "Token Sale"
        second_project.mkdir()
        error_context.record_command_event(
            project_root=self.project,
            command=["build"],
            exit_code=0,
            output="First project build.",
        )
        error_context.record_command_event(
            project_root=second_project,
            command=["test"],
            exit_code=0,
            output="Second project test.",
        )

        first = error_context.read_project_context(self.project)
        second = error_context.read_project_context(second_project)
        self.assertEqual([event["command"] for event in first["events"]], ["build"])
        self.assertEqual([event["command"] for event in second["events"]], ["test"])

        history_path, _ = error_context._project_context_path(self.project)
        self.assertEqual(stat.S_IMODE(history_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(history_path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.state_root / "projects").stat().st_mode), 0o700)

    def test_corrupt_history_does_not_block_context_reads(self):
        history_path, _ = error_context._project_context_path(self.project)
        history_path.parent.mkdir(parents=True, exist_ok=True)
        history_path.write_text("{broken json", encoding="utf-8")

        result = error_context.read_project_context(self.project)
        self.assertEqual(result["events"], [])
        self.assertIsInstance(result["project_knowledge"], dict)


if __name__ == "__main__":
    unittest.main()
