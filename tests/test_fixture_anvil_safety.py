"""Legacy fixture PIDs are never trusted as process ownership proof."""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lowkeycast_fixture_safety", ROOT / "lowkey" / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


def test_legacy_fixture_pid_is_not_treated_as_owned_process():
    old_pid, base = lk._fixture_anvil_lineage({
        "purpose": "project-fixture-block-context",
        "pid": 41234,
        "rpc": "http://127.0.0.1:8545",
        "base_anvil": {"auto_started": True, "pid": 111},
    }, "http://127.0.0.1:8545")
    assert old_pid is None
    assert base == {"auto_started": True, "pid": 111}


def test_registered_fixture_session_id_is_returned_for_safe_replacement():
    old_id, _ = lk._fixture_anvil_lineage({
        "purpose": "project-fixture-block-context",
        "fixture_session_id": "session-uuid-123",
        "pid": 41234,
    }, "http://127.0.0.1:8545")
    assert old_id == "session-uuid-123"


def test_stopping_fixture_restores_only_verified_active_network(monkeypatch, tmp_path):
    class FakeManager:
        def __init__(self):
            self.state = {
                "fixture_session_id": "fixture-id",
                "purpose": "project-fixture-block-context",
                "rpc": "http://127.0.0.1:8550",
                "pid": 500,
                "managed_session_id": "old-session-id",
                "active_session_id": "base-session-id",
                "managed_sessions": {
                    "base-session-id": {
                        "name": "dev", "pid": 400,
                        "rpc": "http://127.0.0.1:8545",
                        "started_at": "2026-11-26T10:00:00+03:00",
                    },
                },
            }
            self.written = None

        def list(self):
            return [{
                "id": "base-session-id", "name": "dev", "pid": 400,
                "rpc": "http://127.0.0.1:8545", "started_at": "2026-11-26T10:00:00+03:00",
                "process_owned": True, "status": "running",
            }]

        def stop_session(self, session_id):
            assert session_id == "fixture-id"
            return {"id": session_id, "name": "fixture-context", "status": "stopped"}

        def _read(self):
            return dict(self.state)

        def _write(self, state):
            self.written = dict(state)

    manager = FakeManager()
    monkeypatch.setattr(lk, "_project_network_manager", lambda _root: manager)
    monkeypatch.setattr(lk, "read_project_anvil_state", lambda _root: manager.state)
    monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)

    assert lk.stop_project_anvil(tmp_path) == 0
    assert manager.written["rpc"] == "http://127.0.0.1:8545"
    assert manager.written["pid"] == 400
    assert manager.written["managed_session_id"] == "base-session-id"
    assert "fixture_session_id" not in manager.written


def test_stopping_fixture_does_not_resurrect_unverified_legacy_pid(monkeypatch, tmp_path):
    class FakeManager:
        def __init__(self):
            self.state = {
                "fixture_session_id": "fixture-id",
                "purpose": "project-fixture-block-context",
                "rpc": "http://127.0.0.1:8550",
                "pid": 500,
                "auto_started": True,
                "managed_session_id": "old-stale-id",
            }
            self.written = None

        def list(self):
            return []

        def stop_session(self, session_id):
            return {"id": session_id, "name": "fixture-context", "status": "stopped"}

        def _read(self):
            return dict(self.state)

        def _write(self, state):
            self.written = dict(state)

    manager = FakeManager()
    monkeypatch.setattr(lk, "_project_network_manager", lambda _root: manager)
    monkeypatch.setattr(lk, "read_project_anvil_state", lambda _root: manager.state)
    monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)

    assert lk.stop_project_anvil(tmp_path) == 0
    for key in ("rpc", "pid", "auto_started", "managed_session_id", "fixture_session_id"):
        assert key not in manager.written
