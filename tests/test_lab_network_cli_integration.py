"""The public lk CLI dispatcher reaches project-scoped network commands."""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENTRY = ROOT / "lowkey" / "lk.py"


def _run(project, home, *args):
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    environment["XDG_CONFIG_HOME"] = str(home / ".config")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, str(ENTRY), *args],
        cwd=project,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_public_cli_routes_lab_network_list_to_selected_project(tmp_path):
    project = tmp_path / "project"
    home = tmp_path / "home"
    project.mkdir()
    home.mkdir()
    (project / "foundry.toml").write_text('[profile.default]\nsrc="src"\n', encoding="utf-8")
    result = _run(project, home, "lab", "network", "list")
    assert result.returncode == 0, result.stderr
    assert "No managed networks for this project." in result.stdout
    assert (project / ".audit" / "context.json").is_file()
    assert not (home / ".config" / "lowkey" / "config.json").exists()


def test_public_cli_fails_closed_when_requested_managed_anvil_cannot_start(tmp_path):
    project = tmp_path / "project"
    home = tmp_path / "home"
    project.mkdir()
    home.mkdir()
    (project / "foundry.toml").write_text('[profile.default]\n', encoding="utf-8")
    # A deliberately minimal PATH makes anvil unavailable without modifying
    # the host's Foundry installation or any existing managed network.
    environment = os.environ.copy()
    environment.update({
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    result = subprocess.run(
        [sys.executable, str(ENTRY), "lab", "network", "create", "--name", "must-not-start"],
        cwd=project, env=environment, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 2
    combined = result.stdout + result.stderr
    assert "anvil" in combined.lower()
    assert "no such file" in combined.lower() or "not found" in combined.lower()
    state_path = project / ".audit" / "anvil.json"
    assert not state_path.exists() or '"managed_sessions": {}' in state_path.read_text()



def test_public_cli_resolves_network_create_help_without_mutating_network_state(tmp_path):
    project = tmp_path / "project"
    home = tmp_path / "home"
    project.mkdir()
    home.mkdir()
    (project / "foundry.toml").write_text('[profile.default]\nsrc="src"\n', encoding="utf-8")

    result = _run(project, home, "lab", "network", "create", "--help")

    assert result.returncode == 0, result.stderr
    assert "Usage: lk lab network create" in result.stdout
    assert "Unknown subcommand" not in result.stdout
    assert not (project / ".audit" / "anvil.json").exists()
