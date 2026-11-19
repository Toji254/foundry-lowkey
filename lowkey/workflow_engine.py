#!/usr/bin/env python3
"""Evidence-aware audit checkpoints layered over Lowkey's existing q engine."""
from __future__ import annotations
import argparse, json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

try:
    import audit_context
    import question_engine
except ImportError:
    from lowkey import audit_context, question_engine

PHASES = (
    ("PREPARE", "Freeze scope and baseline",
     "Pin revision, read scope/docs, record compiler/dependency assumptions, and understand the existing build/test state.",
     "Scope/exclusions are understood and a real build matches the reviewed source snapshot.",
     "lk project | lk build | lk test"),
    ("MAP", "Map assets and trust boundaries",
     "Map assets/liabilities, actors/roles, entry points, dependencies, external calls, state transitions and invariants.",
     "The critical system map and security properties are written down.",
     "lk system | lk functions | lk deps | lk q"),
    ("HUNT", "Generate ranked attack hypotheses",
     "Compare intended behavior with reachable paths. Prioritize authorization, accounting, callbacks, signatures/nonces, oracles, upgrades, ordering and DoS.",
     "High-value hypotheses have exact locations, assumptions and plausible impact.",
     "lk q | lk findings | lk risk"),
    ("PROVE", "Prove or kill each hypothesis",
     "Build the smallest reproducible PoC. Compare attack and control from equivalent pre-state; inspect trace and state changes.",
     "Each reportable hypothesis has a runnable PoC, meaningful control, violated property and measured impact.",
     "lk test --match-test <PoCName> -vvvv | lk trace | lk changes"),
    ("VERIFY", "Validate impact and remediation",
     "Justify severity, re-check alternate paths, inspect fixes in context, run regressions and preserve the exact reviewed revision.",
     "Findings/limitations are reproducible; fixes close the path and regression tests pass.",
     "lk test | lk report"),
)
STATE_DIR = Path(".audit") / "workflow"
STATE_FILE = "state.json"

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _root(hint=None) -> Path:
    return Path(audit_context.foundry_project_root(hint)).expanduser().resolve()

def _path(root: Path) -> Path:
    return root / STATE_DIR / STATE_FILE

def _default(root: Path) -> dict[str, Any]:
    return {"schema_version": 1, "project_root": str(root), "started": False,
            "started_at": None, "baseline": None, "completed": {}, "notes": [],
            "last_build": None, "build_tip_shown": False}

def _load(root: Path) -> dict[str, Any]:
    try:
        state = json.loads(_path(root).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _default(root)
    if not isinstance(state, dict) or state.get("project_root") != str(root):
        return _default(root)
    fresh = _default(root)
    fresh.update(state)
    if not isinstance(fresh.get("completed"), dict): fresh["completed"] = {}
    if not isinstance(fresh.get("notes"), list): fresh["notes"] = []
    return fresh

def _save(root: Path, state: dict[str, Any]) -> None:
    path = _path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    state = dict(state)
    state["schema_version"] = 1
    state["project_root"] = str(root)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)

def _snapshot(root: Path) -> dict[str, Any]:
    def git(args):
        try:
            result = subprocess.run(args, cwd=root, capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.stdout.strip() if result.returncode == 0 else None
    commit = git(["git", "rev-parse", "HEAD"])
    branch = git(["git", "branch", "--show-current"])
    status = git(["git", "status", "--porcelain", "--untracked-files=all", "--",
                  ".", ":(exclude).audit/**"])
    paths = None if status is None else sorted(line[3:].strip() for line in status.splitlines() if len(line) >= 4)
    return {"commit": commit, "branch": branch, "dirty_paths": paths, "captured_at": _now()}

def _matches(a, b) -> bool:
    return bool(isinstance(a, dict) and isinstance(b, dict) and a.get("commit")
                and b.get("commit") and a.get("commit") == b.get("commit")
                and a.get("dirty_paths") == b.get("dirty_paths"))

def _build_current(root: Path, state: dict[str, Any]) -> bool:
    build = state.get("last_build")
    return bool(isinstance(build, dict) and _matches(build.get("snapshot"), _snapshot(root)))

def _current(state):
    return next((p for p in PHASES if p[0] not in state.get("completed", {})), None)

def _parse_time(value):
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None

def _events(root, state):
    start = _parse_time(state.get("started_at"))
    if not start: return []
    try: items = audit_context.read_events(root, limit=500)
    except Exception: return []
    return [e for e in items if isinstance(e, dict) and
            (stamp := _parse_time(e.get("timestamp"))) is not None and stamp >= start]

def _command(event):
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    command = data.get("command")
    return str(command[0] if isinstance(command, list) and command else command or "")

def _latest(events, name):
    found = [e for e in events if e.get("status") == "completed"
             and _command(e).lower() == name
             and e.get("type") in {"forge-command", "command-completed", "tool-run"}]
    return found[-1] if found else None

def _event_text(event):
    if not event: return "not detected since workflow start"
    stamp = str(event.get("timestamp") or "").replace("T", " ")[:19]
    return "completed" + (f" • {stamp} UTC" if stamp else "")

def _project_ok(root):
    try: return bool(audit_context.is_audit_project(root))
    except Exception: return (root / "foundry.toml").is_file()

def render(root: Path) -> str:
    state = _load(root)
    phase = _current(state)
    lines = ["", "LOWKEY // AUDIT WORKFLOW", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
             f"PROJECT • {root.name}"]
    if not state["started"]:
        lines += ["STATUS • NOT STARTED", "", "Start with: lk workflow start",
                  "State is stored in .audit/workflow/; existing audit evidence is untouched."]
        if state.get("last_build"):
            lines += ["", "LAST BUILD • " + ("CURRENT" if _build_current(root, state) else "OUTDATED / UNPINNED")]
        return "\n".join(lines)
    baseline = state.get("baseline") or {}
    now = _snapshot(root)
    changed = bool(baseline.get("commit") and now.get("commit") and
                   (baseline.get("commit") != now.get("commit") or baseline.get("dirty_paths") != now.get("dirty_paths")))
    complete = state.get("completed", {})
    lines += [f"REVISION • {str(baseline.get('commit') or 'UNPINNED')[:12]}",
              "WORKTREE • " + ("CHANGED SINCE START" if changed else "DIRTY AT START" if baseline.get("dirty_paths") else "CLEAN AT START"),
              f"PROGRESS • {len(complete)}/{len(PHASES)} phases", "", "PHASES"]
    for item in PHASES:
        done = item[0] in complete
        marker = "✓" if done else "→" if phase and item[0] == phase[0] else "○"
        suffix = "completed" if done else "current" if phase and item[0] == phase[0] else "waiting"
        lines.append(f"  {marker} {item[0]:<7} {item[1]} [{suffix}]")
    if changed:
        lines += ["", "SCOPE WARNING", "  The revision or source worktree changed. Reconcile scope before trusting earlier notes/proofs."]
    ev = _events(root, state)
    lines += ["", "AUTOMATIC EVIDENCE",
              "  Foundry build : " + ("CURRENT for this source snapshot" if _build_current(root, state) else "not current / not recorded"),
              "  Forge tests   : " + _event_text(_latest(ev, "test")),
              "  Coverage      : " + _event_text(_latest(ev, "coverage")),
              "  Slither       : " + _event_text(next((e for e in reversed(ev) if e.get("tool") == "slither" and e.get("status") == "completed"), None)),
              "  Observations only; none of these is a security verdict."]
    if phase:
        lines += ["", f"NEXT • {phase[0]} — {phase[1]}", phase[2], "", "EXIT CHECK", f"  {phase[3]}",
                  "", "USEFUL COMMANDS", f"  {phase[4]}",
                  "", 'Record your decision: lk workflow done --note "evidence + conclusion"']
    else:
        lines += ["", "WORKFLOW COMPLETE", "All five human checkpoints are recorded. Preserve the exact reviewed revision and report."]
    try:
        ranked = question_engine.rank_questions(root, limit=1)
        if ranked:
            q = ranked[0]["question"]
            lines += ["", "LOWKEY QUESTION FRONTIER", f"  {q.id} • {q.text}", "  Open details with: lk q"]
    except Exception: pass
    lines += ["", "RULES",
              "  • Lowkey records tool evidence where available; you make the audit judgment.",
              "  • A build/test passing is not proof of security. A heuristic is not a finding.",
              "  • No AI/provider is required.",
              "", "CONTROLS", "  lk workflow start", "  lk workflow", '  lk workflow note "..."',
              '  lk workflow done --note "..."', "  lk workflow reset --yes"]
    return "\n".join(lines)

def start(root: Path) -> int:
    state = _load(root)
    if state["started"]:
        print("Workflow already active. Run 'lk workflow' for its next action.")
        return 0
    state.update({"started": True, "started_at": _now(), "baseline": _snapshot(root),
                  "completed": {}, "notes": []})
    _save(root, state)
    base = state["baseline"]
    print(f"Audit workflow started. Scope baseline: {str(base.get('commit') or 'UNPINNED')[:12]}")
    if not base.get("commit"): print("WARNING: no git revision; build freshness cannot be matched automatically.")
    elif base.get("dirty_paths"): print("WARNING: pre-existing source changes are present; reconcile scope before proceeding.")
    print(render(root))
    return 0

def done(root: Path, requested: str | None, note: str) -> int:
    state = _load(root)
    if not state["started"]:
        print("Start first: lk workflow start", file=sys.stderr); return 2
    phase = _current(state)
    if not phase: print("All workflow phases are already complete."); return 0
    if requested and requested.upper() != phase[0]:
        print(f"Complete phases in order. Current phase: {phase[0]}.", file=sys.stderr); return 2
    if not note.strip():
        print("A human evidence note is required with --note.", file=sys.stderr); return 2
    if phase[0] == "PREPARE" and (root / "foundry.toml").is_file() and not _build_current(root, state):
        print("PREPARE blocked: run a real 'lk build' for the current source snapshot. --plan does not count.", file=sys.stderr); return 2
    state.setdefault("completed", {})[phase[0]] = {"at": _now(), "note": note.strip()}
    _save(root, state)
    try:
        audit_context.emit("audit-workflow-phase", root, tool="workflow",
                           summary=f"{phase[0]} checkpoint completed",
                           data={"phase": phase[0], "note": note.strip()})
    except Exception: pass
    following = _current(state)
    print(f"Recorded {phase[0]}. Next phase: {following[0]}" if following else "All five workflow phases are complete.")
    return 0

def add_note(root: Path, note: str, phase_name: str | None) -> int:
    state = _load(root)
    if not state["started"]:
        print("Start first: lk workflow start", file=sys.stderr); return 2
    phase = (phase_name or (_current(state) or ("",))[0]).upper()
    if phase not in {p[0] for p in PHASES}:
        print("Unknown phase.", file=sys.stderr); return 2
    state.setdefault("notes", []).append({"phase": phase, "at": _now(), "text": note.strip()})
    _save(root, state)
    print(f"Saved note under {phase}.")
    return 0

def reset(root: Path) -> int:
    old = _load(root)
    fresh = _default(root)
    fresh["last_build"] = old.get("last_build")
    fresh["build_tip_shown"] = bool(old.get("build_tip_shown"))
    _save(root, fresh)
    print("Workflow checkpoints reset. Audit evidence and question history remain intact.")
    return 0

def on_build_success(root: Path, *, scope: str = "full") -> None:
    """Called only after a real successful build; never affects its exit status."""
    try:
        root = _root(root)
        if not _project_ok(root): return
        state = _load(root)
        state["last_build"] = {"at": _now(), "scope": scope, "snapshot": _snapshot(root)}
        first = not state.get("build_tip_shown")
        state["build_tip_shown"] = True
        _save(root, state)
        if state["started"]:
            phase = _current(state)
            if phase and phase[0] == "PREPARE":
                print("\nAUDIT WORKFLOW: successful build recorded for this source snapshot. Run 'lk workflow'.")
        elif first:
            print("\nAUDIT WORKFLOW SUGGESTION\nCompilation passed; that is not a security review.\n  lk workflow start")
    except Exception:
        return

def _parser():
    parser = argparse.ArgumentParser(prog="lk workflow", description="A lazy, evidence-aware smart-contract audit workflow.")
    parser.add_argument("--root", help="explicit project/package root (before the action)")
    sub = parser.add_subparsers(dest="action")
    sub.add_parser("start", help="pin the audit scope baseline")
    sub.add_parser("status", help="show phases, evidence and next action")
    sub.add_parser("next", help="alias for status")
    note = sub.add_parser("note", help="save a phase note")
    note.add_argument("text", nargs="+")
    note.add_argument("--phase", choices=[p[0] for p in PHASES])
    mark = sub.add_parser("done", help="finish the current phase with evidence")
    mark.add_argument("phase", nargs="?", choices=[p[0] for p in PHASES])
    mark.add_argument("--note", required=True, help="evidence and conclusion")
    reset_parser = sub.add_parser("reset", help="reset checkpoints, retain audit evidence")
    reset_parser.add_argument("--yes", action="store_true", required=True, help="confirm reset")
    return parser

def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if any(v in {"-h", "--h", "--help", "help"} for v in values):
        _parser().print_help(); return 0
    parser = _parser()
    args = parser.parse_args(values)
    root = _root(args.root)
    if not _project_ok(root):
        print(f"Not a detected Lowkey audit project: {root}", file=sys.stderr); return 2
    action = args.action or "status"
    if action == "start": return start(root)
    if action in {"status", "next"}: print(render(root)); return 0
    if action == "done": return done(root, args.phase, args.note)
    if action == "note": return add_note(root, " ".join(args.text), args.phase)
    if action == "reset": return reset(root)
    parser.print_help(); return 2

if __name__ == "__main__":
    raise SystemExit(main())
