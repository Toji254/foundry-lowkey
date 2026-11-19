# Lowkey auditor workflow

A five-checkpoint navigation layer over Lowkey's existing evidence journal and auditor-question engine. It is not a second vulnerability engine and does not require an AI provider.

## Quick start

From the project/package root:

~~~bash
lk build
lk workflow start
lk workflow
lk q
~~~

Workflow state lives in .audit/workflow/state.json. It does not overwrite .audit/context.json, events, question history, findings, Forge artifacts or test files.

## Checkpoints

1. **PREPARE** — pin source revision and worktree, understand scope/exclusions, read project docs, record compiler/dependency assumptions and establish the build/test baseline.
2. **MAP** — identify assets/liabilities, actors/roles, entry points, dependencies, external calls/callbacks, state transitions and critical invariants.
3. **HUNT** — turn the map into focused hypotheses. Prioritize authorization, accounting/rounding, callbacks/reentrancy, signatures/nonces, oracle assumptions, initialization/upgrades, ordering/MEV, lifecycle and DoS.
4. **PROVE** — build a minimal reproducible PoC, compare it with a meaningful control from equivalent pre-state, inspect traces/state changes and record the violated property and impact.
5. **VERIFY** — justify severity, re-check alternate paths, inspect fixes in context, run regressions and preserve exact revision/report limitations.

The detailed, project-aware question frontier remains lk q.

## Commands

~~~bash
lk workflow
lk workflow start
lk workflow next
lk workflow note "..."
lk workflow done --note "evidence and conclusion"
lk workflow done MAP --note "evidence and conclusion"
lk workflow reset --yes
lk workflow --help
~~~

Phases complete in order and require a human evidence note. For Foundry projects, PREPARE also requires a successful real build for the current git commit and source worktree. A plan-only build does not count. A build performed before workflow start may count if its source snapshot still matches. A changed commit or source path makes it stale.

The display reports successful Forge test, coverage and Slither events where available, but these never auto-complete phases. Some routes may not emit structured events; “not detected” does not mean “not run”. Lowkey does not decide whether a property is meaningful, a PoC proves impact, or a fix closes every path.

## Audit discipline

- Pin what was actually reviewed. Reconcile dirty worktrees and known exclusions.
- Record source locations, dependency versions, assumptions and known issues.
- Compare implementation with intended behavior; docs and NatSpec are not enforcement.
- Review reachable entry points and external-call contexts, not isolated functions.
- Use automation to prioritize review, not replace it. Static analyzers and fuzzers produce leads to validate.
- Require a minimal PoC and control for serious claims. Separate local simulation from authenticated deployment evidence.
- Verify fixes and regressions against the exact post-fix commit.
- Preserve uncertainty: UNKNOWN and UNVERIFIED beat unsupported green checks.

A successful build prints the workflow suggestion once per project. Compilation is not an audit.
