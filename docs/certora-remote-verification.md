# Authenticated Certora remote verification

Lowkey's Certora adapter requests native CLI wait-for-results behavior by default. A successful CLI installation or a submitted cloud job is not treated as a completed proof. The adapter distinguishes `passed`, `failed`, `submitted`, `inconclusive`, `timeout`, and execution `error` outcomes, and retains a remote report URL/job identifier when the CLI exposes one.

## Fixture

`MiniToken.sol` and `MiniToken.spec` form a small stateful model. The CVL invariant is `balanceOf(account) <= totalSupply()` and is checked across constructors and state-changing methods. The config sets basic rule sanity checking so vacuous specifications are less likely to appear successful.

## Explicit remote submission

Remote proof submission is deliberately not part of normal `push` CI because it uses a remote service and may incur usage. A maintainer must manually run the **Optional authenticated Certora proof acceptance** workflow, select the branch to test, and explicitly set `submit_remote_proof=true`.

The workflow requires a repository Actions secret named `CERTORAKEY`. Store the personal access key only in GitHub Settings → Secrets and variables → Actions. Do not put it in `.conf`, campaign JSON, repository files, command-line arguments, or logs. The workflow checks only whether the environment variable is present and never prints or writes its value.

The remote acceptance runs `lk verification run` against `certora-campaign.json`, which selects the Certora adapter and requests wait-for-results. The workflow only passes when the installed Lowkey campaign reports a completed `passed` proof and preserves a remote job/report reference. A submission-only result, unrecognized output, missing credentials, failed rule or tool error does not count as a pass.

## Current validation status

The fixture, workflow, and adapter parser tests are committed on the isolated capability-completion branch. An authenticated remote proof has **not** yet been executed in this repository; it remains unvalidated until a maintainer adds `CERTORAKEY` and deliberately triggers the manual workflow. GitHub only exposes `workflow_dispatch` workflows in the repository's default branch. Because this task deliberately leaves `master` untouched, this workflow will become manually runnable in the GitHub UI only after its reviewed merge to the default branch. Until then, do not claim remote proof execution; the ordinary CI job checks CLI installation only and does not submit paid work.

Certora's documentation describes `.conf` files as JSON5 configurations, `wait_for_results: ALL` as the mode that waits for cloud completion, and `CERTORAKEY` as the recommended environment variable for authentication. See the [official configuration guide](https://docs.certora.com/projects/tutorials/en/latest/lesson2_started/config_files.html), [CLI options](https://docs.certora.com/en/latest/docs/prover/cli/options.html), and [installation guide](https://docs.certora.com/en/latest/docs/user-guide/install.html).
