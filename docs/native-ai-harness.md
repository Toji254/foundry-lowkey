# Native-first AI harness

Lowkey's AI extension is optional and task-specific. It is not a chatbot and is not required for native workflows. Lowkey remains responsible for command dispatch, project analysis, tool execution, test verification, evidence and security conclusions.

## Configure once

DeepSeek API example. The key is requested with hidden terminal input and stored separately from normal configuration with owner-only file permissions.

~~~bash
lk ai setup --provider deepseek --model deepseek-flash
lk ai status
lk ai test
~~~

The test sends a fixed connectivity probe without project source. Provider charges may apply; free access in a consumer app does not necessarily include API access.

Keep the key in an environment variable instead:

~~~bash
export DEEPSEEK_API_KEY='your-key'
lk ai setup --provider deepseek --model deepseek-flash --api-key-env DEEPSEEK_API_KEY
~~~

Local OpenAI-compatible Ollama example:

~~~bash
lk ai setup --provider ollama --model qwen2.5-coder
lk ai status
~~~

OpenAI API example (the key is requested with hidden terminal input and saved separately):

~~~bash
lk ai setup --provider openai --model MODEL
lk ai status
~~~

Custom compatible endpoint:

~~~bash
lk ai setup --provider openai-compatible --base-url https://provider.example/v1 --model MODEL
~~~

Provider availability and pricing are controlled by the provider. Never put credentials in a URL or commit them to source control.

## Preview the exact context before sending it

Use the local preview to see which production-source excerpts and approved lessons would be included. This works while AI is disabled or unconfigured and never contacts a model.

~~~bash
# Summarize selected file paths, context size and redaction markers
lk ai preview

# Focus the selection on a named contract
lk ai preview --contract ConfidencePool

# Print the complete redacted context as JSON for a local review
lk ai preview --contract ConfidencePool --show-context
~~~

The preview uses the same context-building function as the explicit protocol review, including its source filters, secret redaction and approved-memory selection. The default view shows paths and sizes, not source contents. The show-context option prints the full redacted context to your terminal; handle that output as private project data. No source is sent anywhere by the preview command.

This is a useful preflight, not a guarantee that the best-effort redactor recognizes every possible secret. Review the actual payload before opting into remote analysis.

## Test the installed CLI without an AI provider

After pulling the branch and running `bash install.sh`, execute the same local-only CLI smoke check used by integration CI:

~~~bash
bash scripts/test-native-ai-harness.sh
~~~

The script checks the installed `lk ai` and `lk memory` command routes, verifies that preview makes no provider request, and confirms the payload excludes test/dependency source and redacts its deliberate test secret. It uses a temporary fixture and removes it on exit. It does not configure or enable an AI provider. The Python regression tests are separate:

~~~bash
python3 -m unittest tests.test_ai_harness tests.test_ai_harness_live_integration tests.test_experience_memory -v
~~~

The live-request integration tests start a local HTTP server and exercise Lowkey's actual HTTP request/response path, structured protocol-review validation, redaction, and metadata-only event logging. They use a fixture response, do not contact an external model, and do not incur provider charges. They verify transport and application handling—not the quality of a real model review or compatibility with an external provider's current service.

To verify an actual provider end to end, configure a model name that is enabled for API use in your provider account, then run the fixed connectivity check before sending contract context:

~~~bash
lk ai setup --provider openai --model 'YOUR_API_MODEL_NAME'
lk ai status
lk ai test
~~~

The setup command prompts for the API key with hidden terminal input. The fixed connectivity test sends no project source. After it passes, enter the audited project and explicitly run a protocol review:

~~~bash
cd /path/to/your/foundry-project
lk ai preview --contract ConfidencePool
lk lab --ai-review
~~~

The preview is local-only. The explicit review sends the selected, redacted source excerpts and approved memory to the configured provider, and provider charges may apply. Inspect the result as unverified hypotheses; it is not proof of safety or a confirmed vulnerability report.

## Structured security review and evidence lifecycle

The protocol overview (`lk lab --ai-review`) and the focused security-review task are separate jobs. The overview helps map a project; `lk ai security-review` asks for concrete candidate vulnerabilities and normalizes each item into a review record. Model confidence is descriptive only.

~~~bash
lk ai security-review --contract ConfidencePool
lk ai ledger
lk ai ledger --json

# Plan one selected test without executing it
lk ai verify F-0123456789ab --test test/unit/ConfidencePool.t.sol --match-test testWithdrawSucceedsInAttackRequested

# After reviewing the test code and plan, explicitly execute that test
lk ai verify F-0123456789ab --test test/unit/ConfidencePool.t.sol --match-test testWithdrawSucceedsInAttackRequested --run

# Make a separate human decision after inspecting the evidence
lk ai disposition F-0123456789ab --status confirmed --reviewer auditor --reason 'Reviewed the reproduction assertion and impact.' --evidence-id NATIVE_TEST_EVENT_ID

lk ai runtime
~~~

The security-review pipeline stores a report under `.audit/ai-review/reviews/` and append-only events in `.audit/ai-review/ledger.jsonl`. Every AI-produced item starts as `candidate`, with `verified=false`. The source-quote checker checks whether the quoted code exists in the selected source excerpt. A matching quote proves only that the citation exists, not that the security claim is true.

`lk ai verify` plans by default. Supplying `--run` explicitly authorizes one native `forge test` command with one exact test name. The tool rejects shell commands, deployment scripts, non-test paths, and fork-test paths; it uses a bounded timeout and stores summary lines plus hashes rather than the full test output. Tests are repository code: inspect the selected test before executing it. A passing test is execution evidence and never automatically upgrades a finding.

`lk ai disposition` is a separate human decision. `confirmed` requires a recorded passing native test plus a non-empty human reviewer/reason; `rejected` also requires a linked native run. These checks provide traceability, not a guarantee that the test proves exploit impact. The reviewer must inspect the assertion, test scope, and source. The model has no API to set a human disposition, deploy, sign, broadcast, or run arbitrary shell commands.

Provider adapters are selected through a replaceable registry. Agents depend on a structured task interface rather than a specific vendor. The built-in providers currently share an OpenAI-compatible transport; replacing a transport requires explicit application-code registration and regression tests. The agent registry exposes bounded capabilities, one-level allowlisted delegation, and an action log at `.audit/ai-review/runtime-events.jsonl`. Logs store action metadata and digests rather than prompts, model responses, credentials, or raw test output.

Historical project feedback is included only as labeled historical context when available. It is not a source citation or current proof and must be rechecked against the current source revision and current native tests. Only separately approved memory lessons are treated as reusable validated procedures, and those lessons remain reference context—not proof that a current finding is true.
## Optional AI test planning

`lk ai test-plan --contract ConfidencePool` proposes targeted unit, fuzz, invariant, regression, integration, and (when justified) fork-test cases from the current source. It records source quote matches, explicit assertions, setup/steps, priority, limitations, and whether existing coverage may overlap.

~~~bash
lk ai test-plan --contract ConfidencePool
lk ai test-plan --contract ConfidencePool --json
~~~

The result is a saved proposal at `.audit/ai-review/test-plans/TP-<id>.json` and a `test_plan_created` ledger event. This command does not write Solidity tests, execute tests, or mark any proposed test as passing. Review the source quote, assertion, test setup, and existing coverage before implementing a case. Use the native `lk ai verify` flow only for a test that already exists and has been manually inspected.
## Error diagnosis and key failover

Lowkey can retain the most recent routed CLI failure in a private, redacted state file and diagnose it on demand. The model provides proposed causes and copy-pasteable checks/fixes; it does not run any suggested command.

~~~bash
# Explain the most recently captured lk error
lk ai explain-error --last

# Or explain an error copied from any command, including commands outside the main router
lk ai explain-error --text 'failed to retrieve chain ID from fork endpoint: connection timed out' --command 'forge test --match-path test/fork/*'

# Keep automatic explanations off unless you explicitly enable them
lk ai errors status
lk ai errors auto
lk ai errors manual
~~~

Automatic explanations are opt-in and can make provider requests (and incur charges) after routed command failures. The last-error record is stored at the user's XDG state directory with private file permissions; raw argv is not stored, diagnostic strings are redacted/truncated, and only the command name, status, project label/path and sanitized error are retained. For commands routed directly to external tools or any error not captured automatically, `--text` provides the universal fallback.

Each provider can hold up to three private API-key slots. Secrets are saved separately from ordinary configuration with restrictive file permissions and are never printed by key-management commands or written to request logs.

~~~bash
# Add/replace a key; input is hidden
lk ai keys add --provider openai-compatible --slot 1
lk ai keys add --provider openai-compatible --slot 2
lk ai keys add --provider openai-compatible --slot 3

# See slot numbers only; never prints credential values
lk ai keys list --provider openai-compatible

# Remove a single slot or all saved keys for that provider
lk ai keys remove --provider openai-compatible --slot 2
lk ai keys clear --provider openai-compatible
~~~

On quota exhaustion, rate limiting, or key-auth rejection, the harness tries the other configured key slots and records only the slot label and failover count. It remembers the last successful slot as the next request's starting preference. Network failures and non-key-related HTTP errors do not trigger key rotation. Provider/model are not silently changed, and retries remain bounded to the configured three slots. Environment-variable keys can fill an unused slot when fewer than three saved keys exist.

## Other opt-in AI tasks

Use AI where it reduces investigation time without owning the workflow: explain a compiler/Forge/Slither/RPC error; suggest regression test cases from a cited invariant; summarize the current evidence for hand-off; and explain a static-analysis candidate in plain language. Each task should stay explicit and bounded. Generated commands/tests must be previewed, reviewed and run by native tools; AI output is never deployment authority or security proof.
## Manual and automatic assistance modes

The default is **manual**: Lowkey does not make a model request unless you explicitly run \`lk lab --ai-review\`.

~~~bash
lk ai mode manual
lk ai status
~~~

To opt in to complexity-triggered assistance:

~~~bash
lk ai mode auto
lk ai status
~~~

In auto mode, Lowkey first runs a local, deterministic complexity heuristic over bounded first-party source excerpts. It triggers a protocol review only when the configured provider is ready and the project has signals such as several interrelated contracts combined with proxy, factory, implementation, initializer, or registry patterns (or a large cross-contract source set). A simple project remains native-only. The selected contract source and approved experience snippets are sent to the configured provider only when the heuristic triggers. This may incur charges.

Return to manual mode at any time with \`lk ai mode manual\`. Neither mode gives the model tool execution, deployment, target-selection, or finding-confirmation authority.

## AI next-command recommendations

Lowkey's deterministic footer remains the **LOWKEY RECOMMENDED NEXT COMMANDS** section. Extra recommendations from the model are a separate, watermarked section and are disabled by default:

~~~bash
lk ai recommendations status
lk ai recommendations auto
lk ai recommendations manual
~~~

Auto mode may make a provider request after a successful command only when Lowkey already has a native next-command menu. It sends bounded, redacted first-party source excerpts plus the existing native suggestions. AI suggestions must cite a selected file and symbol and use a read-only command allowlist; malformed/unsafe suggestions are discarded. No suggested command is executed. Provider pricing and best-effort redaction still apply.

## Explicit protocol review in the lab

~~~bash
lk lab --ai-review
~~~

This explicitly asks the configured model to review bounded excerpts of likely first-party contract source and return a structured overview, candidate invariants, open questions and deployment considerations. The normal native lab workflow then continues. Output is labelled unverified; it is not a vulnerability finding and does not control target selection, deployment, or testing. When AI is disabled, unconfigured or unreachable, Lowkey reports that the optional review was skipped and proceeds with native lab logic.

Lowkey locally redacts obvious API-key/password/private-key/seed-phrase assignments and PEM private-key blocks before assembling source excerpts. This is a best-effort filter, not a guarantee that arbitrary secrets will be recognized. The opt-in review sends selected source excerpts to the configured provider. Do not use it if source must not leave the machine, and keep private keys, credentials, .env contents and production secrets out of contract source.

Approved native experience memory is selected by local relevance matching against the current bounded protocol source, then added as bounded context for this opt-in review. Proposed lessons are excluded until the user explicitly promotes them with recorded validation; see [the experience memory guide](experience-memory.md). Project lessons remain project-scoped, and global lessons require explicit promotion.

## Boundaries

- AI is disabled until configured and can be switched off with lk ai disable.
- No general chat endpoint, model-controlled tool loop, autonomous file editing, signing or deployment.
- Native discovery, parsers, analyzers, build/test workflows, verification engines and evidence reporting remain independent.
- Only named structured task purposes are accepted.
- Context and response size, token output and request time are bounded.
- Model output is parsed and checked before it is displayed.
- Request logs store provider/model, purpose, timing, outcome and a context digest; they do not store source, prompts, responses or API keys.
- Remote endpoints require HTTPS. Secrets are stored apart from normal configuration or read from an explicitly named environment variable.
- Suggested invariants and deployment considerations are hypotheses. Native tools and executable tests remain the verification authority.

The internal request_structured API is for Lowkey-owned callers. It is deliberately not exposed as arbitrary prompt/chat.


## Readable output by default

Model-derived prose is visibly labelled with `@ AI OUTPUT` (or `@ AI CANDIDATE` inside the review ledger) so it is not mistaken for a native Lowkey result. JSON remains valid JSON and carries `ai_generated: true` and `origin: "configured-model"` metadata where the report is model-derived. Lowkey's native recommendations are labelled separately from model suggestions.

Lowkey's AI commands are intended to be understandable without reading internal JSON. Commands such as `lk ai status`, `lk ai runtime`, `lk ai keys list`, `lk ai errors status`, `lk ai security-review`, `lk ai test-plan`, and `lk ai ledger` print short explanations and next steps by default. Use `--json` where supported when another tool needs the structured data.

- **Ready to try** means the configuration and a credential are present; it does not prove the provider is reachable. Run `lk ai test` to check connectivity.
- A security-review item is a possible issue, not a confirmed vulnerability. A matching source quote means only that the quoted text was found.
- A test plan is a suggestion. It does not write Solidity test code or run tests. Existing test coverage must be checked separately.
- A passing test is evidence about that test run; it does not automatically prove an AI claim is correct.
- Lowkey does not execute suggested commands. Local Foundry test execution requires an explicit `--run`.


## Complete built-in command guide

Run `lk ai --help` (or `lk ai help`) for the full on-terminal command guide. It documents every public AI subcommand and its flags, explains when and why to use it, gives copy-paste examples, and distinguishes local-only commands from commands that contact the provider. A command-specific form such as `lk ai setup --help` shows that command's own options plus a short usage example.

Human-readable output is the default. Use `--json` on commands that support it when you need machine-readable data. The root guide is built alongside the argument parser; update its command syntax and tests whenever a CLI option is added or changed.
