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

## Explicit protocol review in the lab

~~~bash
lk lab --ai-review
~~~

This explicitly asks the configured model to review bounded excerpts of likely first-party contract source and return a structured overview, candidate invariants, open questions and deployment considerations. The normal native lab workflow then continues. Output is labelled unverified; it is not a vulnerability finding and does not control target selection, deployment, or testing. When AI is disabled, unconfigured or unreachable, Lowkey reports that the optional review was skipped and proceeds with native lab logic.

The opt-in review sends selected source excerpts to the configured provider. Do not use it if source must not leave the machine, and keep private keys, credentials, .env contents and production secrets out of contract source.

Approved native experience memory is available as bounded context for this opt-in review. Proposed lessons are excluded until the user explicitly promotes them with recorded validation; see [the experience memory guide](experience-memory.md). Project lessons remain project-scoped, and global lessons require explicit promotion.

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
