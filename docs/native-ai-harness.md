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

Custom compatible endpoint:

~~~bash
lk ai setup --provider openai-compatible --base-url https://provider.example/v1 --model MODEL
~~~

Provider availability and pricing are controlled by the provider. Never put credentials in a URL or commit them to source control.

## Explicit protocol review in the lab

~~~bash
lk lab --ai-review
~~~

This explicitly asks the configured model to review bounded excerpts of likely first-party contract source and return a structured overview, candidate invariants, open questions and deployment considerations. The normal native lab workflow then continues. Output is labelled unverified; it is not a vulnerability finding and does not control target selection, deployment, or testing. When AI is disabled, unconfigured or unreachable, Lowkey reports that the optional review was skipped and proceeds with native lab logic.

The opt-in review sends selected source excerpts to the configured provider. Do not use it if source must not leave the machine, and keep private keys, credentials, .env contents and production secrets out of contract source.

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
