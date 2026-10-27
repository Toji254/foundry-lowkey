# TypeSafe Jev integration and autonomy

Jev is integrated as Lowkey's **structured decision layer**. It evaluates state against typed questions (Choice, Score, and Noul). It is not a prose-generating chatbot; Lowkey's existing optional text-AI harness still handles natural-language explanations, test plans, and longer reasoning tasks.

Jev is a hosted API. Lowkey does not include Jev weights or run Jev locally. TypeSafe currently publishes a price of $0.042 per million input tokens; output tokens are free. Verify your account's plan and billing in the [TypeSafe model docs](https://docs.typesafe.ai/models). Lowkey's local budget guard limits usage but cannot create a free plan or guarantee zero charges.

## Set up and control Jev

```bash
# Save a TypeSafe key using hidden input (or set TYPESAFE_API_KEY in your environment).
lk ai jev setup

# Send one fixed, source-free connectivity probe. This makes a real, metered API call.
lk ai jev test

# Turn automatic Jev triage on, using the conservative local request guard.
lk ai jev on

# Show key readiness, model, switch and local budget. This does not call TypeSafe.
lk ai jev status

# Pause Jev automation without changing other LK AI settings or native commands.
lk ai jev off

# Remove the saved key; this does not unset TYPESAFE_API_KEY if you set it yourself.
lk ai jev remove-key
```

Optional controls:

```bash
# Change the local guard to at most six provider attempts per device-local day.
lk ai jev on --daily-limit 6

# Disable Lowkey's local request/context guard only if you've decided to do so.
lk ai jev on --tier standard

# Pause Jev and retain guarded usage settings.
lk ai jev off

# Pause Jev and explicitly turn the local guard off too.
lk ai jev off --tier standard
```

The API key is saved separately in Lowkey's private configuration directory (mode-restricted files), unless `TYPESAFE_API_KEY` is set. The key value is never printed by status. `lk ai jev setup` does not send a request. `lk ai jev test` sends a small fixed state and one typed question, with no project source or captured command output.

## What autonomous mode does

When `lk ai jev on` is enabled and a TypeSafe key is available, Lowkey sends a **bounded, redacted snapshot of selected command arguments and captured output** to Jev after eligible native workflows. Jev returns structured classifications, including:
- What the result most resembles: ordinary output, failure, test failure, security signal, target/runtime mismatch, incomplete evidence, state change, or unclear.
- A review priority and model confidence where the selected question type provides one.
- Whether an extra explanation seems useful and the safe response category to consider.

The current triggers include successful build/test/scan/audit workflows, selected verification and fuzz/invariant/mutation operations, diagnostics and project summaries, successful project onboarding, selected question/investigation views, plus failed non-AI CLI commands. Routine successful read operations do not trigger a Jev API call. Machine-readable JSON/help output is not appended to or sent for autonomous classification. `lk import` uses Jev after an install attempt or failed lookup; ordinary symbol lookup remains native and local.

Jev's result is a routing hint, **not a security verdict**. Its probability or confidence must not mark a finding confirmed, replace actual test evidence, or override human disposition. Lowkey never executes Jev's suggested response. The classifier does not run commands, change targets or RPC endpoints, edit files, install dependencies, deploy, sign or send transactions.

## Low-key usage guard

The guard is enabled by default when `lk ai jev setup` or `lk ai jev on` is used, unless you explicitly choose `--tier standard`.

| Local guard | Default |
|---|---:|
| Total TypeSafe and text-AI provider attempts per device-local day | 8 |
| Jev request body | 16,000 bytes maximum |
| Separate text-AI response limit | 650 output tokens |
| Separate text-AI request timeout | 30 seconds maximum |
| Exact-match response cache | 30 minutes; up to 40 entries |

The daily count is shared by TypeSafe Jev calls and the existing text-AI harness while the guard is active. A failed provider attempt counts because it may have consumed quota. TypeSafe requests are not retried automatically on 429/529 responses. After the local cap is spent, background Jev triage quietly stops; a direct AI request reports that the guard is exhausted. The counter resets at the next local-device calendar day. Check `lk ai jev status` to see current usage.

Exact repeat TypeSafe decision requests can be reused from a private, bounded local cache for 30 minutes. The cache key is a digest of the model and request; it does not persist the input state or API key. Cached results do not spend another provider request. Lowkey's text-AI harness has a separate exact-match cache for its own structured responses.

These are local safeguards, not TypeSafe's published quota, and **not evidence that an API account is free**. The actual input-token bill depends on the request tokenization and your account's billing terms. Status and other deterministic native commands remain available if the guard is exhausted. `--tier standard` removes Lowkey's local caps, not TypeSafe's account limits or price.

## Jev and existing Lowkey AI are separate

- `lk ai jev on/off` controls the direct TypeSafe Jev decision layer.
- `lk ai mode`, `lk ai errors`, and `lk ai recommendations` keep their existing independent behavior. They use Lowkey's configured text-AI provider, not TypeSafe Jev, and are not silently toggled by the Jev master switch.
- All existing Lowkey commands, evidence stores, native recommendations, local analyzers and test execution remain in place.
- Explicit tasks such as `lk ai security-review`, `lk ai test-plan`, `lk ai run`, and `lk ai explain-error --last` remain available when their own provider is configured.

This separation avoids silently using a second model or double-spending a small request budget. Use `--ai` or an existing `lk ai ...` task when you want the configured text model to produce a natural-language explanation.

## Privacy and evidence

Lowkey applies its existing argument redaction plus URL/bearer-token and 32-byte-hex redaction to the bounded command snapshot. Redaction is best effort, not a guarantee that arbitrary secrets can always be recognized. Keep sensitive projects off external providers unless you are comfortable sending the selected command output; command output can include source snippets or addresses. Review text-AI source context separately with `lk ai preview --show-context`.

The request-budget file and caches live outside the audited repository, under the user's private Lowkey state directory. Budget records keep the local day, request count, last request purpose and timestamp; they do not contain API key values or complete input states.
