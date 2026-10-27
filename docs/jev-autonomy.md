# Jev integration and autonomy

Jev is Lowkey's **structured decision layer**. It answers typed Choice, Score and Noul questions; it does not write natural-language explanations or code. Lowkey's existing optional text-AI provider remains separate and can be used explicitly for longer explanations, test plans and reviews.

## Pick a Jev endpoint

A fresh setup defaults to **JevModel**, an independent hosted service that currently advertises 100,000 starter input tokens after email verification and five successful free runs per UTC day, subject to service capacity. The run allowance resets daily; the 100,000-token grant is a separate shared balance. Provider terms or availability can change. JevModel uses its own API key and endpoint, so a TypeSafe key will not work there.

The official **TypeSafe API** is also supported. TypeSafe's published price is $0.042 per million input tokens, with output tokens free; check its current account terms before using it. Lowkey will preserve an existing TypeSafe setup/key rather than silently redirecting it to JevModel.

**Jevos-v5** is supported as an optional local provider. It uses the Jev-compatible API at `http://127.0.0.1:8017/v1/systemone`, requires no API key, and runs on your own CPU. Keep its `jev serve` process running while Lowkey uses it. `lk ai jev status` does not probe the server; `lk ai jev test` does. Local requests do not consume the hosted-provider daily request allowance. The existing JevModel hosted default is intentionally unchanged.

## Set up and control Jev

```bash
# Fresh setup: JevModel starter-token endpoint (hidden key input).
lk ai jev setup

# Choose a provider explicitly:
lk ai jev setup --provider jevmodel
lk ai jev setup --provider typesafe
lk ai jev setup --provider jevos     # select local Jevos-v5; no key prompt

# Switch back to the existing hosted default (or the official hosted endpoint):
lk ai jev setup --provider jevmodel
# or: lk ai jev setup --provider typesafe

# Test connection with one fixed question and no project source.
lk ai jev test

# Enable / inspect / pause automatic Jev triage.
lk ai jev on
lk ai jev status
lk ai jev off

# Remove only the saved key for the active Jev provider.
lk ai jev remove-key
```

Optional local-budget controls:

```bash
# Cap provider attempts at six per UTC day.
lk ai jev on --daily-limit 6

# Use the conservative local request guard (default).
lk ai jev on --tier guarded

# Remove Lowkey's local guard only when you intentionally choose to.
lk ai jev on --tier standard
lk ai jev off --tier standard
```

You can also set `JEVMODEL_API_KEY` or `TYPESAFE_API_KEY` in your environment. Choose the variable that belongs to the selected hosted provider. Jevos does not use an API key. Status never prints key values. `lk ai jev setup` saves the selected endpoint/model/key source without sending a request. `lk ai jev test` makes one real, source-free request: hosted Jev may consume tokens or incur usage; Jevos runs locally.

## What autonomous mode does

When `lk ai jev on` is enabled and the selected provider is available, Lowkey sends a **bounded, redacted snapshot** of selected arguments and captured output to Jev after eligible native workflows. Hosted providers require their own key; local Jevos-v5 requires the local server to be running. Jev returns structured classifications, including:

- What the result most resembles: ordinary output, command/tool failure, test failure, security signal, target/runtime mismatch, incomplete evidence, state change, or unclear.
- A review priority and model confidence where the answer type provides one.
- Whether an extra explanation seems useful and which safe response category to consider.

Eligible triggers include selected build/test/scan/audit workflows, verification and fuzz/invariant/mutation operations, diagnostics and project summaries, successful project onboarding, selected investigation views, and failed non-AI CLI commands. Routine successful reads do not trigger Jev calls. Machine-readable JSON/help output stays clean. `lk import` uses Jev after an install attempt or failed lookup; ordinary symbol lookups remain native and local.

Jev's output is a routing hint, **not a security verdict**. A probability or confidence cannot mark a finding confirmed, replace actual test evidence, or override human disposition. Lowkey never executes a Jev suggestion, changes targets/RPCs, edits files, installs dependencies, deploys, signs, or sends transactions.

## Local free-tier guard

When Jev setup or autonomy is enabled, Lowkey defaults to a conservative local guard. The cap is deliberately separate from the provider's actual free balance or billing rules.

| Local guard | Default |
|---|---:|
| Combined hosted Jev/text-AI provider attempts | 5 per UTC day |
| TypeSafe Jev request size | 16,000 bytes maximum |
| JevModel request size | 7,500 bytes maximum |
| Jevos-v5 local request size | 32,000 bytes maximum (also subject to configured context cap) |
| Optional text-AI response cap | 650 output tokens |
| Exact-match Jev response cache | 30 minutes; up to 40 entries |

The daily count applies to hosted Jev and the existing text-AI harness while the guard is on; **local Jevos-v5 inference does not consume this counter**. It resets at 00:00 UTC to align with JevModel's advertised free-run window. Lowkey counts every provider attempt—including errors—so it may stop earlier than JevModel's five successful free runs. JevModel says failed requests are not charged and successful requests after the daily free allowance draw from the shared token balance; check the live account balance in its console. Jev requests are not automatically retried after rate limits or overload errors. After the local cap is spent, background triage stops quietly. Inspect `lk ai jev status` to check usage.

Exact-repeat decision requests can be reused from a private, bounded local cache for 30 minutes. The cache key is a digest of the provider/model and request; it does not store the original input state or API key. Cache hits do not spend another provider attempt.

These are **local safeguards**, not an entitlement from JevModel or TypeSafe and not a zero-cost guarantee. Jevos uses local compute instead of hosted inference, although your machine still spends CPU time and memory. JevModel advertises five successful free runs per UTC day plus 100,000 starter input tokens after email verification; verify your account balance and current terms. TypeSafe uses its own published input-token pricing. `--tier standard` removes Lowkey's local guard, not provider limits or prices. Deterministic Lowkey commands remain usable even when the guard is exhausted.

## Jev and existing Lowkey AI stay separate

- `lk ai jev on/off` controls the typed Jev decision layer.
- `lk ai mode`, `lk ai errors`, and `lk ai recommendations` keep their existing independent behavior. Those settings use the configured text-AI provider and are not silently enabled by Jev.
- Use `lk ai jev on --with-text-ai` only when you also want Lowkey's existing text model to provide prose after Jev says it may help. That requires the text-AI provider to be configured and enabled; it can use a separate provider allowance.
- All existing Lowkey commands, evidence stores, native recommendations, local analyzers and test execution remain in place.

## Privacy and evidence

Lowkey applies existing argument redaction plus URL/bearer-token and 32-byte-hex redaction to the bounded command snapshot. Redaction is best-effort, not a guarantee that arbitrary secrets can always be recognized. Keep sensitive project output off external providers unless you are comfortable sharing the selected data. Review text-AI context separately with `lk ai preview --show-context`.

The request budget and caches live outside the audited repository under Lowkey's private state directory. They store usage metadata and cache digests/results—not API key values or complete request states.
