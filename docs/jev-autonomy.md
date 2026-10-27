# Jev autonomy in Lowkey

Jev is Lowkey's coordinated AI-assistance mode. It activates existing features; it does not replace Forge, native analyzers, Lowkey's project/evidence stores, or command handlers.

## Commands

```bash
lk ai jev on
lk ai jev status
lk ai jev off

# Optional: set a smaller/larger local request cap, up to 24 requests per device-local day.
lk ai jev on --daily-limit 6

# Only choose standard when your configured provider plan supports the larger requests.
lk ai jev on --tier standard

# Pause automation but keep explicit AI requests guarded by the free-tier budget.
lk ai jev off

# Turn off the local free-tier request/context/output caps while leaving Jev automation off.
lk ai jev off --tier standard
```

Run `lk ai status` for provider readiness and `lk ai test` for a small connectivity probe.

## What turns on

`lk ai jev on` enables the existing AI extension and coordinates the established automatic settings:

- Automatic protocol/lab review when Lowkey's existing complexity check says it is useful.
- Post-command guidance after the eligible native workflows already supported by Lowkey.
- Automatic explanations after eligible command failures.
- Optional learner-first recommendations after command attempts.

Each feature still uses its existing context gathering, validation, and output rules. Static/native recommendations are preserved. Jev suggestions remain hypotheses, not verified findings, and are never executed. Jev does not edit files, install dependencies, choose a new target or RPC, deploy, sign, or send transactions.

`lk ai jev off` turns off those automatic behaviors. It does not uninstall AI, remove commands, erase model profiles, delete API keys, or remove existing project/evidence data. Explicit requests such as `lk ai security-review` remain available.

Individual settings (`lk ai mode`, `lk ai errors`, and `lk ai recommendations`) remain supported. Jev's master switch turns those existing settings on or off together.

## Free-tier safeguards

When enabled, the local guard defaults to:

| Guard | Default |
|---|---:|
| Provider requests per device-local day | 8 |
| Context sent per request | 16,000 bytes maximum |
| Generated output requested per call | 650 tokens maximum |
| Request timeout | 30 seconds maximum |

Lowkey trims large context before sending it and counts each provider attempt before the request, including attempts that fail and may have consumed quota. After the daily cap, background automation stops quietly; explicit AI requests return an actionable message. The counter resets at the next local-device calendar day. Use `lk ai jev status` to check usage.

These are **local safety limits**, not the provider's published free quota. Providers differ by account, model, region and time; a provider may impose stricter rate limits or have different billing terms. The local counter cannot guarantee zero charges. Keep the guard on for a free provider account and choose a daily limit deliberately.

The free-tier guard also applies to explicit AI requests while it is on, so automatic and manual AI use share one budget. Turning Jev automation off preserves that guard. Use `lk ai jev off --tier standard` only when you intentionally want to remove local context/output/request caps; provider-side limits still apply.

## Evidence and safety boundaries

Lowkey remains the source of truth for whether a command ran, what its output was, which tests passed, and whether a finding has reproducible evidence. Jev can compare hypotheses, classify a failure, explain missing evidence, and recommend the next safe read-only step. It cannot elevate a probability score into a confirmed diagnosis without supporting evidence.

AI context continues through the existing redaction and bounded-context pipeline. Review sensitive projects before sharing source with an external provider using `lk ai preview --show-context`. The budget file lives in Lowkey's private user state directory and contains only the local day, request count, last request purpose and timestamp—not API key values or source excerpts.
