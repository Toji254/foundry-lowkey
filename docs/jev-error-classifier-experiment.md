# Jev error-classifier experiment

## Scope

This is an experiment-only benchmark, not a production integration. It compares a small deterministic rules baseline with TypeSafe Jev on a curated set of 25 Foundry/Solidity diagnostic examples. Each fixture has two independently labeled dimensions:

- **Failure stage:** where progress stopped, such as dependency resolution, compilation, test execution, RPC transport, or deployment.
- **Root cause:** the most specific supported explanation, such as a missing import or a Solidity compiler diagnostic.

This separation is deliberate. A missing import can cause compilation to stop, but calling every compiler-stage failure a generic compilation error loses the fixable cause. Jev's probabilities are recorded as model outputs, not calibrated correctness estimates.

The current corpus is hand-curated and small. It is useful for exercising the request/response path and spotting obvious taxonomy mistakes; it is not a representative dataset and must not be described as demonstrating production accuracy.

## Run it through Lowkey

After switching to this branch and reinstalling Lowkey:

    lk jev benchmark

This runs only local rules. It makes no network request and requires no key. It writes a machine-readable report to .audit/jev-error-classifier-benchmark.json. Use `lk jev --h` or `lk jev benchmark --h` for the command reference.

The standalone script remains as a convenience wrapper, but the supported native entry point is `lk jev benchmark`:
    
    python3 scripts/jev-error-classifier-benchmark.py

Run a small live smoke test after confirming that your TypeSafe account has API-key access:

    export TYPESAFE_API_KEY='your-key'
    lk jev benchmark --with-jev --limit 3

The key is read from the environment and sent only in the Authorization header. Never commit it, paste it into issue text, or add it to the report. Jev receives only the fixed benchmark fixture, not your source tree, project files, environment, audit ledger, or live command history. The tool makes one request per selected fixture, asks for stage and root-cause choices in the same request, and does not retry provider errors automatically.

To run the full corpus:

    lk jev benchmark --with-jev

The direct API endpoint and model are TypeSafe's documented POST https://api.typesafe.ai/v1/systemone endpoint and jev-latest model. Access depends on the TypeSafe account. The independent Jev Playground does not issue reusable API keys. See https://jevplayground.com/jev-api for current access, payload, typed response, pricing, and data-handling details.

Use a custom report path or adjust the request timeout:

    lk jev benchmark --with-jev --limit 5 --timeout 20 --output /tmp/jev-smoke.json

## Validate the local adapter and taxonomy

    python3 -m unittest tests.test_jev_error_benchmark -v

The unit tests use a fake HTTP response; they do not contact TypeSafe or incur provider usage.

## How to interpret the report

The JSON report records expected labels, rule predictions, Jev predictions, probability distributions where returned, latency, token usage, request failures, and accuracy by dimension. A provider request error counts as an unanswered case for the Jev accuracy metric. It is not silently removed from the denominator.

Before making a decision to integrate Jev into the Lowkey runtime, build a larger adjudicated corpus from real but sanitized failures, include confusing and unknown examples, and compare three lanes: existing rules, Jev alone, and rules plus Jev. Track overall and per-category accuracy, false confident decisions, answer rate, latency, and cost. Any threshold must be selected using held-out examples, not the same examples used to tune the prompts or rules.

## Safety boundary

Jev is advisory only. Its result never changes a Lowkey command route, runs a suggested command, edits project state, chooses a transaction target, signs or broadcasts a transaction, or marks a finding verified. The benchmark does not replace Lowkey's existing native diagnostics or error advisor. Do not use a prediction or probability as proof that a diagnosis is correct.
