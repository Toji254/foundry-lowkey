# AI-assisted attack hypothesis research

Run `lk attack research --root . --max-candidates 5 --json` after configuring the optional Lowkey AI provider. The command asks the model to propose source-grounded attack hypotheses using bounded source excerpts and the available compiler/runtime graph summary.

## What it produces

- A candidate family, title, falsifiable security property and explanation.
- Exact source references with file path, line range, full-file SHA-256 and quoted source text.
- Preconditions, proposed attack steps, a matched control, a bounded test plan and mutation ideas.
- Provider/model identifiers, project Git revision when available, context hash, and a saved report at `.audit/lowkey/attack-research/latest.json`.

Each accepted candidate is marked `CANDIDATE_ONLY`. The validator rejects source paths not supplied to the model, stale file hashes, invalid line ranges and quotes that do not occur in the cited current-source lines. Rejected candidates are retained with reason codes.

## Safety contract

This command never executes model-generated text, shell commands, tests or deployments. It does not sign or broadcast transactions. It does not modify Solidity files. Model confidence is informational only and is never an acceptance score. Source comments, NatSpec, repository text and saved logs are untrusted data, not instructions.

An accepted citation proves only that the quoted text appears at the cited source revision. It does not prove reachability, exploitability or impact. Before promoting a candidate, build a target-specific adapter, execute a matched control, require mutation killing, capture canonical traces, and independently reprove the result.

## Limits

The request is bounded to four first-party Solidity/Vyper source files, a bounded graph summary and at most five candidates. The source context may therefore omit relevant modules in large projects; a missing hypothesis is not evidence that the code is safe. The current output is research planning, not autonomous attack execution or full novel exploit discovery.
