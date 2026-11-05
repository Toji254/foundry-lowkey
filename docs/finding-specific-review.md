# Finding-specific investigation and remote evidence

Lowkey's finding explainer is anchored to an existing native signal. It is a skeptical second reviewer, not a finding-disposition authority.

## Local-first workflow

1. Run `lk findings` and select an existing signal ID.
2. Preview the exact local source, helper/import context and related tests before any provider call:

   ```bash
   lk ai preview --finding SIGNAL_ID --show-context
   ```

3. Ask the configured text provider to challenge that one detector candidate:

   ```bash
   lk ai explain-finding SIGNAL_ID
   ```

A preview without external URLs is fully local and network-free. When you explicitly supply `--evidence-url`, preview fetches only those public links, keeps bounded/redacted excerpts local, and displays the exact remote text that would be included; it still makes no provider request. Explanation is opt-in and may incur provider charges. It does not run tests, write Solidity, deploy, choose an RPC/actor/target, sign or broadcast transactions. The report remains unverified and cannot change native finding disposition.

## Optional public evidence links

External evidence is never fetched automatically. Supply one or more explicit public HTTPS links only when they add useful context:

```bash
lk ai preview --finding SIGNAL_ID \
  --evidence-url 'https://github.com/OWNER/REPO/blob/COMMIT_SHA/src/Contract.sol'

lk ai explain-finding SIGNAL_ID \
  --evidence-url 'https://github.com/OWNER/REPO/blob/COMMIT_SHA/src/Contract.sol' \
  --evidence-url 'https://PUBLIC-AUDIT-OR-DOCS-URL'
```

Use a full 40- or 64-character commit SHA in GitHub `/commit/`, `/blob/` or `/tree/` links. Moving branch/tag references and unpinned repository-root links are rejected. GitHub file links are checked against the exact commit and read from that immutable raw-file path. Generic documentation links must be public HTTPS text. Redirects are not followed; provide the final destination URL.

At most five URLs are accepted. Lowkey rejects local/private network destinations, embedded credentials, credential-like query parameters, sensitive GitHub paths (such as `.env`), binary/non-UTF-8 content and secret-like responses. Requests use bounded response sizes, an eight-second connection timeout, DNS checks and an IP-pinned TLS connection. Only short, redacted text excerpts are eligible for the provider context.

The output labels these pages as **remote untrusted supplementary evidence**. For GitHub links it records the resolved SHA and whether it matches the local checkout's commit. A different SHA is clearly identified; it does not replace the local snapshot. Remote quotes are labelled `remote-unverified`, never as matched local source quotes. Remote reports, snippets and documentation are not proof that the checked-out code is vulnerable.

Preview without `--evidence-url` is fully local and network-free. When one or more explicit URLs are supplied, preview fetches those bounded public references locally and displays the exact excerpts eligible for a later provider request; it still does not call the text provider. Use `--show-context` or `--json` to inspect the final bounded context. An unsafe or unavailable URL is reported as unavailable; local finding context remains usable and authoritative.

## Test planning and execution boundary

`lk ai test-plan --finding SIGNAL_ID` only proposes tests. It never writes or runs them.

`lk verification investigate SIGNAL_ID` is a read-only source investigation plan. To execute a test, inspect the complete test and its assertions, then provide one exact Foundry test file and function:

```bash
lk verification run-test SIGNAL_ID test/Vault.t.sol test_withdrawRejectsUnauthorized
```

This executes only that file/function via Forge. Forge may compile as needed and update `out/` or `cache/`. Inspect the selected test and its imports for fork/RPC use, broadcast cheatcodes or other external effects before running: test code can do more than a local assertion. Lowkey itself does not choose a live target, sign or broadcast a transaction. The result is appended as evidence; passing or failing does not automatically confirm, reject or close the native finding. The auditor must inspect what the assertion actually measures.
