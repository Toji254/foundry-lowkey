# Evidence-first error diagnosis

Lowkey's optional error advisor explains failures from native evidence rather than plausible-sounding guesses.

## Diagnostic sequence

1. Preserve the original command, exit code, compiler/runtime diagnostic and bounded command history.
2. Inspect only project metadata relevant to the failure. For a missing Solidity import, read the importing source line and pragma, `foundry.toml`, `remappings.txt`, the matching remapping target, and bounded dependency-file candidates.
3. Separate facts from hypotheses. A missing import is not automatically a missing package: it can be a missing alias, incorrect target, absent file, or incompatible package layout.
4. Produce a repair sequence that addresses the evidenced cause. Do not recommend `forge update` as a substitute for installing a missing dependency or creating a missing remapping.
5. Give ordered verification commands. A repeated build is useful only after the project has changed, or when the diagnosis explicitly needs a fresh compiler result.
6. Never execute the proposed repair. Commands that install dependencies or modify project configuration must be labelled as local changes.

## Privacy and safety

Project inspection is local and read-only. Only bounded, redacted evidence is sent to the configured AI provider. Do not send complete source files, environment values, credentials, absolute project paths, or unbounded directory listings. Paths in the diagnosis are relative to the project root.

The AI model may explain or improve a native repair plan, but it cannot claim a filesystem fact that the evidence collector did not establish. Native compiler output remains authoritative. Suggested shell commands are display-only.

## Regression fixture: legacy OpenZeppelin SafeMath

For an unresolved import such as:

```solidity
import "openzeppelin-contracts-06/math/SafeMath.sol";
```

the advisor checks whether the exact import prefix is mapped and whether the target file exists. If the compatible file is already installed under another package path, it recommends mapping the alias to that file. If no matching file is present, it proposes installing a pinned Solidity-0.6-era OpenZeppelin package and adding the exact `openzeppelin-contracts-06/` remapping. It must not recommend repeating `lk forge update` as the repair.

The final verification checks the requested file, displays Forge remappings, and rebuilds the project.