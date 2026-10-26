# Lowkey native experience memory

Lowkey's experience store is native Python and works without an AI provider. It keeps project feedback and reusable lessons in a private directory under the user's Lowkey data directory, keyed to the canonical path of the audited project. It deliberately does not trust memory files inside the target repository, because a checked-out or hostile repository could forge them. Approved global lessons are kept in the same private Lowkey data directory. Lessons are inert structured text; Lowkey never executes them as code or automatically changes security rules from memory.

## Record outcomes

~~~bash
lk memory feedback --kind false-positive --summary "Detector lead was unreachable" --evidence "Forge test shows the role check guards the only call path."
lk memory feedback --kind confirmed-finding --summary "Second withdrawal repeated the claim" --finding-id FINDING-123 --evidence "Regression test reproduces the state change."
lk memory feedback --kind useful-test --summary "Factory registry invariant caught missing registration"
lk memory feedback-list
lk memory status
~~~

Feedback records what the auditor corrected, confirmed, or learned from a run. It does not itself change audit rules.

## Propose, validate, and reuse a lesson

~~~bash
lk memory propose --kind test-procedure --title "Check factory child registry" --lesson "Assert both the factory event and the registry mapping." --when "A factory creates and tracks instances." --evidence "Observed in a local Foundry fixture." --tag factory --tag foundry
lk memory list --status proposed
lk memory show LESSON_ID
lk memory approve LESSON_ID --validation-kind test --validation "tests/test_project_targeting.py: locked implementation regression passes"
~~~

Proposed lessons do not enter AI context. Approval requires a validation type (test, reproduction, or manual-review) plus a specific note recording the evidence. This is a human promotion step; Lowkey does not claim that writing the note independently validates the lesson.

Only deliberately approved lessons are offered as compact reference context when an AI task is explicitly called. When source context is available, the selector ranks lesson titles, tags, relevance notes, and content against the current protocol before applying the size limit. Project lessons remain scoped to that project's canonical filesystem path. Moving the project changes the scope key. To promote a lesson for reuse across projects, explicitly request it:

~~~bash
lk memory approve LESSON_ID --validation-kind reproduction --validation "Reproduced on the controlled fixture; regression test retained" --global
lk memory list --scope global --status approved
~~~

Global promotion is opt-in. Keep project-specific assumptions, addresses, paths, private source and deployment notes in project scope.

## Reject and inspect

~~~bash
lk memory reject LESSON_ID --reason "Evidence did not reproduce"
lk memory list --scope both
lk memory status
~~~

The store has bounded record counts and field lengths. It records lesson text and feedback; it does not store API credentials, private keys or complete model prompts. The AI harness may include a small bounded set of approved lessons during an explicit protocol review, but model output remains a hypothesis and must be verified with native tools and tests.
