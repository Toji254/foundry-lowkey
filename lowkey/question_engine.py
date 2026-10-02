#!/usr/bin/env python3
"""Deterministic, project-agnostic auditor-question engine for Lowkey.

The engine is intentionally evidence-first and AI-free:
- a stable question corpus is the knowledge base;
- project detection decides which packs apply;
- .audit/context.json + events.jsonl provide the shared evidence bus;
- .audit/questions/ stores only the learner's question state/history;
- ranking chooses the next question, but never declares a vulnerability.

The core catalog applies to ordinary software projects. Blockchain/EVM,
web/service, native/system, data, and other packs add narrower questions
only when project evidence makes them relevant.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import audit_context

try:
    from project_detection import detect_project
except ImportError:
    detect_project = None


SCHEMA_VERSION = 1
QUESTION_DIR_NAME = "questions"
STATE_FILE_NAME = "state.json"
HISTORY_FILE_NAME = "history.jsonl"
MAX_HISTORY = 200
MAX_VISIBLE_QUESTIONS = 8


@dataclass(frozen=True)
class Question:
    id: str
    family: str
    concept: str
    text: str
    why: str
    phase: str
    priority: int
    tags: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()
    evidence_keys: tuple[str, ...] = ()
    commands: tuple[str, ...] = ()
    children: tuple[str, ...] = ()
    proof_questions: tuple[str, ...] = ()
    contradiction_questions: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()


def Q(
    qid: str,
    family: str,
    concept: str,
    text: str,
    why: str,
    *,
    phase: str = "understand",
    priority: int = 70,
    tags: Iterable[str] = (),
    prerequisites: Iterable[str] = (),
    evidence_keys: Iterable[str] = (),
    commands: Iterable[str] = (),
    children: Iterable[str] = (),
    proof_questions: Iterable[str] = (),
    contradiction_questions: Iterable[str] = (),
    sources: Iterable[str] = (),
) -> Question:
    return Question(
        id=qid,
        family=family,
        concept=concept,
        text=text,
        why=why,
        phase=phase,
        priority=priority,
        tags=tuple(tags),
        prerequisites=tuple(prerequisites),
        evidence_keys=tuple(evidence_keys),
        commands=tuple(commands),
        children=tuple(children),
        proof_questions=tuple(proof_questions),
        contradiction_questions=tuple(contradiction_questions),
        sources=tuple(sources),
    )


SOURCES = {
    "tob-context": (
        "Trail of Bits audit context-building",
        "https://github.com/trailofbits/skills/blob/main/plugins/audit-context-building/skills/audit-context-building/SKILL.md",
    ),
    "tob-function": (
        "Trail of Bits function analyzer",
        "https://github.com/trailofbits/skills/blob/main/plugins/audit-context-building/skills/function-analyzer/SKILL.md",
    ),
    "tob-secure": (
        "Trail of Bits secure smart-contract workflow",
        "https://github.com/crytic/building-secure-contracts/blob/master/program-analysis/README.md",
    ),
    "ethereum-security": (
        "Ethereum smart contract security considerations",
        "https://ethereum.org/en/developers/docs/smart-contracts/security/",
    ),
    "solidity-security": (
        "Solidity security considerations",
        "https://docs.soliditylang.org/en/latest/security-considerations.html",
    ),
    "scsvs": (
        "OWASP Smart Contract Security Verification Standard",
        "https://scs.owasp.org/",
    ),
    "scstg": (
        "OWASP Smart Contract Security Testing Guide",
        "https://scs.owasp.org/SCSTG/",
    ),
    "openzeppelin-audit": (
        "OpenZeppelin audit readiness guidance",
        "https://www.openzeppelin.com/security-audits",
    ),
    "foundry-invariant": (
        "Foundry invariant testing",
        "https://getfoundry.sh/forge/advanced-testing/invariant-testing/",
    ),
    "echidna": (
        "Trail of Bits Echidna",
        "https://github.com/crytic/echidna",
    ),
    "c4": (
        "Code4rena competitive audit findings / judging",
        "https://docs.code4rena.com/",
    ),
    "immunefi": (
        "Immunefi bug-fix / security research examples",
        "https://immunefi.com/immunefi-enhanced-bugfix-reviews/",
    ),
}


CORE_QUESTIONS: tuple[Question, ...] = (
    Q(
        "ARCH-001", "architecture", "purpose",
        "What is this project actually responsible for, and what valuable outcome is it supposed to produce?",
        "Auditors need a working model of intended behavior before they can tell a strange behavior from a security-relevant one.",
        phase="understand", priority=100,
        tags=("all", "architecture"),
        evidence_keys=("project_identity", "readme", "docs", "project_map"),
        commands=("lk project", "lk system", "lk read"),
        children=("ARCH-002", "ARCH-003", "ARCH-004"),
        sources=("tob-context", "openzeppelin-audit"),
    ),
    Q(
        "ARCH-002", "architecture", "assets",
        "What are the important assets, records, capabilities, or outcomes the system must protect?",
        "You cannot reason about impact until you know what can be lost, corrupted, exposed, or misused.",
        phase="understand", priority=96,
        tags=("all", "architecture"),
        prerequisites=("ARCH-001",),
        evidence_keys=("project_identity", "state_model", "value_or_data"),
        commands=("lk project", "lk system", "lk read"),
        children=("ARCH-005", "INV-001"),
        sources=("tob-context", "ethereum-security"),
    ),
    Q(
        "ARCH-003", "architecture", "trust",
        "Which actors, services, accounts, users, maintainers, or components are trusted, and exactly what are they trusted to do?",
        "A security boundary is defined by who may do what, not by names like admin, owner, service, or internal.",
        phase="understand", priority=98,
        tags=("all", "trust"),
        prerequisites=("ARCH-001",),
        evidence_keys=("project_map", "actors", "auth", "docs"),
        commands=("lk project", "lk system", "lk functions", "lk deps"),
        children=("AUTH-001", "AUTH-002", "EXT-001"),
        contradiction_questions=("AUTH-003",),
        sources=("tob-context", "scsvs"),
    ),
    Q(
        "ARCH-004", "architecture", "entry-points",
        "What are all the meaningful entry points into the system, including indirect entry through callbacks, messages, jobs, events, APIs, scripts, or dependencies?",
        "Auditors look for reachable behavior, not just the obvious public functions.",
        phase="surface", priority=94,
        tags=("all", "entry"),
        prerequisites=("ARCH-001",),
        evidence_keys=("entry_points", "functions", "routes", "commands", "system_graph"),
        commands=("lk functions", "lk project", "lk system", "lk rg"),
        children=("AUTH-001", "STATE-001", "EXT-002"),
        sources=("tob-context", "tob-function", "scsvs"),
    ),
    Q(
        "ARCH-005", "architecture", "data-flow",
        "Where does important data or value enter, change, move, and leave the system?",
        "Following the complete path exposes validation gaps, trust changes, and mismatched assumptions between components.",
        phase="surface", priority=90,
        tags=("all", "dataflow"),
        prerequisites=("ARCH-002", "ARCH-004"),
        evidence_keys=("system_graph", "trace", "state_diff", "call_graph"),
        commands=("lk system", "lk trace", "lk changes", "lk deps"),
        children=("INPUT-001", "EXT-002", "INV-001"),
        sources=("tob-function", "scsvs"),
    ),
    Q(
        "ARCH-006", "architecture", "dependencies",
        "Which dependencies and integrations are inside the security boundary, and which are being trusted from the outside?",
        "A bug or assumption in a dependency can become your bug once your system relies on its behavior.",
        phase="understand", priority=88,
        tags=("all", "dependencies"),
        evidence_keys=("dependencies", "imports", "package_manifests", "system_graph"),
        commands=("lk deps", "lk project", "lk system", "lk audit"),
        children=("EXT-001", "SUPPLY-001"),
        sources=("tob-context", "openzeppelin-audit"),
    ),
    Q(
        "ARCH-007", "architecture", "failure-model",
        "What is the intended behavior when a dependency, network call, external service, transaction, job, or internal operation fails?",
        "Many security properties only become visible on partial failure rather than the happy path.",
        phase="logic", priority=84,
        tags=("all", "failure"),
        evidence_keys=("error_handling", "tests", "trace", "logs"),
        commands=("lk test", "lk trace", "lk logs", "lk rg"),
        children=("ERROR-001", "DOS-001"),
        sources=("tob-context",),
    ),
    Q(
        "AUTH-001", "authorization", "identity",
        "How does the system identify the actor making a security-sensitive request?",
        "An authorization rule is only as strong as the identity signal it trusts.",
        phase="trust", priority=92,
        tags=("all", "auth"),
        prerequisites=("ARCH-003", "ARCH-004"),
        evidence_keys=("auth", "actors", "request_context", "function_guards"),
        commands=("lk functions", "lk read", "lk trace", "lk project"),
        children=("AUTH-002", "AUTH-003"),
        sources=("tob-context", "scsvs"),
    ),
    Q(
        "AUTH-002", "authorization", "authorization",
        "For each privileged action, what exact condition makes an untrusted actor unable to perform it?",
        "Auditors distinguish an intended rule from the concrete check that enforces the rule.",
        phase="trust", priority=100,
        tags=("all", "auth"),
        prerequisites=("AUTH-001",),
        evidence_keys=("auth", "function_guards", "source", "trace"),
        commands=("lk read", "lk trace", "lk rg", "lk findings"),
        children=("AUTH-003", "AUTH-004", "INV-002"),
        proof_questions=("AUTH-003",),
        sources=("tob-context", "scsvs"),
    ),
    Q(
        "AUTH-003", "authorization", "indirect-reachability",
        "Can the same protected state change or capability be reached another way without passing the check you just identified?",
        "Protecting one entry point does not prove the underlying state transition is protected everywhere.",
        phase="attack", priority=99,
        tags=("all", "auth", "reachability"),
        prerequisites=("AUTH-002", "ARCH-005"),
        evidence_keys=("call_graph", "trace", "entry_points", "state_diff"),
        commands=("lk trace", "lk changes", "lk system", "lk probe"),
        children=("EXT-002", "STATE-003", "PROOF-001"),
        contradiction_questions=("AUTH-002",),
        sources=("tob-context", "scsvs", "c4"),
    ),
    Q(
        "AUTH-004", "authorization", "default-access",
        "What happens when the authorization state is unset, defaulted, rotated, deleted, or misconfigured?",
        "Security boundaries often fail at initialization and lifecycle edges rather than steady-state.",
        phase="lifecycle", priority=86,
        tags=("all", "auth", "lifecycle"),
        prerequisites=("AUTH-002",),
        evidence_keys=("configuration", "initialization", "lifecycle", "tests"),
        commands=("lk project", "lk read", "lk test", "lk trace"),
        children=("LIFE-001", "CONFIG-001"),
        sources=("scsvs", "openzeppelin-audit"),
    ),
    Q(
        "INPUT-001", "input", "validation",
        "Which inputs are attacker-controlled, and what property is the code actually checking before using each one?",
        "Validation should match the security property that later code relies on, not merely reject obviously bad values.",
        phase="attack", priority=92,
        tags=("all", "input"),
        prerequisites=("ARCH-004", "ARCH-005"),
        evidence_keys=("entry_points", "validation", "source", "tests"),
        commands=("lk functions", "lk ask", "lk rg", "lk test"),
        children=("BOUND-001", "ERROR-001"),
        sources=("tob-function", "scsvs"),
    ),
    Q(
        "STATE-001", "state", "state-model",
        "What are the important states the system can be in, and what actions move it from one state to another?",
        "Many security bugs are state-machine bugs: a valid local step becomes invalid in a different sequence.",
        phase="state", priority=98,
        tags=("all", "state"),
        prerequisites=("ARCH-005",),
        evidence_keys=("state_model", "storage", "database", "trace", "state_diff"),
        commands=("lk project", "lk system", "lk layout", "lk changes", "lk trace"),
        children=("STATE-002", "STATE-003", "INV-001"),
        sources=("tob-context", "tob-function", "scsvs"),
    ),
    Q(
        "STATE-002", "state", "lifecycle",
        "For every security-sensitive state variable or record, what creates it, updates it, consumes it, and clears it?",
        "Lifecycle analysis reveals replay, stale state, double-use, and cleanup failures.",
        phase="state", priority=96,
        tags=("all", "state", "lifecycle"),
        prerequisites=("STATE-001",),
        evidence_keys=("state_model", "storage", "database", "changes", "tests"),
        commands=("lk changes", "lk mapping", "lk layout", "lk trace"),
        children=("REPLAY-001", "INV-001"),
        sources=("tob-function", "immunefi"),
    ),
    Q(
        "STATE-003", "state", "transition-guards",
        "What must be true immediately before and after each important state transition?",
        "Explicit pre/post conditions make it possible to prove or falsify a state transition.",
        phase="state", priority=94,
        tags=("all", "state", "invariant"),
        prerequisites=("STATE-001",),
        evidence_keys=("state_model", "tests", "state_diff", "trace"),
        commands=("lk changes", "lk trace", "lk test", "lk invariant"),
        children=("INV-001", "PROOF-001"),
        sources=("tob-context", "foundry-invariant"),
    ),
    Q(
        "INV-001", "invariants", "system-property",
        "What must always remain true for the system to stay correct and safe?",
        "Auditors move from individual functions to properties that should survive every reachable sequence.",
        phase="prove", priority=100,
        tags=("all", "invariant"),
        prerequisites=("STATE-003", "ARCH-002"),
        evidence_keys=("invariants", "docs", "tests", "fuzz", "walkthrough"),
        commands=("lk invariant", "lk fuzz", "lk test", "lk walkthrough test"),
        children=("INV-002", "PROOF-001"),
        sources=("tob-context", "scsvs", "foundry-invariant", "echidna"),
    ),
    Q(
        "INV-002", "invariants", "conservation",
        "Does the system preserve the quantities or relationships that should be conserved, such as balances, ownership, debt, permissions, supply, or record counts?",
        "Accounting and authorization failures often surface as broken conservation relationships.",
        phase="prove", priority=96,
        tags=("all", "invariant", "accounting"),
        prerequisites=("INV-001",),
        evidence_keys=("state_diff", "storage", "balances", "database", "tests"),
        commands=("lk changes", "lk layout", "lk diff", "lk invariant", "lk test"),
        children=("PROOF-001",),
        sources=("tob-function", "scsvs"),
    ),
    Q(
        "ERROR-001", "error handling", "failure-consistency",
        "When an operation fails halfway through, what state is left behind, and is that state safe?",
        "Partial failure can leave a permission, reservation, balance, lock, or record in a dangerous intermediate state.",
        phase="logic", priority=86,
        tags=("all", "failure"),
        prerequisites=("ARCH-007", "STATE-003"),
        evidence_keys=("trace", "state_diff", "tests", "logs", "error_handling"),
        commands=("lk trace", "lk changes", "lk test"),
        children=("DOS-001", "INV-001"),
        sources=("tob-context",),
    ),
    Q(
        "EXT-001", "external", "trust-boundary",
        "What external systems, libraries, services, contracts, queues, APIs, or plugins can influence important behavior?",
        "Every external boundary adds a new set of assumptions that your local code does not control.",
        phase="trust", priority=94,
        tags=("all", "external"),
        prerequisites=("ARCH-006",),
        evidence_keys=("dependencies", "integrations", "imports", "call_graph", "project_map"),
        commands=("lk deps", "lk system", "lk project", "lk trace"),
        children=("EXT-002", "SUPPLY-001"),
        sources=("tob-context", "scsvs"),
    ),
    Q(
        "EXT-002", "external", "return-value",
        "What does the caller do when an external operation returns an unexpected result, partial result, false value, or malformed response?",
        "A call succeeding at the transport level does not prove the external action satisfied your security assumption.",
        phase="attack", priority=91,
        tags=("all", "external", "failure"),
        prerequisites=("EXT-001", "ARCH-005"),
        evidence_keys=("trace", "error_handling", "return_checks", "tests"),
        commands=("lk trace", "lk test", "lk rg", "lk probe"),
        children=("ERROR-001", "PROOF-001"),
        sources=("tob-function", "scsvs"),
    ),
    Q("EXT-003", "external", "callback", "Can an external component call back into the system before an important state update finishes?", "Callbacks create a second execution path while your original assumptions are still in flight.", phase="attack", priority=90, tags=("all","external","callback"), prerequisites=("EXT-001",), evidence_keys=("call_graph","trace","callbacks","state_diff"), commands=("lk trace","lk changes","lk probe","lk system"), children=("EXT-004","INV-001"), sources=("tob-function","scsvs")),
    Q("EXT-004", "external", "nested-execution", "During one operation, can code re-enter another function, job, handler, or component that sees partially updated state?", "The dangerous boundary may be cross-function or cross-component rather than a direct recursive call.", phase="attack", priority=89, tags=("all","external","reentrancy"), prerequisites=("EXT-003",), evidence_keys=("trace","call_graph","state_diff"), commands=("lk trace","lk changes","lk walkthrough","lk probe"), children=("PROOF-001",), sources=("tob-context","scsvs")),
    Q("SUPPLY-001", "supply chain", "dependency-integrity", "Which dependencies are security-critical, and how do you know the exact code/version being executed is the code you reviewed?", "A correct review can be invalidated by an unexpected dependency, generated artifact, or package change.", phase="understand", priority=84, tags=("all","supply-chain"), prerequisites=("ARCH-006",), evidence_keys=("dependencies","package_manifests","lockfiles","build"), commands=("lk project","lk deps","lk audit","lk doctor"), children=("SUPPLY-002",), sources=("scsvs","openzeppelin-audit")),
    Q("SUPPLY-002", "supply chain", "build-integrity", "Which generated code, build steps, plugins, hooks, scripts, or compilers can change what actually ships?", "The reviewed source tree is not always the exact execution artifact.", phase="lifecycle", priority=82, tags=("all","supply-chain","build"), prerequisites=("SUPPLY-001",), evidence_keys=("build","generated_code","ci","manifests"), commands=("lk build","lk project","lk doctor","lk rg"), children=("PROOF-001",), sources=("scsvs",)),
    Q("BOUND-001", "boundaries", "edge-values", "What happens at zero, one, maximum, minimum, empty, missing, duplicated, stale, and unexpectedly large inputs?", "Boundary behavior is where ordinary business rules meet implementation limits.", phase="attack", priority=88, tags=("all","boundary"), prerequisites=("INPUT-001",), evidence_keys=("tests","fuzz","validation"), commands=("lk fuzz","lk brutalize","lk probe","lk test"), children=("BOUND-002","PROOF-001"), sources=("scsvs",)),
    Q("BOUND-002", "boundaries", "type-conversion", "Where are values converted between types, units, encodings, precisions, or signed/unsigned representations, and what can be lost?", "Different representations can make two components disagree about the same value.", phase="logic", priority=86, tags=("all","boundary","types"), prerequisites=("BOUND-001",), evidence_keys=("source","tests","trace"), commands=("lk rg","lk test","lk fuzz"), children=("INV-002",), sources=("tob-function","scsvs")),
    Q("DOS-001", "availability", "resource-bounds", "What attacker-controlled work, storage growth, memory, gas, CPU, retries, queueing, or locking can grow without a dependable bound?", "A path can be logically correct but still unusable or exploitable through resource exhaustion.", phase="attack", priority=84, tags=("all","dos"), prerequisites=("ARCH-004",), evidence_keys=("source","gas","tests","metrics","storage"), commands=("lk gas","lk rg","lk test","lk fuzz"), children=("DOS-002",), sources=("scsvs",)),
    Q("DOS-002", "availability", "griefing", "Can one actor force someone else to spend resources, lose liveness, or become unable to complete a required action?", "Griefing often needs no direct theft to create a meaningful security failure.", phase="attack", priority=80, tags=("all","dos","griefing"), prerequisites=("DOS-001",), evidence_keys=("state_model","tests","trace"), commands=("lk matrix","lk probe","lk test"), children=("PROOF-001",), sources=("scsvs","c4")),
    Q("ORDER-001", "ordering", "race-order", "Does correctness depend on which of two valid actions happens first?", "Order-dependent behavior creates race conditions, front-running opportunities, and inconsistent state.", phase="attack", priority=82, tags=("all","ordering"), prerequisites=("STATE-001",), evidence_keys=("state_model","trace","tests"), commands=("lk trace","lk matrix","lk test","lk probe"), children=("ORDER-002","PROOF-001"), sources=("scsvs",)),
    Q("ORDER-002", "ordering", "idempotency", "If the same request is delivered twice, what prevents an unintended second effect?", "Retries, duplicate messages, repeated transactions, and replayed requests are normal failure modes.", phase="attack", priority=90, tags=("all","replay","ordering"), prerequisites=("STATE-002",), evidence_keys=("state_model","tests","trace","nonces"), commands=("lk test","lk probe","lk matrix","lk changes"), children=("REPLAY-001",), sources=("tob-function","scsvs")),
    Q("REPLAY-001", "replay", "consumption", "What exact state makes a one-time authorization, claim, withdrawal, message, job, or entitlement become unusable after it is consumed?", "The security property is the consumption of authority, not merely the existence of a first successful call.", phase="attack", priority=95, tags=("all","replay"), prerequisites=("ORDER-002",), evidence_keys=("state_diff","tests","nonces","consumption"), commands=("lk changes","lk trace","lk test","lk matrix"), children=("PROOF-001",), sources=("immunefi","c4")),
    Q("CONFIG-001", "configuration", "defaults", "Which security-sensitive settings can be unset, defaulted, zeroed, or changed, and what does the system do in that state?", "A safe steady-state assumption can become unsafe during deployment, rotation, or partial configuration.", phase="lifecycle", priority=84, tags=("all","configuration"), prerequisites=("ARCH-003",), evidence_keys=("configuration","initialization","project_map"), commands=("lk project","lk read","lk test","lk rg"), children=("LIFE-001",), sources=("scsvs","openzeppelin-audit")),
    Q("LIFE-001", "lifecycle", "deployment", "What must happen before the system is safe to use, and what happens during initialization, upgrade, migration, restart, or recovery?", "Lifecycle states can temporarily expose capabilities or leave stale assumptions behind.", phase="lifecycle", priority=88, tags=("all","lifecycle"), evidence_keys=("deployment","initialization","configuration","tests","ci"), commands=("lk project","lk system","lk test","lk script"), children=("LIFE-002",), sources=("scsvs","openzeppelin-audit")),
    Q("LIFE-002", "lifecycle", "rollback", "After a failed deployment, migration, upgrade, restart, or rollout, what is the rollback path and what state survives it?", "Recovery can leave old and new assumptions coexisting.", phase="lifecycle", priority=78, tags=("all","lifecycle","rollback"), prerequisites=("LIFE-001",), evidence_keys=("deployment","migrations","ci","configuration"), commands=("lk project","lk test","lk rg"), children=("INV-001",), sources=("tob-context",)),
    Q("TEST-001", "testing", "negative-cases", "Which important actions have explicit tests for rejection, failure, and hostile inputs rather than only happy-path success?", "Security properties are often about what must not happen.", phase="prove", priority=90, tags=("all","testing"), prerequisites=("ARCH-004",), evidence_keys=("tests",), commands=("lk test","lk project"), children=("TEST-002","TEST-003"), sources=("scstg","c4")),
    Q("TEST-002", "testing", "property-tests", "Which important system properties are tested across many inputs or state sequences rather than with a few fixed examples?", "A fixed example can miss a bug that depends on values or action order.", phase="prove", priority=88, tags=("all","testing","fuzz"), prerequisites=("INV-001","TEST-001"), evidence_keys=("fuzz","invariant","tests"), commands=("lk fuzz","lk invariant","lk test"), children=("TEST-003","PROOF-001"), sources=("foundry-invariant","echidna")),
    Q("TEST-003", "testing", "reproduction", "Can an important observation be reduced to a deterministic, repeatable reproduction with the evidence needed to explain why it matters?", "A reproducible proof is much stronger than an interesting one-off behavior.", phase="prove", priority=94, tags=("all","testing","proof"), prerequisites=("INV-001",), evidence_keys=("tests","trace","state_diff","walkthrough"), commands=("lk generate test","lk trace","lk changes","lk test"), children=("PROOF-001",), sources=("c4","immunefi")),
    Q("PROOF-001", "proof", "claim-vs-proof", "What exact security property are you trying to establish, and what evidence would distinguish a real violation from a merely surprising behavior?",
        "Successful calls, analyzer warnings, and test failures are observations; they do not by themselves establish impact.",
        phase="prove", priority=100,
        tags=("all","proof"),
        prerequisites=("ARCH-005",),
        evidence_keys=("trace","state_diff","tests","signals","findings"),
        commands=("lk trace","lk changes","lk findings","lk test","lk generate test"),
        children=("PROOF-002",),
        sources=("tob-context","c4","immunefi")),
    Q("PROOF-002", "proof", "alternative-explanation", "What benign or intended explanation could produce the same observation, and what evidence would rule that explanation out?", "An auditor must falsify competing explanations instead of treating anomalies as bugs.", phase="prove", priority=86, tags=("all","proof"), prerequisites=("PROOF-001",), evidence_keys=("docs","source","tests","trace","state_diff"), commands=("lk project","lk rg","lk trace","lk test"), children=("TEST-003",), sources=("tob-context",)),
    Q("OBS-001", "observability", "evidence-quality", "What logs, traces, metrics, events, or audit evidence would let you reconstruct what happened after an incident?", "A system that cannot explain its own behavior is harder to secure and harder to investigate.", phase="lifecycle", priority=70, tags=("all","observability"), evidence_keys=("logs","trace","events","metrics"), commands=("lk logs","lk trace","lk project"), children=("LIFE-002",), sources=("tob-context",)),
    Q("SECRET-001", "secrets", "secret-handling", "Where do secrets, tokens, credentials, or signing capabilities live, and what components can read or use them?", "A secret is only as safe as every place and process that can access it.", phase="trust", priority=86, tags=("all","secrets"), evidence_keys=("configuration","secrets","ci","source"), commands=("lk project","lk rg","lk doctor"), children=("SECRET-002",), sources=("scsvs",)),
    Q("SECRET-002", "secrets", "secret-exposure", "Can secrets or privileged material leak through logs, error messages, source, test fixtures, artifacts, crash dumps, or client responses?", "Many secret compromises happen outside the intended secret store.", phase="attack", priority=82, tags=("all","secrets"), prerequisites=("SECRET-001",), evidence_keys=("logs","source","tests","artifacts"), commands=("lk rg","lk logs","lk project","lk test"), children=("PROOF-002",), sources=("scsvs",)),
    Q("CRYPTO-001", "cryptography", "randomness", "Where does the system rely on randomness or uniqueness, and who can predict, influence, or repeat the value?", "Security-critical randomness must be unpredictable to the relevant attacker.", phase="attack", priority=78, tags=("all","crypto"), evidence_keys=("randomness","source","tests"), commands=("lk rg","lk test","lk fuzz"), children=("PROOF-001",), sources=("scsvs",)),
    Q("PARSER-001", "parsing", "parser-consistency", "Do different components parse, normalize, validate, or serialize the same input in different ways?", "Parser differentials can bypass checks that appear correct in isolation.", phase="attack", priority=78, tags=("all","parsing"), evidence_keys=("serialization","protocols","source","tests"), commands=("lk rg","lk test","lk fuzz"), children=("PROOF-001",), sources=("scsvs",)),
    Q("PRIV-001", "privacy", "data-exposure", "Which data should be private or access-controlled, and where could it become observable through outputs, logs, metadata, errors, or alternate interfaces?", "Confidentiality often fails through a second interface rather than the primary one.", phase="attack", priority=72, tags=("all","privacy"), evidence_keys=("data_model","apis","logs","source"), commands=("lk project","lk rg","lk test"), children=("PROOF-001",), sources=("scsvs",)),
    Q("CRIT-001", "criticality", "blast-radius", "If this component fails or is compromised, what other components, assets, users, or privileges become reachable?", "Impact analysis needs the system graph, not just the local function.", phase="prove", priority=85, tags=("all","architecture","impact"), prerequisites=("ARCH-006",), evidence_keys=("system_graph","dependencies","trust"), commands=("lk system","lk project","lk deps"), children=("PROOF-001",), sources=("tob-context","openzeppelin-audit")),
)


BLOCKCHAIN_QUESTIONS: tuple[Question, ...] = (
    Q("BC-001","blockchain","asset-flow","Where does value enter the protocol, where is it recorded, and where can it leave?", "Money-flow analysis is the backbone of DeFi security review.", phase="understand", priority=99, tags=("blockchain","evm","solidity","vyper","cairo","move","anchor"), evidence_keys=("value_flow","balances","trace","state_diff"), commands=("lk project","lk system","lk trace","lk changes"), children=("BC-002","BC-003"), sources=("ethereum-security","tob-context")),
    Q("BC-002","blockchain","token-semantics","Does accounting assume tokens behave like a plain ERC-20, or does it handle transfer hooks, fees, rebasing, unusual return values, decimals, or non-standard semantics?", "Token implementations can change the amount actually received or the code executed during a transfer.", phase="attack", priority=95, tags=("blockchain","evm","token"), prerequisites=("BC-001",), evidence_keys=("token_behavior","source","trace","state_diff"), commands=("lk token","lk trace","lk changes","lk rg","lk test"), children=("BC-003","INV-002"), sources=("openzeppelin-audit","immunefi","scsvs")),
    Q("BC-003","blockchain","accounting","Do internal balances, shares, debt, fees, or supply values match actual assets after every relevant operation?", "Accounting bugs frequently become value-extraction bugs when internal state and external assets diverge.", phase="logic", priority=100, tags=("blockchain","accounting"), prerequisites=("BC-001",), evidence_keys=("balances","state_diff","storage","invariants"), commands=("lk changes","lk diff","lk layout","lk invariant","lk test"), children=("BC-004","PROOF-001"), sources=("tob-function","immunefi","scsvs")),
    Q("BC-004","blockchain","rounding","Who receives rounding loss, and can repeated operations or adversarial ordering turn small differences into meaningful value?", "Rounding that is harmless once can become exploitable when repeated or composed.", phase="attack", priority=88, tags=("blockchain","accounting","math"), prerequisites=("BC-003",), evidence_keys=("math","tests","state_diff"), commands=("lk rg","lk fuzz","lk changes","lk test"), children=("PROOF-001",), sources=("scsvs","openzeppelin-audit")),
    Q("BC-005","blockchain","oracle","What external price, rate, liquidity, or state assumption does the protocol trust, and how fresh/manipulable is it?", "A mathematically correct calculation can still be unsafe when the input can be controlled or made stale.", phase="attack", priority=98, tags=("blockchain","oracle","defi"), evidence_keys=("oracle","prices","trace","state_model"), commands=("lk project","lk rg","lk trace","lk test"), children=("BC-006","PROOF-001"), sources=("ethereum-security","immunefi","scsvs")),
    Q("BC-006","blockchain","oracle-manipulation","Can one transaction, flash loan, donation, liquidity shift, or callback change an oracle-dependent value before the check completes?", "Spot state can be transiently manipulated and then restored while the vulnerable operation still uses it.", phase="attack", priority=96, tags=("blockchain","oracle","flashloan","defi"), prerequisites=("BC-005","BC-001"), evidence_keys=("trace","state_diff","oracle","tests"), commands=("lk trace","lk changes","lk probe","lk test","lk walkthrough test"), children=("PROOF-001",), sources=("immunefi","c4")),
    Q("BC-007","blockchain","reentrancy","After an external call, can any path observe partially updated state and perform a second meaningful action?", "Reentrancy is fundamentally about interleaving state transitions, not only recursive calls.", phase="attack", priority=96, tags=("blockchain","evm","reentrancy","callbacks"), prerequisites=("EXT-003","STATE-003"), evidence_keys=("trace","state_diff","call_graph","callbacks"), commands=("lk trace","lk changes","lk probe","lk walkthrough test"), children=("BC-008","PROOF-001"), sources=("tob-secure","scsvs")),
    Q("BC-008","blockchain","cross-function-reentrancy","Can a callback or external call enter a different function that touches the same sensitive state?", "A single-function nonReentrant guard does not prove the whole state machine is safe.", phase="attack", priority=93, tags=("blockchain","evm","reentrancy"), prerequisites=("BC-007",), evidence_keys=("call_graph","trace","state_diff"), commands=("lk system","lk trace","lk changes","lk probe"), children=("PROOF-001",), sources=("tob-function","scsvs")),
    Q("BC-009","blockchain","read-only-reentrancy","Can another contract read a transient or partially updated value during a callback even if no state-changing function is re-entered?", "View/quote paths can influence later decisions even when the first read looks harmless.", phase="attack", priority=86, tags=("blockchain","evm","reentrancy","view"), prerequisites=("BC-007",), evidence_keys=("trace","call_graph","oracle","read_paths"), commands=("lk trace","lk system","lk read","lk test"), children=("PROOF-001",), sources=("immunefi","scsvs")),
    Q("BC-010","blockchain","mev-ordering","Does correctness or economic safety depend on an operation staying first, last, private, or unobserved until execution?", "Public ordering can change prices, state, eligibility, or execution outcomes.", phase="attack", priority=92, tags=("blockchain","evm","mev","ordering"), prerequisites=("ORDER-001","BC-001"), evidence_keys=("ordering","mempool","slippage","state_model"), commands=("lk trace","lk matrix","lk test","lk txpool"), children=("BC-011","PROOF-001"), sources=("ethereum-security","immunefi","scsvs")),
    Q("BC-011","blockchain","slippage","What user-controlled bound stops an execution from completing at a materially different price or amount?", "Without a meaningful bound, ordering and market movement can turn a valid transaction into a loss.", phase="attack", priority=90, tags=("blockchain","defi"), prerequisites=("BC-010",), evidence_keys=("parameters","math","tests"), commands=("lk ask","lk probe","lk test","lk fuzz"), children=("PROOF-001",), sources=("scsvs","immunefi")),
    Q("BC-012","blockchain","signatures","What exactly is signed, who can sign it, and which chain/contract/action/domain is that signature bound to?", "A valid signature for the wrong domain can authorize an unintended action.", phase="trust", priority=94, tags=("blockchain","signatures","auth"), evidence_keys=("signatures","chain_id","domain","source","tests"), commands=("lk rg","lk ask","lk test","lk probe"), children=("BC-013",), sources=("scsvs","openzeppelin-audit")),
    Q("BC-013","blockchain","replay","What nonce, state consumption, expiry, or domain binding prevents reuse of a signed authorization?", "Signature safety depends on preventing valid data from being valid again in the wrong context or time.", phase="attack", priority=94, tags=("blockchain","signatures","replay"), prerequisites=("BC-012",), evidence_keys=("nonces","expiry","domain","state_diff","tests"), commands=("lk read","lk changes","lk test","lk matrix"), children=("PROOF-001",), sources=("scsvs","c4")),
    Q("BC-014","blockchain","upgradeability","Who can change the implementation, configuration, or validation rules after deployment?", "Upgrade authority is part of the protocol's security boundary.", phase="lifecycle", priority=92, tags=("blockchain","upgrade","proxy","governance"), evidence_keys=("proxy","admin","implementation","upgrade","roles"), commands=("lk proxy","lk implementation","lk admin","lk project"), children=("BC-015","LIFE-001"), sources=("openzeppelin-audit","scsvs")),
    Q("BC-015","blockchain","initialization","Can initialization, re-initialization, migration, or upgrade setup be invoked in an unsafe state or by the wrong caller?", "Many proxy and upgrade failures begin with initialization boundaries.", phase="lifecycle", priority=92, tags=("blockchain","upgrade","proxy","initializer"), prerequisites=("BC-014",), evidence_keys=("initialization","proxy","roles","tests"), commands=("lk proxy","lk read","lk probe","lk test"), children=("PROOF-001",), sources=("openzeppelin-audit","immunefi")),
    Q("BC-016","blockchain","storage-layout","Could storage slots, namespaced state, delegatecall targets, or inherited layouts disagree across upgrades or components?", "Storage interpretation must remain consistent when code changes or executes through another context.", phase="lifecycle", priority=84, tags=("blockchain","evm","storage","upgrade"), prerequisites=("BC-014",), evidence_keys=("storage","layout","proxy"), commands=("lk layout","lk namespace","lk mapping","lk proof"), children=("PROOF-001",), sources=("openzeppelin-audit","solidity-security")),
    Q("BC-017","blockchain","delegatecall","Which code runs with the caller's storage/permissions through delegatecall or an equivalent mechanism, and what assumptions does it inherit?", "Delegate execution moves authority and state ownership across code boundaries.", phase="attack", priority=92, tags=("blockchain","evm","delegatecall"), evidence_keys=("call_graph","proxy","bytecode","trace"), commands=("lk trace","lk proxy","lk disasm","lk selectors"), children=("PROOF-001",), sources=("solidity-security","openzeppelin-audit")),
    Q("BC-018","blockchain","forced-value","Can the contract's native asset balance change without the expected accounting path, and what does the protocol assume about the difference?", "Observed balance and internal accounting can diverge even without a normal deposit call.", phase="attack", priority=82, tags=("blockchain","evm","accounting"), prerequisites=("BC-003",), evidence_keys=("balances","state_diff","source"), commands=("lk recon","lk changes","lk diff","lk test"), children=("PROOF-001",), sources=("solidity-security","ethereum-security")),
    Q("BC-019","blockchain","time","Which behavior depends on timestamps, block numbers, deadlines, epochs, or freshness windows, and what happens at the exact boundary?", "Time conditions are attacker-influenced or sequence-dependent enough to deserve explicit boundary review.", phase="attack", priority=80, tags=("blockchain","evm","time"), evidence_keys=("time","tests","state_model"), commands=("lk rg","lk brutalize","lk test"), children=("PROOF-001",), sources=("solidity-security","scsvs")),
    Q("BC-020","blockchain","chain-context","Which assumptions depend on chain id, fork, network, block producer behavior, finality, or deployment address?", "A property can be valid on one chain and unsafe on another execution context.", phase="lifecycle", priority=78, tags=("blockchain","cross-chain"), evidence_keys=("chain","deployment","signatures","configuration"), commands=("lk chain","lk project","lk fork","lk test"), children=("PROOF-001",), sources=("ethereum-security","scsvs")),
    Q("BC-021","blockchain","gas","Which user-controlled path can become unbounded in gas because it loops over growing state or performs many external calls?", "A transaction that cannot complete can lock funds or block required state transitions.", phase="attack", priority=82, tags=("blockchain","gas","dos"), evidence_keys=("gas","source","storage","tests"), commands=("lk gas","lk rg","lk test"), children=("DOS-002",), sources=("scsvs")),
    Q("BC-022","blockchain","randomness","Can an actor predict, influence, or bias a supposedly random value using block or transaction context?", "Public chain context is not a secret randomness source.", phase="attack", priority=76, tags=("blockchain","evm","randomness"), prerequisites=("CRYPTO-001",), evidence_keys=("randomness","block","timestamp","tests"), commands=("lk rg","lk brutalize","lk test"), children=("PROOF-001",), sources=("solidity-security","scsvs")),
    Q("BC-023","blockchain","economic-invariants","What economic relationship must hold even when prices move, fees accrue, or users act adversarially?", "Economic security is often a protocol-level invariant rather than a code-local condition.", phase="prove", priority=92, tags=("blockchain","defi","economics"), prerequisites=("BC-003",), evidence_keys=("math","invariants","state_model","tests"), commands=("lk invariant","lk fuzz","lk test","lk matrix"), children=("PROOF-001",), sources=("openzeppelin-audit","scsvs","immunefi")),
    Q("BC-024","blockchain","governance","Which changes can governance make, how quickly, and what stops a bad or compromised proposal from immediately violating security assumptions?", "Governance is an active trust boundary when it can change protocol rules.", phase="lifecycle", priority=84, tags=("blockchain","governance"), prerequisites=("AUTH-003",), evidence_keys=("roles","governance","timelock","upgrade"), commands=("lk project","lk system","lk read","lk trace"), children=("LIFE-001",), sources=("scsvs","openzeppelin-audit")),
    Q("BC-025","blockchain","cross-contract","Which contract or module assumes another component's internal state, and what proves those components remain synchronized?", "Composed protocols fail when one contract believes another is in a different state.", phase="system", priority=94, tags=("blockchain","system"), prerequisites=("ARCH-005",), evidence_keys=("system_graph","trace","state_diff","dependencies"), commands=("lk system","lk trace","lk changes","lk project"), children=("INV-002","PROOF-001"), sources=("tob-context","immunefi")),
)


WEB_QUESTIONS: tuple[Question, ...] = (
    Q("WEB-001","web","request-auth","Which requests require authentication, and how is the authenticated identity carried across the request lifecycle?", "Authentication is a boundary, not just a login screen.", phase="trust", priority=94, tags=("web","service","api"), evidence_keys=("routes","auth","sessions","middleware"), commands=("lk project","lk rg","lk test"), children=("WEB-002","WEB-003"), sources=("scsvs",)),
    Q("WEB-002","web","object-auth","Can an authenticated user reach another user's object, record, job, file, or capability by changing an identifier or path?", "Object-level authorization failures often survive ordinary authentication tests.", phase="attack", priority=96, tags=("web","api","auth"), prerequisites=("WEB-001",), evidence_keys=("routes","auth","data_model","tests"), commands=("lk rg","lk test","lk probe"), children=("PROOF-001",), sources=("scsvs",)),
    Q("WEB-003","web","admin-auth","How are privileged web/API actions separated from ordinary authenticated actions?", "Role checks must protect the sensitive operation itself.", phase="trust", priority=90, tags=("web","api","auth"), prerequisites=("WEB-001",), evidence_keys=("auth","routes","roles"), commands=("lk rg","lk test","lk project"), children=("PROOF-001",), sources=("scsvs",)),
    Q("WEB-004","web","input-injection","Which user-controlled strings reach databases, shells, templates, interpreters, file paths, or other execution contexts?", "Context changes can turn data into code.", phase="attack", priority=92, tags=("web","service","input"), evidence_keys=("routes","source","dependencies","tests"), commands=("lk rg","lk test","lk fuzz"), children=("PROOF-001",), sources=("scsvs",)),
    Q("WEB-005","web","ssrf","Can an external caller influence where the server makes an outbound request?", "Server-side network reachability can cross trust boundaries invisible to the client.", phase="attack", priority=84, tags=("web","service","network"), evidence_keys=("http_clients","urls","network"), commands=("lk rg","lk test"), children=("PROOF-001",), sources=("scsvs",)),
    Q("WEB-006","web","upload","What files can users upload, where are they stored, and what later interprets or executes them?", "Upload paths cross storage, parsing, and execution boundaries.", phase="attack", priority=78, tags=("web","files","input"), evidence_keys=("uploads","storage","parsers"), commands=("lk rg","lk test"), children=("PROOF-001",), sources=("scsvs",)),
    Q("WEB-007","web","csrf","Which browser-authenticated state changes can be triggered from a different origin?", "Cookie-based authentication can make an otherwise authorized action reachable through an unintended browser path.", phase="attack", priority=74, tags=("web","browser","auth"), evidence_keys=("sessions","routes","csrf"), commands=("lk rg","lk test","lk project"), children=("PROOF-001",), sources=("scsvs",)),
    Q("WEB-008","web","rate-limit","Which endpoints or operations can be repeated cheaply, and what prevents resource exhaustion or automated abuse?", "Availability and abuse controls must be considered at attacker-controlled boundaries.", phase="attack", priority=76, tags=("web","availability"), evidence_keys=("routes","rate_limits","metrics"), commands=("lk rg","lk test","lk project"), children=("DOS-002",), sources=("scsvs",)),
    Q("WEB-009","web","serialization","Do proxies, clients, application code, and downstream services agree on how the same request/body/path is parsed?", "Protocol differentials can bypass validation or authorization.", phase="attack", priority=80, tags=("web","parsing"), evidence_keys=("serialization","routes","proxies"), commands=("lk rg","lk test"), children=("PARSER-001",), sources=("scsvs",)),
    Q("WEB-010","web","secrets","Which environment variables, config files, CI jobs, logs, or responses can expose credentials?", "Operational secret exposure is often outside business logic.", phase="trust", priority=84, tags=("web","secrets","ops"), evidence_keys=("configuration","ci","logs","source"), commands=("lk rg","lk project","lk doctor"), children=("SECRET-002",), sources=("scsvs",)),
)


NATIVE_QUESTIONS: tuple[Question, ...] = (
    Q("NATIVE-001","native","processes","Can attacker-controlled input reach command execution, subprocess spawning, shells, plugins, or dynamic loading?", "Process boundaries are privilege boundaries.", phase="attack", priority=92, tags=("native","service"), evidence_keys=("processes","source","tests"), commands=("lk rg","lk test"), children=("PROOF-001",), sources=("scsvs",)),
    Q("NATIVE-002","native","filesystem","Which paths, files, links, archives, or permissions are attacker-controlled, and what assumptions are made about them?", "Filesystem names can cross privilege and trust boundaries.", phase="attack", priority=88, tags=("native","filesystem"), evidence_keys=("filesystem","source","tests"), commands=("lk rg","lk test","lk fuzz"), children=("PROOF-001",), sources=("scsvs",)),
    Q("NATIVE-003","native","memory-safety","Where does the project use unsafe memory operations, raw pointers, unchecked indexing, manual allocation, or equivalent escape hatches?", "Memory-unsafe boundaries deserve direct, local reasoning and targeted tests.", phase="attack", priority=90, tags=("native","memory","unsafe"), evidence_keys=("source","compiler","tests"), commands=("lk rg","lk test","lk fuzz"), children=("PROOF-001",), sources=("tob-context",)),
    Q("NATIVE-004","native","privilege","Which code runs with more operating-system privilege than the caller or user normally has?", "Privilege amplification creates a larger blast radius for a local bug.", phase="trust", priority=88, tags=("native","privilege"), evidence_keys=("deployment","permissions","processes","config"), commands=("lk project","lk rg","lk test"), children=("NATIVE-005",), sources=("tob-context",)),
    Q("NATIVE-005","native","syscalls","Which system calls, device access, IPC channels, or kernel interfaces are exposed to untrusted input?", "Low-level interfaces often have assumptions that higher-level code hides.", phase="attack", priority=74, tags=("native","system"), prerequisites=("NATIVE-004",), evidence_keys=("syscalls","source","tests"), commands=("lk rg","lk test"), children=("PROOF-001",), sources=("tob-context",)),
    Q("NATIVE-006","native","concurrency","Which shared state can be observed or modified concurrently, and what establishes its synchronization or atomicity?", "Concurrency changes the set of reachable state sequences.", phase="attack", priority=88, tags=("native","concurrency","service"), evidence_keys=("concurrency","tests","state_model"), commands=("lk rg","lk test","lk fuzz"), children=("ORDER-001","PROOF-001"), sources=("tob-context",)),
)


DATA_QUESTIONS: tuple[Question, ...] = (
    Q("DATA-001","data","integrity","Which records are security-critical, and what prevents unauthorized creation, mutation, deletion, or replay of those records?", "Data integrity is the state-machine layer of many applications.", phase="state", priority=90, tags=("data","service"), evidence_keys=("data_model","authorization","database","tests"), commands=("lk project","lk rg","lk test"), children=("INV-002","PROOF-001"), sources=("tob-context",)),
    Q("DATA-002","data","migration","What happens to security-critical records during schema migrations, backfills, imports, or version changes?", "Migration code can temporarily violate invariants that steady-state code assumes.", phase="lifecycle", priority=76, tags=("data","database","lifecycle"), evidence_keys=("migrations","database","tests"), commands=("lk project","lk rg","lk test"), children=("INV-001",), sources=("tob-context",)),
    Q("DATA-003","data","tenant-isolation","If the project serves multiple users, tenants, organizations, or namespaces, what enforces separation between their data and capabilities?", "Multi-tenant isolation is an explicit trust boundary.", phase="attack", priority=92, tags=("data","web","auth"), evidence_keys=("data_model","auth","routes","tests"), commands=("lk project","lk rg","lk test"), children=("PROOF-001",), sources=("tob-context",)),
    Q("DATA-004","data","serialization","Can two components disagree about identifiers, canonical forms, encoding, nullability, or ordering of the same record?", "Data representation drift can bypass authorization and integrity checks.", phase="attack", priority=78, tags=("data","parsing"), evidence_keys=("serialization","schema","tests"), commands=("lk rg","lk test","lk fuzz"), children=("PARSER-001",), sources=("tob-context",)),
)


PACKS = {
    "core": CORE_QUESTIONS,
    "blockchain": BLOCKCHAIN_QUESTIONS,
    "web": WEB_QUESTIONS,
    "native": NATIVE_QUESTIONS,
    "data": DATA_QUESTIONS,
}

QUESTION_CATALOG: dict[str, Question] = {}
for _pack in PACKS.values():
    for _question in _pack:
        QUESTION_CATALOG[_question.id] = _question


PHASE_ORDER = {
    "understand": 0,
    "surface": 1,
    "trust": 2,
    "state": 3,
    "logic": 4,
    "attack": 5,
    "prove": 6,
    "lifecycle": 7,
    "system": 4,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _project_root(root: Path | None = None) -> Path:
    return audit_context.foundry_project_root(root)


def _state_dir(root: Path | None = None) -> Path:
    return audit_context.audit_dir(_project_root(root)) / QUESTION_DIR_NAME


def _state_path(root: Path | None = None) -> Path:
    return _state_dir(root) / STATE_FILE_NAME


def _history_path(root: Path | None = None) -> Path:
    return _state_dir(root) / HISTORY_FILE_NAME


def _default_state(root: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project_root": str(root),
        "answers": {},
        "current_id": None,
        "started_at": _now(),
        "updated_at": _now(),
    }


def load_state(root: Path | None = None) -> dict[str, Any]:
    root_path = _project_root(root)
    path = _state_path(root_path)
    default = _default_state(root_path)
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
    if not isinstance(data, dict):
        return default
    stored_root = str(data.get("project_root") or "")
    try:
        if stored_root and Path(stored_root).expanduser().resolve() != root_path.resolve():
            return default
    except OSError:
        return default
    state = default
    state.update(data)
    state["schema_version"] = SCHEMA_VERSION
    state["project_root"] = str(root_path)
    state.setdefault("answers", {})
    return state


def save_state(state: dict[str, Any], root: Path | None = None) -> Path:
    root_path = _project_root(root)
    if not audit_context.is_audit_project(root_path):
        return _state_path(root_path)
    target = _state_path(root_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    state = dict(state)
    state["schema_version"] = SCHEMA_VERSION
    state["project_root"] = str(root_path)
    state["updated_at"] = _now()
    tmp = target.with_name(f".{target.name}.{__import__('os').getpid()}.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(target)
    return target


def _append_history(event: dict[str, Any], root: Path | None = None) -> None:
    root_path = _project_root(root)
    if not audit_context.is_audit_project(root_path):
        return
    path = _history_path(root_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = dict(event)
    record.setdefault("timestamp", _now())
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_HISTORY:
            path.write_text("\n".join(lines[-MAX_HISTORY:]) + "\n", encoding="utf-8")
    except OSError:
        pass


def _read_history(root: Path | None = None, limit: int = 30) -> list[dict[str, Any]]:
    path = _history_path(root)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    records = []
    for line in lines[-limit:]:
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
        except json.JSONDecodeError:
            continue
    return records


def _read_events(root: Path | None = None, limit: int = 120) -> list[dict[str, Any]]:
    path = audit_context.events_path(_project_root(root))
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events = []
    for line in lines[-limit:]:
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                events.append(item)
        except json.JSONDecodeError:
            continue
    return events


def _source_files(root: Path) -> list[Path]:
    try:
        return sorted(
            p for p in root.rglob("*")
            if p.is_file()
            and ".git" not in p.parts
            and ".audit" not in p.parts
            and "node_modules" not in p.parts
            and p.suffix.lower() in {
                ".sol",".vy",".vyi",".cairo",".move",".rs",".go",".py",".js",".jsx",".ts",".tsx",
                ".java",".kt",".swift",".c",".cc",".cpp",".h",".hpp",".cs",".rb",".php",".ex",".exs",
            }
        )
    except OSError:
        return []


def _sample_source(root: Path, limit_files: int = 140, limit_chars: int = 700_000) -> str:
    chunks: list[str] = []
    total = 0
    for path in _source_files(root)[:limit_files]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        remaining = limit_chars - total
        if remaining <= 0:
            break
        part = content[: min(len(content), remaining)]
        chunks.append(f"\n// LOWKEY_FILE {path.relative_to(root).as_posix()}\n{part}")
        total += len(part)
    return "\n".join(chunks).lower()


def _read_text_file(path: Path, limit: int = 40_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit].lower()
    except OSError:
        return ""


def _readme_text(root: Path) -> str:
    for name in ("README.md","README.rst","README.txt","docs/README.md"):
        text = _read_text_file(root / name, 50_000)
        if text:
            return text
    return ""


def _manifest_text(root: Path) -> str:
    parts = []
    for name in (
        "package.json","pyproject.toml","Cargo.toml","go.mod","go.work","pom.xml",
        "build.gradle","build.gradle.kts","mix.exs","Package.swift","CMakeLists.txt",
        "foundry.toml","hardhat.config.js","hardhat.config.ts","Scarb.toml","Move.toml","Anchor.toml",
    ):
        text = _read_text_file(root / name, 30_000)
        if text:
            parts.append(f"\n{name}\n{text}")
    return "\n".join(parts)


def detect_features(root: Path | None = None) -> dict[str, Any]:
    root_path = _project_root(root)
    context = audit_context.load(root_path)
    info: dict[str, Any] = {}
    if detect_project is not None:
        try:
            maybe = detect_project(root_path)
            if isinstance(maybe, dict):
                info = maybe
        except Exception:
            info = {}

    sample = _sample_source(root_path)
    manifest = _manifest_text(root_path)
    readme = _readme_text(root_path)
    languages = info.get("languages") or {}
    stacks = [str(x).lower() for x in (info.get("stacks") or info.get("build_systems") or [])]
    kind = str(info.get("kind") or "").lower()

    ext_presence = {p.suffix.lower() for p in _source_files(root_path)}
    blockchain = any(
        token in kind or token in stacks
        for token in ("foundry","hardhat","vyper","cairo","move","anchor","solana")
    ) or bool(ext_presence & {".sol",".vy",".vyi",".cairo",".move"})
    web = (
        bool(Path(root_path / "package.json").is_file() and re.search(r'"(?:express|fastify|koa|hapi|nest|next|nuxt|react|remix)"', manifest))
        or bool(re.search(r"\b(?:fastapi|flask|django|starlette)\b", manifest))
        or bool(re.search(r"\b(?:gin-gonic|echo-gin|fiber|net/http|axum|actix-web|rocket)\b", manifest))
        or bool(re.search(r"\b(?:router|route|middleware|httpserver|endpoint|api/v\d)\b", sample[:220_000]))
    )
    native = bool(
        ext_presence & {".rs",".go",".c",".cc",".cpp",".h",".hpp",".cs"}
        or any(name in manifest for name in ("cargo","go.mod","cmakelists","build.gradle","package.swift"))
    )
    data = bool(
        any((root_path / d).is_dir() for d in ("migrations","alembic","prisma","drizzle","db","database"))
        or bool(re.search(r"\b(?:sql|orm|sequelize|typeorm|sqlalchemy|diesel|gorm|postgres|mysql|sqlite)\b", manifest + sample[:180_000]))
    )
    crypto = bool(re.search(r"\b(?:sha256|keccak|hmac|signature|signer|nonce|random|rng|ed25519|secp256k1|bls)\b", sample))
    secrets = bool(re.search(r"\b(?:private[_ -]?key|secret|api[_ -]?key|token|credential|password|mnemonic)\b", sample + manifest))
    concurrency = bool(
        any(token in stacks for token in ("rust","go"))
        or bool(re.search(r"\b(?:async|await|thread|goroutine|mutex|lock|atomic|channel|concurrent)\b", sample))
    )
    serialization = bool(
        any(p in {".json",".yaml",".yml",".toml",".proto",".graphql"} for p in {x.suffix.lower() for x in root_path.rglob("*") if x.is_file() and ".git" not in x.parts})
        or bool(re.search(r"\b(?:json|yaml|protobuf|grpc|graphql|serde|abi|marshal|deserialize|serialize)\b", sample))
    )
    upgrades = bool(re.search(r"\b(?:upgrade|proxy|initializer|migration|versioned|delegatecall)\b", sample + manifest))
    oracle = bool(re.search(r"\b(?:oracle|price feed|twap|spot price|exchange rate|chainlink)\b", sample + readme))
    auth = bool(re.search(r"\b(?:owner|admin|role|permission|authorize|authentication|session|jwt|oauth|acl|access control)\b", sample + manifest + readme))
    callbacks = bool(re.search(r"\b(?:callback|hook|fallback|receive|webhook|listener|plugin)\b", sample))
    ordering = bool(re.search(r"\b(?:deadline|expiry|nonce|timestamp|block\.|mempool|front.?run|race|idempotent|replay)\b", sample + readme))
    tokens = bool(re.search(r"\b(?:erc20|erc721|erc4626|transferfrom|safeerc20|permit|rebasing|fee.?on.?transfer)\b", sample))
    storage = bool(re.search(r"\b(?:storage|mapping|database|redis|cache|state|snapshot|persist|migration)\b", sample + manifest))
    ci = bool((root_path / ".github" / "workflows").is_dir() or (root_path / ".gitlab-ci.yml").exists() or (root_path / ".circleci").is_dir())

    feature_map = {
        "blockchain": blockchain,
        "evm": blockchain and bool(ext_presence & {".sol",".vy",".vyi"}),
        "web": web,
        "native": native,
        "data": data,
        "crypto": crypto,
        "secrets": secrets,
        "concurrency": concurrency,
        "serialization": serialization,
        "upgrades": upgrades,
        "oracle": oracle,
        "auth": auth,
        "callbacks": callbacks,
        "ordering": ordering,
        "tokens": tokens,
        "storage": storage,
        "ci": ci,
    }

    return {
        "kind": kind,
        "languages": languages,
        "stacks": stacks,
        "features": feature_map,
        "context": context,
        "sample_source": sample,
        "manifest": manifest,
        "readme": readme,
    }


def _pack_enabled(question: Question, features: dict[str, Any]) -> bool:
    tags = set(question.tags)
    f = features.get("features") or {}
    if "all" in tags:
        return True
    if "blockchain" in tags and not f.get("blockchain"):
        return False
    if "evm" in tags and not f.get("evm"):
        return False
    if "web" in tags and not f.get("web"):
        return False
    if "native" in tags and not f.get("native"):
        return False
    if "data" in tags and not f.get("data"):
        return False

    specialized = {"oracle":"oracle","tokens":"tokens","upgrade":"upgrades","proxy":"upgrades","concurrency":"concurrency"}
    for tag, feature in specialized.items():
        if tag in tags and not f.get(feature):
            return False
    return True


def _event_signals(features: dict[str, Any]) -> dict[str, Any]:
    root = Path(str(features["context"]["project"]["root"]))
    context = features["context"]
    events = _read_events(root)
    command_names = []
    recent_tools = []
    latest_event = None
    for event in events:
        tool = str(event.get("tool") or "")
        typ = str(event.get("type") or "")
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        if typ == "lk-command":
            command = data.get("command")
            if command:
                command_names.append(str(command).lower())
        if tool:
            recent_tools.append(tool.lower())
        latest_event = event

    latest = context.get("latest") if isinstance(context.get("latest"), dict) else {}
    signals = context.get("signals") if isinstance(context.get("signals"), list) else []
    focus = context.get("focus") if isinstance(context.get("focus"), dict) else {}

    return {
        "events": events,
        "command_names": command_names[-40:],
        "recent_tools": recent_tools[-40:],
        "latest_event": latest_event,
        "latest": latest,
        "signals": signals,
        "focus": focus,
        "has_live_evidence": bool(latest.get("tx_hash") or latest.get("trace") or latest.get("state_diff")),
        "focused_signal": focus.get("signal_id"),
    }


def _evidence_present(key: str, *, features: dict[str, Any], observed: dict[str, Any]) -> bool:
    context = features["context"]
    latest = observed["latest"]
    commands = set(observed["command_names"])
    tools = set(observed["recent_tools"])
    signals = observed["signals"]
    source = features["sample_source"]
    readme = features["readme"]
    manifest = features["manifest"]

    mapping = {
        "project_identity": bool(context.get("project")) ,
        "project_map": "project" in commands or "system" in commands or "project" in tools,
        "readme": bool(readme),
        "docs": any((features.get("context") or {}).get("tools", {}).get(x) for x in ("project","system")),
        "value_or_data": bool(re.search(r"\b(?:eth|token|asset|balance|money|payment|account|record|data|resource)\b", source + readme)),
        "actors": bool(context.get("actor")) or bool(re.search(r"\b(?:actor|user|role|owner|admin|caller|principal)\b", source)),
        "auth": bool(re.search(r"\b(?:onlyowner|owner|admin|role|permission|authorize|authentication|session|jwt|oauth|acl|access control)\b", source + manifest)),
        "function_guards": bool(re.search(r"\b(?:require\s*\(|assert\s*\(|onlyowner|accesscontrol|permission|authorize|checkpermission|isadmin|roles)\b", source)),
        "entry_points": bool(re.search(r"\b(?:function\s+\w+|def\s+\w+\(|func\s+\w+|route\s*\(|@(?:get|post|put|patch|delete)|public\s+class)\b", source)),
        "functions": bool(re.search(r"\b(?:function\s+\w+|def\s+\w+\(|func\s+\w+)\b", source)),
        "routes": bool(re.search(r"\b(?:route|router|endpoint|@(?:get|post|put|patch|delete))\b", source)),
        "commands": bool(re.search(r"\b(?:argparse|click|cobra|clap|command|subcommand)\b", source)),
        "system_graph": "system" in commands or "project" in commands or bool(context.get("tools", {}).get("system")),
        "call_graph": bool(latest.get("trace")) or bool(re.search(r"\b(?:call|invoke|dispatch|send|delegatecall|http|rpc|request)\b", source)),
        "dependencies": bool(manifest) or bool(context.get("tools", {}).get("deps")),
        "imports": bool(re.search(r"\b(?:import|require|use\s+|from\s+)\b", source)),
        "package_manifests": bool(manifest),
        "source": bool(source),
        "trace": bool(latest.get("trace") or any("trace" in x for x in tools) or "trace" in commands),
        "state_diff": bool(latest.get("state_diff") or any("state-diff" in x or "changes" in x for x in commands)),
        "storage": bool(re.search(r"\b(?:storage|mapping|slot|database|redis|state|persist|cache)\b", source)),
        "database": "data" in (features.get("features") or {}),
        "state_model": bool(re.search(r"\b(?:state|status|phase|stage|lifecycle|mapping|database|record|cache)\b", source)),
        "invariants": bool(re.search(r"\b(?:invariant|must always|assert|conservation|total supply|balance ==)\b", source + readme)),
        "tests": any(name in commands for name in ("test","fuzz","invariant","walkthrough","audit")) or any("test" in x for x in tools),
        "fuzz": "fuzz" in commands or "fuzz" in tools,
        "invariant": "invariant" in commands or "invariant" in tools,
        "walkthrough": "walkthrough" in commands or "walkthrough" in tools,
        "signals": bool(signals),
        "findings": bool(signals),
        "configuration": bool(manifest) or bool(re.search(r"\b(?:config|configuration|environment|env|settings)\b", source)),
        "initialization": bool(re.search(r"\b(?:init|initialize|constructor|setup|bootstrap|migration)\b", source)),
        "deployment": bool(re.search(r"\b(?:deploy|deployment|release|rollout|script)\b", source + manifest)),
        "ci": features.get("features", {}).get("ci", False),
        "error_handling": bool(re.search(r"\b(?:revert|error|exception|catch|try|unwrap|expect|panic|fallback)\b", source)),
        "logs": bool(re.search(r"\b(?:log|logger|event|emit|console)\b", source)),
        "events": bool(re.search(r"\b(?:event|emit|webhook|listener)\b", source)),
        "metrics": bool(re.search(r"\b(?:metric|metrics|prometheus|telemetry|monitoring)\b", source + manifest)),
        "secrets": bool(re.search(r"\b(?:secret|private[_ -]?key|api[_ -]?key|credential|password|mnemonic|token)\b", source + manifest)),
        "artifacts": bool(any((root / d).is_dir() for d in ("out","dist","build","target","artifacts","coverage"))),
        "generated_code": bool(re.search(r"\b(?:generated|codegen|openapi|protobuf|abi|bindings)\b", manifest + source)),
        "serialization": features.get("features", {}).get("serialization", False),
        "data_model": features.get("features", {}).get("data", False) or bool(re.search(r"\b(?:struct|record|model|schema|table|mapping|database)\b", source)),
        "randomness": features.get("features", {}).get("crypto", False) or bool(re.search(r"\b(?:random|rng|rand|prevrandao|timestamp)\b", source)),
        "chain_id": bool(re.search(r"\b(?:chainid|chain_id|domain separator|network id)\b", source)),
        "oracle": features.get("features", {}).get("oracle", False),
        "token_behavior": features.get("features", {}).get("tokens", False),
        "parameters": bool(re.search(r"\b(?:slippage|minimum|max(?:imum)?|limit|deadline|expiry|amount|price|rate)\b", source)),
        "math": bool(re.search(r"\b(?:round|floor|ceil|division|multiply|decimal|precision|share|fee|rate|price)\b", source)),
        "balances": bool(re.search(r"\b(?:balance|supply|debt|reserve|asset|token)\b", source)),
        "value_flow": bool(re.search(r"\b(?:payable|transfer|withdraw|deposit|mint|burn|stake|borrow|repay|balance|reserve)\b", source)),
        "proxy": bool(re.search(r"\b(?:proxy|implementation|delegatecall|eip.?1967|uups|transparent)\b", source)),
        "upgrade": features.get("features", {}).get("upgrades", False),
        "roles": bool(re.search(r"\b(?:owner|admin|role|governance|timelock|operator|guardian)\b", source)),
        "timelock": bool(re.search(r"\btimelock\b", source)),
        "network": bool(re.search(r"\b(?:rpc|http|https|socket|grpc|websocket|network)\b", source + manifest)),
        "processes": bool(re.search(r"\b(?:subprocess|exec|spawn|shell|popen|system\(|command)\b", source)),
        "filesystem": bool(re.search(r"\b(?:file|filesystem|path|symlink|archive|zip|tar|open\(|read_file|write_file)\b", source)),
        "memory": bool(re.search(r"\b(?:unsafe|malloc|free|ptr|pointer|raw\s+pointer|memcpy|index)\b", source)),
        "syscalls": bool(re.search(r"\b(?:syscall|ioctl|mmap|socket|fork|execve)\b", source)),
        "concurrency": features.get("features", {}).get("concurrency", False),
        "http_clients": bool(re.search(r"\b(?:requests\.|axios|fetch\(|http\.client|urllib|curl|reqwest)\b", source)),
        "urls": bool(re.search(r"\b(?:https?://|url|uri|endpoint|hostname)\b", source)),
        "uploads": bool(re.search(r"\b(?:upload|multipart|file upload)\b", source)),
        "sessions": bool(re.search(r"\b(?:session|cookie|jwt|oauth)\b", source)),
        "csrf": bool(re.search(r"\b(?:csrf|xsrf|sameSite|samesite|origin|referer)\b", source)),
        "rate_limits": bool(re.search(r"\b(?:rate.?limit|throttle|quota|bucket|backoff)\b", source)),
        "proxies": bool(re.search(r"\b(?:nginx|haproxy|proxy|reverse proxy|gateway|load balancer)\b", manifest + source)),
        "migrations": bool(features.get("features", {}).get("data") and re.search(r"\b(?:migration|migrate|alembic|prisma|schema)\b", manifest + source)),
        "tenancy": bool(re.search(r"\b(?:tenant|organization|workspace|namespace|account_id|user_id)\b", source)),
        "permission": bool(re.search(r"\b(?:permission|acl|rbac|role|capability)\b", source)),
        "proof": bool(latest.get("trace") or latest.get("state_diff") or signals),
    }

    if latest.get("tx_hash"):
        mapping["trace"] = mapping["trace"] or bool(latest.get("tx_hash"))
    return mapping.get(key, False)


def question_evidence(q: Question, *, features: dict[str, Any], observed: dict[str, Any]) -> list[str]:
    context = features["context"]
    root = Path(str(context["project"]["root"]))
    evidence: list[str] = []
    if context.get("target", {}).get("contract"):
        evidence.append(f"target contract: {context['target'].get('contract')}")
    if context.get("target", {}).get("address"):
        evidence.append(f"target address: {context['target'].get('address')}")
    latest = observed.get("latest") or {}
    if latest.get("function"):
        evidence.append(f"latest function: {latest.get('function')}")
    if latest.get("tx_hash"):
        evidence.append(f"latest tx: {latest.get('tx_hash')}")
    if latest.get("trace"):
        evidence.append("Lowkey has trace evidence for the latest operation.")
    if latest.get("state_diff"):
        evidence.append("Lowkey has state-diff evidence for the latest operation.")
    signals = observed.get("signals") or []
    if signals:
        titles = [str(item.get("title") or item.get("check") or "signal") for item in signals[-5:] if isinstance(item, dict)]
        evidence.append("signals: " + "; ".join(titles))
    feature_notes = {
        "project_identity": "project metadata is available",
        "readme": "a README/documentation file exists",
        "project_map": "project/system mapping evidence exists",
        "actors": "actor/identity evidence exists",
        "auth": "authorization-like source concepts were detected",
        "entry_points": "callable/route entry points were detected",
        "dependencies": "dependency/build metadata exists",
        "storage": "persistent state concepts were detected",
        "configuration": "configuration/build metadata exists",
        "initialization": "initialization/setup concepts were detected",
        "tests": "test activity/evidence exists",
        "serialization": "serialization/protocol data formats were detected",
        "ci": "CI configuration was detected",
        "oracle": "oracle/price concepts were detected",
        "token_behavior": "token-specific behavior was detected",
        "proxy": "proxy/delegate/upgrade concepts were detected",
        "concurrency": "concurrency primitives/concepts were detected",
    }
    for key in q.evidence_keys:
        if _evidence_present(key, features=features, observed=observed):
            note = feature_notes.get(key)
            if note and note not in evidence:
                evidence.append(note)
    if not evidence:
        evidence.append(f"source root: {root}")
    return evidence[:10]


def _manual_status(state: dict[str, Any], qid: str) -> str | None:
    item = state.get("answers", {}).get(qid)
    if not isinstance(item, dict):
        return None
    return str(item.get("status") or "").upper() or None


def _prereqs_met(q: Question, state: dict[str, Any], enabled_ids: set[str]) -> bool:
    for parent in q.prerequisites:
        if parent not in enabled_ids:
            return False
        if _manual_status(state, parent) not in {"ANSWERED", "NOT_APPLICABLE", "SKIPPED"}:
            return False
    return True


def _recent_question_ids(root: Path | None = None, limit: int = 12) -> list[str]:
    return [
        str(item.get("question_id"))
        for item in _read_history(root, limit)
        if item.get("event") in {"shown", "answered", "not-applicable", "skipped"} and item.get("question_id")
    ]


def enabled_questions(root: Path | None = None) -> list[Question]:
    features = detect_features(root)
    return [q for q in QUESTION_CATALOG.values() if _pack_enabled(q, features)]


def _question_state(q: Question, state: dict[str, Any], features: dict[str, Any], observed: dict[str, Any]) -> str:
    manual = _manual_status(state, q.id)
    if manual == "ANSWERED":
        return "ANSWERED"
    if manual == "NOT_APPLICABLE":
        return "NOT APPLICABLE"
    if manual == "SKIPPED":
        return "SKIPPED"

    if q.contradiction_questions:
        if any(
            _signal_mentions(item, q.concept)
            for item in observed.get("signals", [])
            if isinstance(item, dict)
        ):
            return "CONTRADICTED"

    prereqs = _prereqs_met(q, state, set(QUESTION_CATALOG))
    if not prereqs:
        return "UNKNOWN"

    evidence_ready = any(_evidence_present(key, features=features, observed=observed) for key in q.evidence_keys)
    if evidence_ready and q.phase == "prove":
        return "NEEDS PROOF"
    if evidence_ready:
        return "ANSWERABLE"
    return "ANSWERABLE"


def _signal_mentions(signal: dict[str, Any], concept: str) -> bool:
    haystack = " ".join(
        str(signal.get(key) or "")
        for key in ("title","description","meaning","next","check","pattern_id","function")
    ).lower()
    terms = [token for token in re.split(r"[^a-z0-9]+", concept.lower()) if len(token) >= 4]
    return bool(terms and sum(1 for token in terms if token in haystack) >= max(1, len(terms) // 2))


def _score(
    q: Question,
    *,
    state: dict[str, Any],
    features: dict[str, Any],
    observed: dict[str, Any],
) -> tuple[float, list[str]]:
    status = _question_state(q, state, features, observed)
    if status in {"ANSWERED", "NOT APPLICABLE", "SKIPPED", "UNKNOWN"}:
        return (-10_000.0, [])
    score = float(q.priority)
    reasons: list[str] = []
    current_id = state.get("current_id")
    recent_ids = _recent_question_ids(Path(features["context"]["project"]["root"]), 10)

    phase = PHASE_ORDER.get(q.phase, 4)
    seen_answered = sum(
        1 for item in state.get("answers", {}).values()
        if isinstance(item, dict) and str(item.get("status") or "").upper() in {"ANSWERED","NOT_APPLICABLE","SKIPPED"}
    )
    expected_phase = min(phase, max(0, seen_answered // 2))
    if phase <= expected_phase + 1:
        score += 10
        reasons.append("fits the current learning stage")
    else:
        score -= min(35, (phase - expected_phase) * 8)

    if q.id == current_id:
        score += 5
        reasons.append("continues the current thread")

    if q.id in recent_ids:
        score -= 18
        reasons.append("was shown recently")

    evidence_hits = sum(
        1 for key in q.evidence_keys
        if _evidence_present(key, features=features, observed=observed)
    )
    missing = max(0, len(q.evidence_keys) - evidence_hits)
    if evidence_hits:
        score += min(20, evidence_hits * 4)
        reasons.append("Lowkey already has evidence to reason from")
    if missing:
        score += min(10, missing * 2)

    commands = " ".join(observed.get("command_names") or [])
    latest_function = str((observed.get("latest") or {}).get("function") or "")
    if any(token in commands for token in ("trace","changes","probe","walkthrough","findings","audit","project","system")):
        if any(key in q.evidence_keys for key in ("trace","state_diff","signals","project_map","system_graph")):
            score += 15
            reasons.append("your recent Lowkey work opened this branch")
    if latest_function and any(token in q.tags for token in ("state","auth","replay","accounting","entry","proof")):
        score += 5

    focused = observed.get("focused_signal")
    if focused:
        score += 12
        reasons.append(f"an investigation focus is active ({focused})")

    if observed.get("has_live_evidence") and any(key in q.evidence_keys for key in ("trace","state_diff","proof")):
        score += 18
        reasons.append("a live execution observation is available")

    if observed.get("signals") and any(key in q.evidence_keys for key in ("signals","findings","proof")):
        score += 16
        reasons.append("existing audit signals need manual validation")

    f = features.get("features") or {}
    if "blockchain" in q.tags and f.get("blockchain"):
        score += 9
        reasons.append("blockchain behavior is present")
    if "web" in q.tags and f.get("web"):
        score += 9
        reasons.append("web/API behavior is present")
    if "native" in q.tags and f.get("native"):
        score += 9
        reasons.append("native/runtime behavior is present")
    if "data" in q.tags and f.get("data"):
        score += 7
        reasons.append("persistent data behavior is present")

    return score, reasons


def rank_questions(root: Path | None = None, *, limit: int = MAX_VISIBLE_QUESTIONS) -> list[dict[str, Any]]:
    root_path = _project_root(root)
    state = load_state(root_path)
    features = detect_features(root_path)
    observed = _event_signals(features)
    rows: list[dict[str, Any]] = []
    for q in enabled_questions(root_path):
        score, reasons = _score(q, state=state, features=features, observed=observed)
        if score < -1_000:
            continue
        rows.append({
            "question": q,
            "score": round(score, 2),
            "reasons": reasons,
            "status": _question_state(q, state, features, observed),
            "evidence": question_evidence(q, features=features, observed=observed),
        })
    rows.sort(key=lambda item: (-float(item["score"]), PHASE_ORDER.get(item["question"].phase, 4), item["question"].id))
    return rows[:max(1, int(limit))]


def current_question(root: Path | None = None) -> dict[str, Any] | None:
    rows = rank_questions(root, limit=12)
    if not rows:
        return None
    root_path = _project_root(root)
    state = load_state(root_path)
    chosen = rows[0]
    state["current_id"] = chosen["question"].id
    save_state(state, root_path)
    _append_history({
        "event": "shown",
        "question_id": chosen["question"].id,
        "status": chosen["status"],
    }, root_path)
    return chosen


def _family_summary(root: Path | None = None) -> list[dict[str, Any]]:
    root_path = _project_root(root)
    state = load_state(root_path)
    features = detect_features(root_path)
    observed = _event_signals(features)
    rows = []
    questions = enabled_questions(root_path)
    families: dict[str, list[Question]] = {}
    for q in questions:
        families.setdefault(q.family, []).append(q)
    family_order = ["architecture","authorization","state","invariants","external","input","accounting","oracle","ordering","replay","testing","proof","lifecycle","availability","secrets","crypto","parsing","web","native","data","blockchain"]
    for family in family_order + sorted(set(families) - set(family_order)):
        items = families.get(family)
        if not items:
            continue
        answered = 0
        active = 0
        proof = 0
        for q in items:
            status = _question_state(q, state, features, observed)
            if status in {"ANSWERED","NOT APPLICABLE","SKIPPED"}:
                answered += 1
            elif status == "NEEDS PROOF":
                proof += 1
            if status in {"ANSWERABLE","NEEDS PROOF","CONTRADICTED"}:
                active += 1
        rows.append({
            "family": family,
            "total": len(items),
            "answered": answered,
            "active": active,
            "proof": proof,
        })
    return rows


def _phase_label(phase: str) -> str:
    return {
        "understand":"UNDERSTAND",
        "surface":"SURFACE",
        "trust":"TRUST",
        "state":"STATE",
        "logic":"LOGIC",
        "attack":"ATTACK",
        "prove":"PROVE",
        "lifecycle":"LIFECYCLE",
        "system":"SYSTEM",
    }.get(phase, phase.upper())


def _progress_marker(row: dict[str, Any]) -> str:
    if row["answered"] >= row["total"]:
        return "✓"
    if row["active"] or row["proof"]:
        return "→"
    return "○"


def render_current(root: Path | None = None) -> str:
    chosen = current_question(root)
    if not chosen:
        return "LOWKEY // AUDITOR QUESTIONS\n\nNo applicable questions remain in the current project."
    q: Question = chosen["question"]
    features = detect_features(root)
    observed = _event_signals(features)
    lines = [
        "",
        "LOWKEY // AUDITOR QUESTIONS",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"THREAD   •  {q.family.upper()} / {q.concept.upper()}",
        f"STAGE    •  {_phase_label(q.phase)}",
        "",
        f"QUESTION → {q.text}",
        "",
        "WHAT LOWKEY KNOWS",
    ]
    for item in chosen["evidence"][:6]:
        lines.append(f"  • {item}")
    lines += [
        "",
        "WHY THIS MATTERS",
        f"  {q.why}",
        "",
        "TRY",
    ]
    for command in q.commands[:4]:
        lines.append(f"  {command}")
    if q.proof_questions:
        lines += ["", "NEXT PROOF QUESTIONS"]
        for item in q.proof_questions[:3]:
            child = QUESTION_CATALOG.get(item)
            if child:
                lines.append(f"  → {child.text}")
    if q.children:
        visible_children = [QUESTION_CATALOG[c] for c in q.children if c in QUESTION_CATALOG][:3]
        if visible_children:
            lines += ["", "WHEN THIS IS SETTLED"]
            for child in visible_children:
                lines.append(f"  → {child.text}")
    lines += [
        "",
        "MINDSET",
        "  Establish the rule first. Then find the exact code/state evidence that proves or breaks it.",
        "",
        "CONTROL",
        "  lk q done                 mark this answered",
        "  lk q note \"...\"          save your answer with the question",
        "  lk q skip \"...\"          record why it is not pursued",
        "  lk q why                  explain why Lowkey chose it",
        "  lk q evidence             show supporting evidence",
        "  lk questions              see the frontier map",
    ]
    return "\n".join(lines)


def render_why(root: Path | None = None) -> str:
    chosen = current_question(root)
    if not chosen:
        return "No current auditor question."
    q: Question = chosen["question"]
    reasons = chosen.get("reasons") or []
    lines = [
        "",
        f"WHY THIS QUESTION  •  {q.id}",
        "--------------------------------",
        f"Question: {q.text}",
        f"Score   : {chosen['score']} (deterministic, not a vulnerability score)",
    ]
    if reasons:
        lines.append("")
        lines.append("REASONS")
        for reason in reasons:
            lines.append(f"  • {reason}")
    lines += [
        "",
        "LOWKEY'S RULE",
        "  Evidence changes which question is next; it does not rewrite the underlying question universe.",
    ]
    return "\n".join(lines)


def render_evidence(root: Path | None = None) -> str:
    chosen = current_question(root)
    if not chosen:
        return "No current auditor question."
    q: Question = chosen["question"]
    features = detect_features(root)
    observed = _event_signals(features)
    lines = [
        "",
        f"EVIDENCE FOR {q.id}",
        "--------------------",
    ]
    for item in question_evidence(q, features=features, observed=observed):
        lines.append(f"  • {item}")
    lines += ["", "STATUS", f"  {chosen['status']}"]
    if observed.get("latest_event"):
        event = observed["latest_event"]
        lines.append(f"  latest event: {event.get('tool')} / {event.get('type')}")
    return "\n".join(lines)


def render_path(root: Path | None = None) -> str:
    history = _read_history(root, 25)
    state = load_state(root)
    lines = [
        "",
        "LOWKEY // QUESTION PATH",
        "------------------------",
        "This is the investigation thread Lowkey has observed; it is not a hidden chain of thought.",
    ]
    shown = [item for item in history if item.get("question_id")]
    if not shown:
        lines.append("  No question history yet.")
        return "\n".join(lines)
    for item in shown[-15:]:
        marker = {
            "shown":"→",
            "answered":"✓",
            "not-applicable":"—",
            "skipped":"↷",
        }.get(item.get("event"), "•")
        lines.append(
            f"  {marker} {item.get('question_id')} "
            f"{item.get('status','').upper()} "
            f"{item.get('note','')}".rstrip()
        )
    lines += ["", f"Current: {state.get('current_id') or 'none'}"]
    return "\n".join(lines)


def render_source(qid: str, root: Path | None = None) -> str:
    q = QUESTION_CATALOG.get(str(qid).upper())
    if not q:
        return f"Unknown question id: {qid}"
    lines = ["", f"SOURCES FOR {q.id}", "------------------"]
    if not q.sources:
        lines.append("  No source references recorded for this question.")
        return "\n".join(lines)
    for key in q.sources:
        label, url = SOURCES.get(key, (key, ""))
        lines.append(f"  {label}")
        if url:
            lines.append(f"    {url}")
    return "\n".join(lines)


def answer_current(
    status: str,
    *,
    note: str | None = None,
    root: Path | None = None,
) -> int:
    root_path = _project_root(root)
    chosen = current_question(root_path)
    if not chosen:
        print("No current auditor question.")
        return 0
    q: Question = chosen["question"]
    normalized = status.upper()
    allowed = {"ANSWERED", "NOT_APPLICABLE", "SKIPPED"}
    if normalized not in allowed:
        return 2
    state = load_state(root_path)
    answers = state.setdefault("answers", {})
    answers[q.id] = {
        "status": normalized,
        "note": str(note or "").strip(),
        "answered_at": _now(),
        "evidence_at_answer": question_evidence(q, features=detect_features(root_path), observed=_event_signals(detect_features(root_path))),
    }
    save_state(state, root_path)
    event_name = {
        "ANSWERED":"answered",
        "NOT_APPLICABLE":"not-applicable",
        "SKIPPED":"skipped",
    }[normalized]
    _append_history({
        "event": event_name,
        "question_id": q.id,
        "status": normalized,
        "note": str(note or "").strip(),
    }, root_path)
    audit_context.emit(
        "question-state",
        root_path,
        tool="questions",
        summary=f"{q.id}: {normalized}",
        data={"question_id": q.id, "status": normalized, "note": str(note or "").strip()},
    )
    if normalized == "ANSWERED":
        print(f"Recorded {q.id} as answered.")
    elif normalized == "NOT_APPLICABLE":
        print(f"Recorded {q.id} as not applicable.")
    else:
        print(f"Recorded {q.id} as skipped.")
    print("")
    print(render_current(root_path))
    return 0


def reset(root: Path | None = None) -> int:
    root_path = _project_root(root)
    state = _default_state(root_path)
    save_state(state, root_path)
    _append_history({"event": "reset"}, root_path)
    audit_context.emit("question-reset", root_path, tool="questions", summary="question state reset")
    print("Question learning state reset. Audit evidence was left intact.")
    return 0


def overview(root: Path | None = None, *, show_all: bool = False) -> str:
    root_path = _project_root(root)
    features = detect_features(root_path)
    state = load_state(root_path)
    enabled = enabled_questions(root_path)
    rows = _family_summary(root_path)
    ranked = rank_questions(root_path, limit=3)
    lines = [
        "",
        "LOWKEY // AUDITOR QUESTION FRONTIER",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"PROJECT  •  {root_path.name}",
        f"TYPE     •  {features.get('kind') or 'generic'}",
        f"PACKS    •  core" + (", blockchain" if (features.get("features") or {}).get("blockchain") else "") + (", web" if (features.get("features") or {}).get("web") else "") + (", native" if (features.get("features") or {}).get("native") else "") + (", data" if (features.get("features") or {}).get("data") else ""),
        "",
        "FRONTIER",
    ]
    for row in rows[:12]:
        lines.append(
            f"  { _progress_marker(row) } {row['family']:<16} "
            f"{row['answered']}/{row['total']} settled"
            + (f"  • {row['active']} live" if row["active"] else "")
            + (f"  • {row['proof']} proof" if row["proof"] else "")
        )
    if ranked:
        lines += ["", "NEXT QUESTIONS"]
        for row in ranked[:3]:
            q: Question = row["question"]
            lines.append(f"  → {q.id}  {q.text}")
    lines += [
        "",
        f"QUESTION UNIVERSE  •  {len(enabled)} applicable / {len(QUESTION_CATALOG)} total",
        "The universe stays stable. Evidence changes the frontier.",
        "",
        "NEXT",
        "  lk q                       take the current best question",
        "  lk q why                   see why it was selected",
        "  lk q path                  see the investigation path",
    ]
    if show_all:
        lines += ["", "FULL APPLICABLE CATALOG"]
        for q in sorted(enabled, key=lambda item: (PHASE_ORDER.get(item.phase, 4), item.id)):
            lines.append(f"  {q.id:<12} {q.family:<16} {q.text}")
    return "\n".join(lines)


def run(config: dict[str, Any] | None = None, args: list[str] | None = None, *, root: Path | None = None, mode: str = "current") -> int:
    del config
    root_path = _project_root(root)
    argv = list(args or [])
    if mode == "overview":
        show_all = "--all" in argv or "all" in argv
        print(overview(root_path, show_all=show_all))
        return 0

    action = str(argv[0]).lower() if argv else "current"
    if action in {"current","next"}:
        print(render_current(root_path))
        return 0
    if action == "why":
        print(render_why(root_path))
        return 0
    if action == "evidence":
        print(render_evidence(root_path))
        return 0
    if action == "path":
        print(render_path(root_path))
        return 0
    if action == "reset":
        return reset(root_path)
    if action == "done":
        return answer_current("ANSWERED", root=root_path)
    if action == "note":
        note = " ".join(argv[1:]).strip()
        if not note:
            print('Usage: lk q note "your answer/evidence"')
            return 2
        return answer_current("ANSWERED", note=note, root=root_path)
    if action in {"skip","na","not-applicable","not_applicable"}:
        note = " ".join(argv[1:]).strip()
        return answer_current("NOT_APPLICABLE", note=note or None, root=root_path)
    if action == "source":
        if len(argv) < 2:
            current = current_question(root_path)
            return 0 if not current else print(render_source(current["question"].id, root_path))
        print(render_source(argv[1], root_path))
        return 0
    if action in {"all","catalog"}:
        print(overview(root_path, show_all=True))
        return 0
    return (
        print(
            "Usage: lk q [current|why|evidence|path|done|note|skip|source|reset]"
        ) or 2
    )


__all__ = [
    "QUESTION_CATALOG",
    "PACKS",
    "SOURCES",
    "Question",
    "detect_features",
    "enabled_questions",
    "rank_questions",
    "current_question",
    "overview",
    "render_current",
    "render_why",
    "render_evidence",
    "render_path",
    "render_source",
    "answer_current",
    "run",
]
