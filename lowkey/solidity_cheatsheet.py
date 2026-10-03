#!/usr/bin/env python3
"""Read-only Solidity learning dictionary for LowkeyCast."""
from __future__ import annotations

import difflib
import re


HELP = """
LOWKEY // SOLIDITY CHEATSHEET
==============================

Read-only lookup. No RPC, Anvil, target, config, Forge, or audit state.

Usage:
  lk cheat
  lk cheat <topic>
  lk cheat symbols
  lk cheat keywords
  lk cheat search <word>
  lk compare <topicA> <topicB> [topicC]
  lk connect <conceptA> <conceptB> [conceptC...]
  lk connect --list
  lk expression "<expression>"
  lk practice [topic]
  lk confused <term>
  lk patterns
  lk cheat --help

After opening a topic:
  lk cheat <topic> 1          contract lab
  lk cheat <topic> 2          plain-English walkthrough
  lk cheat <topic> 3          term decoder
  lk cheat <topic> 4          audit lens
  lk cheat <topic> p          practice drill

Examples:
  lk cheat mapping
  lk cheat nested-mapping
  lk cheat arrays-mappings
  lk cheat require
  lk cheat receive
  lk cheat fallback
  lk cheat interface
  lk cheat calls
  lk cheat storage
  lk cheat test
  lk cheat script
  lk cheat poc
  lk cheat forge-cheatcodes-map
  lk cheat symbols
"""

import sys
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from solidity_cheat_topics import register_topics
from solidity_cheat_data import CONTRACT_LABS as _CONTRACT_LABS, TERM_DEFINITIONS as _TERM_DEFINITIONS
from solidity_connect_data import (
    CONNECTION_LABS,
    find_connection,
    list_connections,
    canonicalize,
    expand_name,
    is_known_concept,
    connection_paths,
    find_micro_scene,
    connection_meaning,
    connection_route,
    find_connection_scenes,
    render_connection_pack,
    _FINAL_GRAPH_AUDIT_RESULT,
)

TOPICS = []

# Frozen connection-graph health snapshot used by regression tests and doctoring.
_FINAL_GRAPH_AUDIT_RESULT = _FINAL_GRAPH_AUDIT_RESULT


def add(name, aliases, category, meaning, mental, syntax, example, steps,
        audit="", gotchas="", version="Solidity 0.8.x"):
    TOPICS.append({
        "name": name,
        "aliases": aliases,
        "category": category,
        "meaning": meaning,
        "mental": mental,
        "syntax": syntax,
        "example": example,
        "steps": steps,
        "audit": audit,
        "gotchas": gotchas,
        "version": version,
    })


register_topics(add)

for _topic in TOPICS:
    if _topic["name"] in {
        "loops", "receive", "fallback", "receive-vs-fallback",
        "calls", "calldata", "storage-memory-calldata",
        "msg-block-tx", "msg.value-vs-balance", "ternary", "types",
    }:
        _topic["_learning_ready"] = True



def _render_contract_lab(topic):
    print(f"LOWKEY // CONTRACT LAB • {topic['name']}")
    print("────────────────────────────────────────────────────────────────────────────")
    code = _CONTRACT_LABS.get(topic["name"])
    if code is None:
        raw = topic["example"].strip()
        if re.search(r"^\s*(?:abstract\s+)?(?:contract|interface|library)\b", raw, re.M):
            code = raw
        elif raw.startswith("import "):
            code = raw
        else:
            code = "contract CheatExample {\n"
            code += "    // Educational contract context for: " + topic["name"] + "\n"
            for line in raw.splitlines():
                if line.startswith(("pragma ", "import ")):
                    continue
                code += "    " + line + "\n"
            code += "}"
    print(code)
    print()
    print("LAB NOTES")
    print("---------")
    print("  • Copy this contract into a scratch Foundry project to run it.")
    print("  • The cheat command itself is read-only: it does not create files or start Anvil.")
    print("  • Pair it with one tiny test that proves your prediction.")


def _render_walkthrough(topic):
    print()
    print(f"LOWKEY // WALKTHROUGH • {topic['name']}")
    print("=" * 76)
    print("PLAIN ENGLISH")
    print("------------")
    print(topic["meaning"])
    print()
    print("HOW IT RUNS")
    print("-----------")
    for index, step in enumerate(topic["steps"], 1):
        print(f"  {index}. {step}")
    print()
    print("MENTAL MODEL")
    print("------------")
    print(topic["mental"])
    print()
    print("CONTRACT CONTEXT")
    print("----------------")
    _render_contract_lab(topic)

def _render_term_decoder(topic):
    print()
    print(f"LOWKEY // TERM DECODER • {topic['name']}")
    print("=" * 76)
    blob = " ".join([topic["name"], topic["meaning"], topic["mental"], topic["syntax"], topic["example"]]).lower()
    found = []
    for term, definition in _TERM_DEFINITIONS.items():
        if term.lower() in blob:
            found.append((term, definition))
    if not found:
        found = [("value", _TERM_DEFINITIONS["value"])]
    for term, definition in found[:18]:
        print(f"  {term:<18} {definition}")
    print()
    print("Full glossary: lk cheat terminology")

def _render_audit_lens(topic):
    print()
    print(f"LOWKEY // AUDIT LENS • {topic['name']}")
    print("=" * 76)
    print(topic["audit"] or "No topic-specific audit note yet.")
    print()
    print("QUESTIONS")
    print("---------")
    for question in (
        "Who controls the inputs?",
        "What storage is read or written?",
        "Does execution cross an external call boundary?",
        "Can it repeat, nest, or become unexpectedly expensive?",
        "What happens on failure: revert, false return, empty/default value, or partial effect?",
        "What invariant or authorization rule must remain true?",
    ):
        print("  - " + question)
    if topic["gotchas"]:
        print()
        print("WATCH OUT")
        print("---------")
        print(topic["gotchas"])

def _render_next_views(topic):
    print()
    print("NEXT VIEW")
    print("---------")
    print("  1  Contract Lab     see the concept inside contract-shaped code")
    print("  2  Walkthrough      plain-English execution path")
    print("  3  Term Decoder     translate the jargon used here")
    print("  4  Audit Lens       turn the concept into review questions")
    print("  P  Practice         prediction exercises")
    print()
    print(f"Use: lk cheat {topic['name']} 1   (or 2 / 3 / 4 / p)")

_COMPARISONS = {
    ("for", "while", "do-while"): [
        ("for", "Counted/indexed repetition; initializer, condition, increment in one line.", "for (uint256 i = 0; i < n; i++) { ... }"),
        ("while", "Test before every iteration.", "while (i < n) { i++; }"),
        ("do-while", "Run the body once before testing.", "do { i++; } while (i < n);"),
    ],
    ("require", "revert", "assert"): [
        ("require", "Expected/user-controlled condition guard.", "require(amount > 0);"),
        ("revert", "Explicit abort, often after branching.", "if (bad) revert Bad();"),
        ("assert", "Internal invariant that should never fail.", "assert(total == expected);"),
    ],
    ("msg.value", "address(this).balance"): [
        ("msg.value", "ETH attached to the current message/call.", "msg.value"),
        ("address(this).balance", "ETH currently held by this contract address.", "address(this).balance"),
    ],
    ("calldata", "msg.data"): [
        ("calldata", "Read-only external input data location; also used to mean raw call bytes.", "bytes calldata input"),
        ("msg.data", "Complete calldata bytes of the current call.", "msg.data"),
    ],
    ("receive", "fallback"): [
        ("receive", "Empty-calldata ETH route.", "receive() external payable { ... }"),
        ("fallback", "Unmatched-call route; bytes form can expose raw input.", "fallback(bytes calldata input) external payable { ... }"),
    ],
    ("call", "staticcall", "delegatecall"): [
        ("call", "Normal external message call.", "target.call(data)"),
        ("staticcall", "External call constrained from changing state.", "target.staticcall(data)"),
        ("delegatecall", "Runs target code using caller storage/context.", "target.delegatecall(data)"),
    ],
    ("storage", "memory", "calldata"): [
        ("storage", "Persistent contract data.", "T storage ref"),
        ("memory", "Temporary mutable reference data.", "T memory tmp"),
        ("calldata", "Read-only external input.", "T calldata input"),
    ],
}

def _render_compare(names):
    print()
    print("LOWKEY // COMPARE")
    print("=" * 76)
    normalized = tuple(sorted(_norm(name) for name in names))
    rows = None
    for key, value in _COMPARISONS.items():
        if tuple(sorted(_norm(x) for x in key)) == normalized:
            rows = value
            break
    if rows is None:
        topics = [find_topic(name) for name in names]
        if any(topic is None for topic in topics) or len(topics) < 2:
            print("Usage: lk compare <topicA> <topicB> [topicC]")
            return 2
        rows = [(topic["name"], topic["meaning"], topic["syntax"].splitlines()[0]) for topic in topics]
    width = max(16, max(len(row[0]) for row in rows))
    print(f"{'CONCEPT':<{width}} | WHAT IT ANSWERS | SYNTAX")
    print("-" * (width + 65))
    for name, meaning, syntax in rows:
        print(f"{name:<{width}} | {meaning} | {syntax}")
    print()
    print("READING RULE")
    print("------------")
    print("Compare the question each concept answers, not just the spelling.")
    return 0

def _render_connect(names):
    print()
    print("LOWKEY // CONNECT")
    print("=" * 76)

    if names and _norm(names[0]) in {"--list", "list", "all"}:
        print("CONNECTION LABS")
        print("---------------")
        for lab in list_connections():
            print(f"  {lab['name']}")
            print(f"    concepts: {', '.join(lab['concepts'])}")
            print(f"    {lab['summary']}")
        print()
        print("The normal view is progressive. Full code is explicit.")
        return 0

    if len(names) < 2:
        print("Usage: lk connect <conceptA> <conceptB> [conceptC...]")
        print()
        print("Examples:")
        print("  lk connect interface functions arrays")
        print("  lk connect structs mappings arrays enums bytes addresses")
        print("  lk connect mapping keccak256 abi.decode")
        print("  lk connect yul mapping keccak256")
        print()
        print("Deeper:")
        print("  lk connect interface functions arrays 1")
        print("  lk connect interface functions arrays 2")
        return 2

    mode = "guided"
    cleaned = list(names)
    mode_alias = {
        "1": "full",
        "--full": "full",
        "full": "full",
        "2": "walkthrough",
        "--walkthrough": "walkthrough",
        "walkthrough": "walkthrough",
    }
    if cleaned and _norm(cleaned[-1]) in mode_alias:
        mode = mode_alias[_norm(cleaned.pop())]

    if len(cleaned) < 2:
        print("Usage: lk connect <conceptA> <conceptB> [conceptC...]")
        return 2

    invalid = [raw for raw in cleaned if not is_known_concept(raw)]
    print("REQUESTED CONCEPTS")
    print("------------------")
    requested = []
    seen = set()
    for raw in cleaned:
        for concept in sorted(expand_name(raw)):
            if concept not in seen:
                seen.add(concept)
                requested.append(concept)
                print(f"  {concept}")

    if invalid:
        print()
        print("Unknown Solidity/Yul concept(s): " + ", ".join(invalid))
        print("Use 'lk cheat <topic>' to inspect a concept.")
        return 2

    if len(requested) < 2:
        print()
        print("Usage: lk connect <conceptA> <conceptB> [conceptC...]")
        return 2

    if mode == "full":
        lab = find_connection(requested)
        print()
        print("FULL CONNECTION LAB")
        print("-------------------")
        print(f"  {lab['name']}")
        print()
        if lab.get("support_files"):
            print("FILE: <main contract>")
            print("---------------------")
        print(lab["source"].rstrip())
        for filename, source in lab.get("support_files", {}).items():
            print()
            print(f"FILE: {filename}")
            print("-" * (6 + len(filename)))
            print(source.rstrip())
        print()
        print("VARIABLE MAP")
        print("------------")
        for role, value_type, name, value, purpose in lab.get("variables", []):
            print(
                f"  {role:<18} {value_type:<42} {name:<16} "
                f"{value:<32} {purpose}"
            )
        print()
        print("This is intentionally exhaustive. The default connect view is not.")
        return 0

    route = connection_route(requested)
    scenes = find_connection_scenes(requested, max_scenes=4)

    # Keep the familiar single-scene view for focused requests. When several
    # independent concepts are requested, show a small set of actual code
    # bridges so every requested concept appears in something executable.
    if mode != "full" and len(scenes) > 1:
        render_connection_pack(
            requested,
            scenes,
            walkthrough=(mode == "walkthrough"),
        )
        return 0

    scene = scenes[0] if scenes else find_micro_scene(requested)

    print()
    print("CONNECTION ROUTE")
    print("----------------")
    print("  " + " → ".join(route))

    print()
    print("THE CONNECTION")
    print("--------------")
    route_name = scene.get("route_name")
    if route_name:
        print(f"  PATH: {route_name}")
        print()
    print(scene["title"])
    print()
    print(scene["story"])

    print()
    print("1. WHAT EACH PIECE IS")
    print("----------------------")
    for concept in requested:
        print(f"  {concept}: {connection_meaning(concept)}")

    print()
    print("2. TINY CONNECTED EXAMPLE")
    print("--------------------------")
    print(scene["code"].rstrip())

    print()
    print("3. VARIABLES IN THIS EXAMPLE")
    print("-----------------------------")
    variables = scene.get("variables", [])
    if variables:
        for role, value_type, name, value, purpose in variables:
            print(
                f"  {role:<22} {value_type:<26} "
                f"{name:<18} = {value:<24} {purpose}"
            )
    else:
        print("  See the code and route above; this connection is intentionally kept compact.")

    print()
    print("4. FOLLOW THE VALUE")
    print("-------------------")
    for index, step in enumerate(scene.get("flow", []), 1):
        print(f"  {index}. {step}")

    print()
    print("5. TRY THIS CALL")
    print("----------------")
    print(f"  {scene.get('call', 'Trace the example by hand first.')}")

    if mode == "walkthrough":
        print()
        print("WALKTHROUGH")
        print("------------")
        for index, step in enumerate(scene.get("flow", []), 1):
            print(f"  {index}. {step}")

    print()
    print("NEXT")
    print("----")
    print("  1  full contract lab")
    print("  2  slower walkthrough")
    print("  lk cheat <concept>")
    return 0

def _render_expression(expr):
    expression = expr.strip()
    print()
    print("LOWKEY // EXPRESSION READER")
    print("=" * 76)
    print("INPUT")
    print("-----")
    print(expression)
    print()
    print("TOKENS / HOW TO READ")
    print("--------------------")
    match = re.match(r"^(.*)\\[(.*)\\](\\s*\\+=\\s*)(.*)$", expression)
    if match:
        print(f"  BASE          {match.group(1)}")
        print(f"  KEY / INDEX   {match.group(2)}  -> choose one mapping key/index")
        print(f"  OPERATOR      {match.group(3).strip()}  -> calculate, then store back")
        print(f"  RIGHT SIDE    {match.group(4)}  -> value being added")
        return 0
    match = re.match(r"^(.*)\\{value\\s*:\\s*(.*)\\}\\((.*)\\)$", expression)
    if match:
        print(f"  TARGET        {match.group(1)}")
        print(f"  CALL OPTION   value: {match.group(2)} -> send ETH with the call")
        print(f"  ARGUMENTS     {match.group(3)} -> actual values supplied to parameters")
        return 0
    print("  No special pattern matched; read left-to-right:")
    print("  1. Find the base variable/function.")
    print("  2. Read [] as lookup/index, . as member access, () as a call.")
    print("  3. Read operators as transformations between values.")
    print("  4. Trace msg.sender/msg.value to the current call context.")
    return 0

_TOPICS_PRACTICE_TEXT = """PREDICT FIRST
-------------
1. Missing mapping key -> what default?
2. do-while -> how many times can the body execute?
3. Which four bytes identify a normal function?
4. msg.value vs address(this).balance -> same or different?
5. storage vs memory -> which one persists?"""

def _render_practice(topic_name):
    print()
    print("LOWKEY // PRACTICE")
    print("=" * 76)
    topic = find_topic(topic_name) if topic_name else None
    if topic and topic["name"] != "practice":
        print(f"TOPIC • {topic['name']}")
        print("-" * (8 + len(topic["name"])))
        print("PREDICT BEFORE EXECUTING")
        print("------------------------")
        print(topic["syntax"])
        print()
        print("Questions:")
        print("  1. What value is read?")
        print("  2. What value is written?")
        print("  3. What are msg.sender/msg.value?")
        print("  4. Could this revert or return a default?")
        print("  5. What changes with a different caller/argument?")
    else:
        print(_TOPICS_PRACTICE_TEXT)
    return 0

_TOPICS_CONFUSION = """KEY CONFUSIONS
--------------
parameter / argument
calldata / msg.data
msg.value / address(this).balance
receive / fallback
for / while / do-while
require / revert / assert
call / staticcall / delegatecall
storage / memory / calldata"""

def _render_confused(term):
    print()
    print("LOWKEY // COMMONLY CONFUSED")
    print("=" * 76)
    topic = find_topic(term) if term else None
    q = _norm(term)
    if topic and topic["name"] != "confused":
        for key, rows in _COMPARISONS.items():
            if any(_norm(x) == q for x in key):
                print(f"Related concepts for: {topic['name']}")
                print()
                for name, meaning, syntax in rows:
                    print(f"  {name:<22} {meaning}")
                return 0
    print(_TOPICS_CONFUSION)
    return 0

_ALIAS = {}
for _topic in TOPICS:
    _ALIAS[_topic["name"].lower()] = _topic
    for _alias in _topic["aliases"]:
        _ALIAS[_alias.lower()] = _topic


def _norm(value: str) -> str:
    return "-".join(
        value.strip().lower().replace("_", "-").split()
    )


def find_topic(query: str):
    key = _norm(query)
    return _ALIAS.get(key)


def search(query: str):
    key = _norm(query)
    ranked = []
    for topic in TOPICS:
        hay = " ".join(
            [topic["name"]] + topic["aliases"] + [topic["meaning"]]
        ).lower()
        score = difflib.SequenceMatcher(
            None, key, _norm(topic["name"])
        ).ratio()
        if key and key in _norm(hay):
            score = max(score, 0.9)
        if score >= 0.4:
            ranked.append((score, topic))
    ranked.sort(key=lambda item: (-item[0], item[1]["name"]))
    return [topic for _, topic in ranked[:20]]


def render_index():
    print("LOWKEY // SOLIDITY CHEATSHEET")
    print("==============================")
    print("READ-ONLY • no RPC • no Anvil • no target • no project/audit state")
    print()
    current = None
    for topic in TOPICS:
        if topic["category"] != current:
            current = topic["category"]
            print(current)
            print("-" * len(current))
        print(f"  {topic['name']:<28} {topic['meaning']}")
    print()
    print("Use:")
    print("  lk cheat <topic>            syntax-first topic")
    print("  lk cheat <topic> 1          contract lab")
    print("  lk cheat <topic> 2          walkthrough")
    print("  lk cheat <topic> 3          term decoder")
    print("  lk cheat <topic> 4          audit lens")
    print("  lk compare <topic...>       compare concepts")
    print('  lk expression "<expr>"      explain one expression')
    print("  lk practice [topic]         prediction drill")
    print("  lk confused <term>          common confusions")
    print("  lk patterns                 recurring Solidity patterns")
    print("  lk cheat search <word>      topic search")
    print("  lk cheat --help             cheatsheet help")


def render_topic(topic):
    print()
    print(f"LOWKEY // CHEAT • {topic['name'].upper()}")
    print("=" * 76)

    print()
    print(topic["name"].upper())
    print("─" * len(topic["name"]))

    print()
    print("SYNTAX")
    print("──────")
    print(topic["syntax"])

    print()
    print("VERSION")
    print("───────")
    print(topic.get("version", "Solidity 0.8.x"))

    print()
    print("CONTRACT USE")
    print("────────────")
    _render_contract_lab(topic)

    print()
    print("MENTAL MODEL")
    print("────────────")
    print(topic["mental"])

    print()
    print("REAL EXAMPLE")
    print("────────────")
    print(topic["example"])

    print()
    print("STEP BY STEP")
    print("────────────")
    for index, step in enumerate(topic["steps"], 1):
        print(f"  {index}. {step}")

    if topic["audit"]:
        print()
        print("AUDIT LOOKOUT")
        print("─────────────")
        print(topic["audit"])
    if topic["gotchas"]:
        print()
        print("WATCH OUT")
        print("─────────")
        print(topic["gotchas"])

    related = [
        item["name"]
        for item in TOPICS
        if item["name"] != topic["name"] and item["category"] == topic["category"]
    ]
    if related:
        print()
        print("RELATED")
        print("───────")
        print("  " + ", ".join(related[:10]))

    print()
    print("Educational lookup. Verify exact details against your compiler/version.")
    _render_next_views(topic)


def run(args=None):
    args = list(args or [])
    if not args:
        render_index()
        return 0

    command = args[0].lower()

    if command in {"--help", "--h", "-h", "help"}:
        print(HELP.strip())
        return 0
    if command in {"list", "all"}:
        render_index()
        return 0
    if command == "search":
        query = " ".join(args[1:]).strip()
        if not query:
            print("Usage: lk cheat search <word or phrase>")
            return 2
        rows = search(query)
        print(f"CHEATSHEET SEARCH • {query}")
        print("===========================")
        if not rows:
            print("No matching topics.")
            return 0
        for index, topic in enumerate(rows, 1):
            print(f"  {index:>2}. {topic['name']:<28} {topic['meaning']}")
        print()
        print("Open one with: lk cheat <topic>")
        return 0
    if command == "compare":
        names = args[1:]
        if len(names) < 2:
            print("Usage: lk compare <topicA> <topicB> [topicC]")
            return 2
        return _render_compare(names)
    if command == "connect":
        return _render_connect(args[1:])
    if command == "expression":
        expression = " ".join(args[1:]).strip()
        if not expression:
            print('Usage: lk expression "<expression>"')
            return 2
        return _render_expression(expression)
    if command == "practice":
        return _render_practice(" ".join(args[1:]).strip())
    if command == "confused":
        return _render_confused(" ".join(args[1:]).strip())
    if command == "patterns":
        topic = find_topic("patterns")
        render_topic(topic)
        return 0

    mode = None
    query_args = list(args)
    if len(query_args) > 1:
        mode = {
            "1": "contract",
            "2": "walkthrough",
            "3": "terms",
            "4": "audit",
            "p": "practice",
            "--contract": "contract",
            "--walkthrough": "walkthrough",
            "--terms": "terms",
            "--audit": "audit",
            "--practice": "practice",
        }.get(query_args[-1].lower())
        if mode:
            query_args = query_args[:-1]

    topic = find_topic(" ".join(query_args).strip())
    if topic:
        if mode == "contract":
            _render_contract_lab(topic)
        elif mode == "walkthrough":
            _render_walkthrough(topic)
        elif mode == "terms":
            _render_term_decoder(topic)
        elif mode == "audit":
            _render_audit_lens(topic)
        elif mode == "practice":
            _render_practice(topic["name"])
        else:
            render_topic(topic)
        return 0

    query = " ".join(query_args).strip()
    print(f"No Solidity cheat topic matched: {query}")
    rows = search(query)
    if rows:
        print("Did you mean:")
        for topic in rows[:5]:
            print(f"  - {topic['name']}")
    else:
        print("Try: lk cheat search <word>")
    return 2


if __name__ == "__main__":
    raise SystemExit(run())
