#!/usr/bin/env python3
"""Evidence-first offensive-security workflows for Lowkey.

Static signals are leads. Executed attacks, sequential controls, economic
measurements and reproofs are separate evidence stages.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

VERSION = "0.2.0"
EXTS = {".sol", ".vy", ".yul", ".huff", ".rs", ".move", ".cairo"}
SKIP = {".git", ".audit", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "out", "cache", "artifacts", "build", "dist", "target", "vendor", "coverage"}
EIP1967 = {
    "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}
CAPABILITIES = [
(1,"cheat-fingerprint","Fingerprint dangerous source sequences","partial"),
(2,"control","Sequential control gate","implemented"),
(3,"mutation-score","Harness mutation score","implemented"),
(4,"target-coverage","Coverage restricted to target lines","implemented"),
(5,"provenance","Artifact hash and run provenance","partial"),
(6,"sandbox","Isolated untrusted build/test execution","partial"),
(7,"decompile","Unverified bytecode decompilation","adapter-required"),
(8,"storage-infer","Probabilistic storage-layout inference","partial"),
(9,"proxy-resolve","Generic proxy and implementation resolution","partial"),
(10,"selectors-full","Runtime selector extraction and resolution","partial"),
(11,"cfg","Control-flow outline","partial"),
(12,"reentrancy-graph","Storage read/call/write graph","partial"),
(13,"fallback-map","Fallback and callback map","implemented"),
(14,"calldata-mine","Historical calldata corpus","partial"),
(15,"attack-forge","Executable attack-library harness starter","partial"),
(16,"invariant-forge","Invariant candidate generator","partial"),
(17,"archetype","Protocol-shaped attack suites","partial"),
(18,"token-weird","Adversarial token fixtures","partial"),
(19,"oracle-map","Oracle dependency and skew map","partial"),
(20,"flashmax","Flash-loan venue integration","adapter-required"),
(21,"time","Timestamp/block-boundary campaign","partial"),
(22,"sig-matrix","Signature replay matrix","partial"),
(23,"init-frontrun","Initializer exposure analysis","partial"),
(24,"path","Symbolic path enumeration","adapter-required"),
(25,"compose","Cross-contract attack-chain planner","partial"),
(26,"fidelity","Evidence fidelity ledger","implemented"),
(27,"reprove","Cheatcode-free local-fork reproof","partial"),
(28,"economic","Net-profit calculation","implemented"),
(29,"gas-ladder","Measured gas/DoS threshold search","partial"),
(30,"state-diff","Predicted/observed storage diff","partial"),
(31,"watch","Deployment/code-change watcher","partial"),
(32,"godmode","End-to-end audit orchestrator","partial"),
(33,"custody","Asset custody and authority map","partial"),
(34,"questions","Question-driven audit loop","implemented"),
(35,"agent-split","Planner/attacker/verifier/critic roles","partial"),
(36,"verify-hack","Historical exploit replay","adapter-required"),
(37,"unravel","Transaction call-tree decoder","partial"),
(38,"bundle","Private bundle simulation","adapter-required"),
(39,"sandwich","Sandwich/JIT ordering simulation","adapter-required"),
(40,"fork-cache","Local Anvil snapshot cache","partial"),
(41,"upgrade-diff","Implementation upgrade diff","partial"),
(42,"cross-vm","Cross-VM static/native detector routing","partial"),
(43,"learn","Evidence-backed experience learning","implemented"),
(44,"report","Reproducible audit report","implemented"),
]
FALLBACK = {
"receive":r"\breceive\s*\(\s*\)\s*external",
"fallback":r"\bfallback\s*(?:\([^)]*\))?\s*external",
"erc721_receiver":r"\bonERC721Received\s*\(",
"erc1155_single":r"\bonERC1155Received\s*\(",
"erc1155_batch":r"\bonERC1155BatchReceived\s*\(",
"erc777_hook":r"\bonTokensReceived\s*\(",
"erc1363_hook":r"\bonTransferReceived\s*\(",
"erc1363_approval_hook":r"\bonApprovalReceived\s*\(",
"callback":r"\b(?:callback|executeOperation|uniswapV3FlashCallback|receiveFlashLoan)\s*\(",
"try_catch":r"\btry\b|\bcatch\b",
"low_level_call":r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()",
}
PATTERNS = {
"oracle":r"\b(?:latestRoundData|latestAnswer|getReserves|slot0|observe|consult|exchangeRate|virtualPrice|sharePrice)\s*\(",
"freshness":r"\b(?:updatedAt|answeredInRound|heartbeat|stale|staleness)\b",
"signature":r"\b(?:ecrecover|ECDSA\.recover|tryRecover|SignatureChecker|permit)\s*\(",
"nonce_domain":r"\b(?:nonces?|DOMAIN_SEPARATOR|domainSeparator|EIP712|chainId)\b",
"initializer":r"\b(?:initializer|reinitializer|initialize[A-Z_a-z0-9]*|_disableInitializers)\b",
"custody":r"\b(?:onlyOwner|owner\s*\(|onlyRole|grantRole|revokeRole|guardian|Timelock|upgradeTo|_authorizeUpgrade|pause|unpause)\b",
"cross_vm":r"\b(?:Signer<|is_signer|find_program_address|create_program_address|AccountInfo|TreasuryCap|AdminCap|get_caller_address|require_auth)\b",
"external_call":r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()|\.transfer\s*\(|\.send\s*\(|safeTransfer(?:From)?\s*\(",
}
def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
def root_path(value="."):
    p=Path(value).expanduser().resolve()
    if not p.is_dir(): raise ValueError(f"project root does not exist: {p}")
    return p
def safe_out(root,path):
    p=(root/path).resolve()
    if not p.is_relative_to(root): raise ValueError("output path must stay inside project")
    p.parent.mkdir(parents=True,exist_ok=True)
    return p
def write_json(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix(path.suffix+".tmp")
    temp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    os.replace(temp,path)
    return path
def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()
def files(root,include_tests=False):
    out=[]
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXTS: continue
        rel=p.relative_to(root); parts=set(rel.parts[:-1])
        if parts & SKIP or (not include_tests and parts & {"test","tests","script","scripts","fixtures","mocks"}): continue
        try:
            if p.stat().st_size <= 2_000_000: out.append(p)
        except OSError: pass
    return sorted(out)
def patterns(root,table,include_tests=False):
    compiled={k:re.compile(v,re.I) for k,v in table.items()}
    rows=[]
    for path in files(root,include_tests):
        try: lines=path.read_text(encoding="utf-8",errors="replace").splitlines()
        except OSError: continue
        for n,line in enumerate(lines,1):
            for key,rx in compiled.items():
                if rx.search(line):
                    rows.append({"kind":key,"file":path.relative_to(root).as_posix(),"line":n,"text":line.strip()[:400]})
    return rows
def funcs(text):
    rx=re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^;{}]*\)[^{;]*\{")
    for m in rx.finditer(text):
        depth=1; i=m.end()
        while i<len(text) and depth:
            if text[i]=="{": depth+=1
            elif text[i]=="}": depth-=1
            i+=1
        if depth==0: yield {"name":m.group(1),"start":m.start(),"body":text[m.end():i-1]}
def reentrancy_graph(root):
    out=[]
    calls=re.compile(r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()|\.transfer\s*\(|\.send\s*\(|safeTransfer(?:From)?\s*\(")
    reads=re.compile(r"\b([A-Za-z_$][\w$]*)\s*\[[^\]]+\]")
    writes=re.compile(r"\b([A-Za-z_$][\w$]*)\s*(?:\[[^\]]+\])?\s*(?:\+\+|--|[+\-*/]?=)")
    for p in files(root):
        text=p.read_text(encoding="utf-8",errors="replace")
        for f in funcs(text):
            r= list(reads.finditer(f["body"])); w=list(writes.finditer(f["body"]))
            for call in calls.finditer(f["body"]):
                before={m.group(1) for m in r if m.start()<call.start()}
                after={m.group(1) for m in w if m.start()>call.start()}
                shared=sorted(before&after)
                if shared:
                    out.append({"file":p.relative_to(root).as_posix(),"function":f["name"],"variables":shared,
                                "call_offset":call.start(),"confidence":"heuristic",
                                "excerpt":f["body"][max(0,call.start()-80):call.end()+100].strip()[:280]})
    return out
def source_maps(root):
    return {
      "fallback_map":patterns(root,{**FALLBACK,"generic_hook":r"\bon[A-Z][A-Za-z0-9_]*\s*\("},True),
      "oracle_map":patterns(root,{
          "chainlink_aggregator":r"\b(?:latestRoundData|latestAnswer|getRoundData)\s*\(",
          "uniswap_v2_spot":r"\bgetReserves\s*\(",
          "uniswap_v3_spot":r"\bslot0\s*\(",
          "twap_observation":r"\b(?:observe|consult)\s*\(",
          "generic_price_or_rate":r"\b(?:price|oracle|exchangeRate|virtualPrice|sharePrice)\b",
          "freshness_guard":r"\b(?:updatedAt|answeredInRound|heartbeat|stale|staleness)\b"}),
      "time_map":patterns(root,{"timestamp":r"\bblock\.timestamp\b","block_number":r"\bblock\.number\b",
          "blockhash":r"\bblockhash\s*\(","prevrandao":r"\bblock\.prevrandao\b",
          "deadline":r"\b(?:deadline|expiry|expiration)\b","lock_window":r"\b(?:unlock|lockUntil|epoch|vesting)\b"}),
      "storage_map":patterns(root,{"mapping_declaration":r"\bmapping\s*\(","dynamic_array":r"\b[A-Za-z_$][\w$]*\s*\[\s*\]\s+(?:public|private|internal|external)?",
          "storage_assembly":r"\b(?:sload|sstore)\s*\(","hash_derived_slot":r"\b(?:keccak256|keccak)\s*\("}),
      "token_map":patterns(root,{"erc20_transfer":r"\b(?:transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\(",
          "unchecked_balance":r"\bbalanceOf\s*\(","decimals_assumption":r"\bdecimals\s*\(",
          "permit":r"\bpermit\s*\(","approval":r"\b(?:approve|allowance)\s*\("}),
      "signature_map":patterns(root,{"signature":PATTERNS["signature"],"nonce_domain":PATTERNS["nonce_domain"]}),
      "initializer_map":patterns(root,{"initializer":r"\binitializer\b","reinitializer":r"\breinitializer\s*\(",
          "initialize_function":r"\bfunction\s+initialize[A-Za-z0-9_]*\s*\(","disable_initializers":r"\b_disableInitializers\s*\("}),
      "custody_map":patterns(root,{"owner":r"\b(?:onlyOwner|owner\s*\(|transferOwnership|renounceOwnership)\b",
          "access_control":r"\b(?:AccessControl|onlyRole|grantRole|revokeRole|hasRole)\b","guardian":r"\bguardian\b",
          "pause":r"\b(?:pause|unpause|whenNotPaused|Pausable)\b","timelock":r"\b(?:Timelock|timelock|schedule|execute)\b",
          "upgrade":r"\b(?:upgradeTo|upgradeToAndCall|_authorizeUpgrade|ProxyAdmin|beacon)\b"}),
      "cross_vm_map":patterns(root,{"solana_signer":r"\bSigner\s*<|\bis_signer\b","solana_pda":r"\bseeds\s*=|find_program_address|create_program_address",
          "solana_account":r"\bAccountInfo\b|\bowner\s*==\s*\*?program_id",
          "move_capability":r"\b(?:has key|acquires|TreasuryCap|AdminCap|public entry|friend)\b",
          "cairo_caller":r"\b(?:get_caller_address|caller_address|external\s*\()",
          "soroban_auth":r"\b(?:require_auth|require_auth_for_args|\.auth\s*\()"}),
      "reentrancy_graph":reentrancy_graph(root),
      "cfg_outline":[{"file":p.relative_to(root).as_posix(),"function":f["name"],
          "nodes":[{"kind":"entry","offset":0}]+[
            {"kind":"external_call" if m.group(0).find("call")>=0 else "state_write","offset":m.start(),"text":m.group(0)[:90]}
            for m in sorted(list(re.finditer(PATTERNS["external_call"],f["body"],re.I))+list(re.finditer(r"\b[A-Za-z_$][\w$]*\s*(?:\[[^\]]+\])?\s*(?:\+\+|--|[+\-*/]?=)",f["body"])),key=lambda x:x.start())
          ]+[{"kind":"exit","offset":len(f["body"])}]}
          for p in files(root) for f in funcs(p.read_text(encoding="utf-8",errors="replace"))
          if re.search(PATTERNS["external_call"],f["body"],re.I)]
    }
class AhoCorasick:
    def __init__(self,patterns):
        self.next=[{}]; self.fail=[0]; self.out=[[]]
        for label,tokens in patterns:
            state=0
            for token in tokens:
                if token not in self.next[state]:
                    self.next[state][token]=len(self.next); self.next.append({}); self.fail.append(0); self.out.append([])
                state=self.next[state][token]
            self.out[state].append((label,len(tokens)))
        q=list(self.next[0].values()); pos=0
        while pos<len(q):
            state=q[pos]; pos+=1
            for token,nxt in self.next[state].items():
                q.append(nxt); failure=self.fail[state]
                while failure and token not in self.next[failure]: failure=self.fail[failure]
                self.fail[nxt]=self.next[failure].get(token,0)
                self.out[nxt].extend(self.out[self.fail[nxt]])
    def scan(self,tokens):
        state=0; hits=[]
        for i,token in enumerate(tokens):
            while state and token not in self.next[state]: state=self.fail[state]
            state=self.next[state].get(token,0)
            hits.extend((i-size+1,label,size) for label,size in self.out[state])
        return hits
def cheat_fingerprints(root):
    try:
        try: from .solidity_cheat_topics import register_topics
        except ImportError: from solidity_cheat_topics import register_topics
        entries=[]
        def collect(*args,**kwargs):
            label=str(args[0]) if args else "cheat-topic"
            for item in args[1:]:
                if not isinstance(item,str): continue
                for line in item.splitlines():
                    if not re.search(r"(?:mapping|call|delegatecall|keccak|sload|sstore|fallback|receive|signature|nonce|vm\.)",line,re.I): continue
                    toks=tuple(re.findall(r"[A-Za-z_$][\w$]*|0x[0-9a-fA-F]+|\d+|==|!=|<=|>=|=>|&&|\|\||[^\s]",line))
                    if 3<=len(toks)<=30: entries.append((label,toks))
        register_topics(collect)
    except Exception: entries=[]
    unique={}
    for label,toks in entries: unique.setdefault(toks,label)
    if not unique: unique={("delegatecall",):"delegatecall",("mapping",):"mapping",("sstore",):"storage-write",("call",):"external-call"}
    ac=AhoCorasick([(v,k) for k,v in unique.items()])
    result=[]
    for p in files(root):
        text=p.read_text(encoding="utf-8",errors="replace")
        matches=list(re.finditer(r"[A-Za-z_$][\w$]*|0x[0-9a-fA-F]+|\d+|==|!=|<=|>=|=>|&&|\|\||[^\s]",text))
        tokens=[m.group(0) for m in matches]
        for idx,label,size in ac.scan(tokens):
            line=text.count("\n",0,matches[idx].start())+1
            result.append({"topic":label,"file":p.relative_to(root).as_posix(),"line":line,
                           "fingerprint":hashlib.sha256(" ".join(tokens[idx:idx+size]).encode()).hexdigest()[:16]})
    return {"patterns":len(unique),"hits":result,"meaning":"Fingerprint matches are leads, never vulnerability verdicts."}
def rpc_url(v=None):
    url=v or os.environ.get("FOUNDRY_ETH_RPC_URL") or os.environ.get("ETH_RPC_URL") or os.environ.get("LOWKEY_RPC_URL")
    if not url or urlparse(url).scheme not in {"http","https"}: raise ValueError("Pass --rpc-url or set FOUNDRY_ETH_RPC_URL/ETH_RPC_URL.")
    return url
def rpc(url,method,params,timeout=20):
    data=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req=Request(url,data=data,headers={"Content-Type":"application/json"})
    with urlopen(req,timeout=timeout) as res: body=json.loads(res.read().decode())
    if body.get("error"): raise RuntimeError(f"{method}: {body['error']}")
    return body.get("result")
def addr(v):
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}",v or ""): raise ValueError("Expected a 20-byte 0x-prefixed address.")
    return v.lower()
def local_rpc(url):
    return (urlparse(url).hostname or "").lower() in {"127.0.0.1","localhost","::1"}
def push4(code):
    raw=bytes.fromhex(code[2:] if code.startswith("0x") else code)
    found=set(); i=0
    while i<len(raw):
        op=raw[i]
        if op==0x63 and i+4<len(raw): found.add("0x"+raw[i+1:i+5].hex()); i+=5
        elif 0x60<=op<=0x7f: i+=1+op-0x5f
        else: i+=1
    return sorted(found)
def proxy(target,url,slots=120):
    target=addr(target); slots=max(0,min(int(slots),120))
    queries=[("eth_getStorageAt",[target,s,"latest"]) for s in EIP1967.values()]
    queries += [("eth_getStorageAt",[target,hex(i),"latest"]) for i in range(slots)]
    values=[rpc(url,m,p) for m,p in queries]
    rows=[]
    for i,(name,slot) in enumerate(EIP1967.items()):
        value=str(values[i] or "0x"+"0"*64); a="0x"+value[-40:]
        if int(a,16): rows.append({"kind":name,"slot":slot,"address":a})
    for i,value in enumerate(values[len(EIP1967):]):
        if value and int(value,16):
            a="0x"+value[-40:]
            if int(a,16): rows.append({"kind":"code-address-candidate","slot":hex(i),"address":a})
    out=[]
    for row in rows:
        code=rpc(url,"eth_getCode",[row["address"],"latest"])
        has=bool(code and code!="0x")
        out.append({**row,"has_code":has,"confidence":"high" if has and row["kind"] in EIP1967 else "medium" if has else "low"})
    return {"target":target,"candidates":out,"warning":"Candidate slots only; confirm the actual proxy standard and upgrade semantics."}
def selectors(target,url):
    target=addr(target); code=rpc(url,"eth_getCode",[target,"latest"]); values=push4(code or "0x")
    rows=[]
    for s in values:
        names=[]
        if shutil.which("cast"):
            try:
                p=subprocess.run(["cast","4byte",s],capture_output=True,text=True,timeout=5)
                if p.returncode==0: names=[x.strip() for x in p.stdout.splitlines() if x.strip()]
            except (OSError,subprocess.TimeoutExpired): pass
        rows.append({"selector":s,"signatures":names,"status":"resolved" if names else "unresolved"})
    return {"target":target,"selectors":rows,"count":len(rows),"warning":"PUSH4 constants can be mistaken for selectors; unresolved values remain unresolved."}
def run(argv,cwd,timeout=300,env=None):
    if not argv or not all(isinstance(x,str) for x in argv): raise ValueError("Supply a non-empty argv array.")
    return subprocess.run(argv,cwd=str(cwd),capture_output=True,text=True,timeout=max(1,min(timeout,3600)),shell=False,env=env)
def analyze_harness_fidelity(source_text, path="<memory>"):
    """Static fidelity inventory for a generated test harness; never a proof verdict."""
    source_text=str(source_text or "")
    patterns={
        "synthetic_eth":r"\bvm\.deal\s*\(",
        "synthetic_token_balance":r"(?<![\w.])deal\s*\(",
        "caller_impersonation":r"\bvm\.(?:prank|startPrank|hoax)\s*\(",
        "storage_override":r"\bvm\.(?:store|load)\s*\(",
        "code_injection":r"\bvm\.etch\s*\(",
        "external_call_mock":r"\bvm\.(?:mockCall|mockCallRevert|mockFunction|expectCall)\s*\(",
        "time_or_block_override":r"\bvm\.(?:warp|roll|setBlockhash)\s*\(",
        "test_assumption":r"\bvm\.(?:assume|bound)\s*\(",
    }
    signals=[]
    for kind,pattern in patterns.items():
        rx=re.compile(pattern)
        for match in rx.finditer(source_text):
            line=source_text.count("\n",0,match.start())+1
            signals.append({"kind":kind,"line":line,"token":match.group(0)})
    pinned=bool(re.search(r"\bvm\.(?:createSelectFork|createFork)\s*\([^;]*,\s*(?:0x[0-9a-fA-F]+|[0-9]+)",source_text))
    gas_measured=bool(re.search(r"\bgasleft\s*\(|snapshotGas|startSnapshotGas",source_text,re.I))
    synthetic_kinds={x["kind"] for x in signals}
    synthetic_state=bool(synthetic_kinds & {"synthetic_eth","synthetic_token_balance","storage_override","code_injection","external_call_mock","time_or_block_override"})
    gaps=[]
    labels={
        "synthetic_eth":"Foundry ETH balances are synthetically assigned",
        "synthetic_token_balance":"Token balances are synthetically assigned",
        "caller_impersonation":"Caller identity is impersonated with a test cheatcode",
        "storage_override":"Storage is directly overridden with a test cheatcode",
        "code_injection":"Runtime code is injected with a test cheatcode",
        "external_call_mock":"External dependency behavior is mocked",
        "time_or_block_override":"Timestamp or block number is overridden",
        "test_assumption":"Fuzzer inputs are constrained with assumptions",
    }
    for kind in sorted(synthetic_kinds):
        gaps.append(labels.get(kind,kind))
    if not pinned: gaps.append("No explicit block-pinned fork creation was detected")
    if not gas_measured: gaps.append("Transaction gas cost is not measured by this harness")
    gaps.append("Net profit and financing costs are not independently verified by a test harness scan")
    hard_blocked={"synthetic_eth","synthetic_token_balance","caller_impersonation","storage_override","code_injection","external_call_mock","time_or_block_override"}
    observed_kinds=sorted(synthetic_kinds)
    fork_blockers=sorted(hard_blocked & synthetic_kinds)
    policy={
        "SIMULATED_BREAK":{"allowed":"All detected test cheatcodes are permitted only as disclosed simulation inputs; never label as realistic."},
        "FORK_REPRODUCED":{"allowed":["test_assumption"],"blocked":sorted(hard_blocked)},
        "REALISTIC":{"allowed":[],"blocked":sorted(hard_blocked | {"test_assumption"})},
        "PROFITABLE":{"requirements":["FORK_REPRODUCED","measured recipient/attacker balance deltas","actual receipt gasUsed and effectiveGasPrice","net profit greater than zero"]},
        "HUMAN_CONFIRMED":{"requirements":["PROFITABLE or documented non-profit impact","native evidence reviewed","explicit human disposition in evidence ledger"]},
    }
    return {
        "schema_version":1,
        "path":str(path),
        "source_sha256":hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        "signals":signals,
        "synthetic_eth":"synthetic_eth" in synthetic_kinds,
        "synthetic_token_balance":"synthetic_token_balance" in synthetic_kinds,
        "caller_impersonation":"caller_impersonation" in synthetic_kinds,
        "storage_override":"storage_override" in synthetic_kinds,
        "code_injection":"code_injection" in synthetic_kinds,
        "external_call_mock":"external_call_mock" in synthetic_kinds,
        "time_or_block_override":"time_or_block_override" in synthetic_kinds,
        "fork_block_pinned":pinned,
        "gas_measured":gas_measured,
        "transaction_gas_verified":False,
        "net_profit_verified":False,
        "synthetic_state":synthetic_state,
        "classification":"SIMULATED" if synthetic_state or not pinned else "FORK_REPRODUCTION_CANDIDATE",
        "confirmation_eligible":False,
        "promotion_policy":policy,
        "fork_reproduction_blockers":fork_blockers,
        "allowed_cheatcodes_for_fork_reproduction":policy["FORK_REPRODUCED"]["allowed"],
        "observed_cheatcodes":observed_kinds,
        "proof_gaps":gaps,
        "policy":"Static harness inspection only. This record does not prove exploitability, authorization, gas realism, or profitability.",
    }


def _trace_flatten(trace, limit=512):
    rows=[]
    def walk(node,depth=0):
        if not isinstance(node,dict) or len(rows)>=limit: return
        rows.append({
            "depth":depth,
            "type":str(node.get("type") or ""),
            "from":str(node.get("from") or "").lower(),
            "to":str(node.get("to") or "").lower(),
            "input":str(node.get("input") or "").lower(),
            "value":str(node.get("value") or "0x0").lower(),
            "error":str(node.get("error") or ""),
        })
        for child in node.get("calls") or []:
            walk(child,depth+1)
    walk(trace)
    return rows


def _control_transaction_envelope(tx, chain_id):
    """Canonical transaction fields that can affect call context or gas accounting."""
    fields=("nonce","gas","gasPrice","maxFeePerGas","maxPriorityFeePerGas","type","accessList")
    envelope={"chain_id":str(chain_id).lower()}
    for name in fields:
        value=tx.get(name)
        if name=="accessList" and isinstance(value,list):
            envelope[name]=[
                {"address":str(row.get("address") or "").lower(),
                 "storageKeys":sorted(str(key).lower() for key in (row.get("storageKeys") or []))}
                for row in value if isinstance(row,dict)
            ]
        elif value is None:
            envelope[name]=None
        elif isinstance(value,str):
            envelope[name]=value.lower()
        else:
            envelope[name]=value
    digest=hashlib.sha256(json.dumps(envelope,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return digest,envelope


def _control_entry_digest(tx, chain_id):
    value=tx.get("value") or "0x0"
    try: value_int=int(str(value),16) if str(value).startswith("0x") else int(value)
    except (TypeError,ValueError): raise ValueError("Traced transaction has an invalid value field.")
    entry={
        "chain_id":str(chain_id).lower(),
        "from":str(tx.get("from") or "").lower(),
        "to":str(tx.get("to") or "").lower(),
        "input":str(tx.get("input") or tx.get("data") or "").lower(),
        "value_wei":value_int,
    }
    if not entry["from"] or not entry["to"] or not entry["input"].startswith("0x"):
        raise ValueError("RPC transaction is missing sender, recipient or calldata.")
    return hashlib.sha256(json.dumps(entry,sort_keys=True,separators=(",",":")).encode()).hexdigest(),entry


def _control_prestate_digest(url, receipt, addresses, slots, comparison_excluded_slots=None):
    block_number=int(str(receipt.get("blockNumber") or "0x0"),16)
    tx_index=int(str(receipt.get("transactionIndex") or "0x0"),16)
    if block_number<1 or tx_index!=0:
        raise ValueError("Trace-backed control requires an automined transaction at index 0 so its parent block is the exact pre-state.")
    block=rpc(url,"eth_getBlockByNumber",[hex(block_number-1),False])
    if not isinstance(block,dict): raise ValueError("RPC did not return the transaction's parent block.")
    prestate={"parent_block_number":block_number-1,"parent_block_hash":str(block.get("hash") or "").lower(),
              "timestamp":str(block.get("timestamp") or "").lower(),
              "base_fee_per_gas":str(block.get("baseFeePerGas") or "").lower(),
              "addresses":[],"storage":[]}
    for address in sorted(set(addresses)):
        prestate["addresses"].append({
            "address":address,
            "balance":rpc(url,"eth_getBalance",[address,hex(block_number-1)]),
            "nonce":rpc(url,"eth_getTransactionCount",[address,hex(block_number-1)]),
            "code_sha256":hashlib.sha256(bytes.fromhex(str(rpc(url,"eth_getCode",[address,hex(block_number-1)]) or "0x").removeprefix("0x"))).hexdigest(),
        })
    for item in sorted(slots,key=lambda x:(x["address"],x["slot"])):
        prestate["storage"].append({
            "address":item["address"],"slot":item["slot"],
            "value":rpc(url,"eth_getStorageAt",[item["address"],item["slot"],hex(block_number-1)]),
        })
    # The parent hash itself includes the intentionally different attacker-only
    # scenario setup transaction. Keep it in evidence, but compare the execution
    # context and explicitly declared target/account state rather than the hash.
    excluded={str(x.get("address","")).lower()+":"+str(x.get("slot","")).lower()
              for x in (comparison_excluded_slots or []) if isinstance(x,dict)}
    comparable={key:value for key,value in prestate.items() if key!="parent_block_hash"}
    if excluded:
        comparable["storage"]=[
            row for row in comparable["storage"]
            if str(row.get("address","")).lower()+":"+str(row.get("slot","")).lower() not in excluded
        ]
    digest=hashlib.sha256(json.dumps(comparable,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    prestate["equivalence_fields"] = sorted(comparable.keys())
    prestate["comparison_excluded_slots"] = sorted(excluded)
    prestate["equivalence_policy"] = "Parent block hash is retained for provenance but excluded because scenario preparation transactions differ. Explicit scenario-parameter slots are retained in evidence but excluded from equality only after their control/attack values are independently verified. All other trace-derived and declared account/storage pre-state is compared."
    return digest,prestate



def _trace_storage_prestate(url, tx_hash):
    """Best-effort Geth/Anvil prestateTracer read set for one mined transaction."""
    try:
        payload=rpc(url,"debug_traceTransaction",[
            tx_hash,{"tracer":"prestateTracer","tracerConfig":{"diffMode":False}}
        ],60)
    except Exception as exc:
        return {"supported":False,"reason":str(exc)[:500],"addresses":[],"slots":[]}
    if not isinstance(payload,dict):
        return {"supported":False,"reason":"prestateTracer returned a non-object result.","addresses":[],"slots":[]}
    state=payload.get("pre") if isinstance(payload.get("pre"),dict) else payload
    addresses=[]; slots=[]
    for raw_address,account in state.items():
        try:
            address=addr(raw_address)
        except ValueError:
            continue
        if not isinstance(account,dict):
            continue
        addresses.append(address)
        storage=account.get("storage") or {}
        if isinstance(storage,dict):
            for raw_slot,raw_value in storage.items():
                slot_raw=str(raw_slot).lower().removeprefix("0x")
                value_raw=str(raw_value).lower().removeprefix("0x")
                if (re.fullmatch(r"[0-9a-f]{1,64}",slot_raw) and
                    re.fullmatch(r"[0-9a-f]{1,64}",value_raw)):
                    slots.append({"address":address,"slot":"0x"+slot_raw.rjust(64,"0"),
                                  "value":"0x"+value_raw.rjust(64,"0")})
    slots.sort(key=lambda item:(item["address"],item["slot"]))
    if not addresses:
        return {"supported":False,"reason":"prestateTracer result did not contain account prestate entries.",
                "addresses":[],"slots":[]}
    return {
        "supported":True,
        "mode":"prestateTracer",
        "addresses":sorted(set(addresses)),
        "slots":slots,
        "slot_count":len(slots),
        "note":"prestateTracer read-set evidence is tracer-specific and may not cover all transitive dependency state.",
    }



def _trace_control_run(root, url, name, entry, spec, env):
    snapshot=rpc(url,"evm_snapshot",[])
    if snapshot is None: raise RuntimeError("Anvil did not return an evm_snapshot ID.")
    try:
        temp=Path(tempfile.mkdtemp(prefix="lk-control-")); work=temp/"project"
        try:
            shutil.copytree(root,work,ignore=shutil.ignore_patterns(".git",".audit","out","cache","node_modules","__pycache__"))
            addresses=[addr(x) for x in (spec.get("prestate_addresses") or [])]
            scenario_parameters=[]
            prepare_argv=entry.get("prepare_argv")
            for command_name,command_argv in (("prepare_argv",prepare_argv),("argv",entry.get("argv"))):
                if command_argv:
                    command_audit=inspect_reproduction_command(root,command_argv)
                    if command_audit["blocked"]:
                        raise ValueError(f"{name} {command_name} contains local RPC state-fabrication calls: {command_audit['state_fabrication_calls']}")
            if spec.get("scenario_parameters") and not prepare_argv:
                raise ValueError(f"{name} requires prepare_argv so attacker-only scenario variables can be verified before transaction execution.")
            if prepare_argv:
                prepared=run([str(x) for x in prepare_argv],work,int(spec.get("prepare_timeout_seconds",60)),env=env)
                prepared_output=(prepared.stdout or "")+"\n"+(prepared.stderr or "")
                if prepared.returncode!=0:
                    raise RuntimeError(f"{name} scenario preparation failed (exit {prepared.returncode}): {prepared_output[-1200:]}")
            for scenario in spec.get("scenario_parameters") or []:
                if not isinstance(scenario,dict): raise ValueError("scenario_parameters entries must be objects.")
                scenario_address=addr(scenario.get("address"))
                if scenario_address not in addresses:
                    raise ValueError(f"Scenario parameter address {scenario_address} must also appear in prestate_addresses.")
                scenario_slot=str(scenario.get("slot") or "").lower()
                if re.fullmatch(r"0x[0-9a-f]{64}",scenario_slot) is None:
                    try: scenario_slot=hex(int(scenario_slot,0))
                    except ValueError: raise ValueError("Invalid scenario parameter storage slot.")
                observed=rpc(url,"eth_getStorageAt",[scenario_address,scenario_slot,"latest"])
                expected_raw=scenario.get(name+"_value")
                if expected_raw is None: raise ValueError(f"scenario parameter is missing {name}_value.")
                expected_value=int(str(expected_raw),16) if str(expected_raw).lower().startswith("0x") else int(expected_raw)
                observed_value=int(str(observed),16)
                if observed_value!=expected_value:
                    raise ValueError(f"Scenario parameter {scenario.get('name') or scenario_slot} has value {observed}, expected {expected_raw} for {name} before the transaction.")
                scenario_parameters.append({"name":scenario.get("name"),"address":scenario_address,
                                            "slot":scenario_slot,"observed_value":observed,
                                            "expected_value":expected_raw,"description":scenario.get("description"),
                                            "verified_before_transaction":True})
            proc=run([str(x) for x in entry["argv"]],work,int(spec.get("timeout_seconds",300)),env=env)
            combined=(proc.stdout or "")+"\n"+(proc.stderr or "")
            hashes=re.findall(r"LOWKEY_TRACE_TX_HASH\s+(0x[0-9a-fA-F]{64})",combined)
            if proc.returncode!=0: raise RuntimeError(f"{name} command failed (exit {proc.returncode}): {combined[-1200:]}")
            if len(hashes)!=1: raise ValueError(f"{name} command must emit exactly one LOWKEY_TRACE_TX_HASH marker for the transaction under test.")
            tx_hash=hashes[0].lower()
            tx=rpc(url,"eth_getTransactionByHash",[tx_hash])
            receipt=rpc(url,"eth_getTransactionReceipt",[tx_hash])
            if not isinstance(tx,dict) or not isinstance(receipt,dict): raise ValueError(f"{name} transaction was not mined on the supplied Anvil node.")
            if str(receipt.get("status") or "").lower() not in {"0x1","1"}: raise ValueError(f"{name} transaction reverted; it cannot be used as a passing control trace.")
            chain_id=rpc(url,"eth_chainId",[])
            block_number=int(str(receipt.get("blockNumber") or "0x0"),16)
            latest=int(str(rpc(url,"eth_blockNumber",[])),16)
            if block_number>latest: raise ValueError(f"{name} transaction receipt refers to a future block.")
            block=rpc(url,"eth_getBlockByNumber",[hex(block_number),False])
            hashes_in_block=[str(x).lower() for x in ((block or {}).get("transactions") or [])]
            if len(hashes_in_block)!=1 or hashes_in_block[0]!=tx_hash:
                raise ValueError(f"{name} transaction must be the only transaction in its block; disable batching/mining bundles for this control run.")
            trace=rpc(url,"debug_traceTransaction",[tx_hash,{"tracer":"callTracer"}],60)
            if not isinstance(trace,dict): raise ValueError(f"{name} node did not return a callTracer result.")
            calls=_trace_flatten(trace)
            target=str(spec.get("target_address") or "").lower()
            touched={x["to"] for x in calls if x.get("to")}
            if target and target not in touched: raise ValueError(f"{name} transaction trace never called the manifest target {target}.")
            required={str(tx.get("from") or "").lower(),str(tx.get("to") or "").lower()}
            if not required.issubset(set(addresses)): raise ValueError(f"{name} prestate_addresses must include the transaction sender and root recipient.")
            if target and target not in addresses: raise ValueError(f"{name} prestate_addresses must include target_address.")
            storage_trace=_trace_storage_prestate(url,tx_hash)
            for discovered_address in storage_trace.get("addresses",[]):
                if discovered_address not in addresses:
                    addresses.append(discovered_address)
            slots=[]
            for raw in spec.get("prestate_slots") or []:
                if not isinstance(raw,dict): raise ValueError("prestate_slots entries must be objects with address and slot.")
                address=addr(raw.get("address"))
                slot=str(raw.get("slot") or "").lower()
                if re.fullmatch(r"0x[0-9a-f]{64}",slot) is None:
                    try: slot=hex(int(slot,0))
                    except (TypeError,ValueError): raise ValueError(f"Invalid prestate slot: {raw.get('slot')}")
                slots.append({"address":address,"slot":slot})
            for item in storage_trace.get("slots",[]):
                slots.append({"address":item["address"],"slot":item["slot"]})
            slots=list({(item["address"],item["slot"]):item for item in slots}.values())
            if not slots:
                raise ValueError("No target/dependency storage slots were declared or discovered by prestateTracer.")
            if spec.get("require_trace_storage") and not storage_trace.get("supported"):
                raise ValueError("Manifest requires trace-derived storage, but the RPC does not support prestateTracer: "+str(storage_trace.get("reason")))
            entry_digest,entry_call=_control_entry_digest(tx,chain_id)
            envelope_digest,envelope=_control_transaction_envelope(tx,chain_id)
            trace_entry_digest,trace_entry=_control_entry_digest(trace,chain_id)
            if trace_entry_digest!=entry_digest:
                raise ValueError(f"{name} callTracer root does not match eth_getTransactionByHash.")
            scenario_exclusions=[
                {"address":row["address"],"slot":row["slot"]}
                for row in scenario_parameters
            ]
            prestate_digest,prestate=_control_prestate_digest(
                url,receipt,addresses,slots,comparison_excluded_slots=scenario_exclusions
            )
            parent_storage={(item["address"],item["slot"]):str(item["value"]).lower()
                            for item in prestate.get("storage",[])}
            for observed_slot in storage_trace.get("slots",[]):
                key=(observed_slot["address"],observed_slot["slot"])
                if key in parent_storage and parent_storage[key]!=str(observed_slot["value"]).lower():
                    raise ValueError(
                        f"{name} prestateTracer value for {key[0]}:{key[1]} "
                        "does not match eth_getStorageAt at the transaction parent block."
                    )
            metric_addresses=sorted({addr(x) for x in (spec.get("metric_addresses") or [])})
            sender=str(tx.get("from") or "").lower()
            if not metric_addresses or sender not in metric_addresses:
                raise ValueError("metric_addresses must include the actual transaction sender so gas expenditure is included in the measured portfolio.")
            if not set(metric_addresses).issubset(set(addresses)):
                raise ValueError("Every metric_address must also appear in prestate_addresses.")
            before_by_address={x["address"]:int(str(x["balance"]),16) for x in prestate["addresses"]}
            after_by_address={address:int(str(rpc(url,"eth_getBalance",[address,hex(block_number)])),16)
                              for address in metric_addresses}
            metric=sum(after_by_address[x]-before_by_address[x] for x in metric_addresses)
            gas_used=int(str(receipt.get("gasUsed") or "0x0"),16)
            gas_price=int(str(receipt.get("effectiveGasPrice") or tx.get("gasPrice") or "0x0"),16)
            gas_cost=gas_used*gas_price
            semantic_check=None
            semantic_argv=entry.get("semantic_check_argv")
            if semantic_argv:
                semantic_audit=inspect_reproduction_command(root,semantic_argv)
                if semantic_audit["blocked"]:
                    raise ValueError(f"{name} semantic_check_argv contains local RPC state-fabrication calls.")
                semantic_proc=run([str(x) for x in semantic_argv],work,
                                  int(spec.get("semantic_timeout_seconds",600)),env=env)
                semantic_output=(semantic_proc.stdout or "")+"\\n"+(semantic_proc.stderr or "")
                semantic_check={
                    "argv":semantic_argv,"exit_code":semantic_proc.returncode,
                    "verified":semantic_proc.returncode==0,
                    "output_tail":semantic_output[-1600:],
                }
            return {
                "exit_code":proc.returncode,
                "metric":metric,
                "metric_kind":"native_balance_delta_after_gas",
                "metric_addresses":metric_addresses,
                "gas_used":gas_used,
                "effective_gas_price_wei":gas_price,
                "gas_cost_wei":gas_cost,
                "tx_hash":tx_hash,
                "chain_id":chain_id,
                "block_number":block_number,
                "entry_call_sha256":entry_digest,
                "entry_call":entry_call,
                "transaction_envelope_sha256":envelope_digest,
                "transaction_envelope":envelope,
                "prestate_sha256":prestate_digest,
                "prestate":prestate,
                "storage_trace":storage_trace,
                "derived_storage_slots":storage_trace.get("slots",[]),
                "scenario_parameters":scenario_parameters,
                "semantic_check":semantic_check,
                "call_trace":calls,
                "argv":entry["argv"],
                "output_tail":combined[-2500:],
            }
        finally: shutil.rmtree(temp,ignore_errors=True)
    finally:
        reverted=rpc(url,"evm_revert",[snapshot])
        if reverted is not True: raise RuntimeError("Could not revert the local Anvil snapshot after the control run.")



def _forge_source_verification(source_url, fork_url, normalized, spec):
    result = {
        "verified": False,
        "method": "independent archive RPC: chain/block anchor, EIP-1186 code hashes and trace-derived storage",
        "checked_addresses": [],
        "checked_storage_slots": [],
    }
    if not source_url:
        result["reason"] = "No independent --source-rpc-url was supplied."
        return result
    source = rpc_url(source_url)
    if urlparse(source).hostname == urlparse(fork_url).hostname:
        result["reason"] = "Source RPC host must differ from the Foundry fork RPC host."
        return result
    chain_id = int(normalized["chain_id"])
    block_number = int(normalized["block_number"])
    if block_number < 1:
        result["reason"] = "Fork block must be at least 1 to verify its parent hash."
        return result
    source_chain = rpc(source, "eth_chainId", [])
    try:
        source_chain_int = int(str(source_chain), 16)
    except ValueError:
        source_chain_int = int(source_chain)
    if source_chain_int != chain_id:
        result["reason"] = "Archive RPC chain ID differs from the Foundry state-diff chain ID."
        return result
    source_parent = rpc(source, "eth_getBlockByNumber", [hex(block_number - 1), False])
    if not isinstance(source_parent, dict):
        result["reason"] = "Archive RPC did not return the fork parent block."
        return result
    expected_parent = str(normalized.get("fork_parent_hash") or "").lower()
    if not expected_parent or expected_parent == "0x" + "0" * 64:
        result["reason"] = "Recorder artifact has no usable fork parent block hash."
        return result
    if str(source_parent.get("hash") or "").lower() != expected_parent:
        result["reason"] = "Archive parent block hash does not match the test's recorded fork anchor."
        return result
    target = str(normalized["target_address"]).lower()
    source_addresses = sorted({addr(x) for x in (spec.get("source_addresses") or [target])})
    if target not in source_addresses:
        raise ValueError("source_addresses must include target_address.")
    prestate_by_address = {item["address"]: item for item in normalized.get("prestate") or []}
    for address in source_addresses:
        prestate = prestate_by_address.get(address)
        if prestate is None:
            result["reason"] = "Source address " + address + " was not observed in the Forge state-diff."
            return result
        expected_code_hash = (
            normalized["target_code_hash"] if address == target else prestate.get("code_hash")
        )
        if not expected_code_hash:
            result["reason"] = "No code hash was captured for source address " + address + "."
            return result
        try:
            proof = rpc(source, "eth_getProof", [address, [], hex(block_number)])
        except Exception as exc:
            result["reason"] = "Archive RPC eth_getProof unavailable or rejected: " + str(exc)[:300]
            return result
        actual_code_hash = str((proof or {}).get("codeHash") or "").lower()
        if actual_code_hash != str(expected_code_hash).lower():
            result["reason"] = "EIP-1186 code hash differs for source address " + address + "."
            return result
        if prestate.get("balance_wei") is not None:
            try:
                actual_balance = int(str((proof or {}).get("balance")), 16)
            except (TypeError, ValueError):
                result["reason"] = "Archive eth_getProof omitted a parseable balance for " + address + "."
                return result
            if actual_balance != int(prestate["balance_wei"]):
                result["reason"] = "Source balance differs for " + address + "."
                return result
        if prestate.get("nonce") is not None:
            try:
                actual_nonce = int(str((proof or {}).get("nonce")), 16)
            except (TypeError, ValueError):
                result["reason"] = "Archive eth_getProof omitted a parseable nonce for " + address + "."
                return result
            if actual_nonce != int(prestate["nonce"]):
                result["reason"] = "Source nonce differs for " + address + "."
                return result
        result["checked_addresses"].append({
            "address": address, "code_hash": actual_code_hash,
            "balance_wei": prestate.get("balance_wei"), "nonce": prestate.get("nonce"),
        })
        for storage in prestate.get("storage") or []:
            slot = str(storage["slot"]).lower()
            expected_value = str(storage["value"]).lower()
            try:
                actual_value = str(rpc(
                    source, "eth_getStorageAt", [address, slot, hex(block_number)]
                )).lower()
            except Exception as exc:
                result["reason"] = "Archive storage read failed for " + address + ":" + slot + ": " + str(exc)[:200]
                return result
            if actual_value != expected_value:
                result["reason"] = "Trace-derived prestate slot differs for " + address + ":" + slot + "."
                return result
            result["checked_storage_slots"].append(
                {"address": address, "slot": slot, "value": actual_value}
            )
    result["verified"] = True
    result["source_chain_id"] = source_chain
    result["fork_block"] = block_number
    result["fork_parent_hash"] = expected_parent
    return result


def _forge_control_run(root, fork_url, name, entry, spec, env, source_url=None):
    try:
        try:
            from .forge_state_diff import normalize_forge_state_diff
        except ImportError:
            from forge_state_diff import normalize_forge_state_diff
    except ImportError as exc:
        raise RuntimeError("Forge state-diff normalizer is unavailable: " + str(exc)) from exc

    harness_name = entry.get("harness") or spec.get("harness")
    if not isinstance(harness_name, str) or not harness_name:
        raise ValueError(name + " requires harness pointing to the Foundry test file.")
    harness = (root / harness_name).resolve()
    if not harness.is_relative_to(root) or not harness.is_file():
        raise ValueError(name + " harness must be an existing file inside the project.")
    artifact_name = entry.get("state_diff_file")
    if not isinstance(artifact_name, str) or not artifact_name:
        raise ValueError(name + " requires state_diff_file written by LowkeyForgeStateDiffRecorder.")
    artifact_rel = Path(artifact_name)
    if artifact_rel.is_absolute() or ".." in artifact_rel.parts:
        raise ValueError(name + " state_diff_file must be a safe project-relative path.")
    argv = entry.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        raise ValueError(name + " argv must be a non-empty string array.")
    if Path(argv[0]).name not in {"forge", "forge.exe"}:
        raise ValueError(name + " Forge backend argv must invoke forge directly.")
    command_audit = inspect_reproduction_command(root, argv)
    if command_audit["blocked"]:
        raise ValueError(name + " command contains local RPC state-fabrication calls: " +
                         str(command_audit["state_fabrication_calls"]))
    fidelity = analyze_harness_fidelity(
        harness.read_text(encoding="utf-8", errors="replace"),
        harness.relative_to(root).as_posix(),
    )
    temp = Path(tempfile.mkdtemp(prefix="lk-forge-control-"))
    work = temp / "project"
    try:
        shutil.copytree(
            root, work,
            ignore=shutil.ignore_patterns(".git", ".audit", "out", "cache", "node_modules", "__pycache__"),
        )
        artifact_path = (work / artifact_rel).resolve()
        if not artifact_path.is_relative_to(work):
            raise ValueError("state_diff_file escaped the isolated Forge project.")
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            artifact_path.unlink()
        except FileNotFoundError:
            pass
        prepare_argv = entry.get("prepare_argv")
        if prepare_argv:
            prepare_audit = inspect_reproduction_command(root, prepare_argv)
            if prepare_audit["blocked"]:
                raise ValueError(name + " prepare_argv contains state fabrication.")
            prepared = run([str(x) for x in prepare_argv], work,
                           int(spec.get("prepare_timeout_seconds", 120)), env=env)
            if prepared.returncode != 0:
                raise RuntimeError(name + " Forge preparation failed: " +
                                   ((prepared.stdout or "") + (prepared.stderr or ""))[-1200:])
        proc = run(argv, work, int(spec.get("timeout_seconds", 600)), env=env)
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode != 0:
            raise RuntimeError(name + " Forge test command failed (exit " +
                               str(proc.returncode) + "): " + combined[-1600:])
        if not artifact_path.is_file():
            raise ValueError(name + " Forge test passed but did not write state_diff_file; " +
                             "ensure _lowkeyStartTrace/_lowkeyWriteTrace wrap the target call.")
        raw = json.loads(artifact_path.read_text(encoding="utf-8"))
        target = addr(spec.get("target_address"))
        normalized = normalize_forge_state_diff(raw, expected_target=target)
        semantic_check = None
        semantic_argv = entry.get("semantic_check_argv")
        if semantic_argv:
            audit = inspect_reproduction_command(root, semantic_argv)
            if audit["blocked"]:
                raise ValueError(name + " semantic_check_argv contains state fabrication.")
            semantic_proc = run([str(x) for x in semantic_argv], work,
                                int(spec.get("semantic_timeout_seconds", 600)), env=env)
            semantic_check = {
                "argv": semantic_argv, "exit_code": semantic_proc.returncode,
                "verified": semantic_proc.returncode == 0,
                "output_tail": ((semantic_proc.stdout or "") + (semantic_proc.stderr or ""))[-1200:],
            }
        metrics = {x["address"]: x["delta_wei"] for x in normalized.get("balance_deltas", [])}
        metric_addresses = sorted({addr(x) for x in (spec.get("metric_addresses") or [])})
        metric = None
        if metric_addresses and all(address in metrics for address in metric_addresses):
            metric = sum(metrics[address] for address in metric_addresses)
        source_verification = _forge_source_verification(source_url, fork_url, normalized, spec)
        fidelity_label = "simulated_caller"
        if fidelity.get("synthetic_state"):
            fidelity_label = "synthetic_state"
        elif any(signal.get("kind") == "external_call_mock" for signal in fidelity.get("signals", [])):
            fidelity_label = "simulated_dependencies"
        return {
            "backend": "forge-state-diff", "exit_code": proc.returncode, "metric": metric,
            "metric_kind": "forge_account_balance_delta_without_eoa_gas",
            "metric_addresses": metric_addresses, "gas_verified": False,
            "transaction_envelope_verified": False, "tx_hash": None,
            "chain_id": normalized["chain_id"], "block_number": normalized["block_number"],
            "fork_parent_hash": normalized.get("fork_parent_hash"),
            "entry_call_sha256": normalized["entry_call_sha256"],
            "entry_call": normalized["entry_call"],
            "prestate_sha256": normalized["prestate_sha256"], "prestate": normalized["prestate"],
            "derived_storage_accesses": normalized["storage_accesses"],
            "derived_storage_slots": [
                {"address": item["account"], "slot": item["slot"],
                 "prestate_value": item["previous_value"]}
                for item in normalized["storage_accesses"]
            ],
            "balance_deltas": normalized.get("balance_deltas", []),
            "call_trace": normalized["calls"], "raw_account_accesses": normalized["raw_account_accesses"],
            "target_code_hash": normalized["target_code_hash"],
            "source_verification": source_verification,
            "target_authenticity_verified": source_verification["verified"],
            "fidelity": fidelity, "fidelity_label": fidelity_label, "semantic_check": semantic_check,
            "state_diff_file": artifact_rel.as_posix(), "argv": argv, "output_tail": combined[-2500:],
            "limitations": normalized["limitations"],
        }
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def control(args):
    p=argparse.ArgumentParser(prog="lk control")
    p.add_argument("manifest")
    p.add_argument("--root",default=".")
    p.add_argument("--rpc-url",required=True)
    p.add_argument("--source-rpc-url")
    p.add_argument("--output",default=".audit/godmode/control.json")
    p.add_argument("--freeze",action="store_true",help="Freeze the manifest, commands, harnesses and expectations without running them.")
    p.add_argument("--freeze-file",default=".audit/godmode/control.freeze.json")
    p.add_argument("--require-frozen",action="store_true",help="Refuse to execute unless a matching frozen manifest exists.")
    p.add_argument("--non-economic",action="store_true",help="Require a passing semantic invariant instead of positive profit.")
    ns=p.parse_args(args)

    root=root_path(ns.root)
    url=rpc_url(ns.rpc_url)
    mf=(root/ns.manifest).resolve()
    if not mf.is_relative_to(root) or not mf.is_file():
        raise ValueError("Manifest must be an existing file inside project.")
    spec=json.loads(mf.read_text(encoding="utf-8"))
    attack=spec.get("attack") or {}
    control_run=spec.get("control") or {}
    backend=str(spec.get("trace_backend") or "anvil-calltracer").lower()
    if backend not in {"anvil-calltracer","forge-state-diff"}:
        raise ValueError("trace_backend must be anvil-calltracer or forge-state-diff.")
    if not spec.get("same_calls_id"):
        raise ValueError("Declare same_calls_id as a human-readable label for the matched experiment.")
    if not isinstance(attack.get("argv"),list) or not isinstance(control_run.get("argv"),list):
        raise ValueError("Manifest requires control.argv and attack.argv.")
    target=addr(spec.get("target_address"))
    if not isinstance(spec.get("metric_addresses"),list) or not spec["metric_addresses"]:
        raise ValueError("Declare metric_addresses for the attacker portfolio.")

    try:
        try:
            from . import proof_evidence
        except ImportError:
            import proof_evidence
    except ImportError as exc:
        raise RuntimeError("Proof evidence policy module is unavailable: " + str(exc)) from exc

    if ns.freeze:
        frozen, freeze_path = proof_evidence.freeze_control_manifest(
            root, mf, spec, ns.freeze_file
        )
        print("CONTROL EXPECTATIONS FROZEN")
        print("  file: " + str(freeze_path.relative_to(root)))
        print("  sha256: " + frozen["freeze_sha256"])
        print("  manifest: " + frozen["manifest_sha256"])
        print("No attack or control command was executed.")
        return 0

    freeze_status=proof_evidence.validate_control_freeze(
        root, mf, spec, required=ns.require_frozen, freeze_path=ns.freeze_file
    )
    if backend=="anvil-calltracer" and not local_rpc(url):
        raise ValueError("Anvil callTracer control accepts a local Anvil RPC endpoint only.")
    if backend=="forge-state-diff" and not url:
        raise ValueError("Forge state-diff requires a fork RPC URL via --rpc-url.")

    env=os.environ.copy()
    env.update({"ETH_RPC_URL":url,"FOUNDRY_ETH_RPC_URL":url,"LOWKEY_RPC_URL":url})
    rows={}
    scenarios=[("control",control_run),("attack",attack)]
    negative=spec.get("negative_control")
    if negative is not None:
        if not isinstance(negative,dict) or not isinstance(negative.get("argv"),list):
            raise ValueError("negative_control must contain an argv string array.")
        scenarios.append(("negative_control",negative))
    elif spec.get("require_negative_control"):
        raise ValueError("Manifest requires negative_control but does not define it.")

    for name,entry in scenarios:
        try:
            if backend=="forge-state-diff":
                rows[name]=_forge_control_run(
                    root,url,name,entry,spec,env,source_url=ns.source_rpc_url
                )
            else:
                rows[name]=_trace_control_run(root,url,name,entry,spec,env)
        except Exception as exc:
            rows[name]={
                "exit_code":None,"metric":None,"trace_error":str(exc),
                "argv":entry.get("argv"),"backend":backend,
            }

    control_metric=rows.get("control",{}).get("metric")
    attack_metric=rows.get("attack",{}).get("metric")
    delta=None
    if isinstance(control_metric,int) and isinstance(attack_metric,int):
        delta=attack_metric-control_metric
    same_entry=bool(
        rows.get("control",{}).get("entry_call_sha256") and
        rows.get("control",{}).get("entry_call_sha256")==rows.get("attack",{}).get("entry_call_sha256")
    )
    same_envelope=(
        backend=="forge-state-diff" or bool(
            rows.get("control",{}).get("transaction_envelope_sha256") and
            rows.get("control",{}).get("transaction_envelope_sha256")==rows.get("attack",{}).get("transaction_envelope_sha256")
        )
    )
    same_prestate=bool(
        rows.get("control",{}).get("prestate_sha256") and
        rows.get("control",{}).get("prestate_sha256")==rows.get("attack",{}).get("prestate_sha256")
    )
    same_chain=bool(
        rows.get("control",{}).get("chain_id") is not None and
        str(rows["control"]["chain_id"]).lower()==str(rows.get("attack",{}).get("chain_id","")).lower()
    )
    same_block=bool(
        rows.get("control",{}).get("block_number") is not None and
        rows.get("control",{}).get("block_number")==rows.get("attack",{}).get("block_number")
    )
    same_fork_anchor=(
        backend!="forge-state-diff" or bool(
            rows.get("control",{}).get("fork_parent_hash") and
            str(rows.get("control",{}).get("fork_parent_hash")).lower()==
            str(rows.get("attack",{}).get("fork_parent_hash","")).lower()
        )
    )
    fork_pin_verified=True
    if backend=="forge-state-diff":
        expected_block=spec.get("expected_fork_block")
        expected_chain=spec.get("expected_chain_id")
        if expected_block is None or expected_chain is None:
            fork_pin_verified=False
        else:
            try:
                expected_block_int=int(str(expected_block),16) if str(expected_block).lower().startswith("0x") else int(expected_block)
                expected_chain_int=int(str(expected_chain),16) if str(expected_chain).lower().startswith("0x") else int(expected_chain)
            except (TypeError,ValueError):
                raise ValueError("expected_fork_block and expected_chain_id must be integers or 0x quantities.")
            fork_pin_verified=(
                rows.get("control",{}).get("block_number")==expected_block_int and
                rows.get("attack",{}).get("block_number")==expected_block_int and
                int(rows.get("control",{}).get("chain_id") or -1)==expected_chain_int and
                int(rows.get("attack",{}).get("chain_id") or -1)==expected_chain_int
            )

    trace_expectations=spec.get("trace_expectations") or []
    trace_checks=[]
    trace_delta_verified=bool(trace_expectations)
    reasons_placeholder="Manifest must declare trace_expectations for the expected target/callback path delta."
    for expectation in trace_expectations:
        if not isinstance(expectation,dict):
            trace_delta_verified=False
            trace_checks.append({"verified":False,"reason":"trace_expectation must be an object"})
            continue
        address=addr(expectation.get("address"))
        counts={}
        expected={}
        names=["control","attack"]
        if negative is not None:
            names.append("negative_control")
        for name in names:
            calls=rows.get(name,{}).get("call_trace") or []
            counts[name]=sum(1 for call in calls if str(call.get("to") or "").lower()==address)
            lo=expectation.get(name+"_min_calls")
            hi=expectation.get(name+"_max_calls")
            if lo is None or hi is None or int(lo)<0 or int(hi)<int(lo):
                if name=="negative_control" and not spec.get("require_negative_control"):
                    expected[name]={"configured":False,"matched":None}
                else:
                    trace_delta_verified=False
                    expected[name]={"valid":False,"reason":"min/max calls are missing or invalid"}
            else:
                expected[name]={"min":int(lo),"max":int(hi),
                                "matched":int(lo)<=counts[name]<=int(hi)}
                if not expected[name]["matched"]:
                    trace_delta_verified=False
        trace_checks.append({
            "address":address,"description":expectation.get("description"),
            "observed_call_counts":counts,"expected":expected,
            "verified":all(item.get("matched",True) is not False for item in expected.values()),
        })
    trace_delta_verified=trace_delta_verified and all(item.get("verified",False) for item in trace_checks)

    negative_control_present=negative is not None
    negative_control_verified=(
        negative_control_present and
        all("negative_control" in check.get("expected",{}) and
            check["expected"]["negative_control"].get("matched") is True
            for check in trace_checks)
    )
    if spec.get("require_negative_control") and not negative_control_verified:
        trace_delta_verified=False

    attack_metric_positive=bool(isinstance(attack_metric,int) and attack_metric>0)
    semantic_check=rows.get("attack",{}).get("semantic_check") or {}
    semantic_invariant_verified=bool(semantic_check.get("verified"))
    family=proof_evidence.normalize_family(spec.get("family"))
    non_economic=bool(ns.non_economic or spec.get("non_economic") or
                      family in proof_evidence.NON_ECONOMIC_FAMILIES)
    economics=proof_evidence.evaluate_economic_policy(
        family,attack_metric,non_economic=non_economic,
        semantic_invariant_verified=semantic_invariant_verified,
    )

    scenario_errors=[name for name,_ in scenarios if rows.get(name,{}).get("trace_error")]
    execution_attempted=all(
        rows.get(name,{}).get("exit_code")==0 for name in ("control","attack")
    )
    base_valid=(
        same_entry and same_prestate and same_chain and same_block and same_fork_anchor and
        trace_delta_verified and not scenario_errors and freeze_status.get("verified",False)
    )
    if backend=="anvil-calltracer":
        base_valid=base_valid and same_envelope
    else:
        # Forge has no signed transaction envelope or EOA receipt gas. Require a
        # block-pinned, independently verified target before calling it fork evidence.
        base_valid=base_valid and fork_pin_verified and all(
            rows.get(name,{}).get("target_authenticity_verified",False)
            for name in ("control","attack")
        )

    if non_economic:
        passed=base_valid and economics["accepted"] and semantic_invariant_verified
    else:
        # Anvil's metric is net of actual receipt gas. Forge's is a state-diff
        # balance delta without gas, so it can never satisfy this profit gate.
        passed=(base_valid and backend=="anvil-calltracer" and economics["accepted"] and
                attack_metric_positive and isinstance(delta,int) and delta>0)

    rejection_reasons=[]
    for name in ("control","attack","negative_control"):
        if rows.get(name,{}).get("trace_error"):
            rejection_reasons.append(name+": "+rows[name]["trace_error"])
    if not same_entry: rejection_reasons.append("Control and attack do not share the same target entry call.")
    if not same_prestate: rejection_reasons.append("Control and attack pre-state digests differ.")
    if not same_chain: rejection_reasons.append("Control and attack were executed on different chain IDs.")
    if not same_block: rejection_reasons.append("Control and attack used different block numbers.")
    if not same_fork_anchor: rejection_reasons.append("Control and attack used different fork parent hashes.")
    if backend=="forge-state-diff" and not fork_pin_verified:
        rejection_reasons.append("Forge runs do not match the manifest's expected_chain_id and expected_fork_block pins.")
    if backend=="anvil-calltracer" and not same_envelope:
        rejection_reasons.append("RPC-derived transaction nonce/gas/fee/type/access-list envelope differs.")
    if not trace_delta_verified:
        rejection_reasons.append(reasons_placeholder if not trace_expectations else
            "Observed nested-call trace did not match the frozen manifest expectations.")
    if spec.get("require_negative_control") and not negative_control_verified:
        rejection_reasons.append("Required negative control is missing or did not match its expected callback/path behavior.")
    if not freeze_status.get("verified"):
        rejection_reasons.append("Frozen expectations are missing or were not verified; this run cannot be promoted.")
    if non_economic and not semantic_invariant_verified:
        rejection_reasons.append("Non-economic attack requires a passing semantic_check_argv.")
    if not non_economic and backend=="forge-state-diff":
        rejection_reasons.append("Forge state-diff has no EOA receipt gas accounting; it cannot prove net profitability.")
    if not non_economic and (delta is None or delta<=0):
        rejection_reasons.append("Attack metric did not exceed the control metric.")
    if not non_economic and not attack_metric_positive:
        rejection_reasons.append("Attack metric is not positive after measured costs.")

    authenticity=(
        "forked_deployment" if all(
            rows.get(name,{}).get("target_authenticity_verified",False)
            for name in ("control","attack")
        ) else str(spec.get("target_authenticity") or "unknown")
    )
    fidelity_labels=[rows.get(name,{}).get("fidelity_label") for name in ("control","attack")]
    if backend=="forge-state-diff":
        fidelity="simulated_caller"
        if "synthetic_state" in fidelity_labels: fidelity="synthetic_state"
        elif "simulated_dependencies" in fidelity_labels: fidelity="simulated_dependencies"
    else:
        fidelity="real_funded" if all(
            not (rows.get(name,{}).get("fidelity") or {}).get("synthetic_state",False) and
            not (rows.get(name,{}).get("fidelity") or {}).get("fork_reproduction_blockers")
            for name in ("control","attack")
        ) else "synthetic_state"

    rejection_codes=[]
    if not same_entry: rejection_codes.append("mismatch")
    if (not same_prestate or not same_chain or not same_block or not same_fork_anchor or
        (backend=="anvil-calltracer" and not same_envelope) or
        (backend=="forge-state-diff" and not fork_pin_verified)):
        rejection_codes.append("mismatch")
    if not trace_delta_verified: rejection_codes.append("control_path_mismatch")
    if spec.get("require_negative_control") and not negative_control_verified:
        rejection_codes.append("negative_control_failed")
    if non_economic and not semantic_invariant_verified:
        rejection_codes.append("semantic_invariant_failed")
    if not non_economic and isinstance(attack_metric,int) and attack_metric<=0:
        rejection_codes.append("net_negative")
    if isinstance(delta,int) and delta<=0:
        rejection_codes.append("control_not_outperformed")
    rejected=(
        execution_attempted and not scenario_errors and not passed and bool(rejection_codes)
    )
    outcome="profitable" if passed and not non_economic else (
        "observed" if passed or execution_attempted else "not_run"
    )
    if rejected:
        outcome="rejected"
    proof=proof_evidence.classify_proof(
        authenticity,fidelity,outcome,
        authenticity_verified=authenticity=="forked_deployment" and all(
            rows.get(name,{}).get("target_authenticity_verified",False)
            for name in ("control","attack")
        ),
    )
    legacy_status="BREAK" if passed else ("REJECTED" if rejected else "OBSERVED")
    proof_status=proof["status"]
    # Non-economic attacks and Forge-only state diffs must not be promoted as
    # profitable deployment exploits even when their semantic assertions pass.
    if non_economic and passed:
        proof_status="SIMULATED_BREAK"
    if not freeze_status.get("verified"):
        proof_status="OBSERVED"

    memory_feedback=None
    if rejected:
        try:
            try:
                from . import experience_memory
            except ImportError:
                import experience_memory
            memory_feedback=experience_memory.record_feedback(
                kind="false-positive",
                summary="Rejected control-gate hypothesis for "+str(spec.get("same_calls_id")),
                evidence="Control evidence rejected this attempted exploit. Reasons: "+
                         "; ".join(rejection_reasons)[:1000],
                finding_id="",
                root=root,
            )
        except Exception as exc:
            memory_feedback={"recorded":False,"reason":str(exc)[:300]}

    payload={
        "created_at":now(),"status":proof_status,"proof_status":proof_status,
        "legacy_status":legacy_status,"proof_axes":proof,
        "target_authenticity":authenticity,"fidelity":fidelity,
        "outcome":outcome,"family":family,"economic_policy":economics,
        "trace_backend":backend,"verification_method":(
            "Foundry Vm.startStateDiffRecording/stopAndReturnStateDiff" if backend=="forge-state-diff"
            else "local-Anvil RPC transaction plus debug_traceTransaction callTracer"
        ),
        "freeze":freeze_status,"negative_control_present":negative_control_present,
        "negative_control_verified":negative_control_verified,
        "control_delta":delta,"metric_name":spec.get("metric_name","attacker_gain"),
        "same_calls_id":spec["same_calls_id"],"same_entry_call_verified":same_entry,
        "same_transaction_envelope_verified":same_envelope,
        "same_prestate_verified":same_prestate,"same_chain_verified":same_chain,
        "same_block_verified":same_block,"same_fork_anchor_verified":same_fork_anchor,
        "fork_pin_verified":fork_pin_verified,
        "trace_delta_verified":trace_delta_verified,"trace_checks":trace_checks,
        "attack_metric_positive_after_gas":attack_metric_positive if backend=="anvil-calltracer" else None,
        "semantic_invariant_verified":semantic_invariant_verified,
        "target_address":target,"prestate_slots_declared":spec.get("prestate_slots") or [],
        "storage_slots_derived_from_trace":sorted({
            (item.get("address") or item.get("account","")).lower()+":"+str(item.get("slot","")).lower()
            for name in ("control","attack","negative_control")
            for item in rows.get(name,{}).get("derived_storage_accesses",[])
        }),
        "runs":rows,"reasons":rejection_reasons,"rejection_codes":sorted(set(rejection_codes)),
        "memory_feedback":memory_feedback,
        "gate":"Promotion requires frozen expectations, matched entry calls and pre-state, the configured trace backend, expected path/callback deltas, and a family-appropriate outcome. Forge state-diff is test-execution evidence and cannot prove EOA gas or net profitability.",
    }
    out=safe_out(root,ns.output)
    write_json(out,payload)
    print(f"{proof_status}: {backend}; delta {delta}; entry {'matched' if same_entry else 'DIFFERENT'}; pre-state {'matched' if same_prestate else 'DIFFERENT'}; frozen {'verified' if freeze_status.get('verified') else 'NO'}; evidence {out.relative_to(root)}")
    return 0 if passed else 1



def coverage(args):
    p=argparse.ArgumentParser(prog="lk target-coverage"); p.add_argument("source_file"); p.add_argument("--start-line",type=int,default=1); p.add_argument("--end-line",type=int); p.add_argument("--root",default="."); p.add_argument("--output",default=".audit/godmode/target-coverage.json"); ns=p.parse_args(args)
    root=root_path(ns.root); src=(root/ns.source_file).resolve()
    if not src.is_relative_to(root) or not src.is_file(): raise ValueError("Target source must be inside the project.")
    if not shutil.which("forge"): raise RuntimeError("Forge not installed.")
    proc=run(["forge","coverage","--report","lcov"],root,900)
    lcov=next((x for x in (root/"lcov.info",root/"coverage"/"lcov.info") if x.is_file()),None)
    if proc.returncode or not lcov: raise RuntimeError("Forge did not produce lcov.info; inspect coverage output.")
    current=None; rows=[]
    for line in lcov.read_text(errors="replace").splitlines():
        if line.startswith("SF:"):
            candidate=Path(line[3:])
            current=(candidate if candidate.is_absolute() else root/candidate).resolve()
        elif line.startswith("DA:") and current==src:
            n,count=map(int,line[3:].split(",")[:2])
            if n>=ns.start_line and (ns.end_line is None or n<=ns.end_line): rows.append({"line":n,"hits":count,"covered":count>0})
    total=len(rows); covered=sum(r["covered"] for r in rows)
    payload={"source":src.relative_to(root).as_posix(),"start_line":ns.start_line,"end_line":ns.end_line,
             "lines":total,"covered":covered,"uncovered":[x["line"] for x in rows if not x["covered"]],
             "percent":round(covered*100/total,2) if total else None,"warning":"Execution reachability is not assertion quality or security proof."}
    write_json(safe_out(root,ns.output),payload); print(json.dumps(payload,indent=2)); return 0 if total else 1
def provenance(args):
    p=argparse.ArgumentParser(prog="lk provenance")
    p.add_argument("artifacts",nargs="*"); p.add_argument("--root",default="."); p.add_argument("--chain-id")
    p.add_argument("--fork-block"); p.add_argument("--signing-key")
    p.add_argument("--output",default=".audit/godmode/provenance.json"); ns=p.parse_args(args)
    root=root_path(ns.root); rows=[]
    for raw in ns.artifacts:
        f=(root/raw).resolve()
        if not f.is_relative_to(root) or not f.is_file(): raise ValueError(f"Artifact must exist inside project: {raw}")
        rows.append({"path":f.relative_to(root).as_posix(),"sha256":sha(f),"bytes":f.stat().st_size})
    rev=None
    if shutil.which("git"):
        x=run(["git","rev-parse","HEAD"],root,5); rev=x.stdout.strip() if x.returncode==0 else None
    versions={}
    for tool in ("forge","cast","anvil","slither","halmos","heimdall","bwrap"):
        if shutil.which(tool):
            x=run([tool,"--version"],root,4); versions[tool]=(x.stdout or x.stderr).strip().splitlines()[0][:160]
    payload={"created_at":now(),"project":str(root),"git_revision":rev,"chain_id":ns.chain_id,
             "fork_block":ns.fork_block,"artifacts":rows,"tool_versions":versions,
             "signature":"detached .sig file when --signing-key is provided"}
    out=safe_out(root,ns.output); write_json(out,payload)
    signature=None
    if ns.signing_key:
        key=Path(ns.signing_key).expanduser().resolve()
        if not key.is_file(): raise ValueError("Signing key file does not exist.")
        if not shutil.which("openssl"): raise RuntimeError("OpenSSL is required for detached provenance signing.")
        sig=out.with_suffix(out.suffix+".sig")
        proc=run(["openssl","dgst","-sha256","-sign",str(key),"-out",str(sig),str(out)],root,20)
        if proc.returncode: raise RuntimeError("OpenSSL signing failed: "+proc.stderr[-1000:])
        signature=str(sig.relative_to(root))
    print("Provenance: "+str(out.relative_to(root)))
    print("SHA-256: "+sha(out))
    print("Detached signature: "+(signature or "not requested"))
    return 0

def output(payload):
    print(json.dumps(payload,indent=2,sort_keys=True)); return 0
def source_cmd(command,args):
    p=argparse.ArgumentParser(prog="lk "+command); p.add_argument("--root",default="."); ns=p.parse_args(args); root=root_path(ns.root); data=source_maps(root)
    key={"fallback-map":"fallback_map","oracle-map":"oracle_map","sig-matrix":"signature_map","init-frontrun":"initializer_map","custody":"custody_map","cross-vm":"cross_vm_map","reentrancy-graph":"reentrancy_graph","cfg":"cfg_outline"}[command]
    payload={"command":command,"signals":data[key]}
    if command=="sig-matrix": payload["candidate_replay_cases"]=["same signature twice","nonce not consumed","wrong chain ID","wrong verifying contract","expired deadline","wrong signer","malleable s","v normalization","wrong action/domain","packed-encoding collision","ERC-1271 contract signer"]
    if command=="oracle-map": payload["next"]="Trace the consumer and prove a downstream asset delta; no pool manipulation is inferred from a read."
    if command=="init-frontrun": payload["safety"]="Read-only static map only; Lowkey does not seize or initialize a live contract."
    if command=="reentrancy-graph": payload["confidence"]="heuristic; check exact storage identity and run a callback plus sequential control."
    return output(payload)
def fingerprint(args):
    p=argparse.ArgumentParser(prog="lk cheat fingerprint"); p.add_argument("--root",default="."); ns=p.parse_args(args); data=cheat_fingerprints(root_path(ns.root)); print(json.dumps(data,indent=2)); return 0
def economic(args):
    p=argparse.ArgumentParser(prog="lk economic"); p.add_argument("--gross-wei",type=int,required=True); p.add_argument("--gas-used",type=int,required=True); p.add_argument("--max-fee-wei",type=int,required=True); p.add_argument("--pool-fee-bps",type=int,default=0); p.add_argument("--slippage-bps",type=int,default=0); p.add_argument("--capital-cost-wei",type=int,default=0); ns=p.parse_args(args)
    vals=[ns.gross_wei,ns.gas_used,ns.max_fee_wei,ns.pool_fee_bps,ns.slippage_bps,ns.capital_cost_wei]
    if min(vals)<0 or ns.pool_fee_bps>10000 or ns.slippage_bps>10000: raise ValueError("Economic inputs must be nonnegative; bps <= 10000.")
    gas=ns.gas_used*ns.max_fee_wei; pool=ns.gross_wei*ns.pool_fee_bps//10000; slip=ns.gross_wei*ns.slippage_bps//10000
    net=ns.gross_wei-gas-pool-slip-ns.capital_cost_wei
    return output({"gross_wei":ns.gross_wei,"gas_cost_wei":gas,"pool_fee_wei":pool,"slippage_wei":slip,"capital_cost_wei":ns.capital_cost_wei,"net_profit_wei":net,"status":"positive-candidate" if net>0 else "OBSERVED","limitations":["MEV competition and unmodeled price impact are excluded."]})
def rpc_command(kind,args):
    p=argparse.ArgumentParser(prog="lk "+kind); p.add_argument("target"); p.add_argument("--rpc-url"); p.add_argument("--slots",type=int,default=120); p.add_argument("--no-resolve",action="store_true"); p.add_argument("--key",action="append",default=[]); ns=p.parse_args(args); url=rpc_url(ns.rpc_url); target=addr(ns.target)
    if kind=="selectors-full": return output(selectors(target,url))
    if kind=="proxy-resolve": return output(proxy(target,url,ns.slots))
    count=max(1,min(ns.slots,120))
    calls=[rpc(url,"eth_getStorageAt",[target,hex(i),"latest"]) for i in range(count)]
    nonzero=[{"slot":i,"word":v} for i,v in enumerate(calls) if v and int(v,16)]
    probes=[]; derivation="not-run"
    if ns.key:
        try:
            from Crypto.Hash import keccak
            derivation="pycryptodome-keccak"
            for raw_key in ns.key:
                key=addr(raw_key)
                for anchor in range(count):
                    packed=bytes.fromhex(key[2:].rjust(64,"0")+format(anchor,"064x"))
                    digest=keccak.new(digest_bits=256); digest.update(packed)
                    derived="0x"+digest.hexdigest()
                    value=rpc(url,"eth_getStorageAt",[target,derived,"latest"])
                    if value and int(value,16):
                        probes.append({"key":key,"mapping_anchor_slot":anchor,"derived_slot":derived,"value":value,"confidence":"known-key-probe-hit"})
        except ImportError:
            if shutil.which("cast"):
                derivation="cast-index"
                for raw_key in ns.key:
                    key=addr(raw_key)
                    for anchor in range(count):
                        proc=run(["cast","index","address",key,str(anchor)],Path.cwd(),5)
                        if proc.returncode: continue
                        derived=proc.stdout.strip()
                        if not re.fullmatch(r"0x[0-9a-fA-F]{64}",derived): continue
                        value=rpc(url,"eth_getStorageAt",[target,derived,"latest"])
                        if value and int(value,16):
                            probes.append({"key":key,"mapping_anchor_slot":anchor,"derived_slot":derived,"value":value,"confidence":"known-key-probe-hit"})
            else: derivation="blocked-no-keccak-library-or-cast"
    return output({"target":target,"scanned_slots":count,"nonzero_slots":nonzero,
                   "known_key_probes":probes,"probe_derivation":derivation,
                   "warning":"A hit supports a mapping candidate at that anchor. No hit does not disprove a mapping; nested mappings and struct offsets need explicit modelling."})
def unravel(args):
    p=argparse.ArgumentParser(prog="lk unravel"); p.add_argument("tx_hash"); p.add_argument("--rpc-url"); ns=p.parse_args(args)
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}",ns.tx_hash): raise ValueError("Transaction hash must be 32-byte hex.")
    trace=rpc(rpc_url(ns.rpc_url),"debug_traceTransaction",[ns.tx_hash,{"tracer":"callTracer"}],60)
    def walk(x,d=0):
        if not isinstance(x,dict): return []
        rows=[{"depth":d,"type":x.get("type"),"from":x.get("from"),"to":x.get("to"),"value":x.get("value"),"gasUsed":x.get("gasUsed"),"error":x.get("error"),"input":str(x.get("input") or "")[:74]}]
        for y in x.get("calls") or []: rows += walk(y,d+1)
        return rows
    return output({"tx_hash":ns.tx_hash,"call_tree":walk(trace)})
def state_diff(args):
    p=argparse.ArgumentParser(prog="lk state-diff"); p.add_argument("target"); p.add_argument("--before",required=True); p.add_argument("--after",required=True); p.add_argument("--slot",action="append",required=True); p.add_argument("--rpc-url"); ns=p.parse_args(args)
    url=rpc_url(ns.rpc_url); target=addr(ns.target); rows=[]
    for x in ns.slot:
        slot=x if x.startswith("0x") else hex(int(x))
        a=rpc(url,"eth_getStorageAt",[target,slot,ns.before if ns.before.startswith("0x") else hex(int(ns.before))])
        b=rpc(url,"eth_getStorageAt",[target,slot,ns.after if ns.after.startswith("0x") else hex(int(ns.after))])
        if a!=b: rows.append({"slot":slot,"before":a,"after":b})
    return output({"target":target,"changed_slots":rows,"count":len(rows)})
def attack_forge(args):
    p=argparse.ArgumentParser(prog="lk attack forge"); p.add_argument("attack_id"); p.add_argument("--target",required=True); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); target=addr(ns.target)
    try:
        try: from .attack_catalog import ATTACKS
        except ImportError: from attack_catalog import ATTACKS
    except Exception: ATTACKS=[]
    entry=next((x for x in ATTACKS if str(x.get("id","")).lower()==ns.attack_id.lower() or str(x.get("slug","")).lower()==ns.attack_id.lower()),None)
    if not entry: raise ValueError("Unknown attack ID/slug.")
    out=safe_out(root,".audit/attack-forge/"+str(entry["id"])+"/AttackHarness.template.t.sol")
    fixture=None
    try:
        try: from .attack_library import LAB_SNIPPETS
        except ImportError: from attack_library import LAB_SNIPPETS
        snippet=LAB_SNIPPETS.get(str(entry.get("slug") or ""))
        if snippet:
            fixture=safe_out(root,".audit/attack-forge/"+str(entry["id"])+"/VulnerableFixture.sol")
            fixture.write_text(str(snippet).rstrip()+"\n",encoding="utf-8")
    except (ImportError,AttributeError,TypeError):
        snippet=None
    out.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport \"forge-std/Test.sol\";\ncontract LowkeyAttackCandidate is Test {\n address constant TARGET = "+target+";\n function test_candidate() external { assertGt(TARGET.code.length, 0, \"no runtime code\"); /* add exact protocol invariant and impact */ }\n}\n",encoding="utf-8")
    attack={key:entry.get(key) for key in ("id","slug","title","category","severity","plain","pattern","audit_signal","local_lab","mitigation","references")}
    write_json(out.parent/"attack.json",{"attack":attack,"target":target,"fixture":str(fixture.relative_to(root)) if fixture else None,
      "status":"starter-needs-protocol-specific-predicate","proof":False,
      "required":["bind exact target ABI and function","set up realistic actors, permissions and asset state",
        "assert a measurable security-property violation","run the matched sequential control","validate test sensitivity with mutation",
        "record fork block, gas, fees, recipient delta and artifact hashes"]})
    (out.parent/"README.md").write_text("# Attack candidate: "+str(entry.get("title") or entry["id"])+"\n\n"+
       "Library metadata is preserved in attack.json. The generated harness only checks that the target has code; replace it with the actual exploit preconditions and measurable impact before treating it as a PoC.\n\n"+
       ("A local fixture snippet was included. Review it; do not assume it is byte-for-byte compatible with the live target.\n" if fixture else "No runnable fixture snippet exists for this catalogue entry yet.\n"),encoding="utf-8")
    print("Attack workspace: "+str(out.parent.relative_to(root)))
    print("Fixture: "+(str(fixture.relative_to(root)) if fixture else "none available"))
    print("Status: starter only; no exploit proof claimed.")
    return 0

def generate(args,kind):
    p=argparse.ArgumentParser(prog="lk "+kind); p.add_argument("profile",nargs="?",default="general"); p.add_argument("--root",default="."); ns=p.parse_args(args); root=root_path(ns.root); out=safe_out(root,f".audit/godmode/{kind}-{ns.profile}.md")
    templates={
      "invariant-forge":{"vault":["totalAssets >= totalSupply after matching units/fees","sum(user shares) == totalSupply"],"lending":["total debt reconciles with account debt","collateral and debt valuation obey liquidation rules"],"amm":["fee-adjusted invariant is preserved","pool balances reconcile with reserves"],"staking":["sum(user stake) == totalStaked","claimed rewards never exceed earned rewards"],"bridge":["message nonce consumed at most once","minted representation never exceeds finalized deposits"],"governance":["proposal executes at most once","vote weight counted once at declared snapshot"]},
      "archetype":{"vault":["deposit/withdraw/preview/share-inflation handlers","donation and rounding ghost state"],"lending":["borrow/repay/liquidate handlers","health-factor and bad-debt ghosts"],"amm":["swap/mint/burn/flash handlers","reserve and invariant ghosts"],"staking":["stake/unstake/claim handlers","reward-index and lockup ghosts"],"bridge":["send/relay/claim handlers","message nonce and finality ghosts"],"governance":["propose/vote/queue/execute handlers","snapshot and timelock ghosts"]}
    }
    if kind not in templates or ns.profile not in templates[kind]: raise ValueError("Unknown protocol profile.")
    out.write_text("# "+kind+" / "+ns.profile+"\n\n"+"".join("- [ ] "+x+"\n" for x in templates[kind][ns.profile])+"\nThese are candidates/starters. Bind the real protocol, actors, ghost state and assertions before running a proof engine.\n")
    print(f"Starter: {out.relative_to(root)}"); return 0
def token_weird(args):
    p=argparse.ArgumentParser(prog="lk token-weird"); p.add_argument("--root",default="."); ns=p.parse_args(args); root=root_path(ns.root)
    out=safe_out(root,".audit/godmode/token-weird/WeirdTokens.sol")
    out.write_text("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract WeirdERC20 {
 uint8 public decimals=18; uint256 public totalSupply; bool public paused; bool public returnFalse; uint256 public feeBps;
 mapping(address=>uint256) public balanceOf; mapping(address=>mapping(address=>uint256)) public allowance;
 mapping(address=>bool) public blocked; address public hook;
 function configure(uint8 d,uint256 fee,bool pause_,bool false_,address hook_) external {decimals=d;feeBps=fee;paused=pause_;returnFalse=false_;hook=hook_;}
 function setBlocked(address a,bool b) external {blocked[a]=b;}
 function mint(address a,uint256 n) external {balanceOf[a]+=n;totalSupply+=n;}
 function approve(address s,uint256 n) external returns(bool){allowance[msg.sender][s]=n;return true;}
 function transfer(address to,uint256 n) external returns(bool){if(returnFalse)return false;_move(msg.sender,to,n);return true;}
 function transferFrom(address f,address t,uint256 n) external returns(bool){if(returnFalse)return false;uint256 a=allowance[f][msg.sender];require(a>=n);allowance[f][msg.sender]=a-n;_move(f,t,n);return true;}
 function rebase(address account,int256 delta) external {if(delta>=0){balanceOf[account]+=uint256(delta);totalSupply+=uint256(delta);}else{uint256 cut=uint256(-delta);require(balanceOf[account]>=cut);balanceOf[account]-=cut;totalSupply-=cut;}}
 function _move(address f,address t,uint256 n) internal {require(!paused&&!blocked[f]&&!blocked[t]&&balanceOf[f]>=n);balanceOf[f]-=n;uint256 fee=n*feeBps/10000;balanceOf[t]+=n-fee;totalSupply-=fee;if(hook!=address(0)){(bool ok,)=hook.call(abi.encodeWithSignature("tokensReceived(address,address,address,uint256,bytes,bytes)",msg.sender,f,t,n,bytes(""),bytes("")));require(ok);}}
}
contract NoReturnERC20 {mapping(address=>uint256) public balanceOf;mapping(address=>mapping(address=>uint256)) public allowance;function mint(address a,uint n) external {balanceOf[a]+=n;}function approve(address s,uint n) external {allowance[msg.sender][s]=n;}function transfer(address a,uint n) external {require(balanceOf[msg.sender]>=n);balanceOf[msg.sender]-=n;balanceOf[a]+=n;}function transferFrom(address f,address t,uint n) external {require(allowance[f][msg.sender]>=n&&balanceOf[f]>=n);allowance[f][msg.sender]-=n;balanceOf[f]-=n;balanceOf[t]+=n;}}
contract WideDecimalsToken {uint256 public decimals=1000;mapping(address=>uint256) public balanceOf;function mint(address a,uint256 n) external {balanceOf[a]+=n;}function transfer(address to,uint256 n) external returns(bool){require(balanceOf[msg.sender]>=n);balanceOf[msg.sender]-=n;balanceOf[to]+=n;return true;}}
contract ERC1155ReceiverLike {function onERC1155Received(address,address,uint256,uint256,bytes calldata) external pure returns(bytes4){return this.onERC1155Received.selector;}function onERC1155BatchReceived(address,address,uint256[] calldata,uint256[] calldata,bytes calldata) external pure returns(bytes4){return this.onERC1155BatchReceived.selector;}}
contract ERC777ReceiverLike {function tokensReceived(address,address,address,uint256,bytes calldata,bytes calldata) external pure {}}
""")
    print(f"Hostile token fixtures: {out.relative_to(root)}"); print("Includes fee-on-transfer, explicit rebasing, false-return, no-return transfer/transferFrom, pause, blacklist, reentrant hooks, and ERC1155/777 receivers. WideDecimalsToken returns uint256(1000) deliberately; a standard IERC20Metadata decimals() returns uint8."); return 0
def run_control_alias(args): return control(args)
def run_control(args):
    """Entry point used by break_engine for the mandatory control gate."""
    return control(args)


def mutation(args):
    p=argparse.ArgumentParser(prog="lk mutation-score")
    p.add_argument("manifest")
    p.add_argument("--min-score",type=float,default=0.90)
    p.add_argument("--timeout",type=int,default=300)
    p.add_argument("--output",default=".audit/verification/mutation-score-report.json")
    ns=p.parse_args(args)
    if not 0.0<=ns.min_score<=1.0: raise ValueError("--min-score must be between 0 and 1.")
    try:
        try: from . import behavioral_validation
        except ImportError: import behavioral_validation
    except ImportError as exc: raise RuntimeError("Existing mutation runner unavailable: "+str(exc))
    rc=behavioral_validation.run_cli([ns.manifest,"--output",ns.output,"--timeout",str(ns.timeout)])
    if rc!=0:
        print("MUTATION GATE: FAIL (baseline or mutation campaign did not complete)")
        return rc
    report_path=Path(ns.output).expanduser()
    if not report_path.is_absolute(): report_path=Path.cwd()/report_path
    if not report_path.is_file(): raise RuntimeError("Mutation runner did not create its report: "+str(report_path))
    report=json.loads(report_path.read_text(encoding="utf-8"))
    score=report.get("mutation_score")
    passed=isinstance(score,(float,int)) and score>=ns.min_score
    print("MUTATION GATE: "+("PASS" if passed else "FAIL"))
    print("  Required: "+format(ns.min_score,".1%"))
    print("  Observed: "+(format(score,".1%") if isinstance(score,(int,float)) else "not available"))
    print("  Invalid/timeouts are excluded from the score and must be reviewed separately.")
    return 0 if passed else 1

def inspect_reproduction_command(root, argv):
    """Inspect the replay argv and referenced local scripts for state-fabricating RPCs."""
    patterns={
        "rpc_storage_override":r"\b(?:anvil|hardhat)_setStorageAt\b|\bevm_setAccountStorageAt\b",
        "rpc_balance_override":r"\b(?:anvil|hardhat)_setBalance\b|\bevm_setAccountBalance\b",
        "rpc_code_override":r"\b(?:anvil|hardhat)_setCode\b|\bevm_setAccountCode\b",
        "rpc_impersonation":r"\b(?:anvil|hardhat)_impersonateAccount\b|\bev[m]?_unlockUnknownAccount\b",
        "rpc_time_override":r"\b(?:anvil|hardhat)_setNextBlockTimestamp\b|\bevm_setNextBlockTimestamp\b|\b(?:anvil|hardhat)_setBlockTimestamp\b",
    }
    findings=[]
    inspected=[]
    candidates=[str(x) for x in argv]
    for token in candidates:
        for kind,pattern in patterns.items():
            for match in re.finditer(pattern,token,re.I):
                findings.append({"kind":kind,"source":"argv","token":match.group(0)})
        possible=Path(token).expanduser()
        if not possible.is_absolute():
            possible=(root/possible).resolve()
        else:
            possible=possible.resolve()
        if possible.is_relative_to(root) and possible.is_file() and possible not in inspected:
            inspected.append(possible)
            try: text_value=possible.read_text(encoding="utf-8",errors="replace")
            except OSError: continue
            for kind,pattern in patterns.items():
                for line_number,line in enumerate(text_value.splitlines(),1):
                    for match in re.finditer(pattern,line,re.I):
                        findings.append({"kind":kind,"source":possible.relative_to(root).as_posix(),
                                         "line":line_number,"token":match.group(0)})
    return {"inspected_scripts":[x.relative_to(root).as_posix() for x in inspected],
            "state_fabrication_calls":findings,
            "blocked":bool(findings),
            "policy":"Direct local RPC state/balance/code/time overrides and account impersonation are not accepted as fork-reproduction setup. Configure the attacker through real transactions instead."}


def reprove(args):
    p=argparse.ArgumentParser(prog="lk reprove")
    p.add_argument("harness"); p.add_argument("--root",default="."); p.add_argument("--rpc-url",required=True)
    p.add_argument("--fork-block",required=True,type=int); p.add_argument("--tx-hash")
    p.add_argument("--target-address",required=True); p.add_argument("--profit-address",action="append",required=True)
    p.add_argument("--source-rpc-url",help="Independent read-only archive RPC used to verify the fork anchor and real sender funding.")
    p.add_argument("--prestate-slot",action="append",default=[],help="Storage slot to compare between local fork and source, as ADDRESS:SLOT.")
    p.add_argument("--argv-json")
    ns=p.parse_args(args)
    root=root_path(ns.root); harness=(root/ns.harness).resolve()
    if not harness.is_relative_to(root) or not harness.is_file(): raise ValueError("Harness must be inside project.")
    url=rpc_url(ns.rpc_url)
    if not local_rpc(url): raise ValueError("Reproof accepts local Anvil fork endpoint only.")
    if ns.fork_block<0: raise ValueError("--fork-block must be non-negative.")
    fidelity=analyze_harness_fidelity(harness.read_text(encoding="utf-8",errors="replace"),harness.relative_to(root).as_posix())
    blockers=fidelity.get("fork_reproduction_blockers") or []
    if blockers:
        payload={"status":"SIMULATED_BREAK","command_run":False,"fidelity":fidelity,
                 "blocked_cheatcodes":blockers,
                 "reason":"Harness contains state-fabricating or environment-changing cheatcodes that are not allowed for fork reproduction."}
        write_json(safe_out(root,".audit/godmode/reprove.json"),payload); print(json.dumps(payload,indent=2)); return 1
    tx_hash=ns.tx_hash
    command_result=None
    execution_command={"inspected_scripts":[],"state_fabrication_calls":[],"blocked":False}
    if ns.argv_json:
        argv=json.loads(ns.argv_json)
        if not isinstance(argv,list) or not argv or not all(isinstance(x,str) for x in argv):
            raise ValueError("--argv-json must be a non-empty JSON string array.")
        execution_command=inspect_reproduction_command(root,argv)
        if execution_command["blocked"]:
            payload={"status":"SIMULATED_BREAK","command_run":False,"fidelity":fidelity,
                     "execution_command":execution_command,
                     "reason":"Replay script contains a local RPC state-fabrication call; configure actors through actual transactions."}
            write_json(safe_out(root,".audit/godmode/reprove.json"),payload); print(json.dumps(payload,indent=2)); return 1
        env=os.environ.copy(); env.update({"ETH_RPC_URL":url,"FOUNDRY_ETH_RPC_URL":url,"LOWKEY_RPC_URL":url})
        command_result=run(argv,root,900,env=env)
        if command_result.returncode:
            payload={"status":"UNPROVEN","command_run":True,"exit_code":command_result.returncode,
                     "stdout":command_result.stdout[-3000:],"stderr":command_result.stderr[-1500:],
                     "fidelity":fidelity,"reason":"Reproduction command did not complete successfully."}
            write_json(safe_out(root,".audit/godmode/reprove.json"),payload); print(json.dumps(payload,indent=2)); return 1
        hashes=re.findall(r"LOWKEY_TRACE_TX_HASH\s+(0x[0-9a-fA-F]{64})",command_result.stdout+"\n"+command_result.stderr)
        if len(hashes)!=1: raise ValueError("Reproof command must emit exactly one LOWKEY_TRACE_TX_HASH for the transaction it just executed.")
        if tx_hash and tx_hash.lower()!=hashes[0].lower():
            raise ValueError("--tx-hash does not match the transaction emitted by --argv-json.")
        tx_hash=hashes[0]
    if not tx_hash or not re.fullmatch(r"0x[0-9a-fA-F]{64}",tx_hash):
        raise ValueError("Supply --tx-hash or make --argv-json emit LOWKEY_TRACE_TX_HASH <32-byte hash>.")
    tx_hash=tx_hash.lower()
    tx=rpc(url,"eth_getTransactionByHash",[tx_hash])
    receipt=rpc(url,"eth_getTransactionReceipt",[tx_hash])
    if not isinstance(tx,dict) or not isinstance(receipt,dict):
        raise ValueError("Transaction hash is not mined on this Anvil node.")
    if str(receipt.get("status") or "").lower() not in {"0x1","1"}:
        raise ValueError("Reproof transaction reverted.")
    block_number=int(str(receipt.get("blockNumber") or "0x0"),16)
    tx_index=int(str(receipt.get("transactionIndex") or "0x0"),16)
    if block_number!=ns.fork_block+1 or tx_index!=0:
        raise ValueError("For a precise fork reproof, the tested transaction must be the first and only transaction in the block immediately after --fork-block.")
    parent=rpc(url,"eth_getBlockByNumber",[hex(ns.fork_block),False])
    if not isinstance(parent,dict) or not parent.get("hash"):
        raise ValueError("The declared fork parent block is unavailable from this RPC.")
    block=rpc(url,"eth_getBlockByNumber",[hex(block_number),False])
    block_txs=[str(x).lower() for x in ((block or {}).get("transactions") or [])]
    if block_txs!=[tx_hash]:
        raise ValueError("The tested transaction must be the only transaction in its block.")
    chain_id=rpc(url,"eth_chainId",[])
    target=addr(ns.target_address)
    profit_addresses=sorted({addr(x) for x in ns.profit_address})
    if not profit_addresses: raise ValueError("At least one --profit-address is required.")
    source_verification={"verified":False,"reason":"No independent source archive RPC was supplied; result is local-only."}
    if ns.source_rpc_url:
        if not ns.argv_json:
            raise ValueError("Source-verified FORK_REPRODUCED/PROFITABLE status requires --argv-json so the replay command can be inspected.")
        source_url=rpc_url(ns.source_rpc_url)
        if local_rpc(source_url) or urlparse(source_url).hostname==urlparse(url).hostname:
            raise ValueError("--source-rpc-url must be an independent non-local source endpoint, not the local Anvil node.")
        source_chain_id=rpc(source_url,"eth_chainId",[])
        source_parent=rpc(source_url,"eth_getBlockByNumber",[hex(ns.fork_block),False])
        if str(source_chain_id).lower()!=str(chain_id).lower():
            raise ValueError("Local Anvil chain ID does not match the independent source RPC.")
        if not isinstance(source_parent,dict) or str(source_parent.get("hash") or "").lower()!=str(parent.get("hash") or "").lower():
            raise ValueError("Local Anvil parent block hash does not match the independent source chain at --fork-block.")
        local_target_code=rpc(url,"eth_getCode",[target,hex(ns.fork_block)])
        source_target_code=rpc(source_url,"eth_getCode",[target,hex(ns.fork_block)])
        if not local_target_code or local_target_code=="0x" or str(local_target_code).lower()!=str(source_target_code or "").lower():
            raise ValueError("Target bytecode on the local fork does not match the independent source chain at --fork-block.")
        if not ns.prestate_slot:
            raise ValueError("Source-verified fork reproduction requires at least one --prestate-slot for the target's accounting or authorization state.")
        checked_slots=[]
        for raw_slot in ns.prestate_slot:
            if ":" not in raw_slot: raise ValueError("--prestate-slot must use ADDRESS:SLOT.")
            raw_address,raw_slot_value=raw_slot.split(":",1)
            slot_address=addr(raw_address)
            if slot_address!=target:
                raise ValueError("Source-verified reproof slots must belong to --target-address.")
            slot_value=raw_slot_value.lower()
            if re.fullmatch(r"0x[0-9a-f]{64}",slot_value) is None:
                try: slot_value=hex(int(slot_value,0))
                except ValueError: raise ValueError("Invalid --prestate-slot slot value.")
            local_value=rpc(url,"eth_getStorageAt",[slot_address,slot_value,hex(ns.fork_block)])
            source_value=rpc(source_url,"eth_getStorageAt",[slot_address,slot_value,hex(ns.fork_block)])
            if str(local_value).lower()!=str(source_value).lower():
                raise ValueError(f"Pre-state slot {slot_address}:{slot_value} differs between local fork and source chain.")
            checked_slots.append({"address":slot_address,"slot":slot_value,"value":local_value})
        source_sender_balance=int(str(rpc(source_url,"eth_getBalance",[str(tx.get("from")).lower(),hex(ns.fork_block)])),16)
        source_profit_balances=[]
        for address in profit_addresses:
            local_balance=int(str(rpc(url,"eth_getBalance",[address,hex(ns.fork_block)])),16)
            source_balance=int(str(rpc(source_url,"eth_getBalance",[address,hex(ns.fork_block)])),16)
            if local_balance!=source_balance:
                raise ValueError(f"Profit account {address} has a different fork-block balance on local Anvil and the independent source chain.")
            source_profit_balances.append({"address":address,"balance_wei":source_balance})
        source_verification={"verified":True,"source_chain_id":source_chain_id,
                             "source_parent_hash":source_parent.get("hash"),
                             "target_code_sha256":hashlib.sha256(bytes.fromhex(str(source_target_code).removeprefix("0x"))).hexdigest(),
                             "sender_balance_at_fork_wei":source_sender_balance,
                             "profit_account_balances":source_profit_balances,
                             "prestate_slots":checked_slots}
    trace=rpc(url,"debug_traceTransaction",[tx_hash,{"tracer":"callTracer"}],60)
    if not isinstance(trace,dict): raise ValueError("The node did not return a callTracer execution trace.")
    tx_digest,entry=_control_entry_digest(tx,chain_id)
    trace_digest,_=_control_entry_digest(trace,chain_id)
    if tx_digest!=trace_digest: raise ValueError("CallTracer root does not match the mined transaction.")
    calls=_trace_flatten(trace)
    if target not in {x.get("to") for x in calls}:
        raise ValueError("The transaction trace did not call --target-address.")
    sender=str(tx.get("from") or "").lower()
    if sender not in profit_addresses:
        # If the gas payer is omitted from the measured portfolio, subtract its actual fee explicitly below.
        subtract_fee=True
    else:
        subtract_fee=False
    before_total=0; after_total=0; balances=[]
    for address in profit_addresses:
        before=int(str(rpc(url,"eth_getBalance",[address,hex(ns.fork_block)])),16)
        after=int(str(rpc(url,"eth_getBalance",[address,hex(block_number)])),16)
        before_total+=before; after_total+=after
        balances.append({"address":address,"before_wei":before,"after_wei":after,"delta_wei":after-before})
    gas_used=int(str(receipt.get("gasUsed") or "0x0"),16)
    gas_price=receipt.get("effectiveGasPrice") or tx.get("gasPrice") or "0x0"
    effective_gas_price=int(str(gas_price),16)
    gas_cost=gas_used*effective_gas_price
    if source_verification["verified"] and source_verification["sender_balance_at_fork_wei"]<gas_cost:
        raise ValueError("Transaction sender did not have enough native ETH on the source chain to pay the measured gas cost.")
    gross_delta=after_total-before_total
    net_profit=gross_delta-gas_cost if subtract_fee else gross_delta
    if command_result is None:
        final_status="LOCAL_TRACE_ONLY"
    elif source_verification["verified"]:
        final_status="PROFITABLE" if net_profit>0 else "FORK_REPRODUCED"
    else:
        final_status="LOCAL_PROFITABLE" if net_profit>0 else "LOCAL_REPRODUCED"
    fidelity_label="real_funded"
    if fidelity.get("synthetic_state"):
        fidelity_label="synthetic_state"
    elif any(signal.get("kind")=="caller_impersonation" for signal in fidelity.get("signals",[])):
        fidelity_label="simulated_caller"
    elif any(signal.get("kind")=="external_call_mock" for signal in fidelity.get("signals",[])):
        fidelity_label="simulated_dependencies"
    proof_outcome="profitable" if net_profit>0 else "observed"
    try:
        try:
            from . import proof_evidence
        except ImportError:
            import proof_evidence
        proof_axes=proof_evidence.classify_proof(
            "forked_deployment" if source_verification.get("verified") else "unknown",
            fidelity_label,
            proof_outcome,
            authenticity_verified=bool(source_verification.get("verified")),
        )
    except Exception as exc:
        proof_axes={
            "status":"OBSERVED","target_authenticity":"unknown","fidelity":fidelity_label,
            "outcome":proof_outcome,"policy_error":str(exc),
        }
    payload={
        "status":proof_axes["status"],
        "proof_status":proof_axes["status"],
        "legacy_status":final_status,
        "proof_axes":proof_axes,
        "command_run":bool(command_result),
        "exit_code":command_result.returncode if command_result else None,
        "tx_hash":tx_hash,"chain_id":chain_id,"fork_parent_block":ns.fork_block,
        "source_fork_verification":source_verification,
        "transaction_block":block_number,"transaction_index":tx_index,
        "target_address":target,"entry_call":entry,"entry_call_sha256":tx_digest,
        "call_trace":calls,"receipt_status":receipt.get("status"),
        "gas_used":gas_used,"effective_gas_price_wei":effective_gas_price,"gas_cost_wei":gas_cost,
        "profit_addresses":balances,"gross_balance_delta_wei":gross_delta,
        "net_profit_wei":net_profit,
        "fidelity":fidelity,
        "fidelity_label":fidelity_label,
        "target_authenticity":"forked_deployment" if source_verification.get("verified") else "unknown",
        "outcome":proof_outcome,
        "execution_command":execution_command,
        "promotion_policy":{
            "FORK_REPRODUCED":"Block-pinned parent state, real mined local Anvil transaction, successful receipt, callTracer match, declared target reached, no synthetic funding/storage/code/mock/time/caller cheatcodes.",
            "PROFITABLE":"FORK_REPRODUCED plus measured portfolio balance delta net of actual transaction gas is positive.",
            "HUMAN_CONFIRMED":"Never assigned automatically; requires explicit human disposition in the evidence ledger.",
        },
        "human_confirmation_required":True,
        "limitations":["Native-ETH balance accounting only; ERC20/ERC4626 share profit requires token-specific balance measurement.",
                       "Without --source-rpc-url, this is a local Anvil reproduction only, not an independently verified source-chain fork.",
                       "An independent source check verifies chain ID, parent block hash, target bytecode, and transaction-sender ETH balance; it does not prove that every dependency or storage slot is identical.",
                       "A replayed transaction proves only the tested path and state; it is not a completeness guarantee."],
    }
    out=safe_out(root,".audit/godmode/reprove.json"); write_json(out,payload)
    print(json.dumps(payload,indent=2))
    return 0

def fork_cache(args):
    p=argparse.ArgumentParser(prog="lk fork-cache"); p.add_argument("action",choices=("snapshot","revert","list")); p.add_argument("--id"); p.add_argument("--rpc-url"); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); f=safe_out(root,".audit/godmode/fork-cache.json"); data=json.loads(f.read_text()) if f.exists() else {}
    if ns.action=="list": return output(data)
    url=rpc_url(ns.rpc_url)
    if not local_rpc(url): raise ValueError("Fork cache is local Anvil only.")
    if ns.action=="snapshot":
        sid=rpc(url,"evm_snapshot",[]); data[str(sid)]={"snapshot_id":sid,"block":rpc(url,"eth_blockNumber",[]),"chain_id":rpc(url,"eth_chainId",[]),"created_at":now()}
        write_json(f,data); print("Snapshot "+str(sid)); return 0
    if ns.id not in data: raise ValueError("Snapshot ID not found.")
    ok=rpc(url,"evm_revert",[ns.id]); data.pop(ns.id,None) if ok else None; write_json(f,data); print("Reverted: "+str(bool(ok))); return 0 if ok else 1
def questions(args):
    p=argparse.ArgumentParser(prog="lk questions"); p.add_argument("action",nargs="?",default="current"); p.add_argument("--root",default="."); p.add_argument("note",nargs="*"); ns=p.parse_args(args)
    try:
        try: from . import question_engine
        except ImportError: import question_engine
        return question_engine.run({},[ns.action,*ns.note],root=root_path(ns.root),mode="current")
    except ImportError as exc: raise RuntimeError(str(exc))
def learn(args):
    p=argparse.ArgumentParser(prog="lk learn"); p.add_argument("--kind",default="protocol-pattern",choices=("protocol-pattern","test-procedure","tool-configuration","project-fact","false-positive-rule")); p.add_argument("--title",required=True); p.add_argument("--lesson",required=True); p.add_argument("--evidence",required=True); p.add_argument("--when",default=""); p.add_argument("--rationale",default=""); p.add_argument("--root",default="."); ns=p.parse_args(args)
    try:
        try: from . import experience_memory
        except ImportError: import experience_memory
        root=root_path(ns.root); old=Path.cwd()
        try:
            os.chdir(root)
            return experience_memory.main(["propose","--kind",ns.kind,"--title",ns.title,"--lesson",ns.lesson,"--evidence",ns.evidence,"--when",ns.when,"--rationale",ns.rationale])
        finally: os.chdir(old)
    except ImportError as exc: raise RuntimeError(str(exc))
def godmode(args):
    p=argparse.ArgumentParser(prog="lk godmode"); p.add_argument("target",nargs="?"); p.add_argument("--root",default="."); p.add_argument("--rpc-url"); p.add_argument("--profile",choices=("light","balanced","deep"),default="balanced"); p.add_argument("--attack",action="store_true"); p.add_argument("--control-manifest"); p.add_argument("--mutation-manifest"); p.add_argument("--coverage-source"); p.add_argument("--plan-only",action="store_true"); ns=p.parse_args(args)
    root=root_path(ns.root); target=addr(ns.target) if ns.target else None; maps=source_maps(root); cheat=cheat_fingerprints(root); stages=[]
    stages.append({"name":"source-recon","status":"completed","signals":sum(len(v) for v in maps.values() if isinstance(v,list))})
    stages.append({"name":"cheat-fingerprints","status":"completed","hits":len(cheat["hits"])})
    chain=block=None; onchain={}
    if target:
        try:
            url=rpc_url(ns.rpc_url); chain=rpc(url,"eth_chainId",[]); block=rpc(url,"eth_blockNumber",[])
            onchain={"proxy":proxy(target,url,40 if ns.profile=="light" else 120),"selectors":selectors(target,url)}
            stages.append({"name":"onchain-recon","status":"completed","selectors":onchain["selectors"]["count"]})
        except Exception as exc: stages.append({"name":"onchain-recon","status":"blocked","reason":str(exc)})
    else: stages.append({"name":"onchain-recon","status":"skipped","reason":"No address supplied."})
    if ns.attack:
        if not target: stages.append({"name":"attack","status":"blocked","reason":"Target address required."})
        elif not ns.rpc_url or not local_rpc(rpc_url(ns.rpc_url)): stages.append({"name":"attack","status":"blocked","reason":"Attack requires local Anvil fork RPC; production RPC is rejected."})
        elif not shutil.which("lk"): stages.append({"name":"attack","status":"blocked","reason":"lk command not found."})
        else:
            argv=["lk","break","--system","--until-found"]
            if ns.control_manifest: argv += ["--control-manifest",ns.control_manifest]
            proc=run(argv,root,1800); stages.append({"name":"attack","status":"review","exit_code":proc.returncode,"output":(proc.stdout+proc.stderr)[-3000:]})
    else: stages.append({"name":"attack","status":"not-run","reason":"Pass --attack to execute only on local Anvil."})
    if ns.control_manifest: stages.append({"name":"control","status":"provided","manifest":ns.control_manifest})
    else: stages.append({"name":"control","status":"not-run","reason":"No sequential-control manifest; BREAK remains ineligible."})
    if ns.mutation_manifest:
        old=Path.cwd()
        try: os.chdir(root); rc=mutation([ns.mutation_manifest])
        finally: os.chdir(old)
        stages.append({"name":"mutation","status":"completed" if rc==0 else "review","exit_code":rc})
    else: stages.append({"name":"mutation","status":"not-run","reason":"No mutation manifest."})
    if ns.coverage_source:
        old=Path.cwd()
        try: os.chdir(root); rc=coverage([ns.coverage_source,"--root",str(root)])
        finally: os.chdir(old)
        stages.append({"name":"target-coverage","status":"completed" if rc==0 else "review","exit_code":rc})
    else: stages.append({"name":"target-coverage","status":"not-run","reason":"No target source line scope."})
    blockers=[s for s in stages if s["status"] in {"blocked","review","not-run","skipped"}]
    payload={"created_at":now(),"target":target,"project_root":str(root),"git_revision":None,"chain_id":chain,"fork_block":block,
             "profile":ns.profile,"stages":stages,"signals":maps,"cheat_fingerprints":cheat,
             "onchain":onchain,"overall_status":"REVIEW_REQUIRED",
             "proof_gate":["attack must demonstrate a measurable security-property delta","matched sequential control must pass",
               "target lines must be covered","harness mutation score must meet threshold","net profit must remain positive after costs",
               "reproof must not depend on state-fabricating cheatcodes"]}
    out=safe_out(root,".audit/godmode/latest.json"); write_json(out,payload)
    prov=safe_out(root,".audit/godmode/provenance.json"); write_json(prov,{"created_at":now(),"sha256":hashlib.sha256(out.read_bytes()).hexdigest(),"chain_id":chain,"fork_block":block,"artifacts":["latest.json"]})
    print("GODMODE: "+payload["overall_status"])
    for s in stages: print("  ["+s["status"].upper()+"] "+s["name"]+": "+str(s.get("reason",s.get("signals",s.get("output",""))))[:190])
    print("Report: "+str(out.relative_to(root))); return 2 if blockers else 0
def report(args):
    p=argparse.ArgumentParser(prog="lk report")
    p.add_argument("--root",default="."); p.add_argument("--input",default=".audit/godmode/latest.json")
    p.add_argument("--output",default=".audit/godmode/report.md"); ns=p.parse_args(args)
    root=root_path(ns.root); src=(root/ns.input).resolve()
    if not src.is_relative_to(root) or not src.is_file(): raise ValueError("Report input not found inside project.")
    data=json.loads(src.read_text(encoding="utf-8"))
    lines=["# Lowkey Security Audit Report","",f"Generated: {now()}",
           f"Overall status: **{data.get('overall_status','REVIEW_REQUIRED')}**",
           f"Target: {data.get('target') or 'source workspace'}",
           f"Chain ID: {data.get('chain_id') or 'not recorded'}",
           f"Fork block: {data.get('fork_block') or 'not recorded'}","",
           "## Scope and execution stages"]
    for stage in data.get("stages",[]):
        lines.append("- **"+str(stage.get("name"))+" — "+str(stage.get("status"))+"**: "+str(stage.get("reason",stage.get("output",stage.get("signals","")))))
    lines += ["","## Findings",""]
    findings=data.get("findings") or []
    if not findings:
        lines.append("No validated findings are recorded in this run. The source maps below are leads, not reportable vulnerabilities.")
    for index,finding in enumerate(findings,1):
        lines += [f"### {index}. {finding.get('title','Untitled finding')}","",
          f"- **Severity:** {finding.get('severity','Needs human review')}",
          f"- **Severity rubric:** {finding.get('severity_rubric','Not supplied')}",
          f"- **Affected asset / contract:** {finding.get('asset',finding.get('target','Not supplied'))}",
          f"- **Impact:** {finding.get('impact','Not supplied')}",
          f"- **Attacker prerequisites:** {finding.get('prerequisites','Not supplied')}",
          f"- **Fork block:** {finding.get('fork_block',data.get('fork_block','Not supplied'))}",
          f"- **Gas used:** {finding.get('gas_used','Not measured')}",
          f"- **Gross profit:** {finding.get('gross_profit','Not measured')}",
          f"- **Net profit:** {finding.get('net_profit','Not measured')}",
          f"- **Harness:** {finding.get('harness','Not supplied')}",
          f"- **Control evidence:** {finding.get('control_evidence','Not supplied')}",
          f"- **Recommendation:** {finding.get('recommendation','Not supplied')}","",
          "**Reproduction steps**",""]
        steps=finding.get("reproduction_steps") or []
        lines += [f"{n}. {step}" for n,step in enumerate(steps,1)] if steps else ["Not supplied."]
        lines.append("")
    lines += ["## Reconnaissance signals",""]
    for group,rows in (data.get("signals") or {}).items():
        lines += ["### "+group]
        if not rows: lines.append("- No matching source signals observed.")
        for row in rows[:100]:
            lines.append("- "+str(row.get("file",""))+":"+str(row.get("line",""))+" "+
                         str(row.get("kind",row.get("function",row.get("variables","signal"))))+
                         ": "+str(row.get("text",row.get("variables",""))))
        lines.append("")
    lines += ["## Proof limitations",
      "- Static matches, selector guesses, generated templates and source-level order are leads, not findings.",
      "- A candidate BREAK requires a matching sequential control with a positive measured delta.",
      "- Target-line coverage and mutation score measure harness reachability and sensitivity; neither alone proves impact.",
      "- Net economics must account for gas, pool fees, slippage, financing and realistic recipient balance changes.",
      "- Local-fork reproduction is not permission to broadcast; no production transaction is sent by this report command.",""]
    out=safe_out(root,ns.output); out.write_text("\n".join(lines),encoding="utf-8")
    digest=sha(out); sidecar=out.with_suffix(out.suffix+".sha256"); sidecar.write_text(digest+"  "+out.name+"\n",encoding="utf-8")
    print("Report: "+str(out.relative_to(root))); print("SHA-256: "+digest); return 0

def provenance_cli(args): return provenance(args)

def calldata_mine(args):
    p=argparse.ArgumentParser(prog="lk calldata-mine"); p.add_argument("target"); p.add_argument("hash_file"); p.add_argument("--rpc-url"); ns=p.parse_args(args)
    target=addr(ns.target); url=rpc_url(ns.rpc_url); hashes=[]
    for line in Path(ns.hash_file).expanduser().read_text(encoding="utf-8").splitlines():
        value=line.strip()
        if re.fullmatch(r"0x[0-9a-fA-F]{64}",value): hashes.append(value)
    rows=[]; grouped={}
    for tx_hash in dict.fromkeys(hashes):
        tx=rpc(url,"eth_getTransactionByHash",[tx_hash])
        if not tx or str(tx.get("to") or "").lower()!=target: continue
        data=str(tx.get("input") or "0x"); selector=data[:10] if len(data)>=10 else None
        row={"tx_hash":tx_hash,"selector":selector,"calldata_bytes":max(0,(len(data)-2)//2),
             "from":tx.get("from"),"value":tx.get("value"),"block":tx.get("blockNumber")}
        rows.append(row); grouped.setdefault(selector,[]).append(row)
    return output({"target":target,"supplied_hashes":len(hashes),"matched_transactions":len(rows),
                   "deduplicated_selectors":grouped,
                   "limitation":"The supplied transaction list is the discovery boundary; full address history needs an explorer/indexer adapter."})

def gas_ladder(args):
    p=argparse.ArgumentParser(prog="lk gas-ladder"); p.add_argument("manifest"); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); mf=(root/ns.manifest).resolve()
    if not mf.is_relative_to(root) or not mf.is_file(): raise ValueError("Gas-ladder manifest must be inside the project.")
    spec=json.loads(mf.read_text()); template=spec.get("argv")
    if not isinstance(template,list) or not all(isinstance(x,str) for x in template): raise ValueError("manifest.argv must be an argv array containing {n}.")
    if not any("{n}" in x for x in template): raise ValueError("At least one argv entry must contain {n}.")
    low=int(spec.get("min",1)); high=int(spec.get("max",10000))
    if low<0 or high<low or high-low>10_000_000: raise ValueError("Invalid search range (0..10,000,000).")
    marker=re.compile(str(spec.get("oom_regex") or r"(?:out of gas|gas required exceeds allowance|\bOOG\b)"),re.I)
    timeout=int(spec.get("timeout_seconds",300)); trials=[]
    # First establish a non-OOG lower baseline and a failing upper bound.
    def measure(n):
        argv=[x.replace("{n}",str(n)) for x in template]; proc=run(argv,root,timeout); text=proc.stdout+"\n"+proc.stderr
        hit=bool(marker.search(text))
        trials.append({"n":n,"exit_code":proc.returncode,"oom":hit,"tail":text[-1200:]})
        return hit
    if low==high:
        first=measure(low)
        threshold=low if first else None
    else:
        high_hit=measure(high)
        if not high_hit: threshold=None
        else:
            lo_hit=measure(low)
            if lo_hit: threshold=low
            else:
                left,right=low,high
                while right-left>1:
                    mid=(left+right)//2
                    if measure(mid): right=mid
                    else: left=mid
                threshold=right
    payload={"first_reported_oom_size":threshold,"trials":trials,
             "meaning":"First size matching the declared OOG marker, only within this harness and environment.",
             "warning":"A revert, failed build, generic nonzero exit or timeout is not automatically counted as out-of-gas."}
    write_json(safe_out(root,".audit/godmode/gas-ladder.json"),payload); print(json.dumps(payload,indent=2)); return 0 if threshold is not None else 2

def symbolic_path(args):
    p=argparse.ArgumentParser(prog="lk path"); p.add_argument("manifest"); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); mf=(root/ns.manifest).resolve()
    if not mf.is_relative_to(root) or not mf.is_file(): raise ValueError("Path manifest must be inside the project.")
    spec=json.loads(mf.read_text()); argv=spec.get("argv")
    if not isinstance(argv,list) or not argv or not all(isinstance(x,str) for x in argv): raise ValueError("Manifest requires explicit argv, e.g. [\"halmos\", \"--function\", \"check_withdraw\"].")
    if not shutil.which(argv[0]): print("BLOCKED: symbolic engine "+argv[0]+" is not installed."); return 2
    proc=run(argv,root,int(spec.get("timeout_seconds",600))); print(proc.stdout,end="")
    if proc.stderr: print(proc.stderr,file=sys.stderr,end="")
    print("Symbolic execution is path-planning evidence, not an exploit proof.")
    return proc.returncode

def watch(args):
    p=argparse.ArgumentParser(prog="lk watch"); p.add_argument("target"); p.add_argument("--rpc-url"); p.add_argument("--count",type=int,default=1); p.add_argument("--interval",type=float,default=3); ns=p.parse_args(args)
    target=addr(ns.target); url=rpc_url(ns.rpc_url)
    if not 1<=ns.count<=100 or not 0<=ns.interval<=60: raise ValueError("Bounded watch accepts count 1..100 and interval 0..60 seconds.")
    checks=[]; previous=None
    for i in range(ns.count):
        code=rpc(url,"eth_getCode",[target,"latest"]); block=rpc(url,"eth_blockNumber",[])
        digest=hashlib.sha256(bytes.fromhex(code[2:])).hexdigest() if code and code!="0x" else None
        checks.append({"block":block,"code_hash":digest,"has_code":bool(digest),"changed":i>0 and digest!=previous})
        previous=digest
        if i+1<ns.count: time.sleep(ns.interval)
    payload={"target":target,"checks":checks,"mode":"bounded-one-shot",
             "note":"Runtime bytecode only. No persistent daemon, TVL feed, deployment indexer or automatic TVL-risk estimate is configured."}
    print(json.dumps(payload,indent=2)); return 0

def upgrade_diff(args):
    p=argparse.ArgumentParser(prog="lk upgrade-diff"); p.add_argument("old_address"); p.add_argument("new_address"); p.add_argument("--rpc-url"); p.add_argument("--old-layout"); p.add_argument("--new-layout"); ns=p.parse_args(args)
    url=rpc_url(ns.rpc_url); old=addr(ns.old_address); new=addr(ns.new_address)
    a=rpc(url,"eth_getCode",[old,"latest"]); b=rpc(url,"eth_getCode",[new,"latest"])
    old_selectors=set(push4(a or "0x")); new_selectors=set(push4(b or "0x")); layout={"status":"not-supplied"}
    if ns.old_layout and ns.new_layout:
        before=json.loads(Path(ns.old_layout).expanduser().read_text()); after=json.loads(Path(ns.new_layout).expanduser().read_text())
        aa=before.get("storageLayout",before).get("storage",[]); bb=after.get("storageLayout",after).get("storage",[])
        am={(str(x.get("slot")),str(x.get("offset"))):x for x in aa}; bm={(str(x.get("slot")),str(x.get("offset"))):x for x in bb}
        layout={"removed":[v for k,v in am.items() if k not in bm],
                "changed":[v for k,v in am.items() if k in bm and (v.get("type")!=bm[k].get("type") or v.get("label")!=bm[k].get("label"))],
                "added":[v for k,v in bm.items() if k not in am],"status":"compare"}
    return output({"old":old,"new":new,"old_code_hash":hashlib.sha256(bytes.fromhex(a[2:])).hexdigest(),
                   "new_code_hash":hashlib.sha256(bytes.fromhex(b[2:])).hexdigest(),
                   "added_selectors":sorted(new_selectors-old_selectors),"removed_selectors":sorted(old_selectors-new_selectors),
                   "storage_layout":layout,"warning":"PUSH4 extraction is a candidate selector set and can include constants. Use compiler storage layout before judging compatibility."})

def verify_hack(args):
    p=argparse.ArgumentParser(prog="lk verify-hack"); p.add_argument("tx_hash"); p.add_argument("--rpc-url",required=True); p.add_argument("--block",type=int,required=True); ns=p.parse_args(args)
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}",ns.tx_hash) or ns.block<1: raise ValueError("Supply a transaction hash and positive attacked block.")
    tx=rpc(rpc_url(ns.rpc_url),"eth_getTransactionByHash",[ns.tx_hash])
    if not tx: raise RuntimeError("Transaction not found on this RPC.")
    actual=int(str(tx.get("blockNumber") or "0x0"),16)
    if actual!=ns.block: raise ValueError(f"Transaction is in block {actual}, not declared block {ns.block}.")
    print(json.dumps({"tx_hash":ns.tx_hash,"attacked_block":ns.block,"required_fork_block":ns.block-1,
                   "from":tx.get("from"),"to":tx.get("to"),"input":tx.get("input"),"value":tx.get("value"),
                   "status":"replay-harness-required",
                   "next":"Fork at block N-1, replay the exact attacker sequence, and compare recipient/target balances. This lookup does not reproduce the hack."}, indent=2))
    return 2

def compose(args):
    p=argparse.ArgumentParser(prog="lk compose"); p.add_argument("--root",default="."); ns=p.parse_args(args); root=root_path(ns.root); m=source_maps(root)
    nodes=[{"id":"attacker","kind":"actor"},{"id":"asset","kind":"asset-impact","status":"not-measured"}]; edges=[]
    signals=[("reentrancy",m["reentrancy_graph"]),("oracle",m["oracle_map"]),("signature",m["signature_map"]),("custody",m["custody_map"]),("initializer",m["initializer_map"])]
    index=0
    for kind,rows in signals:
        for row in rows:
            ident=kind+"-"+str(index); index+=1
            nodes.append({"id":ident,"kind":kind,"source":row})
            edges.append({"from":"attacker","to":ident,"relationship":"candidate reachability"})
            edges.append({"from":ident,"to":"asset","relationship":"impact must be measured"})
    payload={"nodes":nodes,"edges":edges,"candidate_signal_count":index,
             "profitability":"not-computed","warning":"No path is profitable until an executable adapter measures asset gain after gas, fees and slippage."}
    write_json(safe_out(root,".audit/godmode/compose.json"),payload); return output(payload)

def skew_plan(args):
    p=argparse.ArgumentParser(prog="lk skew"); p.add_argument("manifest"); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); mf=(root/ns.manifest).resolve()
    if not mf.is_relative_to(root) or not mf.is_file(): raise ValueError("Skew manifest must be inside the project.")
    spec=json.loads(mf.read_text()); required=("pool","asset","oracle_read","consumer_call","amounts")
    missing=[x for x in required if x not in spec]
    if missing: raise ValueError("Missing skew manifest fields: "+", ".join(missing))
    plan={"manifest_hash":sha(mf),"pool":spec["pool"],"asset":spec["asset"],"oracle_read":spec["oracle_read"],
          "consumer_call":spec["consumer_call"],"amounts":spec["amounts"],
          "required_assertions":["oracle deviation at the point of consumption","downstream debt/mint/withdraw impact",
            "attacker recipient delta","pool unwind and residual loss","gas, pool fee and slippage deducted"],
          "status":"adapter-and-harness-required"}
    write_json(safe_out(root,".audit/godmode/skew-plan.json"),plan); return output(plan)

def flashmax(args):
    p=argparse.ArgumentParser(prog="lk flashmax"); p.add_argument("venue",choices=("aave","balancer","uniswap-v3")); p.add_argument("asset"); p.add_argument("--adapter",required=True); p.add_argument("--rpc-url"); ns=p.parse_args(args)
    asset=addr(ns.asset); spec=json.loads(Path(ns.adapter).expanduser().read_text())
    if str(spec.get("venue","")).lower()!=ns.venue or str(spec.get("asset","")).lower()!=asset: raise ValueError("Adapter venue/asset must match command.")
    pool=addr(str(spec.get("pool") or "")); calldata=str(spec.get("liquidity_call") or "")
    if not re.fullmatch(r"0x[0-9a-fA-F]*",calldata): raise ValueError("Adapter liquidity_call must be explicit 0x calldata.")
    raw=rpc(rpc_url(ns.rpc_url),"eth_call",[{"to":pool,"data":calldata},"latest"])
    liquidity=int(raw,16) if raw and raw!="0x" else 0
    callback={"aave":"executeOperation","balancer":"receiveFlashLoan","uniswap-v3":"uniswapV3FlashCallback"}[ns.venue]
    return output({"venue":ns.venue,"asset":asset,"pool":pool,"liquidity_raw":liquidity,
                   "fee_bps":spec.get("fee_bps"),"max_borrow_raw":liquidity,
                   "callback":callback,"status":"liquidity-read-only",
                   "warning":"Adapter must encode the right reserve/liquidity read and fee. This does not borrow, deploy a callback, or prove a profitable attack."})

def agent_split(args):
    p=argparse.ArgumentParser(prog="lk agent-split"); p.add_argument("--root",default="."); p.add_argument("--harness"); ns=p.parse_args(args)
    root=root_path(ns.root); m=source_maps(root); cheat=[]
    if ns.harness:
        h=(root/ns.harness).resolve()
        if not h.is_relative_to(root) or not h.is_file(): raise ValueError("Harness must be inside project.")
        rx=re.compile(r"\bvm\.(?:deal|store|etch|mockCall|warp|roll)\s*\(")
        cheat=[{"line":i,"text":line.strip()} for i,line in enumerate(h.read_text(errors="replace").splitlines(),1) if rx.search(line)]
    payload={"planner":{"candidate_reentrancy_paths":len(m["reentrancy_graph"]),"candidate_oracle_reads":len(m["oracle_map"])},
             "attacker":{"families_with_signals":[k for k,v in (("reentrancy",m["reentrancy_graph"]),("oracle",m["oracle_map"]),("signature",m["signature_map"])) if v]},
             "verifier":{"required":["measured attack delta","sequential control","target-line coverage","mutation score","positive net economics","cheatcode-free reproof"],"status":"not-run"},
             "critic":{"harness_cheatcode_hits":cheat,"warnings":["Check actor authority and impersonation.","Check vm.deal/storage writes do not create the claimed exploit state.","Check control executes the same sequential calls."]}}
    write_json(safe_out(root,".audit/godmode/agent-split.json"),payload); return output(payload)

def bundle_simulate(args):
    p=argparse.ArgumentParser(prog="lk bundle"); p.add_argument("--tx",action="append",required=True); p.add_argument("--target-block",type=int,required=True); p.add_argument("--relay-url",required=True); p.add_argument("--auth-signature",required=True); ns=p.parse_args(args)
    if ns.target_block<1: raise ValueError("Target block must be positive.")
    if not all(re.fullmatch(r"0x[0-9a-fA-F]+",x) for x in ns.tx): raise ValueError("Provide raw signed transactions as 0x hex.")
    params={"txs":ns.tx,"blockNumber":hex(ns.target_block),"stateBlockNumber":"latest"}
    body=json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_callBundle","params":[params]}).encode()
    req=Request(ns.relay_url,data=body,headers={"Content-Type":"application/json","X-Flashbots-Signature":ns.auth_signature})
    with urlopen(req,timeout=30) as res: result=json.loads(res.read().decode())
    if result.get("error"): raise RuntimeError(str(result["error"]))
    return output({"simulation":result.get("result"),"broadcast":False,"note":"Simulation only; Lowkey does not call eth_sendBundle."})

def main(argv=None):
    a=list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] in {"-h","--help","help"}:
        print("Usage: lk capabilities | godmode | control | mutation-score | target-coverage | provenance | fallback-map | oracle-map | reentrancy-graph | custody | sig-matrix | init-frontrun | cfg | cross-vm | proxy-resolve | storage-infer | selectors-full | calldata-mine | unravel | state-diff | attack-forge | invariant-forge | archetype | token-weird | time | compose | skew | flashmax | path | reprove | economic | gas-ladder | fidelity | watch | verify-hack | bundle | sandwich | jit | fork-cache | upgrade-diff | agent-split | learn | questions | report")
        return 0
    cmd,rest=a[0],a[1:]
    if cmd=="capabilities":
        for n,name,title,status in CAPABILITIES: print(f"{n:02d} {name:20} [{status:16}] {title}")
        print("All 44 capabilities are registered. Partial and adapter-required are explicit.")
        return 0
    if cmd=="godmode": return godmode(rest)
    if cmd=="control": return control(rest)
    if cmd=="mutation-score": return mutation(rest)
    if cmd=="target-coverage": return coverage(rest)
    if cmd=="provenance": return provenance(rest)
    if cmd=="fidelity":
        p=argparse.ArgumentParser(prog="lk fidelity"); p.add_argument("--root",default="."); p.add_argument("--record",action="store_true"); p.add_argument("--inspect"); p.add_argument("--cheatcode",action="append",default=[]); p.add_argument("--strength",choices=("heuristic","simulated-funds","reproduced-fork"),default="heuristic"); ns=p.parse_args(rest); root=root_path(ns.root)
        try:
            if ns.inspect:
                harness=(root/ns.inspect).resolve()
                if not harness.is_relative_to(root) or not harness.is_file(): raise ValueError("Harness must be an existing file inside the project.")
                return output(analyze_harness_fidelity(harness.read_text(encoding="utf-8",errors="replace"),harness.relative_to(root).as_posix()))
            try: from . import evidence_ledger
            except ImportError: import evidence_ledger
            if ns.record:
                ev=evidence_ledger.append_event(root,"fidelity_record",{"strength":ns.strength,"cheatcodes":ns.cheatcode,"created_at":now()}); print("Recorded "+ev["event_id"]); return 0
            rows=[e for e in evidence_ledger.read_events(root) if e.get("event_type")=="fidelity_record"]; return output(rows)
        except ImportError as exc: raise RuntimeError(str(exc))
    if cmd=="sandbox":
        p=argparse.ArgumentParser(prog="lk sandbox"); p.add_argument("--root",default="."); p.add_argument("--timeout",type=int,default=300); p.add_argument("command",nargs=argparse.REMAINDER); ns=p.parse_args(rest)
        root=root_path(ns.root)
        if not shutil.which("bwrap"): raise RuntimeError("bubblewrap unavailable; refusing unsandboxed execution.")
        if not ns.command or ns.command[0]!="--": raise ValueError("Usage: lk sandbox -- <command> [args]")
        temp=Path(tempfile.mkdtemp(prefix="lk-sandbox-")); work=temp/"project"
        try:
            def ignore_sensitive(directory,names):
                ignored=[]
                for name in names:
                    lower=name.lower()
                    if name in {".git",".audit","node_modules","out","cache","__pycache__",".venv","venv"}:
                        ignored.append(name)
                    elif lower.startswith(".env") or any(token in lower for token in ("credential","keystore","private_key","wallet.json","id_rsa","id_ed25519",".npmrc")):
                        ignored.append(name)
                return ignored
            shutil.copytree(root,work,ignore=ignore_sensitive)
            home=Path.home()
            home_args=[]
            # Build an isolated home path inside the sandbox; do not expose the
            # host home directory. Only Foundry executables and solc versions
            # are selectively mounted read-only.
            if str(home).startswith("/home/"):
                home_args += ["--dir","/home"]
            if str(home)!="/":
                home_args += ["--dir",str(home)]
            foundry_bin=home/".foundry"/"bin"
            if foundry_bin.is_dir():
                home_args += ["--dir",str(home/".foundry"),"--ro-bind",str(foundry_bin),str(foundry_bin)]
            svm=home/".svm"
            if svm.is_dir():
                home_args += ["--dir",str(home/".svm"),"--ro-bind",str(svm),str(svm)]
            path_value=str(foundry_bin)+":/usr/local/bin:/usr/bin:/bin"
            argv=["bwrap","--die-with-parent","--unshare-net","--unshare-pid","--unshare-ipc","--unshare-uts",
                  "--clearenv","--setenv","HOME",str(home), "--setenv","PATH",path_value,
                  "--ro-bind","/usr","/usr","--ro-bind","/etc","/etc","--dev","/dev","--proc","/proc",
                  "--tmpfs","/tmp",*home_args,"--bind",str(work),"/workspace","--chdir","/workspace","--",*ns.command[1:]]
            proc=run(argv,root,ns.timeout)
            print(proc.stdout,end=""); print(proc.stderr,file=sys.stderr,end=""); return proc.returncode
        finally: shutil.rmtree(temp,ignore_errors=True)
    if cmd=="cheat-fingerprint": return fingerprint(rest)
    if cmd in {"fallback-map","oracle-map","reentrancy-graph","sig-matrix","init-frontrun","custody","cross-vm","cfg"}: return source_cmd(cmd,rest)
    if cmd in {"proxy-resolve","storage-infer","selectors-full"}: return rpc_command(cmd,rest)
    if cmd=="unravel": return unravel(rest)
    if cmd=="state-diff": return state_diff(rest)
    if cmd=="economic": return economic(rest)
    if cmd=="attack-forge": return attack_forge(rest)
    if cmd=="invariant-forge": return generate(rest,cmd)
    if cmd=="archetype": return generate(rest,cmd)
    if cmd=="token-weird": return token_weird(rest)
    if cmd=="fork-cache": return fork_cache(rest)
    if cmd=="questions": return questions(rest)
    if cmd=="learn": return learn(rest)
    if cmd=="report": return report(rest)
    if cmd=="reprove": return reprove(rest)
    if cmd=="time":
        p=argparse.ArgumentParser(prog="lk time"); p.add_argument("--root",default="."); p.add_argument("--output",default=".audit/godmode/TimeLadder.template.t.sol"); ns=p.parse_args(rest); root=root_path(ns.root); out=safe_out(root,ns.output)
        offsets=(3600,86400,604800,2592000); body="\n".join(" function test_warp_"+str(x)+"() public { vm.warp(block.timestamp + "+str(x)+"); vm.roll(block.number + "+str(max(1,x//12))+"); /* invoke target and assert invariant */ }" for x in offsets)
        out.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport \"forge-std/Test.sol\";\ncontract LowkeyTimeLadder is Test {\n"+body+"\n}\n"); print("Time ladder template: "+str(out.relative_to(root))); return 0
    if cmd=="compose": return compose(rest)
    if cmd=="skew": return skew_plan(rest)
    if cmd=="flashmax": return flashmax(rest)
    if cmd=="path": return symbolic_path(rest)
    if cmd=="gas-ladder": return gas_ladder(rest)
    if cmd=="watch": return watch(rest)
    if cmd=="verify-hack": return verify_hack(rest)
    if cmd=="bundle": return bundle_simulate(rest)
    if cmd=="upgrade-diff": return upgrade_diff(rest)
    if cmd=="agent-split": return agent_split(rest)
    if cmd=="calldata-mine": return calldata_mine(rest)
    if cmd in {"sandwich","jit"}:
        print("BLOCKED: "+cmd+" requires a pending-transaction feed and pool-specific simulation adapter. No transaction was sent.")
        return 2
    if cmd=="decompile":
        print("BLOCKED: install and configure a supported Heimdall adapter; no decompiler invocation guessed."); return 2
    if cmd=="flashmax":
        print("BLOCKED: requires Aave/Balancer/Uniswap V3 venue-specific pool and callback adapter."); return 2
    if cmd=="time":
        print("Use: lk time"); return 2
    raise ValueError("Unknown Godmode command: "+cmd)
if __name__=="__main__":
    try: raise SystemExit(main())
    except KeyboardInterrupt: raise SystemExit(130)
    except (ValueError,RuntimeError,OSError,json.JSONDecodeError,subprocess.TimeoutExpired) as exc:
        print("Lowkey: "+str(exc),file=sys.stderr); raise SystemExit(2)
