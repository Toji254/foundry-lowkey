import os
import json
import subprocess
import sys
import re
import shlex
import io
import shutil
import hashlib
from contextlib import redirect_stdout
from datetime import datetime
from urllib.parse import urlsplit
from difflib import SequenceMatcher
from pathlib import Path

try:
    from forge_tools import NATIVE_COMMANDS as FORGE_NATIVE_COMMANDS
except ImportError:
    FORGE_NATIVE_COMMANDS = set()

try:
    from audit_engine import run_slither, run_rg, run_audit_pipeline, generate_poc, record_evidence
except ImportError:
    run_slither = run_rg = run_audit_pipeline = generate_poc = record_evidence = None

try:
    from project_tools import (
        build_dependency_graph,
        detect_project,
        project_source_files,
        render_project_map,
    )
except ImportError:
    build_dependency_graph = detect_project = project_source_files = render_project_map = None

CONFIG_DIR = os.path.expanduser("~/.lowkey")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
SNAPSHOT_DIR = os.path.join(CONFIG_DIR, "snapshots")
AUDIT_DIR = os.path.expanduser("~/.lowkey/audit")
SESSION_FILE = os.path.join(AUDIT_DIR, "session_log.txt")
WORKSPACE_DIR = os.path.join(os.getcwd(), ".audit")

AUDIT_CHECKLIST = [
    "Understand protocol purpose and trust assumptions",
    "Map privileged roles and access-control boundaries",
    "Review state transitions and invariants",
    "Validate user-controlled inputs and edge cases",
    "Review external calls and callback/reentrancy surfaces",
    "Check ETH and token accounting and balance assumptions",
    "Review oracle, price, and time-dependent logic",
    "Review signatures, replay, nonce, and authorization flows",
    "Review upgradeability, proxy, and initialization paths",
    "Verify storage layout and collision risks",
    "Check token/standard integration assumptions",
    "Review denial-of-service and gas-sensitive paths",
    "Review ordering, MEV, and front-running assumptions",
    "Reproduce important observations with tests or traces",
    "Record findings, impact, and recommended remediation",
]

DEFAULT_CONFIG = {
    "target": None, "aliases": {}, "targets": {}, "rpc": None,
    "rpc_profiles": {}, "actor": None, "wallets": {},
    "abi_paths": {}, "labels": {}, "confirm_sends": False, "version": 2
}

_COMMAND_STATUS = 0

class CommandResult(str):
    def __new__(cls, output="", code=0):
        result = super().__new__(cls, output or "")
        result.code = code
        return result

def record_status(code):
    global _COMMAND_STATUS
    if isinstance(code, int) and code != 0 and _COMMAND_STATUS == 0:
        _COMMAND_STATUS = code
    return code

def fail(message, code=2):
    print(message, file=sys.stderr)
    return record_status(code)

def is_tx_hash(value):
    return isinstance(value, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{64}", value))

def fresh_config():
    return json.loads(json.dumps(DEFAULT_CONFIG))

def load_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_FILE):
        return fresh_config()
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
    except (OSError, json.JSONDecodeError):
        print(f"Warning: invalid config at {CONFIG_FILE}; using defaults.", file=sys.stderr)
        return fresh_config()
    if not isinstance(loaded, dict):
        return fresh_config()
    config = fresh_config()
    config.update(loaded)
    for key in ["aliases", "targets", "rpc_profiles", "wallets", "abi_paths", "labels"]:
        if not isinstance(config.get(key), dict): config[key] = {}
    return config

def save_config(config):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp=CONFIG_FILE+".tmp"
    try:
        with open(tmp,"w",encoding="utf-8") as f:
            json.dump(config,f,indent=4); f.write("\n")
        os.chmod(tmp,0o600); os.replace(tmp,CONFIG_FILE); os.chmod(CONFIG_FILE,0o600)
    finally:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except OSError: pass

INSTALL_MANIFEST = os.path.join(CONFIG_DIR, "install-manifest.json")


def _sha256_file(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def load_install_manifest():
    try:
        with open(INSTALL_MANIFEST, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def runtime_sync_status():
    """Detect stale/corrupted installed Lowkey files without changing anything."""
    manifest = load_install_manifest()
    if not manifest:
        return {"status": "unknown", "detail": "no install manifest; run install.sh"}

    mismatches = []
    for path, expected in (manifest.get("files") or {}).items():
        actual = _sha256_file(path)
        if actual is None:
            mismatches.append(f"missing: {path}")
        elif actual != expected:
            mismatches.append(f"modified: {path}")

    source_repo = manifest.get("source_repo")
    installed_sha = manifest.get("git_sha")
    source_sha = None
    if source_repo and os.path.isdir(os.path.join(source_repo, ".git")):
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=source_repo,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                source_sha = result.stdout.strip()
        except OSError:
            pass

    if mismatches:
        return {
            "status": "corrupt",
            "detail": "; ".join(mismatches[:4]),
            "installed_sha": installed_sha,
            "source_sha": source_sha,
            "source_repo": source_repo,
        }
    if source_sha and installed_sha and source_sha != installed_sha:
        return {
            "status": "stale",
            "detail": f"source checkout is {source_sha[:12]}, installed runtime is {installed_sha[:12]}",
            "installed_sha": installed_sha,
            "source_sha": source_sha,
            "source_repo": source_repo,
        }
    return {
        "status": "ok",
        "detail": f"installed runtime {installed_sha[:12]}" if installed_sha else "installed runtime verified",
        "installed_sha": installed_sha,
        "source_sha": source_sha,
        "source_repo": source_repo,
    }

def normalize_private_key(value):
    if not value: return None
    value=str(value).strip()
    if re.fullmatch(r"(0x)?[0-9a-fA-F]{64}",value):
        return value if value.startswith("0x") else "0x"+value
    return None

def resolve_wallet_key(config,wallet_name=None):
    name=wallet_name or config.get("actor")
    if not name: return None
    entry=config.get("wallets",{}).get(name)
    if isinstance(entry,dict):
        if entry.get("env"): return normalize_private_key(os.environ.get(entry["env"]))
        return normalize_private_key(entry.get("private_key"))
    if isinstance(entry,str): return normalize_private_key(entry)
    if isinstance(name,str) and name.startswith("env:"): return normalize_private_key(os.environ.get(name[4:]))
    return normalize_private_key(name)
def rpc_display(url):
    if not url: return None
    try:
        parts=urlsplit(url)
        if parts.hostname in {"localhost","127.0.0.1","::1"}: return url
        host=parts.hostname or "<rpc>"
        if ":" in host and not host.startswith("["): host=f"[{host}]"
        if parts.port: host += f":{parts.port}"
        return f"{parts.scheme or 'rpc'}://{host}/<redacted>"
    except ValueError:
        return "<redacted-rpc-url>"

def redact_secrets(text):
    text=re.sub(r"(--private-key(?:=|\s+))(\S+)",r"\1<redacted>",text,flags=re.I)
    text=re.sub(r"(--jwt-secret(?:=|\s+))(\S+)",r"\1<redacted>",text,flags=re.I)
    return re.sub(r"(--rpc-url(?:=|\s+))(\S+)",
                  lambda m:m.group(1)+(rpc_display(m.group(2)) or "<redacted-rpc-url>"),
                  text,flags=re.I)

def is_probable_private_key(value):
    return bool(re.fullmatch(r"(0x)?[0-9a-fA-F]{64}",str(value or "")))

def target_aliases(config):
    merged={}
    for name,addr in config.get("aliases",{}).items():
        if is_address(addr): merged[str(name)]=addr
    for name,addr in config.get("targets",{}).items():
        if is_address(addr): merged[str(name)]=addr
    return merged

def resolve_target_ref(config,ref):
    if ref is None: return config.get("target")
    if is_address(ref): return ref
    aliases=target_aliases(config)
    if str(ref) in aliases: return aliases[str(ref)]
    if str(ref).isdigit():
        names=list(aliases); index=int(ref)-1
        if 0<=index<len(names): return aliases[names[index]]
    return None

def canonical_type(param):
    if not isinstance(param,dict): return ""
    raw=param.get("type","")
    if raw.startswith("tuple"):
        suffix=raw[len("tuple"):]
        return f"({','.join(canonical_type(c) for c in param.get('components',[]))}){suffix}"
    return raw

def format_signature(item):
    return f"{item.get('name','<anonymous>')}({','.join(canonical_type(v) for v in item.get('inputs',[]))})"
def format_output_signature(item):
    return f"{item.get('name','<anonymous>')}({','.join(canonical_type(v) for v in item.get('inputs',[]))})({','.join(canonical_type(v) for v in item.get('outputs',[]))})"

def abi_functions(abi): return [item for item in abi if item.get("type")=="function"]

def matching_functions(abi,func_name):
    if "(" in func_name: return [item for item in abi_functions(abi) if format_signature(item)==func_name]
    return [item for item in abi_functions(abi) if item.get("name")==func_name]

def resolve_function(func_name,target,config):
    abi=load_abi(target,config)
    if not abi: return func_name
    matches=matching_functions(abi,func_name)
    if len(matches)==1: return format_signature(matches[0])
    if len(matches)>1:
        raise ValueError("Ambiguous overloaded function '%s'. Use one of: %s" % (
            func_name,", ".join(format_signature(item) for item in matches)))
    return func_name

def function_score(item,query):
    candidate=format_signature(item).lower(); query=query.lower()
    return 1.0 if query in candidate else SequenceMatcher(None,candidate,query).ratio()

def artifact_json_files(root="."):
    result=[]
    for base in ["out","broadcast"]:
        base_path=os.path.join(root,base)
        if not os.path.isdir(base_path): continue
        for path,_,files in os.walk(base_path):
            for filename in files:
                if filename.endswith(".json"): result.append(os.path.join(path,filename))
    return result
def last_transaction(config):
    return config.get("last_tx")

def log_session(command, result):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(SESSION_FILE, "a") as f:
        f.write(f"[{timestamp}] CMD: {command}\nRES: {result}\n{'-'*40}\n")

def load_abi(target,config):
    abi_paths=config.get("abi_paths",{})
    abi_path=abi_paths.get(target)
    if not abi_path and isinstance(target,str):
        lowered=target.lower()
        abi_path=next((path for address,path in abi_paths.items() if isinstance(address,str) and address.lower()==lowered),None)
    if not abi_path or not os.path.exists(abi_path): return []
    try:
        with open(abi_path,"r",encoding="utf-8") as f: artifact=json.load(f)
        abi=artifact.get("abi",[]) if isinstance(artifact,dict) else artifact
        return abi if isinstance(abi,list) else []
    except (OSError,json.JSONDecodeError): return []
def run_chain(config):
    chain_id = run_cast(["chain-id"], config, capture=True)
    block = run_cast(["block-number"], config, capture=True)
    print(f"Chain ID: {chain_id or 'Unknown'}")
    print(f"Block:    {block or 'Unknown'}")
    print(f"RPC:      {config.get('rpc') or 'Not configured'}")

def run_abi(config):
    target = config.get("target")
    if not target:
        print("Error: Set target first.")
        return
    abi = load_abi(target, config)
    if not abi:
        print("Error: No ABI loaded for the current target.")
        return
    groups = {
        "READ": [item for item in abi if item.get("type") == "function" and item.get("stateMutability") in ["view", "pure"]],
        "WRITE": [item for item in abi if item.get("type") == "function" and item.get("stateMutability") not in ["view", "pure"]],
        "EVENTS": [item for item in abi if item.get("type") == "event"],
        "ERRORS": [item for item in abi if item.get("type") == "error"],
    }
    print(f"ABI: {config['abi_paths'].get(target)}")
    for group, items in groups.items():
        if items:
            print(f"\n{group}")
            for item in items:
                print(f"  {format_signature(item)}")

def run_functions(config,query=None):
    target=config.get("target")
    if not target: return fail("Error: Set target first.")
    functions=abi_functions(load_abi(target,config))
    if not functions: return fail("Error: No ABI functions loaded for the current target.")
    if query:
        functions=sorted(functions,key=lambda item:function_score(item,query),reverse=True)[:8]
        print(f"Function matches for '{query}':")
    else: print("Functions:")
    for index,item in enumerate(functions,1):
        print(f"{index:>2}. {item.get('stateMutability','unknown').upper():10} {format_signature(item)}")
def run_info(config):
    target = config.get("target")
    if not target:
        return fail("Error: Set target first.")
    print(f"Target: {target}")
    run_chain(config)
    code = run_cast(["code", target], config, capture=True) or ""
    print(f"Code:   {'YES' if code.startswith('0x') and len(code) > 2 else 'NO'}")
    print(f"ABI:    {'LOADED' if load_abi(target, config) else 'NOT LOADED'}")
    print(f"Proxy:  {'YES' if inspect_proxy(config, quiet=True) else 'NO'}")

def run_encode(config,args):
    if not args:
        return fail("Usage: lk encode <function> [args]")
    values=list(args)
    target=config.get("target")
    if target and ("(" not in values[0] or ")" not in values[0]):
        try: values[0]=resolve_function(values[0],target,config)
        except ValueError as error:
            return fail(f"Error: {error}")
    run_cast(["calldata"]+values,config)
def run_signature(args):
    if not args:
        return fail("Usage: lk sig <function(signature)>")
    code,out,err=cast_output(["cast","sig",args[0]])
    if out: print(out)
    if err: print(err,file=sys.stderr)
    if code!=0 and not err:
        print("Unable to resolve selector.",file=sys.stderr)
    return record_status(code)
def cast_output(args,input_text=None):
    result=subprocess.run(args,capture_output=True,text=True,input=input_text)
    return result.returncode,result.stdout.strip(),result.stderr.strip()
def abi_selector(signature):
    output, _ = cast_output(["cast", "sig", signature])
    return output.splitlines()[0].strip() if output else None

def decode_abi_input(signature,data):
    payload=data[10:] if data.startswith("0x") and len(data)>=10 else data
    _,out,err=cast_output(["cast","decode-abi","--input",signature,"0x"+payload])
    return out or err
def run_decode_error(config,args):
    if not args: return fail("Usage: lk decode-error <revert-data>")
    data=args[0]
    if not re.fullmatch(r"0x[0-9a-fA-F]+",data or "") or len(data)<10:
        return fail("Error: revert data must be hex calldata beginning with 0x.")
    for item in [x for x in load_abi(config.get("target"),config) if x.get("type")=="error"]:
        signature=format_signature(item)
        if (abi_selector(signature) or "").lower()==data[:10].lower():
            print(f"Error: {signature}")
            print(decode_abi_input(signature,data) if item.get("inputs") else "Arguments: none"); return
    print("Loaded ABI did not contain that custom error; asking Cast resolver:")
    run_cast(["decode-error",data],config)
def run_tx(config,args):
    tx_hash=args[0] if args else last_transaction(config)
    if not tx_hash: return fail("Usage: lk tx <transaction-hash> (or save a transaction first)")
    if not is_tx_hash(tx_hash): return fail("Error: invalid transaction hash")
    command=["cast","tx",tx_hash,"--json"]
    if config.get("rpc"): command.extend(["--rpc-url",config["rpc"]])
    code,output,error=cast_output(command)
    if code!=0 and not output:
        print(error or "cast tx failed",file=sys.stderr)
        return record_status(code)
    try: transaction=json.loads(output)
    except json.JSONDecodeError: print(output or error); return
    if not isinstance(transaction,dict): print("Unexpected cast tx JSON."); return
    if isinstance(transaction.get("transaction"),dict): transaction=transaction["transaction"]
    elif isinstance(transaction.get("data"),dict) and any(k in transaction["data"] for k in ["hash","from","to"]):
        transaction=transaction["data"]
    tx_to=transaction.get("to") or ""
    abi_target=tx_to if is_address(tx_to) else config.get("target")
    abi=load_abi(abi_target,config)
    print(f"Hash:  {transaction.get('hash',tx_hash)}")
    print(f"From:  {apply_labels(transaction.get('from','Unknown'),config)}")
    print(f"To:    {apply_labels(transaction.get('to','Unknown'),config)}")
    value=transaction.get("value","0")
    if isinstance(value,str) and value.startswith("0x"):
        try: value=str(int(value,16))
        except ValueError: pass
    print(f"Value: {humanize_value(str(value))}")
    input_data=transaction.get("input") or transaction.get("data") or "0x"
    if isinstance(input_data,str) and input_data.startswith("0x") and len(input_data)>=10:
        selector=input_data[:10].lower(); decoded=False
        for item in abi_functions(abi):
            signature=format_signature(item)
            if (abi_selector(signature) or "").lower()==selector:
                print(f"Function: {signature}")
                print(f"Args:    {decode_abi_input(signature,input_data)}"); decoded=True; break
        if not decoded:
            print(f"Selector: {selector} (unknown to loaded ABI)")
            _,fourbyte,_=cast_output(["cast","4byte",selector])
            if fourbyte: print(f"4byte:   {fourbyte}")
def run_receipt(config, tx_hash=None):
    tx_hash = tx_hash or last_transaction(config)
    if not tx_hash: return fail("Error: No transaction hash supplied or saved.")
    if not is_tx_hash(tx_hash): return fail("Error: invalid transaction hash")
    code=run_cast(["receipt", tx_hash, "--async"], config)
    if record_evidence:
        record_evidence("receipt", {"tx":tx_hash,"exit_code":code})
    return code if isinstance(code,int) else 0

def run_trace(config,args=None):
    args=list(args or [])
    tx_hash=args.pop(0) if args and args[0].startswith("0x") else last_transaction(config)
    if not tx_hash: return fail("Error: No transaction hash supplied or saved.")
    grep=None
    if "--grep" in args:
        i=args.index("--grep")
        if i+1>=len(args): return fail("Usage: lk trace [tx] [--quick] [--decode-internal] [--trace-printer] [--grep text]")
        grep=args[i+1]; del args[i:i+2]
    output=run_cast(["run",tx_hash]+args,config,capture=True)
    output_text=str(output)
    if record_evidence:
        record_evidence("trace", {"tx":tx_hash,"args":args,"grep":grep,"output":output_text})
    if grep:
        matched=[line for line in output_text.splitlines() if grep.lower() in line.lower()]
        print("\n".join(matched) if matched else f"No trace lines matched '{grep}'.")
    else:
        print(output_text)
def decode_event_log(config,log):
    topics=log.get("topics",[]) if isinstance(log,dict) else []
    data=log.get("data","0x") if isinstance(log,dict) else "0x"
    if not topics: return None
    topic0=topics[0].lower()
    for item in [x for x in load_abi(config.get("target"),config) if x.get("type")=="event" and not x.get("anonymous")]:
        signature=format_signature(item)
        event_topic=cast_output(["cast","sig-event",signature])[1]
        if event_topic.lower().strip()==topic0:
            if item.get("inputs"):
                output=io.StringIO()
                with redirect_stdout(output): code=decode_event_values(item,data,topics)
                return signature,output.getvalue().strip() if code==0 else output.getvalue().strip()
            try: payload=event_payload(data,topics)
            except ValueError as error:
                record_status(2)
                return signature,str(error)
            code,decoded,error=cast_output(["cast","decode-event","--sig",signature,payload])
            record_status(code)
            if error and not decoded: decoded=error
            return signature,decoded
    return None

def run_logs(config,args):
    args=list(args); decode="--decode" in args
    if decode: args.remove("--decode")
    if not decode: run_cast(["logs"]+args,config); return
    command=["cast","logs","--json"]+args
    if config.get("rpc"): command.extend(["--rpc-url",config["rpc"]])
    code,output,error=cast_output(command)
    if code!=0:
        print(error or "cast logs failed",file=sys.stderr)
        return record_status(code)
    try: payload=json.loads(output)
    except json.JSONDecodeError: print(output); return
    logs=payload if isinstance(payload,list) else payload.get("logs",payload.get("result",[]))
    if not isinstance(logs,list): print(output); return
    if not logs:
        print("No logs found.")
        if record_evidence: record_evidence("logs", {"args":args,"logs":[]})
        return
    decoded=[]
    for log in logs:
        print(json.dumps(log,indent=2))
        event=decode_event_log(config,log)
        if event:
            decoded.append({"signature":event[0],"decoded":event[1]})
            print(f"Event: {event[0]}\nDecoded: {event[1]}")
    if record_evidence:
        record_evidence("logs", {"args":args,"logs":logs,"decoded":decoded})
def apply_labels(text, config):
    labels = config.get("labels", {})
    for addr, label in labels.items():
        text = text.replace(addr, f"{label} ({addr})")
    return text

def humanize_value(text):
    wei_pattern=r'\b(0x)?(\d{18,})\b'
    def replace_wei(match):
        eth_val=int(match.group(2))/10**18
        return f"{match.group(0)} [~{eth_val:.4f} ETH]"
    return re.sub(wei_pattern,replace_wei,text)
def is_address(value):
    return isinstance(value,str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{40}",value))
def is_nonzero_slot(value):
    try:
        return int(value, 16) != 0
    except (TypeError, ValueError):
        return False

def run_cast(args,config,capture=False):
    if not args:
        result=CommandResult("",2)
        record_status(result.code)
        return result if capture else result.code
    action=args[0]; shortcut_map={"c":"call","s":"send","st":"storage"}; cast_cmd=shortcut_map.get(action,action)
    remaining=list(args[1:]); target=config.get("target")
    if cast_cmd in {"call","send","storage"}:
        if remaining and is_address(remaining[0]): target=remaining.pop(0)
        if not target:
            result=CommandResult("Error: no target set. Use lk target <address> or pass one explicitly.",2)
            record_status(result.code)
            if capture: return result
            print(str(result),file=sys.stderr); return result.code
        cmd=["cast",cast_cmd,target]
    else: cmd=["cast",cast_cmd]
    if cast_cmd in {"call","send"} and remaining:
        if "(" not in remaining[0] or ")" not in remaining[0]:
            try: remaining[0]=resolve_function(remaining[0],target,config)
            except ValueError as error:
                result=CommandResult(f"Error: {error}",2)
                record_status(result.code)
                print(str(result),file=sys.stderr)
                return result if capture else result.code
    preview="--preview" in remaining or "--dry-run" in remaining
    confirm="--confirm" in remaining
    bypass="--yes" in remaining
    for flag in ["--preview","--dry-run","--confirm","--yes"]:
        while flag in remaining: remaining.remove(flag)
    cmd.extend(remaining)
    rpc_commands={"balance","call","send","storage","chain-id","block-number","code","codesize","codehash","nonce","logs","receipt","run","tx","estimate","implementation","admin","proof","lookup-address","resolve-name","erc20-token","block","gas-price"}
    if cast_cmd in rpc_commands and config.get("rpc") and "--rpc-url" not in cmd: cmd.extend(["--rpc-url",config["rpc"]])
    actor=config.get("actor")
    actor_key=resolve_wallet_key(config)
    if cast_cmd=="send" and actor and actor in config.get("wallets",{}) and not actor_key:
        return fail(f"Error: signer profile '{actor}' has no usable private key. Check its environment variable.")
    if cast_cmd=="send" and actor_key and "--private-key" not in " ".join(cmd): cmd.extend(["--private-key",actor_key])
    safe_cmd=redact_secrets(shlex.join(cmd))
    if not capture: print(f"DEBUG: Executing -> {safe_cmd}")
    if cast_cmd=="send" and preview:
        print(f"Preview: {safe_cmd}"); return 0
    if cast_cmd=="send" and (confirm or (config.get("confirm_sends") and not bypass)):
        print(f"Preview: {safe_cmd}")
        try: answer=input("Send transaction? [y/N] ").strip().lower()
        except EOFError: answer=""
        if answer not in {"y","yes"}: print("Transaction cancelled."); return 0
    try:
        code,out,err=cast_output(cmd); final=out or err; log_session(safe_cmd,final)
        if cast_cmd=="send" and out:
            match=re.search(r"transactionHash(?:\s|:)+([0-9A-Fa-fx]{66})",out)
            if match: config["last_tx"]=match.group(1); config["last_tx_block"]=None; save_config(config)
        result=CommandResult(final,code)
        record_status(code)
        if capture: return result
        if out: print(humanize_value(apply_labels(out,config)))
        if err:
            if code!=0 and "execution reverted" in err.lower(): err="REVERT: "+err
            print(apply_labels(err,config),file=sys.stderr)
        return code
    except FileNotFoundError:
        message="Error: cast was not found in PATH. Install/update Foundry first."
        result=CommandResult(message,127)
        record_status(result.code)
        if capture: return result
        print(message,file=sys.stderr)
        return result.code
    except OSError as error:
        result=CommandResult(f"Error executing cast: {error}",1)
        record_status(result.code)
        if capture: return result
        print(str(result),file=sys.stderr)
        return result.code
def run_recon(config):
    target=config.get("target")
    if not target:
        print("Error: Set target first."); return
    print(f"CONTRACT RECON: {target}\n" + "="*52)
    balance=run_cast(["balance",target],config,capture=True)
    code=run_cast(["code",target],config,capture=True) or ""
    codehash=run_cast(["codehash",target],config,capture=True)
    nonce=run_cast(["nonce",target],config,capture=True)
    codesize=run_cast(["codesize",target],config,capture=True)
    print(f"Balance:  {humanize_value(balance) if balance else 'Unknown'}")
    print(f"Code:     {'YES' if code.startswith('0x') and len(code)>2 else 'NO'}")
    print(f"Codehash: {codehash or 'Unknown'}")
    print(f"Codesize: {codesize or 'Unknown'} bytes")
    print(f"Nonce:    {nonce or 'Unknown'}")
    proxy=inspect_proxy(config,quiet=True)
    print(f"Proxy:    {'YES' if proxy else 'NO'}")
    print("="*52)
def inspect_proxy(config, quiet=False):
    target = config.get("target")
    if not target:
        return False
    implementation_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    beacon_slot = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
    implementation = run_cast(["st", implementation_slot], config, capture=True)
    beacon = run_cast(["st", beacon_slot], config, capture=True)
    implementation_found = is_nonzero_slot(implementation)
    beacon_found = is_nonzero_slot(beacon)
    is_proxy = implementation_found or beacon_found
    if not quiet:
        print(f"Proxy: {'YES' if is_proxy else 'NO'}")
        if implementation_found:
            print(f"Implementation slot: {implementation}")
        if beacon_found:
            print(f"Beacon slot: {beacon}")
    return is_proxy

def run_proxy(config):
    target=config.get("target")
    if not target:
        print("Error: Set target first."); return
    detected=inspect_proxy(config)
    if not detected: return
    implementation=run_cast(["implementation",target],config,capture=True)
    admin=run_cast(["admin",target],config,capture=True)
    print(f"Implementation: {implementation or 'Unknown'}")
    print(f"Admin:         {admin or 'Unknown'}")
def run_mapping(config,*args):
    if not config.get("target"): return fail("Error: Set target first.")
    if len(args)==2: slot,key=args; key_type="address" if is_address(key) else "uint256"
    elif len(args)==3: key_type,slot,key=args
    else: return fail("Usage: lk mapping [key_type] <slot> <key>")
    if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+",str(slot)):
        return fail(f"Error: invalid storage slot: {slot}")
    if key_type=="address" and not is_address(key):
        return fail(f"Error: invalid address mapping key: {key}")
    computed=run_cast(["index",key_type,key,slot],config,capture=True)
    if not computed: return fail("Error: could not compute mapping slot.")
    print(f"Mapping slot: {computed}"); run_cast(["st",computed],config)
def snapshot_path(config):
    target=config.get("target") or "no-target"; chain=run_cast(["chain-id"],config,capture=True) or "unknown-chain"
    safe_target=re.sub(r"[^0-9a-fA-Fx_-]","_",target); directory=os.path.join(SNAPSHOT_DIR,str(chain)); os.makedirs(directory,exist_ok=True)
    return os.path.join(directory,f"{safe_target}.json")

def snapshot_path(config,chain=None):
    target=config.get("target") or "no-target"
    chain=chain or run_cast(["chain-id"],config,capture=True) or "unknown-chain"
    safe_target=re.sub(r"[^0-9a-fA-Fx_-]","_",target)
    directory=os.path.join(SNAPSHOT_DIR,str(chain)); os.makedirs(directory,exist_ok=True)
    return os.path.join(directory,f"{safe_target}.json")

def run_snapshot(config,slots=None):
    if not config.get("target"):
        print("Error: Set target first."); return
    values=list(slots or [])
    block=None
    if "--block" in values:
        i=values.index("--block")
        if i+1>=len(values):
            print("Usage: lk snapshot [slot ...] [--block BLOCK]"); return
        block=values[i+1]; del values[i:i+2]
    requested=values or [str(i) for i in range(10)]
    state={}
    storage_args=[]
    if block: storage_args=["--block",block]
    for slot in requested:
        state[str(slot)]=run_cast(["st",str(slot)]+storage_args,config,capture=True)
    current_block=block or run_cast(["block-number"],config,capture=True)
    chain=run_cast(["chain-id"],config,capture=True) or "unknown-chain"
    payload={"target":config["target"],"rpc":rpc_display(config.get("rpc")),"block":current_block,"chain":chain,"saved_at":datetime.now().isoformat(timespec="seconds"),"slots":state}
    path=snapshot_path(config,chain); Path(path).write_text(json.dumps(payload,indent=4),encoding="utf-8")
    if record_evidence:
        record_evidence("snapshot", payload)
    print(f"Snapshot saved: {path}")
def run_diff(config):
    path=snapshot_path(config)
    if not os.path.exists(path): print("No snapshot for the current target/chain."); return
    try: old=json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError): print("Error: invalid snapshot."); return
    old_slots=old.get("slots",old); print(f"Snapshot block: {old.get('block','unknown')}")
    changed=0
    changes=[]
    for slot,old_val in old_slots.items():
        new_val=run_cast(["st",slot],config,capture=True)
        if str(new_val).lower()!=str(old_val).lower():
            changed+=1; changes.append({"slot":slot,"before":old_val,"after":str(new_val)}); print(f"Slot {slot}: {old_val} -> {new_val}")
    if record_evidence:
        record_evidence("storage_diff", {"snapshot_block":old.get("block"),"changes":changes})
    if not changed: print("No changes detected in snapshotted slots.")
def run_finding(config, note):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    line = f"- [{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}\n"
    with open(os.path.join(AUDIT_DIR, "findings.md"), "a") as f:
        f.write(line)
    workspace_finding = workspace_paths()["findings"]
    if os.path.isdir(WORKSPACE_DIR):
        with open(workspace_finding, "a") as f:
            f.write(line)
    if record_evidence:
        record_evidence("finding_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"), {
            "note": note,
            "target": config.get("target"),
            "last_tx": config.get("last_tx"),
        })
    print("Finding recorded.")

def _fit_text_for_cli(value, width):
    value = str(value).replace("\n", " ")
    return value if len(value) <= width else value[:max(0, width - 3)] + "..."


def run_findings(config, args=None):
    """Render stored Slither/manual findings without falling through to Cast."""
    paths = workspace_paths()
    evidence_path = os.path.join(paths["root"], "evidence", "slither.json")
    slither = read_json_file(evidence_path, {})
    findings = slither.get("findings", []) if isinstance(slither, dict) else []
    findings = findings if isinstance(findings, list) else []

    manual_path = paths["findings"] if os.path.exists(paths["findings"]) else os.path.join(AUDIT_DIR, "findings.md")
    manual = []
    if os.path.exists(manual_path):
        try:
            manual = [
                line.strip()
                for line in Path(manual_path).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except OSError:
            manual = []

    print("\n=== LOWKEY FINDINGS ===")
    print("=" * 96)

    print("\nSLITHER")
    print("-" * 96)
    if findings:
        print(f"{'#':>3}  {'IMPACT':<12} {'CONFIDENCE':<11} {'DETECTOR':<34} LOCATION")
        print("-" * 96)
        for index, finding in enumerate(findings, 1):
            locations = finding.get("locations") or []
            location = locations[0] if locations else {}
            source = location.get("source") or "unknown"
            line = location.get("start") or "?"
            detector = finding.get("check") or finding.get("detector") or "unknown"
            impact = str(finding.get("impact") or "unknown").upper()
            confidence = str(finding.get("confidence") or "unknown").upper()
            print(
                f"{index:>3}  {impact:<12} {confidence:<11} "
                f"{_fit_text_for_cli(detector, 34):<34} {source}#{line}"
            )
    else:
        print("No Slither findings recorded.")
        print("Run lk audit --checks to refresh evidence.")

    print("\nMANUAL / RECORDED")
    print("-" * 96)
    if manual:
        for line in manual:
            print(line)
    else:
        print("No manual findings recorded.")

    print(f"\nEvidence: {evidence_path}")
    return 0


def run_focus(config, args=None):
    """Show ABI functions with the strongest review-surface signals."""
    args = list(args or [])
    target = config.get("target")
    if not target:
        return fail("Error: Set target first.")
    funcs = abi_functions(load_abi(target, config))
    if not funcs:
        return fail("Error: No ABI functions loaded.")

    query = " ".join(args).strip().lower()
    rows = []
    for item in funcs:
        name = item.get("name", "").lower()
        signals = []
        if item.get("stateMutability") in {"nonpayable", "payable"}:
            signals.append("state-write")
        if item.get("stateMutability") == "payable":
            signals.append("value-flow")
        if any(x in name for x in ["owner", "admin", "role", "upgrade", "pause", "unpause"]):
            signals.append("privileged-looking")
        if any(x in name for x in ["withdraw", "transfer", "send", "execute", "call", "mint", "burn", "sweep"]):
            signals.append("asset/action")
        if any(canonical_type(i).startswith("address") for i in item.get("inputs", [])):
            signals.append("address-input")
        signature = format_signature(item)
        if query and query not in signature.lower() and not any(query in s for s in signals):
            continue
        score = sum({
            "state-write": 1,
            "value-flow": 2,
            "privileged-looking": 2,
            "asset/action": 2,
            "address-input": 1,
        }.get(signal, 0) for signal in signals)
        rows.append((score, signature, signals))

    rows.sort(key=lambda row: (-row[0], row[1]))
    print("\n=== LOWKEY FOCUS ===")
    print("=" * 96)
    if not rows:
        print("No matching focus surfaces.")
        return 0

    print(f"{'SCORE':>5}  {'FUNCTION':<58} SIGNALS")
    print("-" * 96)
    for score, signature, signals in rows:
        print(
            f"{score:>5}  {_fit_text_for_cli(signature, 58):<58} "
            f"{', '.join(signals) or 'no heuristic signals'}"
        )
    print("\nUse lk fn <term> to inspect matching ABI functions.")
    if record_evidence:
        record_evidence("focus", {"target": target, "query": query, "functions": [
            {"signature": signature, "score": score, "signals": signals}
            for score, signature, signals in rows
        ]})
    return 0


def workspace_paths():
    return {
        "root": WORKSPACE_DIR,
        "matrix": os.path.join(WORKSPACE_DIR, "matrix"),
        "matrix_actors": os.path.join(WORKSPACE_DIR, "matrix", "actors.json"),
        "matrix_states": os.path.join(WORKSPACE_DIR, "matrix", "states.json"),
        "matrix_scenarios": os.path.join(WORKSPACE_DIR, "matrix", "scenarios.json"),
        "notes": os.path.join(WORKSPACE_DIR, "notes.md"),
        "todos": os.path.join(WORKSPACE_DIR, "TODO.md"),
        "config": os.path.join(WORKSPACE_DIR, "config.json"),
        "findings": os.path.join(WORKSPACE_DIR, "findings.md"),
        "session": os.path.join(WORKSPACE_DIR, "history", "session.log"),
    }

def run_workspace(config,args):
    paths=workspace_paths(); action=args[0] if args else "init"
    if action!="init": print("Usage: lk workspace init"); return
    for directory in [paths["root"],os.path.join(paths["root"],"abi"),os.path.join(paths["root"],"transactions"),os.path.join(paths["root"],"traces"),os.path.join(paths["root"],"storage"),os.path.join(paths["root"],"findings"),os.path.join(paths["root"],"history"),os.path.join(paths["root"],"evidence"),os.path.join(paths["root"],"poc"),paths["matrix"]]:
        os.makedirs(directory,exist_ok=True)
    for key in ["notes","todos","findings"]:
        if not os.path.exists(paths[key]): open(paths[key],"w",encoding="utf-8").close()
    if not os.path.exists(paths["config"]):
        Path(paths["config"]).write_text(json.dumps({"target":config.get("target"),"rpc":rpc_display(config.get("rpc")),"abi":config.get("abi_paths",{}).get(config.get("target")),"created":datetime.now().isoformat(timespec="seconds")},indent=4),encoding="utf-8")
    print(f"Audit workspace ready: {paths['root']}")
def read_json_file(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default

def write_json_file(path, value):
    with open(path, "w") as f:
        json.dump(value, f, indent=4)

def solidity_identifier(value):
    value=re.sub(r"[^A-Za-z0-9_]", "_", str(value))
    if not value: value="scenario"
    if value[0].isdigit(): value="_"+value
    return value

def run_matrix(config,args):
    paths=workspace_paths()
    action=args[0] if args else "init"
    if action=="init":
        run_workspace(config,["init"])
        for path,default in [(paths["matrix_actors"],{}),(paths["matrix_states"],{}),(paths["matrix_scenarios"],[])]:
            if not os.path.exists(path): write_json_file(path,default)
        print("Attacker-state matrix initialized."); return
    if not os.path.exists(paths["matrix_scenarios"]):
        print("Error: Run lk matrix init first."); return
    if action=="actor" and len(args)==3:
        if not is_address(args[2]):
            print("Error: actor address must be a 20-byte hex address."); return
        actors=read_json_file(paths["matrix_actors"],{})
        actors[args[1]]={"address":args[2],"label":args[1]}
        write_json_file(paths["matrix_actors"],actors)
        print(f"Matrix actor saved: {args[1]}"); return
    if action=="add" and len(args)>=5:
        name=args[1]
        if name in {item.get("name") for item in read_json_file(paths["matrix_scenarios"],[])}:
            print(f"Error: Scenario already exists: {name}"); return
        scenario={
            "name":name,"target":config.get("target"),"function":args[2],"actor":args[3],
            "expected":" ".join(args[4:]),
            "evidence":{
                "last_tx":config.get("last_tx"),
                "snapshot":snapshot_path(config) if os.path.exists(snapshot_path(config)) else None,
                "session":SESSION_FILE,
            },
            "created":datetime.now().isoformat(timespec="seconds"),
        }
        scenarios=read_json_file(paths["matrix_scenarios"],[]); scenarios.append(scenario); write_json_file(paths["matrix_scenarios"],scenarios)
        if record_evidence:
            record_evidence("matrix_" + solidity_identifier(scenario["name"]), scenario)
        print(f"Scenario saved: {scenario['name']}"); return
    scenarios=read_json_file(paths["matrix_scenarios"],[])
    if action=="list":
        if not scenarios: print("No matrix scenarios yet."); return
        for scenario in scenarios: print(f"{scenario['name']}: {scenario['function']} as {scenario['actor']} -> {scenario['expected']}")
        return
    if action=="test" and len(args)==2:
        scenario=next((item for item in scenarios if item.get("name")==args[1]),None)
        if not scenario:
            print(f"Error: Scenario not found: {args[1]}"); return
        identifier=solidity_identifier(scenario["name"])
        actor=read_json_file(paths["matrix_actors"],{}).get(scenario["actor"],{}).get("address")
        actor_line=f"    address actor = {actor};\n" if actor else ""
        prank_line="        vm.prank(actor);\n" if actor else ""
        target=scenario["target"] if is_address(scenario.get("target")) else "address(0)"
        template=f'''pragma solidity ^0.8.20;
import "forge-std/Test.sol";

contract Matrix_{identifier} is Test {{
    address target = {target};
{actor_line}
    function test_{identifier}() public {{
        // Arrange: establish the precondition described in the scenario.
{prank_line}        // Act: call {scenario["function"]}
        // TODO: encode arguments and invoke the target.
        // Assert: expected outcome: {scenario["expected"]}
    }}
}}
'''
        os.makedirs("test",exist_ok=True)
        base=os.path.join("test",f"Matrix_{identifier}.t.sol")
        filename=base if not os.path.exists(base) else os.path.join("test",f"Matrix_{identifier}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.t.sol")
        Path(filename).write_text(template,encoding="utf-8")
        if record_evidence:
            record_evidence("generated_matrix_test_" + identifier, {"scenario":scenario,"file":filename})
        print(f"Matrix test skeleton generated: {filename}"); return
    print("Usage: lk matrix init | actor <name> <address> | state <name> <desc> | add <name> <function> <actor> <expected> | list | test <name>")

def run_note(note):
    if not note:
        print("Usage: lk note \"your note\"")
        return
    paths = workspace_paths()
    os.makedirs(paths["root"], exist_ok=True)
    with open(paths["notes"], "a") as f:
        f.write(f"- [{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}\n")
    if record_evidence:
        record_evidence("note_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"), {
            "note": note,
            "target": load_config().get("target"),
            "source": "lk note",
        })
    print("Note saved.")

def run_todo(todo):
    if not todo:
        print("Usage: lk todo \"task to investigate\"")
        return
    paths = workspace_paths()
    os.makedirs(paths["root"], exist_ok=True)
    with open(paths["todos"], "a") as f:
        f.write(f"- [ ] {todo}\n")
    if record_evidence:
        record_evidence("todo_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"), {
            "todo": todo,
            "target": load_config().get("target"),
            "source": "lk todo",
        })
    print("TODO saved.")

def run_session_lifecycle(config, action):
    paths = workspace_paths()
    if action == "start":
        os.makedirs(os.path.dirname(paths["session"]), exist_ok=True)
        config["session_active"] = True
        config["session_started"] = datetime.now().isoformat(timespec="seconds")
        save_config(config)
        with open(paths["session"], "a") as f:
            f.write(f"\nSESSION START {config['session_started']}\n")
        if record_evidence:
            record_evidence("session_start", {
                "project": os.getcwd(),
                "target": config.get("target"),
                "rpc": rpc_display(config.get("rpc")),
                "started": config["session_started"],
            })
        print("Audit session started.")
    elif action == "resume":
        config["session_active"] = True
        save_config(config)
        if record_evidence:
            record_evidence("session_resume", {
                "project": os.getcwd(),
                "target": config.get("target"),
                "rpc": rpc_display(config.get("rpc")),
                "resumed": datetime.now().isoformat(timespec="seconds"),
            })
        print(f"Audit session resumed: {paths['root']}")
    else:
        print("Usage: lk session start|resume")

def run_audit_startup(config):
    """Create/resume the project audit workspace and run the automatic baseline."""
    paths = workspace_paths()
    runtime = runtime_sync_status()
    if runtime["status"] == "stale":
        print("WARNING: installed Lowkey runtime is stale relative to its source checkout.")
        print(f"         {runtime['detail']}")
        if runtime.get("source_repo"):
            print(f"         Reinstall with: bash {runtime['source_repo']}/install.sh")
    elif runtime["status"] == "corrupt":
        print("WARNING: installed Lowkey runtime failed its install-manifest integrity check.")
        print(f"         {runtime['detail']}")
        if runtime.get("source_repo"):
            print(f"         Reinstall with: bash {runtime['source_repo']}/install.sh")
    run_workspace(config, ["init"])
    run_matrix(config, ["init"])
    run_checklist(config)

    if not config.get("session_active"):
        run_session_lifecycle(config, "start")
    else:
        run_session_lifecycle(config, "resume")

    context = {
        "project": os.getcwd(),
        "target": config.get("target"),
        "rpc": rpc_display(config.get("rpc")),
        "started": datetime.now().isoformat(timespec="seconds"),
        "workspace": paths["root"],
    }
    if record_evidence:
        record_evidence("audit_start", context)

    print("\n=== LOWKEY AUDIT STARTUP ===")
    print("Workspace initialized.")
    print("Evidence collection enabled.")
    print("Running baseline: build -> tests -> coverage -> Slither -> source triage.")

    baseline_code = run_audit_pipeline(".", [], False) if run_audit_pipeline else 0

    if generate_poc:
        print("\n=== LOWKEY AUDIT POC ===")
        generate_poc(".", None, None)

    print(f"\nBaseline status: {'PASS' if baseline_code == 0 else 'REVIEW NEEDED'}")
    return baseline_code


def run_export(config):
    paths=workspace_paths(); export_dir=os.path.join(os.getcwd(),"audit-report"); os.makedirs(export_dir,exist_ok=True)
    lines=["# LowkeyCast Audit Report","",f"- Target: {config.get('target') or 'Not set'}",f"- RPC: {rpc_display(config.get('rpc')) or 'Not set'}",f"- ABI: {config.get('abi_paths',{}).get(config.get('target')) or 'Not loaded'}",f"- Last transaction: {config.get('last_tx') or 'None'}",f"- Generated: {datetime.now().isoformat(timespec='seconds')}","","## Findings",""]
    finding_path=paths["findings"] if os.path.exists(paths["findings"]) else os.path.join(AUDIT_DIR,"findings.md")
    lines.append(Path(finding_path).read_text(encoding="utf-8") if os.path.exists(finding_path) else "No findings recorded.")
    lines += ["","## Checklist",""]
    checklist_path=os.path.join(AUDIT_DIR,"CHECKLIST.md")
    lines.append(Path(checklist_path).read_text(encoding="utf-8") if os.path.exists(checklist_path) else "No checklist initialized.")
    Path(os.path.join(export_dir,"report.md")).write_text("\n".join(lines),encoding="utf-8")
    for name,source in [("notes.md",paths["notes"]),("TODO.md",paths["todos"]),("session.log",paths["session"]),("matrix_actors.json",paths["matrix_actors"]),("matrix_states.json",paths["matrix_states"]),("matrix_scenarios.json",paths["matrix_scenarios"])]:
        if os.path.exists(source): Path(os.path.join(export_dir,name)).write_text(Path(source).read_text(encoding="utf-8"),encoding="utf-8")
    Path(os.path.join(export_dir,"contract.json")).write_text(json.dumps({"target":config.get("target"),"rpc":rpc_display(config.get("rpc")),"abi":config.get("abi_paths",{}).get(config.get("target")),"last_tx":config.get("last_tx")},indent=4),encoding="utf-8")
    evidence_dir=os.path.join(WORKSPACE_DIR,"evidence")
    poc_dir=os.path.join(WORKSPACE_DIR,"poc")
    if os.path.isdir(evidence_dir):
        import shutil as _shutil
        _shutil.copytree(evidence_dir,os.path.join(export_dir,"evidence"),dirs_exist_ok=True)
    if os.path.isdir(poc_dir):
        import shutil as _shutil
        _shutil.copytree(poc_dir,os.path.join(export_dir,"poc"),dirs_exist_ok=True)
    print(f"Audit report exported: {export_dir}")
def run_self_test():
    checks=[
        ("address validation",is_address("0x"+"1"*40) and not is_address("0x"+"1"*64) and not is_address(None)),
        ("slot validation",is_nonzero_slot("0x"+"1"+"0"*63) and not is_nonzero_slot("not-hex")),
        ("ETH formatting","1.0000 ETH" in humanize_value("1000000000000000000")),
        ("secret redaction","<redacted>" in redact_secrets("--private-key 0x"+"1"*64)),
        ("jwt redaction","<redacted>" in redact_secrets("--jwt-secret supersecret")),
        ("rpc redaction","sensitive-token" not in redact_secrets("--rpc-url https://example.com/sensitive-token")),
        ("tuple canonicalization",canonical_type({"type":"tuple","components":[{"type":"address"},{"type":"uint256"}]})=="(address,uint256)"),
        ("nested tuple array",canonical_type({"type":"tuple[]","components":[{"type":"address"},{"type":"uint256[]"}]})=="(address,uint256[])[]"),
        ("output signature",format_output_signature({"name":"f","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]})=="f(address)(uint256)"),
        ("target alias resolution",resolve_target_ref({"aliases":{"one":"0x"+"1"*40},"targets":{}},"one")=="0x"+"1"*40),
        ("safe solidity identifier",solidity_identifier("unauthorized release #1")=="unauthorized_release__1"),
    ]
    failed=[name for name,passed in checks if not passed]
    for name,passed in checks: print(f"{'PASS' if passed else 'FAIL'}  {name}")
    if failed:
        print("Self-test failed: "+", ".join(failed)); return 1
    print(f"Self-test passed ({len(checks)} checks)."); return 0

def run_doctor():
    failures = 0
    project = detect_project(".") if detect_project else {"kind": "generic", "build_systems": []}
    systems = set(project.get("build_systems", []))

    print("Lowkey doctor")
    print("============")
    print(f"PROJECT  {project.get('kind', 'generic')}")
    print(f"LANGUAGES {', '.join(project.get('languages', [])) or 'none detected'}")
    print(f"TOOLCHAINS {', '.join(project.get('build_systems', [])) or 'none detected'}")

    for name in ("python3",):
        path = shutil.which(name)
        if not path:
            print(f"FAIL  {name}: not found")
            failures += 1
            continue
        try:
            result = subprocess.run([path, "--version"], capture_output=True, text=True)
            version = (result.stdout or result.stderr).splitlines()[0] if result.returncode == 0 else "version check failed"
        except OSError as error:
            print(f"FAIL  {name}: {error}")
            failures += 1
            continue
        print(f"{'PASS' if result.returncode == 0 else 'FAIL'}  {name}: {path} ({version})")
        if result.returncode != 0:
            failures += 1

    if "vyper" in systems:
        uv = shutil.which("uv")
        if uv:
            try:
                result = subprocess.run([uv, "--version"], capture_output=True, text=True)
                version = (result.stdout or result.stderr).splitlines()[0] if result.returncode == 0 else "version check failed"
                print(f"{'PASS' if result.returncode == 0 else 'FAIL'}  uv: {uv} ({version})")
                if result.returncode != 0:
                    failures += 1
            except OSError as error:
                print(f"FAIL  uv: {error}")
                failures += 1
        else:
            print("FAIL  uv: not found (required by detected Vyper/uv project)")
            failures += 1

    foundry_required = "foundry" in systems
    for name in ("cast", "forge", "anvil"):
        path = shutil.which(name)
        if not path:
            if foundry_required:
                print(f"FAIL  {name}: not found")
                failures += 1
            else:
                print(f"INFO  {name}: not found (not required by detected project type)")
            continue
        try:
            result = subprocess.run([path, "--version"], capture_output=True, text=True)
            version = (result.stdout or result.stderr).splitlines()[0] if result.returncode == 0 else "version check failed"
        except OSError as error:
            print(f"WARN  {name}: {error}")
            continue
        print(f"PASS  {name}: {path} ({version})")

    print("OPTIONAL AUDIT TOOLS")
    for name in ("rg", "slither"):
        path = shutil.which(name)
        if not path:
            print(f"INFO  {name}: not found (optional)")
            continue
        try:
            result = subprocess.run([path, "--version"], capture_output=True, text=True)
            version = (result.stdout or result.stderr).splitlines()[0] if result.returncode == 0 else "version check failed"
        except OSError as error:
            print(f"WARN  {name}: {error}")
            continue
        print(f"PASS  {name}: {path} ({version})")

    forge = shutil.which("forge")
    if forge and foundry_required:
        try:
            result = subprocess.run([forge, "--help"], capture_output=True, text=True)
            advertised = set(FORGE_NATIVE_COMMANDS)
            available = {
                line.strip().split()[0]
                for line in result.stdout.splitlines()
                if line.startswith("  ") and line.strip() and not line.strip().startswith("-")
            }
            missing = sorted(advertised - available)
            if missing:
                print(f"FAIL  forge commands missing: {', '.join(missing)}")
                failures += 1
            else:
                print(f"PASS  forge commands: {', '.join(sorted(advertised))}")
        except OSError as error:
            print(f"FAIL  forge command check: {error}")
            failures += 1

    for command, args in (
        ("cast decode-event", ["cast", "decode-event", "--help"]),
        ("cast receipt", ["cast", "receipt", "--help"]),
        ("cast sig-event", ["cast", "sig-event", "--help"]),
        ("forge inspect", ["forge", "inspect", "--help"]),
    ):
        if not shutil.which(args[0]):
            if foundry_required:
                print(f"FAIL  dependency command: {command} (binary not found)")
                failures += 1
            else:
                print(f"INFO  dependency command: {command} not required by detected project type")
            continue
        try:
            result = subprocess.run(args, capture_output=True, text=True)
        except OSError:
            result = None
        if result is not None and result.returncode == 0:
            print(f"PASS  dependency command: {command}")
        else:
            if foundry_required:
                print(f"FAIL  dependency command: {command}")
                failures += 1
            else:
                print(f"INFO  dependency command: {command} check skipped")

    runtime = runtime_sync_status()
    if runtime["status"] == "ok":
        print(f"PASS  Lowkey runtime: {runtime['detail']}")
    elif runtime["status"] == "stale":
        print(f"WARN  Lowkey runtime: {runtime['detail']}")
        print(f"      reinstall with: bash {runtime.get('source_repo') or '<source-repo>'}/install.sh")
    elif runtime["status"] == "corrupt":
        print(f"FAIL  Lowkey runtime: {runtime['detail']}")
        failures += 1
    else:
        print(f"INFO  Lowkey runtime: {runtime['detail']}")

    return 1 if failures else 0


def run_test_gen(config):
    if not os.path.exists(SESSION_FILE):
        print("Error: No session history found."); return
    lines=Path(SESSION_FILE).read_text(encoding="utf-8").splitlines()
    last_send=next((line.split("CMD: ",1)[1].strip() for line in reversed(lines) if "CMD: cast send " in line),None)
    if not last_send:
        print("Error: No send transaction found in session."); return
    try:
        parts=shlex.split(last_send)
        send_index=parts.index("send")
        target=parts[send_index+1]; func=parts[send_index+2]
        positional=[]; value="0"; index=send_index+3
        while index<len(parts):
            if parts[index]=="--value" and index+1<len(parts):
                value=parts[index+1]; index+=2; continue
            if parts[index].startswith("--"):
                index+=2 if index+1<len(parts) and not parts[index+1].startswith("--") else 1; continue
            positional.append(parts[index]); index+=1
        code,encoded,error=cast_output(["cast","calldata",func,*positional])
        if code!=0 and not encoded:
            print(f"Error generating calldata: {error}"); return
        calldata=encoded.removeprefix("0x")
    except (ValueError,IndexError) as error:
        print(f"Error generating test: {error}"); return
    value_expression=value
    for unit in ["ether","gwei","wei"]:
        if unit in value_expression and " " not in value_expression:
            value_expression=value_expression.replace(unit,f" {unit}")
    test=f'''pragma solidity ^0.8.20;
import "forge-std/Test.sol";

contract Exploit_Reproduction is Test {{
    address constant TARGET = {target};

    function test_reproduce() public {{
        uint256 value = {value_expression};
        vm.deal(address(this), value);
        (bool success, bytes memory data) = TARGET.call{{value: value}}(hex"{calldata}");
        assertTrue(success, string(data));
    }}
}}
'''
    os.makedirs("test",exist_ok=True)
    filename=os.path.join("test",f"Exploit_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.t.sol")
    Path(filename).write_text(test,encoding="utf-8")
    print(f"Exploit reproduction generated: {filename}")
def run_checklist(config,action=None,item=None):
    path=os.path.join(AUDIT_DIR,"CHECKLIST.md"); os.makedirs(AUDIT_DIR,exist_ok=True)
    if not os.path.exists(path): Path(path).write_text("\n".join(f"- [ ] {x}" for x in AUDIT_CHECKLIST)+"\n",encoding="utf-8")
    lines=Path(path).read_text(encoding="utf-8").splitlines(True)
    if action=="reset":
        Path(path).write_text("\n".join(f"- [ ] {x}" for x in AUDIT_CHECKLIST)+"\n",encoding="utf-8"); print("Checklist reset."); return
    if action=="done" and item:
        q=item.lower()
        for i,line in enumerate(lines):
            if q in line.lower() and "[ ]" in line:
                lines[i]=line.replace("[ ]","[x]",1); Path(path).write_text("".join(lines),encoding="utf-8"); print(f"Marked complete: {line.strip()[6:]}"); return
        print(f"Checklist item not found: {item}"); return
    print("".join(lines))
def run_targets(config):
    aliases=target_aliases(config); current=config.get("target")
    if not aliases: print("No saved targets. Use lk target <name> <address>."); return
    for i,(name,address) in enumerate(aliases.items(),1):
        print(f"{'*' if address==current else ' '} {i:>2}. {name:<20} {address}")

def discover_deployments(root="."):
    records=[]
    for path in artifact_json_files(root):
        if not path.startswith(os.path.join(root,"broadcast")): continue
        try: payload=json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError): continue
        txs=payload.get("transactions",[]) if isinstance(payload,dict) else []
        if not isinstance(txs,list): continue
        mtime=os.path.getmtime(path)
        for tx in txs:
            if not isinstance(tx,dict): continue
            tx_type=str(tx.get("transactionType","")).upper(); address=tx.get("contractAddress") or tx.get("address")
            if tx_type.startswith("CREATE") and is_address(address):
                records.append({"contract":tx.get("contractName") or "Unknown","address":address,"file":path,"time":mtime,"hash":tx.get("hash")})
    return sorted(records,key=lambda x:x["time"],reverse=True)

def run_deployments(config):
    records=discover_deployments(".")
    if not records: print("No Foundry broadcast deployments discovered."); return
    seen=set()
    for r in records:
        key=(r["contract"],r["address"])
        if key in seen: continue
        seen.add(key); print(f"{r['contract']:<24} {r['address']}  {r['file']}")

def run_auto_target(config,name=None):
    records=discover_deployments(".")
    if not records: print("No deployment found in broadcast/."); return
    record=records[0]; alias=name or record["contract"]
    config["aliases"][alias]=record["address"]; config["targets"][alias]=record["address"]; config["target"]=record["address"]
    for path in artifact_json_files("."):
        if os.path.join(".","out") in path and os.path.basename(path)==f"{record['contract']}.json":
            config["abi_paths"][record["address"]]=path; print(f"ABI auto-loaded: {path}"); break
    save_config(config); print(f"Target selected: {alias} -> {record['address']}")

def run_ens(config,args):
    if not args: print("Usage: lk ens <name|address>"); return
    value=args[0]; run_cast(["lookup-address",value] if is_address(value) else ["resolve-name",value],config)

def run_token(config,args):
    if not args: print("Usage: lk token <token> | lk token balance <token> <holder>"); return
    if args[0]=="balance":
        if len(args)!=3: print("Usage: lk token balance <token> <holder>"); return
        run_cast(["erc20-token","balance",args[1],args[2]],config); return
    for action in ["name","symbol","decimals","total-supply"]: run_cast(["erc20-token",action,args[0]],config)

def run_decode(config,args):
    if len(args)<2: print("Usage: lk decode <function> <return-data>"); return
    matches=matching_functions(load_abi(config.get("target"),config),args[0])
    if len(matches)!=1: print("Error: function must resolve to exactly one ABI entry."); return
    item=matches[0]
    if not item.get("outputs"): print("Function has no outputs."); return
    run_cast(["decode-abi",format_output_signature(item),args[1]],config)

def decode_event_values(event,data,topics):
    if not topics or len(topics[0])!=66:
        return fail("Error: event topics must include a 32-byte topic0.")
    expected=cast_output(["cast","sig-event",format_signature(event)])[1].lower().strip()
    if topics[0].lower()!=expected:
        return fail("Error: topic0 does not match the event signature.")
    indexed=[item for item in event.get("inputs",[]) if item.get("indexed")]
    non_indexed=[item for item in event.get("inputs",[]) if not item.get("indexed")]
    if len(topics)-1!=len(indexed):
        return fail(f"Error: expected {len(indexed)} indexed topics, received {len(topics)-1}.")
    print(f"Event: {format_signature(event)}")
    status=0
    for item,topic in zip(indexed,topics[1:]):
        value=topic
        item_type=canonical_type(item)
        if not any(token in item_type for token in ("bytes", "string", "[", "tuple")):
            code,decoded,error=cast_output(["cast","decode-abi",f"value()({item_type})",topic])
            if code==0 and decoded: value=decoded
            elif code!=0: status=code
        print(f"Indexed {item.get('name') or '<anonymous>'}: {value}")
    if non_indexed:
        output_types=",".join(canonical_type(item) for item in non_indexed)
        code,decoded,error=cast_output(["cast","decode-abi",f"event()({output_types})",data])
        if code!=0:
            if error: print(error,file=sys.stderr)
            status=code
        elif decoded:
            print(f"Data: {decoded}")
    return record_status(status)

def run_event(config,args):
    if len(args)<2:
        return fail("Usage: lk event <event-signature> <data> [topic0 indexed-topic ...]")
    signature,data,*topics=args
    try: payload=event_payload(data,topics)
    except ValueError as error: return fail(f"Error: {error}")
    if topics:
        abi=load_abi(config.get("target"),config)
        event=next((item for item in abi if item.get("type")=="event" and format_signature(item)==signature),None)
        if event:
            return decode_event_values(event,data,topics)
    code,output,error=cast_output(["cast","decode-event","--sig",signature,payload])
    if output: print(output)
    if error: print(error,file=sys.stderr)
    return record_status(code)

def event_payload(data,topics):
    parts=[]
    for value in list(topics)+[data]:
        if not re.fullmatch(r"0x[0-9a-fA-F]*",value or "") or len(value)%2:
            raise ValueError(f"event data/topics must be even-length hex: {value}")
        parts.append(value[2:])
    return "0x"+"".join(parts)

def run_namespace(config,args):
    if len(args)!=1: print("Usage: lk namespace <erc7201-namespace-id>"); return
    run_cast(["index-erc7201",args[0]],config)

def run_proof(config,args):
    if not args: print("Usage: lk proof <slot> [block]"); return
    run_cast(["proof",config.get("target"),args[0]]+(["--block",args[1]] if len(args)>1 else []),config)

def run_selectors(config,args):
    code=args[0] if args else run_cast(["code",config.get("target")],config,capture=True)
    if not code or not str(code).startswith("0x"): return fail("Error: no runtime bytecode available.")
    run_cast(["selectors",code],config)

def run_layout(args):
    if not args: return fail("Usage: lk layout <ContractName>")
    code,out,err=cast_output(["forge","inspect",args[0],"storage-layout","--json"])
    if code!=0:
        print(err or "forge inspect failed",file=sys.stderr)
        return record_status(code)
    try: payload=json.loads(out)
    except json.JSONDecodeError: print(out); return
    storage=payload.get("storage",payload) if isinstance(payload,dict) else payload
    if isinstance(storage,list):
        print("Storage layout:")
        for entry in storage:
            if isinstance(entry,dict): print(f"slot={entry.get('slot')} offset={entry.get('offset')} label={entry.get('label')} type={entry.get('type')}")
    else: print(json.dumps(payload,indent=2))

def source_sol_files(root="."):
    """Backward-compatible Solidity-only source listing."""
    if os.path.isfile(root):
        return [root] if str(root).lower().endswith(".sol") else []
    if project_source_files:
        return [str(path) for path in project_source_files(root, {"sol"})]
    root_path = Path(root)
    return sorted(
        str(path)
        for path in root_path.rglob("*.sol")
        if not any(part in {".git", "out", "cache", "lib", ".audit"} for part in path.parts)
    )


def _source_files_for_scan(root):
    if os.path.isfile(root):
        return [Path(root)]
    if project_source_files:
        return list(project_source_files(root))
    return [Path(path) for path in source_sol_files(root)]


def run_scan(args):
    root=args[0] if args else "."
    if not os.path.exists(root):
        return fail(f"Path not found: {root}")
    if not os.path.isdir(root) and not str(root).lower().endswith((".sol", ".vy", ".vyi")):
        return fail(f"Path is not a supported source file or directory: {root}")

    patterns = {
        ".sol": [
            ("REENTRANCY REVIEW", re.compile(r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()")),
            ("ETH TRANSFER REVIEW", re.compile(r"\.(transfer|send)\s*\(")),
            ("TX.ORIGIN", re.compile(r"\btx\.origin\b")),
            ("DELEGATECALL", re.compile(r"\bdelegatecall\b")),
            ("SELFDESTRUCT", re.compile(r"\bselfdestruct\s*\(")),
            ("UNCHECKED", re.compile(r"\bunchecked\s*\{")),
            ("ASSEMBLY", re.compile(r"\bassembly\s*\{")),
            ("ENCODE_PACKED", re.compile(r"\babi\.encodePacked\s*\(")),
            ("TIMESTAMP", re.compile(r"\bblock\.timestamp\b")),
            ("BLOCKHASH", re.compile(r"\bblock\.hash\s*\(|\bblockhash\s*\(")),
            ("PREVRANDAO", re.compile(r"\bblock\.prevrandao\b")),
            ("ECRECOVER", re.compile(r"\becrecover\s*\(")),
            ("CREATE2", re.compile(r"\bcreate2\b")),
        ],
        ".vy": [
            ("RAW_CALL", re.compile(r"\braw_call\s*\(")),
            ("EXTERNAL_CALL", re.compile(r"\b(?:extcall|staticcall)\b")),
            ("ETH TRANSFER", re.compile(r"\bsend\s*\(")),
            ("CREATE", re.compile(r"\bcreate_(?:minimal_proxy_to|forwarder_to|from_blueprint)\b")),
            ("SELFDESTRUCT", re.compile(r"\bselfdestruct\s*\(")),
            ("TX.ORIGIN", re.compile(r"\btx\.origin\b")),
            ("TIMESTAMP", re.compile(r"\bblock\.timestamp\b")),
            ("BLOCK NUMBER", re.compile(r"\bblock\.number\b")),
            ("PREV HASH", re.compile(r"\bblock\.prevhash\b")),
            ("RAW LOG", re.compile(r"\braw_log\s*\(")),
        ],
        ".vyi": [],
    }

    files = _source_files_for_scan(root)
    hits = 0
    markers = []
    for path in files:
        suffix = path.suffix.lower()
        if suffix not in patterns:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            for label, pattern in patterns[suffix]:
                if pattern.search(line):
                    hits += 1
                    marker = {
                        "file": str(path.resolve()),
                        "line": lineno,
                        "language": "solidity" if suffix == ".sol" else "vyper",
                        "label": label,
                        "text": line.strip(),
                    }
                    markers.append(marker)
                    print(
                        f"{marker['file']}:{lineno}: "
                        f"[{marker['language']}:{label}] {line.strip()}"
                    )

    if record_evidence:
        record_evidence(
            "source_scan",
            {
                "root": str(Path(root).resolve()),
                "project": detect_project(root) if detect_project else None,
                "files_scanned": len(files),
                "count": hits,
                "markers": markers,
            },
        )
    print(f"\nReview markers: {hits}")
    print("These are source-level review markers, not vulnerability verdicts.")
    return 0


def run_deps(args):
    root = args[0] if args else "."
    if not os.path.exists(root):
        return fail(f"Path not found: {root}")

    if build_dependency_graph:
        payload = build_dependency_graph(root)
        summary = payload.get("summary", {})
        print("LOWKEY SYSTEM GRAPH")
        print("=" * 72)
        print(
            f"Files: {summary.get('files', 0)} | "
            f"Imports: {summary.get('imports', 0)} | "
            f"Inheritance: {summary.get('inheritance', 0)} | "
            f"Call sites: {summary.get('external_call_sites', 0)} | "
            f"Unresolved: {summary.get('unresolved_imports', 0)}"
        )
        for edge in payload.get("edges", []):
            state = "OK" if edge.get("resolved") else "UNRESOLVED"
            extra = f" [{', '.join(edge.get('symbols', []))}]" if edge.get("symbols") else ""
            print(
                f"  {state:<10} {edge.get('from')} -> {edge.get('to')} "
                f"({edge.get('kind')}, line {edge.get('line')}){extra}"
            )
        unresolved = payload.get("unresolved", [])
        if unresolved:
            print("\nUnresolved/external imports:")
            for edge in unresolved:
                print(f"  {edge.get('from')}:{edge.get('line')} -> {edge.get('to')}")
        if record_evidence:
            record_evidence("dependencies", payload)
        return 0

    files = source_sol_files(root)
    if not files:
        print(f"No Solidity files found under {root}.")
        return 0
    print("Dependency / inheritance map:")
    imports=[]; inherits=[]
    for path in files:
        try:
            text_content=Path(path).read_text(encoding="utf-8")
        except OSError:
            continue
        rel=os.path.relpath(path,root)
        for imported in re.findall(r'import\s+(?:[^;]*from\s+)?["\']([^"\']+)["\']\s*;',text_content):
            item={"file":rel,"import":imported}; imports.append(item); print(f"  {rel} -> import {imported}")
        for contract in re.finditer(r"\b(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?",text_content):
            for parent in [p.strip().split()[0] for p in (contract.group(3) or "").split(",") if p.strip()]:
                item={"file":rel,"contract":contract.group(2),"inherits":parent}; inherits.append(item); print(f"  {contract.group(2)} -> inherits {parent} [{rel}]")
    if record_evidence:
        record_evidence("dependencies", {"root":root,"imports":imports,"inherits":inherits})
    return 0


def run_project(args=None):
    if render_project_map is None:
        return fail("Project analysis module is not installed. Reinstall Lowkey.")
    return 0 if render_project_map(args[0] if args else ".") else 0

def run_walkthrough(args=None):
    """Project-agnostic protocol/system walkthrough using Lowkey's source graph."""
    if render_project_map is None:
        return fail("Project analysis module is not installed. Reinstall Lowkey.")

    root = args[0] if args else "."
    payload = render_project_map(root)
    project = payload.get("project", {})
    graph = payload.get("graph", {})

    print("\nPROTOCOL / SYSTEM WALKTHROUGH")
    print("=" * 72)
    print(f"Project type : {project.get('kind', 'generic')}")
    print(f"Languages    : {', '.join(project.get('languages', [])) or 'unknown'}")
    print(f"Toolchains   : {', '.join(project.get('build_systems', [])) or 'unknown'}")
    print(f"Source roots : {', '.join(project.get('source_roots', [])) or '.'}")

    print("\nCONTRACT / MODULES")
    print("-" * 72)
    for node in graph.get("nodes", []):
        declarations = node.get("declarations", [])
        names = ", ".join(
            f"{item.get('kind')} {item.get('name')}"
            for item in declarations
        )
        print(f"- {node.get('file')} [{node.get('language')}]")
        if names:
            print(f"  declarations: {names}")
        calls = node.get("calls", [])
        for call in calls[:20]:
            print(f"  call: {call.get('kind')} @ line {call.get('line')}: {call.get('text')}")

    print("\nRELATIONSHIPS")
    print("-" * 72)
    for edge in graph.get("edges", []):
        state = "RESOLVED" if edge.get("resolved") else "UNRESOLVED"
        print(
            f"- {edge.get('from')} -> {edge.get('to')} "
            f"[{edge.get('kind')}, {state}, line {edge.get('line')}]"
        )

    if graph.get("unresolved"):
        print("\nREVIEW REQUIRED")
        print("-" * 72)
        for edge in graph["unresolved"]:
            print(f"- Resolve/understand dependency: {edge.get('from')} -> {edge.get('to')}")

    if record_evidence:
        record_evidence(
            "protocol_walkthrough",
            {
                "project": project,
                "graph_summary": graph.get("summary", {}),
                "relationships": graph.get("edges", []),
                "unresolved": graph.get("unresolved", []),
            },
        )
    print("\nWalkthrough is source-derived; runtime/deployment behavior still needs to be validated.")
    return 0

def run_risk(config):
    target=config.get("target")
    if not target:
        print("Error: Set target first."); return
    funcs=abi_functions(load_abi(target,config))
    if not funcs:
        print("Error: No ABI functions loaded."); return
    print("Function review-surface heuristic:")
    rows=[]
    for item in funcs:
        name=item.get("name","").lower(); signals=[]
        if item.get("stateMutability") in {"nonpayable","payable"}: signals.append("state-write")
        if item.get("stateMutability")=="payable": signals.append("value-flow")
        if any(x in name for x in ["owner","admin","role","upgrade","pause","unpause"]): signals.append("privileged-looking")
        if any(x in name for x in ["withdraw","transfer","send","execute","call","mint","burn","sweep"]): signals.append("asset/action")
        if any(canonical_type(i).startswith("address") for i in item.get("inputs",[])): signals.append("address-input")
        rows.append({"signature":format_signature(item),"signals":signals})
        print(f"{format_signature(item):55}  {', '.join(signals) if signals else 'no heuristic signals'}")
    if record_evidence:
        record_evidence("risk", {"target":target,"functions":rows})
def run_gas(config,args):
    if not args:
        print("Usage: lk gas <function> [args]"); return
    target=config.get("target")
    if not target:
        print("Error: Set target first."); return
    values=list(args)
    if values and ("(" not in values[0] or ")" not in values[0]):
        try: values[0]=resolve_function(values[0],target,config)
        except ValueError as error:
            print(f"Error: {error}",file=sys.stderr); return
    run_cast(["estimate",target]+values,config)
def run_raw(config,args):
    if not args: return fail("Usage: lk raw <cast-subcommand> [args...]")
    safe=redact_secrets(shlex.join(["cast"]+args)); print(f"DEBUG: Executing -> {safe}")
    code,out,err=cast_output(["cast"]+args); log_session(safe,out or err)
    if out: print(humanize_value(apply_labels(out,config)))
    if err: print(err,file=sys.stderr)
    return record_status(code)

def run_batch(config,args):
    if len(args)!=1:
        print("Usage: lk batch <command-file>"); return
    path=args[0]
    if not os.path.exists(path):
        print(f"Batch file not found: {path}"); return
    for lineno,line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(),1):
        stripped=line.strip()
        if not stripped or stripped.startswith("#"): continue
        try: tokens=shlex.split(stripped)
        except ValueError as error:
            print(f"Batch line {lineno}: {error}",file=sys.stderr); continue
        if not tokens: continue
        command=tokens[0]
        command_args=tokens[1:]
        if command in {"s","send"} and "--yes" not in command_args and "--confirm" not in command_args and "--preview" not in command_args and "--dry-run" not in command_args:
            command_args.append("--confirm")
        if command=="raw": run_raw(config,command_args)
        else: dispatch_command(command,command_args,config,from_batch=True)
def run_audit_mode(config):
    print("\n=== LOWKEYCAST AUDIT MODE ===")
    config["audit_project"] = os.getcwd()
    save_config(config)

    # Every explicit audit launch gets a fresh baseline against the
    # current checkout, while the project-local evidence workspace persists.
    run_audit_startup(config)

    while True:
        print(f"\nTarget: {config.get('target') or 'none'} | RPC: {rpc_display(config.get('rpc')) or 'none'}")
        print("1) recon   2) functions   3) risk   4) checklist   5) targets   6) deployments   7) full evidence pass   8) generate PoC   9) protocol walkthrough   0) exit")
        try: choice=input("lk> ").strip()
        except EOFError: return
        if choice=="1": run_recon(config)
        elif choice=="2": run_functions(config)
        elif choice=="3": run_risk(config)
        elif choice=="4": run_checklist(config)
        elif choice=="5": run_targets(config)
        elif choice=="6": run_deployments(config)
        elif choice=="7" and run_audit_pipeline: run_audit_pipeline(".")
        elif choice=="8" and generate_poc: generate_poc(".", None, None)
        elif choice=="9": run_walkthrough([])
        elif choice=="0":
            if generate_poc:
                print("\nRefreshing PoC before leaving audit mode...")
                generate_poc(".", None, None)
            return
        else: print("Unknown option.")


def run_version():
    runtime = runtime_sync_status()
    print("LowkeyCast 2.1")
    print(f"Runtime: {runtime['status'].upper()} - {runtime['detail']}")
    if runtime.get("source_repo"):
        print(f"Source : {runtime['source_repo']}")


def actor_display(config):
    actor=config.get("actor")
    if not actor: return "none"
    if actor in config.get("wallets",{}): return str(actor)
    if is_probable_private_key(actor): return "<raw private key configured>"
    return str(actor)

def run_status(config):
    print(f"Target : {config.get('target') or 'none'}")
    print(f"RPC    : {rpc_display(config.get('rpc')) or 'none'}")
    print(f"Actor  : {actor_display(config)}")
    print(f"ABI    : {config.get('abi_paths',{}).get(config.get('target')) or 'not loaded'}")
    print(f"LastTX : {config.get('last_tx') or 'none'}")

def run_wizard(config,args):
    if not args:
        print("Usage: lk wizard <function> [call|send|encode]")
        return
    mode=args[1].lower() if len(args)>1 else "call"
    if mode not in {"call","send","encode"}:
        print("Mode must be call, send, or encode."); return
    target=config.get("target")
    if not target:
        print("Error: Set target first."); return
    funcs=abi_functions(load_abi(target,config))
    matches=matching_functions(funcs,args[0])
    if len(matches)!=1:
        print("Function must resolve to exactly one ABI entry.")
        for item in sorted(funcs,key=lambda x:function_score(x,args[0]),reverse=True)[:8]:
            print(" ",format_signature(item))
        return
    item=matches[0]; signature=format_signature(item); values=[]
    print(f"Function: {signature}")
    for index,param in enumerate(item.get("inputs",[]),1):
        label=param.get("name") or f"arg{index}"
        try: value=input(f"{label} ({canonical_type(param)}): ").strip()
        except EOFError: print("Wizard cancelled."); return
        if not value:
            print("Argument values are required."); return
        values.append(value)
    if mode=="encode": run_cast(["calldata",signature,*values],config)
    elif mode=="send": run_cast(["send",signature,*values,"--confirm"],config)
    else: run_cast(["call",signature,*values],config)

def run_replay(config,args):
    if not args:
        print("Usage: lk replay <transaction-hash> [trace flags...]"); return
    run_trace(config,args)

def run_fork(args):
    if not args:
        print("Usage: lk fork <rpc-url> [block-number]"); return
    rpc=args[0]
    command=["anvil","--fork-url",rpc]
    if len(args)>1: command.extend(["--fork-block-number",args[1]])
    print("Start a local fork with:")
    print("  "+redact_secrets(shlex.join(command)))
    print("Then point LowkeyCast at it:")
    print("  lk rpc http://127.0.0.1:8545")
def print_help():
    print("""
LowkeyCast - Foundry auditor interface

CORE
  lk target <addr>                    Set target
  lk target <name> <addr>             Save + select target
  lk target list                      List saved targets
  lk target auto [name]               Use latest broadcast deployment
  lk use <name|number>                Switch target
  lk deployments                      List deployments
  lk status                           Show target/RPC/actor/ABI/last tx
  lk rpc <url>                        Set RPC
  lk rpc set <name> <url>             Save RPC profile
  lk rpc use <name>                   Select RPC profile
  lk wallet list                      List signer profiles
  lk wallet set <name> <private-key>  Save local test key (plaintext on disk)
  lk wallet set-env <name> <ENV_VAR>  Use environment-backed signer
  lk wallet use <name>                Select signer
  lk wallet remove <name>             Remove signer
  lk actor reset                      Clear signer

ABI / INTERACTION
  lk abi <path>                       Load ABI
  lk abi auto                         Auto-load ABI
  lk functions [query]                List/fuzzy-find functions
  lk fn <query>                       Fuzzy-find functions
  lk ask <function>                   Show argument names/types
  lk wizard <function> [mode]         Prompt for call/send/encode arguments
  lk c <func> [args]                  Read
  lk s <func> [args]                  Send
  lk s ... --preview                  Preview without sending
  lk s ... --confirm                  Preview + confirmation prompt
  lk encode <func> [args]             Build calldata
  lk decode <function> <return-data>  Decode return values
  lk decode-error <revert-data>       Decode custom error
    lk event <sig> <data> [topic0 indexed-topic ...]
                                                                            Topics are prepended to one Cast DATA payload
  lk tx [hash]                        Inspect/decode transaction
  lk raw <cast-command> ...           Raw Cast bypass

INSPECTION
  lk info                             Target/chain/code/ABI/proxy
  lk recon                            Balance/codehash/codesize/nonce
  lk proxy                            Proxy + implementation/admin
  lk implementation                   Resolve implementation
  lk admin                            Resolve proxy admin
  lk selectors                        Extract runtime selectors
  lk mapping <slot> <key>             Compute/read mapping slot
  lk mapping <type> <slot> <key>      Explicit key type
  lk namespace <id>                   ERC-7201 namespace slot
  lk proof <slot> [block]             Storage proof
  lk snapshot [slot ...]              Save target/chain-scoped storage
  lk diff                             Compare snapshot
  lk ens <name|address>               ENS lookup
  lk token <token>                    ERC20 metadata
  lk token balance <token> <holder>   ERC20 balance

SOURCE TRIAGE
  lk scan [src]                       High-signal Solidity review markers
  lk rg <pattern> [path]              Ripgrep search + evidence capture
  lk slither [args...]                Slither static analysis + normalized evidence
  lk deps [src]                       Import/inheritance map
  lk project                           Detect project/toolchain + print whole-system graph
  lk walkthrough                       Source-derived protocol/system walkthrough
  lk layout <ContractName>            Forge storage layout
  lk risk                             ABI-level function risk heuristic
  lk gas <func> [args]                Estimate gas
  lk trace [tx] [flags]               Replay/trace transaction
  lk replay <tx> [flags...]            Explicit replay alias
  lk fork <rpc-url> [block]           Print Anvil fork command
  lk logs [args...]                   Query logs
  lk logs --decode [args...]          Query + decode ABI events

AUDIT OS
  lk audit                            Interactive dashboard
  lk audit --checks                   Run full evidence pass + checks + dashboard
  lk audit--checks                   Legacy compact alias for audit --checks
  lk findings                         Show stored Slither/manual findings
  lk focus [query]                   Show high-signal ABI review surfaces
  lk audit run [--slither ARG...]     Build -> tests -> coverage -> Slither
  lk audit run --poc                  Same pipeline + first PoC scaffold
  lk poc [--finding N]                Generate PoC from accumulated evidence
  lk finding <note>                   Record observation
  lk finding add <severity> <title> <text>
  lk checklist                       View/mark/reset checklist
  lk matrix init                      Initialize attacker-state matrix
  lk matrix actor <name> <addr>       Add actor
  lk matrix state <name> <desc>       Add state definition
  lk matrix add <name> <func> <actor> <expected>
  lk matrix list                      List scenarios
  lk matrix test <name>               Generate Forge test skeleton
  lk test-gen                         Reproduce latest send as Forge test
  lk note <text>                      Save audit note
  lk todo <text>                      Add audit TODO
  lk session [start|resume|end]       Audit session lifecycle
  lk export                           Build audit-report/
  lk batch <file>                     Run one lk command per line
  lk self-test                        Run regression checks
    lk doctor                           Check Python, Foundry, Cast, and Anvil

FORENSICS
  lk receipt [tx]                     Transaction receipt
  lk last [tx|trace|logs]             Reuse latest transaction
  lk c ...                            Cast call shortcut
  lk s ...                            Cast send shortcut
  lk st ...                           Cast storage shortcut
""")
def dispatch_command(cmd,args,config,from_batch=False):
    if cmd in {"--help","-h","help"}: print_help()
    elif cmd in {"--version","-V","version"}: run_version()
    elif cmd=="target":
        if not args: print(f"Current target: {config.get('target') or 'none'}"); return
        if args[0]=="reset": config["target"]=None
        elif args[0]=="list": run_targets(config); return
        elif args[0]=="auto": run_auto_target(config,args[1] if len(args)>1 else None); return
        elif len(args)==1:
            resolved=resolve_target_ref(config,args[0])
            if not resolved: return fail("Error: target must be a valid address or saved alias.")
            config["target"]=resolved
        elif len(args)==2 and is_address(args[1]): config["aliases"][args[0]]=args[1]; config["targets"][args[0]]=args[1]; config["target"]=args[1]
        else: return fail("Usage: lk target <address> | lk target <name> <address> | lk target auto")
        save_config(config)
    elif cmd in {"targets","target-list"}: run_targets(config)
    elif cmd=="use":
        if not args: run_targets(config); return
        resolved=resolve_target_ref(config,args[0])
        if not resolved: print(f"Unknown target: {args[0]}"); return
        config["target"]=resolved; save_config(config)
    elif cmd=="deployments": run_deployments(config)
    elif cmd=="rpc":
        if not args: print(f"RPC: {rpc_display(config.get('rpc')) or 'none'}"); return
        sub=args[0]
        if sub=="reset": config["rpc"]=None
        elif sub=="set" and len(args)==3: config["rpc_profiles"][args[1]]=args[2]; config["rpc"]=args[2]
        elif sub=="use" and len(args)==2 and args[1] in config["rpc_profiles"]: config["rpc"]=config["rpc_profiles"][args[1]]
        elif sub=="use": return fail(f"Error: unknown RPC profile: {args[1] if len(args)>1 else ''}")
        elif len(args)==1: config["rpc"]=args[0]
        else: return fail("Usage: lk rpc <url> | lk rpc set <name> <url> | lk rpc use <name> | lk rpc reset")
        save_config(config)
    elif cmd=="wallet":
        if args and args[0]=="list":
            for name,entry in config.get("wallets",{}).items(): print(f"{name}: {'env' if isinstance(entry,dict) and entry.get('env') else 'key'}")
        elif len(args)==3 and args[0]=="set":
            key=normalize_private_key(args[2])
            if not key: print("Invalid private key format."); return
            config["wallets"][args[1]]={"private_key":key}; config["actor"]=args[1]; save_config(config)
            print("Wallet saved. This stores the key locally; use wallet set-env for secret-free storage.")
        elif len(args)==3 and args[0]=="set-env":
            config["wallets"][args[1]]={"env":args[2]}; config["actor"]=args[1]; save_config(config)
            print(f"Wallet profile '{args[1]}' now reads from environment variable {args[2]}.")
        elif len(args)==2 and args[0]=="use" and args[1] in config.get("wallets",{}): config["actor"]=args[1]; save_config(config)
        elif len(args)==2 and args[0]=="use": return fail(f"Error: unknown wallet profile: {args[1]}")
        elif len(args)==2 and args[0]=="remove":
            config["wallets"].pop(args[1],None)
            if config.get("actor")==args[1]: config["actor"]=None
            save_config(config)
        else: return fail("Usage: lk wallet list | set <name> <private-key> | set-env <name> <ENV_VAR> | use <name> | remove <name>")
    elif cmd=="actor":
        if args and args[0]=="reset": config["actor"]=None; save_config(config)
        elif args: config["actor"]=args[0]; save_config(config)
        else: print(f"Actor: {actor_display(config)}")
    elif cmd=="abi":
        target=config.get("target")
        if not target: print("Error: Set target first."); return
        if args:
            if args[0]=="auto":
                records=discover_deployments("."); match=next((x for x in records if x["address"]==target),None)
                if match:
                    for path in artifact_json_files("."):
                        if os.path.join(".","out") in path and os.path.basename(path)==f"{match['contract']}.json":
                            config["abi_paths"][target]=path; break
            else: config["abi_paths"][target]=args[0]
            save_config(config)
        else: run_abi(config)
    elif cmd=="functions": run_functions(config,args[0] if args else None)
    elif cmd=="fn": run_functions(config," ".join(args) if args else None)
    elif cmd=="wizard": run_wizard(config,args)
    elif cmd=="replay": run_replay(config,args)
    elif cmd=="fork": run_fork(args)
    elif cmd=="ask":
        if not args: print("Usage: lk ask <function>"); return
        funcs=abi_functions(load_abi(config.get("target"),config)); matches=matching_functions(funcs,args[0])
        if len(matches)!=1:
            for item in sorted(funcs,key=lambda x:function_score(x,args[0]),reverse=True)[:8]: print(" ",format_signature(item))
        else:
            item=matches[0]; print(f"Function: {format_signature(item)}")
            for index,param in enumerate(item.get("inputs",[]),1): print(f"  arg{index}: {param.get('name') or 'arg'+str(index)} : {canonical_type(param)}")
    elif cmd=="info": run_info(config)
    elif cmd=="status": run_status(config)
    elif cmd=="chain": run_chain(config)
    elif cmd=="encode": run_encode(config,args)
    elif cmd=="sig": run_signature(args)
    elif cmd in {"decode-error","error"}: run_decode_error(config,args)
    elif cmd in {"decode","returns"}: run_decode(config,args)
    elif cmd in {"event","decode-event"}: run_event(config,args)
    elif cmd=="tx": run_tx(config,args)
    elif cmd=="label":
        if len(args)==2: config["labels"][args[0]]=args[1]; save_config(config)
        else: print("Usage: lk label <address> <name>")
    elif cmd=="recon": run_recon(config)
    elif cmd=="proxy": run_proxy(config)
    elif cmd=="implementation": run_cast(["implementation",config.get("target")],config)
    elif cmd=="admin": run_cast(["admin",config.get("target")],config)
    elif cmd in {"mapping","map"}: run_mapping(config,*args)
    elif cmd=="namespace": run_namespace(config,args)
    elif cmd=="proof": run_proof(config,args)
    elif cmd=="selectors": run_selectors(config,args)
    elif cmd in {"ens","resolve","lookup"}: run_ens(config,args)
    elif cmd in {"token","erc20"}: run_token(config,args)
    elif cmd=="snapshot": run_snapshot(config,args)
    elif cmd=="diff": run_diff(config)
    elif cmd in {"findings","finding-list"}:
        run_findings(config,args)
    elif cmd=="focus":
        run_focus(config,args)
    elif cmd=="finding":
        if args and args[0]=="add" and len(args)>=4: run_finding(config,f"[{args[1].upper()}] {args[2]}: {' '.join(args[3:])}")
        elif args: run_finding(config," ".join(args))
        else: print("Usage: lk finding <note>")
    elif cmd=="checklist":
        if args and args[0]=="done": run_checklist(config,"done"," ".join(args[1:]))
        elif args and args[0]=="reset": run_checklist(config,"reset")
        else: run_checklist(config)
    elif cmd=="session":
        if args and args[0] in {"start","resume"}: run_session_lifecycle(config,args[0])
        elif args and args[0]=="end":
            config["session_active"]=False; config["session_ended"]=datetime.now().isoformat(timespec="seconds"); save_config(config); print("Audit session ended.")
        elif os.path.exists(SESSION_FILE): print(Path(SESSION_FILE).read_text(encoding="utf-8"))
        else: print("No session history yet.")
    elif cmd=="workspace": run_workspace(config,args)
    elif cmd=="note": run_note(" ".join(args))
    elif cmd=="todo": run_todo(" ".join(args))
    elif cmd=="export": run_export(config)
    elif cmd=="matrix":
        if args and args[0]=="state" and len(args)>=3:
            paths=workspace_paths(); os.makedirs(paths["matrix"],exist_ok=True)
            states=read_json_file(paths["matrix_states"],{}); states[args[1]]={"description":" ".join(args[2:])}; write_json_file(paths["matrix_states"],states); print(f"Matrix state saved: {args[1]}")
        else: run_matrix(config,args)
    elif cmd=="risk": run_risk(config)
    elif cmd=="scan": run_scan(args)
    elif cmd=="rg":
        if not args:
            print("Usage: lk rg <pattern> [path] [rg flags...]")
        elif run_rg is None:
            fail("Audit engine is not installed. Reinstall Lowkey.")
        else:
            path=args[1] if len(args)>1 and not args[1].startswith("-") else "."
            extra=args[2:] if len(args)>1 and not args[1].startswith("-") else args[1:]
            run_rg(args[0],path,extra)
    elif cmd=="slither":
        if run_slither is None:
            fail("Audit engine is not installed. Reinstall Lowkey.")
        else:
            run_slither(".",args)
    elif cmd in {"poc","poc-gen"}:
        if generate_poc is None:
            fail("Audit engine is not installed. Reinstall Lowkey.")
        else:
            index=None; name=None; rest=list(args)
            if "--finding" in rest:
                i=rest.index("--finding")
                if i+1>=len(rest):
                    fail("Usage: lk poc [--finding N] [--name NAME]")
                    return
                try: index=int(rest[i+1])
                except ValueError:
                    fail("--finding must be an integer")
                    return
                del rest[i:i+2]
            if "--name" in rest:
                i=rest.index("--name")
                if i+1>=len(rest):
                    fail("Usage: lk poc [--finding N] [--name NAME]")
                    return
                name=rest[i+1]
            generate_poc(".",index,name)
    elif cmd=="deps": run_deps(args)
    elif cmd in {"project","project-map","system"}: run_project(args)
    elif cmd in {"walkthrough","protocol-walkthrough","protocol_map"}: run_walkthrough(args)
    elif cmd=="layout": run_layout(args)
    elif cmd=="gas": run_gas(config,args)
    elif cmd=="raw": run_raw(config,args)
    elif cmd=="batch": run_batch(config,args)
    elif cmd in {"audit--checks","audit-checks"}:
        if run_audit_pipeline is None:
            fail("Audit engine is not installed. Reinstall Lowkey.")
        else:
            run_audit_pipeline(".", [], False)
    elif cmd=="audit":
        action=args[0] if args else None
        if action in {"--checks","checks"}:
            if run_audit_pipeline is None:
                fail("Audit engine is not installed. Reinstall Lowkey.")
            else:
                run_audit_pipeline(".", [], False)
        elif action in {"run","full"}:
            if run_audit_pipeline is None:
                fail("Audit engine is not installed. Reinstall Lowkey.")
            else:
                extra=args[1:]
                generate="--poc" in extra
                slither_args=[x for x in extra if x!="--poc"]
                run_audit_pipeline(".",slither_args,generate)
        elif action in {"poc","poc-gen"}:
            if generate_poc is None:
                fail("Audit engine is not installed. Reinstall Lowkey.")
            else:
                generate_poc(".",None,None)
        else:
            run_audit_mode(config)
    elif cmd=="self-test": raise SystemExit(run_self_test())
    elif cmd=="doctor": return run_doctor()
    elif cmd=="receipt": run_receipt(config,args[0] if args else None)
    elif cmd=="trace": run_trace(config,args)
    elif cmd=="logs": run_logs(config,args)
    elif cmd=="last":
        action=args[0] if args else "receipt"
        if action=="tx": run_tx(config,[])
        elif action=="trace": run_trace(config,[])
        elif action=="logs": run_logs(config,[])
        else: run_receipt(config)
    elif cmd=="test-gen": run_test_gen(config)
    elif cmd in {"c","s","st"}: run_cast([cmd]+args,config)
    else: run_cast([cmd]+args,config)

def main():
    global _COMMAND_STATUS
    _COMMAND_STATUS = 0
    config=load_config()
    if len(sys.argv)<2: print_help(); return
    result=dispatch_command(sys.argv[1],sys.argv[2:],config)

    # Keep the PoC scaffold synchronized with evidence gathered by any
    # command during an active audit session. The generator only writes
    # local files; it does not make network calls or assert a vulnerability.
    evidence_commands={
        "scan","rg","slither","recon","proxy","implementation","admin","mapping",
        "namespace","proof","snapshot","diff","risk","trace","replay","logs","tx",
        "receipt","finding","matrix","note","todo","test-gen","workspace","deployments",
        "target","use","rpc","abi","functions","fn","c","s","st","raw","gas","selectors",
        "layout","export","fork","token","ens","decode","decode-error","returns","event",
        "checklist","session","forge"
    }
    if (
        config.get("session_active")
        and sys.argv[1] in evidence_commands
        and sys.argv[1] not in {"audit","poc"}
        and generate_poc
    ):
        try:
            generate_poc(".", None, None)
        except Exception as error:
            print(f"Lowkey PoC refresh warning: {error}", file=sys.stderr)

    if isinstance(result,int): raise SystemExit(result)
    if _COMMAND_STATUS: raise SystemExit(_COMMAND_STATUS)

if __name__ == "__main__":
    main()
