import os
import json
import subprocess
import sys
import re
import shlex
import io
import shutil
import socket
from urllib import request as urllib_request
from contextlib import redirect_stdout
from datetime import datetime
from urllib.parse import urlsplit
from difflib import SequenceMatcher
from pathlib import Path

try:
    from forge_tools import NATIVE_COMMANDS as FORGE_NATIVE_COMMANDS
except ImportError:
    FORGE_NATIVE_COMMANDS = set()

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
    "target": None, "target_contract": None, "aliases": {}, "targets": {}, "rpc": None,
    "rpc_profiles": {}, "actor": None, "wallets": {},
    "abi_paths": {}, "labels": {}, "confirm_sends": False, "rpc_auto": False, "version": 3
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
            persisted={k:v for k,v in config.items() if not str(k).startswith("_")}
        json.dump(persisted,f,indent=4); f.write("\n")
        os.chmod(tmp,0o600); os.replace(tmp,CONFIG_FILE); os.chmod(CONFIG_FILE,0o600)
    finally:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except OSError: pass

def normalize_private_key(value):
    if not value: return None
    value=str(value).strip()
    if re.fullmatch(r"(0x)?[0-9a-fA-F]{64}",value):
        return value if value.startswith("0x") else "0x"+value
    return None

DEFAULT_ANVIL_MNEMONIC = "test test test test test test test test test test test junk"

def rpc_json(url, method, params=None):
    if not url: return None
    try:
        payload=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params or []}).encode()
        req=urllib_request.Request(url, data=payload, headers={"Content-Type":"application/json"})
        with urllib_request.urlopen(req, timeout=0.8) as response:
            body=json.loads(response.read().decode("utf-8"))
        if isinstance(body,dict) and body.get("error"): return None
        return body.get("result") if isinstance(body,dict) else None
    except Exception:
        return None

def local_port_open(host,port):
    try:
        with socket.create_connection((host,port),timeout=0.05): return True
    except OSError:
        return False

def detect_anvil_rpc(preferred=None):
    candidates=[]
    if preferred:
        candidates.append(preferred)
    else:
        env_rpc=os.environ.get("ETH_RPC_URL")
        if env_rpc: candidates.append(env_rpc)
        for host,port in (("127.0.0.1",8545),("127.0.0.1",8546)):
            if local_port_open(host,port): candidates.append(f"http://{host}:{port}")
    for url in candidates:
        client=rpc_json(url,"web3_clientVersion",[])
        if not client or "anvil" not in str(client).lower(): continue
        accounts=rpc_json(url,"eth_accounts",[])
        if not isinstance(accounts,list): accounts=[]
        return {"url":url,"client":str(client),"accounts":[x for x in accounts if is_address(x)]}
    return None


def anvil_rpc_info(config):
    explicit=config.get("rpc")
    if explicit:
        return detect_anvil_rpc(explicit)
    cached=config.get("_auto_rpc_info")
    if isinstance(cached,dict):
        return cached
    info=detect_anvil_rpc()
    if info:
        config["_auto_rpc_info"]=info
    return info

def effective_rpc(config):
    if config.get("rpc"):
        return config["rpc"]
    info=anvil_rpc_info(config)
    return info.get("url") if isinstance(info,dict) else None

def derive_default_anvil_key(index):
    try:
        code,out,err=cast_output(["cast","wallet","private-key",DEFAULT_ANVIL_MNEMONIC,str(index)])
    except Exception:
        return None
    if code != 0: return None
    match=re.search(r"0x[0-9a-fA-F]{64}",out or "")
    return normalize_private_key(match.group(0)) if match else None

def wallet_entry_kind(entry):
    if isinstance(entry,dict):
        if entry.get("source") == "anvil-default": return f"anvil #{entry.get('anvil_index','?')}"
        if entry.get("env"): return "env"
        if entry.get("private_key"): return "key"
    return "key"

def assigned_anvil_index(config,index):
    for name,entry in config.get("wallets",{}).items():
        if isinstance(entry,dict) and entry.get("source")=="anvil-default" and str(entry.get("anvil_index"))==str(index):
            return name
    return None

def assigned_anvil_address(config,address):
    for name,entry in config.get("wallets",{}).items():
        if isinstance(entry,dict) and str(entry.get("address","")).lower()==str(address).lower():
            return name
    return None


def select_anvil_actor(config,index,name):
    try:
        index=int(index)
    except (TypeError,ValueError):
        return fail("Error: Anvil account index must be a number.")
    name=str(name or "").strip()
    if index<0:
        return fail("Error: Anvil account index cannot be negative.")
    if not name:
        return fail("Error: actor name cannot be empty.")
    info=anvil_rpc_info(config)
    if not info:
        return fail("Error: no Anvil node detected. Start 'anvil' or set an Anvil RPC with lk rpc <url>.")
    accounts=info.get("accounts",[])
    if not isinstance(accounts,list) or index>=len(accounts):
        return fail(f"Error: Anvil account {index} does not exist on {info.get('url','the detected RPC')}.")
    address=accounts[index]
    assigned_index=assigned_anvil_index(config,index)
    assigned_address=assigned_anvil_address(config,address)
    if assigned_index and assigned_index!=name:
        return fail(f"Error: Anvil account {index} is already assigned to '{assigned_index}'.")
    if assigned_address and assigned_address!=name:
        return fail(f"Error: address {address} is already assigned to '{assigned_address}'.")
    existing=config.get("wallets",{}).get(name)
    if existing and not (
        isinstance(existing,dict)
        and existing.get("source")=="anvil-default"
        and str(existing.get("anvil_index"))==str(index)
    ):
        return fail(f"Error: wallet profile '{name}' already exists. Pick another actor name.")
    config.setdefault("wallets",{})[name]={
        "source":"anvil-default",
        "anvil_index":index,
        "address":address,
    }
    config.setdefault("labels",{})[address]=name
    config["actor"]=name
    save_config(config)
    print(f"Actor selected: {name} -> Anvil account {index} ({address})")
    print("Private key: derived only when a send is needed; not stored in Lowkey config.")
    return 0

def list_anvil_actors(config):
    info=anvil_rpc_info(config)
    print(f"Actor: {actor_display(config)}")
    if not info:
        print("Anvil: not detected")
        return
    accounts=info.get("accounts",[])
    print(f"Anvil RPC: {info.get('url')}")
    if not accounts:
        print("No Anvil accounts reported by this RPC.")
        return
    print("Accounts:")
    for index,address in enumerate(accounts):
        owner=assigned_anvil_address(config,address)
        marker="*" if owner==config.get("actor") else " "
        label=f" -> {owner}" if owner else ""
        print(f"{marker} {index:>2}: {address}{label}")

def resolve_wallet_key(config,wallet_name=None):
    name=wallet_name or config.get("actor")
    if not name: return None
    entry=config.get("wallets",{}).get(name)
    if isinstance(entry,dict):
        if entry.get("source") == "anvil-default" and entry.get("anvil_index") is not None:
            info=anvil_rpc_info(config)
            if not info:
                return None
            index=int(entry["anvil_index"])
            accounts=info.get("accounts",[])
            if index<0 or index>=len(accounts):
                return None
            recorded=str(entry.get("address","")).lower()
            actual=str(accounts[index]).lower()
            if recorded and recorded!=actual:
                return None
            key=derive_default_anvil_key(index)
            if not key:
                return None
            code,derived_address,_=cast_output(["cast","wallet","address","--private-key",key])
            if code!=0 or not derived_address:
                return None
            derived_address=derived_address.strip().splitlines()[-1].strip()
            if derived_address.lower()!=actual:
                return None
            return key
        if entry.get("env"): return normalize_private_key(os.environ.get(entry["env"]))
        return normalize_private_key(entry.get("private_key"))
    if isinstance(entry,str): return normalize_private_key(entry)
    if isinstance(name,str) and name.startswith("env:"): return normalize_private_key(os.environ.get(name[4:]))
    return normalize_private_key(name)

def actor_display(config):
    actor=config.get("actor")
    if not actor:
        return "none"
    entry=config.get("wallets",{}).get(actor)
    if isinstance(entry,dict) and entry.get("source")=="anvil-default":
        index=entry.get("anvil_index","?")
        address=entry.get("address","?")
        return f"{actor} (Anvil #{index}, {address})"
    if isinstance(entry,dict) and entry.get("env"):
        return f"{actor} (env:{entry['env']})"
    if isinstance(entry,dict) and entry.get("private_key"):
        return f"{actor} (local key)"
    return str(actor)
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

def local_artifact_paths():
    return [p for p in artifact_json_files(".") if "out" in Path(p).parts]

def artifact_contract_name(path, artifact):
    if isinstance(artifact,dict) and artifact.get("contractName"): return str(artifact["contractName"])
    return Path(path).stem

def read_artifact(path):
    try:
        with open(path,"r",encoding="utf-8") as f: value=json.load(f)
        return value if isinstance(value,dict) else None
    except (OSError,json.JSONDecodeError): return None

def auto_abi_path(target,config):
    if not target or not is_address(target): return None
    preferred=config.get("target_contract")
    if not preferred:
        for record in discover_deployments("."):
            if str(record.get("address","")).lower()==target.lower():
                preferred=record.get("contract")
                if preferred: config["target_contract"]=preferred
                break
    paths=local_artifact_paths()
    if preferred:
        preferred_lower=str(preferred).lower()
        for path in paths:
            artifact=read_artifact(path)
            if artifact_contract_name(path,artifact).lower()==preferred_lower or Path(path).stem.lower()==preferred_lower:
                config.setdefault("abi_paths",{})[target]=path
                return path
    rpc=effective_rpc(config)
    if rpc:
        code,runtime,_=cast_output(["cast","code",target,"--rpc-url",rpc])
        if code==0 and runtime and runtime.startswith("0x") and runtime!="0x":
            for path in paths:
                artifact=read_artifact(path)
                deployed=artifact.get("deployedBytecode") if isinstance(artifact,dict) else None
                if isinstance(deployed,dict): deployed=deployed.get("object")
                if isinstance(deployed,str) and deployed.lower()==runtime.lower():
                    config.setdefault("abi_paths",{})[target]=path
                    config["target_contract"]=artifact_contract_name(path,artifact)
                    return path
    return None

def load_abi(target,config):
    if not target: return []
    abi_paths=config.get("abi_paths",{})
    abi_path=abi_paths.get(target)
    if not abi_path and isinstance(target,str):
        lowered=target.lower()
        abi_path=next((path for address,path in abi_paths.items() if isinstance(address,str) and address.lower()==lowered),None)
    if not abi_path or not os.path.exists(abi_path):
        abi_path=auto_abi_path(target,config)
    if not abi_path or not os.path.exists(abi_path): return []
    try:
        with open(abi_path,"r",encoding="utf-8") as f: artifact=json.load(f)
        abi=artifact.get("abi",[]) if isinstance(artifact,dict) else artifact
        if isinstance(artifact,dict) and artifact.get("contractName") and not config.get("target_contract"):
            config["target_contract"]=artifact.get("contractName")
        return abi if isinstance(abi,list) else []
    except (OSError,json.JSONDecodeError): return []

def storage_getter_names(target,config,abi):
    path=config.get("abi_paths",{}).get(target)
    if not path or not os.path.exists(path): path=auto_abi_path(target,config)
    if not path or not os.path.exists(path): return set()
    artifact=read_artifact(path) or {}
    layout=artifact.get("storageLayout",{}) if isinstance(artifact,dict) else {}
    storage=layout.get("storage",[]) if isinstance(layout,dict) else []
    labels={entry.get("label") for entry in storage if isinstance(entry,dict) and entry.get("label")}
    return {item.get("name") for item in abi if item.get("type")=="function" and item.get("stateMutability") in {"view","pure"} and item.get("name") in labels}
def run_chain(config):
    rpc=effective_rpc(config)
    chain_id = run_cast(["chain-id"], config, capture=True)
    block = run_cast(["block-number"], config, capture=True)
    print(f"Chain ID: {chain_id or 'Unknown'}")
    print(f"Block:    {block or 'Unknown'}")
    if rpc:
        mode="manual" if config.get("rpc") else "auto Anvil"
        print(f"RPC:      {rpc} ({mode})")
    else:
        print("RPC:      Not configured / no local Anvil detected")
def run_abi(config):
    target = config.get("target")
    if not target:
        print("Error: Set target first.")
        return
    abi = load_abi(target, config)
    if not abi:
        print("Error: No ABI loaded for the current target.")
        return
    getter_names=storage_getter_names(target,config,abi)
    groups = [
        ("WRITE", [item for item in abi if item.get("type")=="function" and item.get("stateMutability") not in {"view","pure"}]),
        ("READ", [item for item in abi if item.get("type")=="function" and item.get("stateMutability") in {"view","pure"} and item.get("name") not in getter_names]),
        ("STORAGE GETTERS", [item for item in abi if item.get("type")=="function" and item.get("name") in getter_names]),
        ("EVENTS", [item for item in abi if item.get("type")=="event"]),
        ("ERRORS", [item for item in abi if item.get("type")=="error"]),
    ]
    path=config.get("abi_paths",{}).get(target) or auto_abi_path(target,config)
    print(f"ABI: {path or 'not loaded'}")
    for group, items in groups:
        if items:
            print(f"\n{group}")
            for item in items:
                print(f"  {format_signature(item)}")
def run_functions(config,query=None):
    target=config.get("target")
    if not target: return fail("Error: Set target first.")
    functions=abi_functions(load_abi(target,config))
    if not functions: return fail("Error: No ABI functions loaded for the current target.")
    getter_names=storage_getter_names(target,config,functions)
    if query:
        functions=sorted(functions,key=lambda item:function_score(item,query),reverse=True)[:8]
    groups=[
        ("WRITE FUNCTIONS",[item for item in functions if item.get("stateMutability") not in {"view","pure"}]),
        ("READ FUNCTIONS",[item for item in functions if item.get("stateMutability") in {"view","pure"} and item.get("name") not in getter_names]),
        ("STORAGE GETTERS",[item for item in functions if item.get("name") in getter_names]),
    ]
    if query:
        print(f"Function matches for '{query}':")
    for title,items in groups:
        if not items:
            continue
        print(f"\n{title}:")
        for index,item in enumerate(items,1):
            suffix="  [public storage getter]" if title=="STORAGE GETTERS" else ""
            print(f"  {index:>2}. {format_signature(item)}{suffix}")
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
    rpc=effective_rpc(config)
    if rpc: command.extend(["--rpc-url",rpc])
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
    return run_cast(["receipt", tx_hash, "--async"], config)

def run_trace(config,args=None):
    args=list(args or [])
    tx_hash=args.pop(0) if args and args[0].startswith("0x") else last_transaction(config)
    if not tx_hash: return fail("Error: No transaction hash supplied or saved.")
    grep=None
    if "--grep" in args:
        i=args.index("--grep")
        if i+1>=len(args): return fail("Usage: lk trace [tx] [--quick] [--decode-internal] [--trace-printer] [--grep text]")
        grep=args[i+1]; del args[i:i+2]
    output=run_cast(["run",tx_hash]+args,config,capture=True) if grep else None
    if grep:
        matched=[line for line in (output or "").splitlines() if grep.lower() in line.lower()]
        print("\n".join(matched) if matched else f"No trace lines matched '{grep}'.")
    else: run_cast(["run",tx_hash]+args,config)
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
    rpc=effective_rpc(config)
    if rpc: command.extend(["--rpc-url",rpc])
    code,output,error=cast_output(command)
    if code!=0:
        print(error or "cast logs failed",file=sys.stderr)
        return record_status(code)
    try: payload=json.loads(output)
    except json.JSONDecodeError: print(output); return
    logs=payload if isinstance(payload,list) else payload.get("logs",payload.get("result",[]))
    if not isinstance(logs,list): print(output); return
    if not logs: print("No logs found."); return
    for log in logs:
        print(json.dumps(log,indent=2))
        event=decode_event_log(config,log)
        if event: print(f"Event: {event[0]}\nDecoded: {event[1]}")
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
    rpc_commands={"balance","call","send","storage","chain-id","block-number","code","codesize","codehash","nonce","logs","receipt","run","tx","estimate","implementation","admin","proof","lookup-address","resolve-name","erc20-token","block","gas-price","index","selectors"}
    active_rpc=effective_rpc(config)
    if cast_cmd in rpc_commands and active_rpc and "--rpc-url" not in cmd: cmd.extend(["--rpc-url",active_rpc])
    actor=config.get("actor")
    actor_key=resolve_wallet_key(config) if cast_cmd=="send" else None
    if cast_cmd=="send" and actor and actor in config.get("wallets",{}) and not actor_key:
        entry=config.get("wallets",{}).get(actor)
        if isinstance(entry,dict) and entry.get("source")=="anvil-default":
            return fail("Error: current Anvil actor cannot be used safely on this RPC. Make sure the selected actor belongs to the detected Anvil node.")
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
    print(f"Snapshot saved: {path}")
def run_diff(config):
    path=snapshot_path(config)
    if not os.path.exists(path): print("No snapshot for the current target/chain."); return
    try: old=json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError): print("Error: invalid snapshot."); return
    old_slots=old.get("slots",old); print(f"Snapshot block: {old.get('block','unknown')}")
    changed=0
    for slot,old_val in old_slots.items():
        new_val=run_cast(["st",slot],config,capture=True)
        if str(new_val).lower()!=str(old_val).lower():
            changed+=1; print(f"Slot {slot}: {old_val} -> {new_val}")
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
    print("Finding recorded.")

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
    for directory in [paths["root"],os.path.join(paths["root"],"abi"),os.path.join(paths["root"],"transactions"),os.path.join(paths["root"],"traces"),os.path.join(paths["root"],"storage"),os.path.join(paths["root"],"findings"),os.path.join(paths["root"],"history"),paths["matrix"]]:
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
    print("Note saved.")

def run_todo(todo):
    if not todo:
        print("Usage: lk todo \"task to investigate\"")
        return
    paths = workspace_paths()
    os.makedirs(paths["root"], exist_ok=True)
    with open(paths["todos"], "a") as f:
        f.write(f"- [ ] {todo}\n")
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
        print("Audit session started.")
    elif action == "resume":
        config["session_active"] = True
        save_config(config)
        print(f"Audit session resumed: {paths['root']}")
    else:
        print("Usage: lk session start|resume")

def run_export(config):
    paths=workspace_paths(); export_dir=os.path.join(os.getcwd(),"audit-report"); os.makedirs(export_dir,exist_ok=True)
    lines=["# LowkeyCast Audit Report","",f"- Target: {config.get('target') or 'Not set'}",f"- RPC: {rpc_display(effective_rpc(config)) or 'Not set'}",f"- ABI: {config.get('abi_paths',{}).get(config.get('target')) or 'Auto-discovered when needed'}",f"- Last transaction: {config.get('last_tx') or 'None'}",f"- Generated: {datetime.now().isoformat(timespec='seconds')}","","## Findings",""]
    finding_path=paths["findings"] if os.path.exists(paths["findings"]) else os.path.join(AUDIT_DIR,"findings.md")
    lines.append(Path(finding_path).read_text(encoding="utf-8") if os.path.exists(finding_path) else "No findings recorded.")
    lines += ["","## Checklist",""]
    checklist_path=os.path.join(AUDIT_DIR,"CHECKLIST.md")
    lines.append(Path(checklist_path).read_text(encoding="utf-8") if os.path.exists(checklist_path) else "No checklist initialized.")
    Path(os.path.join(export_dir,"report.md")).write_text("\n".join(lines),encoding="utf-8")
    for name,source in [("notes.md",paths["notes"]),("TODO.md",paths["todos"]),("session.log",paths["session"]),("matrix_actors.json",paths["matrix_actors"]),("matrix_states.json",paths["matrix_states"]),("matrix_scenarios.json",paths["matrix_scenarios"])]:
        if os.path.exists(source): Path(os.path.join(export_dir,name)).write_text(Path(source).read_text(encoding="utf-8"),encoding="utf-8")
    Path(os.path.join(export_dir,"contract.json")).write_text(json.dumps({"target":config.get("target"),"rpc":rpc_display(effective_rpc(config)),"abi":config.get("abi_paths",{}).get(config.get("target")),"last_tx":config.get("last_tx")},indent=4),encoding="utf-8")
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
    failures=0
    print("Lowkey doctor")
    print("============")
    for name in ("python3", "cast", "forge", "anvil"):
        path=shutil.which(name)
        if not path:
            print(f"FAIL  {name}: not found")
            failures+=1
            continue
        try:
            result=subprocess.run([path,"--version"],capture_output=True,text=True)
            version=(result.stdout or result.stderr).splitlines()[0] if result.returncode==0 else "version check failed"
        except OSError as error:
            print(f"FAIL  {name}: {error}")
            failures+=1
            continue
        if result.returncode==0:
            print(f"PASS  {name}: {path} ({version})")
        else:
            print(f"FAIL  {name}: {path} ({version})")
            failures+=1
    forge=shutil.which("forge")
    if forge:
        try:
            result=subprocess.run([forge,"--help"],capture_output=True,text=True)
            available={line.strip().split()[0] for line in result.stdout.splitlines() if line.startswith("  ") and line.strip() and not line.strip().startswith("-")}
            advertised=set(FORGE_NATIVE_COMMANDS)
            missing=sorted(advertised-available)
            if missing:
                print(f"FAIL  forge commands missing: {', '.join(missing)}")
                failures+=1
            else:
                print(f"PASS  forge commands: {', '.join(sorted(advertised))}")
        except OSError as error:
            print(f"FAIL  forge command check: {error}")
            failures+=1
    for command,args in (("cast decode-event",["cast","decode-event","--help"]),
                         ("cast receipt",["cast","receipt","--help"]),
                         ("cast sig-event",["cast","sig-event","--help"]),
                         ("forge inspect",["forge","inspect","--help"])):
        if not shutil.which(args[0]):
            print(f"FAIL  dependency command: {command} (binary not found)")
            failures+=1
            continue
        try:
            result=subprocess.run(args,capture_output=True,text=True)
        except OSError:
            result=None
        if result is not None and result.returncode==0:
            print(f"PASS  dependency command: {command}")
        else:
            print(f"FAIL  dependency command: {command}")
            failures+=1
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

def source_sol_files(root):
    if os.path.isfile(root):
        return [root] if root.endswith(".sol") else []
    if not os.path.isdir(root):
        return []
    paths=[]
    for path,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in {".git","out","cache","lib"}]
        for filename in files:
            if filename.endswith(".sol"): paths.append(os.path.join(path,filename))
    return sorted(paths)

def run_scan(args):
    root=args[0] if args else "src"
    if not os.path.exists(root): return fail(f"Path not found: {root}")
    if not os.path.isdir(root) and not root.endswith(".sol"):
        return fail(f"Path is not a Solidity file or directory: {root}")
    patterns=[
        ("REENTRANCY REVIEW",re.compile(r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()")),
        ("ETH TRANSFER REVIEW",re.compile(r"\.(transfer|send)\s*\(")),
        ("TX.ORIGIN",re.compile(r"\btx\.origin\b")),("DELEGATECALL",re.compile(r"\bdelegatecall\b")),
        ("SELFDESTRUCT",re.compile(r"\bselfdestruct\s*\(")),("UNCHECKED",re.compile(r"\bunchecked\s*\{")),
        ("ASSEMBLY",re.compile(r"\bassembly\s*\{")),("ENCODE_PACKED",re.compile(r"\babi\.encodePacked\s*\(")),
        ("TIMESTAMP",re.compile(r"\bblock\.timestamp\b")),("BLOCKHASH",re.compile(r"\bblock\.hash\s*\(|\bblockhash\s*\(")),
        ("PREVRANDAO",re.compile(r"\bblock\.prevrandao\b")),("ECRECOVER",re.compile(r"\becrecover\s*\(")),
        ("CREATE2",re.compile(r"\bcreate2\b"))]
    hits=0
    for path in source_sol_files(root):
        try: lines=Path(path).read_text(encoding="utf-8").splitlines()
        except OSError: continue
        for lineno,line in enumerate(lines,1):
            for label,pattern in patterns:
                if pattern.search(line):
                    hits+=1; print(f"{path}:{lineno}: [{label}] {line.strip()}")
    print(f"\nReview markers: {hits}"); print("These are source-level review markers, not vulnerability verdicts.")

def run_deps(args):
    root=args[0] if args else "."
    if not os.path.exists(root):
        return fail(f"Path not found: {root}")
    if os.path.isfile(root) and not root.endswith(".sol"):
        return fail(f"Path is not a Solidity file: {root}")
    files=source_sol_files(root)
    if not files:
        print(f"No Solidity files found under {root}.")
        return
    display_root=os.path.dirname(root) if os.path.isfile(root) else root
    matches=0
    print("Dependency / inheritance map:")
    for path in files:
        try:
            text_content=Path(path).read_text(encoding="utf-8")
        except OSError:
            continue
        rel=os.path.relpath(path,display_root)
        for imported in re.findall(r'import\s+(?:[^;]*from\s+)?["\']([^"\']+)["\']\s*;',text_content):
            matches+=1
            print(f"  {rel} -> imports {imported}")
        for contract in re.finditer(r"\b(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?",text_content):
            for parent in [p.strip().split()[0] for p in (contract.group(3) or "").split(",") if p.strip()]:
                matches+=1
                print(f"  {contract.group(2)} -> inherits {parent} [{rel}]")
    if matches==0:
        print("No imports or inheritance relationships detected.")
def run_risk(config):
    target=config.get("target")
    if not target:
        print("Error: Set target first."); return
    funcs=abi_functions(load_abi(target,config))
    if not funcs:
        print("Error: No ABI functions loaded."); return
    print("Function review-surface heuristic:")
    for item in funcs:
        name=item.get("name","").lower(); signals=[]
        if item.get("stateMutability") in {"nonpayable","payable"}: signals.append("state-write")
        if item.get("stateMutability")=="payable": signals.append("value-flow")
        if any(x in name for x in ["owner","admin","role","upgrade","pause","unpause"]): signals.append("privileged-looking")
        if any(x in name for x in ["withdraw","transfer","send","execute","call","mint","burn","sweep"]): signals.append("asset/action")
        if any(canonical_type(i).startswith("address") for i in item.get("inputs",[])): signals.append("address-input")
        print(f"{format_signature(item):55}  {', '.join(signals) if signals else 'no heuristic signals'}")
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
    while True:
        print(f"\nTarget: {config.get('target') or 'none'} | RPC: {rpc_display(config.get('rpc')) or 'none'}")
        print("1) recon   2) functions   3) risk   4) checklist   5) targets   6) deployments   0) exit")
        try: choice=input("lk> ").strip()
        except EOFError: return
        if choice=="1": run_recon(config)
        elif choice=="2": run_functions(config)
        elif choice=="3": run_risk(config)
        elif choice=="4": run_checklist(config)
        elif choice=="5": run_targets(config)
        elif choice=="6": run_deployments(config)
        elif choice=="0": return
        else: print("Unknown option.")

def actor_display(config):
    actor=config.get("actor")
    if not actor: return "none"
    if actor in config.get("wallets",{}): return str(actor)
    if is_probable_private_key(actor): return "<raw private key configured>"
    return str(actor)

def run_status(config):
    target=config.get("target")
    if target:
        load_abi(target,config)
    rpc=effective_rpc(config)
    print(f"Target : {target or 'none'}")
    if rpc:
        mode="manual" if config.get("rpc") else "auto Anvil"
        print(f"RPC    : {rpc} ({mode})")
    else:
        print("RPC    : none (no local Anvil detected)")
    print(f"Actor  : {actor_display(config)}")
    abi=config.get("abi_paths",{}).get(target) if target else None
    contract=config.get("target_contract") or "unknown"
    print(f"ABI    : {abi or 'auto/not found'}")
    print(f"Contract: {contract}")
    print(f"Last tx: {config.get('last_tx') or 'none'}")
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
LowkeyCast — your Foundry audit sidekick

START HERE
  lk --h                              Show this help
  lk doctor                           Check Python + Foundry + Cast + Anvil
  lk actor                            Show Anvil accounts and your current actor
  lk actor 0 Alice                    Use Anvil account 0 as Alice
  lk actor 1 Bob                      Use Anvil account 1 as Bob
  lk target <address>                 Set the contract you are auditing
  lk status                            See target, RPC, actor, and ABI

CONTRACT SETUP
  <address>   contract/wallet address, e.g. 0xAbC...123
  <name>      nickname, e.g. Alice or escrow
  <Contract>  Solidity contract name, e.g. EthEscrow
  <function>  Solidity function, e.g. release
  <file>      Solidity file, e.g. src/EthEscrow.sol
  <dir>       folder, e.g. src
  <slot>      storage slot number, e.g. 3
  <key>       mapping key, e.g. 0x1111...1111
  <tx>        transaction hash, e.g. 0xaaa...aaa
  <holder>    wallet address, e.g. Alice's address
  <rpc>       RPC URL, e.g. http://127.0.0.1:8545

ABI / FUNCTIONS
  lk functions                          List functions in simple groups
  lk fn <function>                     Find a function, e.g. lk fn release
  lk ask <function>                     Show its inputs, e.g. lk ask createEscrow
  lk c <function> [args]                Read, e.g. lk c balances <address>
  lk s <function> [args]                Send, e.g. lk s release --preview
  lk encode <function> [args]           Build calldata
  lk decode <function> <data>            Decode return data
  lk decode-error <data>                 Decode custom error data
  lk event <signature> <data> [topics]   Decode an event
  lk abi                                Show the auto-discovered ABI (manual override optional)

AUDIT / SOURCE
  lk scan <file|dir>                     Review source markers
    Example: lk scan src/EthEscrow.sol
  lk deps [dir]                          Show imports + inheritance for the project
    Example: lk deps
  lk layout <Contract>                   Show Forge storage layout
    Example: lk layout EthEscrow
  lk risk                               Show function review-surface hints

STORAGE / FORENSICS
  lk mapping <slot> <key>                Compute/read a mapping slot
    Example: lk mapping 3 <address>
  lk namespace <id>                      Compute an ERC-7201 namespace slot
  lk proof <slot> [block]                Read a storage proof
  lk recon                              Quick contract reconnaissance
  lk trace [<tx>]                        Trace a transaction
  lk tx [<tx>]                            Inspect a transaction
  lk receipt [<tx>]                      Read a receipt
  lk logs --decode                       Find + decode ABI events
  lk snapshot [<slot> ...]               Save selected storage slots
  lk diff                                Compare the latest snapshot

ACTORS / RPC
  lk actor <index> <name>                 Example: lk actor 0 Alice
  lk actor <index> <name>                 Example: lk actor 1 Bob
  lk actor reset                          Clear the current actor
  lk rpc <rpc>                            Manual RPC override
  lk wallet set-env <name> <ENV_VAR>      Use a private key from an environment variable
  lk wallet list                          List saved signer profiles

FOUNDRY
  lk forge test -vvvv                     Run normal Forge commands
  lk forge inspect-audit <Contract>       Build + inspect ABI/methods/errors/events/storage
  lk forge audit                           Build + traced tests + coverage
  lk build                                Shortcut for forge build
  lk test                                 Shortcut for forge test

MANUAL OVERRIDES
  You normally do NOT need to provide an ABI path.
  Lowkey looks in your Foundry out/ artifacts and uses the ABI when needed.
  Use 'lk abi <file>' only when you deliberately want to override it.
  Use 'lk rpc <rpc>' when you want to use a specific network instead of auto-detected Anvil.

ETH ESCROW EXAMPLE
  anvil
  lk actor 0 Alice
  lk actor 1 Bob
  lk target <address>
  lk status
  lk scan src/EthEscrow.sol
  lk deps
  lk functions
  lk fn release
  lk ask createEscrow
  lk s createEscrow 1 <address> --preview
  lk c balances <address>
  lk trace

Notes:
  • Local Anvil private keys are derived only when a send needs them.
  • Anvil account numbers are unique actor assignments: account 0 cannot be Bob after Alice owns it.
  • Heuristic commands show things to review; they do not declare vulnerabilities.
""")
def dispatch_command(cmd,args,config,from_batch=False):
    if cmd in {"--h","--help","-h","help"}: print_help()
    elif cmd in {"--version","-V","version"}: print("LowkeyCast 2.0")
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
        if not args:
            rpc=effective_rpc(config)
            mode="manual" if config.get("rpc") else "auto Anvil"
            print(f"RPC: {rpc_display(rpc) or 'none'} ({mode})" if rpc else "RPC: none (no local Anvil detected)")
            return
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
            for name,entry in config.get("wallets",{}).items():
                print(f"{name}: {wallet_entry_kind(entry)}")
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
        if args and args[0]=="reset":
            config["actor"]=None
            save_config(config)
        elif len(args)>=2 and args[0].isdigit():
            return select_anvil_actor(config,args[0],args[1])
        elif len(args)==1 and args[0] in config.get("wallets",{}):
            config["actor"]=args[0]
            save_config(config)
            print(f"Actor selected: {actor_display(config)}")
        elif not args:
            list_anvil_actors(config)
        else:
            return fail("Usage: lk actor <index> <name> | lk actor [existing-name] | lk actor reset")
    elif cmd=="abi":
        target=config.get("target")
        if not target: return fail("Error: Set target first.")
        if not args:
            run_abi(config)
        elif args[0]=="auto":
            path=auto_abi_path(target,config)
            if not path: return fail("Error: could not auto-discover an ABI for the current target.")
            print(f"ABI auto-loaded: {path}")
        else:
            path=os.path.expanduser(args[0])
            if not os.path.exists(path):
                return fail(f"Error: ABI file not found: {path}")
            config["abi_paths"][target]=path
            config["target_contract"]=artifact_contract_name(path,read_artifact(path))
            save_config(config)
            print(f"ABI override saved: {path}")
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
    elif cmd=="deps": run_deps(args)
    elif cmd=="layout": run_layout(args)
    elif cmd=="gas": run_gas(config,args)
    elif cmd=="raw": run_raw(config,args)
    elif cmd=="batch": run_batch(config,args)
    elif cmd=="audit": run_audit_mode(config)
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
    if isinstance(result,int): raise SystemExit(result)
    if _COMMAND_STATUS: raise SystemExit(_COMMAND_STATUS)

if __name__ == "__main__":
    main()
