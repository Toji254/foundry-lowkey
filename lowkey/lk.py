import hashlib
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
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit
from difflib import SequenceMatcher
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import audit_context

try:
    from forge_tools import NATIVE_COMMANDS as FORGE_NATIVE_COMMANDS
except ImportError:
    FORGE_NATIVE_COMMANDS = set()

CONFIG_DIR = os.path.expanduser("~/.lowkey")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
SNAPSHOT_DIR = os.path.join(CONFIG_DIR, "snapshots")
AUDIT_DIR = os.path.expanduser("~/.lowkey/audit")
SESSION_FILE = os.path.join(AUDIT_DIR, "session_log.txt")
FORK_FILE = os.path.join(CONFIG_DIR, "fork.json")
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
    "abi_paths": {}, "project_roots": {}, "labels": {}, "confirm_sends": False, "rpc_auto": False, "version": 4
}

_COMMAND_STATUS = 0

class CommandResult(str):
    def __new__(cls, output="", code=0):
        result = super().__new__(cls, output or "")
        result.code = code
        result.output = str(output or "")
        return result

    @property
    def text(self):
        return self.output

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
    for key in ["aliases", "targets", "rpc_profiles", "wallets", "abi_paths", "project_roots", "labels"]:
        if not isinstance(config.get(key), dict): config[key] = {}
    # ABI paths are normalized lazily after helper definitions are loaded.
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
        return value if value.lower().startswith("0x") else "0x"+value
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
    if isinstance(entry,dict) and entry.get("source")=="anvil-impersonated":
        return f"{actor} (impersonated, {entry.get('address','?')})"
    if isinstance(entry,dict) and entry.get("env"):
        return f"{actor} (env:{entry['env']})"
    if isinstance(entry,dict) and entry.get("private_key"):
        return f"{actor} (local key)"
    if is_probable_private_key(actor):
        return "<raw private key configured>"
    return str(actor)

def actor_address(config, name=None):
    name = name or config.get("actor")
    if not name:
        return None
    entry = config.get("wallets", {}).get(name)
    if isinstance(entry, dict) and entry.get("address"):
        return entry["address"]
    key = resolve_wallet_key(config, name)
    if not key:
        return None
    code, address, _ = cast_output(["cast", "wallet", "address", "--private-key", key])
    if code == 0 and address:
        return address.strip().splitlines()[-1].strip()
    return None
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

def local_artifact_paths(root="."):
    return [p for p in artifact_json_files(root) if "out" in Path(p).parts]

def artifact_contract_name(path, artifact):
    if isinstance(artifact,dict) and artifact.get("contractName"): return str(artifact["contractName"])
    return Path(path).stem

def read_artifact(path):
    try:
        with open(path,"r",encoding="utf-8") as f: value=json.load(f)
        return value if isinstance(value,dict) else None
    except (OSError,json.JSONDecodeError): return None

def foundry_project_root(start="."):
    try:
        path=Path(start).expanduser().resolve()
    except OSError:
        return None
    if path.is_file():
        path=path.parent
    for parent in [path,*path.parents]:
        if (parent/"foundry.toml").is_file():
            return str(parent)
    return None

def path_is_within(path, root):
    try:
        Path(path).expanduser().resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False

def project_context_target(root=None):
    """Return the current project's remembered target, ignoring stale legacy data."""
    project_root = audit_context.foundry_project_root(root)
    context = audit_context.load(project_root)
    target = context.get("target", {})
    if not isinstance(target, dict) or not is_address(target.get("address")):
        return None

    source = target.get("source")
    artifact = target.get("artifact")
    contract = target.get("contract")

    # Older contexts may contain a global target copied from another project.
    # Accept an explicitly recorded project target, or legacy targets that still
    # point at a contract/artifact belonging to this project.
    if source in {"manual", "auto", "project"}:
        return target
    if artifact and path_is_within(artifact, project_root):
        return target
    return None

def active_project_target(config, root=None):
    """Resolve a target for the current Foundry project before using global config."""
    project_root = audit_context.foundry_project_root(root)
    target = project_context_target(project_root)
    if target:
        return target.get("address")

    global_target = config.get("target")
    if not is_address(global_target):
        return None

    # Never reuse a target whose remembered project root belongs elsewhere.
    configured_root = configured_project_root(global_target, config)
    if configured_root and Path(configured_root).resolve() == Path(project_root).resolve():
        return global_target
    return None

def activate_project_target(config, root=None):
    """Hydrate legacy command config from the current project's target memory."""
    project_root = audit_context.foundry_project_root(root)
    target = project_context_target(project_root)
    if not target:
        if not active_project_target(config, project_root):
            config["target"] = None
        return None

    config["target"] = target.get("address")
    if target.get("contract"):
        config["target_contract"] = target["contract"]
    if target.get("artifact"):
        config.setdefault("abi_paths", {})[target["address"]] = target["artifact"]
    return target["address"]

def project_artifact_function_matches(root, query):
    """Find ABI functions directly from the current project's build artifacts."""
    matches = []
    query_lower = str(query or "").lower()
    for path in local_artifact_paths(root):
        artifact = read_artifact(path)
        if not isinstance(artifact, dict):
            continue
        abi = artifact.get("abi", [])
        if not isinstance(abi, list):
            continue
        contract = artifact_contract_name(path, artifact)
        for item in abi_functions(abi):
            signature = format_signature(item)
            candidate = signature.lower()
            name = str(item.get("name") or "").lower()
            if not query_lower or query_lower in candidate or query_lower == name:
                matches.append((contract, signature, path))
    # Exact signatures/names first, then shortest contract/path ordering.
    matches.sort(key=lambda item: (
        0 if str(query).lower() == item[1].lower() else
        1 if str(query).lower() == item[1].split("(", 1)[0].lower() else 2,
        item[0].lower(),
        item[1].lower(),
    ))
    return matches

def configured_project_root(target,config):
    roots=config.get("project_roots",{}) if isinstance(config,dict) else {}
    root=roots.get(target) if isinstance(roots,dict) else None
    if not root and isinstance(target,str):
        lowered=target.lower()
        root=next(
            (value for address,value in roots.items()
             if isinstance(address,str) and address.lower()==lowered),
            None,
        )
    if not root:
        return None
    try:
        path=Path(os.path.expanduser(str(root)))
        if not path.is_absolute():
            path=Path.cwd()/path
        path=path.resolve()
        return str(path) if path.is_dir() else None
    except OSError:
        return None

def remember_abi_path(config,target,path):
    if not target or not path:
        return path
    try:
        absolute=str(Path(os.path.expanduser(str(path))).resolve())
    except OSError:
        return path
    if not os.path.exists(absolute):
        return path

    root=foundry_project_root(absolute)
    # Persist the resolved artifact as an absolute path. The project root is
    # still remembered separately for project-scoped operations, but artifact
    # reads must never depend on the caller's current working directory.
    stored=absolute

    changed=False
    if config.setdefault("abi_paths",{}).get(target)!=stored:
        config["abi_paths"][target]=stored
        changed=True
    if root and configured_project_root(target,config)!=root:
        config.setdefault("project_roots",{})[target]=root
        changed=True
    if changed:
        config["_config_dirty"]=True
    return absolute

def resolve_abi_path(config,target,path=None):
    if not target:
        return None
    if path is None:
        path=config.get("abi_paths",{}).get(target)
    if not path:
        return None

    expanded=os.path.expanduser(str(path))
    if os.path.isabs(expanded):
        return remember_abi_path(config,target,expanded)

    if os.path.exists(expanded):
        return remember_abi_path(config,target,expanded)

    root=configured_project_root(target,config)
    if root:
        candidate=os.path.join(root,expanded)
        if os.path.exists(candidate):
            return remember_abi_path(config,target,candidate)
    return None

def auto_abi_path(target,config):
    if not target or not is_address(target):
        return None

    search_roots=["."]
    remembered_root=configured_project_root(target,config)
    if remembered_root and os.path.abspath(remembered_root)!=os.path.abspath("."):
        search_roots.insert(0,remembered_root)

    paths=[]
    for root in search_roots:
        paths.extend(local_artifact_paths(root))
    preferred=config.get("target_contract")
    candidate_addresses=[target]

    if not preferred:
        for record in discover_deployments("."):
            if str(record.get("address","")).lower()==target.lower():
                preferred=record.get("contract")
                if preferred:
                    config["target_contract"]=preferred
                break

    rpc=effective_rpc(config)
    if rpc:
        code,implementation,error=cast_output(["cast","implementation",target,"--rpc-url",rpc])
        if code==0 and is_address(implementation):
            implementation=implementation.strip().splitlines()[-1].strip()
            if implementation.lower()!=target.lower():
                candidate_addresses.insert(0,implementation)
                if not preferred:
                    for record in discover_deployments("."):
                        if str(record.get("address","")).lower()==implementation.lower():
                            preferred=record.get("contract")
                            if preferred:
                                config["target_contract"]=preferred
                            break

    if preferred:
        preferred_lower=str(preferred).lower()
        for path in paths:
            artifact=read_artifact(path)
            name=artifact_contract_name(path,artifact).lower()
            if name==preferred_lower or Path(path).stem.lower()==preferred_lower:
                remember_abi_path(config,target,path)
                return path

    if rpc:
        for candidate in candidate_addresses:
            code,runtime,_=cast_output(["cast","code",candidate,"--rpc-url",rpc])
            if code!=0 or not runtime or not runtime.startswith("0x") or runtime=="0x":
                continue
            for path in paths:
                artifact=read_artifact(path)
                deployed=artifact.get("deployedBytecode") if isinstance(artifact,dict) else None
                if isinstance(deployed,dict):
                    deployed=deployed.get("object")
                if isinstance(deployed,str) and deployed.lower()==runtime.lower():
                    remember_abi_path(config,target,path)
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
    abi_path=resolve_abi_path(config,target,abi_path)
    if not abi_path:
        abi_path=auto_abi_path(target,config)
    if not abi_path or not os.path.exists(abi_path): return []
    try:
        with open(abi_path,"r",encoding="utf-8") as f: artifact=json.load(f)
        abi=artifact.get("abi",[]) if isinstance(artifact,dict) else artifact
        if isinstance(artifact,dict) and artifact.get("contractName") and not config.get("target_contract"):
            config["target_contract"]=artifact.get("contractName")
        return abi if isinstance(abi,list) else []
    except (OSError,json.JSONDecodeError): return []

def source_public_storage_names(root="."):
    names=set()
    for path in source_sol_files(root):
        try:
            source=Path(path).read_text(encoding="utf-8")
        except OSError:
            continue
        for statement in source.split(";"):
            lowered=statement.lower()
            if any(token in lowered for token in ("function ", "event ", "error ", "modifier ", "constructor(")):
                continue
            if re.search(r"\b(?:constant|immutable)\b", statement):
                continue
            match=re.search(r"\bpublic\s+([A-Za-z_]\w*)\s*(?:=|$)", statement)
            if match:
                names.add(match.group(1))
    return names


def storage_getter_names(target,config,abi):
    path=resolve_abi_path(config,target)
    if not path:
        path=auto_abi_path(target,config)

    labels=set()
    artifact={}
    if path and os.path.exists(path):
        artifact=read_artifact(path) or {}
        layout=artifact.get("storageLayout",{}) if isinstance(artifact,dict) else {}
        storage=layout.get("storage",[]) if isinstance(layout,dict) else []
        labels.update(
            entry.get("label")
            for entry in storage
            if isinstance(entry,dict) and entry.get("label")
        )

    # Foundry artifacts do not always contain storageLayout. Ask Forge for the
    # authoritative layout when we are inside a Foundry project, so public
    # mapping/struct getters are still classified correctly.
    if not labels:
        # The artifact we loaded is the authority for the contract name. Do not
        # let a stale target_contract config entry point Forge at another contract.
        contract_name = artifact.get("contractName") if isinstance(artifact,dict) else None
        if not contract_name:
            contract_name = config.get("target_contract")

        if contract_name:
            inspect_commands = [
                ["forge","inspect",str(contract_name),"storage-layout","--json"],
                ["forge","inspect",str(contract_name),"storage-layout"],
            ]
            for command in inspect_commands:
                code,out,_=cast_output(command)
                if code!=0 or not out:
                    continue
                try:
                    payload=json.loads(out)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload,dict):
                    layout=payload.get("storageLayout") or payload.get("storage") or payload
                else:
                    layout=payload
                storage=layout if isinstance(layout,list) else []
                labels.update(
                    entry.get("label")
                    for entry in storage
                    if isinstance(entry,dict) and entry.get("label")
                )
                if labels:
                    break

    if not labels:
        labels.update(source_public_storage_names("."))
    
    return {
        item.get("name")
        for item in abi
        if item.get("type")=="function"
        and item.get("stateMutability") in {"view","pure"}
        and item.get("name") in labels
    }
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
        return fail("Error: Set target first.")
    abi = load_abi(target, config)
    if not abi:
        return fail("Error: No ABI loaded for the current target.")
    getter_names=storage_getter_names(target,config,abi)
    groups = [
        ("WRITE", [item for item in abi if item.get("type")=="function" and item.get("stateMutability") not in {"view","pure"}]),
        ("READ", [item for item in abi if item.get("type")=="function" and item.get("stateMutability") in {"view","pure"} and item.get("name") not in getter_names]),
        ("STORAGE GETTERS", [item for item in abi if item.get("type")=="function" and item.get("name") in getter_names]),
        ("EVENTS", [item for item in abi if item.get("type")=="event"]),
        ("ERRORS", [item for item in abi if item.get("type")=="error"]),
    ]
    path=resolve_abi_path(config,target) or auto_abi_path(target,config)
    print(f"ABI: {path or 'not loaded'}")
    for group, items in groups:
        if items:
            print(f"\n{group}")
            for item in items:
                print(f"  {format_signature(item)}")
def run_functions(config,query=None):
    root=audit_context.foundry_project_root()
    target=active_project_target(config,root)
    if not target:
        if not query:
            return fail("Error: no project target selected. Use 'lk fn <function>' to search build artifacts, or deploy and run 'lk target auto'.")
        matches=project_artifact_function_matches(root,query)
        if not matches:
            return fail(f"Error: no built-project function matched '{query}'. Run 'forge build' first.")
        print("LOWKEY BUILD FUNCTION")
        print("====================")
        print(f"Query:   {query}")

        def artifact_kind(contract, path):
            lowered_contract = str(contract).lower()
            lowered_path = str(path).lower()
            if "/mocks/" in lowered_path or lowered_contract.startswith("mock"):
                return "test mock"
            # Solidity interfaces conventionally use an I-prefixed contract name.
            if str(contract).startswith("I") and len(str(contract)) > 1 and str(contract)[1].isupper():
                return "interface"
            if "/interfaces/" in lowered_path:
                return "interface"
            return "implementation"

        ranked = sorted(
            matches,
            key=lambda item: (
                0 if artifact_kind(item[0], item[2]) == "implementation" else
                1 if artifact_kind(item[0], item[2]) == "interface" else 2,
                item[0].lower(),
            ),
        )
        primary = next((item for item in ranked if artifact_kind(item[0], item[2]) == "implementation"), ranked[0])
        contract, signature, path = primary

        print(f"Found:   {contract}::{signature}")
        print(f"ABI:     {path}")

        others = [
            f"{c} ({artifact_kind(c, p)})"
            for c, s, p in ranked
            if (c, s, p) != primary
        ]
        if others:
            print(f"Other:   {', '.join(others)}")

        print("Live:    none")
        print("Next:    deploy a target before using lk changes/trace.")
        return 0

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
    code, output, _ = cast_output(["cast", "sig", signature])
    if code != 0 or not output:
        return None
    return output.splitlines()[0].strip()

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
    else:
        result=run_cast(["run",tx_hash]+args,config)
        root=audit_context.foundry_project_root()
        audit_context.set_latest(root,tx_hash=tx_hash,trace=tx_hash)
        audit_context.record_tool("trace",root,status="completed",summary=f"transaction trace {tx_hash[:10]}...",data={"tx_hash":tx_hash})
        return result
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

def humanize_value(text, assume_wei=False):
    if text is None:
        return text
    if not assume_wei:
        return str(text)
    value = str(text)
    wei_pattern = r'\b(0x)?(\d+)\b'
    def replace_wei(match):
        try:
            raw = int(match.group(2))
        except ValueError:
            return match.group(0)
        eth_val = raw / 10**18
        return f"{match.group(0)} [~{eth_val:.4f} ETH]"
    return re.sub(wei_pattern, replace_wei, value)
def is_address(value):
    return isinstance(value,str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{40}",value))
def is_nonzero_slot(value):
    try:
        return int(value, 16) != 0
    except (TypeError, ValueError):
        return False

def format_send_summary(output, config, call=None):
    output=str(output or "")

    def field(name):
        import re
        match=re.search(rf"(?m)^{name}\s+(.*)$", output)
        return match.group(1).strip() if match else None

    def display_address(value):
        if not value or not is_address(value):
            return value

        lowered=value.lower()

        # User-defined wallet names take priority.
        for name, entry in config.get("wallets",{}).items():
            if isinstance(entry,dict) and str(entry.get("address","")).lower()==lowered:
                return f"{name} ({value})"

        # Then user-defined labels.
        for address, label in config.get("labels",{}).items():
            if str(address).lower()==lowered:
                return f"{label} ({value})"

        # Finally named targets/aliases such as "escrow".
        for name, address in target_aliases(config).items():
            if str(address).lower()==lowered:
                return f"{name} ({value})"

        return value

    tx_hash=field("transactionHash")
    block=field("blockNumber")
    gas=field("gasUsed")
    sender=display_address(field("from"))
    target=display_address(field("to"))
    status=field("status")

    status_text="SUCCESS" if status and status.startswith("1") else "REVERTED"

    lines=[
        "TRANSACTION",
        "===========",
    ]

    if call:
        lines.append(f"Call:      {call}")
    if sender:
        lines.append(f"From:      {sender}")
    if target:
        lines.append(f"To:        {target}")
    lines.append(f"Status:    {status_text}")
    if block:
        lines.append(f"Block:     {block}")
    if gas:
        lines.append(f"Gas used:  {gas}")
    if tx_hash:
        lines.append(f"Tx hash:   {tx_hash}")

    return "\n".join(lines)

def run_cast(args,config,capture=False):
    if not args:
        result=CommandResult("",2)
        record_status(result.code)
        return result if capture else result.code
    action=args[0]; shortcut_map={"c":"call","s":"send","st":"storage"}; cast_cmd=shortcut_map.get(action,action)
    remaining=list(args[1:]); target=config.get("target")

    # --as/--actor belongs to Lowkey, not Cast. Consume it here so it
    # selects the signer for this invocation without changing config["actor"].
    actor_override=None
    cleaned=[]
    index=0
    while index < len(remaining):
        token=remaining[index]
        if token in {"--as","--actor"}:
            if index+1 >= len(remaining):
                result=CommandResult(f"Error: {token} needs an actor name",2)
                record_status(result.code)
                if capture: return result
                print(str(result),file=sys.stderr)
                return result.code
            actor_override=remaining[index+1]
            index += 2
            continue
        cleaned.append(token)
        index += 1
    remaining=cleaned

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
        try:
            abi=load_abi(target,config)
            matches=matching_functions(abi,remaining[0]) if abi else []
            if len(matches)==1:
                remaining[1:]=prepare_argument_values(config,matches[0],remaining[1:])
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
    rpc_commands={"balance","call","send","storage","chain-id","block-number","code","codesize","codehash","nonce","logs","receipt","run","tx","estimate","implementation","admin","proof","lookup-address","resolve-name","erc20-token","block","gas-price","rpc","access-list"}
    active_rpc=effective_rpc(config)
    if cast_cmd in rpc_commands and active_rpc and "--rpc-url" not in cmd: cmd.extend(["--rpc-url",active_rpc])
    actor=actor_override or config.get("actor")
    actor_entry=config.get("wallets",{}).get(actor) if actor else None
    actor_key=resolve_wallet_key(config,actor) if cast_cmd=="send" else None
    if cast_cmd=="send" and isinstance(actor_entry,dict) and actor_entry.get("source")=="anvil-impersonated":
        address=actor_entry.get("address")
        if not is_address(address):
            return fail("Error: impersonated actor has no valid address.")
        if "--from" not in cmd and not any(arg.startswith("--from=") for arg in cmd):
            cmd.extend(["--from",address])
        if "--unlocked" not in cmd:
            cmd.append("--unlocked")
    elif cast_cmd=="send" and actor and actor in config.get("wallets",{}) and not actor_key:
        entry=config.get("wallets",{}).get(actor)
        if isinstance(entry,dict) and entry.get("source")=="anvil-default":
            return fail("Error: current Anvil actor cannot be used on this RPC. Make sure the selected actor belongs to the detected Anvil node.")
        return fail(f"Error: signer profile '{actor}' has no usable private key. Check its environment variable.")
    if cast_cmd=="send" and actor_key and "--private-key" not in " ".join(cmd):
        cmd.extend(["--private-key",actor_key])
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
            if match:
                tx_hash=match.group(1)
                config["last_tx"]=tx_hash; config["last_tx_block"]=None; save_config(config)
                call=remaining[0] if remaining and "(" in remaining[0] else None
                root=audit_context.foundry_project_root()
                audit_context.set_latest(root,tx_hash=tx_hash,function=call)
                audit_context.emit(
                    "transaction",
                    root,
                    tool="cast",
                    summary=call or "transaction sent",
                    data={"tx_hash":tx_hash,"function":call},
                )
        result=CommandResult(final,code)
        record_status(code)
        if capture: return result
        if out:
            if cast_cmd=="send":
                call=remaining[0] if remaining and "(" in remaining[0] else None
                print(format_send_summary(out,config,call))
            else:
                print(humanize_value(apply_labels(out,config), assume_wei=(cast_cmd == "balance")))
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
        return fail("Error: Set target first.")
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
        return fail("Error: Set target first.")
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
    result_code=getattr(computed,"code",0 if computed else 1)
    if result_code != 0:
        return fail("Error: could not compute mapping slot.")
    computed=str(computed).strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}",computed):
        return fail("Error: could not compute mapping slot.")
    if run_mapping_human_view(config,slot,key_type,key,computed):
        return 0
    print(f"Mapping slot: {computed}")
    return run_cast(["st",computed],config)
def snapshot_path(config,chain=None):
    target=config.get("target") or "no-target"
    chain=chain or run_cast(["chain-id"],config,capture=True) or "unknown-chain"
    safe_target=re.sub(r"[^0-9a-fA-Fx_-]","_",target)
    directory=os.path.join(SNAPSHOT_DIR,str(chain)); os.makedirs(directory,exist_ok=True)
    return os.path.join(directory,f"{safe_target}.json")

def run_snapshot(config,slots=None):
    if not config.get("target"):
        return fail("Error: Set target first.")
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
    except (OSError,json.JSONDecodeError): return fail("Error: invalid snapshot.")
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

    # Keep manually recorded findings in the same shared ledger as analyzer signals.
    impact = "Unknown"
    title = str(note)
    description = str(note)
    match = re.match(r"^\[([A-Za-z]+)\]\s*(.*)$", str(note))
    if match:
        level = match.group(1).lower()
        impact = {
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Informational",
            "informational": "Informational",
        }.get(level, "Unknown")
        remainder = match.group(2).strip()
        if ":" in remainder:
            title, description = remainder.split(":", 1)
            title = title.strip()
            description = description.strip()
        else:
            title = remainder

    root = audit_context.foundry_project_root()
    focus = audit_context.load(root).get("focus")
    signal = {
        "tool": "manual",
        "check": "manual",
        "title": title or "Manual finding",
        "impact": impact,
        "confidence": "Manual",
        "file": focus.get("file") if isinstance(focus, dict) else "",
        "line": focus.get("line") if isinstance(focus, dict) else None,
        "column": focus.get("column") if isinstance(focus, dict) else None,
        "function": focus.get("function") if isinstance(focus, dict) else None,
        "description": description,
        "next": "Validate the security property with source review and a reproducible Foundry test.",
        "status": "open",
    }
    audit_context.add_signal(signal, root)
    audit_context.emit(
        "manual-finding",
        root,
        tool="manual",
        summary=title or "Manual finding",
        data=signal,
    )

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
        return fail("Error: Run lk matrix init first.")
    if action=="actor" and len(args)==3:
        if not is_address(args[2]):
            return fail("Error: actor address must be a 20-byte hex address.")
        actors=read_json_file(paths["matrix_actors"],{})
        actors[args[1]]={"address":args[2],"label":args[1]}
        write_json_file(paths["matrix_actors"],actors)
        print(f"Matrix actor saved: {args[1]}"); return
    if action=="add" and len(args)>=5:
        name=args[1]
        if name in {item.get("name") for item in read_json_file(paths["matrix_scenarios"],[])}:
            return fail(f"Error: Scenario already exists: {name}")
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
            return fail(f"Error: Scenario not found: {args[1]}")
        identifier=solidity_identifier(scenario["name"])
        actor=read_json_file(paths["matrix_actors"],{}).get(scenario["actor"],{}).get("address")
        target=scenario["target"] if is_address(scenario.get("target")) else "0x" + "0"*40
        if not actor:
            return fail(f"Error: Matrix actor '{scenario['actor']}' has no address.")
        target_literal=solidity_address_literal(target)
        actor_literal=solidity_address_literal(actor)
        config_target=config.get("target")
        abi=load_abi(config_target or target,config) if config_target else []
        matches=matching_functions(abi,scenario["function"])
        if len(matches)>1:
            return fail(f"Error: Matrix function '{scenario['function']}' is overloaded; use the exact signature.")
        signature=format_signature(matches[0]) if matches else scenario["function"]
        default_args=[]
        if matches:
            for param in matches[0].get("inputs",[]):
                ptype=canonical_type(param)
                if ptype.startswith("address"):
                    default_args.append("address(0)")
                elif ptype.startswith("bool"):
                    default_args.append("false")
                elif ptype.startswith("bytes") and ptype not in {"bytes"}:
                    default_args.append("bytes32(0)" if ptype=="bytes32" else "hex\"\"")
                elif ptype=="bytes":
                    default_args.append("hex\"\"")
                elif ptype.startswith("string"):
                    default_args.append("\"\"")
                elif ptype.startswith("tuple") or ptype.startswith("("):
                    default_args.append("hex\"\"")
                else:
                    default_args.append("0")
        calldata="0x"
        if config_target and matches:
            code,encoded,error=cast_output(["cast","calldata",signature,*[x.replace("address(0)","0x0000000000000000000000000000000000000000") if x.startswith("address(0)") else x for x in default_args]])
            if code==0 and encoded:
                calldata=encoded
        expected=str(scenario.get("expected","")).lower()
        expects_revert=any(word in expected for word in ("revert","fail","reject","unauthor"))
        assertion = "assertFalse(success);" if expects_revert else "assertTrue(success);"
        template=f'''// Generated by LowkeyCast matrix.
pragma solidity ^0.8.20;
import {{Test}} from "forge-std/Test.sol";
import {{console2}} from "forge-std/console2.sol";

contract Matrix_{identifier} is Test {{
    address constant TARGET = {target_literal};
    address constant ACTOR = {actor_literal};

    function test_{identifier}() public {{
        vm.prank(ACTOR);
        (bool success, bytes memory data) = TARGET.call(hex"{calldata.removeprefix('0x')}");
        console2.log("Scenario", "{scenario["name"]}");
        console2.log("Function", "{signature}");
        console2.log("Success", success);
        if (!success) console2.logBytes(data);
        {assertion}
    }}
}}
'''
        path=write_generated_test("matrix_"+identifier,template)
        return run_foundry(["test","--match-path",Path(path).as_posix(),"-vvvv"])
    return fail("Usage: lk matrix init | actor <name> <address> | state <name> <desc> | add <name> <function> <actor> <expected> | list | test <name>")

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
        ("ETH formatting","1.0000 ETH" in humanize_value("1000000000000000000", assume_wei=True)),
        ("secret redaction","<redacted>" in redact_secrets("--private-key 0x"+"1"*64)),
        ("jwt redaction","<redacted>" in redact_secrets("--jwt-secret supersecret")),
        ("rpc redaction","sensitive-token" not in redact_secrets("--rpc-url https://example.com/sensitive-token")),
        ("tuple canonicalization",canonical_type({"type":"tuple","components":[{"type":"address"},{"type":"uint256"}]})=="(address,uint256)"),
        ("nested tuple array",canonical_type({"type":"tuple[]","components":[{"type":"address"},{"type":"uint256[]"}]})=="(address,uint256[])[]"),
        ("output signature",format_output_signature({"name":"f","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]})=="f(address)(uint256)"),
        ("target alias resolution",resolve_target_ref({"aliases":{"one":"0x"+"1"*40},"targets":{}},"one")=="0x"+"1"*40),
        ("safe solidity identifier",solidity_identifier("unauthorized release #1")=="unauthorized_release__1"),
        ("solidity address literal","address(uint160(0x00" in solidity_address_literal("0x"+"1"*40)),
        ("lab options",split_lab_options(["release","1","--actor","Alice","--value","1ether"])[1:] == ("Alice","1ether",False)),
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
    for name in ("python3", "cast", "forge", "anvil", "chisel"):
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
    slither=shutil.which("slither")
    if slither:
        try:
            result=subprocess.run([slither,"--version"],capture_output=True,text=True)
            version=(result.stdout or result.stderr).splitlines()[0] if result.returncode==0 else "version check failed"
            if result.returncode==0:
                print(f"PASS  slither: {slither} ({version})")
            else:
                print(f"WARN  slither: {slither} ({version})")
        except OSError as error:
            print(f"WARN  slither: {error}")
    else:
        print("NOTE  slither: not found (optional static analyzer)")

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
    if forge:
        try:
            help_result=subprocess.run([forge,"test","--help"],capture_output=True,text=True)
            help_text=(help_result.stdout or "")+(help_result.stderr or "")
            for label,flag in (("forge mutation","--mutate"),("forge symbolic","--symbolic"),("forge brutalize","--brutalize"),("forge rerun","--rerun")):
                if flag in help_text:
                    print(f"PASS  {label}: {flag}")
                else:
                    print(f"FAIL  {label}: {flag} not advertised by this Forge")
                    failures+=1
        except OSError as error:
            print(f"FAIL  forge test feature check: {error}")
            failures+=1

    for command,args in (("cast decode-event",["cast","decode-event","--help"]),
                         ("cast receipt",["cast","receipt","--help"]),
                         ("cast sig-event",["cast","sig-event","--help"]),
                         ("forge inspect",["forge","inspect","--help"]),
                         ("cast pretty-calldata",["cast","pretty-calldata","--help"]),
                         ("cast tx-pool",["cast","tx-pool","--help"]),
                         ("cast disassemble",["cast","disassemble","--help"]),
                         ("chisel",["chisel","--help"])):
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
        return fail("Error: No session history found.")
    lines=Path(SESSION_FILE).read_text(encoding="utf-8").splitlines()
    last_send=next((line.split("CMD: ",1)[1].strip() for line in reversed(lines) if "CMD: cast send " in line),None)
    if not last_send:
        return fail("Error: No send transaction found in session.")
    try:
        parts=shlex.split(last_send)
        send_index=parts.index("send")
        target=parts[send_index+1]; func=parts[send_index+2]
        target_literal=solidity_address_literal(target) if is_address(target) else target
        positional=[]; value="0"; index=send_index+3
        while index<len(parts):
            if parts[index]=="--value" and index+1<len(parts):
                value=parts[index+1]; index+=2; continue
            if parts[index].startswith("--"):
                index+=2 if index+1<len(parts) and not parts[index+1].startswith("--") else 1; continue
            positional.append(parts[index]); index+=1
        code,encoded,error=cast_output(["cast","calldata",func,*positional])
        if code!=0 and not encoded:
            return fail(f"Error generating calldata: {error}")
        calldata=encoded.removeprefix("0x")
    except (ValueError,IndexError) as error:
        return fail(f"Error generating test: {error}")
    value_expression=value
    for unit in ["ether","gwei","wei"]:
        if unit in value_expression and " " not in value_expression:
            value_expression=value_expression.replace(unit,f" {unit}")
    test=f'''pragma solidity ^0.8.20;
import "forge-std/Test.sol";

contract Exploit_Reproduction is Test {{
    address constant TARGET = {target_literal};

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
    root=audit_context.foundry_project_root()
    audit_context.record_tool("generator",root,status="completed",summary="exploit reproduction generated",data={"mode":"test-gen","output":filename,"function":func,"target":target})
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
    root=audit_context.foundry_project_root()
    records=discover_deployments(root)
    if not records:
        existing=project_context_target(root)
        if existing:
            print(f"Target already remembered for this project: {existing.get('contract') or 'unknown'} -> {existing.get('address')}")
            return 0
        return fail("No deployment found in broadcast/. Build artifacts exist, but a live target still needs deployment.")

    record=None
    if name:
        requested=str(name).strip().lower()
        record=next(
            (item for item in records if str(item.get("contract","")).strip().lower()==requested),
            None,
        )
        if record is None:
            available=", ".join(dict.fromkeys(str(item.get("contract","Unknown")) for item in records))
            return fail(
                f"Error: no broadcast deployment found for '{name}'."
                + (f" Available: {available}" if available else "")
            )
    else:
        record=records[0]

    alias=name or record["contract"]
    config["aliases"][alias]=record["address"]
    config["targets"][alias]=record["address"]
    config["target"]=record["address"]

    artifact_path=None
    for path in local_artifact_paths(root):
        artifact=read_artifact(path) or {}
        contract_name=artifact_contract_name(path,artifact)
        if contract_name.lower()==str(record["contract"]).lower():
            artifact_path=path
            config["abi_paths"][record["address"]]=path
            print(f"ABI auto-loaded: {path}")
            break

    config["target_contract"]=record["contract"]
    save_config(config)
    audit_context.set_target(
        root,
        address=record["address"],
        contract=record["contract"],
        artifact=artifact_path,
        source="auto",
    )
    print(f"Target selected: {alias} -> {record['address']}")
    return 0

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
    if len(args)<2: return fail("Usage: lk decode <function> <return-data>")
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
    if len(args)!=1: return fail("Usage: lk namespace <erc7201-namespace-id>")
    run_cast(["index-erc7201",args[0]],config)

def run_proof(config,args):
    if not args: return fail("Usage: lk proof <slot> [block]")
    run_cast(["proof",config.get("target"),args[0]]+(["--block",args[1]] if len(args)>1 else []),config)


def tool_path(name):
    return shutil.which(name)

def run_foundry(args, capture=False):
    binary = tool_path("forge")
    root = audit_context.foundry_project_root()
    command_name = args[0] if args else "forge"
    if not binary:
        message = "Error: forge was not found on PATH. Install Foundry first."
        audit_context.emit("forge-command", root, tool="forge", status="failed", summary=command_name)
        result = CommandResult(message, 127)
        record_status(result.code)
        if capture:
            return result
        print(message, file=sys.stderr)
        return result.code
    try:
        completed = subprocess.run([binary, *args], capture_output=capture, text=True)
    except OSError as error:
        message = f"Error executing forge: {error}"
        audit_context.emit("forge-command", root, tool="forge", status="failed", summary=command_name)
        result = CommandResult(message, 1)
        record_status(result.code)
        if capture:
            return result
        print(message, file=sys.stderr)
        return result.code

    code = completed.returncode
    output = (completed.stdout or completed.stderr or "").strip()
    audit_context.emit(
        "forge-command",
        root,
        tool="forge",
        status="completed" if code == 0 else "failed",
        summary=f"forge {command_name}",
        data={"command": command_name, "exit_code": code},
    )

    if capture:
        result = CommandResult(output, code)
        record_status(code)
        return result

    record_status(code)
    return code

def run_tool(name, args=None):
    binary = tool_path(name)
    if not binary:
        return fail(f"Error: {name} was not found on PATH. Install/update Foundry first.")
    try:
        return record_status(subprocess.run([binary, *(args or [])]).returncode)
    except OSError as error:
        return fail(f"Error executing {name}: {error}", 1)

def split_lab_options(args):
    values=[]
    actor=None
    value="auto"
    keep=False
    index=0
    raw=list(args or [])
    while index < len(raw):
        token=raw[index]
        if token in {"--actor","--as"}:
            if index+1>=len(raw):
                raise ValueError(f"{token} needs an actor name")
            actor=raw[index+1]
            index+=2
            continue
        if token in {"--value","--eth"}:
            if index+1>=len(raw):
                raise ValueError(f"{token} needs an ETH amount")
            value=raw[index+1]
            index+=2
            if index < len(raw) and str(raw[index]).lower() in {"wei","gwei","ether"}:
                value=f"{value} {raw[index]}"
                index+=1
            continue
        if token=="--keep":
            keep=True
            index+=1
            continue
        values.append(token)
        index+=1
    return values,actor,value,keep

def solidity_value(value):
    value=str(value or "0").strip()
    value=re.sub(r"(?i)(?<=\d)(ether|gwei|wei)\b", r" \1", value)
    return re.sub(r"\s+", " ", value).strip()

def validate_solidity_value(value):
    normalized=solidity_value(value)
    if not re.fullmatch(r"\d+(?:\.\d+)?(?:\s*(?:ether|gwei|wei))?", normalized, re.I):
        raise ValueError(f"invalid ETH value '{value}'")
    return normalized


def validate_calldata(value):
    normalized=str(value or "").removeprefix("0x")
    if not re.fullmatch(r"[0-9a-fA-F]*", normalized):
        raise ValueError("calldata must contain only hexadecimal bytes")
    if len(normalized) % 2:
        raise ValueError("calldata must contain complete bytes")
    return normalized

def normalize_numeric_argument(value, item_type):
    text=str(value).strip()
    match=re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*(wei|gwei|ether)",text,re.I)
    if not match or not (item_type.startswith("uint") or item_type.startswith("int")):
        return value
    try:
        number=Decimal(match.group(1))
        unit=match.group(2).lower()
        scale={"wei":Decimal(1),"gwei":Decimal(10**9),"ether":Decimal(10**18)}[unit]
        scaled=number*scale
        if scaled != scaled.to_integral_value():
            raise ValueError(f"non-integer value '{value}' cannot be passed to {item_type}")
        return str(int(scaled))
    except InvalidOperation as error:
        raise ValueError(f"invalid numeric value '{value}'") from error


def resolve_argument_aliases(config, function_item, values):
    values=list(values)
    inputs=function_item.get("inputs",[]) if isinstance(function_item,dict) else []
    if len(values)!=len(inputs):
        return values

    resolved=[]
    for item,value in zip(inputs,values):
        item_type=canonical_type(item)
        if item_type=="address":
            name=str(value).strip()
            if not is_address(name):
                address=actor_address(config,name)
                if address:
                    value=address
        value=normalize_numeric_argument(value,item_type)
        resolved.append(value)
    return resolved


def prepare_argument_values(config, function_item, values):
    raw=list(values)
    inputs=function_item.get("inputs",[]) if isinstance(function_item,dict) else []
    prepared=[]
    index=0

    for item in inputs:
        if index >= len(raw):
            break
        item_type=canonical_type(item)
        value=raw[index]
        if (
            (item_type.startswith("uint") or item_type.startswith("int"))
            and index + 1 < len(raw)
            and str(raw[index + 1]).lower() in {"wei","gwei","ether"}
        ):
            value=f"{value} {raw[index + 1]}"
            index += 2
        else:
            index += 1
        prepared.append(value)

    if index != len(raw):
        return raw
    return resolve_argument_aliases(config, function_item, prepared)


def encode_target_call(config, function, values):
    target=config.get("target")
    if not target:
        raise ValueError("Set a target first.")
    values=list(values)
    if any(str(value).strip()=="..." for value in values):
        raise ValueError("Replace '...' with real argument values. Use 'lk ask <function>' to see the required parameters.")

    signature=function
    if "(" not in signature or ")" not in signature:
        signature=resolve_function(signature,target,config)

    abi=load_abi(target,config)
    matches=matching_functions(abi,signature) if abi else []
    if len(matches)==1:
        values=prepare_argument_values(config,matches[0],values)
        inputs=matches[0].get("inputs",[])
        if len(values)!=len(inputs):
            expected=", ".join(
                f"{item.get('name') or 'arg'+str(index+1)}:{canonical_type(item)}"
                for index,item in enumerate(inputs)
            )
            suffix=f" Expected: {expected}." if expected else ""
            raise ValueError(
                f"{format_signature(matches[0])} expects {len(inputs)} argument(s), got {len(values)}.{suffix}"
            )

    code,encoded,error=cast_output(["cast","calldata",signature,*values])
    if code!=0 or not encoded:
        raise ValueError(error or "cast calldata failed")
    return signature, validate_calldata(encoded)

def solidity_address_literal(address):
    if not is_address(address):
        raise ValueError(f"invalid Solidity address literal: {address}")
    return f"address(uint160(0x00{address[2:]}))"

def generated_test_path(prefix, content=None):
    os.makedirs("test",exist_ok=True)
    safe=solidity_identifier(prefix)
    suffix=(
        hashlib.sha256(content.encode("utf-8")).hexdigest()[:10]
        if content is not None
        else datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    )
    return os.path.join("test", f"Lowkey_{safe}_{suffix}.t.sol")

def write_generated_test(prefix, content, announce=True):
    path=generated_test_path(prefix, content)
    temporary=Path(path + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)
    if announce:
        print(f"Lowkey generated test: {path}")
    return path

def discard_generated_test(path):
    try:
        Path(path).unlink()
    except OSError:
        pass

def resolve_lab_value(config, signature, raw_values, value_option):
    if value_option not in {None, "", "auto"}:
        return value_option

    abi=load_abi(config.get("target"),config)
    matches=matching_functions(abi,signature) if abi else []
    if len(matches)!=1 or matches[0].get("stateMutability")!="payable":
        return "0"

    raw=list(raw_values or [])
    for index,token in enumerate(raw):
        text=str(token).strip()
        if re.fullmatch(r"(?i)(?:[0-9]+(?:\\.[0-9]+)?)(?:ether|gwei|wei)",text):
            return text
        if (
            re.fullmatch(r"[0-9]+(?:\\.[0-9]+)?",text)
            and index+1<len(raw)
            and str(raw[index+1]).lower() in {"ether","gwei","wei"}
        ):
            return f"{text} {raw[index+1]}"
    return "0"


def local_foundry_test_args(config, path):
    args=["test","--match-path",Path(path).as_posix(),"-vv"]
    rpc=effective_rpc(config)
    if rpc and anvil_rpc_info(config):
        args[1:1]=["--fork-url",rpc]
    return args


def configured_actor_addresses(config):
    result=[]
    for name,entry in config.get("wallets",{}).items():
        address=entry.get("address") if isinstance(entry,dict) else None
        if not address:
            address=actor_address(config,name)
        if is_address(address):
            result.append((name,address))
    if result:
        return result
    info=anvil_rpc_info(config)
    accounts=info.get("accounts",[]) if info else []
    return [(f"actor{index}",address) for index,address in enumerate(accounts[:5])]

def run_probe(config,args):
    if not args:
        return fail("Usage: lk probe <function> [args...] [--actor NAME] [--value AMOUNT]")
    try:
        values,actor,value,_keep=split_lab_options(args)
        if not values:
            raise ValueError("function is required")
        signature,calldata=encode_target_call(config,values[0],values[1:])
        value=validate_solidity_value(resolve_lab_value(config,signature,values[1:],value))
        target=config.get("target")
        actors=[]
        if actor:
            address=actor_address(config,actor)
            if not address:
                raise ValueError(f"unknown actor: {actor}")
            actors=[(actor,address)]
        else:
            actors=configured_actor_addresses(config)
        if not actors:
            raise ValueError("No actors configured. Use lk actor <index> <name> first.")
        calls=[]
        target_literal=solidity_address_literal(target)
        for index,(name,address) in enumerate(actors):
            actor_literal=solidity_address_literal(address)
            calls.append(f'''        {{
            address actor = {actor_literal};
            console2.log("ACTOR {name} {address}");
            vm.deal(actor, 100 ether);
            vm.startPrank(actor);
            (bool success, bytes memory data) = TARGET.call{{value: VALUE}}(hex"{calldata}");
            vm.stopPrank();
            console2.log("SUCCESS", success);
            if (!success) console2.logBytes(data);
        }}''')
        body=f'''// Generated by LowkeyCast. This is a non-asserting probe: it records behavior.
pragma solidity ^0.8.20;

import {{Test}} from "forge-std/Test.sol";
import {{console2}} from "forge-std/console2.sol";

contract LowkeyProbe is Test {{
    address constant TARGET = {target_literal};
    uint256 constant VALUE = {solidity_value(value)};

    function test_probe() public {{
        // Function: {signature}
{chr(10).join(calls)}
    }}
}}
'''
        path=write_generated_test("probe_"+signature.split("(",1)[0],body)
        code=run_foundry(local_foundry_test_args(config,path))
        if code != 0:
            discard_generated_test(path)
        return code
    except (ValueError,IndexError) as error:
        return fail(f"Error: {error}")

def storage_layout_details(config):
    target=config.get("target")
    paths=[]
    if target:
        preferred_path=resolve_abi_path(config,target) or auto_abi_path(target,config)
        if preferred_path:
            paths.append(preferred_path)
    contracts=[]
    configured=config.get("target_contract")
    if configured:
        contracts.append(str(configured))

    # Prefer the target artifact's own storageLayout when available. It is tied
    # to the exact ABI/artifact Lowkey selected, so it avoids stale contract-name
    # config causing the decoder to silently give up.
    for path in paths:
        artifact=read_artifact(path) or {}
        name=artifact.get("contractName")
        if name and str(name) not in contracts:
            contracts.append(str(name))

        # Some Foundry-compatible artifacts contain ABI/bytecode/metadata
        # but omit contractName and storageLayout. In that case the artifact
        # filename still gives us a trustworthy contract name, e.g.
        # ./out/EthEscrow.sol/Escrow.json -> Escrow.
        if not name:
            fallback=Path(path).stem
            if fallback and fallback not in contracts:
                contracts.append(fallback)

        layout=artifact.get("storageLayout",{}) if isinstance(artifact,dict) else {}
        if isinstance(layout,dict):
            storage=layout.get("storage",[])
            types=layout.get("types",{})
            if isinstance(storage,list) and isinstance(types,dict) and storage and types:
                return types, storage

    # The exact artifact may omit storageLayout. Ask Forge, trying every
    # trustworthy contract name we have for the selected target.
    if not contracts:
        return {}, []

    # Forge inspect is project-relative. When the target artifact belongs to
    # another Foundry project, execute inspect from that project's root rather
    # than from whatever directory the auditor happens to be standing in.
    inspect_cwd=configured_project_root(target,config)
    if not inspect_cwd and paths:
        inspect_cwd=foundry_project_root(paths[0])

    for contract in contracts:
        try:
            completed=subprocess.run(
                ["forge","inspect",contract,"storage-layout","--json"],
                capture_output=True,
                text=True,
                cwd=inspect_cwd or None,
            )
            code=completed.returncode
            out=completed.stdout.strip()
        except OSError:
            continue
        if code!=0 or not out:
            continue
        try:
            payload=json.loads(out)
        except json.JSONDecodeError:
            continue
        storage=payload.get("storage",[]) if isinstance(payload,dict) else []
        types=payload.get("types",{}) if isinstance(payload,dict) else {}
        if isinstance(storage,list) and isinstance(types,dict) and storage and types:
            return types, storage
    return {}, []


def source_mapping_declarations(root):
    """Return generic mapping declarations discovered in Solidity source files."""
    base = Path(root)
    if not base.exists():
        return []

    structs = {}
    struct_pattern = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([\s\S]*?)\}")
    field_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")

    for path in sorted(base.rglob("*.sol")):
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for match in struct_pattern.finditer(source):
            fields = []
            for field in field_pattern.finditer(match.group(2)):
                fields.append((field.group(2), field.group(1)))
            structs[match.group(1)] = fields

    mapping_pattern = re.compile(
        r"\bmapping\s*\(\s*([^=)]+?)\s*=>\s*([^)]*?)\)\s*"
        r"(?:public|private|internal|external)?\s*"
        r"([A-Za-z_][A-Za-z0-9_]*)\s*;"
    )

    declarations = []
    for path in sorted(base.rglob("*.sol")):
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue

        for match in mapping_pattern.finditer(source):
            key_raw = " ".join(match.group(1).split())
            value_raw = " ".join(match.group(2).split())
            name = match.group(3)

            key_parts = key_raw.split()
            value_parts = value_raw.split()
            key_type = key_parts[0] if key_parts else key_raw
            value_type = value_parts[0] if value_parts else value_raw

            declarations.append({
                "file": str(path),
                "label": name,
                "key_type": key_type,
                "value_type": value_type,
                "fields": list(structs.get(value_type, [])),
            })

    return declarations


def storage_type_label(types, type_id):
    if not isinstance(type_id,str):
        return ""
    info=types.get(type_id,{}) if isinstance(types,dict) else {}
    label=str(info.get("label") or type_id)
    # Foundry normally gives human labels ("address", "uint256"), but some
    # layouts expose internal ids such as "t_address" / "t_uint256".
    if label.startswith("t_"):
        label=label[2:]
    return label


def storage_slot_int(value):
    text=str(value).strip()
    try:
        return int(text,16) if text.lower().startswith("0x") else int(text,10)
    except (TypeError,ValueError):
        return None


def mapping_layout_entry(config, base_slot, key_type):
    types,storage=storage_layout_details(config)
    if not types or not storage:
        return None, types

    base_int=storage_slot_int(base_slot)
    if base_int is None:
        return None, types

    for entry in storage:
        entry_slot=storage_slot_int(entry.get("slot"))
        if entry_slot != base_int:
            continue
        mapping_type=types.get(entry.get("type"),{})
        if mapping_type.get("encoding")!="mapping":
            continue
        actual_key=storage_type_label(types,mapping_type.get("key"))
        if actual_key == key_type or (
            key_type=="uint256" and str(actual_key).startswith(("uint","int"))
        ):
            return entry, types
    return None, types


def decode_storage_member(raw, type_id, types, offset=0):
    raw=str(raw).strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}",raw):
        return raw
    info=types.get(type_id,{}) if isinstance(type_id,str) else {}
    label=storage_type_label(types,type_id)
    nbytes=info.get("numberOfBytes")
    try:
        width=int(str(nbytes),0) if nbytes is not None else 32
    except (TypeError,ValueError):
        width=32
    try:
        byte_offset=int(str(offset),0)
    except (TypeError,ValueError):
        byte_offset=0

    raw_int=int(raw,16)
    mask=(1 << (width*8))-1 if width < 32 else (1 << 256)-1
    value_int=(raw_int >> (byte_offset*8)) & mask

    lowered=label.lower()
    if lowered=="address" or lowered.startswith("contract "):
        if value_int==0:
            return "none"
        return f"0x{value_int:040x}"
    if lowered=="bool":
        return "true" if value_int else "false"
    if lowered.startswith("uint") or lowered.startswith("int") or lowered.startswith("enum "):
        return str(value_int)
    return "0x"+format(value_int,"064x")


def format_mapping_member(config, raw, member, types):
    value=decode_storage_member(
        raw,
        member.get("type"),
        types,
        member.get("offset",0),
    )
    if value=="none":
        return value
    if is_address(value):
        name=assigned_anvil_address(config,value)
        return f"{name} ({value})" if name else value
    if re.fullmatch(r"[0-9]+",str(value)):
        label=str(member.get("label","")).lower()
        if any(token in label for token in ("amount","value","balance")):
            try:
                wei=int(value)
                if wei >= 10**9:
                    return f"{wei} wei [~{wei/10**18:.4f} ETH]"
            except ValueError:
                pass
        return value
    return value


def run_mapping_human_view(config, base_slot, key_type, key, mapped_slot):
    entry,types=mapping_layout_entry(config,base_slot,key_type)
    if not entry:
        return False

    mapping_type=types.get(entry.get("type"),{})
    value_type=types.get(mapping_type.get("value"),{})
    members=value_type.get("members",[]) if isinstance(value_type,dict) else []
    if not members:
        return False

    mapping_name=entry.get("label","mapping")
    key_display=display_storage_key(config,key)
    print(f"Mapping:      {mapping_name}")
    print(f"Key:          {key_display}")
    print(f"Base slot:    {base_slot}")
    print(f"Value slot:   {mapped_slot}")
    print("Fields:")

    for member in members:
        try:
            member_offset=int(str(member.get("slot","0")),0)
        except (TypeError,ValueError):
            member_offset=0
        slot_int=storage_slot_int(mapped_slot)
        if slot_int is None:
            return False
        full_slot="0x"+format(slot_int+member_offset,"064x")
        raw=run_cast(["st",full_slot],config,capture=True)
        code=getattr(raw,"code",0)
        if code!=0:
            print(f"  {member.get('label','field'):<16} <unreadable>")
            continue
        shown=format_mapping_member(config,str(raw),member,types)
        print(f"  {member.get('label','field'):<16} {shown}")
    print("  raw mapping slot  ", mapped_slot)
    return True


def lab_argument_candidates(config, signature, raw_values, actor_address_value=None):
    abi=load_abi(config.get("target"),config)
    matches=matching_functions(abi,signature) if abi else []
    candidates=[]
    if len(matches)==1:
        inputs=matches[0].get("inputs",[])
        values=list(raw_values or [])
        # The helper understands "1 ether" as one uint argument.
        prepared=prepare_argument_values(config,matches[0],values)
        for item,value in zip(inputs,prepared):
            item_type=canonical_type(item)
            if item_type in {"address","bytes32"}:
                candidates.append((item_type,value))
            elif item_type.startswith("uint") or item_type.startswith("int"):
                normalized=normalize_numeric_argument(value,item_type)
                if re.fullmatch(r"[0-9]+",str(normalized)):
                    candidates.append((item_type,normalized))
    if actor_address_value:
        candidates.append(("address",actor_address_value))

    for _,address in configured_actor_addresses(config):
        candidates.append(("address",address))

    for number in range(0,17):
        candidates.append(("uint256",str(number)))

    seen=set()
    result=[]
    for key_type,key in candidates:
        marker=(key_type.lower(),str(key).lower())
        if marker in seen:
            continue
        seen.add(marker)
        result.append((key_type,key))
    return result


def mapping_slot_matches(config, signature, raw_values, actor_address_value, changed_slots):
    types,storage=storage_layout_details(config)
    if not storage or not types:
        return {}

    labels={}
    candidates=lab_argument_candidates(config,signature,raw_values,actor_address_value)
    for entry in storage:
        type_id=entry.get("type")
        info=types.get(type_id,{}) if isinstance(type_id,str) else {}
        if info.get("encoding")!="mapping":
            continue
        key_type_id=info.get("key")
        value_type_id=info.get("value")
        key_label=storage_type_label(types,key_type_id)
        base_slot=entry.get("slot")
        if not key_label or base_slot is None:
            continue

        for candidate_type,candidate_value in candidates:
            if candidate_type!=key_label:
                if not (candidate_type=="uint256" and str(key_label).startswith(("uint","int"))):
                    continue
            code,out,_=cast_output(["cast","index",str(key_label),str(candidate_value),str(base_slot)])
            if code!=0 or not out:
                continue
            mapped_slot=out.splitlines()[-1].strip().lower()
            if mapped_slot.startswith("0x"):
                mapped_slot=mapped_slot[2:].zfill(64)
            key_display=display_storage_key(config,candidate_value)
            value_info=types.get(value_type_id,{}) if isinstance(value_type_id,str) else {}
            members=value_info.get("members",[]) if isinstance(value_info,dict) else []

            if not members:
                for changed in changed_slots:
                    if changed.lower().removeprefix("0x").zfill(64)==mapped_slot:
                        labels[changed.lower()]=("%s[%s]"%(entry.get("label","mapping"),key_display),value_type_id)
            else:
                try:
                    base_int=int(mapped_slot,16)
                except ValueError:
                    continue
                for member in members:
                    try:
                        member_slot=base_int+int(str(member.get("slot","0")),0)
                    except ValueError:
                        continue
                    full="0x"+format(member_slot,"064x")
                    if full.lower() in {x.lower() for x in changed_slots}:
                        labels[full.lower()]=(
                            "%s[%s].%s"%(
                                entry.get("label","mapping"),
                                key_display,
                                member.get("label","field")
                            ),
                            member.get("type")
                        )
            if labels:
                # Keep looking for other mappings/keys; a function can touch more than one.
                pass
    return labels


def display_storage_key(config, value):
    text_value=str(value)
    if is_address(text_value):
        name=assigned_anvil_address(config,text_value)
        return name or text_value
    return text_value


def decode_storage_value(raw, type_id, types, path=""):
    raw=str(raw).strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}",raw):
        return raw
    label=storage_type_label(types,type_id)
    lowered=label.lower()

    if lowered=="address" or lowered.startswith("contract "):
        value="0x"+raw[-40:]
        if int(raw[-40:],16)==0:
            return "none"
        return value

    if lowered=="bool":
        return "true" if int(raw,16)!=0 else "false"

    if lowered.startswith("uint") or lowered.startswith("int") or lowered.startswith("enum "):
        return str(int(raw,16))

    return raw


def format_storage_value(config, raw, type_id, types, label, eth_sent_wei=None):
    value=decode_storage_value(raw,type_id,types,label)
    if value=="none":
        return "none"
    if is_address(value):
        return assigned_anvil_address(config,value) or value
    if re.fullmatch(r"[0-9]+",value or ""):
        lowered=label.lower()
        if eth_sent_wei is not None and any(x in lowered for x in ("amount","balance","value")):
            numeric=int(value)
            if numeric == 0:
                return "0 ETH"
            if numeric == eth_sent_wei:
                eth=eth_sent_wei/10**18
                return f"{eth:g} ETH"
        return value
    return value


def _extract_state_diff_json_slots(text_output):
    begin="STATE_DIFF_JSON_BEGIN"
    end="STATE_DIFF_JSON_END"
    start=text_output.find(begin)
    if start<0:
        return []
    start=text_output.find("\n",start)
    if start<0:
        return []
    finish=text_output.find(end,start)
    if finish<0:
        return []
    raw=text_output[start:finish].strip()
    if not raw:
        return []
    try:
        payload=json.loads(raw)
    except json.JSONDecodeError:
        first=raw.find("{")
        last=raw.rfind("}")
        if first<0 or last<=first:
            return []
        try:
            payload=json.loads(raw[first:last+1])
        except json.JSONDecodeError:
            return []

    slots=[]

    def valid_slot(value):
        return isinstance(value,str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{64}",value))

    def valid_value(value):
        return isinstance(value,str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{64}",value))

    def visit(node):
        if isinstance(node,dict):
            # AccountAccess / StorageAccess shaped records.
            slot=node.get("slot")
            before=node.get("previousValue",node.get("previous",node.get("oldValue",node.get("original"))))
            after=node.get("newValue",node.get("new",node.get("current")))
            is_write=node.get("isWrite")
            reverted=node.get("reverted",False)
            if valid_slot(slot) and valid_value(before) and valid_value(after):
                if (is_write is True or is_write is None) and not reverted and before.lower()!=after.lower():
                    slots.append({"slot":slot,"from":before,"to":after})

            # Some JSON state-diff formats use the slot itself as the dictionary key.
            for key,value in node.items():
                if valid_slot(key) and isinstance(value,dict):
                    nested_before=value.get("previousValue",value.get("previous",value.get("oldValue",value.get("original"))))
                    nested_after=value.get("newValue",value.get("new",value.get("current")))
                    if valid_value(nested_before) and valid_value(nested_after) and nested_before.lower()!=nested_after.lower():
                        slots.append({"slot":key,"from":nested_before,"to":nested_after})
                visit(value)
        elif isinstance(node,list):
            for item in node:
                visit(item)

    visit(payload)
    unique={}
    for item in slots:
        unique[item["slot"].lower()]=item
    return list(unique.values())


def parse_state_diff_output(output):
    text_output=str(output or "")
    clean_output=re.sub(r"\x1b\[[0-9;]*m","",text_output)

    gas_match=re.search(r"\[PASS\].*?test_state_diff\(\) \(gas: (\d+)\)",clean_output)
    call_match=re.search(r"(?m)^\s*CALL\s+(.+)$",clean_output)
    success_match=re.search(r"(?m)^\s*SUCCESS\s+(true|false)\s*$",clean_output,re.I)
    eth_match=re.search(r"(?m)^\s*ETH_SENT\s+([0-9]+)\s*$",clean_output)
    change_match=re.search(r"(?m)^\s*STORAGE_CHANGES\s+([0-9]+)\s*$",clean_output)
    fallback_match=re.search(r"(?m)^\s*FALLBACK_WRITES\s+([0-9]+)\s*$",clean_output)

    slots=_extract_state_diff_json_slots(clean_output)
    lines=[line.strip() for line in clean_output.splitlines()]
    for index,line in enumerate(lines):
        if line=="SLOT" and index+5<len(lines):
            slot=lines[index+1]
            if lines[index+2]=="FROM" and lines[index+4]=="TO":
                before=lines[index+3]
                after=lines[index+5]
                if re.fullmatch(r"0x[0-9a-fA-F]{64}",slot) and re.fullmatch(r"0x[0-9a-fA-F]{64}",after):
                    if before=="unknown" or re.fullmatch(r"0x[0-9a-fA-F]{64}",before):
                        slots.append({"slot":slot,"from":before,"to":after})

    dedup={}
    for item in slots:
        dedup[item["slot"].lower()]=item

    return {
        "gas":int(gas_match.group(1)) if gas_match else None,
        "call":call_match.group(1).strip() if call_match else None,
        "success":success_match.group(1).lower()=="true" if success_match else None,
        "eth_sent":int(eth_match.group(1)) if eth_match else 0,
        "changes_expected":int(change_match.group(1)) if change_match else len(dedup),
        "fallback_writes":int(fallback_match.group(1)) if fallback_match else 0,
        "state_diff_json":bool(_extract_state_diff_json_slots(clean_output)),
        "slots":list(dedup.values()),
        "raw":text_output,
    }

def format_lab_value(text_value, address_map=None):
    text_value=str(text_value)
    if is_address(text_value):
        if address_map and text_value.lower() in address_map:
            return address_map[text_value.lower()]
    return text_value


def format_call_display(config, signature, raw_values):
    abi=load_abi(config.get("target"),config)
    matches=matching_functions(abi,signature) if abi else []
    if len(matches)!=1:
        return signature
    prepared=prepare_argument_values(config,matches[0],raw_values)
    inputs=matches[0].get("inputs",[])
    rendered=[]
    address_map={}
    for name,entry in config.get("wallets",{}).items():
        if isinstance(entry,dict) and is_address(entry.get("address")):
            address_map[entry["address"].lower()]=name
    for item,value in zip(inputs,prepared):
        item_type=canonical_type(item)
        shown=str(value)
        if item_type=="address":
            shown=address_map.get(shown.lower(),shown)
        rendered.append(shown)
    return f"{matches[0].get('name','<function>')}({', '.join(rendered)})"


def candidate_storage_slots(config, signature, raw_values, actor_address):
    """Build a conservative set of slots to snapshot before/after an experiment.

    We always inspect the first 16 direct slots, then add mapping slots derived
    from function arguments, the current actor, configured actors, and small
    integer keys. This keeps the generated experiment compatible with older
    forge-std versions while still catching common mappings/structs.
    """
    slots={i for i in range(16)}
    types,storage=storage_layout_details(config)
    candidates=lab_argument_candidates(config,signature,raw_values,actor_address)

    for entry in storage:
        base_raw=entry.get("slot")
        base=storage_slot_int(base_raw)
        if base is None:
            continue
        type_id=entry.get("type")
        info=types.get(type_id,{}) if isinstance(type_id,str) else {}

        if info.get("encoding")=="mapping":
            key_type_id=info.get("key")
            value_type_id=info.get("value")
            key_label=storage_type_label(types,key_type_id)
            if not key_label:
                continue
            value_info=types.get(value_type_id,{}) if isinstance(value_type_id,str) else {}
            members=value_info.get("members",[]) if isinstance(value_info,dict) else []
            for candidate_type,candidate_value in candidates:
                if candidate_type!=key_label and not (
                    candidate_type=="uint256" and str(key_label).startswith(("uint","int"))
                ):
                    continue
                code,out,_=cast_output([
                    "cast","index",str(key_label),str(candidate_value),str(base)
                ])
                if code!=0 or not out:
                    continue
                try:
                    mapped=storage_slot_int(out.splitlines()[-1].strip())
                except Exception:
                    mapped=None
                if mapped is None:
                    continue
                slots.add(mapped)
                for member in members:
                    try:
                        offset=int(str(member.get("slot","0")),0)
                    except (TypeError,ValueError):
                        offset=0
                    slots.add(mapped+offset)
        else:
            slots.add(base)
            members=info.get("members",[]) if isinstance(info,dict) else []
            for member in members:
                try:
                    offset=int(str(member.get("slot","0")),0)
                except (TypeError,ValueError):
                    offset=0
                slots.add(base+offset)

    return sorted({int(slot) for slot in slots if int(slot)>=0})


def run_state_diff(config,args):
    if not args:
        return fail("Usage: lk changes <function> [args...] [--as ACTOR] [--eth AMOUNT]")
    try:
        values,actor,value,_keep=split_lab_options(args)
        if not values:
            raise ValueError("function is required")
        signature,calldata=encode_target_call(config,values[0],values[1:])
        value=validate_solidity_value(resolve_lab_value(config,signature,values[1:],value))
        target=config.get("target")
        selected_actor=actor or config.get("actor")
        address=actor_address(config,selected_actor)
        if not address:
            raise ValueError("Choose an actor first with lk actor <index> <name>.")

        target_literal=solidity_address_literal(target)
        actor_literal=solidity_address_literal(address)
        body=f'''// Generated by LowkeyCast. Snapshots candidate storage slots around a concrete call.
pragma solidity ^0.8.20;

import {{Test}} from "forge-std/Test.sol";
import {{console2}} from "forge-std/console2.sol";

contract LowkeyStateDiff is Test {{
    address constant TARGET = {target_literal};
    address constant ACTOR = {actor_literal};
    uint256 constant VALUE = {solidity_value(value)};

    function test_state_diff() public {{
        vm.deal(ACTOR, 100 ether);

        uint256 candidateCount = {len(candidate_storage_slots(config, signature, values[1:], address))};
        require(candidateCount > 0, "Lowkey: no candidate storage slots");

        bytes32[] memory slots = new bytes32[](candidateCount);
        bytes32[] memory beforeValues = new bytes32[](candidateCount);
        bytes32[] memory afterValues = new bytes32[](candidateCount);

{chr(10).join(f"        slots[{i}] = bytes32(uint256({slot}));" for i,slot in enumerate(candidate_storage_slots(config, signature, values[1:], address)) )}

        for (uint256 i = 0; i < slots.length; i++) {{
            beforeValues[i] = vm.load(TARGET, slots[i]);
        }}

        vm.prank(ACTOR);
        (bool success, bytes memory data) = TARGET.call{{value: VALUE}}(hex"{calldata}");

        for (uint256 i = 0; i < slots.length; i++) {{
            afterValues[i] = vm.load(TARGET, slots[i]);
        }}

        console2.log("CALL", "{signature}");
        console2.log("SUCCESS", success);
        console2.log("ETH_SENT", VALUE);
        console2.log("SLOTS_SCANNED", slots.length);

        if (!success) {{
            console2.log("REVERT_DATA");
            console2.logBytes(data);
            return;
        }}

        uint256 changed = 0;
        for (uint256 i = 0; i < slots.length; i++) {{
            if (beforeValues[i] != afterValues[i]) {{
                changed++;
                console2.log("SLOT");
                console2.logBytes32(slots[i]);
                console2.log("FROM");
                console2.logBytes32(beforeValues[i]);
                console2.log("TO");
                console2.logBytes32(afterValues[i]);
            }}
        }}

        console2.log("STORAGE_CHANGES", changed);
    }}
}}
'''
        path=write_generated_test("state-diff_"+signature.split("(",1)[0],body,announce=False)
        result=run_foundry(local_foundry_test_args(config,path),capture=True)
        output=result.text
        parsed=parse_state_diff_output(output)
        if result.code!=0:
            discard_generated_test(path)
            tail="\n".join(output.splitlines()[-18:]) if output else "forge test failed"
            return fail(f"Error: changes could not run.\n{tail}",result.code)

        address_map={}
        for name,entry in config.get("wallets",{}).items():
            if isinstance(entry,dict) and is_address(entry.get("address")):
                address_map[entry["address"].lower()]=name

        types,_storage=storage_layout_details(config)
        raw_args=values[1:]
        labels=mapping_slot_matches(config,signature,raw_args,address, [item["slot"] for item in parsed["slots"]])

        print("CHANGES")
        print("=======")
        print(f"Call:      {format_call_display(config,signature,raw_args)}")
        print(f"Caller:    {selected_actor or address}")
        eth_sent=parsed["eth_sent"]
        print(f"ETH sent:  {eth_sent/10**18:g} ETH" if eth_sent%10**18==0 else f"ETH sent:  {eth_sent} wei")
        status="SUCCESS" if parsed["success"] else "REVERTED"
        print(f"Result:    {status}")
        if parsed["gas"] is not None:
            print(f"Gas:       {parsed['gas']}")
        print(f"Storage:   {len(parsed['slots'])} change(s)")
        root=audit_context.foundry_project_root()
        audit_context.update(root, latest={"function":signature, "value":str(parsed["eth_sent"]), "calldata":calldata, "state_diff":"recorded"})
        audit_context.record_tool("state-diff", root, status="completed", summary=f"{len(parsed['slots'])} storage change(s)", data={"function":signature, "generated_test":path})

        storage_evidence = []
        if parsed["slots"]:
            print("\nStorage changes:")
        for item in parsed["slots"]:
            slot=item["slot"].lower()
            decoded=labels.get(slot)
            if isinstance(decoded,tuple):
                label,type_id=decoded
            else:
                label=decoded or f"slot {slot}"
                type_id=None
            before=format_storage_value(config,item["from"],type_id,types,label,eth_sent)
            after=format_storage_value(config,item["to"],type_id,types,label,eth_sent)
            print(f"  {label}")
            print(f"    {before}  ->  {after}")
            storage_evidence.append({
                "slot": slot,
                "label": label,
                "type": type_id,
                "from": item["from"],
                "to": item["to"],
                "from_display": before,
                "to_display": after,
            })
            print(f"    slot: {slot}")

        if parsed["changes_expected"]!=len(parsed["slots"]):
            print(f"\nNote: Forge reported {parsed['changes_expected']} changed slots; Lowkey decoded {len(parsed['slots'])}.")

        evidence={
            "kind":"state-diff",
            "function":signature,
            "calldata":calldata,
            "caller":selected_actor or address,
            "actor":selected_actor,
            "success":parsed["success"],
            "gas":parsed["gas"],
            "eth_sent_wei":parsed["eth_sent"],
            "changes_expected":parsed["changes_expected"],
            "fallback_writes":parsed["fallback_writes"],
            "state_diff_json":parsed["state_diff_json"],
            "storage_changes":storage_evidence,
            "generated_test":path,
        }
        focus=audit_context.load(root).get("focus")
        focus_signal_id=focus.get("signal_id") if isinstance(focus,dict) else None
        if focus_signal_id:
            linked=audit_context.attach_signal_evidence(focus_signal_id,evidence,root)
            if linked:
                print(f"\nEvidence linked: {focus_signal_id}")
            else:
                print(f"\nWarning: investigation focus {focus_signal_id} no longer exists; evidence was not linked.",file=sys.stderr)

        if not parsed["slots"]:
            if parsed["success"]:
                print("No storage values changed.")
            print(f"\nTest: {path}")
            return 0

        print(f"\nTest: {path}")
        return 0
    except (ValueError,IndexError) as error:
        return fail(f"Error: {error}")


def run_cast_deep(config,args):
    if not args:
        return fail("Usage: lk <4byte|4byte-calldata|4byte-event|access-list|interface|constructor-args|creation-code|decode-calldata|abi-encode> ...")
    command=args[0]
    values=list(args[1:])
    if command=="interface":
        if values:
            return run_cast(["interface",*values],config)
        target=config.get("target")
        if not target:
            return fail("Error: Set target or provide an ABI path.")
        path=resolve_abi_path(config,target) or auto_abi_path(target,config)
        if not path:
            return fail("Error: no local ABI found for the current target.")
        return run_cast(["interface",path],config)
    if command in {"constructor-args","creation-code"}:
        target=values[0] if values else config.get("target")
        if not target:
            return fail(f"Usage: lk {command} <address>")
        result=run_cast([command,target,*values[1:]],config,capture=True)
        result_code=getattr(result,"code",result if isinstance(result,int) else 1)
        result_text=getattr(result,"text",str(result or ""))
        if result_code != 0 and effective_rpc(config) and anvil_rpc_info(config):
            lowered=result_text.lower()
            if "etherscan" in lowered or "constructor" in lowered or "creation" in lowered:
                return fail(
                    f"Error: {command} needs creation/deployment data that this local Anvil state may not contain."
                )
        print(result_text)
        return result_code
    if command=="access-list":
        target=config.get("target")
        if values and is_address(values[0]):
            target=values.pop(0)
        if not target:
            return fail("Usage: lk access-list [address] <function> [args]")
        if not values:
            return run_cast(["access-list",target],config)
        function=values[0]
        if "(" not in function or ")" not in function:
            try:
                function=resolve_function(function,target,config)
            except ValueError as error:
                return fail(f"Error: {error}")
        return run_cast(["access-list",target,function,*values[1:]],config)
    if command=="decode-calldata":
        if not values:
            return fail("Usage: lk decode-calldata <0x...> | lk decode-calldata '<signature>' <0x...>")
        if len(values)==1:
            data=values[0]
            if not re.fullmatch(r"0x[0-9a-fA-F]*",data or "") or len(data)<10 or len(data)%2:
                return fail("Error: calldata must be even-length hex beginning with 0x.")
            target=config.get("target")
            matches=[]
            for item in abi_functions(load_abi(target,config)):
                signature=format_signature(item)
                selector=abi_selector(signature)
                if selector and selector.lower()==data[:10].lower():
                    matches.append(signature)
            if len(matches)==1:
                print(f"Signature: {matches[0]}")
                return run_cast(["decode-calldata",matches[0],data],config)
            if len(matches)>1:
                print("Ambiguous selector; use an exact signature:")
                for signature in matches:
                    print(f"  {signature}")
                return fail("Error: multiple ABI functions match this selector.")
            return fail("Error: no unique ABI signature for this calldata. Use lk 4byte-calldata or provide the signature explicitly.")
        return run_cast(["decode-calldata",*values],config)
    if command=="abi-encode":
        if not values:
            return fail("Usage: lk abi-encode <type[,type...]> [args...]")
        signature=values[0]
        if "(" not in signature:
            signature=f"lowkey({signature})"
        return run_cast(["abi-encode",signature,*values[1:]],config)
    if command in {"4byte","4byte-calldata","4byte-event"}:
        if not values:
            return fail(f"Usage: lk {command} <value>")
        return run_cast([command,*values],config)
    return fail(f"Error: unsupported Cast power command: {command}")

def run_calldata(config,args):
    if len(args)!=1:
        return fail("Usage: lk calldata <raw-calldata>")
    data=args[0]
    if not re.fullmatch(r"0x[0-9a-fA-F]*",data) or len(data)<10 or len(data)%2:
        return fail("Error: calldata must be even-length hex beginning with 0x.")
    print(f"Selector: {data[:10]}")
    abi=load_abi(config.get("target"),config)
    matches=[]
    for item in abi_functions(abi):
        signature=format_signature(item)
        selector=abi_selector(signature)
        if selector and selector.lower()==data[:10].lower():
            matches.append((signature,item))
    if len(matches)==1:
        signature,item=matches[0]
        print(f"ABI:      {signature}")
        print(f"Args:     {decode_abi_input(signature,data)}")
    elif len(matches)>1:
        print("ABI:      ambiguous")
        for signature,_ in matches:
            print(f"  {signature}")
    else:
        print("ABI:      unknown")
        code,out,error=cast_output(["cast","4byte-calldata",data])
        if out:
            print(out)
        elif error:
            print(error,file=sys.stderr)
            record_status(code)
    code,out,error=cast_output(["cast","pretty-calldata",data])
    if out:
        print("\nPretty calldata:")
        print(out)
    elif error:
        print(error,file=sys.stderr)
    return 0

def run_txpool(config,args):
    rpc=effective_rpc(config)
    if not rpc:
        return fail("Error: an RPC is required for txpool inspection. Start Anvil or set lk rpc <url>.")

    mode=(args[0].lower() if args else "status")
    methods={
        "status":"txpool_status",
        "content":"txpool_content",
        "pending":"txpool_content",
    }
    method=methods.get(mode)
    if not method:
        return fail("Usage: lk txpool [status|content]")

    result=rpc_json(rpc,method,[])
    if result is None:
        return fail(f"Error: RPC method {method} is unavailable on {rpc}.")

    if mode=="status":
        pending=result.get("pending","?") if isinstance(result,dict) else "?"
        queued=result.get("queued","?") if isinstance(result,dict) else "?"
        print("TXPOOL")
        print(f"  pending: {pending}")
        print(f"  queued:  {queued}")
        return 0

    print(json.dumps(result,indent=2))
    return 0

def run_disasm(config,args):
    values=list(args)
    if not values:
        target=config.get("target")
        if not target:
            return fail("Usage: lk disasm [bytecode|address]")
        values=[run_cast(["code",target],config,capture=True)]
    elif len(values)==1 and is_address(values[0]):
        values=[run_cast(["code",values[0]],config,capture=True)]
    if not values[0] or not str(values[0]).startswith("0x"):
        return fail("Error: no bytecode available.")
    return run_cast(["disassemble",values[0]],config)

def runtime_selector_set(code):
    raw=code if isinstance(code,str) else str(code)
    return set(re.findall(r"(?i)0x[0-9a-f]{8}(?![0-9a-f])",raw))

def run_selector_compare(config,args):
    values=list(args)
    if values and values[0]=="--compare":
        values.pop(0)
    target=config.get("target")
    if not target:
        return fail("Error: Set target first.")
    runtime=values[0] if values else run_cast(["code",target],config,capture=True)
    if not runtime or not str(runtime).startswith("0x"):
        return fail("Error: no runtime bytecode available.")
    _,selector_output,_=cast_output(["cast","selectors",runtime])
    runtime_selectors=runtime_selector_set(selector_output)
    abi=load_abi(target,config)
    abi_map={}
    for item in abi_functions(abi):
        signature=format_signature(item)
        selector=abi_selector(signature)
        if selector:
            abi_map[selector.lower()]=signature
    print("SELECTOR COMPARISON")
    print("===================")
    print("ABI SELECTORS:")
    for selector,signature in sorted(abi_map.items()):
        print(f"  {selector}  {signature}")
    print("\nRUNTIME SELECTORS:")
    for selector in sorted(runtime_selectors):
        print(f"  {selector}  {abi_map.get(selector,'<not in loaded ABI>')}")
    abi_only=sorted(set(abi_map)-runtime_selectors)
    runtime_only=sorted(runtime_selectors-set(abi_map))
    print("\nABI-ONLY:")
    for selector in abi_only:
        print(f"  {selector}  {abi_map[selector]}")
    if not abi_only:
        print("  none")
    print("\nRUNTIME-ONLY:")
    for selector in runtime_only:
        print(f"  {selector}")
    if not runtime_only:
        print("  none")
    print("\nReview note: selector extraction is a lead, not proof of hidden functionality.")
    return 0

def run_chisel(args):
    return run_tool("chisel",args)

def run_fuzz(args):
    values=list(args)
    mode=values.pop(0) if values and not values[0].startswith("-") else None
    if mode in {"replay","rerun"}:
        print("Replaying persisted Forge test failures...")
        return run_foundry(["test","--rerun",*values])
    if mode in {"failures","corpus"}:
        roots=[
            os.path.expanduser("~/.foundry/cache/fuzz/failures"),
            os.path.expanduser("~/.foundry/cache/invariant/failures"),
            os.path.expanduser("~/.foundry/cache/test-failures"),
        ]
        found=0
        for root in roots:
            if os.path.exists(root):
                print(f"\n{root}")
                if os.path.isdir(root):
                    entries=sorted(os.path.relpath(p,root) for p in Path(root).rglob("*") if p.is_file())
                    for entry in entries[:100]:
                        print(f"  {entry}")
                        found+=1
                else:
                    print("  present")
                    found+=1
        if not found:
            print("No persisted Forge failure/corpus files found.")
        return 0
    if mode=="watch":
        return run_foundry(["test","--watch",*values])
    print("Running Forge fuzz/test campaign. Fuzz tests are discovered by Forge itself.")
    return run_foundry(["test",*values])

def run_invariant(config,args):
    values=list(args)
    if values and values[0]=="new":
        if len(values)<2:
            return fail("Usage: lk invariant new <ContractName>")
        contract=values[1]
        target=config.get("target") or "0x" + "0"*40
        target_literal=solidity_address_literal(target) if is_address(target) else "address(0)"
        body=f'''// Generated by LowkeyCast.
pragma solidity ^0.8.20;

import {{Test}} from "forge-std/Test.sol";

contract Invariant_{solidity_identifier(contract)} is Test {{
    address constant TARGET = {target_literal};

    function invariant_target_code_stable() public view {{
        if (TARGET != address(0)) {{
            assertGt(TARGET.code.length, 0);
        }}
    }}
}}
'''
        path=write_generated_test("invariant_"+contract,body)
        code=run_foundry(["test","--match-path",Path(path).as_posix()])
        if code==0:
            print("Invariant starter compiles. Edit it to add handlers and protocol invariants.")
        return code
    match_present=any(values[index]=="--match-test" for index in range(len(values)))
    if not match_present:
        values=["--match-test","invariant_.*",*values]
    print("Running Forge invariant-focused tests...")
    return run_foundry(["test",*values])

def run_mutate(args):
    print("Running native Foundry mutation testing.")
    return run_foundry(["test","--mutate",*args])

def run_symbolic(args):
    values=list(args)
    emit=False
    if values and values[0]=="emit":
        values.pop(0)
        emit=True
    if emit and "--emit-regression" not in values:
        values.append("--emit-regression")
    print("Running native Foundry symbolic testing.")
    return run_foundry(["test","--symbolic",*values])


def run_cheatcodes(args):
    snippets = {
        "prank": 'vm.prank(alice);\\ntarget.withdraw();',
        "start-prank": 'vm.startPrank(attacker);\\n...\\nvm.stopPrank();',
        "deal": 'vm.deal(attacker, 100 ether);',
        "warp": 'vm.warp(block.timestamp + 7 days);',
        "roll": 'vm.roll(block.number + 100);',
        "store": 'vm.store(address(target), bytes32(uint256(slot)), bytes32(value));',
        "load": 'bytes32 raw = vm.load(address(target), bytes32(uint256(slot)));',
        "etch": 'vm.etch(address(dependency), maliciousCode);',
        "mock": 'vm.mockCall(address(oracle), abi.encodeWithSignature("getPrice()"), abi.encode(0));',
        "state-diff": 'vm.startStateDiffRecording();\\n...\\nVm.AccountAccess[] memory d = vm.stopAndReturnStateDiff();',
        "ffi": 'vm.ffi(cmds); // LAB ONLY: executes an external process',
    }
    if not args or args[0] in {"list","help"}:
        print("Lowkey cheatcode lab")
        print("====================")
        for name in snippets:
            suffix="  [LAB ONLY]" if name=="ffi" else ""
            print(f"  {name:<11}{suffix}")
        print("\\nUse: lk cheatcode <name>")
        return 0
    name=args[0].lower()
    if name not in snippets:
        return fail(f"Error: unknown cheatcode '{name}'. Use lk cheatcodes.")
    print(f"CHEATCODE: {name}")
    print(snippets[name])
    if name=="ffi":
        print("Warning: vm.ffi executes an external command from the test environment.")
    return 0

def run_brutalize(args):
    print("Running Foundry brutalize testing.")
    print("Foundry may corrupt selected inputs to exercise assumptions around calldata/state handling.")
    return run_foundry(["test","--brutalize",*args])

def run_fuzz_help():
    print("""Lowkey LAB testing:
  lk fuzz                    Run Forge tests (including fuzz tests)
  lk fuzz --fuzz-runs N      Set Forge fuzz iterations
  lk fuzz replay             Replay persisted failures
  lk fuzz failures            Show persisted fuzz/invariant failure artifacts
  lk invariant                Run invariant_* tests
  lk invariant new <Contract> Generate a compiling invariant starter
  lk mutate                   Run Forge mutation testing
  lk symbolic                 Run Forge symbolic testing
  lk symbolic emit            Ask Forge to emit regression cases
""")

def run_selectors(config,args):
    if "--compare" in args:
        return run_selector_compare(config,args)
    code=args[0] if args else run_cast(["code",config.get("target")],config,capture=True)
    if not code or not str(code).startswith("0x"):
        return fail("Error: no runtime bytecode available.")
    return run_cast(["selectors",code],config)

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

def run_seams(config):
    target=config.get("target")
    if not target:
        return fail("Error: Set target first.")
    abi=load_abi(target,config)
    funcs=abi_functions(abi)
    if not funcs:
        return fail("Error: No ABI functions loaded for the current target.")

    print("AUDIT SEAMS / HOTSPOTS")
    print("======================")
    print("Heuristic cross-surface leads. Treat these as places to investigate, not findings.")

    for item in funcs:
        name=item.get("name","<anonymous>")
        signature=format_signature(item)
        signals=[]
        mutable=item.get("stateMutability") not in {"view","pure"}
        payable=item.get("stateMutability")=="payable"
        address_input=any(canonical_type(p).startswith("address") for p in item.get("inputs",[]))
        asset_name=any(token in name.lower() for token in ("withdraw","transfer","send","execute","mint","burn","sweep","claim","release"))
        auth_name=any(token in name.lower() for token in ("owner","admin","role","authorize","pause","upgrade"))
        callbackish=any(token in name.lower() for token in ("call","callback","execute","hook","flash"))
        if mutable and address_input:
            signals.append("state-write + address input")
        if mutable and asset_name:
            signals.append("state-write + asset/value flow")
        if mutable and payable:
            signals.append("state-write + payable")
        if auth_name and mutable:
            signals.append("authorization + state transition")
        if callbackish and mutable:
            signals.append("external/callback surface + state transition")
        if item.get("inputs") and any(canonical_type(p).startswith(("bytes","tuple","string")) for p in item.get("inputs",[])):
            signals.append("complex user-controlled data")
        if signals:
            print(f"\n{signature}")
            for signal in signals:
                print(f"  - {signal}")
    print("\nSEAM CHECKLIST")
    print("  authorization ↔ state transition")
    print("  external call ↔ accounting")
    print("  callback ↔ reentrancy")
    print("  token/oracle read ↔ value decision")
    print("  proxy/implementation ↔ storage layout")
    print("  user input ↔ numeric/encoding assumptions")
    return 0

def run_risk(config):
    target=config.get("target")
    if not target:
        return fail("Error: Set target first.")
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
        return fail("Usage: lk gas <function> [args]")
    target=config.get("target")
    if not target:
        return fail("Error: Set target first.")
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


def _signal_evidence(signal):
    evidence = signal.get("evidence", []) if isinstance(signal, dict) else []
    return [item for item in evidence if isinstance(item, dict)] if isinstance(evidence, list) else []

def _render_signal_evidence(signal, prefix="   "):
    evidence = _signal_evidence(signal)
    if not evidence:
        return
    print(f"\n{prefix}Evidence ({len(evidence)}):")
    for index, item in enumerate(evidence, 1):
        kind = str(item.get("kind") or "evidence").replace("-", " ").title()
        function = item.get("function") or "unknown function"
        success = item.get("success")
        status = "SUCCESS" if success else "REVERTED" if success is False else "UNKNOWN"
        print(f"{prefix}  {index}. {kind} — {function} — {status}")
        caller = item.get("caller") or item.get("actor")
        if caller:
            print(f"{prefix}     Caller      : {caller}")
        if item.get("eth_sent_wei") is not None:
            try:
                wei = int(item.get("eth_sent_wei"))
                rendered = f"{wei / 10**18:g} ETH" if wei % 10**18 == 0 else f"{wei} wei"
                print(f"{prefix}     ETH sent    : {rendered}")
            except (TypeError, ValueError):
                print(f"{prefix}     ETH sent    : {item.get('eth_sent_wei')}")
        if item.get("gas") is not None:
            print(f"{prefix}     Gas         : {item.get('gas')}")
        changes = item.get("storage_changes", [])
        if not isinstance(changes, list) or not changes:
            print(f"{prefix}     Storage     : no changed slots")
            continue
        print(f"{prefix}     Storage     : {len(changes)} changed slot(s)")
        for change in changes:
            label = change.get("label") or f"slot {change.get('slot', 'unknown')}"
            before = change.get("from_display", change.get("from", "unknown"))
            after = change.get("to_display", change.get("to", "unknown"))
            slot = change.get("slot", "unknown")
            print(f"{prefix}       {label}")
            print(f"{prefix}         {before}  ->  {after}")
            print(f"{prefix}         slot: {slot}")

def run_investigate(config, args):
    root = audit_context.foundry_project_root()
    if not args or args[0].lower() in {"help", "-h", "--help"}:
        print("Usage: lk focus <SIGNAL_ID>")
        print("Focus one audit finding and mark it as investigating.")
        print("Use: lk findings to list signal IDs.")
        return 0

    if args[0].lower() == "clear":
        context = audit_context.load(root)
        context["focus"] = None
        audit_context.save(context, root)
        audit_context.emit("focus-cleared", root, tool="lowkey", summary="investigation focus cleared")
        print("Investigation focus cleared.")
        return 0

    signal = audit_context.set_focus(args[0], root)
    if not signal:
        return fail(f"Error: signal '{args[0]}' was not found.")

    print("LOWKEY INVESTIGATION FOCUS")
    print("==========================")
    print(f"Signal     : {signal.get('id')}")
    print(f"Issue      : {signal.get('title')}")
    print(f"Impact     : {signal.get('impact', 'Unknown')}")
    print(f"Confidence : {signal.get('confidence', 'Unknown')}")
    print(f"Location   : {audit_context.source_link(signal.get('file'), signal.get('line'), signal.get('column'), root)}")
    if signal.get("function"):
        print(f"Function   : {signal.get('function')}")
    if signal.get("description"):
        print(f"Observed   : {signal.get('description')}")
    if signal.get("meaning"):
        print(f"Meaning    : {signal.get('meaning')}")
    if signal.get("why"):
        print(f"Why        : {signal.get('why')}")
    if signal.get("next"):
        print(f"Next move  : {signal.get('next')}")
    actions = signal.get("actions", [])
    if isinstance(actions, list) and actions:
        print("Suggested  : " + " -> ".join(str(item) for item in actions))

    _render_signal_evidence(signal)
    print("\nUseful commands:")
    function = signal.get("function")
    if function:
        print(f"  lk fn {function}")
        print(f"  lk ask {function}")
        print(f"  lk changes {function}")
        print("  lk trace")
        print(f"  lk generate test {function} ...")
    print("  lk findings")
    print("  lk context")
    return 0

def _sync_audit_context(config, root=None):
    root = root or audit_context.foundry_project_root()
    existing = audit_context.load(root)
    existing_target = project_context_target(root) or {}
    target = dict(existing_target)

    # Project-local target memory wins. A global target from another Foundry
    # project must never leak into this context.
    if not target:
        global_target = active_project_target(config, root)
        if global_target:
            target = {
                "address": global_target,
                "contract": config.get("target_contract"),
                "artifact": config.get("abi_paths", {}).get(global_target),
                "source": "legacy-global",
            }
        else:
            # Clear stale target fields left by older Lowkey versions. The context updater
            # merges nested dictionaries, so explicit nulls prevent a target from another
            # Foundry project leaking into the current project.
            target = {
                "address": None,
                "contract": None,
                "artifact": None,
                "source": "project-auto",
            }

    actor = actor_display(config)
    if actor == "none":
        actor = existing.get("actor")

    rpc = effective_rpc(config) or existing.get("rpc")
    latest = dict(existing.get("latest", {}))
    if config.get("last_tx"):
        latest["tx_hash"] = config.get("last_tx")

    return audit_context.update(
        root,
        target=target,
        actor=actor,
        rpc=rpc,
        latest=latest,
    )


def run_audit(config, args):
    if args and args[0].lower() in {"help", "-h", "--help"}:
        print("Usage: lk audit")
        print("Build, static-scan, test, and measure the current Foundry project.")
        return 0

    root = audit_context.foundry_project_root()
    _sync_audit_context(config, root)

    try:
        from forge_tools import run_audit as run_forge_audit
    except ImportError as exc:
        return fail(f"Error: Lowkey Forge audit layer unavailable: {exc}")

    # Keep one owner for the audit presentation so the output is not duplicated.
    forge_args = list(args)
    if "--checks" not in forge_args:
        forge_args.insert(0, "--checks")
    return_code = run_forge_audit(forge_args)

    audit_context.record_tool(
        "audit",
        root,
        status="completed" if return_code == 0 else "failed",
        summary="connected audit pipeline",
        data={"exit_code": return_code},
    )
    return return_code

def run_context(config):
    root = audit_context.foundry_project_root()
    _sync_audit_context(config, root)
    print("LOWKEY AUDIT CONTEXT")
    print("====================")
    print(audit_context.human_snapshot(root))
    print(f"Context : {audit_context.context_path(root)}")
    print(f"Events  : {audit_context.events_path(root)}")

def run_signals(config, args):
    root = audit_context.foundry_project_root()

    if args and args[0].lower() in {"set", "status"}:
        if len(args) < 3:
            return fail("Usage: lk signals set <SIGNAL_ID> <open|investigating|proven|dismissed> [note]")
        signal_id = args[1]
        status = args[2].lower()
        note = " ".join(args[3:]) if len(args) > 3 else None
        try:
            signal = audit_context.update_signal_status(signal_id, status, root, note=note)
        except ValueError as error:
            return fail(f"Error: {error}")
        if not signal:
            return fail(f"Error: signal '{signal_id}' was not found.")
        print(f"Signal updated: {signal_id} -> {status}")
        return 0

    requested = args[0].lower() if args else "open"
    status = requested if requested in {"open", "closed", "all", "investigating", "proven", "dismissed"} else "open"
    selected = audit_context.signals(root, None if status == "all" else status)

    print("LOWKEY AUDIT SIGNALS")
    print("====================")
    if not selected:
        print(f"No {status} audit signals recorded.")
        return 0

    for index, signal in enumerate(selected, 1):
        location = audit_context.source_link(
            signal.get("file"),
            signal.get("line"),
            signal.get("column"),
            root,
        )

        print(f"\n{index}. {signal.get('title') or 'Audit signal'}")
        print(f"   ID         : {signal.get('id')}")
        print(f"   Source     : {signal.get('tool')}")
        print(f"   Impact     : {signal.get('impact', 'Unknown')}")
        print(f"   Confidence : {signal.get('confidence', 'Unknown')}")
        print(f"   Location   : {location}")
        if signal.get("description"):
            print(f"   Observation: {signal['description']}")
        if signal.get("next"):
            print(f"   Next       : {signal['next']}")
        if signal.get("triage_note"):
            print(f"   Note       : {signal['triage_note']}")
        print(f"   Status     : {signal.get('status', 'open')}")
        evidence = _signal_evidence(signal)
        if evidence:
            print(f"   Evidence   : {len(evidence)} captured")
            _render_signal_evidence(signal, prefix="      ")
    return 0

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
    abi=resolve_abi_path(config,target) if target else None
    contract=config.get("target_contract") or "unknown"
    print(f"ABI    : {abi or 'auto/not found'}")
    print(f"Contract: {contract}")
    print(f"Last tx: {config.get('last_tx') or 'none'}")
    root = audit_context.foundry_project_root()
    context = audit_context.load(root)
    open_signals = len(audit_context.signals(root, "open"))
    print(f"Signals: {open_signals} open")
    focus = context.get("focus")
    if isinstance(focus, dict) and focus.get("signal_id"):
        print(f"Focus  : {focus.get('signal_id')} — {focus.get('title') or 'audit signal'}")
    for tool_name in ("slither", "forge", "generator"):
        state = context.get("tools", {}).get(tool_name, {})
        if isinstance(state, dict) and state.get("status"):
            print(f"{tool_name.capitalize():<8}: {state.get('status')}" + (f" — {state.get('summary')}" if state.get("summary") else ""))
def run_wizard(config,args):
    if not args:
        return fail("Usage: lk wizard <function> [call|send|encode]")
    mode=args[1].lower() if len(args)>1 else "call"
    if mode not in {"call","send","encode"}:
        return fail("Mode must be call, send, or encode.")
    target=config.get("target")
    if not target:
        return fail("Error: Set target first.")
    funcs=abi_functions(load_abi(target,config))
    matches=matching_functions(funcs,args[0])
    if len(matches)!=1:
        return fail("Error: Function must resolve to exactly one ABI entry.")
        for item in sorted(funcs,key=lambda x:function_score(x,args[0]),reverse=True)[:8]:
            print(" ",format_signature(item))
        return
    item=matches[0]; signature=format_signature(item); values=[]
    print(f"Function: {signature}")
    for index,param in enumerate(item.get("inputs",[]),1):
        label=param.get("name") or f"arg{index}"
        try: value=input(f"{label} ({canonical_type(param)}): ").strip()
        except EOFError: print("Wizard cancelled."); return 0
        if not value:
            return fail("Argument values are required.")
        values.append(value)
    if mode=="encode": run_cast(["calldata",signature,*values],config)
    elif mode=="send": run_cast(["send",signature,*values,"--confirm"],config)
    else: run_cast(["call",signature,*values],config)



def run_impersonate(config,args):
    if not args or not is_address(args[0]):
        return fail("Usage: lk impersonate <address> [name]")
    address=args[0]
    name=args[1] if len(args)>1 else f"actor_{address[-6:]}"
    rpc=effective_rpc(config)
    info=anvil_rpc_info(config)
    if not rpc or not info:
        return fail("Error: an Anvil RPC is required for impersonation.")
    if assigned_anvil_address(config,address) and assigned_anvil_address(config,address)!=name:
        return fail(f"Error: address {address} is already assigned to '{assigned_anvil_address(config,address)}'.")
    result=run_cast(["rpc","anvil_impersonateAccount",address],config,capture=True)
    if result.code!=0:
        return fail(f"Error: Anvil impersonation failed: {result.text or 'unknown error'}", result.code or 1)
    config.setdefault("wallets",{})[name]={
        "source":"anvil-impersonated",
        "address":address,
    }
    config["actor"]=name
    config.setdefault("labels",{})[address]=name
    save_config(config)
    print(f"Actor selected: {name} -> impersonated {address}")
    return 0

def run_as(config,args):
    if len(args)<2:
        return fail("Usage: lk as <actor> <command> [args...]")
    actor=args[0]
    if actor not in config.get("wallets",{}):
        return fail(f"Error: unknown actor '{actor}'. Use lk actor to list actors.")
    if args[1]=="as":
        return fail("Error: nested actor switching is not supported.")
    previous=config.get("actor")
    config["actor"]=actor
    try:
        return dispatch_command(args[1],args[2:],config,from_batch=True)
    finally:
        config["actor"]=previous

def run_replay(config,args):
    if not args:
        print("Usage: lk replay <transaction-hash> [trace flags...]"); return
    run_trace(config,args)

def fork_state():
    return read_json_file(FORK_FILE,{}) if os.path.exists(FORK_FILE) else {}

def fork_running(state):
    pid=state.get("pid")
    if not isinstance(pid,int):
        return False
    try:
        os.kill(pid,0)
        return True
    except OSError:
        return False


def run_fork_state(config,args):
    if not args or args[0] in {"help","-h","--help"}:
        print("Usage: lk fork dump [file] | lk fork load <file>")
        return 0
    rpc=effective_rpc(config)
    if not rpc or not anvil_rpc_info(config):
        return fail("Error: a running Anvil RPC is required.")
    action=args[0]
    if action=="dump":
        path=os.path.expanduser(args[1] if len(args)>1 else "anvil-state.json")
        state=rpc_json(rpc,"anvil_dumpState",[])
        if not isinstance(state,str):
            return fail("Error: Anvil did not return a state snapshot.")
        Path(path).write_text(state,encoding="utf-8")
        print(f"Anvil state dumped: {path}")
        return 0
    if action=="load":
        if len(args)!=2:
            return fail("Usage: lk fork load <file>")
        path=os.path.expanduser(args[1])
        if not os.path.exists(path):
            return fail(f"Error: state file not found: {path}")
        try:
            state=Path(path).read_text(encoding="utf-8").strip()
        except OSError as error:
            return fail(f"Error reading state file: {error}")
        if not re.fullmatch(r"0x[0-9a-fA-F]+",state):
            return fail("Error: state file does not contain an Anvil hex snapshot.")
        result=rpc_json(rpc,"anvil_loadState",[state])
        if result is not True:
            return fail("Error: Anvil rejected the state snapshot.")
        print(f"Anvil state loaded: {path}")
        return 0
    return fail("Usage: lk fork dump [file] | lk fork load <file>")

def run_fork(args, config=None):
    config=config or load_config()
    values=list(args)
    if not values:
        return fail("Usage: lk fork <rpc-url> [block] [--port PORT] | lk fork status | lk fork stop")
    if values[0] in {"dump","load"}:
        return run_fork_state(config,values)
    if values[0]=="status":
        state=fork_state()
        if state and fork_running(state):
            print(f"Fork: running (PID {state.get('pid')})")
            print(f"RPC:  {state.get('local_rpc','unknown')}")
            if state.get("block"):
                print(f"Block: {state['block']}")
            return 0
        print("Fork: stopped")
        return 0
    if values[0]=="stop":
        state=fork_state()
        pid=state.get("pid")
        if isinstance(pid,int) and fork_running(state):
            try:
                os.kill(pid,15)
            except OSError:
                pass
            print(f"Fork stopped (PID {pid}).")
        else:
            print("Fork is not running.")
        try:
            os.remove(FORK_FILE)
        except OSError:
            pass
        if config.get("rpc")==state.get("local_rpc"):
            config["rpc"]=None
            save_config(config)
        return 0
    rpc=values.pop(0)
    block=None
    port=8546
    index=0
    extra=[]
    while index<len(values):
        token=values[index]
        if token=="--port":
            if index+1>=len(values):
                return fail("Usage: lk fork <rpc-url> [block] [--port PORT]")
            try: port=int(values[index+1])
            except ValueError: return fail("Error: fork port must be a number.")
            index+=2; continue
        if block is None and not token.startswith("-"):
            block=token; index+=1; continue
        extra.append(token); index+=1
    if fork_running(fork_state()):
        return fail("Error: a Lowkey fork is already running. Use lk fork stop first.")
    if not tool_path("anvil"):
        return fail("Error: anvil was not found on PATH. Install Foundry first.")
    if local_port_open("127.0.0.1",port):
        return fail(f"Error: port {port} is already in use.")
    command=["anvil","--fork-url",rpc,"--port",str(port),"--auto-impersonate","--silent"]
    if block is not None:
        command.extend(["--fork-block-number",block])
    command.extend(extra)
    log_path=os.path.join(AUDIT_DIR,"fork.log")
    os.makedirs(AUDIT_DIR,exist_ok=True)
    try:
        with open(log_path,"a",encoding="utf-8") as log:
            process=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
    except (OSError,ValueError) as error:
        return fail(f"Error starting fork: {error}",1)
    for _ in range(30):
        if rpc_json(f"http://127.0.0.1:{port}","eth_chainId",[]):
            break
        if process.poll() is not None:
            return fail(f"Error: fork exited early. See {log_path}.")
        import time
        time.sleep(0.1)
    else:
        try: process.terminate()
        except OSError: pass
        return fail(f"Error: fork did not become ready. See {log_path}.")
    state={"pid":process.pid,"local_rpc":f"http://127.0.0.1:{port}","block":block,"started":datetime.now().isoformat(timespec="seconds")}
    Path(FORK_FILE).write_text(json.dumps(state,indent=4),encoding="utf-8")
    config["rpc"]=state["local_rpc"]
    save_config(config)
    print(f"Fork started: {state['local_rpc']}")
    if block is not None:
        print(f"Fork block: {block}")
    print(f"PID: {process.pid}")
    print("Lowkey RPC switched to the local fork.")
    return 0
def print_help():
    print("""
LOWKEY — SMART CONTRACT AUDITOR CONSOLE
=======================================

START
  lk audit                         Run the connected audit pipeline
  lk findings                      Show audit findings
  lk focus <ID>                    Focus one finding and mark it investigating
  lk status                        Show target and audit state
  lk doctor                        Check the toolchain
  lk target <address|name>         Select the contract under review
  lk actor <index> <name>          Name an Anvil account
  lk actor 0 Alice                  Name Anvil account #0 as Alice

UNDERSTAND
  lk recon                         Inspect contract identity and runtime
  lk functions                     List contract functions
  lk fn <name>                     Find a function
  lk ask <function>                Show a function's inputs
  lk layout <Contract>             Show storage layout
  lk risk                          Show review-surface hints
  lk seams                         Show audit hotspots

INTERACT
  lk read <function> [args]         Call without changing state
  lk send <function> [args]         Send a transaction
  lk encode <function> [args]       Build calldata
  lk trace [tx]                     Trace a transaction
  lk logs                           Read contract logs
  lk tx [tx]                        Inspect a transaction

STORAGE
  lk mapping <slot> <key>            Calculate and read a mapping slot
  lk snapshot [slots]                Save storage values
  lk diff                            Compare saved storage values
  lk changes <function> [args]       Show storage changes from a call

TEST / REPRODUCE
  lk probe <function> [args]         Try a call without assertions
  lk test-gen                        Turn the last send into a Forge test
  lk fuzz                            Run Forge fuzz tests
  lk invariant                       Run Forge invariant tests
  lk symbolic                        Run Forge symbolic tests
  lk mutate                          Run Forge mutation testing
  lk brutalize                       Stress calldata/state assumptions
  lk generate test <function> [...]  Generate a reusable Forge test
  lk generate poc <function> [...]   Generate a PoC script
  lk generate deployment <Contract> Generate a deployment script

STATIC ANALYSIS
  lk slither                        Run Slither and save findings

FORK / ACTORS
  lk fork <rpc> [block]              Start a local fork
  lk impersonate <address> [name]    Act as an existing account
  lk rpc <url>                      Set the RPC endpoint

RAW ACCESS
  lk forge <forge-command> [args]    Use native Forge through LK
  lk raw <cast-command> [args]       Use native Cast through LK

NOTES
  Primary commands are short and self-describing.
  Legacy aliases still work: signals, investigate, try, c, s, state-diff.
  Analyzer results are evidence to investigate, not proof by themselves.
""")

def dispatch_command(cmd,args,config,from_batch=False):
    activate_project_target(config)
    if cmd in {"--h","--help","-h","help"}: print_help()
    elif cmd in {"--version","-V","version"}: print("LowkeyCast 2.1 — Foundry Attack Lab")
    elif cmd=="target":
        root=audit_context.foundry_project_root()
        current=active_project_target(config,root)
        if not args:
            project=project_context_target(root)
            if project:
                print(f"Current project target: {project.get('contract') or 'unknown'} -> {project.get('address')}")
            else:
                print(f"Current project target: {current or 'none'}")
            return
        if args[0]=="reset":
            config["target"]=None
            audit_context.set_target(root, address=None, contract=None, artifact=None, source="project")
        elif args[0]=="list":
            run_targets(config); return
        elif args[0]=="auto":
            return run_auto_target(config,args[1] if len(args)>1 else None)
        elif len(args)==1:
            resolved=resolve_target_ref(config,args[0])
            if resolved:
                config["target"]=resolved
            elif is_address(args[0]):
                config["target"]=args[0]
            else:
                return run_auto_target(config,args[0])
            audit_context.set_target(
                root,
                address=config["target"],
                contract=config.get("target_contract"),
                artifact=config.get("abi_paths",{}).get(config["target"]),
                source="manual",
            )
        elif len(args)==2 and is_address(args[1]):
            config["aliases"][args[0]]=args[1]
            config["targets"][args[0]]=args[1]
            config["target"]=args[1]
            config["target_contract"]=args[0]
            audit_context.set_target(
                root,
                address=args[1],
                contract=args[0],
                artifact=config.get("abi_paths",{}).get(args[1]),
                source="manual",
            )
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
            remember_abi_path(config,target,path)
            config["target_contract"]=artifact_contract_name(path,read_artifact(path))
            save_config(config)
            config.pop("_config_dirty",None)
            print(f"ABI override saved: {path}")
    elif cmd in {"read"}:
        return run_cast(["call",*args],config)
    elif cmd in {"send"}:
        return run_cast(["send",*args],config)
    elif cmd in {"try","probe"}:
        return run_probe(config,args)
    elif cmd in {"changes","state-diff"}:
        return run_state_diff(config,args)
    elif cmd=="functions": run_functions(config,args[0] if args else None)
    elif cmd=="fn": run_functions(config," ".join(args) if args else None)
    elif cmd=="wizard": run_wizard(config,args)
    elif cmd=="replay": run_replay(config,args)
    elif cmd=="fork": return run_fork(args,config)
    elif cmd=="ask":
        if not args: return fail("Usage: lk ask <function>")
        query=args[0]
        root=audit_context.foundry_project_root()
        target=active_project_target(config,root)
        funcs=abi_functions(load_abi(target,config)) if target else []
        if not funcs:
            artifact_matches=project_artifact_function_matches(root,query)
            if not artifact_matches:
                return fail(f"Error: no built-project function matched '{query}'. Run 'forge build' first.")
            print(f"Built-project function matches for '{query}':")
            for contract,signature,path in artifact_matches[:8]:
                print(f"  {contract}::{signature}")
            print("Use a deployed project target when you need live-chain details.")
            return 0
        matches=matching_functions(funcs,query)
        if len(matches)!=1:
            for item in sorted(funcs,key=lambda x:function_score(x,query),reverse=True)[:8]:
                print(" ",format_signature(item))
        else:
            item=matches[0]
            print(f"Function: {format_signature(item)}")
            for index,param in enumerate(item.get("inputs",[]),1):
                print(f"  arg{index}: {param.get('name') or 'arg'+str(index)} : {canonical_type(param)}")
    elif cmd=="info": run_info(config)
    elif cmd=="status": run_status(config)
    elif cmd=="audit": return run_audit(config,args)
    elif cmd=="context": return run_context(config)
    elif cmd in {"focus", "investigate", "investigation"}: return run_investigate(config,args)
    elif cmd in {"findings", "signals", "signal"}: return run_signals(config,args)
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
    elif cmd=="selectors": return run_selectors(config,args)
    elif cmd=="calldata": return run_calldata(config,args)
    elif cmd in {"4byte","4byte-calldata","4byte-event","access-list","interface","constructor-args","creation-code","decode-calldata","abi-encode"}: return run_cast_deep(config,[cmd,*args])
    elif cmd=="disasm": return run_disasm(config,args)
    elif cmd=="txpool": return run_txpool(config,args)
    elif cmd=="chisel": return run_chisel(args)
    elif cmd in {"state-diff","statediff","state_diff"}: return run_state_diff(config,args)
    elif cmd=="as": return run_as(config,args)
    elif cmd in {"impersonate","impersonate-actor"}: return run_impersonate(config,args)
    elif cmd=="fuzz": return run_fuzz(args)
    elif cmd=="invariant": return run_invariant(config,args)
    elif cmd=="mutate": return run_mutate(args)
    elif cmd=="symbolic": return run_symbolic(args)
    elif cmd=="brutalize": return run_brutalize(args)
    elif cmd in {"cheatcodes","cheatcode"}: return run_cheatcodes(args)
    elif cmd in {"actors","actor-list"}: return list_anvil_actors(config)
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
    elif cmd in {"seams","hotspots"}: return run_seams(config)
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
    root = audit_context.foundry_project_root()
    _sync_audit_context(config, root)
    if len(sys.argv)<2: print_help(); return
    result=dispatch_command(sys.argv[1],sys.argv[2:],config)
    if config.pop("_config_dirty",False):
        save_config(config)
    _sync_audit_context(config, root)
    audit_context.emit(
        "lk-command",
        root,
        tool="lk",
        status="completed" if (not isinstance(result,int) or result == 0) else "failed",
        summary=sys.argv[1],
        data={"command": sys.argv[1], "exit_code": result if isinstance(result,int) else 0},
    )
    if isinstance(result,int): raise SystemExit(result)
    if _COMMAND_STATUS: raise SystemExit(_COMMAND_STATUS)

if __name__ == "__main__":
    main()
