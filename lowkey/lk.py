import hashlib
import os
import json
import signal
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
import walkthrough
try:
    import question_engine
except ImportError:
    question_engine = None
try:
    import bootstrap as bootstrap_engine
except ImportError:
    bootstrap_engine = None

try:
    from project_detection import (
        detect_project,
        format_detection,
        project_root as detected_project_root,
        run_native_audit,
        discover_nested_projects,
        is_workspace_root,
        workspace_root,
        workspace_selection,
        set_workspace_selection,
        clear_workspace_selection,
        workspace_context,
        bootstrap_project,
        bootstrap_status,
        classify_build_failure,
        project_build_command,
        project_test_command,
        runtime_environment,
        command_uses_node,
        node_runtime_status,
        _is_lowkey_source_checkout,
    )
except ImportError:
    detect_project = format_detection = run_native_audit = None
    discover_nested_projects = is_workspace_root = workspace_root = None
    workspace_selection = set_workspace_selection = clear_workspace_selection = None
    bootstrap_project = None
    bootstrap_status = classify_build_failure = project_build_command = project_test_command = None
    runtime_environment = command_uses_node = node_runtime_status = None
    _is_lowkey_source_checkout = None
    detected_project_root = lambda start=".": Path(start).resolve()

try:
    from analysis_adapters import is_dependency_path as universal_is_dependency_path
except ImportError:
    universal_is_dependency_path = None

try:
    import system_model
except ImportError:
    system_model = None

try:
    import project_tools
except ImportError:
    project_tools = None

try:
    import solidity_cheatsheet
except ImportError:
    solidity_cheatsheet = None

try:
    import benchmark
except ImportError:
    benchmark = None

try:
    from audit_engine import run_rg as audit_run_rg, run_slither as audit_run_slither, run_audit_pipeline as audit_run_pipeline, generate_poc as audit_generate_poc, run_source_triage as audit_run_source_triage
except ImportError:
    audit_run_rg = audit_run_slither = audit_run_pipeline = audit_generate_poc = None

try:
    import break_engine
except (ImportError, SyntaxError):
    # Keep read-only/recon commands usable when an unrelated break-engine
    # checkout is temporarily syntactically invalid. Commands that need the
    # break engine will report that it is unavailable.
    break_engine = None

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
INSTALL_MANIFEST = os.path.join(CONFIG_DIR, "install-manifest.json")
INSTALL_MANIFEST = os.path.join(CONFIG_DIR, "install-manifest.json")

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
    """Detect stale/corrupted installed Lowkey files without mutating them."""
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

def rpc_json_ok(url, method, params=None):
    """Execute a JSON-RPC mutation and distinguish success-with-null from an RPC error."""
    if not url:
        return False, "RPC URL is not configured"
    try:
        payload=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params or []}).encode()
        req=urllib_request.Request(url, data=payload, headers={"Content-Type":"application/json"})
        with urllib_request.urlopen(req, timeout=2.0) as response:
            body=json.loads(response.read().decode("utf-8"))
        if not isinstance(body, dict):
            return False, "RPC returned a non-object response"
        error = body.get("error")
        if error is not None:
            if isinstance(error, dict):
                detail = error.get("message") or str(error)
            else:
                detail = str(error)
            return False, detail
        # JSON-RPC methods such as eth_sendTransaction/anvil_setCode may
        # legitimately return result:null on success. Presence of no error is
        # the success condition; do not interpret null as failure.
        return True, body.get("result")
    except Exception as exc:
        return False, str(exc)

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

INTERNAL_WALLET_NAMES = {'lab-deployer', 'lowkey'}

def wallet_is_internal(name, entry):
    return (
        str(name or '').lower() in INTERNAL_WALLET_NAMES
        or (isinstance(entry, dict) and bool(entry.get('internal')))
    )

def wallet_entry_kind(entry):
    if isinstance(entry,dict):
        if entry.get('source') == 'anvil-default': return f"anvil #{entry.get('anvil_index','?')}"
        if entry.get('env'): return 'env'
        if entry.get('private_key'): return 'key'
    return 'key'

def assigned_anvil_index(config,index):
    for name,entry in config.get('wallets',{}).items():
        if wallet_is_internal(name, entry):
            continue
        if isinstance(entry,dict) and entry.get('source')=='anvil-default' and str(entry.get('anvil_index'))==str(index):
            return name
    return None

def assigned_anvil_address(config,address):
    for name,entry in config.get('wallets',{}).items():
        if wallet_is_internal(name, entry):
            continue
        if isinstance(entry,dict) and str(entry.get('address','')).lower()==str(address).lower():
            return name
    return None

def _ensure_lab_deployer(config, address, index=0):
    '''Keep the deployment signer separate from user-facing actor profiles.'''
    address = str(address or '')
    current = config.get('actor')
    public_same_address = None
    for name, entry in (config.get('wallets', {}) or {}).items():
        if wallet_is_internal(name, entry) or not isinstance(entry, dict):
            continue
        if str(entry.get('address', '')).lower() == address.lower():
            public_same_address = name
            break
    config.setdefault('wallets', {})['lab-deployer'] = {
        'source': 'anvil-default',
        'anvil_index': int(index),
        'address': address,
        'internal': True,
    }
    if config.get('labels', {}).get(address) == 'lab-deployer':
        config['labels'].pop(address, None)
    if config.get('labels', {}).get(address.lower()) == 'lab-deployer':
        config['labels'].pop(address.lower(), None)
    current_entry = config.get('wallets', {}).get(current) if current else None
    if (
        not current
        or not isinstance(current_entry, dict)
        or wallet_is_internal(current, current_entry)
    ):
        config['actor'] = public_same_address or 'lab-deployer'
    return public_same_address

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
    for internal_name, internal_entry in list(config.get("wallets", {}).items()):
        if (
            wallet_is_internal(internal_name, internal_entry)
            and isinstance(internal_entry, dict)
            and str(internal_entry.get("source")) == "anvil-default"
            and int(internal_entry.get("anvil_index", -1)) == index
            and str(internal_name) != name
        ):
            config.setdefault("wallets", {}).pop(internal_name, None)
            if config.get("labels", {}).get(address) == internal_name:
                config["labels"].pop(address, None)
    assigned_index=assigned_anvil_index(config,index)
    assigned_address=assigned_anvil_address(config,address)
    if assigned_index and assigned_index!=name:
        previous=config.get("wallets",{}).get(assigned_index)
        replaceable = (
            isinstance(previous,dict)
            and previous.get("source")=="anvil-default"
            and int(previous.get("anvil_index",-1))==index
            and str(assigned_index).lower() in {"lab-deployer","lowkey"}
        )
        if replaceable:
            config.setdefault("wallets",{}).pop(assigned_index,None)
            if assigned_address == assigned_index:
                assigned_address = None
        else:
            return fail(f"Error: Anvil account {index} is already assigned to '{assigned_index}'.")
    if assigned_address and assigned_address!=name:
        previous=config.get("wallets",{}).get(assigned_address)
        replaceable = (
            isinstance(previous,dict)
            and previous.get("source")=="anvil-default"
            and int(previous.get("anvil_index",-1))==index
            and str(assigned_address).lower() in {"lab-deployer","lowkey"}
        )
        if replaceable:
            config.setdefault("wallets",{}).pop(assigned_address,None)
        else:
            return fail(f"Error: address {address} is already assigned to '{assigned_address}'.")
    existing=config.get('wallets',{}).get(name)
    if existing and not wallet_is_internal(name, existing):
        if (
            isinstance(existing, dict)
            and existing.get('source') == 'anvil-default'
            and str(existing.get('anvil_index')) != str(index)
        ):
            old_address = str(existing.get('address') or '')
            config.setdefault('wallets', {}).pop(name, None)
            if old_address and config.get('labels', {}).get(old_address) == name:
                config['labels'].pop(old_address, None)
        elif not (
            isinstance(existing,dict)
            and existing.get('source')=='anvil-default'
            and str(existing.get('anvil_index'))==str(index)
        ):
            return fail(
                f"Error: wallet profile '{name}' uses an explicit key/env and cannot be rebound. "
                "Use a new actor name or remove that profile first."
            )
    elif existing and wallet_is_internal(name, existing):
        return fail(f"Error: '{name}' is reserved for Lowkey's internal deployment signer.")
    config.setdefault('wallets',{})[name]={
        'source':'anvil-default',
        'anvil_index':index,
        'address':address,
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

def target_aliases(config, root=None):
    """Return targets owned by the current project, never another project's targets."""
    merged={}
    project_root = Path(audit_context.foundry_project_root(root)).resolve()
    roots = config.get("project_roots", {})
    if not isinstance(roots, dict):
        roots = {}

    owners_by_address = {}
    for address, owner in roots.items():
        if not is_address(address) or not owner:
            continue
        try:
            owner_root = Path(os.path.expanduser(str(owner))).resolve()
        except OSError:
            continue
        owners_by_address[str(address).lower()] = owner_root

    names = list(config.get("aliases", {}).items()) + list(config.get("targets", {}).items())
    for name, addr in names:
        if not is_address(addr):
            continue
        owner_root = owners_by_address.get(str(addr).lower())

        artifact = config.get("abi_paths", {}).get(addr)
        # Older configs may not have project_roots yet. When ownership is
        # unknown, only admit the alias if its artifact independently proves
        # that the target belongs to this project.
        if owner_root is None:
            try:
                artifact_path = Path(os.path.expanduser(str(artifact))).resolve() if artifact else None
            except OSError:
                artifact_path = None
            artifact_data = read_artifact(str(artifact_path)) if artifact_path and artifact_path.is_file() else None
            if not artifact_data:
                # Legacy configs often only have aliases. Recover ownership from
                # the alias name and a first-party artifact in this project.
                alias_name = str(name).strip().lower()
                for candidate in local_artifact_paths(project_root):
                    candidate_data = read_artifact(candidate) or {}
                    if artifact_contract_name(candidate, candidate_data).strip().lower() == alias_name:
                        artifact_path = Path(candidate).resolve()
                        artifact_data = candidate_data
                        break
            if not artifact_data or not artifact_is_project_application(project_root, str(artifact_path), artifact_data):
                continue
        elif owner_root != project_root:
            continue
        if artifact:
            try:
                artifact_path = Path(os.path.expanduser(str(artifact))).resolve()
            except OSError:
                continue
            artifact_data = read_artifact(str(artifact_path)) if artifact_path.is_file() else None
            if artifact_data and not artifact_is_project_application(project_root, str(artifact_path), artifact_data):
                continue

        lowered_name = str(name).lower()
        if lowered_name.endswith(("mock", "fixture", "test")) or "mock" in lowered_name:
            continue

        merged.setdefault(str(name), addr)
    return merged

def remember_project_target(config, root, name, address):
    """Persist a target alias together with the project that owns it."""
    if not name or not is_address(address):
        return
    root = str(Path(audit_context.foundry_project_root(root)).resolve())
    config.setdefault("aliases", {})[str(name)] = address
    config.setdefault("targets", {})[str(name)] = address
    config.setdefault("project_roots", {})[address] = root

def resolve_target_ref(config,ref,root=None):
    if ref is None:
        return active_project_target(config, root) if root is not None else config.get("target")

    project_root = audit_context.foundry_project_root(root) if root is not None else audit_context.foundry_project_root()
    entries = _project_target_entries(config, project_root)
    protocol_entries = [entry for entry in entries if _target_entry_is_protocol(project_root, entry)]

    if str(ref).isdigit():
        index = int(ref) - 1
        if 0 <= index < len(protocol_entries):
            return protocol_entries[index].get("address")
        project_roots = config.get("project_roots")
        if not isinstance(project_roots, dict) or not project_roots:
            legacy_aliases = config.get("aliases", {})
            if isinstance(legacy_aliases, dict):
                values = [value for value in legacy_aliases.values() if is_address(value)]
                if 0 <= index < len(values):
                    return values[index]
        return None

    if is_address(ref):
        return ref

    exact_matches = [
        entry for entry in protocol_entries
        if str(entry.get("name") or entry.get("contract") or "").strip().lower() == str(ref).strip().lower()
    ]
    if len(exact_matches) == 1:
        return exact_matches[0].get("address")

    aliases = target_aliases(config, project_root)
    resolved = aliases.get(str(ref))
    if resolved:
        return resolved
    # Backward-compatible fallback for a config that predates project ownership
    # metadata. Do not use this path once project_roots contains ownership data.
    project_roots = config.get("project_roots")
    if not isinstance(project_roots, dict) or not project_roots:
        legacy = config.get("aliases", {}).get(str(ref))
        if is_address(legacy):
            return legacy
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
    query = str(func_name or "").strip()
    if "(" in query:
        return [
            item for item in abi_functions(abi)
            if format_signature(item).lower() == query.lower()
        ]
    return [
        item for item in abi_functions(abi)
        if str(item.get("name") or "").lower() == query.lower()
    ]

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

def _configured_artifact_bases(root_path):
    """Return artifact directories declared by the project's build configuration."""
    bases = []

    foundry_path = root_path / "foundry.toml"
    if foundry_path.is_file():
        try:
            text = foundry_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        # Collect root/profile out= values. This intentionally does not attempt
        # to execute TOML; path discovery only needs the declared output folders.
        for match in re.finditer(r'(?m)^\s*out\s*=\s*["\']([^"\']+)["\']', text):
            value = match.group(1).strip()
            if value:
                bases.append(Path(value))

    return bases


def artifact_json_files(root="."):
    """Find ABI-bearing artifacts across common and project-declared output trees."""
    root_path = Path(root).expanduser().resolve()
    result = []
    bases = [
        root_path / "out",
        root_path / "broadcast",
        root_path / "artifacts",
        root_path / "build",
        root_path / ".audit" / "walkthrough" / "vyper",
        root_path / ".audit" / "build" / "vyper",
    ]

    for configured in _configured_artifact_bases(root_path):
        bases.append(configured if configured.is_absolute() else root_path / configured)

    ignored = {
        ".git", ".venv", ".tox", "__pycache__", "node_modules",
        "cache", "build-info",
    }
    for base_path in bases:
        base_path = base_path.resolve()
        if not base_path.is_dir():
            continue
        for path, dirs, files in os.walk(base_path):
            dirs[:] = [d for d in dirs if d not in ignored]
            for filename in files:
                if filename.endswith(".json"):
                    result.append(os.path.join(path, filename))
    return sorted(set(result))
def last_transaction(config):
    return config.get("last_tx")

def log_session(command, result):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(SESSION_FILE, "a") as f:
        f.write(f"[{timestamp}] CMD: {command}\nRES: {result}\n{'-'*40}\n")

def local_artifact_paths(root="."):
    result = []
    for path in artifact_json_files(root):
        parts = Path(path).parts
        if "build-info" in parts or Path(path).name == "solc-input.json":
            continue
        if any(part in {"node_modules", ".git", "__pycache__"} for part in parts):
            continue
        artifact = read_artifact(path)
        if not isinstance(artifact, dict) or not isinstance(artifact.get("abi"), list):
            continue
        # ABI-bearing artifacts are accepted from common Solidity/Vyper project
        # layouts. Dependency/application ranking is done only after the target
        # or source graph is known.
        result.append(path)
    return sorted(set(result))

def artifact_contract_name(path, artifact):
    if isinstance(artifact,dict) and artifact.get("contractName"): return str(artifact["contractName"])
    return Path(path).stem

def read_artifact(path):
    try:
        with open(path,"r",encoding="utf-8") as f: value=json.load(f)
        return value if isinstance(value,dict) else None
    except (OSError,json.JSONDecodeError): return None

def foundry_project_root(start="."):
    """Resolve the active EVM project root, not only Foundry projects."""
    try:
        path = Path(start).expanduser().resolve()
    except OSError:
        return None
    if path.is_file():
        path = path.parent

    if project_tools is not None and hasattr(project_tools, "project_root"):
        try:
            return str(project_tools.project_root(path))
        except Exception:
            pass

    markers = (
        "foundry.toml", "hardhat.config.js", "hardhat.config.cjs",
        "hardhat.config.mjs", "hardhat.config.ts",
        "brownie-config.yaml", "pyproject.toml", "package.json",
    )
    for parent in (path, *path.parents):
        if any((parent / marker).is_file() for marker in markers):
            return str(parent)
        if any((parent / dirname).is_dir() for dirname in ("src", "contracts", "vyper")):
            return str(parent)
    return str(path)

def path_is_within(path, root):
    try:
        Path(path).expanduser().resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False

def project_context_target(root=None):
    """Return only a valid remembered target for the current project."""
    project_root = audit_context.foundry_project_root(root)
    context = audit_context.load(project_root)
    target = context.get("target", {})
    if not isinstance(target, dict) or not is_address(target.get("address")):
        return None
    source = target.get("source")
    artifact = target.get("artifact")
    contract = target.get("contract")
    if source == "manual":
        return target
    if not artifact:
        return None
    try:
        artifact_path = Path(os.path.expanduser(str(artifact)))
        if not artifact_path.is_absolute():
            artifact_path = Path(project_root) / artifact_path
        artifact_path = artifact_path.resolve()
    except OSError:
        return None
    if not artifact_path.is_file():
        return None
    artifact_data = read_artifact(str(artifact_path))
    if not artifact_data or not artifact_is_project_application(project_root, str(artifact_path), artifact_data):
        return None
    actual_contract = artifact_contract_name(str(artifact_path), artifact_data)
    if contract and str(contract).lower() != str(actual_contract).lower():
        return None
    return target

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
        artifact = config.get("abi_paths", {}).get(global_target)
        contract = config.get("target_contract")
        if artifact:
            try:
                artifact_path = Path(os.path.expanduser(str(artifact)))
                if not artifact_path.is_absolute():
                    artifact_path = Path(project_root) / artifact_path
                artifact_path = artifact_path.resolve()
            except OSError:
                artifact_path = None
            if artifact_path and artifact_path.is_file():
                artifact_data = read_artifact(str(artifact_path))
                if artifact_data and artifact_is_project_application(Path(project_root), str(artifact_path), artifact_data):
                    artifact_contract = artifact_contract_name(str(artifact_path), artifact_data)
                    if not contract or str(contract).lower() == str(artifact_contract).lower():
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


def audit_abi_path(target, config, contract=None):
    """Return the project-local, human-readable ABI copy for a target."""
    if not target:
        return None
    roots = config.get("project_roots", {}) if isinstance(config, dict) else {}
    root = None
    if isinstance(roots, dict):
        root = roots.get(target)
        if not root and isinstance(target, str):
            lowered = target.lower()
            root = next(
                (
                    value for address, value in roots.items()
                    if isinstance(address, str) and address.lower() == lowered
                ),
                None,
            )
    try:
        project_root = Path(root).expanduser().resolve() if root else Path(
            audit_context.foundry_project_root()
        ).expanduser().resolve()
    except OSError:
        return None
    if not project_root.is_dir():
        return None
    contract = str(contract or config.get("target_contract") or "contract").strip() or "contract"
    safe_contract = re.sub(r"[^A-Za-z0-9_.-]", "_", contract).strip("._") or "contract"
    return project_root / ".audit" / "abi" / f"{safe_contract}.json"


def materialize_audit_abi(target, source_path, config):
    """Write a pretty, project-local ABI wrapper without replacing the source artifact."""
    if not target or not source_path:
        return None
    try:
        source = Path(os.path.expanduser(str(source_path))).resolve()
    except OSError:
        return None
    if not source.is_file():
        return None

    artifact = read_artifact(str(source))
    if not isinstance(artifact, dict):
        # A manually supplied bare ABI array is still accepted.
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, list):
            return None
        artifact = {"abi": payload}

    abi = artifact.get("abi")
    if not isinstance(abi, list):
        return None

    contract = artifact_contract_name(str(source), artifact)
    if not contract:
        contract = str(config.get("target_contract") or "contract")
    config.setdefault("target_contract", contract)

    destination = audit_abi_path(target, config, contract)
    if destination is None:
        return None

    # Never rewrite the file if the source already is the project-local ABI.
    try:
        if destination.resolve() == source.resolve():
            return destination
    except OSError:
        pass

    payload = {
        "contractName": str(contract),
        "abi": abi,
    }
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        destination.write_text(rendered, encoding="utf-8")
    except OSError:
        return None
    return destination

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
    try:
        materialize_audit_abi(target, absolute, config)
    except Exception:
        # ABI discovery must never fail merely because the audit-workspace copy
        # cannot be written. The original artifact remains the source of truth.
        pass
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

def auto_abi_path(target,config,root=None):
    """Resolve an ABI using only the requested project's artifact/build tree.

    Passing root is mandatory for lab/protocol bootstrap paths so a target can
    never inherit an ABI from the caller's cwd or another project's config.
    """
    if not target or not is_address(target):
        return None

    project_root = Path(audit_context.foundry_project_root(root)).resolve() if root is not None else Path(".").resolve()
    search_roots = [str(project_root)]
    preferred_root = configured_project_root(target,config)
    if root is None and preferred_root and os.path.abspath(preferred_root)!=os.path.abspath(str(project_root)):
        search_roots.insert(0,preferred_root)

    paths=[]
    for search_root in search_roots:
        paths.extend(local_artifact_paths(search_root))

    preferred=config.get("target_contract")
    candidate_addresses=[target]
    deployment_root = project_root if root is not None else Path(".")

    if not preferred:
        for record in discover_deployments(str(deployment_root)):
            if str(record.get("address","")).lower()==target.lower():
                preferred=record.get("contract")
                if preferred:
                    config["target_contract"]=preferred
                break

    rpc=effective_rpc(config)
    if rpc:
        try:
            code,implementation,error=cast_output(["cast","implementation",target,"--rpc-url",rpc])
        except (OSError, subprocess.SubprocessError):
            code,implementation,error=1,"",""
        if code==0 and is_address(implementation):
            implementation=implementation.strip().splitlines()[-1].strip()
            if implementation.lower()!=target.lower():
                candidate_addresses.insert(0,implementation)
                if not preferred:
                    for record in discover_deployments(str(deployment_root)):
                        if str(record.get("address","")).lower()==implementation.lower():
                            preferred=record.get("contract")
                            if preferred:
                                config["target_contract"]=preferred
                            break

    if preferred:
        preferred_lower=str(preferred).lower()
        for artifact_path in paths:
            artifact=read_artifact(artifact_path)
            name=artifact_contract_name(artifact_path,artifact).lower()
            if name==preferred_lower or Path(artifact_path).stem.lower()==preferred_lower:
                artifact_data = artifact or {}
                if root is not None and not artifact_is_project_application(project_root, artifact_path, artifact_data):
                    continue
                remember_abi_path(config,target,artifact_path)
                return artifact_path

    if rpc:
        for candidate in candidate_addresses:
            try:
                code,runtime,_=cast_output(["cast","code",candidate,"--rpc-url",rpc])
            except (OSError, subprocess.SubprocessError):
                code,runtime=1,""
            if code!=0 or not runtime or not runtime.startswith("0x") or runtime=="0x":
                continue
            for artifact_path in paths:
                artifact=read_artifact(artifact_path)
                deployed=artifact.get("deployedBytecode") if isinstance(artifact,dict) else None
                if isinstance(deployed,dict):
                    deployed=deployed.get("object")
                if isinstance(deployed,str) and deployed.lower()==runtime.lower():
                    remember_abi_path(config,target,artifact_path)
                    config["target_contract"]=artifact_contract_name(artifact_path,artifact)
                    return artifact_path

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
    audit_path = audit_abi_path(target, config)
    if audit_path and audit_path.exists():
        try:
            audit_label = audit_path.relative_to(Path(audit_context.foundry_project_root()).resolve())
        except (OSError, ValueError):
            audit_label = audit_path
        print(f"Audit ABI: {audit_label}")
    for group, items in groups:
        if items:
            print(f"\n{group}")
            for item in items:
                print(f"  {format_signature(item)}")
_FUNCTION_VISIBILITIES = {"public", "external", "internal", "private", "unknown", "ambiguous"}
_FUNCTION_MUTABILITIES = {"pure", "view", "nonpayable", "payable"}
_FUNCTION_CLASS_ALIASES = {
    "state": "STATE-CHANGING", "state-changing": "STATE-CHANGING", "state-write": "STATE-CHANGING",
    "read": "READ-ONLY", "read-only": "READ-ONLY",
    "getter": "STORAGE-GETTER", "storage-getter": "STORAGE-GETTER",
    "payable": "PAYABLE", "admin": "ADMIN", "asset": "ASSET-ACTION", "asset-action": "ASSET-ACTION",
    "external-call": "EXTERNAL-CALL", "callback": "CALLBACK", "upgrade": "UPGRADE",
    "assembly": "ASSEMBLY", "creation": "CONTRACT-CREATION", "eth": "ETH-FLOW", "eth-flow": "ETH-FLOW",
}

def _function_usage():
    return (
        "Usage: lk fn [query] [-v] [-V visibility] [-m mutability] [-c class] [-r]\n"
        "  -v, --verbose              Show per-function audit metadata.\n"
        "  -V, --visibility VALUE     Filter by source visibility (public/external/internal/private/unknown).\n"
        "  -m, --mutability VALUE     Filter by mutability (pure/view/nonpayable/payable).\n"
        "  -c, --class VALUE          Filter by class (state/read/getter/payable/admin/asset/external-call/callback/upgrade/assembly/creation/eth-flow).\n"
        "  -r, --risk                 Show compact audit-review flags.\n"
        "\n"
        "Examples:\n"
        "  lk fn\n"
        "  lk fn -v\n"
        "  lk fn -v withdraw\n"
        "  lk fn -V external\n"
        "  lk fn -m payable\n"
        "  lk fn -c admin\n"
        "  lk fn -r\n"
    )

def _parse_function_options(raw_args):
    args = [str(item) for item in (raw_args if isinstance(raw_args, (list, tuple)) else [raw_args] if raw_args is not None else [])]
    options = {"verbose": False, "visibility": None, "mutability": None, "class": None, "risk": False}
    query_parts = []
    value_flags = {
        "-V": "visibility", "--visibility": "visibility",
        "-m": "mutability", "--mutability": "mutability",
        "-c": "class", "--class": "class",
    }
    bool_flags = {"-v": "verbose", "--verbose": "verbose", "-r": "risk", "--risk": "risk"}
    i = 0
    while i < len(args):
        token = args[i].strip()
        if token in {"-h", "--help", "help"}:
            return None, "help"
        if token in bool_flags:
            options[bool_flags[token]] = True
            i += 1
            continue
        matched = False
        for flag, key in value_flags.items():
            if token == flag:
                if i + 1 >= len(args) or args[i + 1].startswith("-"):
                    return None, f"missing value for {flag}"
                options[key] = args[i + 1].strip()
                i += 2
                matched = True
                break
            prefix = flag + "="
            if token.startswith(prefix):
                value = token[len(prefix):].strip()
                if not value:
                    return None, f"missing value for {flag}"
                options[key] = value
                i += 1
                matched = True
                break
        if matched:
            continue
        if token.startswith("-"):
            return None, f"unknown function option: {token}"
        query_parts.append(token)
        i += 1

    if options["visibility"]:
        options["visibility"] = options["visibility"].lower()
        if options["visibility"] not in _FUNCTION_VISIBILITIES:
            return None, "visibility must be public, external, internal, private, unknown, or ambiguous"
    if options["mutability"]:
        options["mutability"] = options["mutability"].lower()
        if options["mutability"] not in _FUNCTION_MUTABILITIES:
            return None, "mutability must be pure, view, nonpayable, or payable"
    if options["class"]:
        options["class"] = options["class"].lower()
        if options["class"] not in _FUNCTION_CLASS_ALIASES:
            return None, "unknown class; try state, read, getter, payable, admin, asset, external-call, callback, upgrade, assembly, creation, or eth-flow"
    return options, " ".join(query_parts).strip()

def _matching_delimiter(text_content, start, opening="(", closing=")"):
    depth = 0
    quote = ""
    escape = False
    for index in range(start, len(text_content)):
        ch = text_content[index]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                return index
    return None

def _split_top_level(text_content):
    parts = []
    start = 0
    parens = brackets = braces = 0
    quote = ""
    escape = False
    for index, ch in enumerate(text_content):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            parens += 1
        elif ch == ")" and parens:
            parens -= 1
        elif ch == "[":
            brackets += 1
        elif ch == "]" and brackets:
            brackets -= 1
        elif ch == "{":
            braces += 1
        elif ch == "}" and braces:
            braces -= 1
        elif ch == "," and parens == 0 and brackets == 0 and braces == 0:
            parts.append(text_content[start:index].strip())
            start = index + 1
    tail = text_content[start:].strip()
    if tail:
        parts.append(tail)
    return parts

def _solidity_function_source_index(source):
    masked = _strip_scan_comments(source, "solidity")
    declarations = []
    for match in re.finditer(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", masked):
        name = match.group(1)
        opening = masked.find("(", match.start(), match.end())
        closing = _matching_delimiter(masked, opening, "(", ")")
        if closing is None:
            continue

        boundary = None
        parens = brackets = 0
        quote = ""
        escape = False
        for index in range(closing + 1, len(masked)):
            ch = masked[index]
            if quote:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = ""
                continue
            if ch in {"'", '"'}:
                quote = ch
                continue
            if ch == "(":
                parens += 1
            elif ch == ")" and parens:
                parens -= 1
            elif ch == "[":
                brackets += 1
            elif ch == "]" and brackets:
                brackets -= 1
            elif ch == "{" and parens == 0 and brackets == 0:
                boundary = index
                break
            elif ch == ";" and parens == 0 and brackets == 0:
                boundary = index
                break
        if boundary is None:
            continue

        body = ""
        if masked[boundary] == "{":
            end = _matching_delimiter(masked, boundary, "{", "}")
            if end is not None:
                body = source[boundary + 1:end]

        header = source[closing + 1:boundary]
        visibility_match = re.search(r"\b(external|public|internal|private)\b", header)
        mutability_match = re.search(r"\b(pure|view|payable|nonpayable)\b", header)

        clean_header = header
        for keyword in ("returns", "override"):
            while True:
                named = re.search(r"\b" + keyword + r"\b", clean_header)
                if not named:
                    break
                open_pos = clean_header.find("(", named.end())
                if open_pos < 0:
                    clean_header = clean_header[:named.start()] + " " + clean_header[named.end():]
                    break
                close_pos = _matching_delimiter(clean_header, open_pos, "(", ")")
                if close_pos is None:
                    break
                clean_header = clean_header[:named.start()] + " " + clean_header[close_pos + 1:]

        excluded = {
            "external", "public", "internal", "private", "pure", "view", "payable", "nonpayable",
            "virtual", "memory", "calldata", "storage", "returns", "override",
        }
        modifiers = []
        for token_match in re.finditer(r"\b[A-Za-z_]\w*\b", clean_header):
            token = token_match.group(0)
            prefix = clean_header[:token_match.start()]
            depth = prefix.count("(") - prefix.count(")")
            if depth != 0 or token in excluded:
                continue
            if token not in modifiers:
                modifiers.append(token)

        params = source[opening + 1:closing]
        declarations.append({
            "name": name,
            "param_count": len(_split_top_level(params)),
            "visibility": visibility_match.group(1) if visibility_match else "unknown",
            "mutability": mutability_match.group(1) if mutability_match else None,
            "modifiers": modifiers,
            "body": body,
            "line": source.count("\n", 0, match.start()) + 1,
        })
    return declarations

def _function_source_file(artifact, root):
    if not isinstance(artifact, dict):
        return None, []
    root_path = Path(root).expanduser().resolve()
    candidates = []
    source_name = artifact.get("sourceName")
    if source_name:
        candidate = root_path / str(source_name)
        if candidate.is_file():
            candidates.append(candidate)

    contract = str(artifact.get("contractName") or "")
    if not candidates and contract:
        try:
            discovered = source_sol_files(str(root_path))
        except Exception:
            discovered = []
        for path in discovered:
            try:
                content = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if re.search(r"\b(?:contract|interface|library)\s+" + re.escape(contract) + r"\b", content):
                candidates.append(Path(path))
                break

    if not candidates and contract:
        # .audit/abi/*.json intentionally keeps only contractName + ABI. When
        # sourceName was stripped, recover the application source from the
        # project's normal Solidity roots.
        roots = [root_path / "src", root_path / "contracts", root_path]
        seen = set()
        for source_root in roots:
            if not source_root.is_dir():
                continue
            try:
                paths = source_root.rglob("*.sol")
            except OSError:
                continue
            for path in paths:
                try:
                    resolved = path.resolve()
                except OSError:
                    continue
                if resolved in seen or any(
                    part in {".git", "out", "cache", "node_modules", "artifacts", "build", ".audit"}
                    for part in resolved.parts
                ):
                    continue
                seen.add(resolved)
                try:
                    content = resolved.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if re.search(r"\b(?:contract|interface|library)\s+" + re.escape(contract) + r"\b", content):
                    candidates.append(resolved)
                    break
            if candidates:
                break

    if not candidates:
        return None, []
    path = candidates[0]
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return path, []
    return path, _solidity_function_source_index(source)

def _function_storage_labels(target, config, artifact):
    labels = set()
    if isinstance(artifact, dict):
        layout = artifact.get("storageLayout", {})
        storage = layout.get("storage", []) if isinstance(layout, dict) else []
        labels.update(str(entry.get("label")) for entry in storage if isinstance(entry, dict) and entry.get("label"))
    if labels:
        return labels

    contract_name = artifact.get("contractName") if isinstance(artifact, dict) else None
    contract_name = contract_name or config.get("target_contract")
    if not contract_name:
        return labels
    for command in (
        ["forge", "inspect", str(contract_name), "storage-layout", "--json"],
        ["forge", "inspect", str(contract_name), "storage-layout"],
    ):
        code, out, _ = cast_output(command)
        if code != 0 or not out:
            continue
        try:
            payload = json.loads(out)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            payload = payload.get("storageLayout") or payload.get("storage") or payload
        storage = payload if isinstance(payload, list) else []
        labels.update(str(entry.get("label")) for entry in storage if isinstance(entry, dict) and entry.get("label"))
        if labels:
            break
    return labels

def _function_storage_refs(body, storage_labels):
    if not body or not storage_labels:
        return [], []
    reads = set()
    writes = set()
    for line in body.splitlines() or [body]:
        for name in storage_labels:
            if not re.search(r"\b" + re.escape(name) + r"\b", line):
                continue
            write_match = re.search(
                r"\b" + re.escape(name) +
                r"\b[^;\n]*(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=|\+\+|--|(?<![=!<>])=(?!=))",
                line,
            )
            if write_match:
                writes.add(name)
                if any(op in line for op in ("+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "++", "--")):
                    reads.add(name)
                else:
                    operator_pos = re.search(r"(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=|(?<![=!<>])=(?!=))", line)
                    if operator_pos and re.search(r"\b" + re.escape(name) + r"\b", line[operator_pos.end():]):
                        reads.add(name)
            else:
                reads.add(name)
    return sorted(reads), sorted(writes)

def _function_modifier_text(record):
    modifiers = record.get("modifiers", [])
    return ", ".join(modifiers) if modifiers else "—"

def _function_inventory_risk_flags(record):
    flags = []
    name = record["name"].lower()
    mutable = record["mutability"] not in {"view", "pure"}
    modifiers = [str(item).lower() for item in record.get("modifiers", [])]
    if mutable:
        flags.append("STATE-WRITE")
    if record["mutability"] == "payable":
        flags.append("VALUE-FLOW")
    if record.get("eth") == "SENDS":
        flags.append("ETH-SEND")
    elif record.get("eth") == "RECEIVES + SENDS":
        flags.append("ETH-FLOW")
    elif record.get("eth") == "RECEIVES":
        flags.append("ETH-RECEIVE")
    if any(token in name for token in ("owner", "admin", "role", "upgrade", "pause", "unpause")) or any(
        token.startswith(("only", "auth", "when")) for token in modifiers
    ):
        flags.append("PRIVILEGED")
    if any(token in name for token in ("withdraw", "transfer", "send", "execute", "mint", "burn", "sweep", "claim", "release", "approve")):
        flags.append("ASSET/ACTION")
    if record.get("calls") or record.get("eth") in {"SENDS", "RECEIVES + SENDS"}:
        flags.append("EXTERNAL-CALL")
    if any(token in name for token in ("callback", "hook", "flash")):
        flags.append("CALLBACK")
    if any(token in name for token in ("upgrade", "implementation", "proxiable")):
        flags.append("UPGRADE")
    if record.get("assembly"):
        flags.append("ASSEMBLY")
    return flags or ["—"]

def _function_inventory_classes(record):
    classes = []
    if record.get("getter"):
        classes.append("STORAGE-GETTER")
    classes.append("READ-ONLY" if record["mutability"] in {"view", "pure"} else "STATE-CHANGING")
    if record["mutability"] == "payable":
        classes.append("PAYABLE")
    if record.get("eth"):
        classes.append("ETH-FLOW")
    if record.get("admin"):
        classes.append("ADMIN")
    if record.get("asset_action"):
        classes.append("ASSET-ACTION")
    if record.get("calls"):
        classes.append("EXTERNAL-CALL")
    if record.get("callback"):
        classes.append("CALLBACK")
    if record.get("upgrade"):
        classes.append("UPGRADE")
    if record.get("assembly"):
        classes.append("ASSEMBLY")
    if record.get("creates"):
        classes.append("CONTRACT-CREATION")
    return list(dict.fromkeys(classes))

def _function_inventory_record(item, source_decls, storage_labels, getter_names, method_ids, source_path):
    signature = format_signature(item)
    name = str(item.get("name") or "<anonymous>")
    candidates = [
        decl for decl in source_decls
        if decl.get("name") == name and decl.get("param_count") == len(item.get("inputs", []))
    ]
    source = candidates[0] if len(candidates) == 1 else None
    if name in getter_names:
        visibility = "public"
    elif source:
        visibility = source.get("visibility") or "unknown"
    elif len(candidates) > 1:
        visibility = "ambiguous"
    else:
        visibility = "unknown"

    mutability = item.get("stateMutability") or (source or {}).get("mutability") or "unknown"
    body = source.get("body", "") if source else ""
    reads, writes = _function_storage_refs(body, storage_labels)
    if name in getter_names and name in storage_labels:
        reads = sorted(set(reads + [name]))

    events = sorted(set(re.findall(r"\bemit\s+([A-Za-z_]\w*)\s*(?:\(|;)", body)))
    sends_eth = bool(re.search(r"\.\s*call\s*\{\s*value\s*:", body)) or bool(
        re.search(r"\.\s*(?:send|transfer)\s*\(", body)
    )
    calls = [
        method for method in ("delegatecall", "staticcall", "call", "send", "transfer")
        if re.search(r"\.\s*" + method + r"\s*(?:\{|\()", body)
    ]
    if sends_eth and "call" not in calls:
        calls.append("call")
    receives_eth = mutability == "payable"
    eth = "RECEIVES + SENDS" if receives_eth and sends_eth else "RECEIVES" if receives_eth else "SENDS" if sends_eth else None
    creates = bool(re.search(r"\bnew\s+[A-Za-z_]\w*", body))
    assembly = bool(re.search(r"\bassembly\s*\{|\b(?:sstore|sload|calldatacopy|extcodesize)\b", body))

    name_lower = name.lower()
    admin = any(token in name_lower for token in ("owner", "admin", "role", "upgrade", "pause", "unpause")) or any(
        str(token).lower().startswith(("only", "auth", "when")) for token in (source or {}).get("modifiers", [])
    )
    asset_action = any(token in name_lower for token in ("withdraw", "transfer", "send", "execute", "mint", "burn", "sweep", "claim", "release", "approve"))
    callback = any(token in name_lower for token in ("callback", "hook", "flash"))
    upgrade = any(token in name_lower for token in ("upgrade", "implementation", "proxiable"))

    source_label = None
    if source_path:
        source_label = f"{source_path}:{source.get('line')}" if source else str(source_path)

    record = {
        "item": item, "name": name, "signature": signature, "visibility": visibility, "mutability": mutability,
        "modifiers": (source or {}).get("modifiers", []), "inputs": item.get("inputs", []), "outputs": item.get("outputs", []),
        "reads": reads, "writes": writes, "events": events, "calls": calls, "eth": eth, "creates": creates,
        "assembly": assembly, "getter": name in getter_names, "admin": admin, "asset_action": asset_action,
        "callback": callback, "upgrade": upgrade, "source": source_label, "_source": source,
        "selector": (
            (
                (method_ids or {}).get(signature)
                if str((method_ids or {}).get(signature)).lower().startswith("0x")
                else "0x" + str((method_ids or {}).get(signature))
            )
            if (method_ids or {}).get(signature)
            else None
        ),
    }
    record["classes"] = _function_inventory_classes(record)
    record["risk_flags"] = _function_inventory_risk_flags(record)
    return record

def _function_matches_filter(record, options):
    if options.get("visibility") and record["visibility"].lower() != options["visibility"]:
        return False
    if options.get("mutability") and record["mutability"].lower() != options["mutability"]:
        return False
    if options.get("class"):
        wanted = _FUNCTION_CLASS_ALIASES[options["class"]]
        if wanted not in record.get("classes", []):
            return False
    return True

def _print_function_inventory(records, contract=None, source_path=None, verbose=False, show_risk=False):
    title = "LOWKEY // FUNCTION INVENTORY"
    if verbose:
        title += " • VERBOSE"
    elif show_risk:
        title += " • REVIEW FLAGS"
    print(title)
    print("=" * 78)
    if contract:
        print(f"Contract : {contract}")
    if source_path:
        print(f"Source   : {source_path}")
    print(f"Count    : {len(records)}")
    if not records:
        print("\nNo functions matched the requested filters.")
        return

    if verbose:
        for index, record in enumerate(records, 1):
            print(f"\n[{index}] {record['signature']}")
            print(f"  visibility : {record['visibility']}")
            print(f"  mutability : {record['mutability']}")
            print(f"  class      : {' • '.join(record['classes'])}")
            print(f"  modifiers  : {_function_modifier_text(record)}")
            params = [f"{param.get('name') or 'arg' + str(position)}:{canonical_type(param)}"
                      for position, param in enumerate(record["inputs"], 1)]
            outputs = [f"{param.get('name') or 'ret' + str(position)}:{canonical_type(param)}"
                       for position, param in enumerate(record["outputs"], 1)]
            print(f"  params     : {', '.join(params) if params else '—'}")
            print(f"  returns    : {', '.join(outputs) if outputs else '—'}")
            print(f"  reads      : {', '.join(record['reads']) if record['reads'] else '—'}")
            print(f"  writes     : {', '.join(record['writes']) if record['writes'] else '—'}")
            print(f"  emits      : {', '.join(record['events']) if record['events'] else '—'}")
            print(f"  calls      : {', '.join(record['calls']) if record['calls'] else '—'}")
            print(f"  ether      : {record['eth'] or '—'}")
            print(f"  creates    : {'YES' if record['creates'] else '—'}")
            print(f"  assembly   : {'YES' if record['assembly'] else '—'}")
            print(f"  selector   : {record['selector'] or '—'}")
            print(f"  risk flags : {' • '.join(record['risk_flags'])}")
            print(f"  source     : {record['source'] or 'ABI only'}")
        return

    signature_width = min(max(max(len(record["signature"]) for record in records), 18), 48)
    headers = ["FUNCTION", "VISIBILITY", "MUTABILITY", "CLASS"]
    if show_risk:
        headers.append("RISK")
    widths = [
        signature_width,
        max(len(headers[1]), max(len(record["visibility"]) for record in records)),
        max(len(headers[2]), max(len(record["mutability"]) for record in records)),
        min(max(len(headers[3]), max(len(" / ".join(record["classes"])) for record in records)), 42),
    ]
    if show_risk:
        widths.append(min(max(len(headers[4]), max(len(" / ".join(record["risk_flags"])) for record in records)), 64))
    print()
    print("  ".join(headers[index].ljust(widths[index]) for index in range(len(headers))))
    print("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for record in records:
        cells = [
            record["signature"][:signature_width],
            record["visibility"],
            record["mutability"],
            " / ".join(record["classes"])[:widths[3]],
        ]
        if show_risk:
            cells.append(" / ".join(record["risk_flags"])[:widths[4]])
        print("  ".join(cells[index].ljust(widths[index]) for index in range(len(cells))))

def _function_inventory_artifact(target, config):
    path = resolve_abi_path(config, target) or auto_abi_path(target, config)
    artifact = read_artifact(path) if path else None
    return path, artifact or {}

def run_functions(config, args=None):
    raw_args = [args] if isinstance(args, str) else args
    options, query = _parse_function_options(raw_args)
    if options is None:
        if query == "help":
            print(_function_usage())
            return 0
        return fail(f"Error: {query}\n\n{_function_usage()}")

    root = audit_context.foundry_project_root()
    target = active_project_target(config, root)
    if not target:
        explicit_target = config.get("target")
        explicit_abi = config.get("abi_paths", {}).get(explicit_target) if isinstance(config.get("abi_paths"), dict) else None
        if is_address(explicit_target) and explicit_abi and os.path.exists(os.path.expanduser(str(explicit_abi))):
            target = explicit_target
    if not target:
        if not query:
            return fail("Error: no project target selected. Use 'lk fn <function>' to search build artifacts, or deploy and run 'lk target auto'.")
        if any(options.values()):
            return fail("Error: function filters/verbose mode need a selected target with an ABI. Use 'lk target <name|address>' first.")
        matches = project_artifact_function_matches(root, query)
        if not matches:
            return fail(f"Error: no built-project function matched '{query}'. Run 'forge build' first.")
        print("LOWKEY BUILD FUNCTION")
        print("====================")
        print(f"Query:   {query}")
        support_rows = []
        for index, (contract, signature, path) in enumerate(matches[:8]):
            if index == 0:
                print(f"Found:   {contract}::{signature}")
                print(f"Source:  {path}")
            else:
                if str(contract).startswith("I"):
                    label = f"{contract} (interface)"
                elif str(contract).startswith(("Mock", "Test", "Fixture")):
                    label = f"{contract} (test mock)"
                else:
                    label = contract
                support_rows.append(f"{contract}::{signature}")
        if support_rows:
            print("Other:   " + ", ".join(support_rows))
        print("Live:    none")
        print("Next:    deploy a target before using lk changes/trace.")
        return 0

    abi = load_abi(target, config)
    functions = abi_functions(abi)
    if not functions:
        return fail("Error: No ABI functions loaded for the current target.")

    getter_names = storage_getter_names(target, config, functions)
    artifact_path, artifact = _function_inventory_artifact(target, config)
    source_root = Path(root).resolve()
    source_path, source_decls = _function_source_file(artifact, source_root)
    storage_labels = _function_storage_labels(target, config, artifact)
    method_ids = artifact.get("methodIdentifiers") or (
        artifact.get("evm", {}).get("methodIdentifiers") if isinstance(artifact.get("evm"), dict) else {}
    )
    records = [
        _function_inventory_record(
            item, source_decls, storage_labels, getter_names,
            method_ids if isinstance(method_ids, dict) else {}, source_path
        )
        for item in functions
    ]
    records = [record for record in records if _function_matches_filter(record, options)]
    if query:
        records = sorted(records, key=lambda record: function_score(record["item"], query), reverse=True)[:8]

    if options.get("verbose"):
        _print_function_inventory(
            records,
            contract=artifact.get("contractName") or config.get("target_contract"),
            source_path=source_path,
            verbose=True,
        )
        return 0

    if options.get("visibility") or options.get("mutability") or options.get("class") or options.get("risk"):
        _print_function_inventory(
            records,
            contract=artifact.get("contractName") or config.get("target_contract"),
            source_path=source_path,
            show_risk=options.get("risk", False),
        )
        return 0

    groups = [
        ("WRITE FUNCTIONS", [record["item"] for record in records if record["item"].get("stateMutability") not in {"view", "pure"}]),
        ("READ FUNCTIONS", [record["item"] for record in records if record["item"].get("stateMutability") in {"view", "pure"} and record["name"] not in getter_names]),
        ("STORAGE GETTERS", [record["item"] for record in records if record["name"] in getter_names]),
    ]
    if query:
        print(f"Function matches for '{query}':")
    for title, items in groups:
        if not items:
            continue
        print(f"\n{title}:")
        for index, item in enumerate(items, 1):
            suffix = "  [public storage getter]" if title == "STORAGE GETTERS" else ""
            print(f"  {index:>2}. {format_signature(item)}{suffix}")
    return 0

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
    tx_hash = transaction.get("hash", tx_hash)
    root = audit_context.foundry_project_root()
    receipt = walkthrough._receipt(rpc, tx_hash) if rpc else None
    step = walkthrough.Step(
        0,
        str(config.get("actor") or "Caller"),
        str(config.get("target_contract") or "Transaction"),
        str(tx_to or config.get("target") or "0x" + "00" * 20),
        "transaction",
        [],
        status="success" if isinstance(receipt, dict) and receipt.get("status") in ("0x1", 1) else "reverted" if receipt else "checking",
        tx_hash=tx_hash,
    )
    walkthrough._write_transaction_evidence(root, rpc or "", step, receipt)
    print(f"Hash:  {walkthrough._transaction_link(root, tx_hash)}")
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
    code = run_cast(["receipt", tx_hash, "--async"], config)
    root = audit_context.foundry_project_root()
    audit_context.set_latest(root, tx_hash=tx_hash)
    audit_context.record_tool(
        "receipt",
        root,
        status="completed" if code == 0 else "failed",
        summary=f"transaction receipt {tx_hash[:10]}...",
        data={"tx_hash": tx_hash, "exit_code": code},
    )
    return code

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

def decode_abi_output(signature,data):
    """Decode ABI-encoded return data using the loaded function output signature."""
    payload=str(data or "").strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]*", payload):
        return None, "return data is not hex"
    if not payload or payload == "0x":
        return "", None
    code,out,err=cast_output(["cast","abi-decode",signature,payload])
    if code != 0:
        return None, err or out or "ABI decoding failed"
    return out.strip(), None

def _human_type_label(type_name):
    """Translate Solidity ABI types into labels a learner can understand."""
    value=str(type_name or "").strip()
    lowered=value.lower()
    if re.fullmatch(r"u?int\d*", lowered):
        return "integer"
    if lowered=="bool":
        return "true/false value"
    if lowered=="address":
        return "Ethereum address"
    if lowered=="string":
        return "text"
    if lowered=="bytes":
        return "raw bytes"
    if re.fullmatch(r"bytes\d+", lowered):
        return "fixed-size bytes"
    if lowered.startswith("tuple"):
        return "structured value"
    if lowered.endswith("[]"):
        return f"list of {_human_type_label(lowered[:-2])}"
    return value or "value"

def _function_display_name(item):
    name=str(item.get("name") or "").strip()
    if not name:
        return "value"
    spaced=re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    spaced=spaced.replace("_"," ").strip().lower()
    aliases={
        "balance of": "balance",
        "owner of": "owner",
        "get approved": "approved address",
        "is approved for all": "operator approval",
        "token uri": "token URI",
        "total supply": "total supply",
    }
    return aliases.get(spaced, spaced)

def _human_return_unit(item,abi):
    """Add a unit only where the ABI gives Lowkey enough context to justify it."""
    name=str(item.get("name") or "").strip().lower()
    names={str(entry.get("name") or "").strip().lower() for entry in abi_functions(abi)}
    if name=="balanceof":
        if {"ownerof","tokenuri"} <= names:
            return "NFTs"
        if {"decimals","symbol"} <= names:
            return "token units"
        # A custom balanceOf() is not necessarily an ERC20/721 balance.
        return "units"
    if name=="decimals":
        return "decimal places"
    return None

def format_human_abi_return(item, decoded, config, abi=None):
    """Render ABI return data as a human value while retaining useful type context."""
    outputs=item.get("outputs",[]) if isinstance(item,dict) else []
    value=apply_labels(str(decoded or "").strip(),config)
    if not outputs:
        return "Return: no data"

    abi=abi or [item]
    if len(outputs)==1:
        output=outputs[0]
        type_name=canonical_type(output)
        label=str(output.get("name") or "").strip() or _function_display_name(item)
        unit=_human_return_unit(item,abi)
        human_type=_human_type_label(type_name)

        # Cast already decoded the ABI value. Make common scalar values especially
        # readable without hiding the Solidity type auditors may still need.
        rendered=value
        if type_name.lower().startswith("uint") or type_name.lower().startswith("int"):
            try:
                if re.fullmatch(r"-?\d+", rendered):
                    rendered=f"{int(rendered):,}"
            except ValueError:
                pass
        if type_name.lower()=="bool":
            lowered=rendered.lower()
            if lowered in {"true","false"}:
                rendered=lowered
        if unit:
            rendered=f"{rendered} {unit}"

        return f"Return: {label} = {rendered}  ({human_type}; {type_name})"

    types=[canonical_type(output) for output in outputs]
    labels=[
        str(output.get("name") or "").strip() or f"value{index}"
        for index,output in enumerate(outputs,1)
    ]
    decoded_parts=[line.strip() for line in str(value).splitlines() if line.strip()]
    if len(decoded_parts)==len(outputs):
        details=", ".join(
            f"{label}={value_part} ({_human_type_label(type_name)}; {type_name})"
            for label,value_part,type_name in zip(labels,decoded_parts,types)
        )
        return f"Returns: {details}"
    return f"Returns: {value}"


def _function_tokens(name):
    text_value=str(name or "")
    parts=re.findall(r"[A-Z]+(?=[A-Z][a-z]|\b)|[A-Z]?[a-z]+|\d+",text_value)
    return {part.lower() for part in parts if part}

_FUNCTION_CONCEPTS=(
    {"balance","owner","holder","approved","approval","operator","allowance","transfer","safe"},
    {"name","symbol","uri","tokenuri","metadata","decimals","supply","total"},
    {"price","cost","fee","amount","value","rate","quote","payment","buy","sell","deposit","withdraw","redeem","claim"},
    {"admin","owner","role","grant","revoke","pause","unpause","upgrade","implementation"},
)

def _function_type_family(type_name):
    value=str(type_name or "").lower()
    return re.sub(r"\[\d*\]", "[]", value)

def _function_relatedness(current,candidate):
    """Score ABI functions by semantic and type relationships, contract-agnostically."""
    if not isinstance(current,dict) or not isinstance(candidate,dict):
        return -1
    if current is candidate or format_signature(current).lower()==format_signature(candidate).lower():
        return -1

    current_in=[_function_type_family(canonical_type(p)) for p in current.get("inputs",[])]
    current_out=[_function_type_family(canonical_type(p)) for p in current.get("outputs",[])]
    candidate_in=[_function_type_family(canonical_type(p)) for p in candidate.get("inputs",[])]
    candidate_out=[_function_type_family(canonical_type(p)) for p in candidate.get("outputs",[])]

    score=0
    score += 8*len(set(current_out) & set(candidate_in))
    score += 5*len(set(current_in) & set(candidate_out))
    score += 3*len(set(current_in) & set(candidate_in))
    score += 2*len(set(current_out) & set(candidate_out))

    current_tokens=_function_tokens(current.get("name"))
    candidate_tokens=_function_tokens(candidate.get("name"))
    score += 5*sum(1 for concept in _FUNCTION_CONCEPTS if current_tokens & concept and candidate_tokens & concept)
    score += 2*len(current_tokens & candidate_tokens)
    if len(current_in)==len(candidate_in):
        score += 1
    if str(current.get("stateMutability"))==str(candidate.get("stateMutability")):
        score += 1
    return score

def _related_read_functions(current,abi):
    candidates=[
        item for item in abi_functions(abi)
        if item is not current and item.get("stateMutability") in {"view","pure"}
    ]
    ranked=[]
    for item in candidates:
        score=_function_relatedness(current,item)
        if score > 0:
            ranked.append((score,format_signature(item),item))
    ranked.sort(key=lambda entry:(-entry[0],entry[1].lower()))
    return [item for _,_,item in ranked]

def _function_query_for_command(command,args):
    canonical=_canonical_help_command(str(command or "").strip().lower())
    values=[str(value).strip() for value in (args or [])]
    if canonical in {"read","send"}:
        if values and is_address(values[0]):
            return values[1] if len(values)>1 else None
        return values[0] if values else None
    if canonical in {"fn","ask","wizard","changes"}:
        return values[0] if values else None
    return None

def _function_item_for_command(command,args,config):
    if not isinstance(config,dict):
        config={}
    query=_function_query_for_command(command,args)
    if not query:
        return None,[]
    target=config.get("target")
    canonical=_canonical_help_command(str(command or "").strip().lower())
    values=[str(value).strip() for value in (args or [])]
    if canonical in {"read","send"} and values and is_address(values[0]):
        target=values[0]
    abi=load_abi(target,config) if target else []
    if not abi:
        return None,[]
    matches=matching_functions(abi,query)
    return (matches[0] if len(matches)==1 else None),abi

def _function_interaction_recommendations(command,args,config):
    """Build recommendations from the actual ABI function just used."""
    canonical=_canonical_help_command(str(command or "").strip().lower())
    current,abi=_function_item_for_command(command,args,config)
    if not current:
        return []

    current_query=_function_query_for_command(command,args)
    current_name=str(current.get("name") or current_query or "").strip()
    related_reads=_related_read_functions(current,abi)

    if canonical=="read":
        rendered=[]
        for item in related_reads[:3]:
            command_text=_function_recommendation_command("read",item,abi)
            if command_text:
                rendered.append((command_text,_function_recommendation_reason(item)))
        # Once the user has successfully supplied arguments, the more useful
        # next step is another related state observation rather than re-asking
        # for parameters they just supplied.
        return rendered

    if canonical in {"send","wizard"} and current.get("stateMutability") not in {"view","pure"}:
        rendered=[("lk receipt","Confirm the transaction status and decoded receipt."),
                   ("lk trace","See what the transaction actually executed and which contracts it touched.")]
        for item in related_reads[:2]:
            command_text=_function_recommendation_command("read",item,abi)
            if command_text:
                rendered.append((command_text,_function_recommendation_reason(item)))
        return rendered[:4]

    if canonical=="wizard":
        rendered=[]
        for item in related_reads[:3]:
            command_text=_function_recommendation_command("read",item,abi)
            if command_text:
                rendered.append((command_text,_function_recommendation_reason(item)))
        return rendered[:4]

    return []

def _function_recommendation_command(verb,item,abi):
    if not isinstance(item,dict):
        return None
    name=str(item.get("name") or "").strip()
    if not name:
        return None
    same_name=[candidate for candidate in abi_functions(abi) if str(candidate.get("name") or "").lower()==name.lower()]
    query=format_signature(item) if len(same_name)>1 else name
    inputs=[]
    for index,param in enumerate(item.get("inputs",[]),1):
        label=str(param.get("name") or "").strip() or f"arg{index}"
        label=re.sub(r"[^A-Za-z0-9_]+","_",label).strip("_") or f"arg{index}"
        inputs.append(f"<{label}>")
    suffix=(" " + " ".join(inputs)) if inputs else ""
    return f"lk {verb} {query}{suffix}"

def _function_recommendation_reason(item):
    name=str(item.get("name") or "").strip()
    lowered=name.lower()
    reasons={
        "balanceof": "Check how many tokens/NFTs an address holds.",
        "ownerof": "Check which address owns a specific NFT.",
        "getapproved": "Check which address is approved to transfer a specific NFT.",
        "isapprovedforall": "Check whether an operator can manage an owner's NFTs.",
        "tokenuri": "Inspect the metadata URI for a specific NFT.",
        "name": "Identify the asset or contract name.",
        "symbol": "Identify the asset ticker/symbol.",
        "decimals": "See how many decimal places the token uses.",
        "totalsupply": "See the current token supply.",
        "allowance": "Check how much one address can spend on another address's tokens.",
        "getreserves": "Inspect the pool reserves and current token balances.",
    }
    if lowered in reasons:
        return reasons[lowered]
    display=_function_display_name(item)
    if item.get("stateMutability") in {"view","pure"}:
        return f"Inspect {display} without changing contract state."
    return f"Use it to inspect the state related to {display}."


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
        root = audit_context.foundry_project_root()
        tx_label = walkthrough._transaction_link(root, tx_hash)
        lines.append(f"Tx hash:   {tx_label}")
        evidence = walkthrough._transaction_evidence_path(root, tx_hash)
        if evidence.is_file():
            lines.append("Confirm:   Ctrl+Click the tx hash to open Lowkey's on-chain evidence page")

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
    function_item=None
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
                function_item=matches[0]
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
                rpc = effective_rpc(config)
                receipt = walkthrough._receipt(rpc, tx_hash) if rpc else None
                step = walkthrough.Step(
                    0,
                    str(config.get("actor") or "Caller"),
                    str(config.get("target_contract") or "Transaction"),
                    str(config.get("target") or "0x" + "00" * 20),
                    str(call or "transaction"),
                    [],
                    status="success" if isinstance(receipt, dict) and receipt.get("status") in ("0x1", 1, None) else "reverted",
                    tx_hash=tx_hash,
                )
                walkthrough._write_transaction_evidence(root, rpc or "", step, receipt)
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
            elif cast_cmd=="call" and function_item and function_item.get("outputs"):
                output_payload=str(out).strip()
                signature=format_output_signature(function_item)
                decoded,decode_error=decode_abi_output(signature,output_payload)
                if decode_error is None:
                    print(format_human_abi_return(function_item,decoded,config,abi))
                else:
                    print(
                        f"Return: ABI decoding failed for {signature}.",
                        file=sys.stderr,
                    )
                    print(f"  Reason: {decode_error}", file=sys.stderr)
                    print(f"  Raw return data: {apply_labels(output_payload,config)}")
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
    root = audit_context.foundry_project_root()
    paths = workspace_paths(root)
    os.makedirs(paths["root"], exist_ok=True)
    line = f"- [{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}\n"
    with open(paths["findings"], "a", encoding="utf-8") as f:
        f.write(line)

    # Keep manually recorded findings in the same project-scoped ledger as analyzer signals.
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

def project_root_for_scope(base, workspace_root_path):
    try:
        from project_detection import workspace_selection
        selected = workspace_selection(workspace_root_path)
    except Exception:
        selected = None
    return Path(selected or base).resolve()

def workspace_paths(root=None):
    base = Path(root or Path.cwd()).expanduser().resolve()
    if root is None:
        try:
            from project_detection import workspace_root, workspace_selection
            ws_root = workspace_root(base)
            selected = workspace_selection(ws_root)
            project_root = Path(selected or project_root_for_scope(base, ws_root)).resolve()
        except Exception:
            project_root = Path(audit_context.foundry_project_root(base)).expanduser().resolve()
    else:
        project_root = Path(audit_context.foundry_project_root(base)).expanduser().resolve()
    workspace_dir = project_root / ".audit"
    return {
        "root": str(workspace_dir),
        "matrix": os.path.join(workspace_dir, "matrix"),
        "matrix_actors": os.path.join(workspace_dir, "matrix", "actors.json"),
        "matrix_states": os.path.join(workspace_dir, "matrix", "states.json"),
        "matrix_scenarios": os.path.join(workspace_dir, "matrix", "scenarios.json"),
        "notes": os.path.join(workspace_dir, "notes.md"),
        "todos": os.path.join(workspace_dir, "TODO.md"),
        "config": os.path.join(workspace_dir, "config.json"),
        "findings": os.path.join(workspace_dir, "findings.md"),
        "session": os.path.join(workspace_dir, "history", "session.log"),
    }

def run_workspace(config,args,root=None):
    paths=workspace_paths(root); action=args[0] if args else "init"
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
    root = audit_context.foundry_project_root()
    paths=workspace_paths(root)
    export_dir=os.path.join(str(root),"audit-report")
    os.makedirs(export_dir,exist_ok=True)
    _sync_security_patterns(root)
    lines=["# LowkeyCast Audit Report","",f"- Target: {config.get('target') or 'Not set'}",f"- RPC: {rpc_display(effective_rpc(config)) or 'Not set'}",f"- ABI: {config.get('abi_paths',{}).get(config.get('target')) or 'Auto-discovered when needed'}",f"- Last transaction: {config.get('last_tx') or 'None'}",f"- Generated: {datetime.now().isoformat(timespec='seconds')}","","## Security Pattern Signals",""]
    patterns = audit_context.security_patterns(root)
    if patterns:
        for item in patterns:
            verification = str(item.get("verification_status") or "CANDIDATE")
            lines.append(
                f"- {item.get('pattern_id') or item.get('check')}: {item.get('title')} "
                f"({verification}) — {item.get('file') or 'unknown'}:{item.get('line') or '?'}"
            )
            if item.get("description"):
                lines.append(f"  - Observation: {item.get('description')}")
    else:
        lines.append("No security-pattern signals recorded.")
    lines += ["", "## Findings", ""]
    finding_path=paths["findings"] if os.path.exists(paths["findings"]) else os.path.join(AUDIT_DIR,"findings.md")
    lines.append(Path(finding_path).read_text(encoding="utf-8") if os.path.exists(finding_path) else "No findings recorded.")
    lines += ["","## Checklist",""]
    checklist_path=os.path.join(paths["root"],"CHECKLIST.md")
    lines.append(Path(checklist_path).read_text(encoding="utf-8") if os.path.exists(checklist_path) else "No checklist initialized.")
    Path(os.path.join(export_dir,"report.md")).write_text("\n".join(lines),encoding="utf-8")
    for name,source in [("notes.md",paths["notes"]),("TODO.md",paths["todos"]),("session.log",paths["session"]),("matrix_actors.json",paths["matrix_actors"]),("matrix_states.json",paths["matrix_states"]),("matrix_scenarios.json",paths["matrix_scenarios"])]:
        if os.path.exists(source): Path(os.path.join(export_dir,name)).write_text(Path(source).read_text(encoding="utf-8"),encoding="utf-8")
    Path(os.path.join(export_dir,"contract.json")).write_text(json.dumps({"target":config.get("target"),"rpc":rpc_display(effective_rpc(config)),"abi":config.get("abi_paths",{}).get(config.get("target")),"last_tx":config.get("last_tx")},indent=4),encoding="utf-8")
    print(f"Audit report exported: {export_dir}")
def run_self_test():
    alias_address = "0x" + "1" * 40
    alias_config = {"aliases": {}, "targets": {}, "project_roots": {}}
    alias_root = audit_context.foundry_project_root()
    remember_project_target(alias_config, alias_root, "one", alias_address)

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
        ("target alias resolution",resolve_target_ref(alias_config,"one",alias_root)==alias_address),
        ("safe solidity identifier",solidity_identifier("unauthorized release #1")=="unauthorized_release__1"),
        ("solidity address literal","address(uint160(0x00" in solidity_address_literal("0x"+"1"*40)),
        ("lab options",split_lab_options(["release","1","--actor","Alice","--value","1ether"])[1:] == ("Alice","1ether",False)),
    ]
    failed=[name for name,passed in checks if not passed]
    for name,passed in checks: print(f"{'PASS' if passed else 'FAIL'}  {name}")
    if failed:
        print("Self-test failed: "+", ".join(failed)); return 1
    print(f"Self-test passed ({len(checks)} checks)."); return 0

def _doctor_advice(name, *, why, fix):
    print(f"      WHY : {why}")
    print(f"      FIX : {fix}")


def _doctor_tool(name, required=True):
    path = shutil.which(name)
    if not path:
        label = "FAIL" if required else "NOTE"
        print(f"{label:<5} {name}: not found on PATH")
        _doctor_advice(
            name,
            why="Lowkey cannot invoke this tool from your current shell.",
            fix="Install it or fix PATH. For Foundry tools, run 'foundryup' and restart the shell."
            if name in {"forge", "cast", "anvil", "chisel"} else
            "Install Python 3 and make sure 'python3' is on PATH."
            if name == "python3" else
            "Install Slither (for example with 'pipx install slither-analyzer') if you want static-analysis support.",
        )
        return not required
    try:
        result = subprocess.run([path, "--version"], capture_output=True, text=True)
    except OSError as exc:
        print(f"FAIL  {name}: could not execute {path}")
        _doctor_advice(name, why=str(exc), fix="Check execute permissions and PATH, then retry 'lk doctor'.")
        return False
    output = (result.stdout or result.stderr or "").strip().splitlines()
    version = output[0] if output else "version unavailable"
    if result.returncode == 0:
        print(f"PASS  {name}: {path} ({version})")
        return True
    print(f"FAIL  {name}: {path} ({version})")
    detail = (result.stderr or result.stdout or "version command failed").strip().splitlines()
    _doctor_advice(
        name,
        why=detail[-1] if detail else "Version check failed.",
        fix="Reinstall/update the tool and verify it runs directly from the shell.",
    )
    return False


def run_doctor():
    failures = 0
    print("LOWKEY DOCTOR")
    print("=" * 72)

    runtime = runtime_sync_status()
    label = {"ok": "PASS", "stale": "FAIL", "corrupt": "FAIL"}.get(runtime.get("status"), "NOTE")
    print(f"{label:<5} runtime: {runtime.get('status', 'unknown').upper()}")
    print(f"      {runtime.get('detail', '')}")
    if runtime.get("status") in {"stale", "corrupt"}:
        failures += 1
        source_repo = runtime.get("source_repo")
        fix = "Run 'bash install.sh' from the Lowkey checkout."
        if source_repo:
            fix = f"Run 'cd {source_repo} && bash install.sh' to republish the runtime."
        _doctor_advice(
            "runtime",
            why="The installed Lowkey modules do not match the runtime recorded by the installer.",
            fix=fix,
        )

    root = audit_context.foundry_project_root()
    foundry_project = (root / "foundry.toml").is_file()
    info = detect_project(root) if detect_project is not None else {
        "root": str(root),
        "backend": "generic",
        "build_backend": "generic",
        "languages": {},
    }
    if project_tools is not None:
        try:
            source_files = project_tools.project_source_files(root, {"sol", "vy", "vyi"})
        except Exception:
            source_files = []
    else:
        source_files = []
    vyper_project = any(path.suffix.lower() in {".vy", ".vyi"} for path in source_files)

    if bootstrap_status is not None:
        try:
            status = bootstrap_status(info)
            print("")
            print("DEPENDENCY / WORKSPACE STATUS")
            print("=============================")
            print(f"Workspace root  : {status.get('workspace_root')}")
            print(f"Dependency root : {status.get('dependency_root')}")
            if status.get("runtime_requirements"):
                print("Runtime pins    : " + ", ".join(
                    f"{k}={v}" for k, v in status["runtime_requirements"].items()
                ))
            actions = status.get("actions") or []
            if actions:
                print("Repair plan     : available (not executed by doctor)")
                for action in actions[:8]:
                    print(
                        f"  - {action.get('kind')}: "
                        f"{' '.join(str(item) for item in action.get('command', []))}"
                    )
            else:
                print("Repair plan     : none needed")
        except Exception as exc:
            print(f"NOTE  bootstrap diagnostics unavailable: {exc}")

    required_tools = ["python3", "cast", "anvil"]
    optional_project_tools = []
    if foundry_project:
        required_tools.append("forge")
    else:
        optional_project_tools.append(
            ("forge", "this project has no foundry.toml, so Forge is not required for Lowkey's core runtime")
        )
    if vyper_project:
        required_tools.append("vyper")
    else:
        optional_project_tools.append(
            ("vyper", "no Vyper sources were detected in the current project")
        )

    for name in required_tools:
        if not _doctor_tool(name, required=True):
            failures += 1

    for name, why in optional_project_tools:
        if shutil.which(name):
            _doctor_tool(name, required=False)
        else:
            print(f"NOTE  {name}: not found (not required for this project)")
            _doctor_advice(
                name,
                why=why,
                fix=f"Install {name} only when you work on projects that require it.",
            )

    # Chisel is a convenience REPL, not a Lowkey prerequisite.
    if shutil.which("chisel"):
        _doctor_tool("chisel", required=False)
    else:
        print("NOTE  chisel: not found (optional Foundry REPL)")

    slither = shutil.which("slither")
    if slither:
        try:
            result = subprocess.run([slither, "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                version = (result.stdout or result.stderr).strip().splitlines()[0]
                print(f"PASS  slither: {slither} ({version})")
            else:
                print(f"WARN  slither: {slither} (version check failed)")
                _doctor_advice(
                    "slither",
                    why=(result.stderr or result.stdout or "version check failed").strip().splitlines()[-1],
                    fix="Reinstall with 'pipx install -f slither-analyzer' or repair the current Python environment.",
                )
        except OSError as exc:
            print(f"WARN  slither: {slither}")
            _doctor_advice("slither", why=str(exc), fix="Repair the Slither installation or PATH.")
    else:
        print("NOTE  slither: not found (optional static analyzer)")
        _doctor_advice(
            "slither",
            why="Slither is optional, so Lowkey can still run without it.",
            fix="Install it with 'pipx install slither-analyzer' when you want static-analysis checks.",
        )

    forge = shutil.which("forge")
    if forge:
        try:
            result = subprocess.run([forge, "--help"], capture_output=True, text=True)
            available = {
                line.strip().split()[0]
                for line in result.stdout.splitlines()
                if line.startswith("  ") and line.strip() and not line.strip().startswith("-")
            }
            advertised = set(FORGE_NATIVE_COMMANDS)
            missing = sorted(advertised - available)
            if missing:
                print(f"FAIL  forge commands missing: {', '.join(missing)}")
                _doctor_advice(
                    "forge commands",
                    why="The installed Forge does not advertise all features Lowkey expects.",
                    fix="Update Foundry with 'foundryup', restart the shell, then rerun 'lk doctor'.",
                )
                failures += 1
            else:
                print(f"PASS  forge commands: {', '.join(sorted(advertised))}")
        except OSError as exc:
            print("FAIL  forge command check")
            _doctor_advice("forge command check", why=str(exc), fix="Repair the Foundry installation and rerun 'lk doctor'.")
            failures += 1

    if forge:
        try:
            help_result = subprocess.run([forge, "test", "--help"], capture_output=True, text=True)
            help_text = (help_result.stdout or "") + (help_result.stderr or "")
            for label, flag in (
                ("forge mutation", "--mutate"),
                ("forge symbolic", "--symbolic"),
                ("forge brutalize", "--brutalize"),
                ("forge rerun", "--rerun"),
            ):
                if flag in help_text:
                    print(f"PASS  {label}: {flag}")
                else:
                    print(f"FAIL  {label}: {flag} not advertised by this Forge")
                    _doctor_advice(
                        label,
                        why=f"Forge 1.8.x feature check did not find {flag}.",
                        fix="Update Foundry with 'foundryup' and rerun 'lk doctor'.",
                    )
                    failures += 1
        except OSError as exc:
            print("FAIL  forge test feature check")
            _doctor_advice("forge test features", why=str(exc), fix="Repair Foundry and rerun 'lk doctor'.")
            failures += 1

    capability_checks = [
        ("cast decode-event", "cast", "decode-event"),
        ("cast receipt", "cast", "receipt"),
        ("cast sig-event", "cast", "sig-event"),
        *([("forge inspect", "forge", "inspect")] if foundry_project else []),
        ("cast pretty-calldata", "cast", "pretty-calldata"),
        ("cast tx-pool", "cast", "tx-pool"),
        ("cast disassemble", "cast", "disassemble"),
    ]
    for label, binary, subcommand in capability_checks:
        executable = shutil.which(binary)
        if not executable:
            print(f"FAIL  dependency command: {label} (binary not found)")
            _doctor_advice(
                label,
                why=f"{binary} is missing, so {subcommand} cannot be used.",
                fix="Install/update Foundry with 'foundryup', then restart the shell and rerun 'lk doctor'.",
            )
            failures += 1
            continue
        try:
            result = subprocess.run([executable, "--help"], capture_output=True, text=True)
            help_text = (result.stdout or "") + (result.stderr or "")
        except OSError as exc:
            print(f"FAIL  dependency command: {label}")
            _doctor_advice(
                label,
                why=str(exc),
                fix="Repair the Foundry installation and rerun 'lk doctor'.",
            )
            failures += 1
            continue

        advertised = bool(re.search(rf"(?m)^\s*{re.escape(subcommand)}(?:\s|$)", help_text))
        if advertised:
            print(f"PASS  dependency command: {label}")
        else:
            print(f"FAIL  dependency command: {label}")
            _doctor_advice(
                label,
                why=f"{binary} is installed, but its top-level help does not advertise '{subcommand}'.",
                fix="Update Foundry with 'foundryup'. If the command was removed/renamed by your Foundry version, use 'lk --help' to see the Lowkey alternative.",
            )
            failures += 1

    root = audit_context.foundry_project_root() if "audit_context" in globals() else None
    if root:
        print()
        print("PROJECT DIAGNOSTICS")
        print("-" * 72)
        print(f"Project : {root}")

        if foundry_project and forge and shutil.which("forge"):
            try:
                result = subprocess.run(
                    [forge, "build", "--skip", "test", "--skip", "script"],
                    cwd=str(root),
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    print("PASS  project build: Forge can compile the application sources.")
                else:
                    print("FAIL  project build: Forge could not compile the application sources.")
                    combined = (result.stdout or "") + "\n" + (result.stderr or "")
                    lines = [line.strip() for line in combined.splitlines() if line.strip()]
                    useful = [
                        line for line in lines
                        if "Error" in line or "not found" in line or "Source" in line
                    ]
                    for line in (useful[-3:] if useful else lines[-3:]):
                        print(f"      {line}")
                    if "not found" in combined.lower() or (
                        "source" in combined.lower() and "not found" in combined.lower()
                    ):
                        fix = "Run 'forge install' if a dependency is missing, then check remappings with 'forge remappings'."
                    elif "checksum" in combined.lower():
                        fix = "Regenerate the affected Lowkey artifact/PoC with the current branch, then rerun 'lk build'."
                    else:
                        fix = "Fix the reported Solidity/Foundry error above, then rerun 'lk build' and 'lk doctor'."
                    _doctor_advice(
                        "project build",
                        why="The current Foundry project does not compile with the active toolchain.",
                        fix=fix,
                    )
                    failures += 1
            except OSError as exc:
                print("FAIL  project build: could not invoke Forge")
                _doctor_advice(
                    "project build",
                    why=str(exc),
                    fix="Repair Foundry, then rerun 'lk doctor'.",
                )
                failures += 1

        elif vyper_project and shutil.which("vyper"):
            sample = next(
                (path for path in source_files if path.suffix.lower() == ".vy"),
                None,
            )
            if sample:
                try:
                    result = subprocess.run(
                        ["vyper", "-f", "abi", str(sample)],
                        cwd=str(root),
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode == 0:
                        print("PASS  project build: Vyper compiler can compile a source contract.")
                    else:
                        print("FAIL  project build: Vyper compiler rejected a source contract.")
                        detail = (result.stderr or result.stdout or "Vyper compilation failed").strip().splitlines()
                        _doctor_advice(
                            "project build",
                            why=detail[-1] if detail else "Vyper compilation failed.",
                            fix="Fix the reported Vyper error, then rerun 'lk doctor'.",
                        )
                        failures += 1
                except OSError as exc:
                    print("FAIL  project build: could not invoke Vyper")
                    _doctor_advice(
                        "project build",
                        why=str(exc),
                        fix="Repair the Vyper installation and rerun 'lk doctor'.",
                    )
                    failures += 1

        elif source_files:
            print("NOTE  project build: no native project build system was selected by Lowkey.")
            print("      Lowkey will use available ABI/artifact tooling for this project.")
        else:
            print("NOTE  project build: no Solidity/Vyper source files detected.")

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
import {{Test}} from "forge-std/Test.sol";

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
    root = audit_context.foundry_project_root()
    test_dir = Path(root) / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    filename=str(test_dir / f"Exploit_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.t.sol")
    Path(filename).write_text(test,encoding="utf-8")
    print(f"Exploit reproduction generated: {filename}")
    root=audit_context.foundry_project_root()
    audit_context.record_tool("generator",root,status="completed",summary="exploit reproduction generated",data={"mode":"test-gen","output":filename,"function":func,"target":target})
def run_checklist(config,action=None,item=None):
    root = audit_context.foundry_project_root()
    path = os.path.join(workspace_paths(root)["root"], "CHECKLIST.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        Path(path).write_text("\n".join(f"- [ ] {x}" for x in AUDIT_CHECKLIST)+"\n", encoding="utf-8")
    lines=Path(path).read_text(encoding="utf-8").splitlines(True)
    if action=="reset":
        Path(path).write_text("\n".join(f"- [ ] {x}" for x in AUDIT_CHECKLIST)+"\n", encoding="utf-8")
        print("Checklist reset.")
        return
    if action=="done" and item:
        q=item.lower()
        for i,line in enumerate(lines):
            if q in line.lower() and "[ ]" in line:
                lines[i]=line.replace("[ ]","[x]",1)
                Path(path).write_text("".join(lines),encoding="utf-8")
                print(f"Marked complete: {line.strip()[6:]}")
                return
        print(f"Checklist item not found: {item}")
        return
    print("".join(lines))

def _project_target_entries(config, root=None):
    """Build a target list from the current project only, enriched with provenance."""
    project_root = Path(audit_context.foundry_project_root(root)).resolve()
    entries = []
    deployment_records = discover_deployments(project_root)
    deployment_by_address = {}
    for record in deployment_records:
        address = record.get("address")
        if not is_address(address):
            continue
        key = str(address).lower()
        existing = deployment_by_address.get(key)
        if existing is None:
            deployment_by_address[key] = record
            continue
        existing_ts = existing.get("run_timestamp") or 0
        current_ts = record.get("run_timestamp") or 0
        if current_ts >= existing_ts:
            deployment_by_address[key] = record

    def resolve_artifact(contract, address=None):
        if address:
            configured = config.get("abi_paths", {}).get(address)
            if configured:
                configured_path = Path(os.path.expanduser(str(configured)))
                if not configured_path.is_absolute():
                    configured_path = project_root / configured_path
                if configured_path.is_file():
                    return str(configured_path.resolve())

        contract_name = str(contract or "").strip().lower()
        if contract_name:
            for path in local_artifact_paths(project_root):
                artifact_data = read_artifact(path) or {}
                if artifact_contract_name(path, artifact_data).lower() == contract_name:
                    return path

        if address:
            lookup_config = dict(config)
            lookup_config["target_contract"] = contract
            return auto_abi_path(address, lookup_config)
        return None

    def source_from_artifact(artifact, contract):
        if artifact:
            artifact_data = read_artifact(artifact) or {}
            source_name = artifact_source_name(artifact_data, artifact, project_root)
            if source_name:
                return str(source_name)
            fallback = source_contract_fallback(
                project_root, artifact_contract_name(artifact, artifact_data)
            )
            if fallback:
                return str(fallback)
        return str(source_contract_fallback(project_root, contract) or "") or None

    def deployment_metadata(address):
        record = deployment_by_address.get(str(address).lower()) if is_address(address) else None
        if not record:
            return {}
        deployment_file = record.get("file")
        run_timestamp = record.get("run_timestamp")
        if run_timestamp and deployment_file:
            # Prefer the timestamped file for display when Foundry also has
            # run-latest.json for the same run.
            candidate = Path(deployment_file).parent / f"run-{int(run_timestamp) * 1000}.json"
            if candidate.is_file():
                deployment_file = str(candidate)
        return {
            "deployment_file": deployment_file,
            "deployment_hash": record.get("hash"),
            "deployment_run_timestamp": run_timestamp,
            "deployment_run_key": (
                f"{Path(record['file']).parent.resolve()}::{run_timestamp}"
                if run_timestamp is not None
                else str(Path(record["file"]).resolve())
            ),
        }

    def enrich(entry):
        address = entry.get("address")
        metadata = deployment_metadata(address)
        contract = entry.get("contract") or entry.get("name")

        if not entry.get("artifact"):
            entry["artifact"] = resolve_artifact(contract, address)
        if (
            (not entry.get("artifact") or str(contract or "").strip().lower() == "unknown")
            and is_address(address)
        ):
            for candidate_path in local_artifact_paths(project_root):
                candidate_artifact = read_artifact(candidate_path) or {}
                candidate_name = artifact_contract_name(candidate_path, candidate_artifact)
                if not artifact_is_project_application(project_root, candidate_path, candidate_artifact):
                    continue
                if _live_target_artifact_match(config, address, candidate_artifact):
                    entry["artifact"] = candidate_path
                    entry["contract"] = candidate_name
                    entry["name"] = candidate_name
                    contract = candidate_name
                    break
        if not entry.get("source_file"):
            entry["source_file"] = source_from_artifact(entry.get("artifact"), contract)
        if not entry.get("deployment_file"):
            entry["deployment_file"] = metadata.get("deployment_file")
        if entry.get("deployment_hash") is None:
            entry["deployment_hash"] = metadata.get("deployment_hash")
        if entry.get("deployment_run_timestamp") is None:
            entry["deployment_run_timestamp"] = metadata.get("deployment_run_timestamp")
        if entry.get("deployment_run_key") is None:
            entry["deployment_run_key"] = metadata.get("deployment_run_key")
        return entry

    context_target = project_context_target(project_root)
    if context_target:
        artifact = context_target.get("artifact")
        entries.append(enrich({
            "name": context_target.get("contract") or "target",
            "address": context_target.get("address"),
            "artifact": artifact,
            "source_file": context_target.get("source_file"),
            "deployment_file": context_target.get("deployment_file"),
            "deployment_hash": context_target.get("deployment_hash"),
            "deployment_run_timestamp": context_target.get("deployment_run_timestamp"),
            "deployment_run_key": context_target.get("deployment_run_key"),
            "contract": context_target.get("contract"),
            "source": context_target.get("source") or "project-context",
        }))

    for name, address in target_aliases(config, project_root).items():
        if any(str(item.get("address")).lower() == str(address).lower() for item in entries):
            continue
        artifact = config.get("abi_paths", {}).get(address)
        entries.append(enrich({
            "name": name,
            "address": address,
            "artifact": artifact,
            "source_file": None,
            "deployment_file": None,
            "deployment_hash": None,
            "deployment_run_timestamp": None,
            "deployment_run_key": None,
            "contract": name,
            "source": "project-config",
        }))

    for record in deployment_records:
        address = record.get("address")
        if not is_address(address):
            continue
        if any(str(item.get("address")).lower() == str(address).lower() for item in entries):
            continue
        contract = record.get("contract") or "Unknown"
        entries.append(enrich({
            "name": contract,
            "address": address,
            "artifact": None,
            "source_file": None,
            "deployment_file": record.get("file"),
            "deployment_hash": record.get("hash"),
            "deployment_run_timestamp": record.get("run_timestamp"),
            "deployment_run_key": None,
            "contract": contract,
            "source": "broadcast",
        }))
    return entries

def _target_entry_is_protocol(root, entry):
    """Return True for contracts that belong to the protocol, not its test/fixture support."""
    name = str(entry.get("name") or entry.get("contract") or "").strip()
    lowered_name = name.lower()
    if any(token in lowered_name for token in ("mock", "fixture", "test")):
        return False
    if lowered_name in {"erc1967proxy", "erc1967beaconproxy", "stake_token"}:
        return False

    artifact = entry.get("artifact")
    if artifact:
        try:
            artifact_path = Path(os.path.expanduser(str(artifact)))
            if not artifact_path.is_absolute():
                artifact_path = Path(root) / artifact_path
            relative = artifact_path.resolve().relative_to(Path(root).resolve()).as_posix().lower()
            support_parts = (
                "/test/", "/tests/", "/mock/", "/mocks/", "/fixture/", "/fixtures/",
                "/script/", "/scripts/", "/node_modules/",
            )
            if relative.startswith((
                "test/", "tests/", "mock/", "mocks/", "fixture/", "fixtures/",
                "script/", "scripts/", "node_modules/",
            )) or any(part in relative for part in support_parts):
                return False

            source_file = entry.get("source_file")
            if source_file and universal_is_dependency_path is not None:
                source_path = Path(str(source_file))
                if not source_path.is_absolute():
                    source_path = Path(root) / source_path
                try:
                    if universal_is_dependency_path(source_path, Path(root)):
                        return False
                except (OSError, ValueError):
                    pass
        except (OSError, ValueError):
            pass

    return True


def _select_project_target(config, entry, root):
    address = entry.get("address")
    if not is_address(address):
        return fail("Error: selected target has an invalid address.")

    # A remembered address is not a live protocol target merely because it has
    # an ABI/source artifact. On local EVM labs, reject EOAs and stale addresses
    # before they can become the active audit target.
    # Only validate against an explicitly configured RPC. A discovered/default
    # Anvil endpoint is not enough to prove that a remembered project target
    # belongs to the current live audit session.
    rpc = config.get("rpc")
    if rpc:
        try:
            code, runtime, _ = cast_output(["cast", "code", address, "--rpc-url", rpc])
        except Exception:
            code, runtime = 1, ""
        if code == 0 and str(runtime or "").strip().lower() in {"", "0x", "0x0"}:
            return fail(
                f"Error: {address} has no contract bytecode on {rpc}. "
                "Run 'lk lab' to deploy or refresh a live local target.",
                1,
            )

    contract = entry.get("contract") or entry.get("name") or "target"
    artifact = entry.get("artifact")
    if not artifact:
        artifact = auto_abi_path(address, config)

    config["target"] = address
    config["target_contract"] = contract
    if artifact:
        config.setdefault("abi_paths", {})[address] = artifact
    remember_project_target(config, root, entry.get("name") or contract, address)
    save_config(config)
    audit_context.set_target(
        root,
        address=address,
        contract=contract,
        artifact=artifact,
        source=entry.get("source") or "project",
    )
    print(f"Target selected: {entry.get('name') or contract} -> {address}")
    if entry.get("source_file"):
        print(f"  Source       : {entry.get('source_file')}")
    if entry.get("artifact"):
        try:
            artifact_display = str(Path(entry.get("artifact")).resolve().relative_to(Path(root).resolve()))
        except (OSError, ValueError):
            artifact_display = str(entry.get("artifact"))
        print(f"  Artifact     : {artifact_display}")
    if entry.get("deployment_file"):
        try:
            deployment_display = str(Path(entry.get("deployment_file")).resolve().relative_to(Path(root).resolve()))
        except (OSError, ValueError):
            deployment_display = str(entry.get("deployment_file"))
        print(f"  Deployment   : {deployment_display}")
    elif entry.get("source") in {"project-context", "project-config", "manual"}:
        print(f"  Origin       : {entry.get('source')}")
    return 0


def run_targets(config, interactive=False, include_support=False):
    """Show/select deployed protocol contracts grouped by deployment run."""
    root = audit_context.foundry_project_root()
    entries = _project_target_entries(config, root)

    protocol_entries = [entry for entry in entries if _target_entry_is_protocol(root, entry)]
    support_entries = [entry for entry in entries if not _target_entry_is_protocol(root, entry)]
    visible_entries = entries if include_support else protocol_entries

    if not visible_entries:
        print(f"No protocol targets found for project: {root}")
        print("Build/deploy the protocol, then run 'lk targets --all' to inspect lab support contracts.")
        return 0

    current = active_project_target(config, root) or project_context_target(root)
    current_address = current.get("address") if isinstance(current, dict) else current

    def run_label(timestamp):
        if timestamp is None:
            return "REMEMBERED / PROJECT TARGETS"
        try:
            rendered = datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
            return f"DEPLOYMENT RUN  {rendered}"
        except (TypeError, ValueError, OSError, OverflowError):
            return f"DEPLOYMENT RUN  {timestamp}"

    groups = {}
    group_order = []
    for entry in visible_entries:
        key = entry.get("deployment_run_key") or f"entry::{entry.get('address')}"
        if key not in groups:
            groups[key] = []
            group_order.append(key)
        groups[key].append(entry)

    def group_sort_key(key):
        group = groups[key]
        timestamp = group[0].get("deployment_run_timestamp")
        if timestamp is None:
            return (-1, key)
        try:
            return (int(timestamp), key)
        except (TypeError, ValueError):
            return (0, key)

    group_order.sort(key=group_sort_key, reverse=True)

    latest_run_key = next(
        (key for key in group_order if groups[key][0].get("deployment_run_timestamp") is not None),
        None,
    )

    print("AUDIT TARGETS")
    print("=============")
    print(root)
    for key in group_order:
        group = groups[key]
        timestamp = group[0].get("deployment_run_timestamp")
        label = run_label(timestamp)
        if key == latest_run_key:
            label += "  [LATEST]"
        print()
        print(label)
        print("-" * len(label))
        for index, entry in enumerate(visible_entries, 1):
            if entry not in group:
                continue
            marker = "*" if str(entry.get("address")).lower() == str(current_address or "").lower() else " "
            print(
                f" {marker} {index:>2}. "
                f"{entry.get('name') or entry.get('contract') or 'target':<28} "
                f"{entry.get('address')}"
            )
            source_file = entry.get("source_file")
            deployment_file = entry.get("deployment_file")
            if source_file:
                print(f"        Source       : {source_file}")
            artifact = entry.get("artifact")
            if artifact:
                try:
                    artifact_display = str(Path(artifact).resolve().relative_to(Path(root).resolve()))
                except (OSError, ValueError):
                    artifact_display = str(artifact)
                print(f"        Artifact     : {artifact_display}")
            if deployment_file:
                try:
                    deployment_display = str(Path(deployment_file).resolve().relative_to(Path(root).resolve()))
                except (OSError, ValueError):
                    deployment_display = str(deployment_file)
                print(f"        Deployment   : {deployment_display}")
            elif entry.get("source") in {"project-context", "project-config", "manual"}:
                print(f"        Origin       : {entry.get('source')}")

    if support_entries and not include_support:
        print()
        print(f"Lab/test support hidden: {len(support_entries)}")
        print("Use 'lk targets --all' when you need to inspect those addresses.")

    pattern_summary = _security_pattern_summary(root)
    print()
    print(
        "SECURITY SCOPE : "
        f"{pattern_summary['total']} pattern(s) — "
        f"{pattern_summary['reviews']} review, "
        f"{pattern_summary['confirmed']} confirmed, "
        f"{pattern_summary['candidates']} candidate"
    )

    if not interactive:
        return 0

    try:
        choice = input(f"Select audit target [1-{len(visible_entries)}] (Enter to cancel): ").strip()
    except EOFError:
        print()
        return 0
    if not choice:
        return 0
    if not choice.isdigit() or not (1 <= int(choice) <= len(visible_entries)):
        print("Invalid target selection.")
        return 0
    return _select_project_target(config, visible_entries[int(choice) - 1], root)

def _minimal_proxy_implementation(runtime):
    """Extract the implementation address from a standard ERC-1167 clone runtime."""
    raw = str(runtime or "").strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    patterns = (
        r"^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$",
        r"^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, raw)
        if match:
            return "0x" + match.group(1)
    return None


def _live_runtime(config, address):
    rpc = effective_rpc(config)
    if not rpc or not is_address(address):
        return None
    try:
        code, runtime, _ = cast_output(["cast", "code", address, "--rpc-url", rpc])
    except Exception:
        return None
    if code != 0:
        return None
    runtime = str(runtime or "").strip()
    if not runtime or runtime.lower() in {"0x", "0x0"}:
        return None
    return runtime


def _artifact_runtime_matches(path, artifact, runtime):
    deployed = artifact.get("deployedBytecode") if isinstance(artifact, dict) else None
    if isinstance(deployed, dict):
        deployed = deployed.get("object")
    deployed = str(deployed or "").strip().lower()
    runtime = str(runtime or "").strip().lower()
    if deployed and deployed not in {"0x", "0x0"} and deployed == runtime:
        return "runtime"
    return None


def _live_target_artifact_match(config, address, artifact):
    """Match direct deployments and common proxy/clone instances to an artifact."""
    runtime = _live_runtime(config, address)
    if not runtime:
        return None

    direct = _artifact_runtime_matches("", artifact, runtime)
    if direct:
        return direct

    implementation = _minimal_proxy_implementation(runtime)
    if not implementation:
        rpc = effective_rpc(config)
        if rpc:
            try:
                code, impl, _ = cast_output(
                    ["cast", "implementation", address, "--rpc-url", rpc]
                )
            except Exception:
                code, impl = 1, ""
            if code == 0 and is_address(str(impl or "").strip()):
                implementation = str(impl).strip()
    if implementation:
        implementation_runtime = _live_runtime(config, implementation)
        if implementation_runtime and _artifact_runtime_matches("", artifact, implementation_runtime):
            return "clone-or-proxy"
    return None


def discover_deployments(root="."):
    records=[]
    root_path = Path(root).resolve()
    for path in artifact_json_files(root):
        try:
            path_obj = Path(path).resolve()
            path_obj.relative_to(root_path / "broadcast")
        except (OSError, ValueError):
            continue
        try:
            payload=json.loads(path_obj.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError):
            continue
        txs=payload.get("transactions",[]) if isinstance(payload,dict) else []
        if not isinstance(txs,list): continue
        mtime=os.path.getmtime(path)
        run_timestamp=payload.get("timestamp") if isinstance(payload,dict) else None
        try:
            run_timestamp=int(run_timestamp)
        except (TypeError,ValueError):
            run_timestamp=None

        def collect(tx, parent=None, additional=False):
            if not isinstance(tx, dict):
                return
            tx_type=str(tx.get("transactionType","")).upper()
            address=tx.get("contractAddress") or tx.get("address")
            if tx_type.startswith("CREATE") and is_address(address):
                records.append({
                    "contract":tx.get("contractName") or "Unknown",
                    "address":address,
                    "file":path,
                    "time":mtime,
                    "hash":tx.get("hash") or (parent or {}).get("hash"),
                    "run_timestamp":run_timestamp,
                    "deployment_kind":"additional" if additional else "transaction",
                    "parent_contract":(parent or {}).get("contractName") if additional else None,
                    "parent_hash":(parent or {}).get("hash") if additional else None,
                })
            children = tx.get("additionalContracts")
            if isinstance(children, dict):
                children = list(children.values())
            if isinstance(children, list):
                for child in children:
                    collect(child, parent=tx, additional=True)

        for tx in txs:
            collect(tx)

        top_additional = payload.get("additionalContracts") if isinstance(payload,dict) else None
        if isinstance(top_additional, dict):
            top_additional = list(top_additional.values())
        if isinstance(top_additional, list):
            for child in top_additional:
                collect(child, parent=None, additional=True)

    # Foundry keeps run-latest.json alongside the timestamped broadcast for
    # the same run. Treat them as one deployment run, not two deployments.
    deduped={}
    for record in records:
        file_path=Path(record["file"])
        try:
            relative_parent = file_path.parent.relative_to(root_path).as_posix()
        except ValueError:
            relative_parent = str(file_path.parent)
        run_identity=(
            relative_parent,
            record.get("run_timestamp"),
            str(record.get("contract") or "").lower(),
            str(record.get("address") or "").lower(),
        )
        existing=deduped.get(run_identity)
        if existing is None:
            deduped[run_identity]=record
            continue
        existing_name=Path(existing["file"]).name
        current_name=file_path.name
        # Prefer the durable timestamped file over run-latest.json when both
        # describe the same deployment transaction.
        if existing_name == "run-latest.json" and current_name != "run-latest.json":
            deduped[run_identity]=record

    return sorted(
        deduped.values(),
        key=lambda x:(x.get("run_timestamp") or 0, x["time"]),
        reverse=True,
    )

def run_deployments(config):
    records=discover_deployments(".")
    if not records: print("No Foundry broadcast deployments discovered."); return
    seen=set()
    for r in records:
        key=(r["contract"],r["address"])
        if key in seen: continue
        seen.add(key); print(f"{r['contract']:<24} {r['address']}  {r['file']}")

def _auto_target_records(config, root, records, requested=None):
    """Rank broadcast targets by application provenance and live runtime identity."""
    artifacts = []
    for path in local_artifact_paths(root):
        artifact = read_artifact(path) or {}
        if artifact_is_project_application(root, path, artifact):
            artifacts.append((path, artifact, artifact_contract_name(path, artifact)))

    requested_lower = str(requested or "").strip().lower()
    ranked = []

    for raw in records:
        record = dict(raw)
        contract = str(record.get("contract") or "Unknown").strip()
        contract_lower = contract.lower()
        score = 0
        artifact_path = None
        resolved_contract = contract if contract_lower != "unknown" else None
        match_kind = None

        if requested_lower and contract_lower == requested_lower:
            score += 5000

        candidates = artifacts
        if requested_lower:
            candidates = [
                item for item in artifacts
                if item[2].strip().lower() == requested_lower
            ]
        elif contract_lower != "unknown":
            exact = [
                item for item in artifacts
                if item[2].strip().lower() == contract_lower
            ]
            if exact:
                candidates = exact

        for path, artifact, artifact_name in candidates:
            if contract_lower != "unknown" and artifact_name.lower() != contract_lower and requested_lower == "":
                continue
            # Preserve the local ABI/source association even when no RPC is
            # configured. Live runtime identity is stronger evidence, but it
            # should enrich rather than gate artifact discovery.
            if artifact_path is None:
                artifact_path = path
                resolved_contract = artifact_name
                score += 500
            match = _live_target_artifact_match(config, record.get("address"), artifact)
            if match:
                artifact_path = path
                resolved_contract = artifact_name
                match_kind = match
                score += 12000 if match == "clone-or-proxy" else 4000
                break

        if resolved_contract:
            lowered = resolved_contract.lower()
            if any(token in lowered for token in ("mock", "fixture", "test", "interface", "library")):
                score -= 10000
            if lowered.endswith("factory"):
                score -= 150
            else:
                score += 150
            if artifact_path:
                score += 500

        if record.get("deployment_kind") == "additional":
            # Nested CREATEs are often deterministic application instances (for
            # example EIP-1167 clones) rather than implementation deployments.
            score += 500

        # A live contract is stronger evidence than a stale broadcast record.
        if _live_runtime(config, record.get("address")):
            score += 100

        if not requested_lower:
            score += int(record.get("run_timestamp") or 0) // 1000000

        record["_score"] = score
        record["_artifact"] = artifact_path
        record["_resolved_contract"] = resolved_contract or contract
        record["_match_kind"] = match_kind
        ranked.append(record)

    if requested_lower:
        ranked = [
            item for item in ranked
            if str(item.get("_resolved_contract") or "").lower() == requested_lower
            and item.get("_score", 0) > -1000
        ]

    ranked.sort(
        key=lambda item: (
            1 if item.get("_match_kind") == "clone-or-proxy" else 0,
            int(item.get("_score") or 0),
            int(item.get("run_timestamp") or 0),
            float(item.get("time") or 0),
        ),
        reverse=True,
    )
    return ranked


def run_auto_target(config,name=None):
    root=audit_context.foundry_project_root()
    records=discover_deployments(root)
    if not records:
        existing=project_context_target(root)
        if existing:
            print(f"Target already remembered for this project: {existing.get('contract') or 'unknown'} -> {existing.get('address')}")
            return 0
        return fail("No deployment found in broadcast/. Build artifacts exist, but a live target still needs deployment.")

    ranked = _auto_target_records(config, root, records, requested=name)
    if not ranked:
        available=", ".join(dict.fromkeys(str(item.get("contract","Unknown")) for item in records))
        return fail(
            f"Error: no application deployment could be resolved for '{name or 'auto'}'."
            + (f" Available broadcasts: {available}" if available else "")
        )

    record=ranked[0]
    contract = record.get("_resolved_contract") or record.get("contract") or "Target"
    alias=name or contract
    remember_project_target(config, root, alias, record["address"])
    config["target"]=record["address"]

    artifact_path=record.get("_artifact")
    if artifact_path:
        config["abi_paths"][record["address"]]=artifact_path
        print(f"ABI auto-loaded: {artifact_path}")

    config["target_contract"]=contract
    save_config(config)
    audit_context.set_target(
        root,
        address=record["address"],
        contract=contract,
        artifact=artifact_path,
        source="auto",
    )
    match_label = record.get("_match_kind")
    if match_label:
        print(f"Runtime match  : {match_label}")
    if record.get("deployment_kind") == "additional":
        parent = record.get("parent_contract") or "deployment transaction"
        print(f"Instance type  : nested CREATE from {parent}")
    print(f"Target selected: {alias} -> {record['address']}")
    return 0


def _local_test_fixture_candidates(root, requested=None):
    """Discover test contracts that can be promoted into disposable local lab harnesses."""
    root = Path(audit_context.foundry_project_root(root) or root).resolve()
    wanted = str(requested or "").strip().lower()
    roots = [root / "test", root / "tests"]
    candidates = []

    for search_root in roots:
        if not search_root.is_dir():
            continue

        for path in sorted(search_root.rglob("*.sol")):
            relative = path.relative_to(root).as_posix()
            parts = {part.lower() for part in path.relative_to(search_root).parts[:-1]}
            if parts & {"mocks", "mock", "fixtures", "fixture"}:
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if not re.search(
                r"(?m)\bfunction\s+setUp\s*\(\s*\)\s+(?:public|external|internal)\b",
                source,
            ):
                continue

            create_match = re.search(
                r"(?m)\bfunction\s+(_?createPool)\s*\(\s*\)\s+(?:internal|public|external)\b([^{]*)\{",
                source,
            )
            if not create_match:
                continue

            declaration = create_match.group(0)
            returns_match = re.search(r"\breturns\s*\(([^)]*)\)", declaration, re.S)
            returns_text = returns_match.group(1) if returns_match else ""

            contract_match = None
            for declaration in re.finditer(
                r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b",
                source,
            ):
                if declaration.start() <= create_match.start():
                    contract_match = declaration
                else:
                    break
            if not contract_match:
                continue
            fixture_contract = contract_match.group(1)

            base_score = 0
            basename = path.name.lower()
            compact = re.sub(r"[^a-z0-9]", "", basename)
            if basename.endswith(".t.sol"):
                base_score += 40
            if "test" in compact:
                base_score += 10
            if "base" in compact:
                base_score += 15
            if "regression" in compact:
                base_score += 10
            base_score += 20

            contract = fixture_contract
            score = base_score
            if wanted:
                wanted_compact = re.sub(r"[^a-z0-9]", "", wanted)
                if wanted_compact and wanted_compact in re.sub(r"[^a-z0-9]", "", source.lower()):
                    score += 300
                if contract.lower() == wanted:
                    score += 500
                elif wanted_compact in contract.lower():
                    score += 150
            if "test" in contract.lower() or "harness" in contract.lower():
                score += 20
            candidates.append({
                "score": score,
                "relative": relative,
                "path": str(path),
                "contract": contract,
                    "create_function": create_match.group(1),
                    "tuple_return": bool(re.search(r"\bbytes\b", returns_text)),
                })

    return sorted(
        candidates,
        key=lambda item: (
            -int(item.get("score") or 0),
            str(item.get("relative") or ""),
            str(item.get("contract") or ""),
        ),
    )


def discover_local_lab_fixture(root=".", requested=None):
    """Return the strongest project-native test fixture Lowkey can safely promote."""
    candidates = _local_test_fixture_candidates(root, requested)
    return candidates[0] if candidates else None


def _fixture_state_files(root, safe_name):
    # Foundry projects may restrict vm.writeFile via fs_permissions. Keep the
    # promoted fixture snapshot under Forge's permitted snapshot directory.
    state_dir = Path(root).resolve() / ".forge-snapshots" / "lowkey"
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / f"fixture_state_{safe_name}.json"


def _generate_test_fixture_lab_script(root, candidate, state_path=None):
    """Generate a test contract so Forge executes the fixture in its native test context."""
    root_path = Path(audit_context.foundry_project_root(root) or root).resolve()
    if state_path is None:
        state_path = root_path / ".audit" / "lab" / "fixture-state.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
    relative = str(candidate["relative"]).replace("\\", "/")
    contract = str(candidate["contract"])
    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", contract)

    state_literal = os.path.relpath(state_path, root_path).replace("\\", "/")
    create_call = (
        f"address target;\n        (target, ) = {candidate['create_function']}();"
        if candidate.get("tuple_return")
        else f"address target = {candidate['create_function']}();"
    )
    test_dir = root_path / "test" / "foundry" / ".lowkey"
    test_dir.mkdir(parents=True, exist_ok=True)
    test_path = test_dir / f"LowkeyAutoFixture_{safe_name}.t.sol"

    code = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {{ {contract} }} from "{relative}";
import {{ console2 }} from "forge-std/console2.sol";
import {{ Vm }} from "forge-std/Vm.sol";

/// @dev Runs the discovered project fixture using Forge's native test runner.
/// The state dump is taken from inside setUp(), immediately after the fixture
/// finishes, while the setup-created contracts are still observable.
contract LowkeyAutoFixtureTest_{safe_name} is {contract} {{
    function setUp() public override {{
        vm.startStateDiffRecording();
        super.setUp();

        // Some project fixtures expose setup through an internal createPool()
        // helper rather than their setUp(). Invoke that helper inside the native
        // test context so the created application state is captured.
        if ("__CREATE_FIXTURE__" == "__CREATE_FIXTURE__") {{
            // __CREATE_FIXTURE_CALL__ is replaced by Lowkey at generation time.
{create_call}
            console2.log("LOWKEY_TARGET:", target);
        }}

        // Keep this project-agnostic: report every contract account actually
        // created during the fixture. Lowkey later matches those candidates
        // against the requested artifact's runtime bytecode.
        Vm.AccountAccess[] memory accesses = vm.stopAndReturnStateDiff();
        for (uint256 i = 0; i < accesses.length; ++i) {{
            if (
                accesses[i].kind == Vm.AccountAccessKind.Create &&
                accesses[i].account != address(0)
            ) {{
                console2.log("LOWKEY_CREATE:", accesses[i].account);
            }}
        }}

        vm.dumpState("{state_literal}");
    }}

    function testLowkeyLabStateDump() public {{}}
}}
'''
    test_path.write_text(code, encoding="utf-8")
    return test_path


def _fixture_accounts_map(snapshot):
    """Find the account map in Foundry/anvil-compatible state JSON without assuming one wrapper shape."""
    def decode_nested_json(value):
        current = value
        for _ in range(4):
            if not isinstance(current, str):
                return current
            text = current.strip()
            if not text or text[0] not in "{[":
                return current
            try:
                decoded = json.loads(text)
            except (TypeError, json.JSONDecodeError):
                return current
            if decoded == current:
                return current
            current = decoded
        return current

    snapshot = decode_nested_json(snapshot)
    if not isinstance(snapshot, (dict, list)):
        return None, "fixture state snapshot is not a JSON object or array"

    def direct_address_map(value):
        value = decode_nested_json(value)
        if not isinstance(value, dict):
            return None
        entries = {
            key: decode_nested_json(account)
            for key, account in value.items()
            if is_address(str(key).strip()) and isinstance(decode_nested_json(account), dict)
        }
        return entries if entries else None

    def account_list(value):
        value = decode_nested_json(value)
        if not isinstance(value, list):
            return None
        result = {}
        for item in value:
            item = decode_nested_json(item)
            if not isinstance(item, dict):
                continue
            address = (
                item.get("address")
                or item.get("addr")
                or item.get("account")
            )
            address = str(address or "").strip()
            if not is_address(address):
                continue
            account = dict(item)
            account.pop("address", None)
            account.pop("addr", None)
            account.pop("account", None)
            result[address] = account
        return result or None

    direct = direct_address_map(snapshot)
    if direct:
        return direct, "root"

    # Known wrappers first. Anvil uses "accounts"; genesis-style data commonly
    # uses "alloc"/"allocs".
    if isinstance(snapshot, dict):
        for key in ("alloc", "allocs", "accounts", "state", "genesis", "result", "data"):
            candidate = decode_nested_json(snapshot.get(key))
            direct = direct_address_map(candidate)
            if direct:
                return direct, key
            listed = account_list(candidate)
            if listed:
                return listed, f"{key}[list]"

    # Last-resort recursive discovery. This keeps the lab resilient to wrappers
    # added by Foundry/Anvil versions or project tooling without inventing data.
    seen = set()

    def walk(value, path):
        value = decode_nested_json(value)
        marker = id(value)
        if marker in seen:
            return None
        seen.add(marker)

        direct = direct_address_map(value)
        if direct:
            return direct, path

        listed = account_list(value)
        if listed:
            return listed, f"{path}[list]"

        if isinstance(value, dict):
            for key, child in value.items():
                found = walk(child, f"{path}.{key}" if path else str(key))
                if found:
                    return found
        elif isinstance(value, list):
            for index, child in enumerate(value):
                found = walk(child, f"{path}[{index}]")
                if found:
                    return found
        elif isinstance(value, str):
            nested = decode_nested_json(value)
            if nested is not value:
                return walk(nested, path)
        return None

    found = walk(snapshot, "$")
    if found:
        return found

    return None, "fixture state snapshot does not contain an address-keyed alloc/account map"


def _materialize_fixture_state(root, rpc, state_path, target_contract, target_hints=None):
    try:
        raw = Path(state_path).read_text(encoding="utf-8")
        snapshot = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"could not read fixture state snapshot: {exc}"

    accounts, snapshot_kind = _fixture_accounts_map(snapshot)
    if accounts is None:
        return None, snapshot_kind

    code_map = {}
    operations = 0
    parsed_accounts = 0

    for address, account in accounts.items():
        if not is_address(address) or not isinstance(account, dict):
            continue

        parsed_accounts += 1
        code = str(account.get("code") or "0x")
        if code.startswith("0x") and len(code) > 2:
            ok, detail = rpc_json_ok(rpc, "anvil_setCode", [address, code])
            if not ok:
                return None, f"anvil_setCode failed for {address}: {detail}"
            code_map[address.lower()] = code
            operations += 1

        balance = account.get("balance")
        if balance is not None:
            ok, detail = rpc_json_ok(
                rpc, "anvil_setBalance", [address, _fixture_hex_quantity(balance)]
            )
            if not ok:
                return None, f"anvil_setBalance failed for {address}: {detail}"
            operations += 1

        nonce = account.get("nonce")
        if nonce is not None:
            ok, detail = rpc_json_ok(
                rpc, "anvil_setNonce", [address, _fixture_hex_quantity(nonce)]
            )
            if not ok:
                return None, f"anvil_setNonce failed for {address}: {detail}"
            operations += 1

        storage = account.get("storage") or {}
        if isinstance(storage, dict):
            for slot, value in storage.items():
                if not str(slot).startswith("0x") or not str(value).startswith("0x"):
                    continue
                ok, detail = rpc_json_ok(
                    rpc, "anvil_setStorageAt", [address, slot, value]
                )
                if not ok:
                    return None, f"anvil_setStorageAt failed for {address} slot {slot}: {detail}"
                operations += 1

    target = _find_fixture_target(
        root,
        code_map,
        target_contract,
        rpc,
        preferred_addresses=target_hints,
    )
    if not target:
        return None, (
            f"fixture state was materialized ({operations} RPC updates; "
            f"{parsed_accounts} accounts from {snapshot_kind} format), "
            f"but Lowkey could not identify target {target_contract or 'contract'}"
        )

    return target, None


def _fixture_quantity(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return 0
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _fixture_hex_quantity(value):
    return hex(_fixture_quantity(value))


def _artifact_runtime_bytecode(artifact):
    if not isinstance(artifact, dict):
        return None
    deployed = artifact.get("deployedBytecode")
    if isinstance(deployed, dict):
        deployed = deployed.get("object")
    if isinstance(deployed, str) and deployed.startswith("0x") and len(deployed) > 2:
        return deployed.lower()
    return None


def _fixture_target_artifact(root, target_contract):
    target_name = str(target_contract or "").strip().lower()
    if not target_name:
        return None, None
    for path in local_artifact_paths(root):
        artifact = read_artifact(path) or {}
        if artifact_contract_name(path, artifact).lower() == target_name:
            return path, artifact
    return None, None


def _artifact_runtime_normalizer(artifact):
    """Return a bytecode normalizer that masks Solidity immutable references."""
    expected_runtime = _artifact_runtime_bytecode(artifact)
    if not expected_runtime:
        return None

    normalized = expected_runtime.removeprefix("0x").lower()
    immutable_refs = {}
    deployed = artifact.get("deployedBytecode") if isinstance(artifact, dict) else None
    if isinstance(deployed, dict):
        immutable_refs = deployed.get("immutableReferences") or {}

    spans = []
    if isinstance(immutable_refs, dict):
        for references in immutable_refs.values():
            if not isinstance(references, list):
                continue
            for reference in references:
                if not isinstance(reference, dict):
                    continue
                try:
                    start = int(reference.get("start"))
                    length = int(reference.get("length"))
                except (TypeError, ValueError):
                    continue
                if start >= 0 and length > 0:
                    spans.append((start, start + length))

    def normalize(bytecode):
        value = str(bytecode or "").strip().removeprefix("0x").lower()
        if len(value) != len(normalized):
            return None
        chars = list(value)
        for start, end in spans:
            left = start * 2
            right = min(end * 2, len(chars))
            for index in range(left, right):
                chars[index] = "0"
        expected = list(normalized)
        for start, end in spans:
            left = start * 2
            right = min(end * 2, len(expected))
            for index in range(left, right):
                expected[index] = "0"
        return "".join(chars) == "".join(expected)

    return normalize


def _find_fixture_target(root, code_map, target_contract, rpc, preferred_addresses=None):
    _, artifact = _fixture_target_artifact(root, target_contract)
    normalizer = _artifact_runtime_normalizer(artifact)
    if normalizer is None:
        return None

    ordered = []
    seen = set()
    for address in preferred_addresses or []:
        key = str(address or "").strip().lower()
        if key in code_map and key not in seen:
            ordered.append(key)
            seen.add(key)
    for address in code_map:
        key = str(address or "").strip().lower()
        if key not in seen:
            ordered.append(key)
            seen.add(key)

    matches = []
    for address in ordered:
        code_result = run_cast(
            ["code", address, "--rpc-url", str(rpc)],
            config={},
            capture=True,
        )
        runtime = str(code_result.text or "").strip().lower()
        if code_result.code == 0 and normalizer(runtime):
            matches.append(address)

    if len(matches) == 1:
        return matches[0]
    return matches[0] if matches else None


def run_test_fixture_lab(config, root, fixture, rpc, accounts, key, requested=None):
    """Run a discovered Foundry fixture natively as a test, then promote its state to Anvil."""
    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", str(fixture["contract"]))
    state_path = _fixture_state_files(root, safe_name)
    test_path = _generate_test_fixture_lab_script(root, fixture, state_path)
    relative_test = os.path.relpath(test_path, root)

    print("LOWKEY LOCAL AUDIT LAB")
    print("======================")
    print(f"Project : {root}")
    print(f"Fixture : {fixture['relative']}::{fixture['contract']}")
    print(f"Test    : {relative_test}")
    print(f"RPC     : {rpc_display(rpc)}")
    print(f"Actor   : Anvil #0 ({accounts[0]})")
    print("Mode    : promoted project test fixture")
    print("Action  : running the fixture through Forge's native test runner, then materializing its full state into local Anvil...")
    print("Helper  : no broadcast; Forge invokes the fixture setUp() normally.")

    result = run_foundry(
        [
            "test",
            "--match-path",
            relative_test,
            "--match-contract",
            f"LowkeyAutoFixtureTest_{safe_name}",
            "--match-test",
            "testLowkeyLabStateDump",
            "--disable-block-gas-limit",
            "-vv",
        ],
        capture=True,
    )

    output = result.text

    changed_sources = _project_source_mutations(root, before_sources)
    if changed_sources:
        return fail(
            "Error: the project-native lab script changed first-party source files. "
            "Lowkey aborted target selection and will not continue with a mutated source tree. "
            "Changed: " + ", ".join(changed_sources)
        )

    if result.code != 0:
        tail = "\n".join(output.splitlines()[-50:]) if output else "forge test failed"
        return fail(
            "Error: Lowkey fixture test failed.\n" + tail,
            result.code,
        )

    target_name = str(requested or fixture.get("target_contract") or "")
    target_hints = parse_lab_markers(output, "LOWKEY_CREATE")
    target, materialize_error = _materialize_fixture_state(
        root, rpc, state_path, target_name, target_hints=target_hints
    )
    if not target:
        return fail(
            "Error: Lowkey fixture test succeeded, but Anvil state materialization failed.\n"
            + str(materialize_error or "unknown materialization error")
        )

    artifact = None
    if target_name:
        for candidate_path in local_artifact_paths(root):
            candidate_artifact = read_artifact(candidate_path) or {}
            if (
                artifact_contract_name(candidate_path, candidate_artifact).lower()
                == target_name.lower()
            ):
                artifact = candidate_path
                break

    contract_name = target_name or str(fixture.get("contract") or "auto-detected")
    _ensure_lab_deployer(config, accounts[0], 0)
    config["lab_harness"] = {
        "type": "test-fixture-full-state",
        "fixture": fixture.get("relative"),
        "contract": fixture.get("contract"),
        "state_file": str(state_path),
    }
    set_lab_target(config, root, target, contract_name, artifact)

    print(f"Target  : {contract_name} -> {target}")
    print(f"ABI     : {artifact or 'auto-discovered from build artifacts'}")
    print(f"Harness : {fixture['relative']}::{fixture['contract']}")
    _print_security_scope(root)
    print("Ready   : lk read ... | lk changes ... | lk trace")
    return 0


def parse_lab_system(output):
    """Parse generic LOWKEY_<NAME> address markers emitted by lab harnesses."""
    system = {}
    text = str(output or "")
    for match in re.finditer(
        r"(?i)\bLOWKEY_([A-Z][A-Z0-9_]*)\b\s*:?\s*(0x[0-9a-fA-F]{40})\b",
        text,
    ):
        key = re.sub(r"[^a-z0-9]+", "_", match.group(1).lower()).strip("_")
        system[key] = match.group(2)
    return system


LOCAL_LAB_SCRIPTS = (
    "script/LocalAudit.s.sol",
    "script/LocalDeploy.s.sol",
    "script/DeployLocal.s.sol",
)

def _local_lab_script_candidates(root, requested=None):
    """Discover project-native deployment entry points across arbitrary Foundry layouts."""
    root = Path(audit_context.foundry_project_root(root) or root).resolve()
    script_root = root / "script"
    if not script_root.is_dir():
        return []

    wanted = str(requested or "").strip().lower()
    candidates = []
    for path in sorted(script_root.rglob("*.s.sol")):
        relative = path.relative_to(root).as_posix()
        lowered = relative.lower()
        basename = path.name.lower()

        if basename.startswith(("lowkey", "base.")):
            continue
        if any(part.lower() in {"helpers", "interfaces", "libraries"} for part in path.relative_to(script_root).parts[:-1]):
            continue

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if not re.search(r"(?m)\bfunction\s+run\s*\([^)]*\)\s+(?:external|public)", source):
            continue
        if not re.search(r"\b(?:startBroadcast|broadcast|deployCode|create2|new\s+[A-Za-z_])\b", source):
            continue

        score = 0
        compact = re.sub(r"[^a-z0-9]", "", basename)
        if "deploy" in compact:
            score += 120
        if "local" in compact:
            score += 140
        if "bootstrap" in compact or "setup" in compact:
            score += 80
        if "anvil" in compact:
            score += 50
        if wanted:
            wanted_compact = re.sub(r"[^a-z0-9]", "", wanted)
            if wanted_compact and wanted_compact in compact:
                score += 500
            if re.search(r"\b" + re.escape(str(requested)) + r"\b", source, re.I):
                score += 700

        number = re.match(r"^(\d+)", basename)
        if number:
            score += max(0, 60 - int(number.group(1)))

        candidates.append((-score, relative, str(path)))

    return [item[2] for item in sorted(candidates)]


_LAB_SAFE_ENV_NAMES = frozenset({
    "PRIVATE_KEY",
    "DEPLOYER_PRIVATE_KEY",
    "ADMIN_PRIVATE_KEY",
    "OWNER_PRIVATE_KEY",
    "SENDER_PRIVATE_KEY",
    "BROADCAST_PRIVATE_KEY",
    "IS_TESTNET",
    "TESTNET",
    "LOCAL_LAB",
    "ANVIL",
    "RPC_URL",
    "ETH_RPC_URL",
    "ANVIL_RPC_URL",
    "LOCAL_RPC_URL",
    "DEPLOYMENT_RPC_URL",
    "DEPLOYER",
    "DEPLOYER_ADDRESS",
    "OWNER",
    "OWNER_ADDRESS",
    "ADMIN",
    "ADMIN_ADDRESS",
    "SENDER",
    "SENDER_ADDRESS",
})

def _lab_script_unresolved_env_names(script):
    try:
        source = Path(script).read_text(encoding="utf-8", errors="replace")
    except OSError:
        source = ""
    names = set(
        re.findall(
            r"vm\.env(?:Bool|Uint|Address|String|Or)\s*\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\"",
            source,
        )
    )
    return sorted(name for name in names if name.upper() not in _LAB_SAFE_ENV_NAMES)


def discover_local_lab_script(root=".", requested=None):
    root = audit_context.foundry_project_root(root) or root

    candidates = []
    for relative in LOCAL_LAB_SCRIPTS:
        path = os.path.join(root, relative)
        if os.path.isfile(path):
            candidates.append(path)

    discovered = _local_lab_script_candidates(root, requested)
    for path in discovered:
        if path not in candidates:
            candidates.append(path)

    # Auto lab is disposable/local-only. A deployment script that requires an
    # address, moderator, registry, token, or other project-specific environment
    # value cannot be safely invented by Lowkey, so do not execute it implicitly.
    # This also prevents a production-oriented Deploy.s.sol from winning merely
    # because its filename looks deployable.
    for path in candidates:
        if _lab_script_unresolved_env_names(path):
            continue
        return path

    return None

def parse_lab_markers(output, marker):
    """Parse LOWKEY_* address markers even when Forge prefixes console lines.

    Foundry can decorate script output with labels/metadata around console2.log
    lines. The marker itself is the contract between a project-native lab
    script and Lowkey, so parsing must not require the marker to occupy the
    entire physical line.
    """
    return re.findall(
        rf"(?i)\b{re.escape(marker)}\b\s*:?\s*(0x[0-9a-fA-F]{{40}})\b",
        str(output or ""),
    )


def parse_lab_marker(output, marker="LOWKEY_TARGET"):
    """Return the last target address for the given lab marker.

    Keep LOWKEY_TARGET as the default for backwards compatibility with
    existing project-native deployment scripts and callers.
    """
    matches = parse_lab_markers(output, marker)
    return matches[-1] if matches else None

def parse_deployed_address(output):
    text = str(output or "")
    patterns = [
        r"(?i)\bDeployed to:\s*(0x[0-9a-fA-F]{40})",
        r"(?i)\bContract Address:\s*(0x[0-9a-fA-F]{40})",
        r'(?i)"deployedTo"\s*:\s*"(0x[0-9a-fA-F]{40})"',
        r'(?i)"deployed_to"\s*:\s*"(0x[0-9a-fA-F]{40})"',
        r'(?i)"contractAddress"\s*:\s*"(0x[0-9a-fA-F]{40})"',
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    # Last-resort fallback for Forge output that labels an address on the same
    # line with additional status text. Keep the label requirement to avoid
    # accidentally selecting an unrelated address from compiler output.
    return None

def _configured_src_prefix(root):
    root_path = Path(root).expanduser().resolve()
    src_prefix = "src"
    try:
        foundry = (root_path / "foundry.toml").read_text(encoding="utf-8", errors="replace")
        match = re.search(r'(?m)^\s*src\s*=\s*"([^"]+)"', foundry)
        if match:
            src_prefix = match.group(1).strip().rstrip("/").replace("\\", "/")
    except OSError:
        pass
    return src_prefix


def artifact_source_name(artifact, path, root=None):
    if isinstance(artifact, dict) and artifact.get("sourceName"):
        return str(artifact.get("sourceName")).replace("\\", "/").lstrip("./")

    metadata = artifact.get("metadata") if isinstance(artifact, dict) else None
    if isinstance(metadata, str):
        try:
            payload = json.loads(metadata)
            sources = payload.get("sources", {})
            if isinstance(sources, dict):
                contract_dir = Path(path).parent.name
                contract_name = artifact_contract_name(path, artifact)
                preferred = [
                    name for name in sources
                    if Path(name).name == contract_dir
                    or Path(name).stem == contract_dir
                    or Path(name).stem == contract_name
                ]
                if root is not None:
                    src_prefix = _configured_src_prefix(root)
                    root_path = Path(root).expanduser().resolve()
                    for name in preferred:
                        normalized = str(name).replace("\\", "/").lstrip("./")
                        candidate = root_path / normalized
                        if (normalized == src_prefix or normalized.startswith(src_prefix + "/")) and candidate.is_file():
                            return normalized
                if preferred:
                    return str(preferred[0]).replace("\\", "/").lstrip("./")
                if root is None and sources:
                    return str(next(iter(sources))).replace("\\", "/").lstrip("./")
        except (json.JSONDecodeError, TypeError):
            pass

    # When Foundry did not retain sourceName, recover the source only from
    # the current project source tree. Never invent a source path from the
    # artifact directory alone.
    if root is not None:
        root_path = Path(root).expanduser().resolve()
        src_prefix = _configured_src_prefix(root_path)
        src_root = root_path / src_prefix
        contract_dir = Path(path).parent.name

        # When sourceName/metadata is absent, anchor the artifact to the source
        # file represented by Foundry's artifact directory. Do not fall back to
        # "find any source with the same contract name": tests/POCs can compile
        # another artifact with an identical contractName.
        candidates = []
        if src_root.is_dir() and contract_dir:
            candidates.extend(
                sorted(src_root.rglob(contract_dir))
            )

        for candidate in candidates:
            try:
                normalized = candidate.relative_to(root_path).as_posix()
            except ValueError:
                continue
            if normalized == src_prefix or normalized.startswith(src_prefix + "/"):
                return normalized

    return None

def artifact_constructor_inputs(artifact):
    abi = artifact.get("abi", []) if isinstance(artifact, dict) else []
    constructors = [item for item in abi if isinstance(item, dict) and item.get("type") == "constructor"]
    return constructors[0].get("inputs", []) if constructors else []

def artifact_has_initializer(artifact):
    abi = artifact.get("abi", []) if isinstance(artifact, dict) else []
    return any(
        isinstance(item, dict)
        and item.get("type") == "function"
        and str(item.get("name") or "").lower().startswith("initialize")
        for item in abi
    )

def artifact_is_deployable(artifact):
    if not isinstance(artifact, dict):
        return False
    bytecode = artifact.get("bytecode", {})
    if isinstance(bytecode, dict):
        obj = str(bytecode.get("object") or "")
    else:
        obj = str(bytecode or "")
    return bool(obj and obj not in {"0x", "0X"})

def source_contract_fallback(root, contract_name):
    """Find first-party source for an artifact across supported EVM project layouts."""
    root_path = Path(root).expanduser().resolve()
    candidates = []
    if project_tools is not None:
        try:
            candidates.extend(project_tools.project_source_files(root_path, {"sol", "vy"}))
        except Exception:
            pass
    if not candidates:
        ignored = {
            ".git", ".audit", ".venv", ".tox", "__pycache__", "node_modules",
            "out", "artifacts", "build", "cache", "dist",
        }
        for path in root_path.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".sol", ".vy"}:
                if not any(part in ignored for part in path.parts):
                    candidates.append(path)

    excluded_parts = {
        ".git", ".audit", ".venv", ".tox", "__pycache__", "node_modules",
        "out", "artifacts", "build", "cache", "dist", "tests", "test",
        "fixtures", "mocks", "mock",
    }
    for candidate in sorted(set(candidates)):
        try:
            relative_parts = candidate.resolve().relative_to(root_path).parts
        except (OSError, ValueError):
            continue
        if any(str(part).lower() in excluded_parts for part in relative_parts[:-1]):
            continue
        if candidate.stem.lower() != str(contract_name).lower():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if candidate.suffix.lower() == ".vy":
            try:
                return candidate.relative_to(root_path).as_posix()
            except ValueError:
                continue
        if re.search(
            r"\b(contract|library|interface|abstract\s+contract)\s+"
            + re.escape(str(contract_name)) + r"\b",
            text,
        ):
            try:
                return candidate.relative_to(root_path).as_posix()
            except ValueError:
                continue
    return None

def artifact_is_project_application(root, path, artifact):
    """Return True only for deployable, first-party application artifacts."""
    if not artifact_is_deployable(artifact):
        return False

    root_path = Path(root).expanduser().resolve()
    path_obj = Path(path).expanduser().resolve()
    explicit_source = artifact_source_name(artifact, path, root)
    source = explicit_source or source_contract_fallback(
        root, artifact_contract_name(path, artifact)
    )
    if not source:
        return False

    normalized = str(source).replace("\\", "/").lstrip("./")

    # When Foundry stripped sourceName, use the artifact directory only to
    # confirm that the fallback source file belongs to the same artifact stem.
    # The old check compared the artifact directory to the *contract name*,
    # which incorrectly rejected valid layouts such as PurchaseNFT2.sol -> PurchaseNFT.
    # Explicit sourceName metadata is stronger provenance and needs no basename check.
    if not explicit_source:
        parent_stem = path_obj.parent.name
        if parent_stem.lower().endswith(".sol"):
            parent_stem = parent_stem[:-4]
        if Path(normalized).stem.lower() != parent_stem.lower():
            return False
    source_path = root_path / normalized
    if not source_path.is_file():
        return False

    # Keep application ownership project-local without requiring any particular
    # directory name. Common dependency/source locations are excluded below.
    excluded_prefixes = {
        "node_modules", "vendor", ".git", ".audit", "build-info",
        "tests", "test", "fixtures", "mocks", "mock",
    }
    parts = Path(normalized).parts
    if any(part in excluded_prefixes for part in parts):
        return False
    if universal_is_dependency_path is not None:
        try:
            if universal_is_dependency_path(source_path, root_path):
                return False
        except (OSError, ValueError):
            pass

    try:
        source_text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    contract_name = artifact_contract_name(path, artifact)
    if source_path.suffix.lower() == ".vy":
        # Vyper interfaces conventionally use .vyi; only executable .vy sources
        # can back a deployable artifact.
        return True

    if re.search(r"\blibrary\s+" + re.escape(contract_name) + r"\b", source_text):
        return False
    if re.search(r"\binterface\s+" + re.escape(contract_name) + r"\b", source_text):
        return False
    if re.search(r"\babstract\s+contract\s+" + re.escape(contract_name) + r"\b", source_text):
        return False
    return bool(
        re.search(r"\bcontract\s+" + re.escape(contract_name) + r"\b", source_text)
    )


def discover_audit_target_contract(root):
    """Choose a likely application target using artifacts, source evidence, and audit signals."""
    root_path = Path(root).expanduser().resolve()
    artifacts = {}
    scores = {}
    sources = {}
    signals = [
        item for item in audit_context.signals(root_path, "open")
        if isinstance(item, dict)
    ]

    for path in local_artifact_paths(root_path):
        if "build-info" in Path(path).parts:
            continue
        artifact = read_artifact(path)
        if not artifact or not artifact_is_deployable(artifact):
            continue

        name = artifact_contract_name(path, artifact)
        key = str(name).lower()
        source = artifact_source_name(artifact, path, root_path) or source_contract_fallback(
            root_path, name
        )
        owned = artifact_is_project_application(root_path, path, artifact)
        signal_match = any(
            Path(str(item.get("file") or "")).stem.lower() == key
            for item in signals
        )
        # Application ownership is preferred. When sparse test/build artifacts
        # omit source metadata, a matching first-party audit signal is sufficient
        # to rank the artifact as the current review target without pretending it
        # is fully provenance-verified.
        if not owned and not signal_match:
            continue

        artifacts[key] = name
        sources[key] = source or str(path)
        scores.setdefault(key, 0)

        lowered = key
        if lowered.endswith((
            "factory", "router", "manager", "coordinator", "controller",
            "registry", "gateway", "vault", "pool",
        )):
            scores[key] += 100

        if artifact_has_initializer(artifact):
            scores[key] += 20

        if owned:
            scores[key] += 10

        if signal_match:
            for signal in signals:
                if Path(str(signal.get("file") or "")).stem.lower() == key:
                    impact = str(signal.get("impact") or "").lower()
                    scores[key] += {
                        "critical": 250, "high": 100, "medium": 50,
                        "low": 10, "informational": 2,
                    }.get(impact, 5)

    if not artifacts:
        return None

    # A source-backed contract referencing another known application contract is
    # a useful conservative root signal. Never require it.
    contract_names = set(artifacts.values())
    for key, source in list(sources.items()):
        try:
            source_text = (root_path / source).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            source_text = ""
        for other in contract_names:
            if other.lower() == key:
                continue
            if re.search(r"\b" + re.escape(other) + r"\b", source_text):
                scores[key] += 30
                break

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return artifacts[ranked[0][0]] if ranked else None


def discover_generic_lab_contract(root, query=None):
    preferred_name = str(query).strip() if query else discover_audit_target_contract(root)

    # First pass: the strict artifact/source validation.
    candidates = []
    for path in local_artifact_paths(root):
        artifact = read_artifact(path)
        if not artifact or not artifact_is_deployable(artifact):
            continue
        contract = artifact_contract_name(path, artifact)
        if preferred_name and contract.lower() != preferred_name.lower():
            continue
        source = artifact_source_name(artifact, path, root) or source_contract_fallback(root, contract)
        if not source:
            continue
        lowered = str(source).lower().replace("\\", "/")
        lowered_contract = contract.lower()
        if "/interfaces/" in lowered or lowered_contract.startswith("i"):
            continue
        if not artifact_is_project_application(root, path, artifact):
            # Re-check with the source fallback: sparse metadata should not block
            # a valid first-party Foundry artifact from becoming a local lab.
            if not re.search(r"\b(contract|library|interface)\s+" + re.escape(contract) + r"\b",
                             (Path(root) / source).read_text(encoding="utf-8", errors="replace")):
                continue
        candidates.append((
            0 if preferred_name and contract.lower() == preferred_name.lower() else 50,
            contract, path, artifact, artifact_constructor_inputs(artifact),
            f"{source}:{contract}"
        ))

    # If metadata/source-name recovery still failed, use the strongest application
    # contract name and its matching bytecode artifact.
    if not candidates and preferred_name:
        for path in local_artifact_paths(root):
            artifact = read_artifact(path)
            if not artifact or not artifact_is_deployable(artifact):
                continue
            contract = artifact_contract_name(path, artifact)
            if contract.lower() != preferred_name.lower():
                continue
            source = source_contract_fallback(root, contract)
            if source:
                candidates.append((
                    0, contract, path, artifact, artifact_constructor_inputs(artifact),
                    f"{source}:{contract}"
                ))
                break

    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1].lower(), str(item[2])))
    return candidates[0]


def discover_artifact_lab_contract(root, query):
    """Resolve an explicitly requested built artifact for direct local deployment."""
    requested = str(query or "").strip()
    if not requested:
        return None

    matches = []
    for path in local_artifact_paths(root):
        artifact = read_artifact(path)
        if not artifact or not artifact_is_deployable(artifact):
            continue
        contract = artifact_contract_name(path, artifact)
        if contract.lower() != requested.lower():
            continue
        matches.append((
            0,
            contract,
            path,
            artifact,
            artifact_constructor_inputs(artifact),
            f"{artifact_source_name(artifact, path, root) or path}:{contract}",
        ))

    matches.sort(key=lambda item: str(item[2]))
    return matches[0] if matches else None


def set_lab_target(config, root, target, contract, artifact):
    _sync_security_patterns(root)
    config["target"] = target
    config["target_contract"] = contract
    if artifact:
        config.setdefault("abi_paths", {})[target] = artifact
    remember_project_target(config, root, contract, target)
    save_config(config)
    audit_context.set_target(
        root,
        address=target,
        contract=contract,
        artifact=artifact,
        source="project-lab",
    )
    audit_context.update(root, actor=actor_display(config), rpc=effective_rpc(config))

def repo_clone_url(value):
    value = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        return f"https://github.com/{value}.git"
    return value

def repo_clone_name(value):
    value = str(value or "").strip().rstrip("/")
    tail = value.rsplit("/", 1)[-1]
    if ":" in tail and not value.startswith(("http://", "https://", "ssh://")):
        tail = tail.rsplit(":", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail

def project_anvil_state_path(root):
    return os.path.join(root, ".audit", "anvil.json")

def write_project_anvil_state(root, state):
    path = project_anvil_state_path(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    Path(path).write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

def read_project_anvil_state(root):
    path = project_anvil_state_path(root)
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None

def stop_project_anvil(root):
    state = read_project_anvil_state(root)
    if not isinstance(state, dict) or not state.get("auto_started"):
        print("Project Anvil: not managed by Lowkey.")
        return 0
    pid = state.get("pid")
    if isinstance(pid, int):
        try:
            os.kill(pid, 15)
        except OSError:
            pass
    try:
        os.remove(project_anvil_state_path(root))
    except OSError:
        pass
    print(f"Project Anvil stopped: PID {pid or 'unknown'}")
    return 0

def ensure_project_anvil(config, root):
    info = anvil_rpc_info(config)
    if info:
        return info

    if config.get("rpc"):
        return None

    existing = read_project_anvil_state(root)
    if isinstance(existing, dict):
        pid = existing.get("pid")
        rpc = existing.get("rpc")
        if isinstance(pid, int) and isinstance(rpc, str) and local_port_open("127.0.0.1", int(rpc.rsplit(":", 1)[-1])):
            info = detect_anvil_rpc(rpc)
            if info:
                config["_auto_rpc_info"] = info
                return info
        try:
            os.remove(project_anvil_state_path(root))
        except OSError:
            pass

    binary = tool_path("anvil")
    if not binary:
        return None

    port = None
    for candidate in range(8545, 8556):
        if not local_port_open("127.0.0.1", candidate):
            port = candidate
            break
    if port is None:
        return None

    rpc = f"http://127.0.0.1:{port}"
    log_path = os.path.join(root, ".audit", "anvil.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    try:
        log = open(log_path, "a", encoding="utf-8")
        process = subprocess.Popen(
            [binary, "--port", str(port), "--silent"],
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        log.close()
    except (OSError, ValueError) as error:
        try:
            log.close()
        except Exception:
            pass
        print(f"Warning: Lowkey could not start project Anvil: {error}", file=sys.stderr)
        return None

    for _ in range(40):
        info = detect_anvil_rpc(rpc)
        if info:
            state = {
                "auto_started": True,
                "pid": process.pid,
                "rpc": rpc,
                "started": datetime.now().isoformat(timespec="seconds"),
            }
            write_project_anvil_state(root, state)
            config["_auto_rpc_info"] = info
            return info
        if process.poll() is not None:
            return None
        import time
        time.sleep(0.1)

    try:
        process.terminate()
    except OSError:
        pass
    return None

def _format_build_failure(output):
    text = str(output or "").strip()
    if not text:
        return "Build failed with no compiler output."
    # Keep the actionable compiler diagnostics intact while avoiding duplicate blank lines.
    return text


def _node_package_bootstrap_command(root):
    """Backward-compatible adapter to the shared Node dependency planner."""
    if bootstrap_engine is None:
        return None
    plan = bootstrap_engine.bootstrap_plan(
        {"root": str(Path(root))},
        root,
        force=True,
        reason="dependency",
    )
    for action in plan.get("actions", []):
        if action.get("kind") == "node":
            return list(action.get("command") or []) or None
    return None


def _submodule_bootstrap_health(root):
    """Backward-compatible adapter to shared submodule diagnostics."""
    if bootstrap_engine is None:
        return []
    try:
        state = bootstrap_engine._submodule_state(Path(root))
    except Exception:
        return []
    return list(state.get("missing") or [])


def _foundry_native_bootstrap_commands(root, build_output=""):
    """Backward-compatible adapter; all recovery decisions live in bootstrap.py."""
    if bootstrap_engine is None:
        return []
    classification = classify_build_failure(build_output, ["forge", "build"])
    if not classification.get("repairable"):
        return []
    plan = bootstrap_engine.bootstrap_plan(
        {"root": str(Path(root))},
        root,
        force=True,
        reason=str(classification.get("category") or "dependency"),
    )
    return [list(action.get("command") or []) for action in plan.get("actions", []) if action.get("command")]


def _native_command_runtime(cwd, command):
    """Return (env, review_message) for a native command honoring a Node pin.

    If the project declares a Node pin that cannot be satisfied by an
    already-installed runtime, the caller must stop and report REVIEW NEEDED
    rather than run under an incompatible runtime. Lowkey never downloads a
    runtime automatically.
    """
    env = dict(os.environ)
    if runtime_environment is None or command_uses_node is None or not command_uses_node(command):
        return env, None
    try:
        env, required = runtime_environment(cwd)
    except Exception:
        return dict(os.environ), None
    if not required:
        return env, None
    try:
        status = node_runtime_status(cwd) if node_runtime_status is not None else {"matched": True}
    except Exception:
        return env, None
    if status.get("matched"):
        return env, None
    return env, (
        f"RESULT: REVIEW NEEDED — project declares Node {required}, but no "
        "already-installed matching runtime was found. Lowkey will not download a runtime."
    )


def _run_project_build(config, root):
    """Build through the shared repository-aware bootstrap/recovery layer."""
    root_path = Path(root)
    project = detect_project(root) if detect_project is not None else {
        "root": str(root_path),
        "kind": "generic",
        "backend": "generic",
        "build_backend": "generic",
    }

    selected_scope = None
    if discover_nested_projects is not None and workspace_context is not None:
        scope = workspace_context(root)
        for candidate in scope.get("projects") or []:
            if Path(candidate["root"]).resolve() == root_path.resolve():
                selected_scope = candidate
                break
    if selected_scope:
        print("")
        print("LAB SCOPE")
        print("=========")
        print(f"Project    : {selected_scope.get('relative')}")
        print(f"Role       : {selected_scope.get('scope_role') or selected_scope.get('scope_hint')}")
        print(f"Purpose    : {_workspace_project_description(selected_scope)}")
        if selected_scope.get("depends_on"):
            print(f"Depends on : {', '.join(selected_scope['depends_on'])}")
        if selected_scope.get("depended_on_by"):
            print(f"Used by    : {', '.join(selected_scope['depended_on_by'])}")

    bootstrap_project(project, reason="prepare")

    kind = str(project.get("kind") or project.get("backend") or "generic")

    if str(project.get("backend") or "") == "foundry" or kind in {"foundry", "mixed-foundry-vyper"}:
        result = run_foundry(["build"], capture=True, cwd=root)
        if result.code == 0:
            print("")
            print("LOWKEY BUILD")
            print("============")
            print("Build system : forge build")
            print(f"Project      : {root}")
            print("Status       : complete")
            return 0

        first_output = _format_build_failure(
            getattr(result, "text", None) or getattr(result, "output", None) or result
        )
        classification = classify_build_failure(first_output, ["forge", "build"])
        print(
            f"BUILD FAILURE : {classification.get('category', 'unknown')}",
            file=sys.stderr,
        )
        print(f"Reason        : {classification.get('reason', '')}", file=sys.stderr)

        if classification.get("repairable"):
            repair_code = bootstrap_project(
                project,
                force=True,
                reason=str(classification.get("category") or "dependency"),
            )
            if repair_code != 0:
                print(
                    "Warning: repository-declared bootstrap reported a failure; "
                    "Lowkey will still retry the build once.",
                    file=sys.stderr,
                )
            retry = run_foundry(["build"], capture=True)
            if retry.code == 0:
                print("")
                print("LOWKEY BUILD")
                print("============")
                print("Build system : forge build")
                print(f"Project      : {root}")
                print("Status       : complete")
                return 0
            first_output = _format_build_failure(
                getattr(retry, "text", None) or getattr(retry, "output", None) or retry
            )

        print("Build diagnostics:\n" + first_output, file=sys.stderr)
        return result.code

    command_info = project_build_command(project) if project_build_command is not None else None
    if not command_info:
        print("LOWKEY BUILD")
        print("============")
        print(f"Project      : {root}")
        print(f"Build system : {project.get('build_backend') or project.get('backend') or 'unknown'}")
        print("Status       : no safe native build command detected")
        print("Lowkey will not invent an install or build command.")
        print("RESULT: REVIEW NEEDED — no executable project-native build command was established.")
        return 2

    build_root, command, evidence = command_info
    print("")
    print("LOWKEY BUILD")
    print("============")
    print(f"Build system : {' '.join(command)}")
    print(f"Project      : {build_root}")
    print(f"Evidence     : {evidence}")
    native_env, runtime_review = _native_command_runtime(build_root, command)
    if runtime_review:
        print(runtime_review)
        return 2
    print("Status       : running...")

    def run_native_build():
        try:
            completed = subprocess.run(
                command,
                cwd=str(build_root),
                capture_output=True,
                text=True,
                env={**native_env, "CI": "1"},
                timeout=900,
            )
        except subprocess.TimeoutExpired as error:
            return 1, str(error)
        except OSError as error:
            return 1, str(error)
        output = (completed.stdout or "") + (("\n" + completed.stderr) if completed.stderr else "")
        return completed.returncode, output.strip()

    code, output = run_native_build()
    if code == 0:
        print("Status       : complete")
        return 0

    classification = classify_build_failure(output, command)
    print(
        f"BUILD FAILURE : {classification.get('category', 'unknown')}",
        file=sys.stderr,
    )
    print(f"Reason        : {classification.get('reason', '')}", file=sys.stderr)

    if classification.get("repairable"):
        repair_code = bootstrap_project(
            project,
            force=True,
            reason=str(classification.get("category") or "dependency"),
        )
        if repair_code != 0:
            print(
                "Warning: repository-declared bootstrap reported a failure; "
                "Lowkey will still retry the build once.",
                file=sys.stderr,
            )
        code, output = run_native_build()
        if code == 0:
            print("Status       : complete")
            return 0

    if output:
        print("Build diagnostics:\n" + output, file=sys.stderr)
    return code or 1

def _workspace_project_description(project):
    return str(project.get("description") or project.get("name") or Path(project["root"]).name).strip()

def _workspace_project_details(project):
    languages = ", ".join(sorted(project.get("languages") or {})) or str(project.get("backend") or "unknown")
    role = str(project.get("scope_role") or project.get("scope_hint") or "component")
    lines = [
        f"     Purpose   : {_workspace_project_description(project)}",
        f"     Stack     : {languages}",
    ]
    lines.append(f"     Contracts : {project.get('contract_count', 0)}")
    if int(project.get("contract_count", 0)) == 0:
        lines.append(f"     Code units: {project.get('protocol_source_files', 0)}")
    lines.append(f"     Tests     : {project.get('test_files', 0)}")
    if int(project.get("setup_files", 0)) > 0:
        lines.append(f"     Setup     : {project.get('setup_files', 0)} file(s)")
    depends_on = project.get("depends_on") or []
    dependents = project.get("depended_on_by") or []
    if depends_on:
        lines.append(f"     Depends   : {', '.join(depends_on[:6])}{' ...' if len(depends_on) > 6 else ''}")
    if dependents:
        lines.append(f"     Used by   : {', '.join(dependents[:6])}{' ...' if len(dependents) > 6 else ''}")
    if project.get("entrypoint"):
        lines.append(f"     Entry     : {project['entrypoint']}")
    lines.append(f"     Scope     : {role}")
    lines.append(f"     Analysis  : {'audit backend available' if project.get('audit_capable') else 'source/static analysis only'}")
    return lines

def _print_workspace_scope_choices(candidates):
    groups = [
        ("PRIMARY AUDIT CANDIDATE", lambda p: p.get("scope_role") == "primary audit candidate"),
        ("IMPORTANT DEPENDENCIES", lambda p: p.get("scope_role") == "important dependency"),
        ("COMPONENTS / LIBRARIES", lambda p: p.get("scope_role") == "component / library"),
        ("SUPPORT / TOOLING", lambda p: p.get("scope_role") == "support / tooling"),
    ]
    index_map = {index: candidate for index, candidate in enumerate(candidates, 1)}
    for title, predicate in groups:
        members = [(index, candidate) for index, candidate in index_map.items() if predicate(candidate)]
        if not members:
            continue
        print("")
        print(title)
        print("-" * len(title))
        for index, candidate in members:
            print(f"  {index}. {candidate.get('relative')}")
            for line in _workspace_project_details(candidate):
                print(line)
    return index_map


def run_projects(config, args):
    if workspace_context is None:
        return fail("Project discovery layer is unavailable. Reinstall Lowkey.")

    scope = workspace_context(Path.cwd())
    root = Path(scope["workspace"]).resolve()
    candidates = list(scope.get("projects") or [])

    if args and args[0].lower() in {"-h", "--help", "help"}:
        print("Usage:")
        print("  lk projects")
        print("  lk projects <number>")
        print("  lk projects <path>")
        print("  lk projects reset")
        print("")
        print("Shows how Lowkey understands the workspace, then lets you set the active audit project.")
        return 0

    if not candidates:
        return fail(f"Error: no nested projects found in {root}.")

    if args:
        selector = str(args[0]).strip()
        if selector.lower() == "reset":
            clear_workspace_selection(root)
            print(f"Active project cleared for {root}")
            return 0

        selected = None
        if selector.isdigit():
            index = int(selector)
            if 1 <= index <= len(candidates):
                selected = candidates[index - 1]
            else:
                return fail(f"Error: project number must be between 1 and {len(candidates)}.")
        else:
            selector_path = Path(selector).expanduser()
            if not selector_path.is_absolute():
                selector_path = root / selector_path
            selector_path = selector_path.resolve()
            selected = next(
                (item for item in candidates if Path(item["root"]).resolve() == selector_path),
                None,
            )
            if selected is None:
                matches = [
                    item for item in candidates
                    if str(item.get("relative", "")).lower() == selector.lower()
                    or str(item.get("name", "")).lower() == selector.lower()
                    or str(item.get("package_name", "")).lower() == selector.lower()
                ]
                if len(matches) == 1:
                    selected = matches[0]

        if selected is None:
            return fail(f"Error: no workspace project matched '{selector}'.")

        if not set_workspace_selection(root, selected["root"]):
            return fail("Error: could not save the active project selection.")

        print("ACTIVE AUDIT PROJECT")
        print("====================")
        print(f"Project : {selected.get('relative')}")
        for line in _workspace_project_details(selected):
            print(line)
        print("")
        print("Lowkey will now use this project when you work from the shared workspace.")
        print("Next: lk project | lk lab | lk audit")
        return 0

    active = scope.get("active")
    current = scope.get("current")
    print("LOWKEY WORKSPACE")
    print("=" * 72)
    print(f"Workspace : {root}")
    print(f"Projects  : {len(candidates)}")
    if active:
        print(f"Active    : {active.relative_to(root).as_posix()}")
    if current:
        print(f"Here      : {current.relative_to(root).as_posix()}")
    _print_workspace_scope_choices(candidates)
    print("")
    print("Use 'lk projects <number>' to set the audit scope.")
    return 0


def run_clone(config, args):
    """Clone with the cache-aware engine, then perform full Lowkey onboarding."""
    try:
        from clone_tools import (
            parse_clone_args,
            resolve_destination,
            run_clone as clone_project,
        )
    except ImportError as exc:
        return fail(f"Error: Lowkey clone engine unavailable: {exc}")

    try:
        repo_url, destination_arg, depth, jobs, use_cache = parse_clone_args(args)
        destination = resolve_destination(repo_url, destination_arg)
    except SystemExit:
        return 0
    except (ValueError, TypeError) as exc:
        return fail(str(exc))

    if destination.exists():
        # clone_tools safely resumes an existing matching repository; let it own
        # the clone semantics rather than rejecting a recoverable partial checkout.
        pass

    code = clone_project(args)
    if code != 0:
        return code
    project = project_tools.detect_project(destination) if project_tools is not None else {}
    project_kind = str(project.get("kind") or "generic")
    if project_kind == "generic" and not project.get("languages"):
        return fail(
            f"Error: {destination} does not look like a supported Solidity/Vyper/EVM project."
        )

    previous_cwd = Path.cwd()
    try:
        os.chdir(destination)
        root = str(destination)

        print("\n[1/3] Building project...")
        if project_kind in {"foundry", "mixed-foundry-vyper"}:
            build = run_foundry(["build"], capture=True)
            build_code = build.code
        elif project_kind == "hardhat":
            build_code = _run_project_build(config, root)
        elif project_kind == "brownie":
            build_code = _run_project_build(config, root)
        elif project_kind in {"vyper", "vyper-uv"}:
            build_code = _run_project_build(config, root)
        else:
            build_code = 0
            print("NOTE  build: no native build system detected; Lowkey will use available artifacts.")
        if build_code != 0:
            return fail("Error: project build failed.", build_code)
        print("PASS  build")

        print("\n[2/3] Running connected audit...")
        audit_code = run_audit(config, ["--checks"])
        if audit_code != 0:
            print("Warning: connected audit did not finish cleanly.", file=sys.stderr)

        print("\n[3/3] Preparing local audit lab...")
        evm_kinds = {"foundry", "mixed-foundry-vyper", "hardhat", "brownie", "vyper", "vyper-uv", "solidity-source", "evm-source"}
        if project_kind not in evm_kinds:
            print("LAB   : skipped (non-EVM project; native backend does not use Anvil).")
            lab_code = 0
        else:
            info = ensure_project_anvil(config, root)
            if not info:
                print("LAB   : deferred (no local Anvil could be started).", file=sys.stderr)
                lab_code = 1
            else:
                lab_code = run_lab(config, [])

        print("\nLOWKEY CLONE ONBOARDING")
        print("=======================")
        print(f"Project : {root}")
        print(f"Mode    : {'shallow' if depth else 'full'} / {jobs} jobs / cache={'on' if use_cache else 'off'}")
        if lab_code == 0 and audit_code == 0:
            print("Status  : READY FOR AUDIT")
            print("Next    : lk findings")
        elif audit_code == 0:
            print("Status  : STATIC AUDIT READY; LIVE LAB NEEDS ATTENTION")
            print("Next    : lk lab")
        else:
            print("Status  : ONBOARDING NEEDS ATTENTION")
            print("Next    : lk audit")
        return 0 if audit_code == 0 and lab_code == 0 else 1
    finally:
        os.chdir(previous_cwd)


def parse_lab_observations(output):
    observed = {}
    for match in re.finditer(
        r"LOWKEY_OBSERVED(?:\s+|:)\s*([A-Za-z0-9_]+)\s+(0x[0-9a-fA-F]{40})",
        str(output or ""),
    ):
        observed[match.group(1).lower()] = match.group(2)
    return observed


def _lab_script_environment(script, rpc, key, accounts):
    """Derive safe local defaults for common deployment-script environment variables."""
    try:
        source = Path(script).read_text(encoding="utf-8", errors="replace")
    except OSError:
        source = ""

    names = set(
        re.findall(
            r"vm\.env(?:Bool|Uint|Address|String|Or)\s*\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\"",
            source,
        )
    )
    account0 = accounts[0] if accounts else None

    assignments = {}
    for name in names:
        upper = name.upper()
        if upper in {
            "PRIVATE_KEY",
            "DEPLOYER_PRIVATE_KEY",
            "ADMIN_PRIVATE_KEY",
            "OWNER_PRIVATE_KEY",
            "SENDER_PRIVATE_KEY",
            "BROADCAST_PRIVATE_KEY",
        }:
            assignments[name] = str(int(str(key), 16))
        elif upper in {"IS_TESTNET", "TESTNET", "LOCAL_LAB", "ANVIL"}:
            assignments[name] = "true"
        elif upper in {
            "RPC_URL",
            "ETH_RPC_URL",
            "ANVIL_RPC_URL",
            "LOCAL_RPC_URL",
            "DEPLOYMENT_RPC_URL",
        }:
            assignments[name] = str(rpc)
        elif upper in {
            "DEPLOYER",
            "DEPLOYER_ADDRESS",
            "OWNER",
            "OWNER_ADDRESS",
            "ADMIN",
            "ADMIN_ADDRESS",
            "SENDER",
            "SENDER_ADDRESS",
        } and account0:
            assignments[name] = str(account0)

    return assignments, sorted(name for name in names if name not in assignments)


_LAB_SOURCE_OUTPUT_SENTINELS = (
    "LOWKEY // LIVE PROTOCOL WALKTHROUGH",
    "SYSTEM WORKFLOW",
    "PROTOCOL STORY",
    "ENTER = next live interaction",
)

def _project_source_files(root):
    """Return first-party source files that a lab is allowed to observe, never mutate."""
    root_path = Path(root).expanduser().resolve()
    src_prefix = _configured_src_prefix(root_path)
    src_root = root_path / src_prefix
    if not src_root.is_dir():
        return []
    files = []
    for suffix in ("*.sol", "*.vy"):
        files.extend(src_root.rglob(suffix))
    return sorted({path.resolve() for path in files if path.is_file()})


def _project_source_fingerprint(root):
    """Capture first-party source bytes so a lab script cannot silently rewrite user code."""
    fingerprint = {}
    for path in _project_source_files(root):
        try:
            fingerprint[path.relative_to(Path(root).resolve()).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, ValueError):
            continue
    return fingerprint


def _project_source_mutations(root, before):
    after = _project_source_fingerprint(root)
    keys = set(before) | set(after)
    return sorted(key for key in keys if before.get(key) != after.get(key))


def _lab_source_integrity_issue(root):
    """Detect terminal/walkthrough output accidentally inserted into application source."""
    for path in _project_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for sentinel in _LAB_SOURCE_OUTPUT_SENTINELS:
            index = text.find(sentinel)
            if index >= 0:
                line = text.count("\n", 0, index) + 1
                return path.relative_to(Path(root).resolve()).as_posix(), line, sentinel
    return None


def _validate_project_lab_target(
    config,
    root,
    rpc,
    target,
    requested=None,
    provenance_script=None,
):
    """Require a live lab target to resolve to a first-party application artifact."""
    if not is_address(target):
        return None, None, "deployment output did not contain a valid contract address"

    code_result = run_cast(["code", target, "--rpc-url", rpc], config={}, capture=True)
    runtime_code = str(code_result.text or "").strip()
    if code_result.code != 0 or runtime_code in {"", "0x", "0X"}:
        return None, None, "selected address has no live bytecode on the exact local Anvil"

    root_path = Path(root).expanduser().resolve()
    requested_lower = str(requested).strip().lower() if requested else None
    candidate_addresses = [target]

    # Native local harnesses frequently expose an ERC-1967 proxy as the public
    # target. Resolve its implementation explicitly before artifact matching.
    implementation = None
    implementation_result = run_cast(
        ["implementation", target, "--rpc-url", rpc],
        config={},
        capture=True,
    )
    implementation_text = str(implementation_result.text or "").strip()
    match = re.search(r"0x[0-9a-fA-F]{40}", implementation_text)
    if implementation_result.code == 0 and match:
        implementation = match.group(0)

    if not implementation or implementation.lower() == target.lower():
        implementation_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        storage_result = run_cast(
            ["storage", target, implementation_slot, "--rpc-url", rpc],
            config={},
            capture=True,
        )
        storage_text = str(storage_result.text or "").strip()
        words = re.findall(r"0x[0-9a-fA-F]{64}", storage_text)
        if words:
            slot_address = "0x" + words[-1][-40:]
            if is_address(slot_address) and int(slot_address, 16) != 0:
                implementation = slot_address

    if implementation and implementation.lower() != target.lower():
        candidate_addresses.insert(0, implementation)

    # Use deployments from the script Lowkey just executed before considering
    # any other broadcast run. This avoids a newer unrelated deployment from
    # shadowing a valid current lab deployment.
    try:
        deployments = discover_deployments(str(root_path))
    except Exception:
        deployments = []

    scoped = []
    if provenance_script:
        try:
            script_path = Path(provenance_script).expanduser().resolve()
            script_relative = script_path.relative_to(root_path).as_posix()
            broadcast_root = (root_path / "broadcast" / script_path.name).resolve()
            for item in deployments:
                if not isinstance(item, dict):
                    continue
                item_file = item.get("file")
                if not item_file:
                    continue
                try:
                    Path(item_file).expanduser().resolve().relative_to(broadcast_root)
                except (OSError, ValueError):
                    continue
                scoped.append(item)
        except (OSError, ValueError):
            scoped = []

    if scoped:
        provenance_records = scoped
    else:
        latest_timestamp = max(
            (
                int(item.get("run_timestamp") or 0)
                for item in deployments
                if isinstance(item, dict)
            ),
            default=0,
        )
        provenance_records = [
            item for item in deployments
            if isinstance(item, dict)
            and (
                int(item.get("run_timestamp") or 0) == latest_timestamp
                if latest_timestamp
                else True
            )
        ] if deployments else []

    application_artifacts = []
    for artifact_path in local_artifact_paths(str(root_path)):
        artifact_data = read_artifact(artifact_path) or {}
        if not artifact_is_project_application(str(root_path), artifact_path, artifact_data):
            continue
        artifact_name = artifact_contract_name(artifact_path, artifact_data)
        # "requested" is a discovery preference, not proof of the runtime
        # identity. A native lab may intentionally expose a protocol root
        # (for example a factory proxy) while the initially discovered target
        # was another application contract (for example a pool).
        deployed = artifact_data.get("deployedBytecode")
        if isinstance(deployed, dict):
            deployed = deployed.get("object")
        deployed = str(deployed or "").strip()
        application_artifacts.append((artifact_name, artifact_path, deployed))

    implementation_lower = implementation.lower() if implementation else None
    # For a direct deployment the target itself is the deployment identity.
    # For an ERC-1967 target the implementation is the deployment identity.
    provenance_address = implementation_lower or target.lower()

    for item in provenance_records:
        deployed_address = str(item.get("address") or "").lower()
        contract_name = str(item.get("contract") or "").strip()
        if deployed_address != provenance_address:
            continue
        for artifact_name, artifact_path, _ in application_artifacts:
            if artifact_name.strip().lower() == contract_name.lower():
                return artifact_name, artifact_path, None

    # Fall back to exact live runtime-bytecode matching when deployment
    # provenance is unavailable.
    for candidate in candidate_addresses:
        candidate_result = run_cast(["code", candidate, "--rpc-url", rpc], config={}, capture=True)
        candidate_runtime = str(candidate_result.text or "").strip()
        if candidate_result.code != 0 or candidate_runtime in {"", "0x", "0X"}:
            continue
        for artifact_name, artifact_path, deployed in application_artifacts:
            if deployed and deployed.lower() == candidate_runtime.lower():
                return artifact_name, artifact_path, None

    # Preserve the fail-closed behavior, but expose the evidence chain so a
    # repository with generated tests/POCs can be diagnosed without guessing.
    scoped_matches = []
    for item in provenance_records:
        if not isinstance(item, dict):
            continue
        if implementation_lower and str(item.get("address") or "").lower() == implementation_lower:
            scoped_matches.append(
                f"{item.get('contract') or 'Unknown'} @ {item.get('address')}"
            )
    artifact_summary = [
        f"{name} [{Path(path).relative_to(root_path).as_posix()}]"
        for name, path, _ in application_artifacts
    ]
    if not application_artifacts and not requested:
        # A project-native LOWKEY_TARGET marker is still useful in sparse/unit
        # fixtures where no build artifact exists. Keep the contract unresolved
        # instead of fabricating an ABI.
        return str(
            requested
            or (provenance_records[0].get("contract") if provenance_records else None)
            or "Target"
        ), None, None
    details = [
        f"target={target}",
        f"implementation={implementation or 'unresolved'}",
        f"provenance_script={Path(provenance_script).relative_to(root_path).as_posix() if provenance_script else 'none'}",
        f"provenance_matches={'; '.join(scoped_matches) if scoped_matches else 'none'}",
        f"application_artifacts={'; '.join(artifact_summary) if artifact_summary else 'none'}",
    ]
    return None, None, (
        "selected address could not be mapped to a current-project application artifact "
        "(" + " | ".join(details) + ")"
    )

def run_project_lab_script(config, root, script, rpc, accounts, key, requested=None, explicit_requested=False):
    relative = os.path.relpath(script, root)
    if not path_is_within(script, root):
        return fail("Error: selected lab script is outside the current project root.")
    before_sources = _project_source_fingerprint(root)
    print("LOWKEY LOCAL AUDIT LAB")
    print("======================")
    print(f"Project : {root}")
    print(f"Script  : {relative}")
    print(f"RPC     : {rpc_display(rpc)}")
    print(f"Actor   : Anvil #0 ({accounts[0]})")
    print("Mode    : project-native deployment script")
    print("Action  : executing the project's own deployment entry point...")

    script_env, unresolved_env = _lab_script_environment(script, rpc, key, accounts)
    if script_env:
        print(f"Config  : supplied safe local defaults for {len(script_env)} deployment variable(s)")
    if unresolved_env:
        print(
            "Config  : project also references environment variable(s) that Lowkey "
            "cannot safely invent: " + ", ".join(unresolved_env)
        )

    reserved = {
        "LOWKEY_LAB_KEY": str(int(str(key), 16)),
        "LOWKEY_BOB_KEY": str(int(str(derive_default_anvil_key(1) or key), 16)),
    }
    previous = {}
    for name, value in {**reserved, **script_env}.items():
        previous[name] = os.environ.get(name)
        os.environ[name] = value

    try:
        result = run_foundry(
            [
                "script",
                relative,
                "--rpc-url",
                rpc,
                "--broadcast",
                "--private-key",
                key,
            ],
            capture=True,
        )
    finally:
        for name, old_value in previous.items():
            if old_value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old_value

    output = result.text
    if result.code != 0:
        tail = "\n".join(output.splitlines()[-30:]) if output else "forge script failed"
        return fail(
            "Error: local project deployment script failed.\n"
            + tail
            + (
                "\nLowkey could not safely infer: " + ", ".join(unresolved_env)
                if unresolved_env
                else ""
            ),
            result.code,
        )

    target = parse_lab_marker(output)
    selected_record = None

    if not target:
        deployments = discover_deployments(root)
        wanted = str(requested or discover_audit_target_contract(root) or "").strip().lower()
        if wanted:
            matching = [
                item for item in deployments
                if str(item.get("contract") or "").strip().lower() == wanted
            ]
            if len(matching) == 1:
                selected_record = matching[0]
            elif len(matching) > 1:
                selected_record = matching[0]
        if selected_record is not None:
            target = selected_record.get("address")

    if not target:
        matches = re.findall(
            r"(?i)\b(?:Contract Address|Deployed to)\s*:?\s*(0x[0-9a-fA-F]{40})",
            output or "",
        )
        target = matches[-1] if matches else None

    if not target:
        return fail(
            "Error: local project deployment ran, but Lowkey could not identify a deployed application target. "
            "The script may require additional project-specific configuration."
        )

    if not is_address(target):
        return fail("Error: local project deployment did not produce a valid application target.")

    # Do not trust stale broadcast records from another chain/run. The selected
    # target must have bytecode on the exact Anvil RPC used for this lab and must
    # map back to a first-party application artifact in this project.

    system = parse_lab_system(output)
    if selected_record:
        system.setdefault("deployed_contract", target)
        if selected_record.get("contract"):
            system.setdefault("deployed_contract_name", selected_record["contract"])
    # LOWKEY_TARGET is the canonical target contract between a project-native
    # lab script and Lowkey. Other LOWKEY_* markers describe the deployed
    # protocol graph; they must never silently replace the canonical target.
    # This keeps native labs protocol-agnostic: a project may expose a factory,
    # pool, router, vault, proxy, implementation, etc. without Lowkey guessing
    # which one should become the audit target.
    effective_target = target
    if system:
        system.setdefault("target", target)

        config["lab_system"] = system
        config["_lab_system_root"] = str(Path(root).resolve())
        names = {
            "factory": "Factory",
            "pool": "Pool",
            "pool_implementation": "PoolImplementation",
            "stake_token": "StakeToken",
            "attack_registry": "AttackRegistry",
            "safe_harbor_registry": "SafeHarborRegistry",
            "agreement": "Agreement",
            "moderator": "Moderator",
            "deployed_contract": "DeployedContract",
        }
        for alias, address in system.items():
            if alias in {"alice", "bob"}:
                continue
            label = names.get(alias, alias)
            config.setdefault("aliases", {})[label] = address
            config.setdefault("targets", {})[label] = address
            config.setdefault("project_roots", {})[address] = str(Path(root).resolve())

    # Resolve the effective live target exclusively against this project's artifacts.
    # An explicit contract argument may override a native harness target.
    # In automatic mode, however, LOWKEY_TARGET is the harness author's
    # declared protocol root and must take precedence over Lowkey's heuristic
    # "most interesting contract" discovery. Otherwise a system harness that
    # deliberately exposes a factory proxy can be silently replaced by a pool.
    if requested and system and explicit_requested:
        requested_lower = str(requested).strip().lower()
        system_candidates = []
        for alias, address in system.items():
            if alias in {"alice", "bob"} or not is_address(address):
                continue
            temp_contract = config.get("target_contract")
            config["target_contract"] = None
            candidate_artifact = auto_abi_path(address, config, root=root)
            config["target_contract"] = temp_contract
            if candidate_artifact:
                candidate_data = read_artifact(candidate_artifact) or {}
                candidate_name = artifact_contract_name(candidate_artifact, candidate_data)
                if candidate_name.strip().lower() == requested_lower:
                    system_candidates.append((address, candidate_name, candidate_artifact))
        if len(system_candidates) == 1:
            effective_target = system_candidates[0][0]

    contract, artifact, target_error = _validate_project_lab_target(
        config,
        root,
        rpc,
        effective_target,
        requested=requested,
        provenance_script=script,
    )
    if target_error:
        return fail(
            "Error: local project lab produced an unsafe/ambiguous target. "
            + target_error
        )

    config["actor"] = "lab-deployer"
    config.setdefault("wallets", {})["lab-deployer"] = {
        "source": "anvil-default",
        "anvil_index": 0,
        "address": accounts[0],
    }
    config.setdefault("labels", {})[accounts[0]] = "lab-deployer"
    set_lab_target(config, root, effective_target, contract, artifact)

    print(f"Target  : {contract} -> {effective_target}")
    print(f"ABI     : {artifact or 'auto-discovered from build artifacts'}")
    _print_security_scope(root)
    print("Ready   : lk read ... | lk changes ... | lk trace")
    return 0

def _numeric_field_is_value_like(label):
    lowered = str(label or "").lower().replace("_", "")
    return any(
        word in lowered
        for word in (
            "amount", "value", "deposit", "withdraw", "payment",
            "fee", "collateral", "reward", "balance", "price", "cost",
            "limit", "threshold", "rate", "liquidity", "supply",
        )
    )


def _print_numeric_unit_reference(label, ptype):
    if not str(ptype).startswith(("uint", "int")):
        return
    if _numeric_field_is_value_like(label):
        print()
        print("NUMERIC UNIT REFERENCE")
        print("----------------------")
        print("  1 ETH      = 1,000,000,000,000,000,000 wei")
        print("  1 gwei     = 1,000,000,000 wei")
        print("  1 wei      = 0.000000000000000001 ETH")
        print("  0.001 ETH  = 1,000,000,000,000,000 wei")
        print("  ETH-denominated input detected. Examples: 0.5 ETH, 10 gwei, 1 wei")
    else:
        print("  Raw integer field. No ETH unit conversion is suggested for this field.")
    print()


def _normalize_human_numeric_input(value, ptype, label=''):
    if not (str(ptype).startswith('uint') or str(ptype).startswith('int')):
        return value

    raw = str(value or '').strip()
    grouped = re.sub(r'(?<=\d)[,_](?=\d)', '', raw)
    unit_match = re.fullmatch(
        r'([0-9]+(?:\.[0-9]+)?)\s*(wei|gwei|eth|ether)',
        grouped,
        re.I,
    )
    if unit_match:
        if not _numeric_field_is_value_like(label):
            raise ValueError(
                f"'{label}' is a raw integer field; enter the integer directly without ETH/gwei/wei units."
            )
        number = Decimal(unit_match.group(1))
        unit = unit_match.group(2).lower()
        scale = {
            "wei": Decimal(1),
            "gwei": Decimal(10**9),
            "eth": Decimal(10**18),
            "ether": Decimal(10**18),
        }[unit]
        scaled = number * scale
        if scaled != scaled.to_integral_value():
            raise ValueError(f"non-integer value '{value}' cannot be passed to {ptype}")
        return str(int(scaled))

    if re.fullmatch(r'(?:0x[0-9a-fA-F]+|[-+]?[0-9]+(?:\.[0-9]+)?)', grouped):
        return grouped

    return value
def _lab_address_choices(config, accounts):
    choices = []

    # Only expose addresses that are actually local actors or explicitly named
    # wallet profiles. Do not leak stale targets from another project.
    for index, address in enumerate(accounts or []):
        if is_address(address):
            choices.append((f"anvil:{index}", str(address)))

    for name, entry in (config.get("wallets", {}) or {}).items():
        if isinstance(entry, dict) and is_address(entry.get("address")):
            choices.append((str(name), str(entry["address"])))

    seen = set()
    result = []
    for name, address in choices:
        key = address.lower()
        if key not in seen:
            seen.add(key)
            result.append((name, address))
    return result


def _lab_constructor_default(contract, label, ptype):
    name = str(label or "").strip().lower()

    if ptype == "bool":
        return "false"

    if ptype == "string":
        if name in {"name", "poolname"}:
            return f"{contract} Lab"
        if name in {"symbol", "poolsymbol"}:
            return "LKL"
        if name in {"version", "poolversion"}:
            return "v1"

    return None


def _lab_array_parts(param):
    raw_type = str(param.get("type") or "")
    match = re.fullmatch(r"(.+?)\[(\d*)\]", raw_type)
    if not match:
        return None, None
    base_type = match.group(1)
    length = None if match.group(2) == "" else int(match.group(2))
    return base_type, length


def _lab_constructor_meaning(label, ptype, param=None):
    internal_type = str((param or {}).get("internalType") or "")
    normalized = str(ptype or "")

    if normalized == "address":
        if "payable" in internal_type:
            return "Ethereum address allowed to receive ETH."
        if internal_type.startswith("contract "):
            return "Contract address. This field requires deployed bytecode, not an Anvil EOA."
        return "Ethereum address. Lowkey shows known local actor addresses."

    if normalized == "bool":
        return "Boolean flag: true or false."

    if normalized == "string":
        return "Text value."

    if normalized.startswith(("uint", "int")):
        return "Integer value. Commas and underscores are accepted as visual separators; ETH/gwei/wei units are supported."

    if normalized == "bytes":
        return "Dynamic bytes. Enter hex, for example 0x1234."

    if normalized.startswith("bytes"):
        return "Fixed-size bytes value. Enter hex with the required byte length."

    if normalized.startswith("("):
        return "Structured tuple. Lowkey expands its named fields below."

    base_type, length = _lab_array_parts(param or {})
    if base_type is not None:
        if length is None:
            return f"Dynamic array of {base_type} values."
        return f"Fixed array of {base_type} values with exactly {length} item(s)."

    return f"ABI value of type {normalized}."


def _lab_scalar_value(config, accounts, contract, label, ptype, *, nested=False, default=None, param=None):
    print(f"  Field     : {label}")
    print(f"  Type      : {ptype}")
    print(f"  Meaning   : {_lab_constructor_meaning(label, ptype, param)}")

    if ptype.startswith(("uint", "int")):
        _print_numeric_unit_reference(label, ptype)
        print("  Input tip : commas/underscores are accepted in integers, e.g. 1,000,000.")

    if ptype == "address":
        choices = _lab_address_choices(config, accounts)
        requires_contract = str((param or {}).get("internalType") or "").startswith("contract ")
        if requires_contract:
            choices = [
                (name, address)
                for name, address in choices
                if not any(
                    str(address).lower() == str(account).lower()
                    for account in accounts or []
                )
            ]
            print("  Requirement: a live deployed contract is required for this parameter.")
        if choices:
            print("  Known local addresses:")
            for index, (name, address) in enumerate(choices[:12]):
                print(f"    [{index}] {name:<18} {address}")
            print("  Tip       : enter the number, name, or full address.")

    if default is not None:
        print(f"  Suggested : {default}")

    prompt = f"  Value{' [Enter = ' + default + ']' if default is not None else ''}: "
    value = input(prompt).strip()

    if not value:
        if default is None:
            raise ValueError(f"'{label}' needs a value.")
        value = default

    if ptype == "address":
        choices = _lab_address_choices(config, accounts)
        requires_contract = str((param or {}).get("internalType") or "").startswith("contract ")
        if value.isdigit() and int(value) < len(choices):
            value = choices[int(value)][1]
        else:
            lower = value.lower()
            for name, address in choices:
                if name.lower() == lower:
                    value = address
                    break

        if requires_contract and any(
            str(value).lower() == str(account).lower() for account in accounts or []
        ):
            raise ValueError(
                f"'{label}' requires a deployed contract address; Anvil accounts are EOAs."
            )

        rpc = config.get("_lab_rpc")
        if requires_contract and rpc and is_address(value):
            code_check = run_cast(["code", value, "--rpc-url", rpc], config={}, capture=True)
            runtime_code = str(code_check.text or "").strip()
            if code_check.code != 0 or runtime_code in {"", "0x", "0X"}:
                raise ValueError(
                    f"'{label}' points to {value}, but no deployed bytecode exists at that address on the local Anvil."
                )

    if ptype.startswith(("uint", "int")):
        value = _normalize_human_numeric_input(value, ptype, label)

    if nested and ptype == "string":
        return json.dumps(value, ensure_ascii=False)

    return value


def _lab_prompt_value(config, accounts, contract, param, path="root", nested=False):
    raw_type = str(param.get("type") or "")
    label = str(param.get("name") or path)

    # Handle dynamic and fixed arrays recursively from ABI metadata.
    base_type, fixed_length = _lab_array_parts(param)
    if base_type is not None:
        element = dict(param)
        element["type"] = base_type

        print()
        print(f"{path}  {label}")
        print(f"  Type      : {canonical_type(param)}")
        print(f"  Meaning   : {_lab_constructor_meaning(label, canonical_type(param), param)}")

        if fixed_length is None:
            raw_count = input("  Number of items [0]: ").strip()
            count = 0 if not raw_count else int(raw_count)
        else:
            count = fixed_length
            print(f"  Length    : fixed at {count}")

        if count < 0:
            raise ValueError(f"{label}: item count cannot be negative")

        values = []
        for index in range(count):
            values.append(
                _lab_prompt_value(
                    config,
                    accounts,
                    contract,
                    element,
                    path=f"{path}[{index}]",
                    nested=True,
                )
            )

        return "[" + ",".join(values) + "]"

    # Handle structs/tuples recursively using the ABI component metadata.
    if raw_type.startswith("tuple"):
        components = param.get("components") or []
        if not isinstance(components, list):
            raise ValueError(f"{label}: tuple components are missing from the ABI.")

        print()
        print(f"{path}  {label}")
        print(f"  Type      : {canonical_type(param)}")
        print("  Meaning   : Lowkey expanded this struct so you don't have to write ABI tuple syntax.")

        values = []
        for index, component in enumerate(components, 1):
            child_label = component.get("name") or f"field{index}"
            values.append(
                _lab_prompt_value(
                    config,
                    accounts,
                    contract,
                    component,
                    path=f"{path}.{child_label}",
                    nested=True,
                )
            )

        return "(" + ",".join(values) + ")"

    ptype = canonical_type(param)
    default = _lab_constructor_default(contract, label, ptype)

    print()
    return _lab_scalar_value(
        config,
        accounts,
        contract,
        label,
        ptype,
        nested=nested,
        default=default,
        param=param,
    )


def _deployment_tx_hash(output):
    """Extract a deployment transaction hash from Cast output."""
    patterns = [
        r'(?i)\btransaction(?:\s+hash|hash)\s*[:=]\s*(0x[0-9a-fA-F]{64})',
        r'(?i)\btx\s+hash\s*[:=]\s*(0x[0-9a-fA-F]{64})',
        r'(?i)"(?:transactionHash|transaction_hash|hash)"\s*:\s*"(0x[0-9a-fA-F]{64})"',
    ]
    for pattern in patterns:
        match = re.search(pattern, str(output or ""))
        if match:
            return match.group(1)
    return None


def _deployment_receipt_address(rpc, tx_hash):
    """Read the mined CREATE receipt and return only its contract address."""
    if not rpc or not is_tx_hash(tx_hash):
        return None

    commands = [
        ["cast", "receipt", tx_hash, "--rpc-url", rpc, "--json"],
        ["cast", "receipt", tx_hash, "--rpc-url", rpc],
    ]
    for command in commands:
        code, output, error = cast_output(command)
        if code != 0 and not output:
            continue

        raw = str(output or "").strip()
        payloads = [raw]
        try:
            payload = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            payload = None

        if isinstance(payload, dict):
            payloads.insert(0, json.dumps(payload))
            for wrapper in ("receipt", "result"):
                nested = payload.get(wrapper)
                if isinstance(nested, dict):
                    payloads.insert(0, json.dumps(nested))

        combined = "\n".join(payloads + [str(error or "")])
        patterns = [
            r'(?i)"contractAddress"\s*:\s*"(0x[0-9a-fA-F]{40})"',
            r'(?i)"contract_address"\s*:\s*"(0x[0-9a-fA-F]{40})"',
            r'(?i)\bcontractAddress\s*[:=]\s*(0x[0-9a-fA-F]{40})',
            r'(?i)\bcontract address\s*[:=]\s*(0x[0-9a-fA-F]{40})',
        ]
        for pattern in patterns:
            match = re.search(pattern, combined)
            if match:
                return match.group(1)
    return None


def _live_deployed_address(rpc, candidates):
    """Return the first candidate proven to contain runtime bytecode."""
    for candidate in candidates:
        if not is_address(candidate):
            continue
        try:
            code, runtime, _ = cast_output(["cast", "code", candidate, "--rpc-url", rpc])
        except Exception:
            continue
        if code == 0 and str(runtime or "").strip().lower() not in {"", "0x", "0x0"}:
            return candidate
    return None


def _deploy_artifact_locally(config, root, rpc, accounts, artifact, constructor_inputs):
    """Deploy an ABI-bearing artifact directly with cast on local EVM nodes."""
    if not artifact_is_deployable(artifact):
        return None, "artifact has no deployable bytecode"

    bytecode = artifact.get("bytecode")
    creation = bytecode.get("object") if isinstance(bytecode, dict) else bytecode
    creation = str(creation or "").strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]+", creation):
        return None, "artifact bytecode is not valid hex"

    contract = artifact.get("contractName") or artifact.get("sourceName") or "target"

    print()
    print("CONSTRUCTOR WIZARD")
    print("==================")
    print("Lowkey expands structs and arrays from the ABI.")
    print("Lowkey prefers project-native deployment/test harnesses; the generic deployer is the fallback.")
    print("")

    values = []
    for index, param in enumerate(constructor_inputs or [], 1):
        try:
            values.append(
                _lab_prompt_value(
                    config,
                    accounts,
                    str(contract),
                    param,
                    path=f"params[{index}]",
                    nested=False,
                )
            )
        except (EOFError, KeyboardInterrupt):
            return None, "local lab cancelled"
        except (TypeError, ValueError) as error:
            return None, f"constructor input error: {error}"

    command = [
        "cast", "send",
        "--rpc-url", rpc,
        "--unlocked", "--from", accounts[0],
        "--create", creation,
    ]

    if constructor_inputs:
        signature = "constructor(" + ",".join(
            canonical_type(item) for item in constructor_inputs
        ) + ")"
        command.append(signature)
        command.extend(values)

    result = subprocess.run(
        command,
        cwd=str(root),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "cast deployment failed").strip()
        return None, detail[-1200:]

    output = "\n".join(
        part.strip()
        for part in ((result.stdout or ""), (result.stderr or ""))
        if part.strip()
    )

    # Never treat arbitrary address-shaped text as the deployed contract.
    # Cast output can contain the sender address, which is commonly an Anvil EOA.
    tx_hash = _deployment_tx_hash(output)
    receipt_target = _deployment_receipt_address(rpc, tx_hash) if tx_hash else None

    labeled_targets = []
    for pattern in (
        r"(?i)\bcontractAddress\s*[:=]\s*(0x[0-9a-fA-F]{40})",
        r"(?i)\bcontract address\s*[:=]\s*(0x[0-9a-fA-F]{40})",
        r"(?i)\bdeployed to\s*[:=]\s*(0x[0-9a-fA-F]{40})",
        r'(?i)"(?:contractAddress|contract_address)"\s*:\s*"(0x[0-9a-fA-F]{40})"',
    ):
        labeled_targets.extend(match.group(1) for match in re.finditer(pattern, output))

    candidates = []
    if receipt_target:
        candidates.append(receipt_target)
    candidates.extend(labeled_targets)

    # As a compatibility fallback for Cast versions with unusual receipt output,
    # only accept an address after proving it has runtime bytecode on this exact RPC.
    if not candidates:
        candidates = re.findall(r"\b0x[0-9a-fA-F]{40}\b", output)

    target = _live_deployed_address(rpc, candidates)
    if target:
        return target, None

    if tx_hash:
        return None, (
            "deployment transaction succeeded, but Lowkey could not identify a live "
            f"contract from receipt {tx_hash}. The sender address will never be accepted as the target."
        )
    return None, "deployment succeeded, but Lowkey could not identify a live deployed contract address"


def run_generic_lab(config, root, rpc, accounts, key, requested=None, mode="generic"):
    config["_lab_system_root"] = str(Path(root).resolve())
    config.pop("lab_system", None)
    candidate = (
        discover_artifact_lab_contract(root, requested)
        if mode == "artifact"
        else discover_generic_lab_contract(root, requested)
    )
    if not candidate:
        app = discover_audit_target_contract(root)
        return fail(
            "Local lab target discovery failed. "
            + (f"Lowkey identified '{app}' as the likely application contract, but could not match it to deployable bytecode. "
               if app else
               "Lowkey could not identify a first-party application contract with deployable bytecode. ")
            + "Fix: run 'lk build', then 'lk lab <ContractName>' for the exact contract. "
            + "If it still fails, run 'lk project' and check the dependency/target diagnostics."
        )

    _score, contract, path, artifact, constructor_inputs, fqn = candidate

    print("LOWKEY LOCAL AUDIT LAB")
    print("======================")
    print(f"Project : {root}")
    print(f"Target  : {contract}")
    print(f"RPC     : {rpc_display(rpc)}")
    print(f"Actor   : Anvil #0 ({accounts[0]})")
    if mode == "artifact":
        print("Mode    : explicit artifact deployment")
    else:
        print("Mode    : generic ABI deployment")

    print(f"Action  : deploying {contract}...")
    project = project_tools.detect_project(root) if project_tools is not None else {}
    kind = str(project.get("kind") or ("foundry" if (Path(root) / "foundry.toml").is_file() else "generic"))

    # Use one artifact deployment path across Foundry/Hardhat/Brownie/Vyper-on-EVM.
    # It supports constructor prompts instead of assuming a zero-argument contract.
    try:
        target, reason = _deploy_artifact_locally(
            config, root, rpc, accounts, artifact, constructor_inputs
        )
    finally:
        config.pop("_lab_rpc", None)
    if not target:
        label = "artifact" if mode == "artifact" else "generic"
        return fail(
            f"Error: {label} local deployment failed. {reason or ''}".strip(),
            1,
        )

    has_initializer = artifact_has_initializer(artifact)
    if has_initializer:
        print(f"Target  : {contract} -> {target}")
        print(f"ABI     : {path}")
        print("Status  : DEPLOYED IMPLEMENTATION")
        print("Note    : this artifact exposes initialize(); a proxy/initializer may be required.")
        print("         Lowkey used the project's own deployment script first when one was available.")

    current_actor = config.get("actor")
    current_entry = config.get("wallets", {}).get(current_actor) if current_actor else None
    if not (
        current_actor
        and isinstance(current_entry, dict)
        and current_entry.get("source") not in {"anvil-default", "anvil-impersonated"}
    ):
        _ensure_lab_deployer(config, accounts[0], 0)
    set_lab_target(config, root, target, contract, path)
    config["_lab_system_root"] = str(Path(root).resolve())
    config["lab_system"] = {
        "root": target,
        "target": target,
        "root_model": contract,
        "target_model": contract,
    }

    print(f"Target  : {contract} -> {target}")
    print(f"ABI     : {path}")
    _print_security_scope(root)
    print("Ready   : lk read ... | lk changes ... | lk trace")
    return 0

def _tracked_scarb_manifest_drift(root):
    """Report tracked Scarb manifests that differ from the repository HEAD.

    This is diagnostics-only. Lowkey never rewrites the user's manifests or
    lockfiles; it uses git HEAD as evidence when a native resolver conflict
    occurs.
    """
    root_path = Path(root).expanduser().resolve()
    try:
        git_result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if git_result.returncode != 0:
        return []

    repo_root = Path((git_result.stdout or "").strip()).resolve()
    if not repo_root.is_dir():
        return []

    manifests = []
    current = root_path
    while True:
        for name in ("Scarb.toml", "Scarb.lock"):
            path = current / name
            if not path.is_file():
                continue
            try:
                relative = path.relative_to(repo_root).as_posix()
            except ValueError:
                continue
            try:
                current_text = path.read_text(encoding="utf-8", errors="replace")
                tracked = subprocess.run(
                    ["git", "show", f"HEAD:{relative}"],
                    cwd=repo_root,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if tracked.returncode == 0 and current_text != (tracked.stdout or ""):
                manifests.append(relative)

        if current == repo_root:
            break
        try:
            next_current = current.parent
            next_current.relative_to(repo_root)
        except ValueError:
            break
        current = next_current

    return sorted(set(manifests))


def run_native_lab(config, root, project):
    """Run a backend-native local lab for non-EVM projects.

    EVM labs materialize an Anvil contract address and ABI. Cairo/Starknet and
    other non-EVM stacks have different execution/state models, so never route
    them through Anvil/ABI bytecode discovery. Prefer the project's native
    build/test runner and report the resulting local execution honestly.
    """
    root_path = Path(root).expanduser().resolve()
    backend = str(project.get("backend") or project.get("kind") or "generic").lower()
    kind = str(project.get("kind") or "").lower()

    if backend == "cairo-starknet" or kind in {"cairo", "cairo-starknet"}:
        if not shutil.which("scarb"):
            return fail("Error: Cairo/Starknet project detected, but 'scarb' is not installed.")
        commands = [["scarb", "build"]]
        if shutil.which("snforge"):
            commands.append(["snforge", "test"])
        elif (root_path / "Scarb.toml").is_file():
            commands.append(["scarb", "test"])
    elif backend in {"move", "solana-anchor"} or kind in {"move", "move-source", "solana-anchor"}:
        return fail(
            f"Error: {kind or backend} projects do not have an interactive Lowkey lab backend yet. "
            "Lowkey will not pretend they are EVM projects or start Anvil for them."
        )
    else:
        return fail(
            f"Error: backend '{backend}' is non-EVM and has no native Lowkey lab adapter yet. "
            "Lowkey will not route it through Anvil/ABI deployment."
        )

    print("LOWKEY NATIVE LOCAL LAB")
    print("=======================")
    print(f"Project : {root_path}")
    print(f"Backend : {backend}")
    print("Mode    : native toolchain execution")
    print("State   : isolated to the project's native runner; no Anvil and no EVM deployment")

    for command in commands:
        print(f"Action  : {' '.join(command)}")
        try:
            completed = subprocess.run(
                command,
                cwd=root_path,
                capture_output=True,
                text=True,
                timeout=900,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"FAIL    : {exc}", file=sys.stderr)
            return fail("Error: native lab command could not be executed.", 1)

        output = "\n".join(
            part.strip() for part in (completed.stdout or "", completed.stderr or "")
            if part and part.strip()
        )
        if output:
            print(output)
        if completed.returncode != 0:
            classification = classify_build_failure(output, command) if callable(classify_build_failure) else {
                "category": "source_or_build_error",
                "reason": "Native toolchain command failed.",
                "repairable": False,
            }
            print(
                f"NATIVE LAB FAILURE : {classification.get('category', 'unknown')}",
                file=sys.stderr,
            )
            print(
                f"Reason             : {classification.get('reason', '')}",
                file=sys.stderr,
            )
            if classification.get("category") == "dependency_conflict":
                print(
                    "Action             : dependency constraints must be reconciled in the project manifest/workspace; "
                    "Lowkey will not silently rewrite them.",
                    file=sys.stderr,
                )
                drift = _tracked_scarb_manifest_drift(root_path)
                if drift:
                    print("Manifest drift     : detected against git HEAD", file=sys.stderr)
                    for manifest in drift:
                        print(f"  modified         : {manifest}", file=sys.stderr)
                    print(
                        "Manifest note      : local Scarb metadata differs from the checked-out commit; "
                        "resolve the local change before treating the repository dependency graph as canonical.",
                        file=sys.stderr,
                    )
                else:
                    print(
                        "Manifest drift     : none detected for Scarb.toml/Scarb.lock against git HEAD",
                        file=sys.stderr,
                    )
            print(
                f"Command            : {' '.join(command)} (exit {completed.returncode})",
                file=sys.stderr,
            )
            return completed.returncode
        print(f"PASS    : {' '.join(command)}")

    print("Ready   : native build/test state completed; EVM commands such as 'lk read' require an EVM lab target.")
    return 0

def run_lab(config,args):
    if args and args[0].lower() in {"help","-h","--help"}:
        print("Usage:")
        print("  lk lab [Contract]")
        print("  lk lab --generic [Contract]")
        print("  lk lab --artifact <Contract>")
        print("  lk lab stop")
        print("")
        print("MODES")
        print("  auto      Let Lowkey choose the easiest way to build a working local lab.")
        print("            It reuses the project's own setup when possible, then deploys directly.")
        print("  --generic Start from a contract and enter its constructor values yourself.")
        print("             Optional Contract chooses which contract to deploy.")
        print("  --artifact Deploy the exact compiled contract you name.")
        print("             Useful when a project has several contracts with similar names.")
        print("")
        print("EXAMPLES")
        print("  lk lab")
        print("      Let Lowkey set up a realistic local lab automatically.")
        print("  lk lab MyContract")
        print("      Same as above, but prefer MyContract as the main target.")
        print("  lk lab --generic")
        print("      Skip the project's setup and deploy a contract directly.")
        print("  lk lab --generic MyContract")
        print("      Deploy MyContract directly and answer its constructor prompts.")
        print("  lk lab --artifact MyContract")
        print("      Deploy exactly this compiled contract.")
        print("  lk lab stop")
        print("      Stop the local Anvil instance started by Lowkey.")
        return 0

    root = audit_context.foundry_project_root()
    if not root:
        return fail("Error: Lowkey could not resolve the current project root.")

    # Lab state is project-scoped. Clear transient protocol state whenever the
    # caller moves between repositories so a previous lab can never become the
    # current project's protocol graph or walkthrough target.
    project_root_key = str(Path(root).resolve())
    if config.get("_lowkey_active_project_root") != project_root_key:
        config["_lowkey_active_project_root"] = project_root_key
        config.pop("lab_system", None)
        config.pop("_walkthrough_observed", None)
        config.pop("_walkthrough_recipe", None)

    # A repository root may be a workspace/monorepo rather than the project to audit.
    # Lowkey discovers nested projects from manifests and source trees without assuming
    # names such as "pkg", "contracts", or any particular language.
    if is_workspace_root is not None and is_workspace_root(root):
        workspace_container = Path(root).resolve()
        active = workspace_selection(workspace_container) if workspace_selection is not None else None
        candidates = discover_nested_projects(workspace_container) if discover_nested_projects is not None else []

        if active is not None and active.is_dir():
            root = active
            print(f"INFO  Using active project: {Path(root).resolve().relative_to(workspace_container).as_posix()}")
        elif len(candidates) == 1:
            root = candidates[0]["root"]
            if set_workspace_selection is not None:
                set_workspace_selection(workspace_container, root)
            print(f"INFO  Found one project inside this workspace: {Path(root).resolve().relative_to(workspace_container).as_posix()}")
        elif len(candidates) > 1:
            print()
            print("LOWKEY FOUND MULTIPLE PROJECTS")
            print("============================")
            print(f"Workspace: {workspace_container}")
            print("Choose the project whose code, tests, setup, and local state should form the lab scope.")
            _print_workspace_scope_choices(candidates)
            if not sys.stdin.isatty():
                return fail(
                    "Error: this workspace contains multiple projects. "
                    "Run 'lk projects <number>' first, or run 'lk lab' from the project directory."
                )
            while True:
                try:
                    choice = input("Choose a project [1-%d] or q to cancel: " % len(candidates)).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return fail("Project selection cancelled.")
                if choice == "q":
                    return fail("Project selection cancelled.")
                if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                    root = candidates[int(choice) - 1]["root"]
                    if set_workspace_selection is not None:
                        set_workspace_selection(workspace_container, root)
                    print(f"ACTIVE PROJECT: {Path(root).resolve().relative_to(workspace_container).as_posix()}")
                    break
                print("Please enter one of the project numbers, or q.")
    project = project_tools.detect_project(root) if project_tools is not None else {}
    kind = str(project.get("kind") or "generic")

    # Non-Foundry lab paths need the same repository-local dependency bootstrap
    # that native audits receive. Foundry keeps its build-specific recovery loop,
    # which can use compiler diagnostics to repair incomplete dependencies.
    if kind not in {"foundry", "mixed-foundry-vyper"} and bootstrap_project is not None:
        bootstrap_info = dict(project)
        bootstrap_info["root"] = str(root)
        bootstrap_code = bootstrap_project(bootstrap_info)
        if bootstrap_code != 0:
            print(
                "Warning: project dependency bootstrap reported failures; "
                "Lowkey will continue only if the native build/artifact checks succeed.",
                file=sys.stderr,
            )

    # Non-EVM backends must not fall through into the Anvil/ABI lab path.
    if str(project.get("backend") or "").lower() == "cairo-starknet" or str(project.get("kind") or "").lower() in {"cairo", "cairo-starknet"}:
        return run_native_lab(config, root, project)

    # Vyper projects do not have Forge artifacts. Build the project's own Vyper
    # sources before target discovery so lk lab never falls back to stale/test-only
    # artifacts from another phase.
    if kind in {"vyper", "vyper-uv"}:
        try:
            from forge_tools import run_vyper_build
        except ImportError as exc:
            return fail(f"Error: Vyper build layer unavailable: {exc}")
        build_code = run_vyper_build(quiet=True)
        if build_code != 0:
            # Vyper projects can contain unrelated application contracts that do
            # not compile in isolation. Keep the safe target-discovery gate below:
            # only successfully compiled, first-party artifacts may become a lab target.
            print(
                "Warning: Vyper build reported failures; Lowkey will use only successfully "
                "compiled first-party artifacts.",
                file=sys.stderr,
            )

    # Lowkey-generated walkthrough replay scripts are derived artifacts, not
    # project source. Archive stale copies before the lab build so an older
    # generated script cannot break a fresh lab bootstrap.
    if kind in {"foundry", "mixed-foundry-vyper"} and walkthrough is not None:
        archived = walkthrough._quarantine_generated_replays(root)
        if archived:
            print(f"  Refreshed {archived} previous generated walkthrough replay(s)")
    
    if args and args[0].lower() == "stop":
        return stop_project_anvil(root)

    source_issue = _lab_source_integrity_issue(root)
    if source_issue:
        relative_source, line, sentinel = source_issue
        return fail(
            "Error: Lowkey source-integrity check failed. "
            f"Found live Lowkey terminal output in {relative_source}:{line} ({sentinel}). "
            "Lowkey will not modify, compile, or deploy a project whose first-party source "
            "contains generated lab output. Remove the injected output and rerun 'forge build'."
        )

    # A clean checkout should be enough. Build before reading artifacts so the
    # lab does not depend on a manual "lk build" step.
    if kind in {"foundry", "mixed-foundry-vyper"}:
        build_code = _run_project_build(config, root)
        if build_code != 0:
            return fail(
                "Error: project build failed; Lowkey will not deploy stale or partial artifacts.",
                build_code,
            )

    mode = "auto"
    requested = None
    if args:
        first = str(args[0]).strip()
        lowered = first.lower()
        if lowered in {"generic", "--generic"}:
            mode = "generic"
            requested = str(args[1]).strip() if len(args) > 1 else None
        elif lowered in {"artifact", "--artifact"}:
            mode = "artifact"
            requested = str(args[1]).strip() if len(args) > 1 else None
        elif lowered in {"forge", "--forge"}:
            # Backward-compatible alias: bypass native harnesses and use generic deployment.
            mode = "generic"
            requested = str(args[1]).strip() if len(args) > 1 else None
        else:
            requested = first

        if len(args) > (2 if mode in {"generic", "artifact"} else 1):
            return fail("Usage: lk lab [Contract] | lk lab --generic [Contract] | lk lab --artifact <Contract> | lk lab stop")
        if mode == "artifact" and not requested:
            return fail("Usage: lk lab --artifact <Contract>")
        if mode == "generic" and not sys.stdin.isatty():
            return fail(
                "Error: 'lk lab --generic' needs interactive constructor input. "
                "Run it from a terminal, or use 'lk lab --artifact <Contract>' for a non-interactive lab."
            )
    
    auto_selected = requested or discover_audit_target_contract(root)
    script = discover_local_lab_script(root, auto_selected) if mode == "auto" else None
    fixture = discover_local_lab_fixture(root, auto_selected) if mode == "auto" else None

    rpc = effective_rpc(config)
    info = anvil_rpc_info(config)

    # "lk lab" is always local. A stale remote/custom RPC must not prevent a
    # disposable Anvil from being created for the current project.
    if config.get("rpc") and not info:
        print(
            f"Configured RPC {config.get('rpc')} is not an Anvil node; "
            "lk lab will use a disposable local Anvil."
        )
        config["rpc"] = None
        rpc = None
        info = None

    if not info:
        info = ensure_project_anvil(config, root)
        rpc = info.get("url") if isinstance(info, dict) else effective_rpc(config)
        if rpc:
            config["rpc"] = rpc

    if not rpc or not info:
        return fail("Error: no local Anvil detected and Lowkey could not start one.")

    accounts = info.get("accounts", [])
    if not accounts:
        return fail("Error: the detected Anvil node reported no accounts.")
    key = derive_default_anvil_key(0)
    if not key:
        return fail("Error: could not derive the default Anvil account #0 key.")

    config["_lab_rpc"] = rpc

    if script:
        script_code = run_project_lab_script(
            config,
            root,
            script,
            rpc,
            accounts,
            key,
            requested,
            explicit_requested=bool(args) and mode == "auto" and str(args[0]).strip().lower() not in {"", "auto"},
        )
        if script_code == 0:
            return 0
        if fixture:
            print(
                "INFO  native deployment script did not produce a usable lab; "
                "Lowkey will try the discovered project test fixture."
            )
            fixture_code = run_test_fixture_lab(
                config, root, fixture, rpc, accounts, key, requested
            )
            if fixture_code == 0:
                return 0
        return script_code

    if fixture:
        fixture_code = run_test_fixture_lab(
            config, root, fixture, rpc, accounts, key, auto_selected
        )
        if fixture_code == 0:
            return 0
        print(
            "INFO  discovered project fixture could not be promoted; "
            "falling back to generic artifact deployment."
        )

    # No harness? Prefer the audit evidence; it usually points at the application's
    # most security-relevant implementation contract.
    if not requested:
        requested = discover_audit_target_contract(root)

    if not requested:
        context = audit_context.load(root)
        focus = context.get("focus") or {}
        focus_id = focus.get("signal_id") if isinstance(focus, dict) else None
        if focus_id:
            signal = next(
                (
                    item for item in audit_context.signals(root)
                    if isinstance(item, dict) and item.get("id") == focus_id
                ),
                None,
            )
            if isinstance(signal, dict) and signal.get("function"):
                requested = str(signal.get("function")).split("(", 1)[0]

    return run_generic_lab(config, root, rpc, accounts, key, requested, mode=mode)

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
    # Cast can emit decoder failures through either stderr or stdout while
    # still returning a zero status. Explicit decoder-error text means the
    # event was not successfully decoded, so Lowkey must propagate failure.
    emitted_error = str(error or "") + "\n" + str(output or "")
    decoder_failed = bool(error) or bool(
        re.search(r"(?i)(abi decoding failed|decoding failed|buffer overrun while deserializing)", emitted_error)
    )
    effective_code = code if code != 0 else (1 if decoder_failed else 0)
    return record_status(effective_code)

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


def _bounded_forge_timeout(args):
    if "--watch" in args:
        return None
    raw = os.environ.get("LOWKEY_FORGE_TIMEOUT", "900")
    try:
        requested = int(raw)
    except (TypeError, ValueError):
        requested = 900
    return max(30, min(requested, 7200))


def _run_bounded_process(command, capture, cwd, timeout):
    process = subprocess.Popen(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
        start_new_session=(os.name == "posix"),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout or "", stderr or "", False
    except subprocess.TimeoutExpired as exc:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.kill()
        except OSError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except OSError:
                pass
            stdout, stderr = process.communicate()
        if stdout is None:
            stdout = exc.stdout or ""
        if stderr is None:
            stderr = exc.stderr or ""
        return 124, stdout or "", stderr or "", True


def run_foundry(args, capture=False, cwd=None):
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
    timeout = _bounded_forge_timeout(args)
    try:
        code, stdout, stderr, timed_out = _run_bounded_process(
            [binary, *args], capture, cwd if cwd is not None else root, timeout
        )
    except OSError as error:
        message = f"Error executing forge: {error}"
        audit_context.emit("forge-command", root, tool="forge", status="failed", summary=command_name)
        result = CommandResult(message, 1)
        record_status(result.code)
        if capture:
            return result
        print(message, file=sys.stderr)
        return result.code
    if timed_out:
        message = (
            f"TIMEOUT: forge {command_name} exceeded {timeout}s and its process group "
            "was terminated. No security conclusion is supported by this run. "
            "Adjust LOWKEY_FORGE_TIMEOUT (30-7200s) if needed."
        )
        audit_context.emit(
            "forge-command", root, tool="forge", status="failed",
            summary=f"forge {command_name}",
            data={"command": command_name, "exit_code": 124, "timeout": True},
        )
        record_status(124)
        if capture:
            return CommandResult(message, 124)
        print(message, file=sys.stderr)
        return 124
    output = "\n".join(part.strip() for part in (stdout, stderr) if part).strip()
    audit_context.emit(
        "forge-command", root, tool="forge",
        status="completed" if code == 0 else "failed",
        summary=f"forge {command_name}",
        data={"command": command_name, "exit_code": code, "timeout": False},
    )
    if capture:
        result = CommandResult(output, code)
        record_status(code)
        return result
    return record_status(code)


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
    text = str(value).strip()
    if not (item_type.startswith("uint") or item_type.startswith("int")):
        return value

    # Accept common human formatting for integer amounts.
    text = re.sub(r'(?<=\d)[,_](?=\d)', '', text)

    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*(wei|gwei|ether)", text, re.I)
    if not match:
        return text

    try:
        number = Decimal(match.group(1))
        unit = match.group(2).lower()
        scale = {"wei": Decimal(1), "gwei": Decimal(10**9), "ether": Decimal(10**18)}[unit]
        scaled = number * scale
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
            signature_text = format_signature(matches[0])
            hint = ""
            if inputs:
                placeholders = " ".join(
                    f"<{item.get('name') or 'arg'+str(index+1)}>"
                    for index,item in enumerate(inputs)
                )
                hint = f" Use: lk changes '{signature_text}' {placeholders}."
            raise ValueError(
                f"{signature_text} expects {len(inputs)} argument(s), got {len(values)}.{suffix}"
                f" The quoted function signature contains TYPES; pass real VALUES after the closing quote."
                f"{hint}"
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
        if re.fullmatch(r"(?i)(?:[0-9]+(?:\.[0-9]+)?)(?:ether|gwei|wei)",text):
            return text
        if (
            re.fullmatch(r"[0-9]+(?:\.[0-9]+)?",text)
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


def run_cheat(args):
    if solidity_cheatsheet is None:
        return fail("Solidity cheatsheet is not installed. Re-run install.sh from this checkout.")
    return solidity_cheatsheet.run(args)


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
        return [root] if str(root).endswith(".sol") else []
    if not os.path.isdir(root):
        return []
    if project_tools is not None:
        try:
            return [str(path) for path in project_tools.project_source_files(root, {"sol"})]
        except Exception:
            pass
    paths=[]
    for path,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in {".git","out","cache","node_modules","artifacts","build",".audit"}]
        for filename in files:
            if filename.endswith(".sol"): paths.append(os.path.join(path,filename))
    return sorted(paths)

def source_vyper_files(root):
    if os.path.isfile(root):
        return [root] if str(root).endswith(".vy") else []
    if not os.path.isdir(root):
        return []
    if project_tools is not None:
        try:
            return [str(path) for path in project_tools.project_source_files(root, {"vy", "vyi"})]
        except Exception:
            pass
    paths=[]
    for path,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in {".git","out","cache","node_modules","artifacts","build",".audit"}]
        for filename in files:
            if filename.endswith((".vy",".vyi")): paths.append(os.path.join(path,filename))
    return sorted(paths)

def source_evm_files(root):
    return sorted(set(source_sol_files(root) + source_vyper_files(root)))

def _strip_scan_comments(text: str, language="solidity") -> str:
    return _source_comment_strip(text, language)

def _source_comment_strip(text: str, language="solidity") -> str:
    chars = list(text)
    state = "code"
    quote = ""
    escape = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if language == "vyper" and ch == "#":
                chars[i] = " "
                i += 1
                state = "line"
                continue
            if language != "vyper" and ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line"
                continue
            if language != "vyper" and ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block"
                continue
            if ch in {"'", '"'}:
                quote = ch
                escape = False
                state = "string"
            i += 1
            continue
        if state == "line":
            if ch == "\n":
                state = "code"
            elif ch != "\n":
                chars[i] = " "
            i += 1
            continue
        if state == "block":
            if language != "vyper" and ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
            i += 1
            continue
        if escape:
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == quote:
            state = "code"
            quote = ""
        i += 1
    return "".join(chars)

def run_scan(args):
    root = args[0] if args else "."
    if not os.path.exists(root):
        return fail(f"Path not found: {root}")

    # Universal source triage is the first-class path for every repository.
    # Keep the legacy EVM scanner below as a compatibility fallback only.
    try:
        from analysis_adapters import scan_repository
    except ImportError:
        scan_repository = None

    if scan_repository is not None:
        try:
            # scan_repository owns the adapter-specific result semantics. Do not
            # reclassify a successful source-only/single-file EVM scan as a
            # failure merely because repository-wide coverage is not possible.
            universal_result = scan_repository(root)
            try:
                audit_root = audit_context.foundry_project_root(Path(root).resolve())
                scope = {}
                try:
                    from analysis_adapters import inspect_repository
                    scope = inspect_repository(root)
                except Exception:
                    scope = {}
                audit_context.record_tool(
                    "source-triage",
                    audit_root,
                    status=(
                        "completed" if universal_result == 0
                        else "review_needed" if universal_result == 2
                        else "failed"
                    ),
                    summary="universal repository source triage",
                    data={
                        "exit_code": universal_result,
                        "coverage": scope.get("coverage", "unknown"),
                        "analysis_status": scope.get("analysis_status", "unknown"),
                        "backend": scope.get("backend", "unknown"),
                        "files_scanned": scope.get("source_file_count", 0),
                    },
                )
            except Exception:
                pass
            return universal_result
        except Exception as exc:
            print(
                f"Warning: universal source triage could not complete: {exc}",
                file=sys.stderr,
            )

    all_sources = source_evm_files(root)
    has_vyper = bool(source_vyper_files(root))
    if not args and audit_run_source_triage is not None and not has_vyper:
        audit_root = audit_context.foundry_project_root()
        try:
            return audit_run_source_triage(str(audit_root))
        except Exception as exc:
            return fail(f"Source triage failed: {exc}", 1)

    patterns = [
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
        ("VYPER_RAW_CALL", re.compile(r"\braw_call\s*\(")),
        ("VYPER_EXTCALL", re.compile(r"\bextcall\b")),
        ("VYPER_SEND_VALUE", re.compile(r"\b(?:send|raw_call)\s*\(")),
        ("VYPER_MSG_SENDER", re.compile(r"\bmsg\.sender\b")),
        ("VYPER_TX_ORIGIN", re.compile(r"\btx\.origin\b")),
        ("VYPER_TIMESTAMP", re.compile(r"\bblock\.timestamp\b")),
        ("VYPER_CREATE", re.compile(r"\bcreate_minimal_proxy_to\b|\bcreate_copy_of\b")),
    ]
    markers=[]
    for path in all_sources:
        language="vyper" if path.endswith((".vy",".vyi")) else "solidity"
        try:
            lines=_source_comment_strip(Path(path).read_text(encoding="utf-8"),language)
        except OSError:
            continue
        for lineno,line in enumerate(lines.splitlines(),1):
            for label,pattern in patterns:
                if pattern.search(line):
                    # Do not label Solidity-only patterns on Vyper sources.
                    if language=="vyper" and label.startswith(("UNCHECKED","ASSEMBLY","ENCODE_PACKED","PREVRANDAO","ECRECOVER","CREATE2")):
                        continue
                    item={"file":os.path.relpath(path,os.path.dirname(root) if os.path.isfile(root) else "."),"line":lineno,"label":label,"text":line.strip(),"language":language}
                    markers.append(item)
                    print(f"{path}:{lineno}: [{label}] {line.strip()}")
    print(f"\nReview markers: {len(markers)}")
    print("These are source-level review markers, not vulnerability verdicts.")
    audit_root=audit_context.foundry_project_root()
    audit_context.record_tool(
        "source-triage",audit_root,status="completed",
        summary=f"{len(markers)} source review marker(s)",
        data={"count":len(markers),"markers":markers},
    )
    return 0

def _full_evidence_pass(config):
    """Run the integrated evidence engine instead of the legacy Forge audit."""
    try:
        return run_external_audit(config, ["run"])
    except Exception as exc:
        print(f"Warning: integrated evidence pipeline failed: {exc}", file=sys.stderr)
        return 1



def run_native_project_command(config, command_name, args):
    """Run one repository-native build/test command without invoking an unrelated EVM tool."""
    root = detected_project_root(".") if callable(detected_project_root) else Path.cwd().resolve()
    info = detect_project(root) if detect_project else {"root": str(root), "backend": "generic"}
    backend = str(info.get("backend") or "").lower()
    stacks = set(info.get("stacks") or [])
    if command_name in {"build", "test"} and (backend == "foundry" or "foundry" in stacks or info.get("kind") == "lowkey-source"):
        return run_foundry([command_name, *args])

    planner = project_build_command if command_name == "build" else project_test_command
    if planner is None:
        return fail(f"Error: native {command_name} planner is unavailable.")
    command_info = planner(info)
    if not command_info:
        print(f"No safe native '{command_name}' command was detected for {root}.")
        print("Lowkey will not invoke Forge/Cast outside an applicable project backend.")
        print("RESULT: REVIEW NEEDED — no executable project-native command was established.")
        return 2

    cwd, command, evidence = command_info
    print("LOWKEY NATIVE COMMAND")
    print("=====================")
    print(f"Project : {cwd}")
    print(f"Command : {' '.join(command)}")
    print(f"Source  : {evidence}")
    native_env, runtime_review = _native_command_runtime(cwd, command)
    if runtime_review:
        print(runtime_review)
        return 2
    try:
        timeout = max(30, min(int(os.environ.get("LOWKEY_NATIVE_TIMEOUT", "120")), 1800))
    except ValueError:
        timeout = 120
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**native_env, "CI": "1"},
        )
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT: native {command_name} command exceeded {timeout}s.", file=sys.stderr)
        return 124
    except OSError as exc:
        return fail(f"Error executing native {command_name}: {exc}", 1)

    stdout = getattr(result, "stdout", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    if stderr:
        print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)

    returncode = getattr(result, "returncode", 0)
    if returncode != 0 and classify_build_failure is not None:
        classification = classify_build_failure(f"{stdout}\n{stderr}", command)
        print(
            f"NATIVE FAILURE : {classification.get('category', 'unknown')}",
            file=sys.stderr,
        )
        print(f"Reason         : {classification.get('reason', '')}", file=sys.stderr)
        if not classification.get("repairable"):
            print(
                "RESULT: REVIEW NEEDED — Lowkey will not auto-repair this native failure.",
                file=sys.stderr,
            )
    return returncode


def run_deps(args):
    requested = Path(args[0] if args else ".").expanduser().resolve()
    if not requested.exists():
        return fail(f"Path not found: {requested}")
    if requested.is_file() and requested.suffix.lower() not in {".sol", ".vy", ".vyi"}:
        return fail(f"Path is not a Solidity/Vyper source file: {requested}")

    # Resolve the dependency graph from the same selected project scope used by
    # Lowkey's workspace controls. Never silently jump to another sibling project
    # or a previously selected EVM fork.
    root = requested.parent if requested.is_file() else requested
    if requested.is_dir() and is_workspace_root is not None and is_workspace_root(root):
        active = workspace_selection(root) if workspace_selection is not None else None
        candidates = discover_nested_projects(root) if discover_nested_projects is not None else []
        if active is not None and active.is_dir():
            root = active
        elif len(candidates) == 1:
            root = Path(candidates[0]["root"]).resolve()
        elif len(candidates) > 1:
            return fail(
                "Error: 'lk deps' was run from a multi-project workspace without an "
                "active project. Run 'lk projects <number>' first or cd into the project."
            )

    if project_tools is None or not hasattr(project_tools, "build_dependency_graph"):
        return fail("Error: dependency graph engine is unavailable.")

    try:
        graph = project_tools.build_dependency_graph(root)
    except Exception as exc:
        return fail(f"Error: dependency analysis failed for {root}: {exc}")

    print("Dependency / inheritance map:")
    print(f"Project scope: {root}")
    edges = graph.get("edges") or []
    imports = [edge for edge in edges if edge.get("kind") == "import"]
    inheritance = [edge for edge in edges if edge.get("kind") == "inherits"]

    for edge in imports:
        relation = edge.get("raw") or edge.get("to") or edge.get("statement") or "unknown"
        print(f"  {edge.get('from')} -> imports {relation}")
    for edge in inheritance:
        print(f"  {edge.get('from')} -> inherits {edge.get('to')}")

    if not edges:
        print("No imports or inheritance relationships detected.")
    unresolved = graph.get("unresolved") or []
    if unresolved:
        print(f"Unresolved imports: {len(unresolved)}")
        print("These are dependency-resolution leads, not vulnerability findings.")
    return 0

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
    print("HEURISTIC [meaning: pattern-based review lead; trust: LOW — investigate, do not treat as a finding]")

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

RISK_SIGNAL_HELP = {
    "external-call": ("The function is a likely external-call boundary.", "Inspect the callee, arguments, value transfer, trust assumptions, and reentrancy surface."),
    "state-write": ("Changes stored contract data.", "Ask: what state changes, who can trigger it, and what must remain true afterward."),
    "value-flow": ("Can receive ETH with the call.", "Ask: where does the ETH go, who benefits, and can accounting become inconsistent."),
    "privileged-looking": ("The name suggests permissions, administration, pausing, or upgrades.", "Ask: who can call it and whether that authority is correctly restricted."),
    "asset/action": ("The name suggests moving, creating, destroying, or executing an important asset/action.", "Ask: what can be changed or moved, who controls it, and whether checks happen before the action."),
    "address-input": ("The caller supplies an address.", "Ask: is that address trusted, validated, permissioned, or able to point somewhere dangerous."),
}

def run_risk(config):
    target=config.get("target")
    if not target:
        return fail("Error: Set target first.")
    funcs=abi_functions(load_abi(target,config))
    if not funcs:
        print("Error: No ABI functions loaded."); return

    print("LOWKEY REVIEW HINTS")
    print("===================")
    print("HEURISTIC [meaning: rule-based hints from ABI metadata/function names; trust: LOW — useful for triage, not proof]")
    print("They are NOT vulnerability findings. Use them to decide what to inspect.")
    rows = []
    for item in funcs:
        name=item.get("name","").lower()
        signals=[]
        if item.get("stateMutability") in {"nonpayable","payable"}: signals.append("state-write")
        if item.get("stateMutability")=="payable": signals.append("value-flow")
        if any(x in name for x in ["owner","admin","role","upgrade","pause","unpause"]): signals.append("privileged-looking")
        if any(x in name for x in ["withdraw","transfer","send","execute","call","mint","burn","sweep"]): signals.append("asset/action")
        if any(x in name for x in ["withdraw","transfer","send","execute","call"]): signals.append("external-call")
        if any(canonical_type(i).startswith("address") for i in item.get("inputs",[])): signals.append("address-input")
        signature = format_signature(item)
        row = {"signature": signature, "signals": signals}
        rows.append(row)

        print()
        print(f"Function: {signature}")
        if not signals:
            print("  Hint:   No obvious review hint from its ABI/name alone.")
            continue
        for signal in signals:
            meaning, question = RISK_SIGNAL_HELP[signal]
            print(f"  Hint:   {meaning}")
            print(f"          {question}")

    root = audit_context.foundry_project_root()
    _sync_security_patterns(root)
    pattern_by_function = {}
    for signal in audit_context.security_patterns(root):
        function_name = str(signal.get("function") or "").split("(", 1)[0].lower()
        if not function_name:
            continue
        pattern_by_function.setdefault(function_name, []).append(signal)

    print("\nSECURITY PATTERN SIGNALS")
    print("========================")
    shared_patterns = audit_context.security_patterns(root)
    if not shared_patterns:
        print("No source security-pattern signals recorded for this project.")
    else:
        for signal in shared_patterns:
            pattern_id = str(signal.get("pattern_id") or signal.get("check") or "SECURITY")
            verification = str(signal.get("verification_status") or "CANDIDATE")
            location = f"{signal.get('file') or 'unknown'}:{signal.get('line') or '?'}"
            function = signal.get("function") or "contract-level"
            print(f"  {pattern_id:<14} {verification:<10} {function:<24} {location}")
            if signal.get("description"):
                print(f"    {signal.get('description')}")

        for row in rows:
            function_name = str(row.get("signature") or "").split("(", 1)[0].lower()
            shared = pattern_by_function.get(function_name, [])
            if shared:
                row["security_patterns"] = [
                    {
                        "id": signal.get("pattern_id") or signal.get("check"),
                        "verification_status": signal.get("verification_status") or "CANDIDATE",
                    }
                    for signal in shared
                ]

    audit_context.record_tool(
        "risk",
        root,
        status="completed",
        summary=f"{len(rows)} ABI function(s) reviewed",
        data={"target": target, "functions": rows, "security_patterns": _security_pattern_summary(root)},
    )

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
def _full_evidence_pass(config):
    """Run the extended audit pass and source triage as one investigation action."""
    root = audit_context.foundry_project_root()
    try:
        scan_code = run_scan([])
    except Exception as exc:
        print(f"Warning: source triage failed: {exc}", file=sys.stderr)
        scan_code = 1
    audit_code = run_audit(config, ["--checks"])
    return audit_code if audit_code != 0 else scan_code


def _generate_connected_poc(config):
    """Generate the current investigation PoC from the shared evidence context."""
    try:
        from generator import run_generate
        return run_generate(config, ["poc"])
    except Exception as exc:
        print(f"Warning: connected PoC generation failed: {exc}", file=sys.stderr)
        return 1


def _bind_detected_anvil(config, info):
    """Hydrate the current audit session from a detected Anvil without starting it."""
    if not isinstance(info, dict):
        return None

    config["_auto_rpc_info"] = info
    accounts = info.get("accounts", [])
    if not isinstance(accounts, list) or not accounts:
        return None

    account0 = accounts[0]
    current_actor = config.get("actor")
    current_entry = config.get("wallets", {}).get(current_actor) if current_actor else None

    # Never replace an explicitly configured key/env actor. Rebind only a stale
    # Anvil-derived actor or an empty actor slot.
    keep_actor = False
    if isinstance(current_entry, dict):
        source = current_entry.get("source")
        recorded = str(current_entry.get("address", "")).lower()
        keep_actor = source not in {"anvil-default", "anvil-impersonated"} or (
            recorded and recorded in {str(address).lower() for address in accounts}
        )

    if not current_actor or not keep_actor:
        _ensure_lab_deployer(config, account0, 0)
        # The actor profile contains only public account metadata; the private key
        # is still derived on demand from Anvil's default mnemonic.
        save_config(config)

    return info


def _set_audit_auto_target(config, root, address, contract=None, artifact=None, source="auto-detected"):
    """Persist a project-scoped target selected by the audit bootstrap."""
    if not is_address(address):
        return None
    config["target"] = address
    if contract:
        config["target_contract"] = contract
    if artifact:
        config.setdefault("abi_paths", {})[address] = artifact
    if contract:
        config.setdefault("aliases", {})[contract] = address
        config.setdefault("targets", {})[contract] = address
    audit_context.set_target(
        root,
        address=address,
        contract=contract,
        artifact=artifact,
        source=source,
    )
    audit_context.update(root, actor=actor_display(config), rpc=effective_rpc(config))
    save_config(config)
    return address


def _live_target_is_proxy(rpc, address):
    if not rpc or not is_address(address):
        return False
    try:
        code, implementation, _err = cast_output(["cast", "implementation", address, "--rpc-url", rpc])
    except Exception:
        return False
    if code != 0:
        return False
    implementation = str(implementation or "").strip().splitlines()[-1] if implementation else ""
    return is_address(implementation) and implementation.lower() != str(address).lower()

def _live_target_candidate(config, root, contract_name=None):
    """Find a saved target matching a current-project contract and live on the detected Anvil."""
    info = anvil_rpc_info(config)
    rpc = info.get("url") if isinstance(info, dict) else effective_rpc(config)
    if not rpc:
        return None

    artifacts_by_name = {}
    for path in local_artifact_paths(root):
        artifact = read_artifact(path)
        if not isinstance(artifact, dict):
            continue
        name = artifact_contract_name(path, artifact)
        if artifact_is_project_application(root, path, artifact):
            artifacts_by_name[str(name).lower()] = (str(name), path)

    aliases = target_aliases(config, root)
    preferred = str(contract_name or "").strip().lower()

    candidates = []
    for alias, address in aliases.items():
        key = str(alias).strip().lower()
        artifact_info = artifacts_by_name.get(key)
        if not artifact_info:
            continue
        try:
            code, runtime, _ = cast_output(["cast", "code", address, "--rpc-url", rpc])
        except Exception:
            continue
        if code != 0 or not str(runtime or "").strip() or str(runtime).strip() == "0x":
            continue
        contract, artifact = artifact_info
        # An implementation contract with an initializer is not a usable live
        # application target for autonomous walkthrough mode. Prefer its proxy.
        if artifact_has_initializer(read_artifact(artifact) or {}) and not _live_target_is_proxy(rpc, address):
            continue
        priority = 0 if preferred and key == preferred else 1
        if is_address(config.get("target")) and str(config.get("target")).lower() == str(address).lower():
            priority -= 2
        candidates.append((priority, contract.lower(), address.lower(), contract, address, artifact))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[:3])
    # Without a preferred contract, multiple live aliases are ambiguous. Do not
    # silently choose one merely because its name sorts first.
    if len(candidates) > 1 and not preferred:
        return None
    best = candidates[0]
    return {
        "contract": best[3],
        "address": best[4],
        "artifact": best[5],
    }


def _focused_audit_target_contract(root):
    """Return the built contract associated with the current investigation focus."""
    context = audit_context.load(root)
    focus = context.get("focus", {}) if isinstance(context, dict) else {}
    signal_id = focus.get("signal_id") if isinstance(focus, dict) else None
    if not signal_id:
        return None

    signal = next(
        (
            item for item in audit_context.signals(root, None)
            if isinstance(item, dict) and item.get("id") == signal_id
        ),
        None,
    )
    if not isinstance(signal, dict):
        return None

    file_name = str(signal.get("file") or "")
    source_name = Path(file_name).stem if file_name else ""
    if not source_name:
        return None

    for path in local_artifact_paths(root):
        artifact = read_artifact(path)
        if not artifact_is_project_application(root, path, artifact):
            continue
        contract = artifact_contract_name(path, artifact)
        if str(contract).lower() == source_name.lower():
            return str(contract)
    return None


def _bootstrap_audit_target(config, root, allow_deploy=False):
    """Resolve a live project target without guessing across unrelated projects."""
    existing = project_context_target(root)
    if existing:
        artifact = existing.get("artifact")
        source = existing.get("source")
        stale_implementation = False
        if source != "manual" and artifact:
            artifact_data = read_artifact(str(artifact))
            if artifact_has_initializer(artifact_data or {}):
                stale_implementation = not _live_target_is_proxy(effective_rpc(config), existing.get("address"))
        if stale_implementation:
            print(
                f"Existing target ignored: {existing.get('contract') or 'implementation'} "
                "is an implementation contract, not a configured proxy target."
            )
        else:
            # A remembered target is only trusted when it is present on the live
            # local node and its artifact identity matches a first-party application.
            live_existing = _live_target_candidate(
                config, root, existing.get("contract")
            )
            if live_existing:
                return _set_audit_auto_target(
                    config,
                    root,
                    live_existing["address"],
                    live_existing["contract"],
                    live_existing["artifact"],
                )

            # For explicit manual targets we preserve the old behavior.
            if source == "manual":
                activate_project_target(config, root)
                return existing.get("address")

    # Whole-protocol bootstrap prefers an inferred protocol root (factory/router/etc.)
    # over a single focused finding's child implementation. The investigation focus still
    # remains available when no protocol-root candidate can be inferred.
    preferred_contract = discover_audit_target_contract(root) or _focused_audit_target_contract(root)
    if existing and source != "manual":
        config["target"] = None
        config["target_contract"] = None
    candidate = _live_target_candidate(config, root, preferred_contract)
    if candidate:
        return _set_audit_auto_target(
            config,
            root,
            candidate["address"],
            candidate["contract"],
            candidate["artifact"],
        )

    # A broadcast deployment is deterministic and safe to reconnect to.
    before = active_project_target(config, root)
    if not before and discover_deployments(root):
        code = run_auto_target(config, preferred_contract)
        if code == 0 and is_address(config.get("target")):
            return config.get("target")

    if not allow_deploy:
        if preferred_contract:
            print(
                f"Target not auto-selected: no live saved target or broadcast deployment matched {preferred_contract}."
            )
        else:
            print("Target not auto-selected: choose one with 'lk target <name> <address>' or run 'lk lab'.")
        return None

    # Auto mode may provision a disposable local target. Never synthesize
    # constructor arguments: project adapters are trusted, while generic
    # deployment is only automatic when the selected artifact needs no args.
    script = discover_local_lab_script(root)
    if script:
        code = run_lab(config, [])
        if code == 0 and is_address(config.get("target")):
            return config.get("target")
        return None

    candidate_contract = preferred_contract
    generic = discover_generic_lab_contract(root, candidate_contract) if candidate_contract else discover_generic_lab_contract(root)
    if generic:
        _score, _contract, _path, _artifact, constructor_inputs, _fqn = generic
        if not constructor_inputs:
            code = run_lab(config, [])
            if code == 0 and is_address(config.get("target")):
                return config.get("target")
        else:
            print(
                f"Auto target provisioning skipped: {generic[1]} requires "
                f"{len(constructor_inputs)} constructor argument(s)."
            )
    else:
        print("Auto target provisioning skipped: no safe deployable application contract was found.")

    return None


def run_audit_mode(config, args=None, interactive=None):
    """Run the connected audit session with project-aware backend routing."""
    args = list(args or [])
    auto_mode = any(str(item).lower() == "auto" for item in args)
    normalized_args = [
        "--checks" if str(item).lower() in {"check", "checks", "--check"} else item
        for item in args
    ]
    no_checks = "--no-checks" in normalized_args
    checks = "--checks" in normalized_args or not no_checks
    normalized_args = [item for item in normalized_args if item != "--no-checks"]
    if checks and "--checks" not in normalized_args:
        normalized_args.append("--checks")
    args = normalized_args
    walkthrough_mode = "--walkthrough" in args
    force_noninteractive = "--non-interactive" in args
    force_interactive = "--interactive" in args
    mode_args = ["--checks"] if checks else ["--no-checks"]

    root = detected_project_root(".") if callable(detected_project_root) else Path.cwd().resolve()

    # Never silently treat a multi-project workspace as one generic project.
    # Honor an existing workspace selection; otherwise require the user to
    # choose the actual project before audit analysis begins.
    if (
        is_workspace_root is not None
        and is_workspace_root(root)
        and discover_nested_projects is not None
        and not (
            _is_lowkey_source_checkout is not None
            and _is_lowkey_source_checkout(root)
        )
    ):
        workspace_container = Path(root).resolve()
        active = workspace_selection(workspace_container) if workspace_selection is not None else None
        candidates = discover_nested_projects(workspace_container)
        if active is not None and active.is_dir():
            root = active
        elif len(candidates) == 1:
            root = Path(candidates[0]["root"])
            if set_workspace_selection is not None:
                set_workspace_selection(workspace_container, root)
        elif len(candidates) > 1:
            if force_noninteractive or not sys.stdin.isatty():
                return fail(
                    "Error: this workspace contains multiple projects. "
                    "Run 'lk projects <number>' first, then run 'lk audit'."
                )
            print()
            print("LOWKEY AUDIT SCOPE")
            print("==================")
            print(f"Workspace: {workspace_container}")
            print("Choose the project you actually want to audit:")
            _print_workspace_scope_choices(candidates)
            print("")
            print("Lowkey will audit the selected project as the primary scope and keep its listed dependencies in context.")
            while True:
                try:
                    choice = input(f"Project [1-{len(candidates)}] or q: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return fail("Project selection cancelled.")
                if choice == "q":
                    return fail("Project selection cancelled.")
                if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                    root = Path(candidates[int(choice) - 1]["root"])
                    if set_workspace_selection is not None:
                        set_workspace_selection(workspace_container, root)
                    print(f"Active audit scope: {root.relative_to(workspace_container)}")
                    break
                print("Please enter one of the project numbers, or q.")
    info = detect_project(root) if detect_project else {
        "root": str(root),
        "kind": "unknown",
        "backend": "generic",
        "stacks": [],
        "languages": {},
    }
    selected_scope = None
    if discover_nested_projects is not None and workspace_context is not None:
        scope = workspace_context(root)
        for candidate in scope.get("projects") or []:
            if Path(candidate["root"]).resolve() == Path(root).resolve():
                selected_scope = candidate
                break
    if selected_scope:
        print("")
        print("AUDIT SCOPE")
        print("===========")
        print(f"Project    : {selected_scope.get('relative')}")
        print(f"Role       : {selected_scope.get('scope_role') or selected_scope.get('scope_hint')}")
        print(f"Purpose    : {_workspace_project_description(selected_scope)}")
        if selected_scope.get("depends_on"):
            print(f"Depends on : {', '.join(selected_scope['depends_on'])}")
        if selected_scope.get("depended_on_by"):
            print(f"Used by    : {', '.join(selected_scope['depended_on_by'])}")
    stacks = set(info.get("stacks", []))
    backend = str(info.get("backend") or "").lower()
    self_source = info.get("kind") == "lowkey-source"
    foundry_project = backend == "foundry" or "foundry" in stacks or self_source
    evm_project = self_source or backend in {"foundry", "hardhat", "vyper", "evm-source"} or bool(
        stacks & {"foundry", "hardhat", "vyper"}
    )

    config["audit_project"] = str(root)
    save_config(config)

    print()
    print(format_detection(info) if format_detection else f"Project : {root}")

    if bootstrap_project is not None:
        bootstrap_code = bootstrap_project(info, args, reason="audit")
        if bootstrap_code == 0:
            info["_bootstrap_done"] = True
            config["_bootstrap_done_root"] = str(Path(root).resolve())

    info_anvil = anvil_rpc_info(config) if evm_project else None
    started = False
    if foundry_project and auto_mode and not info_anvil and not config.get("rpc"):
        info_anvil = ensure_project_anvil(config, root)
        started = bool(info_anvil)

    if evm_project and info_anvil:
        _bind_detected_anvil(config, info_anvil)
        print(f"Anvil   : {'started by Lowkey' if started else 'detected; using existing node'}")
        print(f"RPC     : {rpc_display(effective_rpc(config))}")
        print(f"Actor   : {actor_display(config)}")
    elif evm_project and auto_mode and config.get("rpc"):
        print("Anvil   : no Anvil detected at the configured RPC; Lowkey will not override the explicit RPC.")
    elif evm_project:
        print("Anvil   : not detected; continuing static/native audit only.")
    else:
        print("Runtime : native project backend; Anvil/Forge target mode disabled.")

    run_workspace(config, ["init"], root)
    run_matrix(config, ["init"])
    run_checklist(config)
    if not config.get("session_active"):
        run_session_lifecycle(config, "start")
    else:
        run_session_lifecycle(config, "resume")

    print("\n=== LOWKEYCAST AUDIT MODE ===")
    print("Starting project-aware audit baseline...")
    baseline_code = 0
    scan_code = 0

    if foundry_project:
        try:
            scan_code = run_scan([])
        except Exception as exc:
            print(f"Warning: source triage failed: {exc}", file=sys.stderr)
            scan_code = 1

        target = _bootstrap_audit_target(config, root, allow_deploy=auto_mode)
        if target:
            _sync_audit_context(config, root)
            abi_source = resolve_abi_path(config, target) or auto_abi_path(target, config)
            audit_abi = audit_abi_path(target, config)
            if abi_source and audit_abi and audit_abi.exists():
                try:
                    audit_label = audit_abi.relative_to(Path(root).resolve())
                except (OSError, ValueError):
                    audit_label = audit_abi
                print(f"ABI workspace: {audit_label}")
        else:
            print("Target : none configured for this project")
            print("         Static audit can continue; use 'lk lab' (or 'lk audit auto') for a live local target.")

    audit_code = run_audit(config, mode_args)

    # The session-level detector has the authoritative mixed-stack scope.
    # Run non-Foundry native checks here instead of asking the Foundry runner
    # to rediscover the project and potentially lose the selected backend.
    if foundry_project and len(stacks) > 1 and run_native_audit:
        native_code = run_native_audit(info, mode_args)
        if native_code != 0 and audit_code == 0:
            audit_code = native_code

    if walkthrough_mode and evm_project:
        walkthrough_args = ["--auto"] if auto_mode else []
        walkthrough_args.append("--yes" if force_noninteractive or not sys.stdin.isatty() else "--interactive")
        walkthrough_code = walkthrough.run(config, walkthrough_args, host=sys.modules[__name__])
        if walkthrough_code != 0 and audit_code == 0:
            audit_code = walkthrough_code

    if audit_code != 0:
        baseline_code = audit_code
    elif scan_code != 0:
        baseline_code = scan_code

    if baseline_code != 0:
        print("\nBaseline completed with review-needed status; the investigation menu is still available.")

    if force_noninteractive:
        interactive = False
    elif force_interactive:
        interactive = True
    elif interactive is None:
        interactive = bool(sys.stdin.isatty()) and str(os.environ.get("CI", "")).lower() not in {"1", "true", "yes"}

    if not interactive:
        print("Non-interactive environment: audit menu skipped.")
        return baseline_code

    while True:
        context = audit_context.load(root)
        target = context.get("target") if isinstance(context.get("target"), dict) else {}
        target_label = target.get("contract") or target.get("address") or config.get("target") or "none"
        runtime_rpc = effective_rpc(config) if evm_project else config.get("rpc")
        print(f"\nTarget: {target_label} | RPC: {rpc_display(runtime_rpc) or 'none'}")

        if evm_project:
            print("1) recon   2) functions   3) risk   4) checklist   5) targets (select target)   6) deployments")
            print("7) full evidence pass   8) generate PoC   9) protocol walkthrough   0) exit")
        else:
            print("1) checklist   2) findings   0) exit")

        try:
            choice = input("lk> ").strip()
        except EOFError:
            print()
            return baseline_code

        if evm_project:
            if choice == "1":
                run_recon(config)
            elif choice == "2":
                run_functions(config)
            elif choice == "3":
                run_risk(config)
            elif choice == "4":
                run_checklist(config)
            elif choice == "5":
                run_targets(config, interactive=True)
            elif choice == "6":
                run_deployments(config)
            elif choice == "7":
                code = _full_evidence_pass(config)
                if code == 0:
                    print("Full evidence pass completed.")
                else:
                    print("Full evidence pass needs review.", file=sys.stderr)
            elif choice == "8":
                code = _generate_connected_poc(config)
                if code == 0:
                    print("Connected PoC scaffold refreshed.")
            elif choice == "9":
                code = walkthrough.run(config, [], host=sys.modules[__name__])
                if code != 0:
                    print("Protocol walkthrough needs review.", file=sys.stderr)
            elif choice == "0":
                return baseline_code
            else:
                print("Unknown option. Choose 0-9.")
        else:
            if choice == "1":
                run_checklist(config)
            elif choice == "2":
                run_signals(config, [])
            elif choice == "0":
                return baseline_code
            else:
                print("Unknown option. Choose 0-2.")



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
        print("Focus one audit signal and mark it as investigating.")
        print("Use: lk findings to list signal IDs.")
        print("For a function, use: lk fn '<function signature>'")
        print("Then use: lk focus <SIGNAL_ID> for the audit signal you want to investigate.")
        return 0

    candidate = str(args[0]).strip()
    if "(" in candidate or ")" in candidate:
        try:
            target = config.get("target")
            functions = abi_functions(load_abi(target, config)) if target else []
            matches = matching_functions(functions, candidate)
        except Exception:
            matches = []
        if matches:
            print("LOWKEY FUNCTION FOCUS")
            print("=====================")
            print(f"Function : {candidate}")
            print("Focus stores an audit signal, not a function selection.")
            print(f"Use: lk fn '{candidate}'")
            print(f"Use: lk ask '{candidate}'")
            print("Then use 'lk findings' + 'lk focus <SIGNAL_ID>' for the related audit signal.")
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
    if signal.get("category") == "security-pattern":
        verification = signal.get("verification_status") or ((signal.get("verification") or {}).get("status") if isinstance(signal.get("verification"), dict) else None) or "CANDIDATE"
        print(f"Pattern    : {signal.get('pattern_id') or signal.get('check')}")
        print(f"Verification: {verification}")
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
        safe_function = shlex.quote(str(function))
        print(f"  lk fn {safe_function}")
        print(f"  lk ask {safe_function}")

        abi = load_abi(config.get("target"), config)
        matches = matching_functions(abi, function) if abi else []
        item = matches[0] if len(matches) == 1 else None

        print("\n  HOW FUNCTION ARGUMENTS WORK")
        print("    Function signature = function name + parameter TYPES.")
        print("    The quoted signature tells Lowkey WHAT the function accepts.")
        print("    Actual parameter VALUES go AFTER the closing quote.")
        if item:
            inputs = item.get("inputs", [])
            if inputs:
                print("    Parameters for this function:")
                for index, param in enumerate(inputs, 1):
                    name = param.get("name") or f"arg{index}"
                    print(f"      {index}. {name} : {canonical_type(param)}")
                print("    Example:")
                print(f"      lk changes '{format_signature(item)}' " + " ".join(
                    f"<{param.get('name') or 'arg'+str(index)}>"
                    for index, param in enumerate(inputs, 1)
                ))
            else:
                print("    This function takes no arguments.")
                print(f"    Example: lk changes '{format_signature(item)}'")
        else:
            print("    Use lk ask '<function>' to see the parameter names and TYPES.")

        print("\n  EXECUTE / INSPECT STATE CHANGES")
        print(f"    lk changes '{function}' <value1> <value2> ...")
        print("    Do NOT put real argument values inside the quoted signature.")
        print("    Put the actual VALUES after the closing quote.")
        if item and item.get("inputs"):
            print("    For this function:")
            print(f"      lk changes '{format_signature(item)}' " + " ".join(
                f"<{param.get('name') or 'arg'+str(index)}>"
                for index, param in enumerate(item.get("inputs", []), 1)
            ))
        else:
            print(f"      lk changes {safe_function}")

        print("\n  GENERATE A REUSABLE TEST / POC")
        print(f"    lk generate test '{function}' <value1> <value2> ...")
        print("    Real VALUES go after the closing quote.")
        if item and item.get("inputs"):
            print("    For this function:")
            print(f"      lk generate test '{format_signature(item)}' " + " ".join(
                f"<{param.get('name') or 'arg'+str(index)}>"
                for index, param in enumerate(item.get("inputs", []), 1)
            ))
        print("    Or provide raw calldata:")
        print(f"      lk generate test '{function}' --calldata <hex>")

        print("\n  OTHER")
        print("    lk trace")
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


def _sync_security_patterns(root, *, announce: bool = False):
    """Synchronize source security-pattern observations into shared Lowkey context."""
    root = Path(root).resolve()
    if not audit_context.is_audit_project(root):
        return []
    try:
        import walkthrough as _walkthrough
        from walkthrough_finding_patterns import scan_project, persist_security_patterns
    except ImportError:
        try:
            from . import walkthrough as _walkthrough
            from .walkthrough_finding_patterns import scan_project, persist_security_patterns
        except ImportError:
            return []
    try:
        models = _walkthrough._artifact_models(root)
        if not models:
            return []
        observations = scan_project(root, models)
        persist_security_patterns(root, observations)
    except Exception as exc:
        if announce:
            print(f"Security pattern synchronization skipped: {exc}", file=sys.stderr)
        return []
    if announce and observations:
        confirmed = sum(1 for item in observations if item.status == "CONFIRMED")
        reviews = sum(1 for item in observations if item.status == "REVIEW")
        candidates = sum(1 for item in observations if item.status == "CANDIDATE")
        print(f"Security patterns : {len(observations)} source match(es) ({confirmed} confirmed, {reviews} review, {candidates} candidate)")
    return observations


def _security_pattern_summary(root):
    return audit_context.security_pattern_summary(root)


def _print_security_scope(root, *, prefix="SECURITY SCOPE"):
    summary = _security_pattern_summary(root)
    print(
        f"{prefix} : {summary['total']} pattern(s) — "
        f"{summary['reviews']} review, {summary['confirmed']} confirmed, "
        f"{summary['candidates']} candidate"
    )
    return summary

def run_audit(config, args):
    if args and args[0].lower() in {"help", "-h", "--help"}:
        print("Usage: lk audit [--no-checks] [--verbose]")
        print("Detect the project/toolchain first, then run the matching audit backend. Static checks run by default.")
        print("Foundry projects use Forge; Cairo/Vyper/Hardhat/Anchor/Move use native checks.")
        return 0

    root = detected_project_root(".") if callable(detected_project_root) else Path.cwd().resolve()
    info = detect_project(root) if detect_project else {
        "root": str(root),
        "name": root.name,
        "kind": "unknown",
        "backend": "generic",
        "stacks": [],
        "languages": {},
    }

    print()
    print(format_detection(info) if format_detection else f"Project : {root}")
    try:
        from analysis_adapters import inspect_repository, render_scope
        print()
        print(render_scope(inspect_repository(root)))
    except Exception as exc:
        print(f"Analysis scope: unavailable ({exc})", file=sys.stderr)

    # The outer connected-audit flow may already have prepared this exact
    # project. Preserve that state so native audit execution does not bootstrap
    # the same dependency tree twice.
    if config.get("_bootstrap_done_root") == str(Path(root).resolve()):
        info["_bootstrap_done"] = True

    project_data = {
        "root": str(root),
        "name": root.name,
        "kind": info.get("kind"),
        "backend": info.get("backend"),
        "stacks": info.get("stacks", []),
        "languages": info.get("languages", {}),
    }
    audit_context.update(root, project=project_data)
    _sync_security_patterns(root, announce=True)

    # Every audit starts with the universal source/scope pass. This is cheap,
    # adapter-aware, and gives non-Foundry repositories a useful result before
    # native build/test execution begins.
    try:
        from analysis_adapters import scan_repository
        scan_code = scan_repository(root)
        if scan_code not in {0, 2}:
            print("Warning: universal source triage failed; native checks will continue where supported.", file=sys.stderr)
    except Exception as exc:
        print(f"Warning: universal source triage unavailable: {exc}", file=sys.stderr)

    stacks = set(info.get("stacks", []))
    if info.get("backend") == "foundry" or "foundry" in stacks or info.get("kind") == "lowkey-source":
        _sync_audit_context(config, root)
        try:
            from forge_tools import run_audit as run_forge_audit
        except ImportError as exc:
            return fail(f"Error: Lowkey Forge audit layer unavailable: {exc}")
        forge_args = list(args)
        return_code = run_forge_audit(forge_args)
        audit_context.record_tool(
            "audit",
            root,
            status="completed" if return_code == 0 else "failed",
            summary="connected Foundry audit pipeline",
            data={"exit_code": return_code, "backend": "foundry"},
        )
        # Mixed-stack native checks are orchestrated by run_audit_mode, which
        # already holds the selected project scope and detected stack inventory.
        return return_code

    if run_native_audit:
        return_code = run_native_audit(info, args)
    else:
        print("Native project audit layer is unavailable; source review only.")
        return_code = 0

    audit_context.record_tool(
        "audit",
        root,
        status="completed" if return_code == 0 else "failed",
        summary=f"native {info.get('backend', 'generic')} audit pipeline",
        data={"exit_code": return_code, "backend": info.get("backend", "generic")},
    )
    return return_code



def refresh_generated_poc(config):
    """Refresh the connected PoC scaffold after audit evidence or a concrete send."""
    root = audit_context.foundry_project_root()
    latest = audit_context.load(root).get("latest", {})
    if not isinstance(latest, dict) or not latest.get("tx_hash"):
        return 0
    try:
        from generator import run_generate
        return run_generate(config, ["poc"])
    except Exception as exc:
        print(f"Warning: PoC scaffold refresh skipped: {exc}", file=sys.stderr)
        return 0
def run_context(config):
    root = audit_context.foundry_project_root()
    _sync_audit_context(config, root)
    _sync_security_patterns(root)
    print("LOWKEY AUDIT CONTEXT")
    print("====================")
    print(audit_context.human_snapshot(root))
    print(f"Context : {audit_context.context_path(root)}")
    print(f"Events  : {audit_context.events_path(root)}")

def run_signals(config, args):
    root = audit_context.foundry_project_root()

    if not audit_context.is_audit_project(root):
        print("No audit project detected at the current root.")
        print(f"Root : {root}")
        print("Findings are project-scoped; run 'lk findings' from the target project.")
        return 0

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
    _sync_security_patterns(root)
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
        verification = signal.get("verification") if isinstance(signal.get("verification"), dict) else {}
        if signal.get("category") == "security-pattern":
            print(f"   Pattern    : {signal.get('pattern_id') or signal.get('check')}")
            print(f"   Verification: {signal.get('verification_status') or verification.get('status') or 'CANDIDATE'}")
            if verification.get("mode"):
                print(f"   Evidence mode: {verification.get('mode')}")
            provenance = signal.get("provenance")
            if isinstance(provenance, list) and provenance:
                print(f"   Research   : {', '.join(str(item) for item in provenance[:4])}")
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
    _sync_security_patterns(root)
    context = audit_context.load(root)
    open_signals = len(audit_context.signals(root, "open"))
    print(f"Signals: {open_signals} open")
    security_summary = _security_pattern_summary(root)
    print(
        "Security patterns: "
        f"{security_summary['total']} "
        f"(review {security_summary['reviews']}, confirmed {security_summary['confirmed']}, candidate {security_summary['candidates']})"
    )
    focus = context.get("focus")
    if isinstance(focus, dict) and focus.get("signal_id"):
        print(f"Focus  : {focus.get('signal_id')} — {focus.get('title') or 'audit signal'}")
    for tool_name in ("slither", "forge", "generator"):
        state = context.get("tools", {}).get(tool_name, {})
        if isinstance(state, dict) and state.get("status"):
            print(f"{tool_name.capitalize():<8}: {state.get('status')}" + (f" — {state.get('summary')}" if state.get("summary") else ""))
def run_wizard(config,args):
    if not args:
        return fail("Usage: lk wizard <function> [values...] [call|send|encode]")

    target=config.get("target")
    if not target:
        return fail("Error: Set target first.")

    funcs=abi_functions(load_abi(target,config))
    matches=matching_functions(funcs,args[0])
    if len(matches)!=1:
        return fail("Error: Function must resolve to exactly one ABI entry.")

    item=matches[0]
    signature=format_signature(item)
    params=item.get("inputs", [])

    # Preserve the explicit mode spelling while treating positional values as
    # actual function arguments. Without a mode, view/pure functions default to
    # call and state-changing functions default to a confirmed send.
    remaining=list(args[1:])
    explicit_mode=None
    if remaining and remaining[0].lower() in {"call","send","encode"}:
        explicit_mode=remaining.pop(0).lower()
    mode=explicit_mode or (
        "call" if item.get("stateMutability") in {"view","pure"} else "send"
    )

    if len(remaining) > len(params):
        return fail(
            f"Error: {signature} expects {len(params)} argument(s), "
            f"but {len(remaining)} value(s) were provided."
        )

    values=[]
    print(f"Function: {signature}")
    for index,param in enumerate(params,1):
        label=param.get("name") or f"arg{index}"
        ptype=canonical_type(param)

        if index <= len(remaining):
            value=str(remaining[index-1]).strip()
            print(f"{label} ({ptype}): {value}")
        else:
            if ptype.startswith(('uint', 'int')):
                _print_numeric_unit_reference(label, ptype)
            try:
                value=input(f"{label} ({ptype}): ").strip()
            except EOFError:
                print("Wizard cancelled.")
                return 0

        if value and ptype.startswith(('uint', 'int')):
            value=_normalize_human_numeric_input(value, ptype, label)
        if not value:
            return fail("Argument values are required.")
        values.append(value)

    if mode=="encode":
        return run_cast(["calldata",signature,*values],config)
    if mode=="send":
        return run_cast(["send",signature,*values,"--confirm"],config)
    return run_cast(["call",signature,*values],config)



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
def run_version():
    runtime = runtime_sync_status()
    print("LowkeyCast 2.1 — Foundry Attack Lab")
    print(f"Runtime: {runtime['status'].upper()} - {runtime['detail']}")
    if runtime.get("source_repo"):
        print(f"Source : {runtime['source_repo']}")
def run_project_map(config, args):
    if project_tools is None:
        return fail("Project tools are not installed. Re-run install.sh from this checkout.")

    json_mode = any(str(item).lower() in {"json", "--json"} for item in args)
    selectors = [str(item).strip() for item in args if str(item).lower() not in {"json", "--json"}]

    # Resolve the workspace from the real working directory, not from the
    # active-project selection. This keeps explicit project selectors useful
    # even when another project is currently active.
    scope = workspace_context(Path.cwd()) if workspace_context is not None else None
    workspace_container = Path(scope["workspace"]).resolve() if scope else None
    candidates = list(scope.get("projects") or []) if scope else []
    current_project = scope.get("current") if scope else None
    active_project = scope.get("active") if scope else None
    in_multi_workspace = bool(workspace_container and len(candidates) > 1)

    if selectors and selectors[0].lower() in {"-h", "--help", "help"}:
        print("Usage:")
        print("  lk project")
        print("  lk project <number>")
        print("  lk project <path>")
        print("  lk project --workspace")
        print("  lk project <number> --json")
        print("  lk project <path> --json")
        print("")
        print("A workspace gives Lowkey the big picture; a project opens the full contract/dependency/security map.")
        print("Use a number or path when you want to switch the active project and inspect it.")
        return 0

    if workspace_container and (in_multi_workspace or (selectors and selectors[0].lower() in {"--workspace", "workspace"})):
        if selectors and selectors[0].lower() in {"--workspace", "workspace"}:
            if json_mode:
                print(json.dumps({
                    "workspace": str(workspace_container),
                    "active_project": str(active_project) if active_project else None,
                    "current_project": str(current_project) if current_project else None,
                    "projects": candidates,
                }, indent=2, default=str))
                return 0
            print("LOWKEY WORKSPACE OVERVIEW")
            print("=" * 72)
            print(f"Workspace : {workspace_container}")
            print(f"Projects  : {len(candidates)}")
            if active_project:
                print(f"Active    : {active_project.relative_to(workspace_container).as_posix()}")
            if current_project:
                print(f"Here      : {current_project.relative_to(workspace_container).as_posix()}")
            print("")
            for index, candidate in enumerate(candidates, 1):
                candidate_root = Path(candidate["root"]).resolve()
                marker = " *" if active_project and candidate_root == active_project.resolve() else "  "
                here = "  <here>" if current_project and candidate_root == current_project.resolve() else ""
                print(f"{marker}{index}. {candidate.get('relative')}{'  <here>' if here else ''}")
                for line in _workspace_project_details(candidate):
                    print(line)
            print("")
            print("Deep dive:     lk project <number>")
            print("Set scope:     lk projects <number>")
            return 0

        selected = None
        if selectors:
            selector = selectors[0]
            if selector.isdigit():
                index = int(selector)
                if 1 <= index <= len(candidates):
                    selected = candidates[index - 1]
                else:
                    return fail(f"Error: project number must be between 1 and {len(candidates)}.")
            else:
                selector_path = Path(selector).expanduser()
                if not selector_path.is_absolute():
                    selector_path = workspace_container / selector_path
                selector_path = selector_path.resolve()
                selected = next(
                    (candidate for candidate in candidates
                     if Path(candidate["root"]).resolve() == selector_path),
                    None,
                )
                if selected is None:
                    matches = [
                        candidate for candidate in candidates
                        if str(candidate.get("relative", "")).lower() == selector.lower()
                        or str(candidate.get("name", "")).lower() == selector.lower()
                        or str(candidate.get("package_name", "")).lower() == selector.lower()
                    ]
                    if len(matches) == 1:
                        selected = matches[0]
            if selected is None:
                return fail(f"Error: no workspace project matched '{selector}'.")

            root = Path(selected["root"]).resolve()
            if set_workspace_selection is not None:
                set_workspace_selection(workspace_container, root)
            active_project = root
            print(f"Active project: {root.relative_to(workspace_container).as_posix()}")
        elif current_project:
            root = current_project.resolve()
        elif active_project:
            root = active_project.resolve()
        else:
            if json_mode:
                print(json.dumps({
                    "workspace": str(workspace_container),
                    "active_project": str(active_project) if active_project else None,
                    "projects": candidates,
                }, indent=2, default=str))
                return 0
            print("LOWKEY WORKSPACE OVERVIEW")
            print("=" * 72)
            print(f"Workspace : {workspace_container}")
            print(f"Projects  : {len(candidates)}")
            print("")
            print("No active project is selected yet.")
            print("Run 'lk projects <number>' to choose the audit project.")
            print("Use 'lk project --workspace' for the full workspace overview.")
            return 0
    else:
        root = current_project.resolve() if current_project else audit_context.foundry_project_root()
        if workspace_container and len(candidates) == 1 and root.resolve() == workspace_container:
            root = Path(candidates[0]["root"]).resolve()
            if set_workspace_selection is not None:
                set_workspace_selection(workspace_container, root)

    if not root:
        return fail("Error: Lowkey could not resolve the current project root.")

    try:
        if json_mode:
            with redirect_stdout(io.StringIO()):
                result = project_tools.render_project_map(root)
        else:
            result = project_tools.render_project_map(root)
        _sync_security_patterns(root)
        result["security_patterns"] = _security_pattern_summary(root)
        if workspace_container and len(candidates) > 1:
            result["workspace"] = {
                "root": str(workspace_container),
                "active_project": str(active_project) if active_project else None,
                "current_project": str(root),
                "project_count": len(candidates),
                "projects": candidates,
            }
        if json_mode:
            print(json.dumps(result, indent=2, default=str))
            return 0

        pattern_summary = result.get("security_patterns", {})
        print("")
        print(
            "SECURITY SIGNALS : "
            f"{pattern_summary.get('total', 0)} pattern(s) — "
            f"{pattern_summary.get('reviews', 0)} review, "
            f"{pattern_summary.get('confirmed', 0)} confirmed, "
            f"{pattern_summary.get('candidates', 0)} candidate"
        )
        if workspace_container and len(candidates) > 1:
            selected_rel = root.relative_to(workspace_container).as_posix() if path_is_within(root, workspace_container) else str(root)
            print("")
            print(f"WORKSPACE SCOPE : {selected_rel}")
            print(f"OTHER PROJECTS  : {len(candidates) - 1}")
            print("Use 'lk project --workspace' to see the workspace map.")
            print("")
        return 0
    except Exception as error:
        return fail(f"Project map failed: {error}", 1)

def run_system_model(config, args):
    if system_model is None:
        return fail("System model is not installed. Re-run install.sh from this checkout.")
    root = audit_context.foundry_project_root()
    rpc = effective_rpc(config)
    try:
        _sync_security_patterns(root)
        manifest, path = system_model.refresh_manifest(
            root,
            rpc=rpc,
            config=config,
            reason="lk system",
        )
        summary = system_model.summarize_manifest(manifest)
        pattern_summary = manifest.get("security_pattern_summary") or _security_pattern_summary(root)
        print("LOWKEY SYSTEM MODEL")
        print("=" * 72)
        print(f"Manifest      : {path}")
        print(f"Contracts     : {summary['contracts']}")
        print(f"Deployments   : {summary['deployments']} ({summary['live']} live)")
        print(f"Relationships : {summary['relationships']}")
        print(f"Roles         : {summary['roles']}")
        print(f"Initialization: {summary['initialization_steps']}")
        print(f"Tests         : {summary['tests']}")
        print(f"Adversarial   : {summary['adversarial_evidence']}")
        print(f"Audit targets : {summary['audit_targets']}")
        print(
            "Security      : "
            f"{pattern_summary['total']} pattern(s) — "
            f"{pattern_summary['reviews']} review, "
            f"{pattern_summary['confirmed']} confirmed, "
            f"{pattern_summary['candidates']} candidate"
        )
        if args and args[0] in {"json", "--json"}:
            manifest = dict(manifest)
            manifest["security_patterns"] = pattern_summary
            print("\n" + json.dumps(manifest, indent=2, default=str))
        return 0
    except Exception as error:
        return fail(f"System model failed: {error}", 1)


def run_audit_rg(config, args):
    if audit_run_rg is None:
        return fail("Audit engine is not installed. Re-run install.sh from this checkout.")
    if not args:
        return fail("Usage: lk rg <pattern> [path] [rg-options...]")
    pattern = args[0]
    path = "."
    extra = list(args[1:])
    if extra and not str(extra[0]).startswith("-"):
        path = extra.pop(0)
    root = audit_context.foundry_project_root()
    return audit_run_rg(pattern, path, extra, str(root))


def run_audit_poc(config, args):
    if audit_generate_poc is None:
        return fail("Audit engine is not installed. Re-run install.sh from this checkout.")
    finding = None
    name = None
    remaining = list(args)
    i = 0
    while i < len(remaining):
        item = remaining[i]
        if item == "--finding" and i + 1 < len(remaining):
            try:
                finding = int(remaining[i + 1])
            except ValueError:
                return fail("Usage: lk poc [--finding N] [--name NAME]")
            i += 2
            continue
        if item == "--name" and i + 1 < len(remaining):
            name = remaining[i + 1]
            i += 2
            continue
        if item in {"--help", "-h"}:
            print("Usage: lk poc [--finding N] [--name NAME]")
            return 0
        return fail(f"Unknown lk poc option: {item}")
    root = audit_context.foundry_project_root()
    save_config(config)
    code, _paths = audit_generate_poc(str(root), finding, name)
    return code


def run_external_audit(config, args):
    if audit_run_pipeline is None:
        return fail("Audit engine is not installed. Re-run install.sh from this checkout.")
    remaining = list(args)
    if remaining and remaining[0] in {"run", "pipeline"}:
        remaining.pop(0)
    generate = False
    slither_args = []
    for item in remaining:
        if item in {"--poc", "--generate-poc"}:
            generate = True
        else:
            slither_args.append(item)
    root = audit_context.foundry_project_root()
    _sync_security_patterns(root, announce=True)
    # The evidence engine reads ~/.lowkey/config.json directly; persist the
    # current command context first so target/RPC changes from this invocation
    # are visible to it.
    save_config(config)
    return audit_run_pipeline(str(root), slither_args=slither_args, generate=generate)



def run_break(config, args):
    if break_engine is None:
        return fail("Break engine is not installed. Re-run install.sh from this checkout.")
    return break_engine.run(config, args, host=sys.modules[__name__])


HELP_FLAGS = {"--h", "--help", "-h", "help"}

def _help_entry(summary, usage, example, use_case, *, children=None, options=None, related=None):
    return {
        "summary": summary,
        "usage": usage,
        "example": example,
        "use": use_case,
        "children": children or {},
        "options": options or [],
        "related": related or [],
    }

COMMAND_HELP = {
    "benchmark": _help_entry(
        "Run deterministic Lowkey source-triage regression cases before trusting a release. This verifies detector behavior and language-boundary handling; it is not a real-world audit-accuracy score.",
        "lk benchmark [--json] [--verbose]",
        "lk benchmark",
        "Use it as the final regression gate after changing the audit engine, adapters, or source-triage rules.",
        options=[
            ("--json", "Emit machine-readable benchmark results.", "lk benchmark --json"),
            ("--verbose", "Show case-level error details.", "lk benchmark --verbose"),
        ],
        related=["lk self-test", "lk doctor", "lk audit run"],
    ),
    "q": _help_entry(
        "Drive a deterministic auditor-mindset question frontier from project evidence. The screen explains what the question means, what to inspect, and how strongly to trust the evidence.",
        "lk q [current|next|why|evidence|path|done|note|skip|na|not-applicable|source|reset]",
        "lk q",
        "Use it when you want Lowkey to turn project evidence into the next useful auditing question without giving you the finding.",
        children={
            "current": _help_entry("Show the current best auditor question plus the beginner workflow for answering it.", "lk q current", "lk q current", "Use it when you need a concrete next step, not just another question."),
            "next": _help_entry("Advance to or display the next applicable auditor question.", "lk q next", "lk q next", "Use it when the current question is settled or you want to move the investigation frontier forward.", related=["lk q done", "lk q current"]),

            "why": _help_entry("Explain which concrete evidence, learner state, and project context pushed the question forward.", "lk q why", "lk q why", "Use it when the chosen question feels surprising."),
            "evidence": _help_entry("Show the current question's evidence and its trust level.", "lk q evidence", "lk q evidence", "Use it to separate direct observations from source facts, derived interpretations, and weak heuristics."),
            "path": _help_entry("Show the question thread recorded so far.", "lk q path", "lk q path", "Use it to see how your investigation has narrowed."),
            "done": _help_entry("Mark the current question answered and move the frontier.", "lk q done", "lk q done", "Use it only after you can explain the answer with evidence; simply running a TRY command is not enough."),
            "note": _help_entry("Record your answer and supporting evidence for the current question, then move the frontier.", "lk q note \"...\"", "lk q note \"onlyOwner gates withdraw() and no alternate path bypasses it\"", "Use it when you have actually answered the question and want the reasoning saved."),
            "skip": _help_entry("Record that you are not pursuing the current question right now.", "lk q skip \"...\"", "lk q skip \"defer until the state review\"", "Use it for an intentional deferral; use na when the entire branch genuinely does not apply."),
            "na": _help_entry("Record that the current question genuinely does not apply to this project.", "lk q na \"...\"", "lk q na \"this project has no web/API layer\"", "Use it only when project evidence shows the whole branch is irrelevant."),
            "source": _help_entry("Show the research sources attached to a question.", "lk q source <QUESTION_ID>", "lk q source ARCH-001", "Use it to inspect the provenance behind a question."),
            "not-applicable": _help_entry("Alias for marking the current question not applicable.", "lk q not-applicable \"...\"", "lk q not-applicable \"no oracle exists in this protocol\"", "Use it as the fully spelled-out form of 'lk q na'.", related=["lk q na"]),

            "reset": _help_entry("Reset question-learning state without deleting audit evidence.", "lk q reset", "lk q reset", "Use it when starting a fresh reasoning pass on the same project."),
        },
        related=["lk questions", "lk project", "lk system", "lk findings", "lk walkthrough"],
    ),
    "questions": _help_entry(
        "Show the auditor-question frontier for the current project, with a built-in legend for waiting, active, settled, and proof states.",
        "lk questions [--all]",
        "lk questions",
        "Use it to see the investigation map and choose where to work next; it is not a vulnerability score or verdict.",
        options=[
            ("--all", "Show every applicable question in the current project.", "lk questions --all"),
            ("frontier legend", "Use ✓ settled, → active, ○ waiting, and 'proof' exactly as described in the output. None means 'vulnerable'.", "lk questions"),
            ("q controls", "Navigate and record your own answer with lk q note, done, skip, and na.", "lk q note \"...\""),
            ("reset", "Reset question-learning state without deleting audit evidence.", "lk q reset"),
        ],
        related=["lk q", "lk q current", "lk q skip", "lk q reset", "lk project", "lk system"],
    ),
    "walkthrough": _help_entry(
        "Walk through the protocol as a live story: execute one interaction, observe what changed, then redraw the board.",
        "lk walkthrough [options]",
        "lk walkthrough --auto --steps 8",
        "Use it when you want to understand how contracts, actors, calls, events, balances, and storage changes fit together before deep auditing.",
        children={
            "test": _help_entry(
                "Run randomized adversarial interactions against disposable local Anvil snapshots, restoring state between probes.",
                "lk walkthrough test [options]",
                "lk walkthrough test --auto --cases 50",
                "Use it when you want to stress assumptions and collect reproducible behavior without permanently mutating the lab state. The seed is the run's reproducibility key: it changes the randomized probe order, actors, arguments, and inputs.",
                children={
                        },
                options=[
                    ("--auto", "Automatically build/provision a local target when possible.", "lk walkthrough test --auto"),
                    ("--cases N", "Run N randomized cases; Lowkey caps this at 200.", "lk walkthrough test --cases 50"),
                    ("--seed N", "Choose the deterministic seed. The same seed reproduces the randomized probe sequence when code and baseline state are unchanged.", "lk walkthrough test --seed 42"),
                    ("--technical", "Show lower-level storage details while testing.", "lk walkthrough test --technical"),
                    ("--yes", "Run without interactive pauses.", "lk walkthrough test --yes"),
                ],
                related=["lk walkthrough", "lk trace", "lk findings"],
            ),
            "seed": _help_entry(
                "Show previous walkthrough test seeds and the short findings recorded for each run.",
                "lk walkthrough seed [SEED]",
                "lk walkthrough seed 12345",
                "Use it after a test run to see which seeds you have used, what each run found, and the exact command needed to replay one.",
            ),
        },
        options=[
            ("--auto", "Let Lowkey find/provision a safe local target and Anvil runtime.", "lk walkthrough --auto"),
            ("--static", "Render the compiled protocol model without sending live transactions.", "lk walkthrough --static"),
            ("--contract NAME", "Focus on a specific compiled contract.", "lk walkthrough --contract Escrow"),
            ("--steps N", "Limit the live story to N observed interactions.", "lk walkthrough --steps 6"),
            ("--technical", "Show lower-level storage details.", "lk walkthrough --technical"),
            ("--yes", "Run without interactive pauses.", "lk walkthrough --auto --yes"),
        ],
        related=["lk project", "lk system", "lk lab", "lk audit"],
    ),
    "break": _help_entry(
        "Run an aggressive local adversarial campaign against one function, the current target, or every live project target. It escalates through attack families and only calls something a BREAK when its harness records an explicit behavioral condition.",
        "lk break [function] [options] | lk break --system [options]",
        "lk break --function withdraw --until-found",
        "Use it when you want Lowkey to attack assumptions and collect reproducible evidence rather than just report static warnings.",
        options=[
            ("--system", "Attack every live project target Lowkey can resolve.", "lk break --system"),
            ("--function <name|signature>", "Constrain the campaign to one state-changing function.", "lk break --function 'withdraw(address,uint256)'"),
            ("--family <name>", "Run one attack family only.", "lk break --family reentrancy"),
            ("--until-found", "Keep running rounds until a concrete BREAK is reached or you stop it with Ctrl-C.", "lk break --until-found"),
            ("--rounds N", "Bound the number of campaign rounds.", "lk break --rounds 5"),
            ("--depth N", "Set the callback/reentrancy depth for the hostile harness.", "lk break --depth 8"),
            ("--seed N", "Make randomized probe selection reproducible.", "lk break --seed 42"),
        ],
        related=["lk audit", "lk probe", "lk fuzz", "lk invariant", "lk findings"],
    ),
    "targets": _help_entry(
        "Show saved targets in a compact switchboard.",
        "lk targets [--all]",
        "lk targets",
        "Use it when a project has several deployed contracts and you want to choose one quickly.",
        related=["lk target list", "lk use <name>"],
    ),
    "use": _help_entry(
        "Switch Lowkey to a saved project target.",
        "lk use <name|number>",
        "lk use Escrow",
        "Use it when several targets are available and you want to change focus without retyping an address.",
        related=["lk targets", "lk target"],
    ),
    "target": _help_entry(
        "Choose which deployed contract Lowkey should treat as the current project target.",
        "lk target <address> | lk target <name> <address> | lk target auto",
        "lk target escrow 0x1111111111111111111111111111111111111111",
        "Use it when no target is selected or Lowkey is pointing at the wrong contract.",
        children={
            "list": _help_entry("List remembered targets.", "lk target list", "lk target list", "Use it before switching when several targets exist."),
            "auto": _help_entry("Reconnect to a usable current-project deployment.", "lk target auto [name]", "lk target auto Escrow", "Use it after local deployment when you do not want to copy an address by hand."),
            "reset": _help_entry("Clear the current project target.", "lk target reset", "lk target reset", "Use it after a reset or when stale target state is getting in the way."),
        },
        related=["lk deployments", "lk status", "lk lab"],
    ),
    "lab": _help_entry(
        "Create a disposable local EVM lab for safe contract interaction and audit experiments.",
        "lk lab [Contract] | lk lab --generic [Contract] | lk lab --artifact <Contract> | lk lab stop",
        "lk lab Escrow",
        "Use it when you need a live local target for read, send, changes, trace, or walkthrough work.",
        children={
            "stop": _help_entry("Stop the project-local Anvil that Lowkey started.", "lk lab stop", "lk lab stop", "Use it when the disposable lab is no longer needed."),
        },
        options=[
            ("--generic [Contract]", "Deploy a contract directly and answer constructor prompts.", "lk lab --generic Escrow"),
            ("--artifact <Contract>", "Deploy the exact compiled artifact you name.", "lk lab --artifact Escrow"),
        ],
        related=["lk target", "lk walkthrough", "lk status"],
    ),
    "audit-checks": _help_entry(
        "Legacy compatibility alias for running the audit with the default static checks.",
        "lk audit-checks [options]",
        "lk audit-checks",
        "Use it when following an older Lowkey command sequence; new scripts should normally use lk audit --checks.",
        related=["lk audit --checks", "lk audit run"],
    ),
    "audit--checks": _help_entry(
        "Legacy compact alias for running the audit with the default static checks.",
        "lk audit--checks [options]",
        "lk audit--checks",
        "Use it only when an older command sequence already uses this spelling.",
        related=["lk audit --checks"],
    ),
    "audit": _help_entry(
        "Coordinate Lowkey's project-aware audit baseline, evidence gathering, checks, and optional live analysis.",
        "lk audit [auto|run] [options]",
        "lk audit auto --checks",
        "Use it when you want Lowkey to coordinate the audit workflow instead of invoking each inspection tool yourself.",
        children={
            "auto": _help_entry("Run the audit in autonomous mode and allow safe local target provisioning.", "lk audit auto [options]", "lk audit auto --checks", "Use it when you want the audit session to bootstrap itself."),
            "run": _help_entry("Run the full evidence pipeline, with optional PoC generation.", "lk audit run [--poc]", "lk audit run --poc", "Use it for a repeatable baseline pass that leaves evidence in the audit workspace.", options=[("--poc", "Generate a connected PoC scaffold after the evidence pass.", "lk audit run --poc")]),
            "pipeline": _help_entry("Compatibility spelling for the full audit evidence pipeline.", "lk audit pipeline [--poc]", "lk audit pipeline --poc", "Use it when an older workflow or script calls the pipeline by name; new usage should normally prefer 'lk audit run'.", related=["lk audit run"]),

        },
        options=[
            ("--checks", "Request the default static-check baseline.", "lk audit --checks"),
            ("--no-checks", "Skip the static-check layer.", "lk audit --no-checks"),
            ("--walkthrough", "Run the protocol walkthrough in the audit session.", "lk audit auto --walkthrough"),
            ("--interactive", "Force the interactive audit menu.", "lk audit --interactive"),
            ("--non-interactive", "Skip the interactive menu.", "lk audit --non-interactive"),
        ],
        related=["lk project", "lk findings", "lk walkthrough"],
    ),
    "project": _help_entry(
        "Explain a project or monorepo in plain English: purpose, contracts, tests, dependencies, and audit scope.",
        "lk project [number|path|--workspace] [--json]",
        "lk project 2",
        "Use it at the start of an audit so you know which package is the application scope and which packages are dependencies/tooling.",
        children={
            "--workspace": _help_entry("Show the larger workspace map.", "lk project --workspace", "lk project --workspace --h", "Use it before choosing a primary audit project in a monorepo."),
        },
        options=[("--json", "Print machine-readable project data.", "lk project 2 --json")],
        related=["lk projects", "lk system", "lk deps"],
    ),
    "projects": _help_entry(
        "Choose the active project inside a multi-project workspace.",
        "lk projects | lk projects <number|path> | lk projects reset",
        "lk projects 2",
        "Use it when Lowkey finds several packages and you need one primary audit scope.",
        children={
            "reset": _help_entry("Clear the active workspace project.", "lk projects reset", "lk projects reset", "Use it to make Lowkey ask for the workspace scope again."),
        },
        related=["lk project", "lk audit", "lk lab"],
    ),
    "system": _help_entry(
        "Build Lowkey's reusable model of contracts, deployments, relationships, roles, and initialization.",
        "lk system [json]",
        "lk system",
        "Use it when you want the protocol architecture before drilling into individual functions.",
        options=[("json", "Print the full system manifest as JSON.", "lk system json")],
        related=["lk project", "lk walkthrough"],
    ),
    "rpc": _help_entry(
        "Select the JSON-RPC endpoint Lowkey should use.",
        "lk rpc <url> | lk rpc set <name> <url> | lk rpc use <name> | lk rpc reset",
        "lk rpc http://127.0.0.1:8545",
        "Use it when switching between local nodes, forks, or other RPC endpoints.",
        children={
            "set": _help_entry("Save an RPC profile.", "lk rpc set <name> <url>", "lk rpc set anvil http://127.0.0.1:8545", "Use it when you have several endpoints."),
            "use": _help_entry("Select a saved RPC profile.", "lk rpc use <name>", "lk rpc use anvil", "Use it to switch RPCs without retyping URLs."),
            "reset": _help_entry("Clear the manual RPC selection.", "lk rpc reset", "lk rpc reset", "Use it when automatic local-node detection should take over."),
        },
        related=["lk fork", "lk lab", "lk status"],
    ),
    "wallet": _help_entry(
        "Manage signer profiles used for transactions.",
        "lk wallet list | set | set-env | use | remove",
        "lk wallet set-env Alice ALICE_PRIVATE_KEY",
        "Use it when you need repeatable actor identities.",
        children={
            "list": _help_entry("List signer profiles without printing secrets.", "lk wallet list", "lk wallet list", "Use it to see available signers."),
            "set": _help_entry("Save a private key locally.", "lk wallet set <name> <private-key>", "lk wallet set Alice 0x...", "Use it only for local/non-production keys you deliberately want persisted."),
            "set-env": _help_entry("Use an environment variable for a wallet key.", "lk wallet set-env <name> <ENV_VAR>", "lk wallet set-env Alice ALICE_PRIVATE_KEY", "Use it when you do not want the key stored in Lowkey config."),
            "use": _help_entry("Select a wallet profile.", "lk wallet use <name>", "lk wallet use Alice", "Use it to change the signer."),
            "remove": _help_entry("Delete a wallet profile.", "lk wallet remove <name>", "lk wallet remove Alice", "Use it to clean up old signers."),
        },
        related=["lk actor", "lk as"],
    ),
    "impersonate-actor": _help_entry(
        "Alias for impersonating an address on local Anvil/a fork.",
        "lk impersonate-actor <address> [name]",
        "lk impersonate-actor 0x... Whale",
        "Use it when a fork already contains the account whose behavior you want to reproduce.",
        related=["lk impersonate", "lk fork"],
    ),
    "actor": _help_entry("Name/select a local Anvil account.", "lk actor <index> <name> | lk actor <name> | lk actor reset", "lk actor 0 Alice", "Use it when you want readable role names instead of anonymous Anvil slots.", related=["lk actors", "lk impersonate"]),
    "actors": _help_entry("List available local Anvil accounts.", "lk actors", "lk actors", "Use it when you need to know which local addresses are available.", related=["lk actor", "lk impersonate"]),
    "impersonate": _help_entry("Impersonate an address on local Anvil/a fork.", "lk impersonate <address> [name]", "lk impersonate 0x... Whale", "Use it when the account you care about already exists on a local fork.", related=["lk fork", "lk actor"]),
    "as": _help_entry("Run one command as another configured actor, then restore your previous actor.", "lk as <actor> <command> [args...]", "lk as Bob send approve 0x... 1000", "Use it when one investigation needs several protocol roles.", related=["lk actor", "lk wallet"]),
    "abi": _help_entry(
        "Show or set the ABI Lowkey should use for the current target.",
        "lk abi | lk abi auto | lk abi <file>",
        "lk abi auto",
        "Use it when Lowkey needs help identifying the target's callable interface.",
        related=["lk functions", "lk ask"],
    ),
    "read": _help_entry("Call a contract without intentionally changing state.", "lk read <function> [args...]", "lk read balanceOf <address>", "Use it for getters and state observation.", related=["lk ask", "lk send"]),
    "send": _help_entry(
        "Send a real transaction to the selected target.",
        "lk send <function> [args...] [--preview|--confirm]",
        "lk send release --preview",
        "Use it to exercise state-changing behavior in a local lab or selected RPC.",
        options=[("--preview", "Encode/check without sending.", "lk send release --preview"), ("--confirm", "Preview first, then ask before sending.", "lk send release --confirm")],
        related=["lk changes", "lk trace", "lk receipt"],
    ),
    "import": _help_entry(
        "Resolve importable packages, symbols, and source files.",
        "lk import <symbol|path>",
        "lk import ERC721",
        "Use it to locate importable packages and verify exact source/import paths.",
        related=["lk project", "lk audit"],
    ),
    "functions": _help_entry(
        "List the selected contract's ABI functions, with optional audit metadata and compact filters.",
        "lk functions [query] [-v] [-V visibility] [-m mutability] [-c class] [-r]",
        "lk functions -v",
        "Use it when starting an unfamiliar contract and you need its callable surface or a fast function-level audit inventory.",
        options=[
            ("-v", "Verbose function metadata: source visibility, modifiers, storage refs, calls, ETH flow, selectors, and review flags.", "lk functions -v"),
            ("-V", "Filter by source visibility.", "lk functions -V external"),
            ("-m", "Filter by mutability.", "lk functions -m payable"),
            ("-c", "Filter by audit class.", "lk functions -c admin"),
            ("-r", "Show compact audit-review flags.", "lk functions -r"),
        ],
        related=["lk fn", "lk ask", "lk risk"]
    ),
    "fn": _help_entry(
        "Short spelling of the function inventory/search command.",
        "lk fn [query] [-v] [-V visibility] [-m mutability] [-c class] [-r]",
        "lk fn -v withdraw",
        "Use it for the same function inventory when you want the compact command.",
        related=["lk functions", "lk ask"]
    ),
    "ask": _help_entry("Show a function's argument names and Solidity types.", "lk ask <function>", "lk ask createbounty", "Use it before read/send/changes when you are unsure what values a function expects.", related=["lk fn", "lk changes"]),
    "wizard": _help_entry(
        "Remix-like contract interaction from the terminal. Pick one ABI function, give it the "
        "argument values, and Lowkey handles the function signature and action for you. "
        "A target must already be selected with 'lk lab' or 'lk target'.",
        "lk wizard <function> [values...] [call|send|encode]",
        "lk wizard buyNft 5",
        "Use it when you want one guided command instead of manually choosing between lk read, "
        "lk send, and lk encode. Omit values to be prompted interactively.",
        options=[
            ("call", "Simulate a read-only call with eth_call; it does not change blockchain state.", "lk wizard balanceOf 0x..."),
            ("send", "Send a state-changing transaction using the current actor; Lowkey asks for confirmation.", "lk wizard buyNft 5 send"),
            ("encode", "Only build the ABI calldata; do not call or send the transaction.", "lk wizard buyNft 5 encode"),
            ("actor", "Transactions use the current actor. Use 'lk actor' or 'lk actors' to see/select the named Anvil account and its address.", "lk actor 0 Alice"),
            ("no values", "Leave the argument values out and Lowkey prompts for each ABI input and type.", "lk wizard buyNft"),
        ],
        related=["lk ask", "lk read", "lk send", "lk encode"]
    ),
    "probe": _help_entry("Try a function as local actors and record success/revert behavior without assertions.", "lk probe <function> [args...]", "lk probe withdraw 1000 --actor Attacker", "Use it for a quick behavioral experiment before writing a full proof.", related=["lk walkthrough test", "lk generate test"]),
    "changes": _help_entry("Show storage changes caused by a function call in an isolated context.", "lk changes '<name(parameter TYPES...)>' <VALUES...>", "lk changes 'createbounty(address,uint256)' 0x... 100 ether", "Use it to connect function behavior to concrete state changes.", related=["lk mapping", "lk layout", "lk trace"]),
    "state-diff": _help_entry("Alias for the storage-change reproduction workflow.", "lk state-diff '<name(parameter TYPES...)>' <VALUES...>", "lk state-diff 'deposit(uint256)' 1000", "Use it when the state-diff terminology makes more sense to you.", related=["lk changes", "lk snapshot", "lk diff"]),
    "risk": _help_entry("Show rule-based ABI review hints and source security-pattern signals.", "lk risk", "lk risk", "Use it to find functions/patterns that deserve manual review; hints are not vulnerability verdicts.", related=["lk scan", "lk seams", "lk findings"]),
    "scan": _help_entry("Find high-signal Solidity review markers.", "lk scan [src]", "lk scan src", "Use it for fast source triage before manual reading.", related=["lk risk", "lk rg"]),
    "seams": _help_entry("Show audit hotspots where protocol boundaries and assumptions deserve extra scrutiny.", "lk seams", "lk seams", "Use it to decide where manual review should start.", related=["lk project", "lk risk", "lk walkthrough"]),
    "deps": _help_entry("Show imports, inheritance, and source dependencies.", "lk deps [src]", "lk deps src", "Use it to separate application logic from libraries, interfaces, and dependency code.", related=["lk project", "lk layout"]),
    "layout": _help_entry("Show compiled Solidity storage layout.", "lk layout <Contract>", "lk layout Escrow", "Use it when auditing mappings, packing, proxies, or storage collisions.", related=["lk mapping", "lk snapshot", "lk proof"]),
    "mapping": _help_entry("Calculate/read a mapping entry's storage location.", "lk mapping <slot> <key> | lk mapping <key_type> <slot> <key>", "lk mapping address 3 0x1111111111111111111111111111111111111111", "Use it when you know a mapping's anchor slot and want to inspect one key.", related=["lk layout", "lk snapshot"]),
    "namespace": _help_entry("Calculate an ERC-7201 namespaced storage slot.", "lk namespace <erc7201-namespace-id>", "lk namespace example.storage", "Use it when auditing namespaced storage.", related=["lk layout", "lk mapping"]),
    "proof": _help_entry("Read an account/storage proof for a slot.", "lk proof <slot> [block]", "lk proof 3 21000000", "Use it when you need storage evidence tied to a specific block.", related=["lk mapping", "lk snapshot"]),
    "snapshot": _help_entry("Save selected storage slots for later comparison.", "lk snapshot [slot ...]", "lk snapshot 0 1 2", "Use it before an experiment when you want a clean storage reference point.", related=["lk diff", "lk changes"]),
    "diff": _help_entry("Compare the saved storage snapshot with current values.", "lk diff", "lk diff", "Use it after an experiment to see which snapshotted slots changed.", related=["lk snapshot", "lk changes"]),
    "last": _help_entry(
        "Inspect the latest transaction context without retyping its hash.",
        "lk last tx | lk last trace | lk last logs",
        "lk last trace",
        "Use it right after a transaction-producing command.",
        children={
            "tx": _help_entry("Inspect the latest transaction.", "lk last tx", "lk last tx", "Use it after a send."),
            "trace": _help_entry("Trace the latest transaction.", "lk last trace", "lk last trace", "Use it when you want the latest call chain."),
            "logs": _help_entry("Show latest transaction logs.", "lk last logs", "lk last logs", "Use it when event evidence matters."),
        },
        related=["lk receipt", "lk trace", "lk logs"],
    ),
    "tx": _help_entry("Inspect and decode a transaction.", "lk tx [tx]", "lk tx 0x...", "Use it when you have a transaction hash and want call/receipt context.", related=["lk receipt", "lk trace", "lk logs"]),
    "receipt": _help_entry("Read a transaction receipt.", "lk receipt [tx]", "lk receipt 0x...", "Use it to check success/revert status, gas, and logs.", related=["lk tx", "lk trace"]),
    "trace": _help_entry("Trace transaction execution and expose the EVM call chain.", "lk trace [tx] [flags]", "lk trace 0x...", "Use it when the final result is not enough and you need to see where execution went.", related=["lk receipt", "lk walkthrough"]),
    "replay": _help_entry("Explicit alias for transaction replay/tracing.", "lk replay <tx> [trace flags...]", "lk replay 0x...", "Use it when you want the intent to be explicit in a script or note.", related=["lk trace"]),
    "logs": _help_entry("Query logs and optionally decode events.", "lk logs [args...]", "lk logs --decode", "Use it when events are part of behavior or security evidence.", options=[("--decode", "Decode matching events with the current ABI.", "lk logs --decode")], related=["lk event", "lk tx"]),
    "chain": _help_entry("Show chain ID, current block, and RPC.", "lk chain", "lk chain", "Use it to verify exactly which local chain/fork you are talking to.", related=["lk rpc", "lk fork"]),
    "label": _help_entry("Give an address a readable label in Lowkey output.", "lk label <address> <name>", "lk label 0x... Treasury", "Use it when traces and balances are easier to read with protocol role names.", related=["lk actor", "lk walkthrough"]),
    "encode": _help_entry("Build ABI calldata for a function and its values.", "lk encode <function> [args...]", "lk encode transfer 0x... 1000", "Use it for calldata debugging or low-level calls.", related=["lk decode", "lk sig", "lk calldata"]),
    "decode": _help_entry("Decode return data using the current target ABI.", "lk decode <function> <return-data>", "lk decode balanceOf 0x...", "Use it when a low-level call returned encoded bytes.", related=["lk encode", "lk decode-error"]),
    "4byte-calldata": _help_entry(
        "Look up possible function signatures for calldata/selector data.",
        "lk 4byte-calldata <selector> [args...]",
        "lk 4byte-calldata 0xa9059cbb",
        "Use it when a raw selector came from calldata and you need candidate signatures.",
        related=["lk calldata", "lk sig"],
    ),
    "4byte-event": _help_entry(
        "Look up possible event signatures from event topic data.",
        "lk 4byte-event <topic> [args...]",
        "lk 4byte-event 0xddf252ad...",
        "Use it when a raw event topic needs candidate human-readable signatures.",
        related=["lk event", "lk logs"],
    ),
    "decode-error": _help_entry("Decode a Solidity custom-error payload.", "lk decode-error <data>", "lk decode-error 0x...", "Use it when a revert payload is hex and you want the actual error and arguments.", related=["lk trace", "lk decode"]),
    "event": _help_entry("Decode an event signature, data payload, and topics.", "lk event <event-signature> <data> [topics]", "lk event 'Transfer(address,address,uint256)' 0x... 0x...", "Use it when raw logs are hard to read.", related=["lk logs", "lk tx"]),
    "poc": _help_entry("Generate an evidence-backed PoC scaffold.", "lk poc [--finding N] [--name NAME]", "lk poc --finding 2 --name withdraw-bypass", "Use it when a finding is concrete enough to deserve a reproducible proof scaffold.", related=["lk finding", "lk export"]),
    "generate": _help_entry(
        "Create reusable Forge tests, PoC scaffolds, or deployment scripts.",
        "lk generate <test|poc|deployment> ...",
        "lk generate test 'withdraw(address,uint256)' 0x... 1000",
        "Use it after observing behavior you want to turn into repeatable evidence.",
        children={
            "test": _help_entry("Generate a reusable Forge test.", "lk generate test '<name(parameter TYPES...)>' <VALUES...>", "lk generate test 'withdraw(address,uint256)' 0x... 1000", "Use it to turn an observed transition into regression evidence."),
            "poc": _help_entry("Generate a PoC scaffold connected to current evidence.", "lk generate poc <function>", "lk generate poc withdraw", "Use it as a starting point for exploit reproduction."),
            "deployment": _help_entry("Generate a deployment script.", "lk generate deployment <Contract>", "lk generate deployment Escrow", "Use it when you need a repeatable local deployment entry point."),
        },
        related=["lk matrix", "lk poc"],
    ),
    "finding": _help_entry(
        "Record a manual audit observation in the project-scoped findings ledger.",
        "lk finding <note> | lk finding add <severity> <title> <description>",
        "lk finding add medium withdraw lacks caller restriction",
        "Use it while manually reviewing source or reproducing behavior you want to track.",
        children={
            "add": _help_entry("Record a structured finding.", "lk finding add <high|medium|low|info> <title> <description>", "lk finding add medium unexpected withdraw access", "Use it when you have a concrete observation."),
            "list": _help_entry("List findings/signals.", "lk finding list", "lk finding list", "Use it as a friendly shortcut to the findings list."),
            "ls": _help_entry("Alias for finding list.", "lk finding ls", "lk finding ls", "Use it as the short form."),
        },
        related=["lk findings", "lk focus"],
    ),
    "findings": _help_entry("Show stored audit signals and their evidence.", "lk findings [status]", "lk findings open", "Use it to move from broad scanning into individual issues that need manual verification.", related=["lk focus", "lk finding"]),
    "focus": _help_entry("Set one audit signal as the investigation focus.", "lk focus <SIGNAL_ID> | lk focus clear", "lk focus SEC-0007", "Use it when one review lead becomes the main investigation thread.", related=["lk findings", "lk changes"]),
    "checklist": _help_entry(
        "Track the standard audit questions you want to cover.",
        "lk checklist | lk checklist done <item> | lk checklist reset",
        "lk checklist",
        "Use it so an interesting exploit idea does not make you skip routine review areas.",
        children={
            "done": _help_entry("Mark a checklist item complete.", "lk checklist done <item>", "lk checklist done 3", "Use it after you have actually reviewed the item."),
            "reset": _help_entry("Reset the checklist.", "lk checklist reset", "lk checklist reset", "Use it when starting a fresh review."),
        },
        related=["lk audit", "lk findings"],
    ),
    "note": _help_entry("Save a free-form audit note.", "lk note <text>", "lk note owner is initialized during setup", "Use it for thoughts that are useful but are not yet findings or TODOs.", related=["lk todo", "lk finding"]),
    "todo": _help_entry("Add an audit TODO.", "lk todo <text>", "lk todo inspect emergencyWithdraw path", "Use it when the next investigation step is clear but not yet a finding.", related=["lk note", "lk findings"]),
    "context": _help_entry("Show the current audit/project context.", "lk context", "lk context", "Use it when you are unsure which target, actor, RPC, or finding focus is active.", related=["lk status", "lk findings"]),
    "session": _help_entry(
        "Start, resume, or end a project-scoped audit session.",
        "lk session start | lk session resume | lk session end",
        "lk session resume",
        "Use it when an investigation spans multiple terminal sessions.",
        children={
            "start": _help_entry("Start a session.", "lk session start", "lk session start", "Use it when beginning an investigation."),
            "resume": _help_entry("Resume a session.", "lk session resume", "lk session resume", "Use it when returning to an existing audit."),
            "end": _help_entry("End a session.", "lk session end", "lk session end", "Use it when done for the day."),
        },
        related=["lk context", "lk export"],
    ),
    "workspace": _help_entry("Inspect/initialize project-local audit workspace files.", "lk workspace [args]", "lk workspace init", "Use it when you need Lowkey's evidence workspace on disk.", related=["lk session", "lk export"]),
    "export": _help_entry("Package current audit evidence into an audit-report directory.", "lk export", "lk export", "Use it when you want a portable audit evidence bundle.", related=["lk findings", "lk workspace"]),
    "matrix": _help_entry(
        "Build an attacker/state matrix and turn scenarios into Forge tests.",
        "lk matrix init | actor | state | add | list | test",
        "lk matrix add badRelease release Attacker revert",
        "Use it when the same security question needs testing across several callers or states.",
        children={
            "init": _help_entry("Create matrix files.", "lk matrix init", "lk matrix init", "Use it before adding scenarios."),
            "actor": _help_entry("Add a named actor/address.", "lk matrix actor <name> <address>", "lk matrix actor Attacker 0x...", "Use it when a scenario needs a specific caller."),
            "state": _help_entry("Define a named state condition.", "lk matrix state <name> <description>", "lk matrix state funded escrow holds 1 ETH", "Use it to document a scenario precondition."),
            "add": _help_entry("Add a testable scenario.", "lk matrix add <name> <function> <actor> <expected>", "lk matrix add badRelease release Attacker revert", "Use it to capture a security hypothesis before generating a test."),
            "list": _help_entry("List saved scenarios.", "lk matrix list", "lk matrix list", "Use it to review queued reproductions."),
            "test": _help_entry("Generate/run a Forge test for one scenario.", "lk matrix test <name>", "lk matrix test badRelease", "Use it when you are ready to turn the scenario into executable evidence."),
        },
        related=["lk probe", "lk generate test"],
    ),
    "fork": _help_entry(
        "Start and control a local Anvil fork of another RPC endpoint.",
        "lk fork <rpc-url> [block] [--port PORT] | lk fork status | stop | dump | load",
        "lk fork https://rpc.example 20000000",
        "Use it when you need realistic chain state but still want local control and safe mutations.",
        children={
            "status": _help_entry("Show whether the fork is running.", "lk fork status", "lk fork status", "Use it before relying on the fork RPC."),
            "stop": _help_entry("Stop the Lowkey-managed fork.", "lk fork stop", "lk fork stop", "Use it when finished with fork testing."),
            "dump": _help_entry("Checkpoint the current Anvil state.", "lk fork dump [file]", "lk fork dump fork-state.json", "Use it before destructive experiments."),
            "load": _help_entry("Restore a dumped state snapshot.", "lk fork load <file>", "lk fork load fork-state.json", "Use it to return to a known local state."),
        },
        related=["lk impersonate", "lk lab", "lk rpc"],
    ),
    "proxy": _help_entry("Inspect an EIP-1967-style proxy.", "lk proxy", "lk proxy", "Use it when a target may be a proxy and you need to distinguish proxy from implementation.", related=["lk implementation", "lk admin"]),
    "implementation": _help_entry("Resolve the implementation behind the selected proxy.", "lk implementation", "lk implementation", "Use it to find the code that executes behind a proxy.", related=["lk proxy", "lk admin"]),
    "admin": _help_entry("Resolve the proxy admin when supported.", "lk admin", "lk admin", "Use it when reviewing who controls upgrades.", related=["lk proxy", "lk implementation"]),
    "selectors": _help_entry("Extract function selectors.", "lk selectors [args...]", "lk selectors", "Use it for bytecode-level callable-surface analysis.", related=["lk sig", "lk calldata"]),
    "calldata": _help_entry("Decode raw calldata and selectors.", "lk calldata <data>", "lk calldata 0xa9059cbb...", "Use it when a trace or transaction gives you raw hex.", related=["lk encode", "lk sig"]),
    "sig": _help_entry("Print a function signature/selector representation.", "lk sig <function>", "lk sig transfer(address,uint256)", "Use it when reasoning about selectors.", related=["lk calldata", "lk encode"]),
    "disasm": _help_entry("Disassemble bytecode into EVM instructions.", "lk disasm [args...]", "lk disasm 0x...", "Use it when source or ABI evidence is unavailable.", related=["lk selectors", "lk tx"]),
    "txpool": _help_entry("Inspect the local transaction pool.", "lk txpool [args...]", "lk txpool status", "Use it when debugging pending local transactions.", related=["lk chain", "lk trace"]),
    "chisel": _help_entry("Launch/use Foundry Chisel for tiny Solidity experiments.", "lk chisel [args...]", "lk chisel", "Use it for quick Solidity/EVM experiments without creating a full contract."),
    "ens": _help_entry("Resolve ENS names or reverse-resolve addresses.", "lk ens <name|address>", "lk ens vitalik.eth", "Use it when human-readable names help identify addresses.", related=["lk label"]),
    "token": _help_entry("Read basic ERC-20 metadata or a holder balance.", "lk token <token> | lk token balance <token> <holder>", "lk token balance 0xToken 0xHolder", "Use it for quick token/accounting checks.", related=["lk read", "lk logs"]),
    "fuzz": _help_entry("Run Forge fuzz tests through Lowkey.", "lk fuzz [args...]", "lk fuzz test --match-test test_withdraw", "Use it when one fixed input is not enough.", related=["lk invariant", "lk brutalize"]),
    "invariant": _help_entry("Run Forge invariant tests.", "lk invariant [args...]", "lk invariant test", "Use it when a property should remain true across many state transitions.", related=["lk fuzz", "lk matrix"]),
    "mutate": _help_entry("Run mutation testing when configured.", "lk mutate [args...]", "lk mutate", "Use it to check whether your tests notice meaningful code changes.", related=["lk test", "lk fuzz"]),
    "symbolic": _help_entry("Run symbolic-testing workflows when configured.", "lk symbolic [args...]", "lk symbolic", "Use it when symbolic path exploration is useful.", related=["lk fuzz", "lk invariant"]),
    "brutalize": _help_entry("Stress calldata/state assumptions with adversarial inputs.", "lk brutalize [args...]", "lk brutalize", "Use it when you suspect edge cases around malformed/extreme input.", related=["lk probe", "lk fuzz"]),
    "cheat": _help_entry(
        "Open the read-only Solidity learning dictionary covering syntax, symbols, data structures, storage, calls, errors, ETH flow, interfaces, fallback/receive, and common audit concepts.",
        "lk cheat [topic] | lk cheat symbols | lk cheat search <word>",
        "lk cheat mapping",
        "Use it whenever a Solidity concept is fuzzy. It gives a mental model, syntax, real example, step-by-step explanation, and audit lookout without touching project state.",
        related=["lk import", "lk functions", "lk ask"],
    ),
    "compare": _help_entry(
        "Compare Solidity concepts side by side.",
        "lk compare <topicA> <topicB> [topicC]",
        "lk compare for while do-while",
        "Use it when concepts sound similar but behave differently.",
        related=["lk cheat", "lk connect", "lk expression"],
    ),
    "connect": _help_entry(
        "Connect two or more Solidity concepts inside one concrete contract-shaped lab.",
        "lk connect <conceptA> <conceptB> [conceptC...] | lk connect --list",
        "lk connect structs mappings arrays enums bytes addresses",
        "Use it when you understand individual pieces but need to see how their variables, values, calls, and state updates fit together.",
        related=["lk cheat", "lk compare", "lk expression"],
    ),
    "expression": _help_entry(
        "Explain one Solidity expression by its pieces.",
        'lk expression "<expression>"',
        'lk expression "balances[msg.sender] += msg.value"',
        "Use it when brackets, dots, call options, or operators make a line hard to parse.",
        related=["lk cheat", "lk compare"],
    ),
    "practice": _help_entry(
        "Run prediction-first Solidity drills.",
        "lk practice [topic]",
        "lk practice mapping",
        "Use it before executing code so you learn to predict state transitions.",
        related=["lk cheat", "lk test"],
    ),
    "confused": _help_entry(
        "Show common Solidity concept confusions.",
        "lk confused <term>",
        "lk confused calldata",
        "Use it when two terms seem interchangeable.",
        related=["lk compare", "lk cheat"],
    ),
    "patterns": _help_entry(
        "Show recurring Solidity coding/audit patterns.",
        "lk patterns",
        "lk patterns",
        "Use it to recognize common state-transition and external-call shapes.",
        related=["lk cheat", "lk audit"],
    ),
    "cheatcode": _help_entry(
        "Alias for the Foundry cheatcode helper.",
        "lk cheatcode [args...]",
        "lk cheatcode",
        "Use it when an older command sequence uses the singular form.",
        related=["lk cheatcodes"],
    ),
    "cheatcodes": _help_entry("Show or run useful Foundry cheatcode helpers.", "lk cheatcodes [args...]", "lk cheatcodes", "Use it when you need controlled local callers, balances, time, or storage.", related=["lk forge", "lk matrix"]),
    "test-gen": _help_entry("Turn the latest useful transaction/evidence into a Forge test.", "lk test-gen", "lk test-gen", "Use it after reproducing behavior and wanting a regression test.", related=["lk generate test", "lk trace"]),
    "forge": _help_entry("Pass a native Forge command through Lowkey.", "lk forge <forge-command> [args...]", "lk forge test -vvvv", "Use it when you need a Forge feature that Lowkey does not wrap separately.", related=["lk build", "lk test"]),
    "build": _help_entry("Compile the current project.", "lk build", "lk build", "Use it before trusting artifacts, ABI data, or storage layout.", related=["lk test", "lk lab"]),
    "test": _help_entry("Run the project's native Forge tests.", "lk test", "lk test", "Use it after changes and before trusting a security reproduction.", related=["lk fuzz", "lk audit"]),
    "script": _help_entry("Run a native Forge script.", "lk script <args...>", "lk script script/LocalDeploy.s.sol --sig run()", "Use it when the project already has a useful setup/deployment script.", related=["lk lab", "lk forge"]),
    "inspect": _help_entry("Run native Forge inspect commands.", "lk inspect <args...>", "lk inspect Escrow storage-layout --json", "Use it for compiler metadata Lowkey does not wrap directly.", related=["lk layout", "lk forge"]),
    "coverage": _help_entry("Run Forge coverage reporting.", "lk coverage <args...>", "lk coverage", "Use it to see which code paths your tests actually execute.", related=["lk test", "lk audit run"]),
    "lint": _help_entry("Run Forge lint tooling when supported.", "lk lint", "lk lint", "Use it for quick static/code-quality checks.", related=["lk geiger", "lk doctor"]),
    "geiger": _help_entry("Run Geiger-style scanning when available.", "lk geiger", "lk geiger", "Use it as an extra dependency/security signal.", related=["lk lint", "lk audit"]),
    "fmt": _help_entry("Format Foundry source files.", "lk fmt", "lk fmt", "Use it after intentional Solidity edits.", related=["lk build", "lk test"]),
    "create": _help_entry("Create a new Foundry component.", "lk create", "lk create", "Use it while bootstrapping contracts, libraries, or tests."),
    "batch": _help_entry("Run one Lowkey command per line from a file.", "lk batch <command-file>", "lk batch audit-steps.lk", "Use it for repeatable local investigation sequences.", related=["lk audit"]),
    "raw": _help_entry("Run a raw Cast command when Lowkey has no friendlier wrapper.", "lk raw <cast-subcommand> [args...]", "lk raw storage 0", "Use it as the advanced EVM inspection escape hatch.", related=["lk encode", "lk tx"]),
    "gas": _help_entry("Estimate gas for a function call.", "lk gas <function> [args]", "lk gas release", "Use it to see the transaction's estimated gas cost before sending.", related=["lk send", "lk trace"]),
    "slither": _help_entry("Run Slither through Lowkey's audit reporter.", "lk slither [args...]", "lk slither", "Use it for static-analysis signals that you then manually verify.", related=["lk scan", "lk findings"]),
    "rg": _help_entry("Search source with ripgrep and save the search in the audit context.", "lk rg <pattern> [path] [rg-options...]", "lk rg delegatecall src", "Use it for targeted source archaeology.", related=["lk scan", "lk deps"]),
    "info": _help_entry("Show target facts such as bytecode, ABI, and proxy information.", "lk info", "lk info", "Use it for quick reconnaissance.", related=["lk recon", "lk status"]),
    "status": _help_entry("Show active target, RPC, actor, ABI, last transaction, and open signals.", "lk status", "lk status", "Use it whenever you are unsure what Lowkey is currently pointing at.", related=["lk context", "lk target"]),
    "recon": _help_entry("Quickly inspect a live target for balance/code/nonce and proxy hints.", "lk recon", "lk recon", "Use it as a first-pass sanity check.", related=["lk info", "lk proxy"]),
    "deployments": _help_entry("List deployment records discovered in the current project.", "lk deployments", "lk deployments", "Use it when you need addresses created by a Foundry deployment run.", related=["lk target auto", "lk lab"]),
    "clone": _help_entry("Clone and onboard a repository for auditing.", "lk clone <repo> [dir] [options]", "lk clone https://github.com/example/protocol", "Use it when starting work on a repository that is not onboarded yet.", related=["lk build", "lk audit", "lk lab"]),
    "doctor": _help_entry("Diagnose Lowkey, Foundry, Anvil, dependencies, and optional tools.", "lk doctor", "lk doctor", "Use it before debugging higher-level audit behavior when the toolchain may be the problem.", related=["lk self-test"]),
    "self-test": _help_entry("Run Lowkey's built-in regression checks.", "lk self-test", "lk self-test", "Use it after changing Lowkey itself."),
    "interface": _help_entry("Inspect interface-related ABI/contract information.", "lk interface [args...]", "lk interface IERC20", "Use it when investigating interface calls or contract boundaries.", related=["lk deps", "lk selectors"]),
    "4byte": _help_entry("Use Cast's 4byte lookup helpers.", "lk 4byte ...", "lk 4byte 0xa9059cbb", "Use it when a selector needs to be matched to possible signatures.", related=["lk sig", "lk calldata"]),
    "access-list": _help_entry("Build an access list for a transaction.", "lk access-list ...", "lk access-list 0x...", "Use it when analyzing/storage-access behavior for a transaction.", related=["lk tx", "lk trace"]),
    "constructor-args": _help_entry("Inspect constructor arguments.", "lk constructor-args ...", "lk constructor-args 0x...", "Use it when reverse-engineering deployment inputs.", related=["lk creation-code", "lk lab"]),
    "creation-code": _help_entry("Inspect contract creation/init code.", "lk creation-code ...", "lk creation-code 0x...", "Use it when deployment-time behavior matters.", related=["lk constructor-args", "lk disasm"]),
    "decode-calldata": _help_entry("Decode calldata directly.", "lk decode-calldata ...", "lk decode-calldata 0xa9059cbb...", "Use it when you need a direct Cast-style calldata decoder.", related=["lk calldata", "lk sig"]),
    "abi-encode": _help_entry("ABI-encode arguments using Cast helpers.", "lk abi-encode ...", "lk abi-encode ...", "Use it for low-level encoding experiments.", related=["lk encode", "lk decode"]),
    "version": _help_entry("Show the installed Lowkey runtime version/status.", "lk version", "lk version", "Use it when checking which Lowkey runtime is installed."),
    "detect": _help_entry("Detect the current project/toolchain.", "lk detect", "lk detect", "Use it when you want Lowkey to explain which build/backend it sees.", related=["lk project", "lk doctor"]),
    "detect-project": _help_entry("Alias for project/toolchain detection.", "lk detect-project", "lk detect-project", "Use it as an explicit project-detection command.", related=["lk detect", "lk project"]),
    "storage": _help_entry("Use raw storage inspection through Cast.", "lk storage ...", "lk raw storage 0", "Use it for low-level storage reads when the higher-level wrappers are not enough.", related=["lk layout", "lk mapping"]),
    "slots": _help_entry("Alias-style low-level storage inspection.", "lk slots ...", "lk raw storage 0", "Use it for direct slot inspection.", related=["lk layout", "lk mapping"]),
    "c": _help_entry("Short alias for a contract read.", "lk c <function> [args...]", "lk c balanceOf 0x...", "Use it when you want the compact read form.", related=["lk read"]),
    "s": _help_entry("Short alias for a contract send.", "lk s <function> [args...]", "lk s release --preview", "Use it when you want the compact send form.", related=["lk send"]),
    "st": _help_entry("Short low-level/state helper alias.", "lk st ...", "lk st storage 0", "Use it when you want the compact forensic form.", related=["lk raw", "lk state-diff"]),
}


def _native_forge_help(command: str, summary: str, example: str) -> dict:
    return _help_entry(
        summary,
        f"lk {command} [forge-options...]",
        example,
        f"Use it when you need Forge's native '{command}' capability while keeping Lowkey's project routing and command surface.",
        options=[
            ("Forge options", "Pass any options supported by the installed Forge command.", f"lk {command} --help"),
            ("Forwarding", "Lowkey forwards the remaining arguments to the native Forge command; behavior depends on the installed Forge version.", f"lk {command} --help"),
        ],
        related=["lk forge", "lk doctor"],
    )


# Native Forge commands routed through bin/lk deserve first-class Lowkey help too.
COMMAND_HELP.update({
    "bind": _native_forge_help("bind", "Generate Rust bindings from the current Forge project interfaces.", "lk bind --help"),
    "bind-json": _native_forge_help("bind-json", "Generate JSON-form binding output from the current Forge project.", "lk bind-json --help"),
    "cache": _native_forge_help("cache", "Manage Forge's compiler/build cache.", "lk cache --help"),
    "clean": _native_forge_help("clean", "Remove Forge build artifacts and generated output.", "lk clean --help"),
    "compiler": _native_forge_help("compiler", "Inspect or use Forge compiler-related tooling.", "lk compiler --help"),
    "completions": _native_forge_help("completions", "Generate shell completion scripts for Forge.", "lk completions --help"),
    "config": _native_forge_help("config", "Inspect or work with Forge configuration.", "lk config --help"),
    "doc": _native_forge_help("doc", "Generate or inspect Forge documentation output.", "lk doc --help"),
    "eip712": _native_forge_help("eip712", "Work with Forge's EIP-712 tooling.", "lk eip712 --help"),
    "flatten": _native_forge_help("flatten", "Flatten Solidity imports into a single Forge output file.", "lk flatten --help"),
    "init": _native_forge_help("init", "Initialize a new Forge project.", "lk init --help"),
    "install": _native_forge_help("install", "Install Forge project dependencies.", "lk install --help"),
    "lsp": _native_forge_help("lsp", "Run Forge's language-server tooling.", "lk lsp --help"),
    "remappings": _native_forge_help("remappings", "Inspect or generate Solidity import remappings.", "lk remappings --help"),
    "remove": _native_forge_help("remove", "Remove Forge project dependencies.", "lk remove --help"),
    "soldeer": _native_forge_help("soldeer", "Manage Solidity dependencies through Forge's Soldeer integration.", "lk soldeer --help"),
    "tree": _native_forge_help("tree", "Show the Forge dependency/project tree.", "lk tree --help"),
    "update": _native_forge_help("update", "Update Forge project dependencies.", "lk update --help"),
    "verify-bytecode": _native_forge_help("verify-bytecode", "Verify deployed bytecode with Forge tooling.", "lk verify-bytecode --help"),
    "verify-check": _native_forge_help("verify-check", "Check whether contract verification configuration is valid.", "lk verify-check --help"),
    "verify-contract": _native_forge_help("verify-contract", "Verify a deployed contract through Forge tooling.", "lk verify-contract --help"),
})

HELP_ALIASES = {
    "cheats": "cheat",
    "cheatsheet": "cheat",
    "walk": "walkthrough",
    "graph": "project",
    "signals": "findings",
    "signal": "findings",
    "investigate": "focus",
    "investigation": "focus",
    "try": "probe",
    "statediff": "state-diff",
    "state_diff": "state-diff",
    "map": "mapping",
    "hotspots": "seams",
    "target-list": "targets",
    "actor-list": "actors",
    "erc20": "token",
    "resolve": "ens",
    "lookup": "ens",
    "decode-event": "event",
    "decode-calldata": "calldata",
    "returns": "decode",
    "error": "decode-error",
}

# Aliases not otherwise given their own page still get the canonical command help.
for _alias, _canonical in HELP_ALIASES.items():
    if _canonical in COMMAND_HELP:
        COMMAND_HELP.setdefault(_alias, COMMAND_HELP[_canonical])

def _canonical_help_command(command):
    return HELP_ALIASES.get(str(command or "").strip().lower(), str(command or "").strip().lower())

def _help_alias_for(command):
    raw = str(command or "").strip().lower()
    canonical = _canonical_help_command(raw)
    if not raw or raw == canonical:
        return None
    return raw

def _help_entry_for_path(path):
    if not path:
        return None, [], None
    root_token = str(path[0] or "").strip().lower()
    root = _canonical_help_command(root_token)
    entry = COMMAND_HELP.get(root)
    if not entry:
        return None, [], None
    consumed = [root]
    current = entry
    unknown = None
    for token in path[1:]:
        raw_key = str(token or "").strip().lower()
        children = current.get("children", {})
        key = HELP_ALIASES.get(raw_key, raw_key)
        if key in children:
            current = children[key]
            consumed.append(key)
        else:
            unknown = raw_key
            break
    return current, consumed, unknown

def _help_parent_path(path):
    if len(path) < 2:
        return None
    child = str(path[-1] or "").strip().lower()
    parent_root = _canonical_help_command(path[0])
    parent = COMMAND_HELP.get(parent_root)
    if not parent:
        return None
    if child in parent.get("children", {}):
        return [parent_root]
    return None


def _help_suggestions(command, limit=3):
    """Return likely Lowkey command names for a misspelled help request."""
    raw = str(command or "").strip().lower()
    if not raw:
        return []
    candidates = set(COMMAND_HELP)
    candidates.update(HELP_ALIASES)
    scored = []
    for candidate in candidates:
        canonical = _canonical_help_command(candidate)
        if candidate != canonical:
            # Prefer canonical names in suggestions; aliases remain valid but
            # should not crowd the result list.
            continue
        if candidate == raw:
            continue
        ratio = SequenceMatcher(None, raw, candidate).ratio()
        if candidate.startswith(raw) or raw.startswith(candidate):
            ratio += 0.15
        if ratio >= 0.55:
            scored.append((ratio, candidate))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [candidate for _, candidate in scored[:limit]]

def _render_command_help(path):
    entry, resolved, unknown = _help_entry_for_path(path)
    shown_path = " ".join(resolved or [str(item) for item in path])
    alias = _help_alias_for(path[0]) if path else None

    print()
    print(f"LOWKEY HELP  •  lk {shown_path}")
    print("=" * 72)

    if unknown:
        print(f"Unknown subcommand: '{unknown}' under 'lk {shown_path}'.")
        available = list((entry or {}).get("children", {}).keys())
        if available:
            print("Available next commands: " + ", ".join(available))
        print(f"Run 'lk {shown_path} --h' to see the parent help.")
        return 2

    if not entry:
        command = str(path[0] if path else "").strip().lower()
        suggestions = _help_suggestions(command)
        print(f"No dedicated Lowkey help page matches '{command}'.")
        if suggestions:
            print("")
            print("DID YOU MEAN")
            print("------------")
            for suggestion in suggestions:
                print(f"  lk {suggestion} --h")
        print("")
        print("ALL COMMANDS")
        print("------------")
        print("  lk --h")
        print("  Help forms: --h | --help | -h | help")
        return 2

    if alias:
        print(f"Alias: 'lk {alias}' is another way to run 'lk {shown_path.split()[0]}'.")
    print(f"What it does: {entry['summary']}")
    print(f"When to use: {entry['use']}")
    print(f"Usage: {entry['usage']}")
    print(f"Example: {entry['example']}")

    children = entry.get("children") or {}
    if children:
        print("")
        print("NEXT COMMANDS")
        print("-------------")
        for name, child in children.items():
            print(f"  lk {shown_path} {name}")
            print(f"      What it does: {child['summary']}")
            print(f"      When to use: {child['use']}")
            print(f"      Example: {child['example']}")
        print("")
        print("TIP")
        print("  Pick a next command above and add --h for its detailed help.")
    else:
        parent = _help_parent_path(path)
        if parent:
            parent_shown = " ".join(parent)
            print("")
            print("NAVIGATION")
            print("----------")
            print(f"  lk {parent_shown} --h")
            print("      Go back to the parent command and see its available subcommands.")

    options = entry.get("options") or []
    if options:
        print("")
        print("OPTIONS / MODES")
        print("---------------")
        for option, description, example in options:
            print(f"  {option}")
            print(f"      {description}")
            print(f"      Example: {example}")

    related = entry.get("related") or []
    if related:
        print("")
        print("RELATED COMMANDS")
        print("---------------")
        for command in related:
            print(f"  {command}")

    print("")
    print("HELP TIP")
    print("  Help is always safe: it does not select targets, send transactions, or change project state.")
    print("  Accepted forms: --h, --help, -h, help.")
    if children:
        first_child = next(iter(children))
        print(f"  Next: lk {shown_path} {first_child} --h")
    elif related:
        print(f"  Related: {related[0]}")
    elif parent:
        print(f"  Parent: lk {' '.join(parent)} --h")
    else:
        print("  Start: lk --h")
    return 0

def print_help():
    print(r"""
LOWKEY — SECURITY & AUDIT CONSOLE
=======================================

START HERE
  lk -h / lk --help                  Show the full command catalog.
  lk <command> --h                  Show friendly help for that command.
  lk <command> <subcommand> --h     Drill into the next command level.
                                   Example: lk walkthrough test --h
  lk doctor                          Check Python, Forge, Cast, Anvil, and optional tools.
  lk build                           Compile the current Foundry project.
  lk test                            Run the project's Forge tests.
  lk lab                             Start/rebuild a disposable local audit lab.
  lk target auto                     Pick the latest usable deployed target.
  lk status                          See target, RPC, actor, ABI, and last transaction.
  lk walkthrough --auto              Understand the whole protocol by executing a local flow.
  lk audit                           Run the interactive audit workflow.
  lk benchmark                       Run deterministic source-triage regression checks.
  lk break                           Aggressively attack the current target/function in a local Anvil/Forge lab.
  lk q                              Get the next auditor-mindset question from current evidence.
  lk questions                      See the compact question frontier across the project.
  lk import                         Browse/import Solidity declarations and source files.
  lk cheat                          Read-only Solidity learning dictionary.
  lk cheat mapping                  Explain mappings with a real contract example.
  lk cheat arrays-mappings           Explain arrays + mappings together.
  lk cheat require                  Explain require(condition, "message") structure.
  lk cheat fallback                 Explain fallback() step by step.
  lk cheat receive                  Explain receive() step by step.
  lk cheat interface                Explain interfaces step by step.
  lk cheat symbols                  Show Solidity symbols/operators at a glance.
  lk compare for while do-while     Compare loop forms.
  lk connect structs mappings arrays Connect concepts inside one contract lab.
  lk expression "balances[...]"     Read one Solidity expression.
  lk practice mapping               Predict behavior before executing.
  lk confused calldata              Compare commonly confused terms.
  lk patterns                       Show recurring Solidity patterns.

FIRST 10 MINUTES
  1. Start Anvil:                  anvil
  2. Compile:                      lk build
  3. Build the local lab:          lk lab
  4. See what Lowkey selected:      lk status
  5. See the project/system map:    lk project
                                     lk project 2
                                     lk system
  6. Understand the flow:           lk walkthrough --auto --steps 6
  7. List the attack surface:      lk functions
                                     lk risk
  8. Try a read safely:             lk read <function> [args]
  9. Preview a transaction:         lk send <function> [args] --preview
 10. Inspect what happened:         lk trace

COMMON TERMS
  <address>   Contract/wallet address, e.g. 0x1111...1111
  <name>      Friendly name, e.g. Alice or escrow
  <Contract>  Solidity contract name, e.g. Escrow
  <function>  Solidity function name, e.g. release
  <file>      Source file, e.g. src/EthEscrow.sol
  <dir>       Folder, e.g. src
  <slot>      Storage slot number, e.g. 3
  <key>       Mapping key, e.g. an address
  <tx>        Transaction hash
  <rpc>       RPC URL, e.g. http://127.0.0.1:8545

PROJECT / TARGET SETUP
  lk target <address>               Select a contract. Example: lk target 0x...
  lk target <name> <address>        Save + select a named target. Example: lk target escrow 0x...
  lk target list                    List saved targets.
  lk target auto [name]             Use a recent deployment. Example: lk target auto escrow
  lk use <name|number>              Switch to a saved target. Example: lk use escrow
  lk deployments                    List deployment records.
  lk clone <repo> [dir] [options]   Clone/prepare a project for auditing.
  lk projects                       Show projects found inside the current workspace.
  lk project [number|path]          Show the human-readable project map.
  lk lab [Contract]                 Set up a realistic local lab automatically.
  lk lab --generic [Contract]      Deploy a contract directly and enter constructor values.
  lk lab --artifact <Contract>     Deploy this exact compiled contract.
  lk lab stop                      Stop the local Anvil instance started by Lowkey.
  lk rpc <url>                      Set RPC manually. Example: lk rpc http://127.0.0.1:8545
  lk rpc set <name> <url>           Save an RPC profile.
  lk rpc use <name>                 Select an RPC profile.
  lk wallet list                    List signer profiles.
  lk wallet set-env <name> <ENV>    Use a private key from an environment variable.
  lk actor                          Show current actor/accounts.
  lk actor <index> <name>           Name an Anvil account. Example: lk actor 0 Alice
  lk actors                         List available Anvil actors.
  lk impersonate <address> [name]   Use an existing account on a local fork.
  lk as <actor> <command> [args]    Run one command as another actor.

UNDERSTAND THE PROJECT
  lk project [json]                Explain the project and dependency graph in plain English.
                                   Use 'lk graph' as the same command; add 'json' for raw machine data.
                                   Example: lk project
  lk system [json]                 Build/show the reusable system bootstrap manifest.
                                   Example: lk system
  lk info                          Show target, bytecode, ABI, proxy information.
  lk recon                         Quick contract reconnaissance: balance/code/nonce.
  lk functions [query]             List contract functions. Example: lk functions
  lk fn [query]                    Find/list functions. Example: lk fn release
  lk fn -h                         Explain function-search syntax.
  lk ask <function>                Show function inputs. Example: lk ask createEscrow
  lk wizard <function> [values...] [call|send|encode] Interactive argument helper.
  lk layout <Contract>             Show Forge storage layout.
  lk deps [src]                    Show imports/inheritance. Example: lk deps
  lk scan [src]                    Find high-signal Solidity review markers. Example: lk scan src
  lk seams [hotspots]              Show audit hotspots.
  lk risk                          Show ABI-level review-surface hints.
  lk gas <function> [args]         Estimate gas. Example: lk gas release
  lk slither [args...]             Run Slither through Lowkey's reporter.
  lk rg <pattern> [path]           Search source and save evidence. Example: lk rg "delegatecall" src

INTERACT WITH CONTRACTS
  lk read <function> [args]        Read without changing state. Example: lk read balanceOf <address>
  lk send <function> [args]        Send a transaction. Example: lk send release --preview
  lk send ... --preview            Encode/check without sending.
  lk send ... --confirm            Preview, then ask before sending.
  lk c <function> [args]           Short read alias. Example: lk c balanceOf <address>
  lk s <function> [args]           Short send alias. Example: lk s release --preview
  lk st ...                        Short raw-storage/low-level alias.
  lk encode <function> [args]      Build calldata. Example: lk encode release
  lk decode <function> <data>      Decode return data.
  lk decode-error <data>           Decode a custom error.
  lk event <sig> <data> [topics]   Decode event data.
  lk raw <cast-command> [args]     Run a raw Cast command when Lowkey has no nicer wrapper.

STORAGE / STATE FORENSICS
  lk mapping <slot> <key>          Calculate/read a mapping slot. Example: lk mapping 3 0x...
  lk mapping <type> <slot> <key>   Explicitly choose the mapping key type.
  lk namespace <id>                Calculate an ERC-7201 namespace slot.
  lk proof <slot> [block]          Read a storage proof.
  lk snapshot [slot ...]           Save selected storage slots.
  lk diff                          Compare the latest storage snapshot.
  lk changes '<name(parameter TYPES...)>' <VALUES...>
                                   Show storage changes from a call.
                                   FUNCTION SIGNATURE = function name + parameter TYPES.
                                   The quoted part contains TYPES, not real values.
                                   Put actual argument VALUES after the closing quote.
                                   Example:
                                     lk changes 'createbounty(address,uint256)' <addr> <amount>
  lk state-diff '<name(parameter TYPES...)>' <VALUES...>
                                   Alias for storage-change reproduction.
  lk storage / slots               Use raw Cast storage tools through lk raw when needed.

TRANSACTION FORENSICS
  lk tx [tx]                       Inspect/decode a transaction.
  lk receipt [tx]                  Read a transaction receipt.
  lk trace [tx] [flags]            Replay/trace execution.
  lk replay <tx> [flags]           Explicit transaction replay alias.
  lk logs [args...]                Query logs.
  lk logs --decode [args...]       Query and ABI-decode events.
  lk last tx                       Inspect the latest sent transaction.
  lk last trace                    Trace the latest transaction.
  lk last logs                     Query logs using the latest transaction context.
  lk chain                         Show chain ID/block/RPC.
  lk label <address> <name>        Give an address a readable label.

REPRODUCE / ATTACK / TEST
  lk probe <function> [args]       Try a call without assertions. Example: lk probe release
  lk test-gen                      Turn the latest send into a Forge test.
  lk generate test '<name(parameter TYPES...)>' <VALUES...>
                                   Generate a reusable Forge test.
                                   FUNCTION SIGNATURE = function name + parameter TYPES.
                                   The quoted part contains TYPES, not real values.
                                   Put actual argument VALUES after the closing quote.
                                   Example:
                                     lk generate test 'createbounty(address,uint256)' <addr> <amount>
  lk generate poc <function>       Generate a PoC scaffold from a function/evidence.
  lk generate deployment <Contract> Generate a deployment script.
  lk poc [--finding N]             Generate an evidence-backed PoC scaffold.
  lk fuzz [args...]                Run Forge fuzz tests.
  lk invariant [args...]           Run Forge invariant tests.
  lk symbolic [args...]            Run symbolic tests when configured.
  lk mutate [args...]              Run mutation testing.
  lk brutalize [args...]           Stress calldata/state assumptions.
  lk cheatcodes [args...]          Show/run useful Foundry cheatcode helpers.
  lk matrix init                   Create an attacker-state test matrix.
  lk matrix actor ...              Add an actor to the matrix.
  lk matrix state ...              Define a state.
  lk matrix add ...               Add a scenario.
  lk matrix list                   List scenarios.
  lk matrix test <name>            Generate a Forge test skeleton for a scenario.

AUDIT WORKFLOW / EVIDENCE
  lk audit                          Interactive audit dashboard.
  lk audit auto                    Local autonomous audit; may provision Anvil.
  lk audit --checks                Explicitly run the default static-check baseline (compatibility alias).
  lk audit --no-checks              Skip Slither/lint/unsafe-cheatcode checks; keep build/tests/coverage.
  lk audit auto --checks           Autonomous audit with the default static-check baseline.
  lk audit run                     Full evidence pipeline: build -> tests -> coverage -> Slither -> triage.
  lk audit run --poc               Same pipeline, then generate a PoC scaffold.
  lk audit--checks                 Legacy compact alias for audit --checks.
  lk finding <note>                Record a manual observation. Example: lk finding caller is not restricted
  lk finding add <sev> <title>...  Record severity/title/text in one command.
  lk findings                      Show stored findings/signals.
  lk focus <id|query>              Focus one finding/review surface.
  lk checklist                    View/reset/mark checklist items.
  lk note <text>                   Save an audit note.
  lk todo <text>                   Add an audit TODO.
  lk session [start|resume|end]   Manage audit sessions.
  lk workspace [args]             Inspect audit workspace files.
  lk export                        Build an audit-report/ bundle.

PROTOCOL WALKTHROUGH
  lk walkthrough --h                Explain the walkthrough, its options, and next commands.
  lk walkthrough test --h           Explain randomized adversarial testing.
  Example: lk walkthrough --auto --steps 8

FORK / PROXY / ABI FORENSICS
  lk fork <rpc> [block]             Start a local fork command/state.
  lk proxy                          Inspect an EIP-1967 proxy.
  lk implementation                 Resolve the implementation address.
  lk admin                          Resolve the proxy admin.
  lk selectors                     Extract runtime function selectors.
  lk calldata <data>                Decode calldata and selectors.
  lk sig <function>                 Print a function signature/selector.
  lk 4byte ...                      Extended Cast 4byte helper.
  lk access-list ...                Build/access an access list.
  lk constructor-args ...           Inspect constructor arguments.
  lk creation-code ...              Inspect creation/init code.
  lk decode-calldata ...            Decode calldata directly.
  lk abi-encode ...                 ABI-encode arguments.
  lk disasm ...                     Disassemble bytecode.
  lk txpool ...                     Inspect the local transaction pool.
  lk chisel ...                     Launch/use Foundry Chisel.
  lk ens <name|address>             ENS forward/reverse lookup.
  lk token <token>                  ERC20 metadata helper.
  lk token balance <token> <holder> ERC20 holder balance helper.
  lk snapshot/diff                   Storage snapshot + comparison.

FOUNDRY SHORTCUTS
  lk forge <forge-command> [args]   Use native Forge through Lowkey. Example: lk forge test -vvvv
  lk build                          Shortcut for forge build. Example: lk build
  lk test                           Shortcut for forge test. Example: lk test
  lk script <args>                  Shortcut for forge script.
  lk inspect <args>                 Shortcut for forge inspect.
  lk coverage <args>                Shortcut for forge coverage.
  lk lint / geiger                  Run those Forge tools when installed.
  lk fmt                            Format Foundry sources.
  lk create                         Create a new Foundry component.

UTILITIES / COMPATIBILITY
  lk context                        Show current audit/project context.
  lk state-diff / statediff         Legacy aliases for state-diff.
  lk try                            Legacy alias for probe.
  lk investigate                   Legacy alias for focus/investigation.
  lk signals                       Legacy alias for findings.
  lk resolve / lookup               ENS lookup aliases.
  lk erc20                         Token helper alias.
  lk receipt / tx / trace / logs   Transaction inspection commands.
  lk batch <file>                   Run one lk command per line.
  lk self-test                      Run Lowkey regression tests.
  lk doctor                        Diagnose installation/toolchain problems.

SAFETY / EXPECTATIONS
  • Preview sends before touching a chain: use --preview or --confirm.
  • Use local Anvil/test keys while learning; do not put production keys in Lowkey.
  • Heuristics and analyzer findings are review leads, not vulnerability verdicts.
  • The goal is RECON → ATTACK → PROVE: understand the system, reproduce behavior, then prove impact.
""")

# Root commands with a deliberate workflow. Reasons are sourced from COMMAND_HELP
# so the recommendation UX stays aligned with the command documentation.
_NEXT_COMMANDS = {
    "status": ["lk functions", "lk actors", "lk recon", "lk abi"],
    "lab": ["lk status", "lk functions", "lk actors", "lk walkthrough --auto"],
    "target": ["lk status", "lk functions", "lk abi", "lk recon"],
    "target list": ["lk target auto", "lk status", "lk functions"],
    "target auto": ["lk status", "lk functions", "lk recon"],
    "functions": ["lk fn <function>", "lk ask <function>", "lk read <function> [args]", "lk wizard <function> [values...]"],
    "fn": ["lk ask <function>", "lk read <function> [args]", "lk wizard <function> [values...]", "lk changes '<signature>' <values...>"],
    "ask": ["lk read <function> [args]", "lk wizard <function> [values...]", "lk changes '<signature>' <values...>"],
    "abi": ["lk functions", "lk ask <function>", "lk read <function> [args]", "lk wizard <function> [values...]"],
    "read": ["lk functions", "lk send <function> [args] --preview", "lk wizard <function> [values...]"],
    "send": ["lk receipt", "lk trace", "lk last tx", "lk changes '<signature>' <values...>"],
    "wizard": ["lk last tx", "lk receipt", "lk trace", "lk changes '<signature>' <values...>"],
    "project": ["lk targets", "lk recon", "lk deps", "lk risk"],
    "projects": ["lk project", "lk targets", "lk doctor"],
    "system": ["lk project", "lk doctor", "lk lab"],
    "rpc": ["lk status", "lk chain", "lk doctor"],
    "wallet": ["lk actors", "lk actor", "lk wizard <function> [values...]"],
    "actor": ["lk actors", "lk wizard <function> [values...]", "lk as <actor> <command>"],
    "actors": ["lk actor 0 Alice", "lk wizard <function> [values...]", "lk as <actor> <command>"],
    "as": ["lk status", "lk functions", "lk actors"],
    "deployments": ["lk targets", "lk target auto", "lk status"],
    "recon": ["lk functions", "lk risk", "lk scan src", "lk slither"],
    "risk": ["lk seams", "lk fn <function>", "lk slither"],
    "seams": ["lk fn <function>", "lk scan src", "lk findings"],
    "scan": ["lk findings", "lk focus <id>", "lk rg \"<marker>\" src"],
    "rg": ["lk focus <id>", "lk fn <function>", "lk changes '<signature>' <values...>"],
    "slither": ["lk findings", "lk focus <id>", "lk build"],
    "build": ["lk test", "lk functions", "lk audit run"],
    "test": ["lk coverage", "lk fuzz", "lk audit run"],
    "coverage": ["lk test", "lk fuzz", "lk audit run"],
    "audit": ["lk findings", "lk checklist", "lk q next", "lk context"],
    "audit run": ["lk findings", "lk focus <id>", "lk test-gen", "lk poc"],
    "audit pipeline": ["lk findings", "lk focus <id>", "lk test-gen"],
    "findings": ["lk focus <id>", "lk q next", "lk context", "lk checklist"],
    "focus": ["lk fn <function>", "lk changes '<signature>' <values...>", "lk trace", "lk finding <note>"],
    "probe": ["lk changes '<signature>' <values...>", "lk trace", "lk finding <note>"],
    "changes": ["lk trace", "lk findings", "lk finding <note>", "lk mapping <slot> <key>"],
    "trace": ["lk changes '<signature>' <values...>", "lk tx <tx>", "lk findings"],
    "tx": ["lk receipt", "lk trace", "lk logs"],
    "receipt": ["lk trace", "lk tx", "lk logs"],
    "logs": ["lk tx", "lk receipt", "lk event <sig> <data>"],
    "chain": ["lk status", "lk recon", "lk actors"],
    "mapping": ["lk storage <slot>", "lk changes '<signature>' <values...>", "lk snapshot <slot>"],
    "storage": ["lk mapping <slot> <key>", "lk snapshot <slot>", "lk diff"],
    "slots": ["lk mapping <slot> <key>", "lk snapshot <slot>", "lk diff"],
    "snapshot": ["lk diff", "lk mapping <slot> <key>", "lk storage <slot>"],
    "diff": ["lk mapping <slot> <key>", "lk changes '<signature>' <values...>", "lk finding <note>"],
    "encode": ["lk calldata <data>", "lk sig <function>", "lk send <function> [args] --preview"],
    "calldata": ["lk decode-calldata <data>", "lk sig <function>", "lk tx <tx>"],
    "sig": ["lk calldata <data>", "lk 4byte <selector>", "lk fn <function>"],
    "selectors": ["lk calldata <data>", "lk sig <function>", "lk disasm <address>"],
    "proxy": ["lk implementation", "lk admin", "lk storage <slot>"],
    "implementation": ["lk proxy", "lk admin", "lk functions"],
    "admin": ["lk proxy", "lk implementation", "lk findings"],
    "gas": ["lk send <function> [args] --preview", "lk changes '<signature>' <values...>", "lk trace"],
    "generate": ["lk generate test '<signature>' <values...>", "lk poc", "lk test"],
    "generate test": ["lk test", "lk trace", "lk findings"],
    "poc": ["lk test", "lk findings", "lk generate test '<signature>' <values...>"],
    "test-gen": ["lk test", "lk fuzz", "lk findings"],
    "fuzz": ["lk findings", "lk test-gen", "lk trace"],
    "invariant": ["lk findings", "lk test-gen", "lk trace"],
    "mutate": ["lk findings", "lk test-gen", "lk test"],
    "symbolic": ["lk findings", "lk trace", "lk test-gen"],
    "brutalize": ["lk findings", "lk test-gen", "lk trace"],
    "q": ["lk q next", "lk q why", "lk q evidence"],
    "q next": ["lk q why", "lk q evidence", "lk q source"],
    "questions": ["lk q next", "lk q skip", "lk q reset"],
    "checklist": ["lk findings", "lk q next", "lk context"],
    "finding": ["lk findings", "lk focus <id>", "lk checklist"],
    "note": ["lk findings", "lk context", "lk todo <text>"],
    "todo": ["lk findings", "lk context", "lk checklist"],
    "session": ["lk context", "lk findings", "lk workspace"],
    "workspace": ["lk findings", "lk context", "lk export"],
    "export": ["lk findings", "lk workspace", "lk session end"],
    "doctor": ["lk self-test", "lk build", "lk status"],
    "self-test": ["lk doctor", "lk status"],
    "clone": ["lk doctor", "lk project", "lk build"],
    "deps": ["lk project", "lk risk", "lk scan src"],
    "layout": ["lk mapping <slot> <key>", "lk storage <slot>", "lk changes '<signature>' <values...>"],
    "namespace": ["lk storage <slot>", "lk proof <slot>", "lk layout <Contract>"],
    "proof": ["lk storage <slot>", "lk snapshot <slot>", "lk diff"],
    "fork": ["lk status", "lk target auto", "lk actors"],
    "impersonate": ["lk actors", "lk status", "lk wizard <function> [values...]"],
    "disasm": ["lk selectors", "lk storage <slot>", "lk findings"],
    "txpool": ["lk tx <tx>", "lk receipt", "lk trace"],
    "ens": ["lk token <address>", "lk status", "lk read <function> [args]"],
    "token": ["lk read <function> [args]", "lk actors", "lk status"],
    "info": ["lk functions", "lk proxy", "lk recon"],
    "label": ["lk actors", "lk status", "lk recon"],
    "matrix": ["lk matrix list", "lk matrix test <name>", "lk matrix add <name> <text>"],
    "matrix list": ["lk matrix test <name>", "lk matrix add <name> <text>"],
    "matrix test": ["lk test", "lk findings"],
    "walkthrough": ["lk functions", "lk changes '<signature>' <values...>", "lk trace"],
    "walkthrough test": ["lk findings", "lk test-gen", "lk trace"],
}


def _recommendation_reason(command_text):
    """Use the command's own help page as the explanation for why to try it."""
    tokens = str(command_text or "").strip().split()
    if not tokens or tokens[0].lower() != "lk":
        return "Continue exploring from here."
    path = [token for token in tokens[1:3] if not token.startswith("<") and not token.startswith("[")]
    entry, _, _ = _help_entry_for_path(path[:2] or [])
    if entry:
        return str(entry.get("use") or entry.get("summary") or "Continue exploring from here.")
    return "Continue exploring from here."


def _recommended_next_commands(command, args=None, config=None):
    """Return a small, contextual next-step menu for an interactive CLI user."""
    raw_command = str(command or "").strip().lower()
    raw_args = [str(item).strip() for item in (args or [])]
    canonical = _canonical_help_command(raw_command)

    # Machine-readable commands must remain machine-readable.
    if any(item.lower() == "--json" or item.lower() == "json" for item in raw_args):
        return []
    if canonical in {"raw", "batch"}:
        return []

    command_key = canonical
    nested = {
        "audit": {"run", "pipeline", "auto"},
        "walkthrough": {"test", "seed"},
        "generate": {"test", "poc", "deployment", "contract"},
        "target": {"list", "auto", "reset"},
        "rpc": {"set", "use", "reset"},
        "wallet": {"list", "set", "set-env", "use", "remove"},
        "session": {"start", "resume", "end"},
        "fork": {"status", "stop", "dump", "load"},
        "matrix": {"init", "actor", "state", "add", "list", "test"},
        "finding": {"add", "list", "ls"},
        "checklist": {"done", "reset"},
        "actor": {"reset"},
        "q": {"current", "next", "why", "evidence", "path", "done", "note", "skip", "na", "not-applicable", "source", "reset"},
    }
    first_arg = raw_args[0].lower() if raw_args else ""
    if first_arg in nested.get(canonical, set()):
        command_key = f"{canonical} {first_arg}"

    dynamic_items = _function_interaction_recommendations(command, raw_args, config or {}) if canonical in {"read","send","wizard"} else []
    items = dynamic_items or list(_NEXT_COMMANDS.get(command_key, _NEXT_COMMANDS.get(canonical, [])))

    if canonical in {"fn", "ask"} and raw_args and not raw_args[0].startswith("-"):
        query = shlex.quote(raw_args[0])
        items = [
            f"lk ask {query}",
            f"lk read {query} [args]",
            f"lk wizard {query} [values...]",
            "lk changes '<signature>' <values...>",
        ]

    # Recommendations are deliberately opt-in. A command without a curated
    # workflow is better served by no footer than by generic/unrelated advice.
    if not items:
        return []

    current_query=_function_query_for_command(command, raw_args)
    if current_query and canonical in {"read","send","wizard","fn","ask"}:
        normalized_current=f"lk {canonical} {str(current_query).strip()}".strip().lower()
    else:
        normalized_current=f"lk {command_key}".strip().lower()
    rendered = []
    for item in items:
        if isinstance(item,(tuple,list)) and len(item)==2:
            command_text=str(item[0]).strip()
            reason=str(item[1]).strip()
        else:
            command_text = str(item).strip()
            reason = _recommendation_reason(command_text)
        if (
            not command_text
            or command_text == normalized_current
            or command_text.startswith(normalized_current + " ")
        ):
            continue
        if not reason:
            reason = _recommendation_reason(command_text)
        pair = (command_text, reason)
        if pair not in rendered:
            rendered.append(pair)
        if len(rendered) >= 4:
            break
    return rendered


def _print_recommended_next_commands(command, args=None, result=0, config=None):
    """Render contextual next steps without breaking failed or machine-readable commands."""
    result_code = result if isinstance(result, int) else getattr(result, "code", 0)
    if result_code not in {None, 0} or _COMMAND_STATUS:
        return
    items = _recommended_next_commands(command, args, config)
    if not items:
        return
    print("")
    print("RECOMMENDED NEXT COMMANDS")
    print("=========================")
    for command_text, reason in items:
        print(f"  {command_text:<42} {reason}")


def dispatch_command(cmd,args,config,from_batch=False):
    # Contextual help is side-effect free: do not activate targets or execute
    # commands when the user is only asking for documentation.
    lowered_cmd = str(cmd or "").strip().lower()
    if lowered_cmd in HELP_FLAGS:
        if args:
            return _render_command_help(args)
        print_help()
        return 0

    help_index = next(
        (
            index for index, token in enumerate(args or [])
            if str(token).strip().lower() in HELP_FLAGS
        ),
        None,
    )
    if help_index is not None:
        return _render_command_help([cmd, *(args or [])[:help_index]])

    activate_project_target(config)
    if cmd in {"--version","-V","version"}: return run_version()
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
            ref = str(args[0]).strip()
            entries = _project_target_entries(config, root)
            protocol_entries = [entry for entry in entries if _target_entry_is_protocol(root, entry)]

            selected_entry = None
            if ref.isdigit():
                index = int(ref) - 1
                if 0 <= index < len(protocol_entries):
                    selected_entry = protocol_entries[index]
                else:
                    return fail(f"Error: target number must be between 1 and {len(protocol_entries)}.")
            elif is_address(ref):
                selected_entry = next(
                    (entry for entry in protocol_entries
                     if str(entry.get("address")).lower() == ref.lower()),
                    None,
                )
                if selected_entry is None:
                    config["target"] = ref
            else:
                matches = [
                    entry for entry in protocol_entries
                    if str(entry.get("name") or entry.get("contract") or "").strip().lower() == ref.lower()
                ]
                if len(matches) == 1:
                    selected_entry = matches[0]
                elif len(matches) > 1:
                    print(f"Ambiguous target name: {ref}")
                    print("Use the number from 'lk targets' or the target address.")
                    return 0
                else:
                    resolved = resolve_target_ref(config, ref, root)
                    if resolved:
                        selected_entry = next(
                            (entry for entry in protocol_entries
                             if str(entry.get("address")).lower() == str(resolved).lower()),
                            None,
                        )
                    if selected_entry is None:
                        return run_auto_target(config, ref)

            if selected_entry is not None:
                return _select_project_target(config, selected_entry, root)

            audit_context.set_target(
                root,
                address=config["target"],
                contract=config.get("target_contract"),
                artifact=config.get("abi_paths",{}).get(config["target"]),
                source="manual",
            )
        elif len(args)==2 and is_address(args[1]):
            remember_project_target(config, root, args[0], args[1])
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
    elif cmd in {"targets","target-list"}: return run_targets(config, include_support=bool(args and args[0] == "--all"))
    elif cmd=="use":
        root=audit_context.foundry_project_root()
        if not args:
            run_targets(config)
            return
        resolved=resolve_target_ref(config,args[0],root)
        if not resolved:
            print(f"Unknown target for project: {args[0]}")
            return
        entries=_project_target_entries(config,root)
        entry=next((item for item in entries if str(item.get("address")).lower()==str(resolved).lower()),None)
        if entry:
            return _select_project_target(config,entry,root)
        return fail("Error: target belongs to a different project context.")
    elif cmd in {"build", "test"}: return run_native_project_command(config, cmd, args)
    elif cmd=="deployments": run_deployments(config)
    elif cmd in {"project","graph"}: return run_project_map(config,args)
    elif cmd=="projects": return run_projects(config,args)
    elif cmd=="system": return run_system_model(config,args)
    elif cmd=="clone": return run_clone(config,args)
    elif cmd=="lab": return run_lab(config,args)
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
        if len(args) == 1 and is_address(args[0]):
            return fail(
                "Usage: lk read <function> [args]\n"
                "       lk read <target> <function> [args]\n"
                "A bare address is a contract target, not a function call."
            )
        return run_cast(["call",*args],config)
    elif cmd in {"send"}:
        return run_cast(["send",*args],config)
    elif cmd in {"try","probe"}:
        return run_probe(config,args)
    elif cmd in {"changes","state-diff"}:
        return run_state_diff(config,args)
    elif cmd=="functions": return run_functions(config,args)
    elif cmd=="fn": return run_functions(config,args)
    elif cmd=="wizard": run_wizard(config,args)
    elif cmd=="replay": run_replay(config,args)
    elif cmd=="fork": return run_fork(args,config)
    elif cmd=="ask":
        if len(args) != 1:
            return fail("Usage: lk ask <function>  (this command only inspects the function's parameters)")
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
        if len(matches) != 1:
            suggestions = sorted(funcs,key=lambda x:function_score(x,query),reverse=True)[:8]
            print(f"No exact function match for '{query}'.")
            if suggestions:
                print("Did you mean:")
                for item in suggestions:
                    print(f"  {format_signature(item)}")
            print("Use 'lk functions' to list the full contract interface.")
            return 2
        item=matches[0]
        print(f"Function: {format_signature(item)}")
        for index,param in enumerate(item.get("inputs",[]),1):
            print(f"  arg{index}: {param.get('name') or 'arg'+str(index)} : {canonical_type(param)}")
    elif cmd=="info": run_info(config)
    elif cmd=="status": run_status(config)
    elif cmd in {"project", "detect-project", "detect"}:
        info = detect_project(detected_project_root(".")) if detect_project else None
        if not info:
            return fail("Project detection layer is unavailable. Reinstall Lowkey.")
        print(format_detection(info))
        return 0
    elif cmd in {"audit--checks","audit-checks"}: return run_audit_mode(config, ["--checks", *args])
    elif cmd=="audit":
        if args and args[0] in {"run","pipeline"}:
            return run_external_audit(config,args)
        return run_audit_mode(config,args)
    elif cmd=="break": return run_break(config,args)
    elif cmd=="benchmark":
        if benchmark is None:
            return fail("Benchmark module is not installed. Re-run install.sh from this checkout.")
        return benchmark.run(args)
    elif cmd=="q":
        if question_engine is None:
            return fail("Question engine is not installed. Re-run install.sh from this checkout.")
        return question_engine.run(config, args)
    elif cmd=="questions":
        if question_engine is None:
            return fail("Question engine is not installed. Re-run install.sh from this checkout.")
        return question_engine.run(config, args, mode="overview")
    elif cmd in {"walkthrough","walk"}: return walkthrough.run(config,args,host=sys.modules[__name__])
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
    elif cmd in {"cheat","cheats","cheatsheet"}: return run_cheat(args)
    elif cmd in {"compare","connect","expression","practice","confused","patterns"}: return run_cheat([cmd,*args])
    elif cmd in {"cheatcodes","cheatcode"}: return run_cheatcodes(args)
    elif cmd in {"actors","actor-list"}: return list_anvil_actors(config)
    elif cmd in {"ens","resolve","lookup"}: run_ens(config,args)
    elif cmd in {"token","erc20"}: run_token(config,args)
    elif cmd=="snapshot": run_snapshot(config,args)
    elif cmd=="diff": run_diff(config)
    elif cmd=="finding":
        if not args:
            print("Usage:")
            print("  lk finding add <high|medium|low|info> <title> <description>")
            print("  lk finding <note>")
            print("  lk findings              List audit signals/findings")
            return 0
        if args[0].lower() in {"list", "ls"}:
            return run_signals(config, args[1:])
        if args[0]=="add" and len(args)>=4:
            run_finding(config,f"[{args[1].upper()}] {args[2]}: {' '.join(args[3:])}")
        else:
            run_finding(config," ".join(args))
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
    elif cmd=="scan": return run_scan(args)
    elif cmd=="rg": return run_audit_rg(config,args)
    elif cmd=="poc": return run_audit_poc(config,args)
    elif cmd=="deps": run_deps(args)
    elif cmd=="layout": run_layout(args)
    elif cmd=="gas": run_gas(config,args)
    elif cmd=="raw": run_raw(config,args)
    elif cmd=="batch": run_batch(config,args)
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
    else:
        print(f"Error: unknown Lowkey command '{cmd}'.", file=sys.stderr)
        print("Run 'lk --help' for the command catalog or 'lk <command> --h' for command help.", file=sys.stderr)
        return 2


def main():
    global _COMMAND_STATUS
    _COMMAND_STATUS = 0
    config=load_config()
    if len(sys.argv)<2:
        print_help()
        return

    command = sys.argv[1]
    if command.lower() in HELP_FLAGS or any(
        str(argument).strip().lower() in HELP_FLAGS for argument in sys.argv[2:]
    ):
        result = dispatch_command(command, sys.argv[2:], config)
        if isinstance(result, int):
            raise SystemExit(result)
        return

    if command.lower() in {"cheat", "cheats", "cheatsheet"}:
        result = run_cheat(sys.argv[2:])
        _print_recommended_next_commands(command, sys.argv[2:], result, config)
        if isinstance(result, int):
            raise SystemExit(result)
        return

    root = audit_context.foundry_project_root()
    _sync_audit_context(config, root)

    runtime = runtime_sync_status()
    runtime_safe_commands = {
        "--h", "--help", "-h", "help", "--version", "-V", "version",
        "doctor", "self-test",
    }
    if runtime.get("status") in {"stale", "corrupt"} and command not in runtime_safe_commands:
        print("LOWKEY RUNTIME OUT OF SYNC", file=sys.stderr)
        print(f"  {runtime.get('detail', 'installed runtime verification failed')}", file=sys.stderr)
        source_repo = runtime.get("source_repo")
        if source_repo:
            print(f"  FIX: cd {source_repo} && bash install.sh", file=sys.stderr)
        else:
            print("  FIX: reinstall Lowkey with bash install.sh", file=sys.stderr)
        return fail("Refusing to run with a mismatched Lowkey installation.", 3)

    result=dispatch_command(command,sys.argv[2:],config)
    evidence_commands={
        "scan","slither","changes","state-diff","trace","logs","tx","receipt",
        "send","probe","test-gen","fuzz","invariant","mutate","symbolic","brutalize",
        "mapping","snapshot","diff","risk","seams","matrix","finding","focus","findings",
        "audit","audit--checks","audit-checks","audit","break","walkthrough","walk","rg","poc","project","system","q","questions"
    }
    if sys.argv[1] in evidence_commands and sys.argv[1] not in {"focus","findings","audit","audit--checks","audit-checks","break"}:
        try:
            refresh_generated_poc(config)
        except Exception as error:
            print(f"Warning: automatic PoC refresh failed: {error}", file=sys.stderr)
    if config.pop("_config_dirty",False):
        save_config(config)
    final_root = audit_context.foundry_project_root()
    _sync_audit_context(config, final_root)
    _print_recommended_next_commands(command_name if 'command_name' in locals() else command, sys.argv[2:], result, config)
    command_name = str(sys.argv[1] or "").strip().lower()
    first_arg = str(sys.argv[2] or "").strip().lower() if len(sys.argv) > 2 else ""
    nested_commands = {
        "audit": {"run", "pipeline"},
        "walkthrough": {"test", "seed"},
        "walk": {"test", "seed"},
        "generate": {"test", "script", "contract"},
        "project": {"--workspace"},
        "projects": {"reset"},
        "target": {"list", "auto", "reset"},
        "rpc": {"set", "use", "reset"},
        "wallet": {"list", "set", "set-env", "use", "remove"},
        "session": {"start", "resume", "end"},
        "fork": {"status", "stop", "dump", "load"},
        "matrix": {"init", "actor", "state", "add", "list", "test"},
        "finding": {"add", "list", "ls"},
        "checklist": {"done", "reset"},
        "actor": {"reset"},
        "q": {"current", "next", "why", "evidence", "path", "done", "note", "skip", "na", "not-applicable", "source", "reset"},
    }
    command_path = command_name
    if first_arg and first_arg in nested_commands.get(command_name, set()):
        command_path = f"{command_name} {first_arg}"
    audit_context.emit(
        "lk-command",
        final_root,
        tool="lk",
        status="completed" if (not isinstance(result,int) or result == 0) else "failed",
        summary=command_path,
        data={
            "command": command_name,
            "command_path": command_path,
            "subcommand": first_arg if command_path != command_name else None,
            "exit_code": result if isinstance(result,int) else 0,
        },
    )
    if isinstance(result,int): raise SystemExit(result)
    if _COMMAND_STATUS: raise SystemExit(_COMMAND_STATUS)

def _safe_main() -> int:
    """Never expose a Python traceback for a CLI-level repository/runtime failure."""
    try:
        result = main()
        return int(result) if isinstance(result, int) else 0
    except KeyboardInterrupt:
        print("\nLOWKEY: interrupted.", file=sys.stderr)
        return 130
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 0
    except Exception as exc:
        root = None
        try:
            root = audit_context.foundry_project_root()
        except Exception:
            root = None

        print("LOWKEY RUNTIME ERROR", file=sys.stderr)
        print(f"  {type(exc).__name__}: {exc}", file=sys.stderr)
        if root:
            print(f"  project: {root}", file=sys.stderr)
            try:
                evidence = Path(root) / ".audit" / "evidence"
                evidence.mkdir(parents=True, exist_ok=True)
                (evidence / "lk-runtime-error.json").write_text(
                    json.dumps({
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "project": str(root),
                        "command": sys.argv[1:],
                        "status": "blocked",
                    }, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                print("  evidence: .audit/evidence/lk-runtime-error.json", file=sys.stderr)
            except Exception as evidence_error:
                print(f"  evidence: unavailable ({evidence_error})", file=sys.stderr)
        print("  RESULT: REVIEW NEEDED — Lowkey could not complete this command.", file=sys.stderr)
        print("  No security conclusion should be inferred from this failure.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_safe_main())
