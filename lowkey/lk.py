import os
import json
import subprocess
import sys
import re
import shlex
from datetime import datetime

CONFIG_DIR = os.path.expanduser("~/.lowkey")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
SNAPSHOT_DIR = os.path.join(CONFIG_DIR, "snapshots")
AUDIT_DIR = os.path.expanduser("~/.lowkey/audit")
SESSION_FILE = os.path.join(AUDIT_DIR, "session_log.txt")
WORKSPACE_DIR = os.path.join(os.getcwd(), ".audit")

def load_config():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
    if not os.path.exists(CONFIG_FILE):
        return {
            "target": None, "aliases": {}, "rpc": None,
            "rpc_profiles": {}, "actor": None, "wallets": {},
            "abi_paths": {}, "labels": {}
        }
    with open(CONFIG_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return {"target": None, "aliases": {}, "rpc": None, "rpc_profiles": {}, "actor": None, "wallets": {}, "abi_paths": {}, "labels": {}}

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    os.chmod(CONFIG_FILE, 0o600)

def last_transaction(config):
    return config.get("last_tx")

def log_session(command, result):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(SESSION_FILE, "a") as f:
        f.write(f"[{timestamp}] CMD: {command}\nRES: {result}\n{'-'*40}\n")

def resolve_function(func_name, target, config):
    abi_path = config.get("abi_paths", {}).get(target)
    if not abi_path or not os.path.exists(abi_path):
        return func_name
    try:
        with open(abi_path, "r") as f:
            abi = json.load(f)
            if isinstance(abi, dict):
                abi = abi.get("abi", [])
            for item in abi:
                if item.get("type") == "function" and item.get("name") == func_name:
                    inputs = item.get("inputs", [])
                    types = [i.get("type") for i in inputs]
                    return f"{func_name}({','.join(types)})"
    except Exception:
        pass
    return func_name

def load_abi(target, config):
    abi_path = config.get("abi_paths", {}).get(target)
    if not abi_path or not os.path.exists(abi_path):
        return []
    try:
        with open(abi_path, "r") as f:
            artifact = json.load(f)
        return artifact.get("abi", []) if isinstance(artifact, dict) else artifact
    except (OSError, json.JSONDecodeError):
        return []

def format_signature(item):
    inputs = ",".join(value.get("type", "") for value in item.get("inputs", []))
    return f"{item.get('name', '<anonymous>')}({inputs})"

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

def run_functions(config):
    target = config.get("target")
    if not target:
        print("Error: Set target first.")
        return
    functions = [item for item in load_abi(target, config) if item.get("type") == "function"]
    if not functions:
        print("Error: No ABI functions loaded for the current target.")
        return
    for item in functions:
        mutability = item.get("stateMutability", "unknown").upper()
        print(f"{mutability:10} {format_signature(item)}")

def run_info(config):
    target = config.get("target")
    if not target:
        print("Error: Set target first.")
        return
    print(f"Target: {target}")
    run_chain(config)
    code = run_cast(["code", target], config, capture=True) or ""
    print(f"Code:   {'YES' if code.startswith('0x') and len(code) > 2 else 'NO'}")
    print(f"ABI:    {'LOADED' if load_abi(target, config) else 'NOT LOADED'}")
    print(f"Proxy:  {'YES' if inspect_proxy(config, quiet=True) else 'NO'}")

def run_encode(config, args):
    if not args:
        print("Usage: lk encode <function> [args]")
        return
    run_cast(["calldata"] + args, config)

def run_signature(args):
    if not args:
        print("Usage: lk sig <function(signature)>")
        return
    signature = args[0]
    selector = subprocess.run(["cast", "sig", signature], capture_output=True, text=True)
    if selector.stdout.strip():
        print(selector.stdout.strip())
    if selector.stderr.strip():
        print(selector.stderr.strip(), file=sys.stderr)

def cast_output(args):
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip()

def abi_selector(signature):
    output, _ = cast_output(["cast", "sig", signature])
    return output.splitlines()[0].strip() if output else None

def decode_abi_input(signature, data):
    payload = data[10:] if data.startswith("0x") else data
    output, error = cast_output(["cast", "decode-abi", "--input", signature, "0x" + payload])
    return output or error

def run_decode_error(config, args):
    if not args:
        print("Usage: lk decode-error <revert-data>")
        return
    data = args[0]
    if not data.startswith("0x") or len(data) < 10:
        print("Error: revert data must be hex calldata beginning with 0x.")
        return
    selector = data[:10].lower()
    errors = [item for item in load_abi(config.get("target"), config) if item.get("type") == "error"]
    for item in errors:
        signature = format_signature(item)
        if (abi_selector(signature) or "").lower() == selector:
            print(f"Error: {signature}")
            if item.get("inputs"):
                decoded = decode_abi_input(signature, data)
                if decoded:
                    print(decoded)
            else:
                print("Arguments: none")
            return
    print(f"Unknown custom error selector: {selector}")
    print(f"Raw data: {data}")

def run_tx(config, args):
    tx_hash = args[0] if args else last_transaction(config)
    if not tx_hash:
        print("Usage: lk tx <transaction-hash> (or save a transaction first)")
        return
    command = ["cast", "tx", tx_hash, "--json"]
    if config.get("rpc"):
        command.extend(["--rpc-url", config["rpc"]])
    output, error = cast_output(command)
    if error and not output:
        print(error, file=sys.stderr)
        return
    try:
        transaction = json.loads(output)
    except json.JSONDecodeError:
        print(output)
        return
    transaction = transaction.get("data", transaction)
    print(f"Hash:  {transaction.get('hash', tx_hash)}")
    print(f"From:  {apply_labels(transaction.get('from', 'Unknown'), config)}")
    print(f"To:    {apply_labels(transaction.get('to', 'Unknown'), config)}")
    value = transaction.get("value", "0")
    if isinstance(value, str) and value.startswith("0x"):
        value = str(int(value, 16))
    print(f"Value: {humanize_value(str(value))}")
    input_data = transaction.get("input", "0x")
    if input_data and input_data != "0x" and len(input_data) >= 10:
        selector = input_data[:10].lower()
        for item in load_abi(config.get("target"), config):
            if item.get("type") != "function":
                continue
            signature = format_signature(item)
            if (abi_selector(signature) or "").lower() == selector:
                print(f"Function: {signature}")
                print(f"Args:    {decode_abi_input(signature, input_data)}")
                break
        else:
            print(f"Selector: {selector} (unknown to loaded ABI)")

def run_receipt(config, tx_hash=None):
    tx_hash = tx_hash or last_transaction(config)
    if not tx_hash:
        print("Error: No transaction hash supplied or saved.")
        return
    run_cast(["receipt", tx_hash], config)

def run_trace(config, args=None):
    args = args or []
    tx_hash = args[0] if args and args[0].startswith("0x") else last_transaction(config)
    if not tx_hash:
        print("Error: No transaction hash supplied or saved.")
        return
    run_cast(["run", tx_hash] + (["-t"] if "--trace-printer" in args else []), config)

def run_logs(config, args):
    run_cast(["logs"] + args, config)

def run_last(config, args):
    action = args[0] if args else "receipt"
    actions = {
        "receipt": run_receipt,
        "tx": run_receipt,
        "trace": run_trace,
        "logs": lambda current: run_logs(current, []),
    }
    handler = actions.get(action)
    if not handler:
        print("Usage: lk last [receipt|trace|logs]")
        return
    handler(config)

def apply_labels(text, config):
    labels = config.get("labels", {})
    for addr, label in labels.items():
        text = text.replace(addr, f"{label} ({addr})")
    return text

def humanize_value(text):
    wei_pattern = r'\b(0x)?(\d{18,})\b'
    def replace_wei(match):
        val = match.group(2)
        try:
            eth_val = int(val) / 10**18
            return f"{match.group(0)} [~{eth_val:.4f} ETH]"
        except:
            return match.group(0)
    return re.sub(wei_pattern, replace_wei, text)

def is_address(value):
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value))

def is_nonzero_slot(value):
    try:
        return int(value, 16) != 0
    except (TypeError, ValueError):
        return False

def redact_secrets(text):
    return re.sub(r"(--private-key\s+)(\S+)", r"\1<redacted>", text)

def run_cast(args, config, capture=False):
    if not args: return None
    action = args[0]
    shortcut_map = {"c": "call", "s": "send", "st": "storage"}
    cast_cmd = shortcut_map.get(action, action)
    cmd = ["cast", cast_cmd]
    remaining_args = args[1:]

    target = config.get("target")
    if cast_cmd in ["call", "send", "storage"]:
        if remaining_args and is_address(remaining_args[0]):
            target = remaining_args.pop(0)
        if target:
            cmd.append(target)

    if cast_cmd in ["call", "send"] and remaining_args:
        func_arg = remaining_args[0]
        if "(" not in func_arg or ")" not in func_arg:
            resolved = resolve_function(func_arg, target, config)
            if resolved != func_arg:
                remaining_args[0] = resolved

    cmd.extend(remaining_args)
    local_commands = {"keccak", "calldata", "sig"}
    if cast_cmd not in local_commands and config.get("rpc") and "--rpc-url" not in " ".join(cmd):
        cmd.extend(["--rpc-url", config["rpc"]])
    if cast_cmd == "send" and config.get("actor") and "--private-key" not in " ".join(cmd):
        cmd.extend(["--private-key", config["actor"]])

    full_cmd = " ".join(cmd)
    safe_cmd = redact_secrets(full_cmd)
    if not capture: print(f"DEBUG: Executing -> {safe_cmd}\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        out = result.stdout.strip()
        err = result.stderr.strip()
        final_res = out if out else err

        log_session(safe_cmd, final_res)

        if cast_cmd == "send" and out:
            match = re.search(r"transactionHash\s+(0x[0-9a-fA-F]{64})", out)
            if match:
                config["last_tx"] = match.group(1)
                save_config(config)

        if capture: return final_res

        if out:
            print(humanize_value(apply_labels(out, config)))
        if err:
            if "execution reverted" in err.lower(): err = "❌ REVERT: " + err
            print(apply_labels(err, config), file=sys.stderr)
    except Exception as e:
        print(f"Error executing cast: {e}")
    return None

def run_recon(config):
    target = config.get("target")
    if not target:
        print("Error: Set target first.")
        return
    print(f"🔍 CONTRACT RECON: {target}\n" + "="*40)
    bal = run_cast(["balance", target], config, capture=True)
    print(f"Balance: {humanize_value(bal) if bal else 'Unknown'}")
    code = run_cast(["code", target], config, capture=True)
    print(f"Code: {'YES' if code and '0x' in code and len(code) > 2 else 'NO'}")
    proxy = inspect_proxy(config, quiet=True)
    print(f"Proxy: {'YES' if proxy else 'NO'}")
    print("="*40)

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
    inspect_proxy(config)

def run_mapping(config, slot, key):
    target = config.get("target")
    if not target: return
    try:
        slot_hex = f"0x{int(slot):x}" if not slot.startswith("0x") else slot
        key_hex = f"0x{key}" if not key.startswith("0x") else key
        padded_key = key_hex.replace("0x", "").zfill(64)
        padded_slot = slot_hex.replace("0x", "").zfill(64)
        combined = "0x" + padded_key + padded_slot
        computed_slot = run_cast(["keccak", combined], config, capture=True)
        if computed_slot:
            print(f"Computed Slot: {computed_slot}")
            run_cast(["st", computed_slot], config)
    except Exception as e: print(f"Error: {e}")

def run_snapshot(config, slots=None):
    target = config.get("target")
    if not target: return
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    slots = slots or [str(i) for i in range(10)]
    state = {str(slot): run_cast(["st", str(slot)], config, capture=True) for slot in slots}
    with open(os.path.join(SNAPSHOT_DIR, "last_state.json"), "w") as f:
        json.dump(state, f, indent=4)
    print(f"Snapshot saved ({len(state)} slots).")

def run_diff(config):
    path = os.path.join(SNAPSHOT_DIR, "last_state.json")
    if not os.path.exists(path): return
    with open(path, "r") as f: old_state = json.load(f)
    print("Comparing storage...\n" + "-"*40)
    for slot, old_val in old_state.items():
        new_val = run_cast(["st", slot], config, capture=True)
        if new_val != old_val:
            print(f"Slot {slot}: {old_val} -> {new_val}")
    print("-" * 40)

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

def run_workspace(config, args):
    paths = workspace_paths()
    action = args[0] if args else "init"
    if action != "init":
        print("Usage: lk workspace init")
        return
    for directory in [
        paths["root"],
        os.path.join(paths["root"], "abi"),
        os.path.join(paths["root"], "transactions"),
        os.path.join(paths["root"], "traces"),
        os.path.join(paths["root"], "storage"),
        os.path.join(paths["root"], "findings"),
        os.path.join(paths["root"], "history"),
        paths["matrix"],
    ]:
        os.makedirs(directory, exist_ok=True)
    if not os.path.exists(paths["notes"]):
        open(paths["notes"], "w").close()
    if not os.path.exists(paths["todos"]):
        open(paths["todos"], "w").close()
    with open(paths["config"], "w") as f:
        json.dump({"target": config.get("target"), "rpc": config.get("rpc"), "abi": config.get("abi_paths", {}).get(config.get("target"))}, f, indent=4)
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

def run_matrix(config, args):
    paths = workspace_paths()
    action = args[0] if args else "init"
    if action == "init":
        run_workspace(config, ["init"])
        for path, default in [(paths["matrix_actors"], {}), (paths["matrix_states"], {}), (paths["matrix_scenarios"], [])]:
            if not os.path.exists(path):
                write_json_file(path, default)
        print("Attacker-state matrix initialized.")
        return
    if not os.path.exists(paths["matrix_scenarios"]):
        print("Error: Run `lk matrix init` first.")
        return
    if action == "actor" and len(args) == 3:
        if not is_address(args[2]):
            print("Error: actor address must be a 20-byte hex address.")
            return
        actors = read_json_file(paths["matrix_actors"], {})
        actors[args[1]] = {"address": args[2], "label": args[1]}
        write_json_file(paths["matrix_actors"], actors)
        print(f"Matrix actor saved: {args[1]}")
        return
    if action == "add" and len(args) >= 5:
        scenario = {
            "name": args[1],
            "target": config.get("target"),
            "function": args[2],
            "actor": args[3],
            "expected": " ".join(args[4:]),
            "evidence": {
                "last_tx": config.get("last_tx"),
                "snapshot": os.path.join(SNAPSHOT_DIR, "last_state.json") if os.path.exists(os.path.join(SNAPSHOT_DIR, "last_state.json")) else None,
                "session": SESSION_FILE,
            },
            "created": datetime.now().isoformat(timespec="seconds"),
        }
        scenarios = read_json_file(paths["matrix_scenarios"], [])
        scenarios.append(scenario)
        write_json_file(paths["matrix_scenarios"], scenarios)
        print(f"Scenario saved: {scenario['name']}")
        return
    scenarios = read_json_file(paths["matrix_scenarios"], [])
    if action == "list":
        if not scenarios:
            print("No matrix scenarios yet.")
            return
        for scenario in scenarios:
            print(f"{scenario['name']}: {scenario['function']} as {scenario['actor']} -> {scenario['expected']}")
        return
    if action == "test" and len(args) == 2:
        scenario = next((item for item in scenarios if item["name"] == args[1]), None)
        if not scenario:
            print(f"Error: Scenario not found: {args[1]}")
            return
        actor = read_json_file(paths["matrix_actors"], {}).get(scenario["actor"], {}).get("address")
        actor_line = f"    address actor = {actor};\n" if actor else ""
        prank_line = "        vm.prank(actor);\n" if actor else ""
        function_call = scenario["function"]
        template = f'''pragma solidity ^0.8.0;
import "forge-std/Test.sol";

contract Matrix_{scenario["name"].replace("-", "_")} is Test {{
    address target = {scenario["target"] or "address(0)"};
{actor_line}
    function test_{scenario["name"].replace("-", "_")}() public {{
        // Arrange: establish the precondition described in the scenario.
{prank_line}        // Act: call {function_call}
        // TODO: encode arguments and invoke the target.
        // Assert: expected outcome: {scenario["expected"]}
    }}
}}
'''
        os.makedirs("test", exist_ok=True)
        filename = os.path.join("test", f"Matrix_{scenario['name']}.t.sol")
        with open(filename, "w") as f:
            f.write(template)
        print(f"Matrix test skeleton generated: {filename}")
        return
    print("Usage: lk matrix init | actor <name> <address> | add <name> <function> <actor> <expected> | list | test <name>")

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
    paths = workspace_paths()
    export_dir = os.path.join(os.getcwd(), "audit-report")
    os.makedirs(export_dir, exist_ok=True)
    report = {
        "target": config.get("target"),
        "rpc": config.get("rpc"),
        "last_tx": config.get("last_tx"),
        "abi": config.get("abi_paths", {}).get(config.get("target")),
    }
    with open(os.path.join(export_dir, "contract.json"), "w") as f:
        json.dump(report, f, indent=4)
    for source, destination in [(paths["notes"], "notes.md"), (paths["todos"], "TODO.md"), (paths["findings"], "findings.md"), (paths["session"], "session.log")]:
        if os.path.exists(source):
            with open(source, "r") as source_file, open(os.path.join(export_dir, destination), "w") as destination_file:
                destination_file.write(source_file.read())
    print(f"Audit report exported: {export_dir}")

def run_self_test():
    checks = [
        ("address validation", is_address("0x" + "1" * 40) and not is_address("0x" + "1" * 64)),
        ("slot validation", is_nonzero_slot("0x" + "1" + "0" * 63) and not is_nonzero_slot("not-hex")),
        ("ETH formatting", "1.0000 ETH" in humanize_value("1000000000000000000")),
    ]
    failed = [name for name, passed in checks if not passed]
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
    if failed:
        print(f"Self-test failed: {', '.join(failed)}")
        return 1
    print(f"Self-test passed ({len(checks)} checks).")
    return 0

def run_test_gen(config):
    if not os.path.exists(SESSION_FILE):
        print("Error: No session history found.")
        return
    with open(SESSION_FILE, "r") as f:
        lines = f.readlines()
    last_send = None
    for line in reversed(lines):
        if "CMD: cast send" in line:
            last_send = line.split("CMD: ")[1].strip()
            break
    if not last_send:
        print("Error: No send transaction found in session.")
        return
    try:
        parts = shlex.split(last_send)
        send_index = parts.index("send")
        target = parts[send_index + 1]
        func = parts[send_index + 2]
        positional = []
        value = "0"
        index = send_index + 3
        while index < len(parts):
            if parts[index] == "--value" and index + 1 < len(parts):
                value = parts[index + 1]
                index += 2
                continue
            if parts[index].startswith("--"):
                index += 2 if index + 1 < len(parts) and not parts[index + 1].startswith("--") else 1
                continue
            positional.append(parts[index])
            index += 1
        calldata_result = subprocess.run(
            ["cast", "calldata", func, *positional],
            capture_output=True,
            text=True,
            check=True,
        )
        calldata = calldata_result.stdout.strip().removeprefix("0x")
    except (ValueError, IndexError, subprocess.CalledProcessError) as error:
        print(f"Error generating test: {error}")
        return

    value_expression = value
    for unit in ["ether", "gwei", "wei"]:
        value_expression = value_expression.replace(unit, f" {unit}")
    template = """pragma solidity ^0.8.0;
import "forge-std/Test.sol";

contract ExploitTest is Test {{
    address target = {target};

    function testReproduce() public {{
        uint256 value = {value};
        vm.deal(address(this), value);
        (bool success, ) = target.call{{value: value}}(hex"{calldata}");
        assertTrue(success);
    }}
}}
"""
    final_test = template.format(target=target, value=value_expression, calldata=calldata)
    os.makedirs("test", exist_ok=True)
    filename = f"test/Exploit_{datetime.now().strftime('%H%M%S')}.t.sol"
    with open(filename, "w") as f:
        f.write(final_test)
    print(f"Exploit skeleton generated: {filename}")

def run_checklist(config, action=None, item=None):
    path = os.path.join(AUDIT_DIR, "CHECKLIST.md")
    default_list = [
        "[ ] Authorization: Check owner/roles",
        "[ ] Reentrancy: Check external calls",
        "[ ] Accounting: Check math/rounding",
        "[ ] Oracles: Check price staleness",
        "[ ] Proxies: Check implementation/admin"
    ]
    if not os.path.exists(path):
        with open(path, "w") as f: f.write("\n".join(default_list))
    with open(path, "r") as f: lines = f.readlines()
    if action == "done" and item:
        for i, line in enumerate(lines):
            if item in line:
                lines[i] = line.replace("[ ]", "[x]")
                break
        with open(path, "w") as f: f.writelines(lines)
        print(f"Marked '{item}' as done.")
    else:
        print("\n--- AUDIT CHECKLIST ---")
        print("".join(lines))

def print_help():
    help_text = """
LowkeyCast (lk) - The Lazy Auditor's Interface for Foundry

PLACEHOLDERS
    <addr>     A contract or wallet address, e.g. 0x1234...abcd
    <alias>    A short name you choose for an address, e.g. escrow
    <url>      An RPC endpoint, e.g. http://127.0.0.1:8545
    <name>     A profile name you choose, e.g. anvil or attacker
    <pk>       A private key; use a local test key, never a real wallet key
    <path>     A JSON ABI file path, e.g. ./out/EthEscrow.sol/Escrow.json
    <func>     A function name or signature, e.g. escrow or escrow(uint256)
    <args>     Values passed to the function, e.g. 1 or 0xabc...
    <slot>     A storage slot number or 32-byte slot hash, e.g. 0 or 0x...
    <key>      A mapping key, usually an address or uint256 value

--- STATE MANAGEMENT (Tier 1) ---
    lk target <addr>                 Set the current contract
        Example: lk target 0x5FbDB2315678afecb367f032d93F642f64180aa3
    lk target <alias> <addr>         Save an address with a friendly name
        Example: lk target escrow 0x5FbDB2315678afecb367f032d93F642f64180aa3
    lk use <alias>                   Switch to a saved address
        Example: lk use escrow
    lk target reset                  Clear the current contract
    lk rpc <url>                     Use an RPC endpoint for this session
        Example: lk rpc http://127.0.0.1:8545
    lk rpc set <name> <url>          Save and select an RPC profile
        Example: lk rpc set anvil http://127.0.0.1:8545
    lk rpc use <name>                Switch to a saved RPC profile
        Example: lk rpc use anvil
    lk rpc reset                     Clear the current RPC
    lk wallet set <name> <pk>        Save a signing key as a wallet profile
        Example: lk wallet set attacker 0xabc123...
    lk wallet use <name>             Select a saved wallet for sends
        Example: lk wallet use attacker
    lk actor <name>                  Use a saved wallet for sends
        Example: lk actor attacker
    lk actor reset                   Clear the active wallet

--- COGNITIVE LOAD REDUCTION (Tier 2) ---
    lk abi <path>                    Load an ABI so function names can be shortened
        Example: lk abi ./out/EthEscrow.sol/Escrow.json
    lk label <addr> <name>           Show a friendly label in command output
        Example: lk label 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 Deployer
    lk c <func> <args>               Read contract state with cast call
        Example: lk c balances(address) 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    lk s <func> <args>               Send a transaction with cast send
        Example: lk s createescrow(uint256,address) 0 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1ether
    lk abi                           Show the loaded ABI as a readable interface
        Example: lk abi
    lk functions                     List functions grouped by mutability
        Example: lk functions
    lk encode <func> <args>          Build calldata without sending a transaction
        Example: lk encode createescrow(uint256,address) 0 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
    lk sig <signature>               Show a function selector
        Example: lk sig balances(address)
    lk decode-error <data>           Decode a custom error using the loaded ABI
        Example: lk decode-error 0x...

--- AUDITOR INSPECTION (Tier 3) ---
    lk info                          Show target, chain, code, ABI, and proxy status
        Example: lk info
    lk chain                         Show chain ID, block, and RPC
        Example: lk chain
    lk recon                         Show balance, bytecode, and proxy status
        Example: lk recon
    lk proxy                         Check standard EIP-1967 proxy slots
        Example: lk proxy
    lk mapping <slot> <key>          Read a mapping value from its hashed slot
        Example: lk mapping 0 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    lk snapshot [slot ...]           Save default slots, or only listed slots
        Example: lk snapshot 0 1 0x7230...da722
    lk diff                          Compare storage with the last snapshot
        Example: lk diff

--- AUDIT OS (Tier 4) ---
    lk finding "<note>"             Record an observation in findings.md
        Example: lk finding "release does not update escrow status"
    lk test-gen                      Generate a Forge test from the last send
        Example: lk test-gen
    lk checklist                     View the audit checklist
        Example: lk checklist
    lk checklist done "<item>"       Mark a checklist item as complete
        Example: lk checklist done "Authorization"
    lk session                       Show the LowkeyCast command history
        Example: lk session
    lk session start                 Start a project audit session
        Example: lk session start
    lk session resume                Resume a project audit session
        Example: lk session resume
    lk workspace init                Create a local .audit workspace
        Example: lk workspace init
    lk note "<text>"                Save a note in the audit workspace
        Example: lk note "release does not update status"
    lk todo "<text>"                Add an audit TODO
        Example: lk todo "check recipient authorization"
    lk export                        Export the audit workspace as audit-report
        Example: lk export
    lk matrix init                   Create the attacker-state matrix
        Example: lk matrix init
    lk matrix actor <name> <addr>    Save a public actor for scenarios
        Example: lk matrix actor attacker 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
    lk matrix add <name> <func> <actor> <expected>
                                    Record a scenario and its evidence context
        Example: lk matrix add unauthorized-release release attacker "revert"
    lk matrix list                   List recorded scenarios
        Example: lk matrix list
    lk matrix test <name>            Generate a Forge test skeleton
        Example: lk matrix test unauthorized-release
    lk self-test                     Run local LowkeyCast regression checks
        Example: lk self-test
    lk receipt [tx]                  Show a transaction receipt
        Example: lk receipt
    lk trace [tx]                    Trace a transaction with Cast
        Example: lk trace
    lk logs [topic]                  Query logs for the current RPC
        Example: lk logs
    lk last [receipt|trace|logs]     Inspect the most recent send
        Example: lk last trace
    lk tx [hash]                     Inspect a transaction and decode its calldata
        Example: lk tx

--- SHORTCUTS ---
    lk st <slot>                     Read raw storage from the current target
        Example: lk st 0

QUICK START
    lk rpc set anvil http://127.0.0.1:8545
    lk rpc use anvil
    lk target escrow 0x5FbDB2315678afecb367f032d93F642f64180aa3
    lk use escrow
    lk abi ./out/EthEscrow.sol/Escrow.json
    lk c escrow 1
    """
    print(help_text)

def main():
    config = load_config()
    if len(sys.argv) < 2:
        print_help()
        return
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd in ["--help", "-h"]:
        print_help()
        return
    if cmd == "target":
        if not args: return
        if args[0] == "reset": config["target"] = None
        elif len(args) == 1: config["target"] = args[0]
        elif len(args) == 2: config["aliases"][args[0]] = args[1]; config["target"] = args[1]
        save_config(config)
    elif cmd == "use":
        if args and args[0] in config["aliases"]:
            config["target"] = config["aliases"][args[0]]; save_config(config)
    elif cmd == "rpc":
        if not args: return
        sub = args[0]
        if sub == "reset": config["rpc"] = None
        elif sub == "set" and len(args) == 3:
            config["rpc_profiles"][args[1]] = args[2]; config["rpc"] = args[2]
        elif sub == "use" and len(args) == 2:
            config["rpc"] = config["rpc_profiles"].get(args[1])
        elif len(args) == 1: config["rpc"] = args[0]
        save_config(config)
    elif cmd == "wallet":
        if len(args) == 3 and args[0] == "set":
            config["wallets"][args[1]] = args[2]; save_config(config)
        elif len(args) == 2 and args[0] == "use" and args[1] in config["wallets"]:
            config["actor"] = config["wallets"][args[1]]; save_config(config)
    elif cmd == "actor":
        if args and args[0] in config["wallets"]:
            config["actor"] = config["wallets"][args[0]]; save_config(config)
        elif args and args[0] == "reset":
            config["actor"] = None; save_config(config)
    elif cmd == "abi":
        if args:
            if not config.get("target"): return
            config["abi_paths"][config["target"]] = args[0]; save_config(config)
        else:
            run_abi(config)
    elif cmd == "functions": run_functions(config)
    elif cmd == "info": run_info(config)
    elif cmd == "chain": run_chain(config)
    elif cmd == "encode": run_encode(config, args)
    elif cmd == "sig": run_signature(args)
    elif cmd == "decode-error": run_decode_error(config, args)
    elif cmd == "tx": run_tx(config, args)
    elif cmd == "label":
        if len(args) == 2: config["labels"][args[0]] = args[1]; save_config(config)
    elif cmd == "recon": run_recon(config)
    elif cmd == "proxy": run_proxy(config)
    elif cmd == "mapping":
        if len(args) >= 2: run_mapping(config, args[0], args[1])
    elif cmd == "snapshot": run_snapshot(config, args)
    elif cmd == "diff": run_diff(config)
    elif cmd == "finding":
        if args: run_finding(config, " ".join(args))
    elif cmd == "test-gen":
        run_test_gen(config)
    elif cmd == "checklist":
        if len(args) >= 2 and args[0] == "done":
            run_checklist(config, "done", " ".join(args[1:]))
        else:
            run_checklist(config)
    elif cmd == "session":
        if args and args[0] in ["start", "resume"]:
            run_session_lifecycle(config, args[0])
        elif os.path.exists(SESSION_FILE):
            with open(SESSION_FILE, "r") as f: print(f.read())
        else:
            print("No session history yet.")
    elif cmd == "workspace": run_workspace(config, args)
    elif cmd == "note": run_note(" ".join(args))
    elif cmd == "todo": run_todo(" ".join(args))
    elif cmd == "export": run_export(config)
    elif cmd == "matrix": run_matrix(config, args)
    elif cmd == "self-test": raise SystemExit(run_self_test())
    elif cmd == "receipt": run_receipt(config, args[0] if args else None)
    elif cmd == "trace": run_trace(config, args)
    elif cmd == "logs": run_logs(config, args)
    elif cmd == "last": run_last(config, args)
    elif cmd in ["c", "s", "st"]:
        run_cast([cmd] + args, config)
    else:
        run_cast([cmd] + args, config)

if __name__ == "__main__":
    main()
