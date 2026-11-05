"""Normalizer for Foundry Vm.startStateDiffRecording() artifacts."""
from __future__ import annotations
import hashlib, json, re

KIND_NAMES = {0:"Call",1:"DelegateCall",2:"CallCode",3:"StaticCall",4:"Create",
              5:"SelfDestruct",6:"Resume",7:"Balance",8:"Extcodesize",9:"Extcodehash",10:"Extcodecopy"}
CALL_KINDS = {"Call","DelegateCall","CallCode","StaticCall"}
TRACE_KINDS = CALL_KINDS | {"Create","Create2"}

try:
    from .trace_evidence import TRACE_SCHEMA_VERSION, build_trace_event
except ImportError:
    from lowkey.trace_evidence import TRACE_SCHEMA_VERSION, build_trace_event

def _address(value, label):
    if not isinstance(value,str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}",value):
        raise ValueError(f"Forge state diff {label} must be a 20-byte address.")
    return value.lower()
def _hexword(value,label):
    if isinstance(value,int):
        if value<0: raise ValueError(f"Forge state diff {label} cannot be negative.")
        return "0x"+format(value,"064x")
    if not isinstance(value,str): raise ValueError(f"Forge state diff {label} must be hex or an integer.")
    raw=value.lower().removeprefix("0x")
    if not raw or not re.fullmatch(r"[0-9a-f]+",raw) or len(raw)>64:
        raise ValueError(f"Forge state diff {label} must fit bytes32.")
    return "0x"+raw.rjust(64,"0")
def _uint(value,label):
    if isinstance(value,int) and value>=0: return value
    if isinstance(value,str):
        try: return int(value,16) if value.lower().startswith("0x") else int(value)
        except ValueError: pass
    raise ValueError(f"Forge state diff {label} must be a nonnegative integer.")

def _unwrap_named_json_object(value, label):
    """Unwrap the one-key object wrapper returned by Vm.serialize* objectKey."""
    if not isinstance(value,dict):
        raise ValueError(f"Forge state diff {label} must be a JSON object.")
    if len(value)==1:
        only=next(iter(value.values()))
        if isinstance(only,dict):
            return only
    return value


def normalize_forge_state_diff(payload, *, expected_target=None):
    if not isinstance(payload,dict):
        raise ValueError("Expected a Lowkey forge-state-diff JSON artifact.")
    # The recorder uses unique objectKey values to assemble nested JSON.
    # Foundry's serialize* return value includes that key as a wrapper.
    if payload.get("backend")!="forge-state-diff":
        candidates=[
            value for value in payload.values()
            if isinstance(value,dict) and value.get("backend")=="forge-state-diff"
        ]
        if len(candidates)==1:
            payload=candidates[0]
    if payload.get("backend")!="forge-state-diff":
        raise ValueError("Expected a Lowkey forge-state-diff JSON artifact.")
    if payload.get("schema_version")!=1: raise ValueError("Unsupported Forge state-diff artifact schema_version.")
    chain_id=_uint(payload.get("chain_id"),"chain_id")
    block_number=_uint(payload.get("block_number"),"block_number")
    target=_address(payload.get("target_address"),"target_address")
    code_hash=str(payload.get("target_code_hash") or "").lower()
    if not re.fullmatch(r"0x[0-9a-f]{64}",code_hash):
        raise ValueError("Forge state diff must include target_code_hash (keccak256 of target runtime code).")
    fork_parent_hash=str(payload.get("fork_parent_hash") or "").lower()
    if not re.fullmatch(r"0x[0-9a-f]{64}",fork_parent_hash):
        raise ValueError("Forge state diff must include a 32-byte fork_parent_hash captured before the measured call.")
    if expected_target and target!=_address(expected_target,"expected_target"):
        raise ValueError("Forge state-diff target_address does not match the control manifest.")
    raw_accesses=payload.get("accesses")
    if not isinstance(raw_accesses,list) or not raw_accesses:
        raise ValueError("Forge state-diff artifact contains no account accesses.")
    calls=[]; trace_events=[]; storage_accesses=[]; accounts={}
    for index,raw in enumerate(raw_accesses):
        raw=_unwrap_named_json_object(raw,f"accesses[{index}]")
        if not isinstance(raw,dict): raise ValueError(f"Forge account access #{index} must be an object.")
        kind_raw=raw.get("kind")
        kind=KIND_NAMES.get(kind_raw,str(kind_raw)) if isinstance(kind_raw,int) else str(kind_raw)
        account=_address(raw.get("account"),f"accesses[{index}].account")
        accessor=_address(raw.get("accessor"),f"accesses[{index}].accessor")
        depth=_uint(raw.get("depth"),f"accesses[{index}].depth")
        value=_uint(raw.get("value",0),f"accesses[{index}].value")
        reverted=bool(raw.get("reverted",False))
        data=str(raw.get("data") or "0x").lower()
        if not re.fullmatch(r"0x(?:[0-9a-f]{2})*",data):
            raise ValueError(f"Forge account access #{index} has invalid calldata bytes.")
        old_balance=_uint(raw.get("old_balance",0),f"accesses[{index}].old_balance")
        new_balance=_uint(raw.get("new_balance",0),f"accesses[{index}].new_balance")
        old_nonce=_uint(raw.get("old_nonce",0),f"accesses[{index}].old_nonce")
        new_nonce=_uint(raw.get("new_nonce",0),f"accesses[{index}].new_nonce")
        code_hash=str(raw.get("code_hash") or "").lower()
        if code_hash and not re.fullmatch(r"0x[0-9a-f]{64}",code_hash):
            raise ValueError(f"Forge account access #{index} has invalid code_hash.")
        account_state=accounts.setdefault(account,{"address":account,"balance_wei":old_balance,
            "nonce":old_nonce,"balance_after_wei":old_balance,"nonce_after":old_nonce,
            "code_hash":code_hash or None,"storage":{}})
        if not reverted:
            account_state["balance_after_wei"]=new_balance
            account_state["nonce_after"]=new_nonce
        slot_rows=raw.get("storage_accesses") or []
        if not isinstance(slot_rows,list): raise ValueError("storage_accesses must be an array.")
        event_storage=[]
        for storage_index,row in enumerate(slot_rows):
            row=_unwrap_named_json_object(row,f"accesses[{index}].storage_accesses[{storage_index}]")
            if not isinstance(row,dict): raise ValueError("Forge StorageAccess entries must be objects.")
            slot=_hexword(row.get("slot"),"storage slot")
            previous=_hexword(row.get("previous_value"),"storage previous_value")
            new_value=_hexword(row.get("new_value"),"storage new_value")
            storage_account=_address(row.get("account") or account,"storage account")
            is_write=bool(row.get("is_write",False))
            storage_reverted=bool(row.get("reverted",reverted))
            storage_item={"access_index":index,"account":storage_account,"slot":slot,
                "previous_value":previous,"new_value":new_value,"is_write":is_write,"reverted":storage_reverted}
            storage_accesses.append(storage_item)
            event_storage.append({key:value for key,value in storage_item.items() if key!="access_index"})
            accounts.setdefault(storage_account,{"address":storage_account,"balance_wei":None,"nonce":None,
                "balance_after_wei":None,"nonce_after":None,"code_hash":None,"storage":{}})
            accounts[storage_account]["storage"].setdefault(slot,previous)
        if kind in CALL_KINDS:
            calls.append({"index":index,"depth":depth,"type":kind.upper(),"from":accessor,"to":account,
                          "input":data,"value":hex(value),"error":"reverted" if reverted else "",
                          "reverted":reverted,"storage_access_count":len(slot_rows)})
        if kind in TRACE_KINDS:
            trace_events.append(build_trace_event(
                index=index,kind=kind,accessor=accessor,account=account,depth=depth,
                value=value,reverted=reverted,input_data=data,storage=event_storage,
                source_backend="forge-state-diff",error="reverted" if reverted else None,
            ))

    prestate=[]
    balance_deltas=[]
    for row in accounts.values():
        if row.get("balance_wei") is not None and row.get("balance_after_wei") is not None:
            balance_deltas.append({"address":row["address"],"before_wei":row["balance_wei"],
                "after_wei":row["balance_after_wei"],"delta_wei":row["balance_after_wei"]-row["balance_wei"]})
        snapshot={key:row.get(key) for key in ("address","balance_wei","nonce","code_hash")}
        snapshot["storage"]=[{"slot":k,"value":v} for k,v in sorted(row["storage"].items())]
        prestate.append(snapshot)
    prestate.sort(key=lambda row:row["address"])
    balance_deltas.sort(key=lambda row:row["address"])
    if not any(row["to"]==target for row in calls): raise ValueError("Forge state-diff trace never called the manifest target.")
    entry=next(row for row in calls if row["to"]==target)
    entry_payload={"chain_id":str(chain_id),"from":entry["from"],"to":entry["to"],
        "input":entry["input"],"value_wei":_uint(entry["value"],"entry value")}
    entry_digest=hashlib.sha256(json.dumps(entry_payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    prestate_digest=hashlib.sha256(json.dumps(prestate,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {"backend":"forge-state-diff","trace_schema_version":TRACE_SCHEMA_VERSION,
        "chain_id":chain_id,"block_number":block_number,
        "target_address":target,"target_code_hash":code_hash,"fork_parent_hash":fork_parent_hash,
        "calls":calls,"trace_events":trace_events,"storage_accesses":storage_accesses,
        "prestate":prestate,"prestate_sha256":prestate_digest,"balance_deltas":balance_deltas,
        "raw_account_accesses":raw_accesses,"entry_call":entry_payload,
        "entry_call_sha256":entry_digest,
        "trace_semantics":"Ordered Forge account-access contexts with calldata and storage accesses; no RPC transaction receipt or EOA envelope.",
        "limitations":["Forge state-diff evidence is test-execution evidence, not a mined EOA transaction.",
            "Gas and effective gas price are not inferred from AccountAccess records.",
            "Caller impersonation, synthetic funding, mocks and dependency mutation must be reported by the harness fidelity scan."]}
