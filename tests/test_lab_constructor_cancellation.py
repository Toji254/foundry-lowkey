"""Nested constructor prompts must propagate q/cancel without deploying."""
import builtins
import importlib.util
import pathlib
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lowkeycast_constructor_cancel", ROOT / "lowkey" / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


def test_scalar_constructor_value_q_cancels_the_wizard():
    with patch.object(builtins, "input", return_value="q"):
        value, error = lk._deploy_artifact_locally(
            {}, "/tmp", "http://127.0.0.1:8545", ["0x" + "11" * 20],
            {"contractName": "Target", "bytecode": {"object": "0x6000"}}, [{"name": "owner", "type": "address"}],
        )
    assert value is None
    assert error == "local lab cancelled"


def test_array_count_cancel_propagates_as_cancellation():
    with patch.object(builtins, "input", return_value="cancel"):
        try:
            lk._lab_prompt_value(
                {}, [], "Target", {"name": "members", "type": "address[]"}
            )
        except lk.LabInputCancelled:
            return
    raise AssertionError("array count cancellation was not propagated")


def test_address_picker_q_cancels_instead_of_looping_or_selecting():
    with patch.object(builtins, "input", return_value="q"):
        try:
            lk._lab_prompt_address_selection(
                [{"name": "Known", "address": "0x" + "22" * 20,
                  "category": "contracts", "origin": "test"}],
                "integration",
            )
        except lk.LabInputCancelled:
            return
    raise AssertionError("address picker cancellation was not propagated")
