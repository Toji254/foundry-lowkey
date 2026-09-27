"""Pluggable stateful walkthrough benchmark adapters.

The walkthrough core owns project modeling, transaction execution, evidence,
snapshot isolation, and rendering. Adapters contribute only protocol-specific
attack stories and the evidence rules used to assess those stories.
"""

from __future__ import annotations

from typing import Any, Protocol
import time

try:
    from . import walkthrough as core
except ImportError:
    import walkthrough as core

# The adapter may use core execution primitives, but never imports protocol logic back into core.
is_address = core.is_address
_cli_arg = core._cli_arg
_cmd = core._cmd
_runtime_code = core._runtime_code
_block_timestamp = core._block_timestamp
_send = core._send
_short_error = core._short_error


class WalkthroughBenchmarkAdapter(Protocol):
    adapter_id: str
    display_name: str

    def matches(
        self,
        model: core.ContractModel,
        models: list[core.ContractModel],
        config: dict[str, Any],
    ) -> bool: ...

    def prepare(
        self,
        root: Any,
        config: dict[str, Any],
        host: Any,
        rpc: str,
        actors: list[core.Actor],
        model: core.ContractModel,
        models: list[core.ContractModel],
    ) -> tuple[dict[str, Any] | None, str | None]: ...

    def build_stories(
        self,
        config: dict[str, Any],
        actors: list[core.Actor],
        target: dict[str, Any],
    ) -> list[core.WalkthroughStory]: ...
    def warmup_steps(
        self,
        config: dict[str, Any],
        actors: list[core.Actor],
        model: core.ContractModel,
        now: int,
    ) -> list[core.Step]: ...

    def workflow_steps(
        self,
        config: dict[str, Any],
        actors: list[core.Actor],
        model: core.ContractModel,
        target: str,
        now: int,
    ) -> list[core.Step]: ...
    def manages_child_prerequisites(self, model: core.ContractModel) -> bool: ...

    def observe_step(
        self,
        story: core.WalkthroughStory,
        step: core.Step,
        rpc: str,
        target: dict[str, Any],
        actors: list[core.Actor],
    ) -> None: ...

    def assess(
        self,
        story: core.WalkthroughStory,
        story_steps: list[core.Step],
        rpc: str,
        target: dict[str, Any],
        actors: list[core.Actor],
    ) -> None: ...


class ConfidencePoolBenchmarkAdapter:
    adapter_id = "confidence-pool"
    display_name = "ConfidencePool"

    def matches(self, model, models, config) -> bool:
        if str(model.name).lower() != "confidencepoolfactory":
            return False
        child_name = str(
            (config.get("lab_system") or {}).get("child_model") or ""
        ).lower()
        if child_name == "confidencepool":
            return True
        return (
            core._model_has_function(model, {"createPool"})
            and any(item.name.lower() == "confidencepool" for item in models)
        )

    def warmup_steps(self, config, actors, model, now):
        if str(model.name).lower() != "confidencepoolfactory":
            return []
        return _confidence_pool_factory_recipe(config, actors, now)[:2]

    def workflow_steps(self, config, actors, model, target, now):
        if str(model.name).lower() == "confidencepoolfactory":
            return _confidence_pool_factory_recipe(config, actors, now)
        if str(model.name).lower() == "confidencepool":
            return _confidence_pool_recipe(config, actors, pool_override=target, now=now)
        return []

    def manages_child_prerequisites(self, model):
        return str(model.name).lower() == "confidencepool"

    def observe_step(self, story, step, rpc, target, actors):
        pool = str(target.get("pool") or "")
        if story.story_id == "CP-01" and step.function.startswith("sweepUnclaimedBonus") and step.status == "success":
            bonus = _cast_read_simple(rpc, pool, "totalBonus()(uint256)")
            finality = _cast_read_simple(rpc, pool, "claimsStarted()(bool)")
            step.diagnostics.extend([
                f"CHECKPOINT totalBonus={bonus}",
                f"CHECKPOINT claimsStarted={finality}",
            ])
        elif story.story_id == "CP-02" and step.actor == (actors[2].name if len(actors) > 2 else "") and step.function.startswith("stake(uint256)"):
            end = _cast_read_simple(rpc, pool, "riskWindowEnd()(uint32)")
            step.diagnostics.append(f"CHECKPOINT riskWindowEnd={end}")

    def prepare(self, root, config, host, rpc, actors, model, models):
        pool, reason = _confidence_pool_live_pool(rpc, config, host, actors)
        if not pool:
            return None, reason or "no live ConfidencePool instance"
        system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
        return {
            "pool": pool,
            "token": system.get("stake_token"),
            "registry": system.get("attack_registry"),
            "moderator": system.get("moderator"),
        }, None

    def build_stories(self, config, actors, target):
        return _confidence_pool_stateful_stories(config, actors, str(target["pool"]))

    def assess(self, story, story_steps, rpc, target, actors):
        _assess_confidence_pool_story(
            story, story_steps, rpc, str(target["pool"]), actors
        )


def _cast_read_simple(
    rpc: str,
    address: str,
    signature: str,
    args: list[Any] | None = None,
) -> Any:
    if not is_address(address):
        return None
    command = ["cast", "call", address, signature]
    command.extend(_cli_arg(value) for value in (args or []))
    command += ["--rpc-url", rpc]
    code, out, err = _cmd(command, timeout=8)
    if code != 0:
        return None
    raw = " ".join((out or err or "").strip().split()).strip()
    if not raw:
        return None
    raw = raw.splitlines()[-1].strip()
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    try:
        return int(raw, 0)
    except ValueError:
        return raw



def _confidence_pool_live_pool(
    rpc: str,
    config: dict[str, Any],
    host: Any,
    actors: list[Actor],
) -> tuple[str | None, str | None]:
    """Recover an existing pool or create one from the prepared factory fixture."""
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    pool = system.get("pool")
    if is_address(pool) and _runtime_code(rpc, pool) not in {"", "0x"}:
        return str(pool), None

    factory = system.get("factory") or config.get("target")
    agreement = system.get("agreement")
    token = system.get("stake_token")
    if not all(is_address(x) for x in (factory, agreement, token)):
        missing = [
            name for name, value in (
                ("factory", factory), ("agreement", agreement), ("stake token", token)
            ) if not is_address(value)
        ]
        return None, "missing live lab dependency: " + ", ".join(missing)

    code, out, _err = _cmd([
        "cast", "call", str(factory),
        "getPoolsByAgreement(address)(address[])",
        str(agreement),
        "--rpc-url", rpc,
    ], timeout=8)
    candidates = re.findall(r"0x[0-9a-fA-F]{40}", out or "") if code == 0 else []
    for candidate in reversed(candidates):
        if _runtime_code(rpc, candidate) not in {"", "0x"}:
            system["pool"] = candidate
            config["lab_system"] = system
            if hasattr(host, "save_config"):
                try:
                    host.save_config(config)
                except Exception:
                    pass
            return candidate, None

    recipe = _confidence_pool_factory_recipe(config, actors, _block_timestamp(rpc))
    if len(recipe) < 2:
        return None, "factory recipe could not resolve agreement, token, and factory"
    create = recipe[1]
    actor = next((a for a in actors if a.name == create.actor), actors[0] if actors else None)
    if not actor:
        return None, "no local actor available for createPool"
    tx, output = _send(host, config, actor, create.address, create.function, create.args, create.value_wei)
    if not tx:
        return None, "createPool failed: " + _short_error(output)

    code, out, _err = _cmd([
        "cast", "call", str(factory),
        "getPoolsByAgreement(address)(address[])",
        str(agreement),
        "--rpc-url", rpc,
    ], timeout=8)
    candidates = re.findall(r"0x[0-9a-fA-F]{40}", out or "") if code == 0 else []
    for candidate in reversed(candidates):
        if _runtime_code(rpc, candidate) not in {"", "0x"}:
            system["pool"] = candidate
            config["lab_system"] = system
            if hasattr(host, "save_config"):
                try:
                    host.save_config(config)
                except Exception:
                    pass
            return candidate, None
    return None, "createPool was accepted but no live child pool could be resolved"



def _confidence_pool_stateful_stories(
    config: dict[str, Any],
    actors: list[Actor],
    pool: str,
) -> list[WalkthroughStory]:
    """Known ConfidencePool state-machine benchmarks; each story is isolated."""
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    token = system.get("stake_token")
    registry = system.get("attack_registry")
    moderator = system.get("moderator")
    if not all(is_address(x) for x in (pool, token, registry, moderator)) or len(actors) < 3:
        return []

    alice, bob, attacker = actors[0], actors[1], actors[2]
    treasury = actors[3] if len(actors) > 3 else bob
    max_uint = 2**256 - 1

    def call(actor: Actor, contract: str, address: str, function: str, args: list[Any] | None = None, reason: str = "") -> dict[str, Any]:
        return {
            "kind": "call", "actor": actor.name, "contract": contract, "address": address,
            "function": function, "args": list(args or []), "value": 0, "reason": reason,
        }

    def clock(seconds: int, reason: str) -> dict[str, Any]:
        return {"kind": "time", "actor": alice.name, "seconds": seconds, "reason": reason}

    return [
        WalkthroughStory(
            "CP-01",
            "Bonus sweep → moderator correction",
            "Can bonus leave the pool before the outcome becomes final?",
            [
                call(alice, "StakeToken", str(token), "approve(address,uint256)", [pool, max_uint]),
                call(bob, "StakeToken", str(token), "approve(address,uint256)", [pool, max_uint]),
                call(alice, "ConfidencePool", pool, "stake(uint256)", [100 * 10**18], "Alice stakes before risk is observed"),
                call(bob, "ConfidencePool", pool, "stake(uint256)", [50 * 10**18], "Bob stakes before risk is observed"),
                call(alice, "ConfidencePool", pool, "contributeBonus(uint256)", [40 * 10**18], "Sponsor seeds the bonus"),
                call(alice, "MockAttackRegistry", str(registry), "setAgreementState(uint8)", [6], "LAB CONTROL: jump directly to CORRUPTED"),
                call(alice, "ConfidencePool", pool, "pokeRiskWindow()", [], "Pool seals the terminal moment"),
                call(alice, "MockConfidencePoolModerator", str(moderator), "flagSurvived(address)", [pool], "Moderator initially treats the breach as out of scope"),
                call(attacker, "ConfidencePool", pool, "sweepUnclaimedBonus()", [], "Permissionless actor tries to sweep the bonus"),
                call(alice, "MockConfidencePoolModerator", str(moderator), "flagCorruptedGoodFaith(address,address)", [pool, attacker.address], "Moderator corrects the outcome and names the whitehat"),
                call(attacker, "ConfidencePool", pool, "claimAttackerBounty()", [], "Named attacker claims the bounty"),
            ],
        ),
        WalkthroughStory(
            "CP-02",
            "DAO rewind → late staker",
            "After a terminal moment is sealed, can a rewind reopen deposits and distort bonus ownership?",
            [
                call(alice, "StakeToken", str(token), "approve(address,uint256)", [pool, max_uint]),
                call(attacker, "StakeToken", str(token), "approve(address,uint256)", [pool, max_uint]),
                call(alice, "ConfidencePool", pool, "stake(uint256)", [100 * 10**18], "Alice becomes the early staker"),
                clock(200, "Move to the first risk observation"),
                call(alice, "MockAttackRegistry", str(registry), "setAgreementState(uint8)", [3], "LAB CONTROL: UNDER_ATTACK"),
                call(alice, "ConfidencePool", pool, "pokeRiskWindow()", [], "Seal riskWindowStart"),
                clock(800, "Let the protocol reach a terminal moment"),
                call(alice, "MockAttackRegistry", str(registry), "setAgreementState(uint8)", [5], "LAB CONTROL: PRODUCTION"),
                call(alice, "ConfidencePool", pool, "pokeRiskWindow()", [], "Seal riskWindowEnd"),
                call(alice, "MockAttackRegistry", str(registry), "setAgreementState(uint8)", [3], "LAB CONTROL: DAO rewind to UNDER_ATTACK"),
                clock(4000, "Wait after the sealed terminal timestamp"),
                call(attacker, "ConfidencePool", pool, "stake(uint256)", [10 * 10**18], "Attacker joins after riskWindowEnd"),
                call(alice, "ConfidencePool", pool, "contributeBonus(uint256)", [100 * 10**18], "Bonus is added during the rewind"),
                call(alice, "MockAttackRegistry", str(registry), "setAgreementState(uint8)", [5], "LAB CONTROL: return to PRODUCTION"),
                call(alice, "MockConfidencePoolModerator", str(moderator), "flagSurvived(address)", [pool], "Moderator resolves as SURVIVED"),
                call(alice, "ConfidencePool", pool, "claimSurvived()", [], "Alice claims her payout"),
                call(attacker, "ConfidencePool", pool, "claimSurvived()", [], "Attacker claims the late-staker payout"),
            ],
        ),
        WalkthroughStory(
            "CP-03",
            "ATTACK_REQUESTED rollback → scope mutation",
            "Does a reverting observation really make the scope lock one-way?",
            [
                call(alice, "StakeToken", str(token), "approve(address,uint256)", [pool, max_uint]),
                call(alice, "ConfidencePool", pool, "stake(uint256)", [1 * 10**18], "Alice deposits against the original scope"),
                call(alice, "MockAttackRegistry", str(registry), "setAgreementState(uint8)", [2], "LAB CONTROL: ATTACK_REQUESTED"),
                call(alice, "ConfidencePool", pool, "setPoolScope(address[])", [[bob.address, treasury.address]], "Owner triggers the reverting observation"),
                call(alice, "MockAttackRegistry", str(registry), "setAgreementState(uint8)", [0], "LAB CONTROL: rewind to NOT_DEPLOYED"),
                call(alice, "ConfidencePool", pool, "setPoolScope(address[])", [[bob.address, treasury.address]], "Owner retries scope replacement after rewind"),
            ],
        ),
        WalkthroughStory(
            "CP-04",
            "Permissionless poke rollback → scope mutation",
            "Can an outsider's reverting poke also leave the scope unlocked?",
            [
                call(alice, "StakeToken", str(token), "approve(address,uint256)", [pool, max_uint]),
                call(alice, "ConfidencePool", pool, "stake(uint256)", [1 * 10**18], "Alice deposits against the original scope"),
                call(alice, "MockAttackRegistry", str(registry), "setAgreementState(uint8)", [2], "LAB CONTROL: ATTACK_REQUESTED"),
                call(bob, "ConfidencePool", pool, "pokeRiskWindow()", [], "Bob triggers the permissionless reverting observation"),
                call(alice, "MockAttackRegistry", str(registry), "setAgreementState(uint8)", [0], "LAB CONTROL: rewind to NOT_DEPLOYED"),
                call(alice, "ConfidencePool", pool, "setPoolScope(address[])", [[bob.address, treasury.address]], "Owner retries scope replacement after rewind"),
            ],
        ),
    ]



def _assess_confidence_pool_story(
    story: WalkthroughStory,
    story_steps: list[Step],
    rpc: str,
    pool: str,
    actors: list[Actor],
) -> None:
    attacker = actors[2] if len(actors) > 2 else actors[-1]

    if story.story_id == "CP-01":
        sweep = next((s for s in story_steps if s.function.startswith("sweepUnclaimedBonus")), None)
        bounty = next((s for s in story_steps if s.function.startswith("claimAttackerBounty")), None)
        payout = (
            bounty.token_balance_after.get(attacker.address.lower(), 0)
            - bounty.token_balance_before.get(attacker.address.lower(), 0)
            if bounty else 0
        )
        sweep_checkpoint = " ".join(sweep.diagnostics) if sweep else ""
        if sweep and sweep.status == "success" and "CHECKPOINT totalBonus=0" in sweep_checkpoint and "CHECKPOINT claimsStarted=False" in sweep_checkpoint and bounty and bounty.status == "success" and payout == 150 * 10**18:
            story.signal = "CONFIRMED"
            story.evidence = [
                "the permissionless sweep moved the 40-token bonus before claimsStarted latched",
                "the later bounty paid 150 instead of the intended 190",
            ]
        else:
            story.signal = "NOT_REPRODUCED"
            story.evidence = ["The sweep → re-flag → reduced bounty chain was not reproduced."]

    elif story.story_id == "CP-02":
        late_stake = next((s for s in story_steps if s.actor == attacker.name and s.function.startswith("stake(uint256)")), None)
        late_bonus = next((s for s in story_steps if s.function.startswith("contributeBonus")), None)
        claim = next((s for s in story_steps if s.actor == attacker.name and s.function.startswith("claimSurvived")), None)
        end = _cast_read_simple(rpc, pool, "riskWindowEnd()(uint32)")
        payout = (
            claim.token_balance_after.get(attacker.address.lower(), 0)
            - claim.token_balance_before.get(attacker.address.lower(), 0)
            if claim else 0
        )
        bonus_share = max(0, payout - 10 * 10**18)
        percent = (bonus_share / (100 * 10**18) * 100) if bonus_share else 0.0
        if late_stake and late_stake.status == "success" and late_bonus and late_bonus.status == "success" and isinstance(end, int) and end != 0 and payout > 50 * 10**18:
            story.signal = "CONFIRMED"
            story.evidence = [
                "riskWindowEnd was sealed before the late stake, yet stake() succeeded",
                "contributeBonus() also succeeded during the rewind",
                f"late attacker payout was {payout / 10**18:.2f} tokens ({percent:.1f}% of the 100-token bonus)",
            ]
        else:
            story.signal = "NOT_REPRODUCED"
            story.evidence = ["The sealed-terminal rewind did not produce an accepted late deposit and distorted payout."]

    else:
        failed = next((s for s in story_steps if s.function.startswith("setPoolScope") and s.status != "success"), None)
        final_scope = next((s for s in reversed(story_steps) if s.function.startswith("setPoolScope") and s.status == "success"), None)
        locked = _cast_read_simple(rpc, pool, "scopeLocked()(bool)")
        original = _cast_read_simple(rpc, pool, "isAccountInScope(address)(bool)", [actors[0].address])
        replacement = _cast_read_simple(rpc, pool, "isAccountInScope(address)(bool)", [actors[3].address if len(actors) > 3 else actors[1].address])
        if failed and final_scope and locked is False and original is False and replacement is True:
            story.signal = "CONFIRMED"
            story.evidence = [
                "the ATTACK_REQUESTED observation reverted and did not persist scopeLocked",
                "after the rewind, the owner successfully replaced the original scope",
            ]
        else:
            story.signal = "NOT_REPRODUCED"
            story.evidence = ["The reverting observation did not produce a persisted scope mutation."]




_REGISTERED_BENCHMARK_ADAPTERS: list[type] = [ConfidencePoolBenchmarkAdapter]


def register_benchmark_adapter(adapter_type: type) -> type:
    """Register a benchmark adapter without changing the walkthrough core."""
    if adapter_type not in _REGISTERED_BENCHMARK_ADAPTERS:
        _REGISTERED_BENCHMARK_ADAPTERS.append(adapter_type)
    return adapter_type


def get_benchmark_adapter(
    model: core.ContractModel,
    models: list[core.ContractModel],
    config: dict[str, Any],
) -> WalkthroughBenchmarkAdapter | None:
    """Return the first registered adapter matching the current project."""
    for adapter_type in _REGISTERED_BENCHMARK_ADAPTERS:
        try:
            adapter = adapter_type()
        except TypeError:
            continue
        if adapter.matches(model, models, config):
            return adapter
    return None


def _confidence_pool_factory_recipe(
    config: dict[str, Any],
    actors: list[core.Actor],
    now: int,
) -> list[Step]:
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    factory = system.get("factory") or config.get("target")
    token = system.get("stake_token")
    agreement = system.get("agreement")
    if not factory or not token or not agreement:
        return []

    alice = actors[0] if actors else core.Actor("Alice", factory, 0)
    bob = actors[1] if len(actors) > 1 else alice
    expiry = now + 31 * 24 * 60 * 60
    scope = [alice.address, bob.address]

    return [
        core.Step(
            0, alice.name, "ConfidencePoolFactory", factory,
            "setStakeTokenAllowed(address,bool)", [token, True],
            reason="factory owner enables the stake token",
            inferred=False,
        ),
        core.Step(
            0, alice.name, "ConfidencePoolFactory", factory,
            "createPool(address,address,uint256,uint256,address,address[])",
            [agreement, token, expiry, 10**18, bob.address, scope],
            reason="factory validates dependencies, clones the pool, and initializes it",
            inferred=False,
        ),
    ]



def _confidence_pool_recipe(
    config: dict[str, Any],
    actors: list[core.Actor],
    pool_override: str | None = None,
    now: int | None = None,
) -> list[Step]:
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    pool = pool_override or system.get("pool") or config.get("target")
    token = system.get("stake_token")
    attack_registry = system.get("attack_registry")
    moderator = system.get("moderator")
    if not pool or not token or not attack_registry or not moderator:
        return []

    timestamp = int(now if now is not None else time.time())
    alice = actors[0] if actors else core.Actor("Alice", pool, 0)
    bob = actors[1] if len(actors) > 1 else alice
    amount = 10**18
    max_uint = 2**256 - 1

    return [
        core.Step(0, alice.name, "StakeToken", token, "approve(address,uint256)", [pool, max_uint],
             reason="Alice gives the pool permission to pull her stake tokens", inferred=False),
        core.Step(0, bob.name, "StakeToken", token, "approve(address,uint256)", [pool, max_uint],
             reason="Bob gives the pool permission to pull his stake tokens", inferred=False),
        core.Step(0, alice.name, "ConfidencePool", pool, "contributeBonus(uint256)", [amount],
             reason="Alice seeds the pool's bonus reserve", inferred=False),
        core.Step(0, alice.name, "ConfidencePool", pool, "stake(uint256)", [amount],
             reason="Alice deposits her stake", inferred=False),
        core.Step(0, bob.name, "ConfidencePool", pool, "stake(uint256)", [amount],
             reason="Bob deposits his stake", inferred=False),
        core.Step(0, alice.name, "MockAttackRegistry", attack_registry, "setAgreementState(uint8)", [3],
             reason="LAB CONTROL: agreement enters UNDER_ATTACK", inferred=False),
        core.Step(0, alice.name, "ConfidencePool", pool, "pokeRiskWindow()",
             [], reason="pool observes the external registry and seals the risk window", inferred=False),
        core.Step(0, alice.name, "MockAttackRegistry", attack_registry, "setAgreementState(uint8)", [5],
             reason="LAB CONTROL: agreement reaches PRODUCTION", inferred=False),
        core.Step(0, alice.name, "MockConfidencePoolModerator", moderator, "flagSurvived(address)", [pool],
             reason="moderator records the survived outcome", inferred=False),
        core.Step(0, alice.name, "ConfidencePool", pool, "claimSurvived()",
             [], reason="Alice claims principal plus her bonus share", inferred=False),
        core.Step(0, bob.name, "ConfidencePool", pool, "claimSurvived()",
             [], reason="Bob claims principal plus his bonus share", inferred=False),
    ]



