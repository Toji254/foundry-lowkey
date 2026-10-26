#!/usr/bin/env python3
"""Live E2E: use project-owned tests to bootstrap a generic factory/proxy/clone lab."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def run(argv: list[str], cwd: Path, env: dict[str, str], timeout: int = 240) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed ({result.returncode}): {argv!r}\n"
            f"--- stdout ---\n{result.stdout[-10000:]}\n"
            f"--- stderr ---\n{result.stderr[-10000:]}"
        )
    return result


def main() -> int:
    forge = shutil.which("forge")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    if not forge:
        raise AssertionError("forge is unavailable on PATH")
    if not Path(lk).is_file() and not shutil.which(lk):
        raise AssertionError("installed lk executable is unavailable")
    runtime = Path.home() / ".lowkey" / "lk.py"
    if not runtime.is_file():
        raise AssertionError(f"installed Lowkey runtime is missing: {runtime}")

    env = os.environ.copy()
    # Force the native deployment script to be incomplete so this E2E proves
    # Lowkey can safely fall back to the project-owned setup test.
    env.pop("EXTERNAL_REGISTRY", None)

    with tempfile.TemporaryDirectory(prefix="lowkey-protocol-lab-e2e-") as temp:
        root = Path(temp).resolve()
        (root / "src").mkdir()
        (root / "test" / "unit").mkdir(parents=True)
        (root / "script").mkdir()
        (root / "lib").mkdir()

        # Reuse the Foundry dependency already installed by the surrounding CI
        # integration job. This keeps the E2E deterministic and avoids another
        # network fetch.
        existing_forge_std = Path("/tmp/lowkey-fixture/lib/forge-std")
        if not existing_forge_std.is_dir():
            raise AssertionError(f"CI forge-std dependency is unavailable: {existing_forge_std}")
        (root / "lib" / "forge-std").symlink_to(existing_forge_std, target_is_directory=True)

        (root / "foundry.toml").write_text(
            '[profile.default]\n'
            'src = "src"\n'
            'test = "test"\n'
            'script = "script"\n'
            'out = "out"\n'
            'libs = ["lib"]\n'
            'solc_version = "0.8.26"\n',
            encoding="utf-8",
        )
        (root / "src" / "PoolTemplate.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract PoolTemplate {\n"
            "    bool private initialized;\n"
            "    address public poolOwner;\n"
            "    constructor() { _disableInitializers(); }\n"
            "    function _disableInitializers() internal { initialized = true; }\n"
            "    function initialize(address owner_) external {\n"
            "        require(!initialized, \"initialized\");\n"
            "        initialized = true;\n"
            "        poolOwner = owner_;\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        (root / "src" / "PoolFactory.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "import {PoolTemplate} from \"./PoolTemplate.sol\";\n"
            "contract PoolFactory {\n"
            "    bool private initialized;\n"
            "    address public poolImplementation;\n"
            "    constructor() { _disableInitializers(); }\n"
            "    function _disableInitializers() internal { initialized = true; }\n"
            "    function initialize(address implementation_) external {\n"
            "        require(!initialized, \"initialized\");\n"
            "        initialized = true;\n"
            "        poolImplementation = implementation_;\n"
            "    }\n"
            "    function createPool() external returns (address pool) {\n"
            "        bytes memory code = abi.encodePacked(\n"
            "            hex\"3d602d80600a3d3981f3\",\n"
            "            hex\"363d3d373d3d3d363d73\",\n"
            "            poolImplementation,\n"
            "            hex\"5af43d82803e903d91602b57fd5bf3\"\n"
            "        );\n"
            "        assembly { pool := create(0, add(code, 0x20), mload(code)) }\n"
            "        require(pool != address(0), \"clone failed\");\n"
            "        PoolTemplate(pool).initialize(msg.sender);\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        (root / "test" / "helpers").mkdir(parents=True, exist_ok=True)
        (root / "test" / "helpers" / "LocalEIP1967Proxy.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract LocalEIP1967Proxy {\n"
            "    bytes32 private constant SLOT = "
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;\n"
            "    constructor(address impl, bytes memory data) {\n"
            "        bytes32 slot = SLOT;\n"
            "        assembly { sstore(slot, impl) }\n"
            "        (bool ok, bytes memory reason) = impl.delegatecall(data);\n"
            "        if (!ok) assembly { revert(add(reason, 0x20), mload(reason)) }\n"
            "    }\n"
            "    fallback() external payable {\n"
            "        bytes32 slot = SLOT;\n"
            "        assembly {\n"
            "            let impl := sload(slot)\n"
            "            calldatacopy(0, 0, calldatasize())\n"
            "            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)\n"
            "            returndatacopy(0, 0, returndatasize())\n"
            "            switch ok\n"
            "            case 0 { revert(0, returndatasize()) }\n"
            "            default { return(0, returndatasize()) }\n"
            "        }\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        (root / "test" / "unit" / "PoolFactoryTest.t.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "import {Test} from \"forge-std/Test.sol\";\n"
            "import {PoolTemplate} from \"../../src/PoolTemplate.sol\";\n"
            "import {PoolFactory} from \"../../src/PoolFactory.sol\";\n"
            "import {LocalEIP1967Proxy} from \"../helpers/LocalEIP1967Proxy.sol\";\n"
            "contract PoolFactoryTest is Test {\n"
            "    PoolTemplate internal poolImplementation;\n"
            "    PoolFactory internal factory;\n"
            "    function setUp() public {\n"
            "        poolImplementation = new PoolTemplate();\n"
            "        PoolFactory implementation = new PoolFactory();\n"
            "        LocalEIP1967Proxy proxy = new LocalEIP1967Proxy(\n"
            "            address(implementation),\n"
            "            abi.encodeCall(PoolFactory.initialize, (address(poolImplementation)))\n"
            "        );\n"
            "        factory = PoolFactory(address(proxy));\n"
            "    }\n"
            "    function test_createPool_success() external {\n"
            "        address pool = factory.createPool();\n"
            "        assertGt(pool.code.length, 0);\n"
            "        assertEq(PoolTemplate(pool).poolOwner(), address(this));\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        (root / "script" / "Deploy.s.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "import {Script} from \"forge-std/Script.sol\";\n"
            "import {PoolTemplate} from \"../src/PoolTemplate.sol\";\n"
            "contract Deploy is Script {\n"
            "    function run() external {\n"
            "        address requiredRegistry = vm.envAddress(\"EXTERNAL_REGISTRY\");\n"
            "        requiredRegistry;\n"
            "        vm.startBroadcast();\n"
            "        new PoolTemplate();\n"
            "        vm.stopBroadcast();\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        run([forge, "build"], root, env)
        lab = run([lk, "lab"], root, env, timeout=360)
        if "project deployment script skipped" not in lab.stdout.lower():
            raise AssertionError(f"Lowkey did not explain the missing project configuration:\n{lab.stdout}")
        if "promoted project test fixture" not in lab.stdout.lower():
            raise AssertionError(
                "Lowkey did not use the project's setup/test fixture when native deployment config was missing:\n"
                + lab.stdout[-12000:]
            )
        if "Target  : PoolFactory @" not in lab.stdout:
            raise AssertionError(f"Lowkey did not select the factory proxy as the protocol root:\n{lab.stdout[-12000:]}")

        generated_harness = root / "test" / "foundry" / ".lowkey" / "LowkeyAutoFixture_PoolFactoryTest.t.sol"
        if generated_harness.exists():
            raise AssertionError(
                "Lowkey left its one-shot fixture harness in the project test tree; "
                "normal forge test runs must not inherit lab bootstrap side effects."
            )

        targets = run([lk, "targets", "--all"], root, env)
        if "PoolFactory" not in targets.stdout or "PoolTemplate" not in targets.stdout:
            raise AssertionError(
                "The local protocol registry must expose the factory and its actual pool clone.\n"
                + targets.stdout[-12000:]
            )
        status = run([lk, "status"], root, env)
        if "Deployment: LIVE" not in status.stdout:
            raise AssertionError(f"The factory proxy is not recorded as a verified live target:\n{status.stdout}")
        print("PASS: a project with a missing native deployment variable used its own test setup,")
        print("      selected the factory proxy, and registered both the factory and created pool clone.")


if __name__ == "__main__":
    raise SystemExit(main())
