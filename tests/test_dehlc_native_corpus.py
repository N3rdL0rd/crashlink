"""Real HL/C reconstruction/lifting checks; no gitignored oracle dependency.

Build with tests/quality/build.py --native and set CRASHLINK_QUALITY_DIR.
CI requires artifacts; ordinary local suites may omit the native toolchain.
Only original ELF execution is claimed faithful, never reconstructed bytecode.
"""

import os
import platform
from pathlib import Path

import pytest

from crashtest.behavior import execute


@pytest.fixture(scope="module")
def corpus():
    directory = Path(os.environ.get("CRASHLINK_QUALITY_DIR", "tests/quality/build"))
    required = [directory / f"QualityNative-{tier}.elf" for tier in ("O0", "O2")]
    required.append(directory / "QualityNative.hl")
    available = platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64")
    if not available or not all(path.is_file() for path in required):
        message = (
            "Build shipped native fixtures with tests/quality/build.py --native and set CRASHLINK_QUALITY_DIR"
        )
        if os.environ.get("CRASHLINK_REQUIRE_QUALITY") == "1":
            pytest.fail(message)
        pytest.skip(message)
    return directory.resolve()


@pytest.mark.parametrize("tier", ["O0", "O2"])
def test_native_execution_reconstruction_and_lifting(corpus, tmp_path, tier):
    from crashlink.core import Fun, I32
    from crashlink.dehlc import code_from_bin
    from crashlink.dehlc.binary import HLCBinary, _resolve_plt_targets
    from crashlink.dehlc.lift import FunctionLifter

    native_path = corpus / f"QualityNative-{tier}.elf"
    native = execute([str(native_path)], str(tmp_path))
    assert native.error is None, native.error
    assert native.returncode == 0, native.stderr
    assert native.stdout.splitlines() == ["22", "5"]
    runtime = os.environ.get("HL_RUNTIME", "hl")
    bytecode = execute([runtime, str(corpus / "QualityNative.hl")], str(tmp_path))
    assert bytecode.error is None, bytecode.error
    assert bytecode.returncode == 0, bytecode.stderr
    assert bytecode.stdout == native.stdout
    assert bytecode.stderr == native.stderr

    recovered = code_from_bin(path=str(native_path))
    assert recovered.inspection_only
    recovered.get_test_obj("QualityNative")
    additions = [
        function
        for function in recovered.functions
        if recovered.full_func_name(function).lstrip("$") == "QualityNative.add"
    ]
    assert len(additions) == 1
    signature = additions[0].type.resolve(recovered).definition
    assert isinstance(signature, Fun)
    assert len(signature.args) == 2
    assert all(isinstance(arg.resolve(recovered).definition, I32) for arg in signature.args)
    assert isinstance(signature.ret.resolve(recovered).definition, I32)
    # The recoverable operation family and machine-code provenance must survive
    # both optimization tiers. This is structural coverage, not semantic proof.
    image = HLCBinary(path=str(native_path))
    symbol = image.symbol("QualityNative_add")
    assert symbol is not None
    lifter = FunctionLifter.for_binary(image, _resolve_plt_targets(image))
    operations = lifter.lift(symbol.value)
    assert "Add" in [operation.op for operation in operations]
    assert "Ret" in [operation.op for operation in operations]
    assert all(symbol.value <= operation.src_addr < symbol.value + symbol.size for operation in operations)
