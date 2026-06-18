"""Tests for lifting of opcodes added in the SafeCast/CallMethod/etc. batch.

Each test decompiles a small purpose-built Haxe sample and asserts that the
targeted opcode no longer surfaces as an ``UNLIFTED OPCODE`` marker and that the
expected high-level Haxe construct is produced.
"""

import re

from crashlink import Bytecode
from crashlink.decomp import IRFunction
from crashlink import pseudo

UNLIFTED_RE = re.compile(r"UNLIFTED OPCODE: (\w+)")


def _decompile_main(path: str) -> str:
    code = Bytecode.from_path(path)
    return pseudo.pseudo(IRFunction(code, code.get_test_main()))


def _decompile_named(path: str, name_suffix: str) -> str:
    code = Bytecode.from_path(path)
    for f in code.functions:
        if code.full_func_name(f).endswith(name_suffix):
            return pseudo.pseudo(IRFunction(code, f))
    raise AssertionError(f"No function ending in {name_suffix!r} found in {path}")


def _unlifted(out: str) -> set:
    return set(UNLIFTED_RE.findall(out))


def test_safecast_unsafecast_lifted():
    out = _decompile_main("tests/haxe/CastOps.hl")
    assert "SafeCast" not in _unlifted(out)
    assert "UnsafeCast" not in _unlifted(out)
    # The safe cast feeds a String local; the unsafe cast feeds an Int local.
    assert "var s: String" in out
    assert "var i: Int" in out


def test_callthis_lifted():
    # MethodBase.compute calls this.helper(x) via CallThis.
    out = _decompile_named("tests/haxe/MethodCalls.hl", "MethodBase.compute")
    assert "CallThis" not in _unlifted(out)
    assert ".helper(" in out


def test_callmethod_lifted():
    # MethodCalls.main does a virtual dispatch obj.compute(...) via CallMethod.
    out = _decompile_main("tests/haxe/MethodCalls.hl")
    assert "CallMethod" not in _unlifted(out)
    assert ".compute(" in out


def test_instanceclosure_lifted():
    out = _decompile_main("tests/haxe/InstanceClosureCase.hl")
    assert "InstanceClosure" not in _unlifted(out)
    # The bound method reference renders as obj.greet.
    assert ".greet" in out


def test_getarray_lifted():
    out = _decompile_main("tests/haxe/GetArrayCase.hl")
    assert "GetArray" not in _unlifted(out)
    # Element read renders as indexed access.
    assert re.search(r"\w+\[\w+\]", out)
