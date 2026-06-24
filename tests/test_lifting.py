"""Tests for lifting of opcodes added in the SafeCast/CallMethod/etc. batch.

Each test decompiles a small purpose-built Haxe sample and asserts that the
targeted opcode no longer surfaces as an ``UNLIFTED OPCODE`` marker and that the
expected high-level Haxe construct is produced.
"""

import re

from crashlink import Bytecode
from crashlink.core import Function, Opcode, Reg, tIndex
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


def _decompile_at(path: str, findex: int) -> str:
    code = Bytecode.from_path(path)
    return pseudo.pseudo(IRFunction(code, code.fn(findex)))


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


def test_gettype_gettid_lifted():
    # TypeIntrinsics.main calls hl.Type.getDynamic(v) (GetType) and reads
    # the resulting type's .kind (GetTID).
    out = _decompile_main("tests/haxe/TypeIntrinsics.hl")
    assert "GetType" not in _unlifted(out)
    assert "GetTID" not in _unlifted(out)
    assert "Type.getDynamic(" in out
    assert ".kind" in out


def test_setglobal_lifted():
    # Type.init (f@243) caches an Abstract handle in a global via
    # `untyped $allTypes(new hl.types.BytesMap())`, compiling to a GetGlobal
    # null-check followed by SetGlobal (mirroring hl/_std/Type.hx's actual
    # `get_allTypes`/`init` source: `untyped $allTypes()` reads, `untyped
    # $allTypes(value)` writes). The global has no source-level name to
    # recover, so a synthesized name is used, but the read/write call-arity
    # idiom is preserved so both sides agree and the null-check stays
    # meaningful.
    out = _decompile_at("tests/haxe/Clazz.hl", 243)
    assert "SetGlobal" not in _unlifted(out)
    assert "untyped $global15() != null" in out
    assert "untyped $global15(new hl.types.BytesMap());" in out


def test_native_map_alloc_lifted():
    # NativeMapAlloc.main directly constructs each of HL's raw map abstracts.
    # Their constructors compile to a no-arg native call (Call0 of
    # hballoc/hialloc/hoalloc); IRNativeMapAllocOptimizer should fold those
    # back into the original `new hl.types.XMap()` rather than leaving a
    # `Native.h*alloc()` call with a generic `Abstract`-typed local.
    out = _decompile_main("tests/haxe/NativeMapAlloc.hl")
    assert "new hl.types.BytesMap()" in out
    assert "new hl.types.IntMap()" in out
    assert "new hl.types.ObjectMap()" in out
    assert "Native.hballoc" not in out
    assert "Native.hialloc" not in out
    assert "Native.hoalloc" not in out
    assert "var b: hl.types.BytesMap" in out
    assert "var i: hl.types.IntMap" in out
    assert "var o: hl.types.ObjectMap" in out


def test_toufloat_lifted():
    # ToUFloatCase.main converts a UInt to Float via ToUFloat.
    out = _decompile_main("tests/haxe/ToUFloatCase.hl")
    assert "ToUFloat" not in _unlifted(out)


def test_setref_lifted():
    # SetrefCase.main uses hl.Ref, generating Ref/Setref/Unref.
    out = _decompile_main("tests/haxe/SetrefCase.hl")
    assert "Setref" not in _unlifted(out)


def test_nop_lifted():
    # Nop is rare in real HL output, so build a minimal in-memory function.
    code = Bytecode.create_empty(no_extra_types=True, version=5)
    func = Function()
    func.findex.value = 0
    func.type = tIndex(0)
    func.regs = [tIndex(0)]
    func.version = code.version.value
    func.has_debug = False

    nop = Opcode()
    nop.op = "Nop"
    nop.df = {}

    ret = Opcode()
    ret.op = "Ret"
    ret.df = {"ret": Reg(0)}

    func.ops = [nop, ret]
    code.functions.append(func)
    code.entrypoint.value = 0
    code.invalidate_findex_cache()

    out = pseudo.pseudo(IRFunction(code, func))
    assert "Nop" not in _unlifted(out)


def test_dynget_lifted():
    # $String.call_toString does a dynamic field read via DynGet.
    out = _decompile_named("tests/haxe/Clazz.hl", "String.call_toString")
    assert "DynGet" not in _unlifted(out)
    assert ".toString" in out
