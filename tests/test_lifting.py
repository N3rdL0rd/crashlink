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


def test_instance_method_rendered():
    # InstanceMethodCase.getValue should render as an instance method, not a
    # static function with an explicit receiver argument.
    out = _decompile_named("tests/haxe/InstanceMethodCase.hl", "InstanceMethodCase.getValue")
    assert "public function getValue(): Int" in out
    assert "arg0" not in out
    assert "return this.value" in out
    # The call site should use dot-call syntax.
    out_main = _decompile_main("tests/haxe/InstanceMethodCase.hl")
    assert "instance.getValue()" in out_main


def test_array_alloc_folded():
    # ArrayAllocCase exercises the std ArrayObj/ArrayDyn allocation wrappers.
    out_empty = _decompile_named("tests/haxe/ArrayAllocCase.hl", "ArrayAllocCase.makeEmpty")
    assert "StdFuncs.__std_" not in out_empty
    assert "[]" in out_empty
    out_new = _decompile_named("tests/haxe/ArrayAllocCase.hl", "ArrayAllocCase.makeNew")
    assert "StdFuncs.__std_" not in out_new
    assert "new Array<Dynamic>()" in out_new


def test_param_name_preserved_after_modification():
    # ParamRenameCase.absDouble reassigns its parameter; the decompiler should
    # keep the original parameter name instead of inventing a fresh varN.
    out = _decompile_named("tests/haxe/ParamRenameCase.hl", "ParamRenameCase.absDouble")
    assert "public static function absDouble(x: Int): Int" in out
    assert "var0" not in out
    assert "x = -x" in out
    assert "return x * 2" in out


def test_operator_precedence_parentheses():
    # OperatorPrecedenceCase verifies that shift/bitwise ops are parenthesised
    # when used as operands of higher-precedence arithmetic.
    out = _decompile_named("tests/haxe/OperatorPrecedenceCase.hl", "OperatorPrecedenceCase.combine")
    assert "(a >> 2) + b" in out
    out = _decompile_named("tests/haxe/OperatorPrecedenceCase.hl", "OperatorPrecedenceCase.maskAdd")
    assert "(a & 255) + b" in out


def test_array_indexing_and_length():
    # ArrayIndexingCase checks that getDyn/setDyn/get_length helpers are
    # rendered as normal array indexing and .length.
    out = _decompile_named("tests/haxe/ArrayIndexingCase.hl", "ArrayIndexingCase.sum")
    assert "for (i in 0...a.length)" in out
    assert "total += a[i]" in out
    out = _decompile_named("tests/haxe/ArrayIndexingCase.hl", "ArrayIndexingCase.swap")
    assert "a[i] = a[j]" in out
    assert "a[j] = tmp" in out
    assert "a.getDyn" not in out
    assert "a.setDyn" not in out
    assert "get_length" not in out


def test_loop_control_flow_structured():
    # LoopControlCase verifies that loops with both internal exits and normal
    # post-loop code are structured correctly: no spurious trailing breaks and
    # no missing post-loop returns.
    out = _decompile_named("tests/haxe/LoopControlCase.hl", "LoopControlCase.sumUntilNegative")
    assert "while (i < arr.length)" in out
    assert "return total" in out
    assert out.count("return total") == 2

    out = _decompile_named("tests/haxe/LoopControlCase.hl", "LoopControlCase.findLastPositive")
    assert "while (i >= 0)" in out
    assert "break" in out
    assert "return -1" in out


def test_loop_internal_return_no_trailing_dead_return():
    # String.findChar is a stdlib while(true) loop that only exits through
    # internal returns. The decompiler should not emit a dead trailing return.
    out = _decompile_at("tests/haxe/Clazz.hl", 4)
    assert "while (true)" in out
    assert "return p" in out
    # There should be no top-level statement after the closing brace of the loop.
    loop_end = out.rfind("}")
    trailing = out[loop_end + 1 :].strip()
    assert trailing == "", f"unexpected trailing code after loop: {trailing!r}"


def test_loop_exit_node_preserved_for_internal_return():
    # String.lastIndexOf has an internal return inside the loop and a normal
    # return after the loop. The post-loop return must not be dropped.
    out = _decompile_at("tests/haxe/Clazz.hl", 6)
    assert "while (pos >= 0)" in out
    assert "return pos" in out
    assert "return -1" in out


def test_temp_inliner_no_stale_reference_in_nested_branch():
    # String.substring's end clamping assigns a temp in one branch and uses it
    # in a nested comparison in the other branch. The decompiler must not leave
    # a stale reference to the temp after inlining.
    out = _decompile_at("tests/haxe/Clazz.hl", 9)
    assert "if (this.length <" in out
    assert "if (this.length < var5)" not in out
    assert "if (this.length < 0)" not in out


def test_throw_lifted():
    # ThrowCase.decode ends with a throw; the decompiler must emit `throw expr;`
    # rather than silently dropping the opcode.
    out = _decompile_named("tests/haxe/ThrowCase.hl", "ThrowCase.decode")
    assert "throw " in out
    assert "UNLIFTED OPCODE: Throw" not in out
