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
    fn = code.fn(findex)
    assert isinstance(fn, Function)
    return pseudo.pseudo(IRFunction(code, fn))


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


def test_typed_array_literal_folded():
    # Arrays.hl exercises typed array literals ([1, 2, 3]).  The decompiler must
    # recover them instead of leaving the raw alloc_bytes/store/allocI32 lowering.
    out = _decompile_main("tests/haxe/Arrays.hl")
    assert "var a: Array<Int> = [1, 2, 3]" in out
    assert "var arr: Array<Int> = [1, 2, 3]" in out
    assert "Native.alloc_bytes" not in out
    assert "allocI32" not in out


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


def test_arraybytes_internal_call_rendered_as_instance_method():
    # ArrayBytes_Float.push calls the private __expand helper. It should render
    # as an instance call rather than a StdFuncs extern stub.
    out = _decompile_at("tests/haxe/Clazz.hl", 100)
    assert "this.__expand(len)" in out
    assert "StdFuncs.__std_" not in out


def test_arrayobj_alloc_factory_rendered_cleanly():
    # ArrayObj.concat returns alloc(arr); the anonymous factory must not become
    # a StdFuncs extern stub.
    out = _decompile_at("tests/haxe/Clazz.hl", 62)
    assert "return alloc(arr)" in out
    assert "StdFuncs.__std_" not in out


def test_parameter_shadowing_preserves_second_parameter_name():
    # ArrayObj.setDyn has a parameter `pos` that is shadowed by a UInt local
    # with the same debug name. The signature must keep the real second param
    # name `v`, not duplicate `pos`.
    out = _decompile_at("tests/haxe/Clazz.hl", 88)
    assert "public function setDyn(pos: Int, v: Dynamic): Void" in out
    assert "pos: Int, pos: Dynamic" not in out


def test_string_bytes_field_rendered():
    # String's private `.bytes` backing field must be visible when it is used as
    # an hl.Bytes value (rather than silently rendering the String itself).
    out = _decompile_at("tests/haxe/Clazz.hl", 11)
    assert "this.bytes" in out
    out = _decompile_at("tests/haxe/Clazz.hl", 13)
    assert "this.bytes" in out
    assert "s.bytes" in out
    out = _decompile_at("tests/haxe/Clazz.hl", 17)
    assert "return s.bytes" in out


def test_string_fromuc2_not_folded_prematurely():
    # String.fromUCS2 computes the length *after* creating the empty string, so
    # it must not be folded into a __alloc__ call with a stale length value.
    out = _decompile_at("tests/haxe/Clazz.hl", 18)
    assert "new String()" in out
    assert "Native.ucs2length(b, 0)" in out


def test_string_concat_shift_amount_constant():
    # String.__add__ lowers shifts as `var n = 1; ... = length << n`. The
    # decompiler should recover the immediate constant shift amount.
    out = _decompile_at("tests/haxe/Clazz.hl", 20)
    assert re.search(r"asize: Int = .*<< 1", out), f"missing constant shift in: {out!r}"
    assert "asize << var5" not in out
    assert "bsize << var5" not in out


def test_loop_carried_value_preserved_after_internal_break():
    # String.indexOf breaks out of its while(true) loop with the bytes_find
    # result in a loop-carried temporary. A previous inliner bug removed the
    # assignment and left `p = 0; return p;` instead of the real result.
    out = _decompile_at("tests/haxe/Clazz.hl", 5)
    assert "p = var9" in out
    assert "p = var9 >> 1" in out
    assert "p = 0 >> 1" not in out


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


def test_throw_lifted():
    # ThrowCase.decode ends with a throw; the decompiler must emit `throw expr;`
    # rather than silently dropping the opcode.
    out = _decompile_named("tests/haxe/ThrowCase.hl", "ThrowCase.decode")
    assert "throw " in out
    assert "UNLIFTED OPCODE: Throw" not in out


def test_stub_file_signatures_and_bodies():
    from crashlink import Bytecode
    from crashlink.pseudo import stub_file

    out = stub_file(Bytecode.from_path("tests/haxe/Clazz.hl"), "Clazz.hx")
    assert out is not None
    # class + field kept
    assert "class Clazz extends Parent" in out
    assert "public var b: Int;" in out
    # constructor calls super so it compiles
    assert "public function new()" in out and "super(" in out
    # void method is empty, non-void method stubs with a throw (type-checks)
    assert "function main(): Void" in out
    assert 'throw "stub' in out and "function method(): Int" in out
