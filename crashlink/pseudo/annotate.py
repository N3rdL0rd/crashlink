"""Tags the symbol tokens of rendered expressions (see `doc.mark`).

The renderer produces an expression's text; this looks at the IR node it came from,
which knows exactly what it refers to, and wraps the one token in that text that
names it. A token is only wrapped where it is found at the place the node's own
rendering puts it (the whole text, a trailing `.field`, a leading `new Name`, the
callee before the first argument list); a rendering that spells the node some other
way gets no span rather than a guessed one.
"""

from __future__ import annotations

import re
import weakref
from typing import Callable, Dict, Optional, Tuple

from ..core import Bytecode, Enum, Function, Native, Obj, Type
from ..decomp import IRFunction
from ..decomp.ir import IRCall, IRConst, IREnumConstruct, IRExpression, IRField, IRLocal, IRNew
from ..errors import MalformedBytecode
from .doc import mark, marking, marking_types
from .symbols import ExprType, SymbolRef
from .typetext import describe

_PATH_RX = re.compile(r"[\w$]+(?:\.[\w$]+)*")

_defn_ti_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[int, int]]] = {}


def _type_indices(code: Bytecode) -> Dict[int, int]:
    """id(type definition) → tindex."""
    cached = _defn_ti_cache.get(id(code))
    if cached is not None and cached[0]() is code:
        return cached[1]
    table = {id(t.definition): ti for ti, t in enumerate(code.types)}
    _defn_ti_cache[id(code)] = (weakref.ref(code), table)
    return table


def tindex_of(code: Bytecode, defn: object) -> Optional[int]:
    return _type_indices(code).get(id(defn))


def _chain(code: Bytecode, obj: Obj) -> "list[Obj]":
    """`obj` and its ancestors, nearest first."""
    chain: "list[Obj]" = []
    seen = set()
    cur: Optional[Obj] = obj
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        chain.append(cur)
        if cur.super.value < 0:
            break
        parent = cur.super.resolve(code).definition
        cur = parent if isinstance(parent, Obj) else None
    return chain


def member_ref(code: Bytecode, obj: Obj, name: str) -> Optional[SymbolRef]:
    """What `obj.name` refers to: the method with that name (nearest declaring class
    first) or the data field, identified the way the xref index does (declaring class
    and own slot)."""
    for cls in _chain(code, obj):
        for proto in cls.protos:
            try:
                if proto.name.resolve(code) == name:
                    return SymbolRef.function(proto.findex.value)
            except IndexError:
                # Corrupt bytecode: the proto's name index is out of range —
                # drop this candidate; a marker must never cost the text.
                continue
        for slot, fld in enumerate(cls.fields):
            try:
                if fld.name.resolve(code) != name:
                    continue
            except IndexError:
                # Corrupt bytecode: the field's name index is out of range —
                # drop this candidate; a marker must never cost the text.
                continue
            ti = tindex_of(code, cls)
            if ti is not None:
                return SymbolRef.field(ti, slot)
    return None


def _mark_first_call(text: str, names: "list[str]", ref: SymbolRef) -> str:
    """Tag the first `name(` at parenthesis depth 0 (the callee, before any argument)."""
    depth = 0
    quote = ""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif (
            depth == 0
            and (ch.isalpha() or ch in "_$")
            and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_$"))
        ):
            m = _PATH_RX.match(text, i)
            if m is not None:
                word = m.group(0)
                last = word.rsplit(".", 1)[-1]
                if last in names and text.startswith("(", m.end()):
                    at = m.end() - len(last)
                    return text[:at] + mark(last, ref) + text[m.end() :]
                i = m.end()
                continue
        i += 1
    return text


def annotate_expression(
    expr: IRExpression, text: str, code: Bytecode, ir_function: Optional[IRFunction]
) -> str:
    """`text`, the rendering of `expr`, with its symbol token tagged."""
    if not marking() or not text:
        return text

    if isinstance(expr, IRLocal):
        if ir_function is None or expr.name == "this" or text != expr.name:
            return text
        return mark(text, SymbolRef.local(ir_function.func.findex.value, expr.name))

    if isinstance(expr, IRConst):
        value = expr.value
        if not _PATH_RX.fullmatch(text):
            return text
        if isinstance(value, (Function, Native)):
            return mark(text, SymbolRef.function(value.findex.value))
        if isinstance(value, Type) and isinstance(value.definition, (Obj, Enum)):
            ti = tindex_of(code, value.definition)
            return mark(text, SymbolRef.type_(ti)) if ti is not None else text
        return text

    if isinstance(expr, IRField):
        defn = expr.target.get_type().definition
        if not isinstance(defn, Obj):
            return text
        if isinstance(expr.target, IRConst) and isinstance(expr.target.value, Type):
            owner = expr.target.value.definition
            if isinstance(owner, Obj):
                defn = owner
        ref = member_ref(code, defn, expr.field_name)
        name = expr.field_name
        if ref is None or not name:
            return text
        at = text.rfind("." + name)
        if at < 0 or text[at + 1 + len(name) :].strip(")") != "":
            return text
        start = at + 1
        return text[:start] + mark(name, ref) + text[start + len(name) :]

    if isinstance(expr, IRCall):
        target = expr.target
        if isinstance(target, IRConst) and isinstance(target.value, Function):
            func = target.value
            names = [code.partial_func_name(func) or ""]
            full = code.full_func_name(func) or ""
            names.append(full.rsplit(".", 1)[-1])
            return _mark_first_call(
                text, [n for n in names if n and n != "<none>"], SymbolRef.function(func.findex.value)
            )
        return text

    if isinstance(expr, IRNew):
        ti = expr.alloc_type_idx.value
        m = re.match(r"new ([\w$]+(?:\.[\w$]+)*)", text)
        if m is None:
            return text
        return text[: m.start(1)] + mark(m.group(1), SymbolRef.type_(ti)) + text[m.end(1) :]

    if isinstance(expr, IREnumConstruct):
        enum = expr.enum_type_idx.resolve(code).definition
        if not isinstance(enum, Enum):
            return text
        for cidx, construct in enumerate(enum.constructs):
            try:
                if construct.name.resolve(code) != expr.construct_name:
                    continue
            except IndexError:
                # Corrupt bytecode: the construct's name index is out of range —
                # drop this candidate; a marker must never cost the text.
                continue
            return _mark_first_call(
                text, [expr.construct_name], SymbolRef.enum_construct(expr.enum_type_idx.value, cidx)
            )
        return text

    return text


def annotate_type(expr: IRExpression, text: str, code: Bytecode) -> str:
    """`text`, the rendering of `expr`, tagged with the type the expression produces."""
    if not marking_types() or not text:
        return text
    return annotate_with_type(expr.get_type, text, code)


def annotate_with_type(get_type: Callable[[], Type], text: str, code: Bytecode) -> str:
    """Tag `text` with the type `get_type()` returns, when it can be computed."""
    try:
        typ = get_type()
    except (IndexError, ValueError, MalformedBytecode):
        # Corrupt bytecode: a type/name table index is out of range or a
        # reference has no context — drop the type tag, never the text. Anything
        # else is our own bug and must propagate.
        return text
    source, kind = describe(code, typ)
    return mark(text, ExprType(source, kind))
