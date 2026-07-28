"""
hxsl shader recovery.

Heaps shaders (`hxsl.Shader` subclasses) are compiled *at macro time* into a
`ShaderData` AST and stored on the class as a serialized `static var SRC : String`
(plus `_MODULE`). The bytecode's normal opcodes only hold the generated uniform-
plumbing wrapper — the shader logic itself is that serialized string, sitting in
the string pool.

Heaps 1.x serializes `ShaderData` with the standard `haxe.Serializer` text format
(`oy4:name...y4:funs...`), so recovering a shader is: find these strings, run a
`haxe.Unserializer` port over them, and interpret the result as a shader. This
module does the first useful slice — find shaders and dump their *interface*
(name + declared vars: inputs, params, textures, outputs). The function bodies
(`funs`) decode too via the same unserializer; rendering them as readable shader
source is a follow-up (a port of `hxsl.Printer`).
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .core import Bytecode

# --- hxsl.Ast enum orderings (constructor index -> name) ---
#
# THESE ARE VERSION-SPECIFIC. hxsl's enums (especially TGlobal and Type) gain
# constructors between heaps releases, which shifts every later index. The tables
# below are for heaps **1.6.0** (the version Dead Cells ships — see sourcerer's
# version pinning). Decoding a shader from a different heaps build needs that
# build's Ast.hx enum orders.
_TYPE = [
    "TVoid",
    "TInt",
    "TBool",
    "TFloat",
    "TString",
    "TVec",
    "TMat3",
    "TMat4",
    "TMat3x4",
    "TBytes",
    "TSampler2D",
    "TSampler2DArray",
    "TSamplerCube",
    "TStruct",
    "TFun",
    "TArray",
    "TBuffer",
    "TChannel",
]
_VARKIND = ["Global", "Input", "Param", "Var", "Local", "Output", "Function"]
_VARQUAL = [
    "Const",
    "Private",
    "Nullable",
    "PerObject",
    "Name",
    "Shared",
    "Precision",
    "Range",
    "Ignore",
    "PerInstance",
    "Doc",
    "Borrow",
    "Sampler",
    "Final",
    "Flat",
    "NoVar",
]
_VECTYPE = ["VInt", "VFloat", "VBool"]
_TEXDIM = ["T1D", "T2D", "T3D", "TCube"]
_PREC = ["Low", "Medium", "High"]
_SIZEDECL = ["SConst", "SVar"]
_COMPONENT = ["x", "y", "z", "w"]
# Var kinds that carry a source-level metadata annotation. Only these four set a
# kind in hxsl's MacroParser; Var/Local/Output render as a bare `var` (there is no
# `@output`/`@local` source qualifier — outputs are the built-in `output`/pixelColor).
_KIND_ANNOT = {"Global": "@global", "Input": "@input", "Param": "@param"}
# Texture/channel read globals rendered as sampler methods: `tex.get(uv)`, not `texture(tex, uv)`.
_TEX_METHOD = {"texture": "get", "textureLod": "getLod", "channelRead": "get", "channelReadLod": "getLod"}
_CONST = ["CNull", "CBool", "CInt", "CFloat", "CString"]
_FUNKIND = ["Vertex", "Fragment", "Init", "Helper", "Main"]
# hxsl.TExprDef constructor order (Ast.hx).
_TEXPRDEF = [
    "TConst",
    "TVar",
    "TGlobal",
    "TParenthesis",
    "TBlock",
    "TBinop",
    "TUnop",
    "TVarDecl",
    "TCall",
    "TSwiz",
    "TIf",
    "TDiscard",
    "TReturn",
    "TFor",
    "TContinue",
    "TBreak",
    "TArray",
    "TArrayDecl",
    "TSwitch",
    "TWhile",
    "TMeta",
    "TField",
    "TSyntax",
]
# hxsl.TGlobal (GLSL builtins), heaps 1.6.0 order.
_TGLOBAL = [
    "radians",
    "degrees",
    "sin",
    "cos",
    "tan",
    "asin",
    "acos",
    "atan",
    "pow",
    "exp",
    "log",
    "exp2",
    "log2",
    "sqrt",
    "inversesqrt",
    "abs",
    "sign",
    "floor",
    "ceil",
    "fract",
    "mod",
    "min",
    "max",
    "clamp",
    "mix",
    "step",
    "smoothstep",
    "length",
    "distance",
    "dot",
    "cross",
    "normalize",
    "reflect",
    "texture",
    "textureLod",
    "int",
    "float",
    "bool",
    "vec2",
    "vec3",
    "vec4",
    "ivec2",
    "ivec3",
    "ivec4",
    "bvec2",
    "bvec3",
    "bvec4",
    "mat2",
    "mat3",
    "mat4",
    "mat3x4",
    "saturate",
    "pack",
    "unpack",
    "packNormal",
    "unpackNormal",
    "screenToUv",
    "uvToScreen",
    "dFdx",
    "dFdy",
    "fwidth",
    "channelRead",
    "channelReadLod",
    "trace",
    "vertexID",
    "instanceID",
]
# haxe.macro.Binop symbol per constructor index (Haxe 4). Index 20 (OpAssignOp) is special.
_BINOP = [
    "+",
    "*",
    "/",
    "-",
    "=",
    "==",
    "!=",
    ">",
    ">=",
    "<",
    "<=",
    "&",
    "|",
    "^",
    "&&",
    "||",
    "<<",
    ">>",
    ">>>",
    "%",
    None,
    "...",
    "=>",
    "in",
]
_UNOP = ["++", "--", "!", "-", "~"]


class HxEnum:
    """A deserialized Haxe enum value: type name + constructor index + args."""

    __slots__ = ("name", "index", "args")

    def __init__(self, name: str, index: int, args: List[Any]):
        self.name = name
        self.index = index
        self.args = args

    def __repr__(self) -> str:
        return f"HxEnum({self.name}#{self.index}{self.args})"


class HaxeUnserializer:
    """Minimal port of `haxe.Unserializer` — enough for serialized `ShaderData`.

    Supports null/bool/int/float, strings (`y`, with the `R` string cache),
    anonymous objects (`o`..`g`), arrays (`a`..`h`, `u` null-runs), enums
    (`j`), and the value cache (`r`)."""

    def __init__(self, s: str):
        self.s = s
        self.pos = 0
        self.scache: List[str] = []  # string cache (R references)
        self.cache: List[Any] = []  # value cache (r references)

    def _err(self, msg: str) -> "UnserializeError":
        ctx = self.s[max(0, self.pos - 20) : self.pos + 20]
        return UnserializeError(f"{msg} at {self.pos}: …{ctx}…")

    def _read_int(self) -> int:
        start = self.pos
        if self.pos < len(self.s) and self.s[self.pos] == "-":
            self.pos += 1
        while self.pos < len(self.s) and self.s[self.pos].isdigit():
            self.pos += 1
        return int(self.s[start : self.pos])

    def _read_float(self) -> float:
        # Values are opcode-separated, so a float is a maximal run of number chars.
        start = self.pos
        while self.pos < len(self.s) and self.s[self.pos] in "0123456789.eE+-":
            self.pos += 1
        return float(self.s[start : self.pos])

    def unserialize(self) -> Any:
        c = self.s[self.pos]
        self.pos += 1
        if c == "n":
            return None
        if c == "t":
            return True
        if c == "f":
            return False
        if c == "z":
            return 0
        if c == "i":
            return self._read_int()
        if c == "d":
            return self._read_float()
        if c == "k":
            return float("nan")
        if c == "m":
            return float("-inf")
        if c == "p":
            return float("inf")
        if c == "y":  # string: length ':' urlencoded
            length = self._read_int()
            assert self.s[self.pos] == ":"
            self.pos += 1
            raw = self.s[self.pos : self.pos + length]
            self.pos += length
            val = urllib.parse.unquote(raw)
            self.scache.append(val)
            return val
        if c == "R":  # string cache reference
            return self.scache[self._read_int()]
        if c == "r":  # value cache reference
            return self.cache[self._read_int()]
        if c == "o":  # anonymous object
            obj: Dict[str, Any] = {}
            self.cache.append(obj)
            while self.s[self.pos] != "g":
                key = self.unserialize()
                obj[key] = self.unserialize()
            self.pos += 1  # consume 'g'
            return obj
        if c == "a":  # array
            arr: List[Any] = []
            self.cache.append(arr)
            while self.s[self.pos] != "h":
                if self.s[self.pos] == "u":  # run of nulls
                    self.pos += 1
                    arr.extend([None] * self._read_int())
                else:
                    arr.append(self.unserialize())
            self.pos += 1  # consume 'h'
            return arr
        if c == "j":  # enum by index
            name = self.unserialize()
            assert self.s[self.pos] == ":"
            self.pos += 1
            index = self._read_int()
            assert self.s[self.pos] == ":"
            self.pos += 1
            nargs = self._read_int()
            # Haxe pushes the enum to the value cache *after* its args, so `r`
            # references stay aligned only if we do the same.
            args = [self.unserialize() for _ in range(nargs)]
            e = HxEnum(name, index, args)
            self.cache.append(e)
            return e
        raise self._err(f"unsupported serializer opcode {c!r}")


class UnserializeError(RuntimeError):
    pass


# --- shader interpretation -------------------------------------------------


@dataclass
class ShaderVar:
    name: str
    kind: str
    type: str
    qualifiers: List[str] = field(default_factory=list)


@dataclass
class Shader:
    name: str
    vars: List[ShaderVar]
    raw: Dict[str, Any]  # the full deserialized structure (name/vars/funs)


def _enum_name(e: Any, table: List[str]) -> str:
    if isinstance(e, HxEnum) and 0 <= e.index < len(table):
        return table[e.index]
    return "?"


def _type_str(t: Any) -> str:
    """Render an hxsl.Type enum as a short GLSL-ish name."""
    if not isinstance(t, HxEnum):
        return "?"
    name = _enum_name(t, _TYPE)
    if name == "TVec":
        size = t.args[0] if t.args else 0
        vt = _enum_name(t.args[1], _VECTYPE) if len(t.args) > 1 else "VFloat"
        base = {"VFloat": "Vec", "VInt": "IVec", "VBool": "BVec"}.get(vt, "Vec")
        return f"{base}{size}"
    if name == "TArray":
        elem = _type_str(t.args[0]) if t.args else "?"
        size = _size_str(t.args[1]) if len(t.args) > 1 else None
        return f"Array<{elem}, {size}>" if size else f"Array<{elem}>"
    if name == "TChannel":
        return "Channel"
    if name == "TStruct":
        fields = t.args[0] if t.args else []
        inner = ", ".join(
            f"var {c.get('name', '?')} : {_type_str(c.get('type'))}" for c in fields if isinstance(c, dict)
        )
        return "{ " + inner + " }"
    # Strip the leading T: TFloat->Float, TMat4->Mat4, TSampler2D->Sampler2D, …
    return name[1:] if name.startswith("T") else name


def _size_str(sd: Any) -> Optional[str]:
    """Render an hxsl.SizeDecl (array size): a constant or a size-variable's name."""
    if not isinstance(sd, HxEnum):
        return None
    name = _enum_name(sd, _SIZEDECL)
    if name == "SConst":
        return str(sd.args[0]) if sd.args else None
    if name == "SVar" and sd.args and isinstance(sd.args[0], dict):
        return sd.args[0].get("name")
    return None


def _qual_str(q: Any) -> str:
    """A var qualifier as source metadata that hxsl's MacroParser accepts, or "" to
    drop it (the `Name` qualifier is folded into the kind annotation by the caller;
    borrow/doc/sampler/final/flat/noVar aren't parseable in 1.6.0, so are omitted —
    losing them doesn't affect whether the shader compiles)."""
    if not isinstance(q, HxEnum):
        return ""
    name = _enum_name(q, _VARQUAL)
    args = q.args
    if name == "Const":
        return "const" + (f"({args[0]})" if args and args[0] else "")
    if name == "Precision":
        return (_enum_name(args[0], _PREC).lower() + "p") if args else "mediump"
    if name == "Range" and len(args) >= 2:
        return f"range({args[0]},{args[1]})"
    if name == "PerInstance":
        return f"perInstance({args[0]})" if args else "perInstance"
    return {
        "Private": "private",
        "Nullable": "nullable",
        "PerObject": "perObject",
        "Shared": "shared",
        "Ignore": "ignore",
    }.get(name, "")


def _interpret(raw: Dict[str, Any]) -> Shader:
    name = raw.get("name", "?")
    vars_out: List[ShaderVar] = []
    for v in raw.get("vars", []) or []:
        if not isinstance(v, dict):
            continue
        quals = [s for s in (_qual_str(q) for q in (v.get("qualifiers") or [])) if s]
        vars_out.append(
            ShaderVar(
                name=v.get("name", "?"),
                kind=_enum_name(v.get("kind"), _VARKIND),
                type=_type_str(v.get("type")),
                qualifiers=quals,
            )
        )
    return Shader(name=name, vars=vars_out, raw=raw)


# --- discovery -------------------------------------------------------------


def _looks_like_shader(s: str) -> bool:
    return s.startswith("oy4:name") and ":funs" in s[:400]


def find_shader_sources(code: Bytecode) -> List[str]:
    """Serialized shader-data strings in the image's string pool."""
    return [s for s in code.strings.value if _looks_like_shader(s)]


def parse_shader(serialized: str) -> Shader:
    """Deserialize one shader-data string into a Shader (name + vars)."""
    raw = HaxeUnserializer(serialized).unserialize()
    if not isinstance(raw, dict):
        raise UnserializeError("shader data did not deserialize to an object")
    return _interpret(raw)


def find_shaders(code: Bytecode) -> List[Shader]:
    """Recover every hxsl shader in the image (interface only for now)."""
    out: List[Shader] = []
    for s in find_shader_sources(code):
        try:
            out.append(parse_shader(s))
        except (UnserializeError, IndexError, AssertionError, ValueError):
            continue
    return out


def shader_header(shader: Shader) -> str:
    """A readable dump of a shader's interface (name + declared vars by kind)."""
    lines = [f"shader {shader.name} {{"]
    order = ["Input", "Param", "Global", "Var", "Local", "Output", "Function"]
    by_kind: Dict[str, List[ShaderVar]] = {}
    for v in shader.vars:
        by_kind.setdefault(v.kind, []).append(v)
    for kind in order + [k for k in by_kind if k not in order]:
        for v in by_kind.get(kind, []):
            quals = f"  @{', '.join(v.qualifiers)}" if v.qualifiers else ""
            lines.append(f"    {v.kind.lower():8} {v.name}: {v.type}{quals}")
    lines.append("}")
    return "\n".join(lines)


# --- full source rendering (port of hxsl.Printer) --------------------------


class _ShaderPrinter:
    """Renders a deserialized ShaderData back to readable hxsl source — a port of
    heaps' own `hxsl.Printer`."""

    def __init__(self, unit: str = "    ") -> None:
        self.buf: List[str] = []
        self.unit = unit  # one indentation level

    def add(self, s: str) -> None:
        self.buf.append(s)

    def render(self, raw: Dict[str, Any], base: str = "") -> str:
        """Render the shader body. Every top-level line is prefixed with `base`, and
        nested blocks indent from there, so the whole thing sits cleanly inside its
        enclosing `static var SRC = { … }`."""
        self.buf = []
        vars_ = raw.get("vars") or []
        for v in vars_:
            if isinstance(v, dict) and _enum_name(v.get("kind"), _VARKIND) == "Function":
                continue
            self.add(base)
            self._var(v, base)
            self.add(";\n")
        if vars_:
            self.add("\n")
        for f in raw.get("funs") or []:
            self.add(base)
            self._fun(f, base)
            self.add("\n\n")
        return "".join(self.buf)

    # -- vars --
    def _var_name(self, v: Dict[str, Any]) -> None:
        parent = v.get("parent")
        if isinstance(parent, dict):
            self._var_name(parent)
            self.add(".")
        self.add(v.get("name", "?"))

    def _var(self, v: Any, tabs: str) -> None:
        """A top-level shader var declaration (the interface): source qualifiers,
        the kind's metadata (`@param`/`@global`/… — bare `var` for Var/Local), then
        `var name : type`."""
        if not isinstance(v, dict):
            self.add("?")
            return
        # The Name qualifier isn't its own metadata — it's the string argument to the
        # kind (`@param("customName")`), so pull it out to fold in below.
        name_qual: Optional[str] = None
        for q in v.get("qualifiers") or []:
            if isinstance(q, HxEnum) and _enum_name(q, _VARQUAL) == "Name" and q.args:
                name_qual = q.args[0]
                continue
            s = _qual_str(q)
            if s:
                self.add("@" + s + " ")
        annot = _KIND_ANNOT.get(_enum_name(v.get("kind"), _VARKIND), "@var" if name_qual else "")
        if annot:
            self.add(f'{annot}("{name_qual}") ' if name_qual else f"{annot} ")
        self.add("var ")
        self._var_name(v)
        self.add(" : " + _type_str(v.get("type")))

    # -- functions --
    def _fun(self, f: Dict[str, Any], base: str) -> None:
        ref = f.get("ref") or {}
        self.add(f"function {ref.get('name', '?')}(")
        args = f.get("args") or []
        for i, a in enumerate(args):
            self.add(" " if i == 0 else ", ")
            # hxsl function params are `name : Type` — no `var`, no return type on the fn.
            self.add(f"{a.get('name', '?')} : {_type_str(a.get('type'))}" if isinstance(a, dict) else "?")
        if args:
            self.add(" ")
        self.add(") ")
        self._expr(f.get("expr"), base)

    # -- expressions --
    def _const(self, c: Any) -> None:
        if not isinstance(c, HxEnum):
            self.add("?")
            return
        name = _enum_name(c, _CONST)
        if name == "CNull":
            self.add("null")
        elif name == "CString":
            self.add('"' + str(c.args[0]) + '"')
        elif name == "CBool":
            self.add("true" if c.args and c.args[0] else "false")
        else:
            self.add(str(c.args[0]) if c.args else "?")

    def _call(self, target: Any, call_args: List[Any], tabs: str) -> None:
        # A texture/channel read prints as a method on the sampler — `tex.get(uv)` —
        # not the `texture(tex, uv)` global-call form, whose name collides with the var.
        if isinstance(target, dict) and isinstance(target.get("e"), HxEnum):
            tnode = target["e"]
            if _enum_name(tnode, _TEXPRDEF) == "TGlobal" and tnode.args:
                g = tnode.args[0]
                gname = _TGLOBAL[g.index] if isinstance(g, HxEnum) and 0 <= g.index < len(_TGLOBAL) else None
                if gname in _TEX_METHOD and call_args:
                    self._expr(call_args[0], tabs)
                    self.add("." + _TEX_METHOD[gname] + "(")
                    for i, arg in enumerate(call_args[1:]):
                        if i:
                            self.add(", ")
                        self._expr(arg, tabs)
                    self.add(")")
                    return
        self._expr(target, tabs)
        self.add("(")
        for i, arg in enumerate(call_args):
            if i:
                self.add(", ")
            self._expr(arg, tabs)
        self.add(")")

    def _binop(self, op: Any) -> str:
        if not isinstance(op, HxEnum):
            return "?"
        if op.index == 20 and op.args:  # OpAssignOp(sub)
            return self._binop(op.args[0]) + "="
        sym = _BINOP[op.index] if 0 <= op.index < len(_BINOP) else None
        return sym if sym else "?"

    def _expr(self, e: Any, tabs: str) -> None:
        if not isinstance(e, dict) or not isinstance(e.get("e"), HxEnum):
            self.add("?")
            return
        node = e["e"]
        kind = _enum_name(node, _TEXPRDEF)
        a = node.args

        if kind == "TConst":
            self._const(a[0])
        elif kind == "TVar":
            self._var_name(a[0]) if isinstance(a[0], dict) else self.add("?")
        elif kind == "TGlobal":
            g = a[0]
            self.add(_TGLOBAL[g.index] if isinstance(g, HxEnum) and 0 <= g.index < len(_TGLOBAL) else "?")
        elif kind == "TParenthesis":
            self.add("(")
            self._expr(a[0], tabs)
            self.add(")")
        elif kind == "TBlock":
            self.add("{")
            inner = tabs + self.unit
            for sub in a[0]:
                self.add("\n" + inner)
                self._expr(sub, inner)
                self.add(";")
            if a[0]:
                self.add("\n" + tabs)
            self.add("}")
        elif kind == "TBinop":
            self._expr(a[1], tabs)
            self.add(f" {self._binop(a[0])} ")
            self._expr(a[2], tabs)
        elif kind == "TUnop":
            op = a[0]
            self.add(_UNOP[op.index] if isinstance(op, HxEnum) and 0 <= op.index < len(_UNOP) else "?")
            self._expr(a[1], tabs)
        elif kind == "TVarDecl":
            # A function-body local: `var name = init` (type inferred), or
            # `var name : Type` when there's no initializer.
            v = a[0]
            self.add("var ")
            self._var_name(v) if isinstance(v, dict) else self.add("?")
            init = a[1] if len(a) > 1 else None
            if init is not None:
                self.add(" = ")
                self._expr(init, tabs)
            elif isinstance(v, dict):
                self.add(" : " + _type_str(v.get("type")))
        elif kind == "TCall":
            self._call(a[0], a[1], tabs)
        elif kind == "TSwiz":
            self._expr(a[0], tabs)
            self.add(".")
            for r in a[1]:
                self.add(_COMPONENT[r.index] if isinstance(r, HxEnum) and 0 <= r.index < 4 else "?")
        elif kind == "TIf":
            self.add("if( ")
            self._expr(a[0], tabs)
            self.add(" ) ")
            self._expr(a[1], tabs)
            if len(a) > 2 and a[2] is not None:
                self.add(" else ")
                self._expr(a[2], tabs)
        elif kind == "TReturn":
            self.add("return")
            if a and a[0] is not None:
                self.add(" ")
                self._expr(a[0], tabs)
        elif kind == "TDiscard":
            self.add("discard")
        elif kind == "TContinue":
            self.add("continue")
        elif kind == "TBreak":
            self.add("break")
        elif kind == "TFor":
            self.add("for( ")
            self._var_name(a[0]) if isinstance(a[0], dict) else self.add("?")
            self.add(" in ")
            self._expr(a[1], tabs)
            self.add(" ) ")
            self._expr(a[2], tabs)
        elif kind == "TArray":
            self._expr(a[0], tabs)
            self.add("[")
            self._expr(a[1], tabs)
            self.add("]")
        elif kind == "TArrayDecl":
            self.add("[")
            for i, sub in enumerate(a[0]):
                if i:
                    self.add(", ")
                self._expr(sub, tabs)
            self.add("]")
        elif kind == "TField":
            self._expr(a[0], tabs)
            self.add(".")
            self.add(str(a[1]))
        elif kind == "TWhile":
            normal = len(a) > 2 and a[2]
            if normal:
                self.add("while( ")
                self._expr(a[0], tabs)
                self.add(" ) {\n" + tabs + self.unit)
                self._expr(a[1], tabs + self.unit)
                self.add("\n" + tabs + "}")
            else:
                self.add("do {\n" + tabs + self.unit)
                self._expr(a[1], tabs + self.unit)
                self.add("\n" + tabs + "} while( ")
                self._expr(a[0], tabs)
                self.add(" )")
        elif kind == "TMeta":
            self.add("@" + str(a[0]))
            self.add(" ")
            self._expr(a[2], tabs)
        elif kind == "TSwitch":
            self.add("switch( ")
            self._expr(a[0], tabs)
            self.add(" ) {")
            inner = tabs + self.unit
            for c in a[1] or []:
                self.add("\n" + tabs + "case ")
                for i, val in enumerate(c.get("values") or []):
                    if i:
                        self.add(", ")
                    self._expr(val, tabs)
                self.add(":\n" + inner)
                self._expr(c.get("expr"), inner)
                self.add(";")
            if len(a) > 2 and a[2] is not None:
                self.add("\n" + tabs + "default:\n" + inner)
                self._expr(a[2], inner)
                self.add(";")
            self.add("\n" + tabs + "}")
        else:
            # TSyntax (raw GLSL/HLSL injection) — rare; leave a visible marker.
            self.add(f"/*{kind}*/")


def render_shader(shader: Shader) -> str:
    """Render a recovered shader back to hxsl Haxe source."""
    unit = "    "
    # Body sits two levels deep: inside the class, inside `static var SRC = { … }`.
    body = _ShaderPrinter(unit=unit).render(shader.raw, base=unit * 2).rstrip("\n") + "\n"
    class_name = shader.name.rsplit(".", 1)[-1]
    return f"class {class_name} extends hxsl.Shader {{\n{unit}static var SRC = {{\n{body}{unit}}};\n}}"


def shaders_by_name(code: Bytecode) -> Dict[str, "Shader"]:
    """All shaders keyed by their embedded name (e.g. `shader.Base2d`), cached on
    the code object so repeated decompiler lookups don't re-scan the string pool."""
    cached = getattr(code, "_hxsl_shaders_cache", None)
    if cached is None:
        cached = {s.name: s for s in find_shaders(code)}
        try:
            code._hxsl_shaders_cache = cached  # type: ignore[attr-defined]
        except (AttributeError, TypeError):
            pass
    return cached


def shader_for_class(code: Bytecode, class_name: str) -> Optional["Shader"]:
    """The recovered shader for a class name (destaticified), if it is one."""
    return shaders_by_name(code).get(class_name)
