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

# --- hxsl.Ast enum orderings (constructor index -> name), from heaps' Ast.hx ---
_TYPE = [
    "TVoid", "TInt", "TBool", "TFloat", "TString", "TVec", "TMat3", "TMat4", "TMat3x4",
    "TBytes", "TSampler", "TRWTexture", "TMat2", "TStruct", "TFun", "TArray", "TBuffer",
    "TChannel", "TTextureHandle", "TBufferHandle",
]
_VARKIND = ["Global", "Input", "Param", "Var", "Local", "Output", "Function"]
_VARQUAL = [
    "Const", "Private", "Nullable", "PerObject", "Name", "Shared", "Precision", "Range",
    "Ignore", "PerInstance", "Doc", "Borrow", "Sampler", "Final", "Flat", "NoVar",
]
_VECTYPE = ["VInt", "VFloat", "VBool"]
_TEXDIM = ["T1D", "T2D", "T3D", "TCube"]


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
        self.cache: List[Any] = []   # value cache (r references)

    def _err(self, msg: str) -> "UnserializeError":
        ctx = self.s[max(0, self.pos - 20):self.pos + 20]
        return UnserializeError(f"{msg} at {self.pos}: …{ctx}…")

    def _read_int(self) -> int:
        start = self.pos
        if self.pos < len(self.s) and self.s[self.pos] == "-":
            self.pos += 1
        while self.pos < len(self.s) and self.s[self.pos].isdigit():
            self.pos += 1
        return int(self.s[start:self.pos])

    def _read_float(self) -> float:
        # Values are opcode-separated, so a float is a maximal run of number chars.
        start = self.pos
        while self.pos < len(self.s) and self.s[self.pos] in "0123456789.eE+-":
            self.pos += 1
        return float(self.s[start:self.pos])

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
            raw = self.s[self.pos:self.pos + length]
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
    if name == "TSampler":
        dim = _enum_name(t.args[0], _TEXDIM) if t.args else "?"
        arr = "Array" if len(t.args) > 1 and t.args[1] else ""
        return f"Sampler{dim[1:]}{arr}"  # T2D -> Sampler2D
    if name == "TArray":
        return f"Array<{_type_str(t.args[0])}>" if t.args else "Array"
    if name == "TChannel":
        return "Channel"
    if name == "TStruct":
        return "Struct"
    # strip leading T for the simple scalars/matrices (TFloat->Float, TMat4->Mat4)
    return name[1:] if name.startswith("T") else name


def _qual_str(q: Any) -> str:
    if not isinstance(q, HxEnum):
        return "?"
    name = _enum_name(q, _VARQUAL)
    if name in ("Name", "Borrow", "Sampler", "Doc") and q.args:
        return f"{name}({q.args[0]})"
    if name == "Const" and q.args and q.args[0]:
        return f"Const({q.args[0]})"
    return name


def _interpret(raw: Dict[str, Any]) -> Shader:
    name = raw.get("name", "?")
    vars_out: List[ShaderVar] = []
    for v in raw.get("vars", []) or []:
        if not isinstance(v, dict):
            continue
        quals = [_qual_str(q) for q in (v.get("qualifiers") or [])]
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
