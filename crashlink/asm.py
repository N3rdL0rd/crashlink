"""
The `.hlasm` notation: a text form of HashLink bytecode that can express every part of an image.

`AsmFile` assembles `.hlasm` source into a `Bytecode`; `to_hlasm` writes any `Bytecode` out as
`.hlasm`. Assembling the output of `to_hlasm` reproduces the original image byte for byte. See
docs/content/docs/hlasm.md for the syntax.
"""

from __future__ import annotations

import re
import struct
from abc import ABC
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple, Union, cast

from .core import (
    Abstract,
    Binding,
    Bytecode,
    BytesBlock,
    Constant,
    DebugInfo,
    Enum,
    EnumConstruct,
    Field,
    Fun,
    Function,
    InlineBool,
    Method,
    Native,
    Null,
    Obj,
    Opcode,
    Packed,
    Proto,
    Ref,
    Reg,
    Regs,
    SerialisableF64,
    Struct,
    Type,
    TypeDef,
    VarInt,
    VarInts,
    Virtual,
    Void,
    bytesRef,
    fieldRef,
    fileRef,
    fIndex,
    floatRef,
    gIndex,
    intRef,
    strRef,
    tIndex,
)
from .opcodes import opcodes


class AsmError(SyntaxError):
    """A problem in `.hlasm` source, reported with the line it was found on."""

    def __init__(self, message: str, line: int = 0) -> None:
        super().__init__(f"line {line}: {message}" if line else message)
        self.line = line


@dataclass
class AsmValue(ABC):
    value: Any
    line: int = field(default=0, kw_only=True)


class AsmValueStr(AsmValue):
    value: str


@dataclass
class AsmSection(AsmValue):
    name: str = ""
    value: "List[AsmValueStr|AsmSection]" = field(default_factory=list)
    #: Tokens written after the section name on its own line (`.obj "Main"` -> ['"Main"']).
    #: They are also the first entries of `value`.
    args: List[str] = field(default_factory=list)

    def get(self, subsection_name: str) -> "AsmSection":
        for val in self.value:
            if isinstance(val, AsmSection) and val.name == subsection_name:
                return val
        raise KeyError(f"No subsection '{subsection_name}' found!")

    def find(self, subsection_name: str) -> "Optional[AsmSection]":
        for val in self.value:
            if isinstance(val, AsmSection) and val.name == subsection_name:
                return val
        return None

    @property
    def body(self) -> "List[AsmValueStr|AsmSection]":
        """Entries on the lines under the section, without the header tokens."""
        return self.value[len(self.args) :]


# ── Tokens ────────────────────────────────────────────────────────────────────


class _Str(str):
    """A decoded "..." literal, as opposed to a bare word."""


class _Pos(NamedTuple):
    """A debug position suffix: `@<file index>:<line>` or `@"file":<line>`."""

    file: Union[int, str]
    line: int


_STRING = r'"(?:[^"\\]|\\.)*"'
_TOKEN_RE = re.compile(
    rf"(x?{_STRING})"  # 1: string or hex bytes literal
    rf"|(@(?:{_STRING}|-?\d+):-?\d+)"  # 2: debug position
    r"|([\[(])"  # 3: group open
    r"|([\])])"  # 4: group close
    r'|([^\s,\[\]()"#]+)'  # 5: bare word
    r"|[\s,]+"  # separators
    r"|(.)",  # 6: anything else is an error
)
_COMMENT_RE = re.compile(rf"x?{_STRING}|#")
_ESCAPE_RE = re.compile(r"\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)")
_SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"'}
_REF_RE = re.compile(r"([a-z])@(-?\d+)")
_INT_RE = re.compile(r"[+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)")
_LABEL_NAME_RE = re.compile(r"[A-Za-z_.$][\w.$]*")
_X86_LABEL_LINE_RE = re.compile(r"[A-Za-z_.$][\w.$]*:")


def _unescape(text: str, line: int) -> str:
    def repl(m: "re.Match[str]") -> str:
        esc = m.group(1)
        if esc[0] == "x":
            byte = int(esc[1:], 16)
            # \xNN is a raw byte: bytes past ASCII that aren't valid UTF-8 are kept the
            # way the loader keeps them (surrogateescape).
            return chr(byte) if byte < 0x80 else chr(0xDC00 + byte)
        if esc[0] == "u" and len(esc) > 1:
            return chr(int(esc[2:-1], 16))
        if esc in _SIMPLE_ESCAPES:
            return _SIMPLE_ESCAPES[esc]
        raise AsmError(f"Unknown escape '\\{esc}' in string literal", line)

    return _ESCAPE_RE.sub(repl, text) if "\\" in text else text


def _decode_literal(token: str, line: int) -> "Union[_Str, bytes]":
    if token[0] == "x":
        try:
            return bytes.fromhex(token[2:-1])
        except ValueError as e:
            raise AsmError(f"Invalid hex bytes literal {token}: {e}", line) from e
    return _Str(_unescape(token[1:-1], line))


_PLAIN_LINE_RE = re.compile(r'[^"\[\]()#]*')


def _tokenize(text: str, line: int) -> List[Any]:
    """Splits one line into tokens: bare words (str), string literals (_Str), hex byte
    literals (bytes), debug positions (_Pos), and bracketed groups (lists)."""
    if _PLAIN_LINE_RE.fullmatch(text):
        # Fast path for the common line with no literals or groups.
        tokens: List[Any] = text.replace(",", " ").split()
        if tokens and tokens[-1][0] == "@":
            where, _, line_no = tokens[-1][1:].rpartition(":")
            try:
                tokens[-1] = _Pos(int(where), int(line_no))
            except ValueError:
                raise AsmError(f"Invalid debug position '{tokens[-1]}'", line) from None
        return tokens
    stack: List[List[Any]] = [[]]
    for m in _TOKEN_RE.finditer(text):
        lit, pos, opening, closing, word, bad = m.groups()
        if word is not None:
            stack[-1].append(word)
        elif lit is not None:
            stack[-1].append(_decode_literal(lit, line))
        elif pos is not None:
            where, _, line_no = pos[1:].rpartition(":")
            file: Union[int, str] = _unescape(where[1:-1], line) if where[0] == '"' else int(where)
            stack[-1].append(_Pos(file, int(line_no)))
        elif opening is not None:
            group: List[Any] = []
            stack[-1].append(group)
            stack.append(group)
        elif closing is not None:
            if len(stack) == 1:
                raise AsmError(f"Unmatched '{closing}'", line)
            stack.pop()
        elif bad is not None:
            raise AsmError(
                "Unterminated string literal" if bad == '"' else f"Unexpected character {bad!r}", line
            )
    if len(stack) != 1:
        raise AsmError("Unclosed bracket", line)
    return stack[0]


def _escape(text: str) -> str:
    """The body of a "..." literal for `text` (see _unescape)."""
    if text.isascii() and text.isprintable() and '"' not in text and "\\" not in text:
        return text
    out = []
    for ch in text:
        code = ord(ch)
        if ch == '"' or ch == "\\":
            out.append("\\" + ch)
        elif ch in "\n\r\t\0":
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t", "\0": "\\0"}[ch])
        elif 0xDC80 <= code <= 0xDCFF:
            out.append(f"\\x{code - 0xDC00:02x}")
        elif code < 0x80 and not ch.isprintable():
            out.append(f"\\x{code:02x}")
        elif not ch.isprintable():
            out.append(f"\\u{{{code:x}}}")
        else:
            out.append(ch)
    return "".join(out)


def _quote(text: str) -> str:
    return f'"{_escape(text)}"'


_CANONICAL_NAN = 0x7FF8000000000000
_F64 = struct.Struct("<d")
_U64 = struct.Struct("<Q")


def _float_bits(value: float) -> int:
    return _U64.unpack(_F64.pack(value))[0]


def _float_from_bits(bits: int) -> float:
    return _F64.unpack(_U64.pack(bits))[0]


def _format_float(value: float) -> str:
    if value != value:
        bits = _float_bits(value)
        return "nan" if bits == _CANONICAL_NAN else f"f64:{bits:#018x}"
    if value in (float("inf"), float("-inf")):
        return "inf" if value > 0 else "-inf"
    return repr(value)


def _parse_float(token: Any, line: int) -> float:
    if isinstance(token, str) and not isinstance(token, _Str):
        low = token.lower()
        if low == "nan":
            return _float_from_bits(_CANONICAL_NAN)
        if low in ("inf", "+inf", "-inf"):
            return float(low)
        if low.startswith("f64:"):
            try:
                return _float_from_bits(int(token[4:], 16))
            except (ValueError, struct.error) as e:
                raise AsmError(f"Invalid raw float {token}", line) from e
        if _INT_RE.fullmatch(token):
            return float(int(token, 0))
        try:
            return float(token)
        except ValueError:
            pass
    raise AsmError(f"Expected a float, got {_show(token)}", line)


def _parse_int(token: Any, line: int, what: str = "an integer") -> int:
    if isinstance(token, str) and not isinstance(token, _Str) and _INT_RE.fullmatch(token):
        return int(token, 0)
    raise AsmError(f"Expected {what}, got {_show(token)}", line)


def _show(token: Any) -> str:
    if isinstance(token, _Pos):
        return "a debug position (it must come last on the line)"
    if isinstance(token, _Str):
        return _quote(token)
    if isinstance(token, bytes):
        return f'x"{token.hex()}"'
    if isinstance(token, list):
        return "[...]"
    return f"'{token}'"


_REF_CLASSES: Dict[str, type] = {
    "f": fIndex,
    "t": tIndex,
    "s": strRef,
    "g": gIndex,
    "i": intRef,
    "d": floatRef,
    "b": bytesRef,
}
_REF_NAMES = {
    "f": "function",
    "t": "type",
    "s": "string",
    "g": "global",
    "i": "int",
    "d": "float",
    "b": "bytes",
}


def _parse_ref(token: Any, prefix: str, line: int) -> int:
    """The index in a `<prefix>@N` reference."""
    if isinstance(token, str) and not isinstance(token, _Str):
        m = _REF_RE.fullmatch(token)
        if m and m.group(1) == prefix:
            return int(m.group(2))
    raise AsmError(f"Expected a {_REF_NAMES[prefix]} reference ({prefix}@N), got {_show(token)}", line)


# Type kinds without data, by name. `Type` is the historical spelling of TypeType.
_SIMPLE_TYPES: Dict[str, int] = {
    cls.__name__: kind
    for kind, cls in enumerate(Type.TYPEDEFS)
    if getattr(cls, "__slots__", None) == () and cls not in (Method, Struct)
}
_SIMPLE_TYPES["Type"] = _SIMPLE_TYPES["TypeType"]
_SIMPLE_TYPE_NAMES = {kind: name for name, kind in _SIMPLE_TYPES.items() if name != "TypeType"}
_KIND = {cls: kind for kind, cls in enumerate(Type.TYPEDEFS)}


def _make_type(definition: TypeDef) -> Type:
    typ = Type()
    typ.kind.value = _KIND[type(definition)]
    typ.definition = definition
    return typ


def _indent_level(line: str) -> Tuple[int, str]:
    """Indentation depth (a tab or four spaces per level) and the rest of the line."""
    stripped = line.lstrip(" \t")
    width = len(line) - len(stripped)
    if "\t" not in line[:width]:
        return width // 4, stripped
    lead = line[:width]
    return lead.count("\t") + lead.count(" ") // 4, stripped


# ── Assembler ─────────────────────────────────────────────────────────────────


class AsmFile:
    def __init__(self, content: str) -> None:
        self.content = content
        self.raw_sections: Dict[str, AsmSection] = {}
        self.strings: List[str] = []
        self.ints: List[int] = []
        self.floats: List[float] = []
        self.bytes: List[bytes] = []
        self._string_index: Dict[str, int] = {}
        self._int_index: Dict[int, int] = {}
        self._float_index: Dict[int, int] = {}
        self._bytes_index: Dict[bytes, int] = {}
        self._debugfile_index: Dict[str, int] = {}
        self._parse()

    @classmethod
    def from_path(cls, path: str) -> "AsmFile":
        with open(path, "r", encoding="utf-8") as file:
            content = file.read()
        return cls(content)

    @staticmethod
    def _strip_comment(line: str) -> str:
        """Strips a trailing `# ...` comment, ignoring '#' characters inside string literals."""
        if "#" not in line:
            return line
        for m in _COMMENT_RE.finditer(line):
            if m.group() == "#":
                return line[: m.start()]
        return line

    def _parse(self) -> None:
        section_stack: List[AsmSection] = []
        # split("\n") rather than splitlines(): the latter also splits on characters
        # (\x0b, \x1c, U+2028, ...) that may sit inside a string literal.
        for line_no, raw_line in enumerate(self.content.split("\n"), start=1):
            line = self._strip_comment(raw_line).rstrip()
            if not line.strip():
                continue
            indent_level, stripped = _indent_level(line)
            # pop extra sections if we decreased the indent level
            while len(section_stack) > indent_level:
                section_stack.pop()
            if stripped.startswith("."):
                name, _, rest = stripped[1:].partition(" ")
                tokens = [m.group() for m in _TOKEN_RE.finditer(rest) if m.lastindex]
                new_section = AsmSection(name=name, value=[], args=tokens, line=line_no)
                new_section.value.extend(AsmValueStr(token, line=line_no) for token in tokens)
                if section_stack:
                    section_stack[-1].value.append(new_section)
                else:
                    if name in self.raw_sections:
                        raise AsmError(f"Duplicate section '.{name}'", line_no)
                    self.raw_sections[name] = new_section
                section_stack.append(new_section)
            else:
                if not section_stack:
                    raise AsmError("Encountered a value outside any section!", line_no)
                section_stack[-1].value.append(AsmValueStr(stripped, line=line_no))

    # ── pools ──

    def _get_str_idx(self, val: str) -> strRef:
        idx = self._string_index.get(val)
        if idx is None:
            idx = self._string_index[val] = len(self.strings)
            self.strings.append(val)
        return strRef(idx)

    def _get_int_idx(self, val: int, line: int = 0) -> intRef:
        if not -(1 << 31) <= val < (1 << 32):
            raise AsmError(f"Integer {val} does not fit in 32 bits", line)
        word = val & 0xFFFFFFFF
        idx = self._int_index.get(word)
        if idx is None:
            idx = self._int_index[word] = len(self.ints)
            self.ints.append(word)
        return intRef(idx)

    def _get_float_idx(self, val: float) -> floatRef:
        bits = _float_bits(val)
        idx = self._float_index.get(bits)
        if idx is None:
            idx = self._float_index[bits] = len(self.floats)
            self.floats.append(val)
        return floatRef(idx)

    def _get_bytes_idx(self, val: bytes) -> bytesRef:
        idx = self._bytes_index.get(val)
        if idx is None:
            idx = self._bytes_index[val] = len(self.bytes)
            self.bytes.append(val)
        return bytesRef(idx)

    def _string(self, token: Any, line: int) -> strRef:
        """A string operand: a literal (interned) or `s@N`."""
        if isinstance(token, _Str):
            return self._get_str_idx(token)
        return strRef(_parse_ref(token, "s", line))

    def _entries(self, section: AsmSection) -> Iterable[Tuple[List[Any], int]]:
        """Token lists of the section's lines, header tokens included (as one line)."""
        if section.args:
            yield _tokenize(" ".join(section.args), section.line), section.line
        for val in section.body:
            if isinstance(val, AsmSection):
                raise AsmError(f"Unexpected subsection '.{val.name}' in '.{section.name}'", val.line)
            yield _tokenize(val.value, val.line), val.line

    def _flat(self, section: AsmSection) -> Iterable[Tuple[Any, int]]:
        """Every token in the section (header and lines), for list-like sections."""
        for tokens, line in self._entries(section):
            for token in tokens:
                yield token, line

    def _add_pools(self) -> None:
        sections = self.raw_sections
        if "strings" in sections:
            for token, line in self._flat(sections["strings"]):
                if not isinstance(token, _Str):
                    raise AsmError(f"Expected a string literal, got {_show(token)}", line)
                self._string_index.setdefault(token, len(self.strings))
                self.strings.append(token)
        if "ints" in sections:
            for token, line in self._flat(sections["ints"]):
                val = _parse_int(token, line)
                if not -(1 << 31) <= val < (1 << 32):
                    raise AsmError(f"Integer {val} does not fit in 32 bits", line)
                self._int_index.setdefault(val & 0xFFFFFFFF, len(self.ints))
                self.ints.append(val & 0xFFFFFFFF)
        if "floats" in sections:
            for token, line in self._flat(sections["floats"]):
                val = _parse_float(token, line)
                self._float_index.setdefault(_float_bits(val), len(self.floats))
                self.floats.append(val)
        if "bytes" in sections:
            for token, line in self._flat(sections["bytes"]):
                if not isinstance(token, bytes):
                    raise AsmError(f'Expected a hex bytes literal (x"..."), got {_show(token)}', line)
                self._bytes_index.setdefault(token, len(self.bytes))
                self.bytes.append(token)

    # ── types ──

    def _add_types(self, code: Bytecode, section: AsmSection) -> None:
        if section.args and section.args != ["novoid"]:
            raise AsmError(f"Unknown '.types' option(s): {' '.join(section.args)}", section.line)
        if section.args:
            # `.types novoid`: t@0 is the first listed type, not an implicit Void.
            code.types.clear()
        for val in section.body:
            if isinstance(val, AsmSection):
                code.types.append(self._type_section(val))
            else:
                code.types.append(self._type_line(_tokenize(val.value, val.line), val.line))
        code.invalidate_proto_field_cache()

    def _type_line(self, tokens: List[Any], line: int) -> Type:
        if not tokens or not isinstance(tokens[0], str) or isinstance(tokens[0], _Str):
            raise AsmError("Expected a type", line)
        name, rest = tokens[0], tokens[1:]
        if name in _SIMPLE_TYPES:
            if rest:
                raise AsmError(f"'{name}' takes no operands", line)
            typ = Type()
            typ.kind.value = _SIMPLE_TYPES[name]
            typ.definition = Type.TYPEDEFS[typ.kind.value]()
            return typ
        if name in ("Fun", "Method"):
            if len(rest) != 3 or not isinstance(rest[0], list) or rest[1] != "->":
                raise AsmError(f"Expected '{name} (<args>) -> <ret>'", line)
            fun = Fun() if name == "Fun" else Method()
            fun.args = [tIndex(_parse_ref(arg, "t", line)) for arg in rest[0]]
            fun.ret = tIndex(_parse_ref(rest[2], "t", line))
            return _make_type(fun)
        if name in ("Ref", "Null", "Packed"):
            if len(rest) != 1:
                raise AsmError(f"Expected '{name} t@N'", line)
            inner = tIndex(_parse_ref(rest[0], "t", line))
            if name == "Packed":
                packed = Packed()
                packed.inner = inner
                return _make_type(packed)
            wrapper = Ref() if name == "Ref" else Null()
            wrapper.type = inner
            return _make_type(wrapper)
        if name == "Abstract":
            if len(rest) != 1:
                raise AsmError("Expected 'Abstract <name>'", line)
            abstract = Abstract()
            abstract.name = self._string(rest[0], line)
            return _make_type(abstract)
        if name.lower() in ("obj", "struct", "enum", "virtual"):
            raise AsmError(f"'{name}' types are written as a '.{name.lower()}' block", line)
        raise AsmError(f"Unknown type '{name}'", line)

    def _type_section(self, section: AsmSection) -> Type:
        line = section.line
        args = _tokenize(" ".join(section.args), line)
        if section.name in ("obj", "struct"):
            if len(args) != 1:
                raise AsmError(f"Expected '.{section.name} <name>'", line)
            obj = Obj() if section.name == "obj" else Struct()
            obj.name = self._string(args[0], line)
            obj.super = tIndex(-1)
            obj._global = gIndex(0)
            for val in section.body:
                if not isinstance(val, AsmSection):
                    raise AsmError(
                        f"Expected .super/.global/.fields/.protos/.bindings in '.{section.name}'", val.line
                    )
                if val.name == "super":
                    obj.super = tIndex(self._single_ref(val, "t"))
                elif val.name == "global":
                    obj._global = gIndex(self._single_ref(val, "g") + 1)  # stored as index + 1; 0 = none
                elif val.name == "fields":
                    obj.fields = [self._field(tokens, ln) for tokens, ln in self._entries(val)]
                elif val.name == "protos":
                    obj.protos = [self._proto(tokens, ln) for tokens, ln in self._entries(val)]
                elif val.name == "bindings":
                    obj.bindings = [self._binding(tokens, ln) for tokens, ln in self._entries(val)]
                else:
                    raise AsmError(f"Unknown subsection '.{val.name}' in '.{section.name}'", val.line)
            return _make_type(obj)
        if section.name == "virtual":
            if args:
                raise AsmError("'.virtual' takes no name", line)
            virtual = Virtual()
            virtual.fields = [self._field(tokens, ln) for tokens, ln in self._entries(section)]
            return _make_type(virtual)
        if section.name == "enum":
            if len(args) != 1:
                raise AsmError("Expected '.enum <name>'", line)
            enum = Enum()
            enum.name = self._string(args[0], line)
            enum._global = gIndex(0)
            for val in section.body:
                if isinstance(val, AsmSection):
                    if val.name != "global":
                        raise AsmError(f"Unknown subsection '.{val.name}' in '.enum'", val.line)
                    enum._global = gIndex(self._single_ref(val, "g") + 1)
                    continue
                tokens = _tokenize(val.value, val.line)
                construct = EnumConstruct()
                if not tokens or len(tokens) > 2 or (len(tokens) == 2 and not isinstance(tokens[1], list)):
                    raise AsmError("Expected an enum construct: <name> [(<param types>)]", val.line)
                construct.name = self._string(tokens[0], val.line)
                if len(tokens) == 2:
                    construct.params = [tIndex(_parse_ref(p, "t", val.line)) for p in tokens[1]]
                enum.constructs.append(construct)
            return _make_type(enum)
        raise AsmError(f"Unknown type block '.{section.name}'", line)

    def _single_ref(self, section: AsmSection, prefix: str) -> int:
        tokens = list(self._flat(section))
        if len(tokens) != 1:
            raise AsmError(f"'.{section.name}' expects one {_REF_NAMES[prefix]} reference", section.line)
        return _parse_ref(tokens[0][0], prefix, tokens[0][1])

    def _field(self, tokens: List[Any], line: int) -> Field:
        if len(tokens) != 2:
            raise AsmError("Expected a field: <name> t@N", line)
        return Field(self._string(tokens[0], line), tIndex(_parse_ref(tokens[1], "t", line)))

    def _proto(self, tokens: List[Any], line: int) -> Proto:
        if len(tokens) != 3:
            raise AsmError("Expected a proto: <name> f@N <virtual slot, or -1>", line)
        proto = Proto()
        proto.name = self._string(tokens[0], line)
        proto.findex = fIndex(_parse_ref(tokens[1], "f", line))
        proto.pindex = VarInt(_parse_int(tokens[2], line))
        return proto

    def _binding(self, tokens: List[Any], line: int) -> Binding:
        if len(tokens) != 2:
            raise AsmError("Expected a binding: <field index> f@N", line)
        binding = Binding()
        binding.field = fieldRef(_parse_int(tokens[0], line, "a field index"))
        binding.findex = fIndex(_parse_ref(tokens[1], "f", line))
        return binding

    # ── globals, natives, constants ──

    def _add_globals(self, code: Bytecode, section: AsmSection) -> None:
        for token, line in self._flat(section):
            code.global_types.append(tIndex(_parse_ref(token, "t", line)))

    def _add_natives(self, code: Bytecode, section: AsmSection) -> None:
        for tokens, line in self._entries(section):
            # f@N (t@T) lib.name   or   f@N (t@T) <lib> <name>, with the parentheses optional
            if len(tokens) not in (3, 4):
                raise AsmError("Expected a native: f@N (t@T) <lib>.<name>, or f@N (t@T) <lib> <name>", line)
            typ = tokens[1][0] if isinstance(tokens[1], list) and len(tokens[1]) == 1 else tokens[1]
            obj = Native()
            obj.findex = fIndex(_parse_ref(tokens[0], "f", line))
            obj.type = tIndex(_parse_ref(typ, "t", line))
            if len(tokens) == 3:
                target = tokens[2]
                if isinstance(target, _Str) or not isinstance(target, str) or "." not in target:
                    raise AsmError(f"Expected <lib>.<name>, got {_show(target)}", line)
                lib, name = target.split(".", 1)
                obj.lib = self._get_str_idx(lib)
                obj.name = self._get_str_idx(name)
            else:
                obj.lib = self._string(tokens[2], line)
                obj.name = self._string(tokens[3], line)
            code.natives.append(obj)
        code.invalidate_findex_cache()

    def _add_constants(self, code: Bytecode, section: AsmSection) -> None:
        for tokens, line in self._entries(section):
            if not tokens:
                continue
            const = Constant()
            const._global = gIndex(_parse_ref(tokens[0], "g", line))
            # Each field is a pool index (into ints, floats or strings, by the field's type).
            fields = []
            for token in tokens[1:]:
                if isinstance(token, _Str):
                    fields.append(VarInt(self._get_str_idx(token).value))
                elif isinstance(token, str) and _REF_RE.fullmatch(token) and token[0] in "sid":
                    fields.append(VarInt(int(token[2:])))
                else:
                    fields.append(VarInt(_parse_int(token, line, "a pool index")))
            const.fields = fields
            code.constants.append(const)

    # ── functions ──

    def _intern_fun_type(self, code: Bytecode, args: List[tIndex], ret: tIndex) -> tIndex:
        """
        Finds an existing `Fun` type matching this exact signature, or appends a new one.
        Mirrors how string/int/float literals get auto-interned rather than requiring the
        assembly source to declare a pool entry by hand.
        """
        for i, existing in enumerate(code.types):
            defn = existing.definition
            if (
                existing.kind.value == 10
                and isinstance(defn, Fun)
                and [a.value for a in defn.args] == [a.value for a in args]
                and defn.ret.value == ret.value
            ):
                return tIndex(i)

        fun = Fun()
        fun.args = args
        fun.ret = ret
        code.types.append(_make_type(fun))
        code.invalidate_proto_field_cache()
        return tIndex(len(code.types) - 1)

    def _make_asm_opcode(self, mode: int, value: int, line: int = 0) -> Opcode:
        """Builds a raw `Asm` opcode (see docs/asm for mode semantics)."""
        if not 0 <= value <= 0xFF:
            raise AsmError(f"Asm byte value {value} out of range (0-255)!", line)
        op = Opcode()
        op.op = "Asm"
        op.df = {"mode": VarInt(mode), "value": VarInt(value), "reg": Reg(0)}
        return op

    def _operand(self, token: Any, kind: str, line: int, pending: List[Tuple[VarInt, int, str]]) -> Any:
        """Parses one opcode operand of schema kind `kind`. Jump operands naming a label
        are returned unresolved and recorded in `pending` as (operand, line)."""
        if kind == "Reg":
            if type(token) is str and token.startswith("reg") and token[3:].isdigit():
                return Reg(int(token[3:]))
            raise AsmError(f"Expected a register (regN), got {_show(token)}", line)
        if kind == "Regs":
            if not isinstance(token, list):
                raise AsmError(f"Expected a register list [regA, regB, ...], got {_show(token)}", line)
            regs = Regs()
            regs.value = [self._operand(t, "Reg", line, pending) for t in token]
            return regs
        if kind == "RefString":
            return self._string(token, line)
        if kind == "RefInt":
            if isinstance(token, str) and not isinstance(token, _Str) and token.startswith("i@"):
                return intRef(_parse_ref(token, "i", line))
            return self._get_int_idx(_parse_int(token, line), line)
        if kind == "RefFloat":
            if isinstance(token, str) and not isinstance(token, _Str) and token.startswith("d@"):
                return floatRef(_parse_ref(token, "d", line))
            return self._get_float_idx(_parse_float(token, line))
        if kind == "RefBytes":
            if isinstance(token, bytes):
                return self._get_bytes_idx(token)
            return bytesRef(_parse_ref(token, "b", line))
        if kind == "InlineBool":
            if token in ("true", "false"):
                inline_bool = InlineBool()
                inline_bool.value = token == "true"
                return inline_bool
            raise AsmError(f"Expected true or false, got {_show(token)}", line)
        if kind == "RefFun":
            return fIndex(_parse_ref(token, "f", line))
        if kind == "RefGlobal":
            return gIndex(_parse_ref(token, "g", line))
        if kind == "RefType":
            return tIndex(_parse_ref(token, "t", line))
        if kind == "RefField":
            return fieldRef(_parse_int(token, line, "a field index"))
        if kind == "JumpOffset":
            if isinstance(token, str) and not isinstance(token, _Str) and _LABEL_NAME_RE.fullmatch(token):
                placeholder = VarInt(0)
                pending.append((placeholder, line, token))
                return placeholder
            return VarInt(_parse_int(token, line, "a jump offset or label"))
        if kind == "JumpOffsets":
            if not isinstance(token, list):
                raise AsmError(f"Expected a list of jump offsets [a, b, ...], got {_show(token)}", line)
            offsets = VarInts()
            offsets.value = [self._operand(t, "JumpOffset", line, pending) for t in token]
            return offsets
        # InlineInt, RefEnumConstruct, RefEnumConstant
        return VarInt(_parse_int(token, line))

    def _opcode(
        self, val: str, line: int = 0, pending: Optional[List[Tuple[VarInt, int, str]]] = None
    ) -> Tuple[Opcode, Optional[_Pos]]:
        tokens = _tokenize(val, line)
        position: Optional[_Pos] = None
        if tokens and type(tokens[-1]) is _Pos:
            position = tokens.pop()
        if not tokens:
            raise AsmError("Expected an opcode", line)
        name = tokens[0]
        if not isinstance(name, str) or isinstance(name, _Str) or name not in opcodes:
            raise AsmError(f"Unknown opcode {_show(name)}", line)
        schema = opcodes[name]
        operands = tokens[1:]
        if len(operands) != len(schema):
            expected = ", ".join(f"{k}: {v}" for k, v in schema.items()) or "none"
            raise AsmError(f"{name} takes {len(schema)} operand(s) ({expected}), got {len(operands)}", line)
        op = Opcode()
        op.op = name
        op.df = {
            key: self._operand(token, kind, line, pending if pending is not None else [])
            for (key, kind), token in zip(schema.items(), operands)
        }
        return op, position

    def _assemble_ops(self, section: AsmSection, debug: bool) -> Tuple[List[Opcode], List[fileRef]]:
        """
        Parses a `.ops` section into opcodes (and their debug positions), handling:

        - `.label <name>`   -> names the next opcode's index, for jump operands
        - `<op> ... @F:L`   -> debug position (debug file index F, line L), kept for later ops
        - `AsmNaked`        -> `Asm 4, 0, reg0`: marks a naked function (raw x86 body)
        - `AsmByte <v>`     -> `Asm 0, <v>, reg0`: emit a single raw byte
        - `X86 <mnemonic>`  -> assembled with keystone-engine into `Asm 0, ...` bytes
        - `<label>:`        -> label for the surrounding X86 block
        """
        ops: List[Opcode] = []
        positions: List[fileRef] = []
        labels: Dict[str, int] = {}
        # (operand placeholder, source line, label, index of the op it belongs to)
        jumps: List[Tuple[VarInt, int, str, int]] = []
        x86_block: List[str] = []
        x86_line = 0
        current = fileRef(-1, 0)  # the decoder's starting state: no file, line 0

        def emit(op: Opcode) -> None:
            ops.append(op)
            positions.append(current)

        def flush_x86() -> None:
            if not x86_block:
                return
            try:
                data = assemble_x86("\n".join(x86_block))
            except X86AsmError as e:
                raise AsmError(f"X86 assembly failed: {e}", x86_line) from e
            for byte in data:
                emit(self._make_asm_opcode(0, byte))
            x86_block.clear()

        for val in section.body:
            if isinstance(val, AsmSection):
                if val.name != "label" or len(val.args) != 1 or not _LABEL_NAME_RE.fullmatch(val.args[0]):
                    raise AsmError(f"Expected '.label <name>' in '.ops', got '.{val.name}'", val.line)
                flush_x86()
                if val.args[0] in labels:
                    raise AsmError(f"Duplicate label '{val.args[0]}'", val.line)
                labels[val.args[0]] = len(ops)
                continue
            stripped = val.value.strip()
            if stripped == "X86" or stripped.startswith("X86 "):
                if not x86_block:
                    x86_line = val.line
                x86_block.append(stripped[3:].strip())
                continue
            if stripped[-1] == ":" and _X86_LABEL_LINE_RE.fullmatch(stripped):
                if not x86_block:
                    x86_line = val.line
                x86_block.append(stripped)
                continue
            flush_x86()
            if stripped == "AsmNaked":
                emit(self._make_asm_opcode(4, 0, val.line))
            elif stripped.startswith("AsmByte"):
                parts = stripped.split()
                if len(parts) != 2:
                    raise AsmError("AsmByte expects exactly one byte value!", val.line)
                emit(self._make_asm_opcode(0, int(parts[1], 0), val.line))
            else:
                pending: List[Tuple[VarInt, int, str]] = []
                op, position = self._opcode(stripped, val.line, pending)
                if position is not None:
                    if not debug:
                        raise AsmError("Debug positions need a '.debugfiles' section", val.line)
                    if isinstance(position.file, str):
                        file = self._debugfile_index.get(position.file, -1)
                        if file < 0:
                            raise AsmError(f"Unknown debug file {_quote(position.file)}", val.line)
                    else:
                        file = position.file
                    if (file, position.line) != (current.value, current.line):
                        current = fileRef(file, position.line)
                jumps.extend((placeholder, line, label, len(ops)) for placeholder, line, label in pending)
                emit(op)
        flush_x86()

        for placeholder, line, label, index in jumps:
            if label not in labels:
                raise AsmError(f"Unknown label '{label}'", line)
            placeholder.value = labels[label] - (index + 1)
        return ops, positions

    def _add_functions(self, code: Bytecode) -> None:
        debug = bool(code.has_debug_info)
        for section in self.raw_sections.values():
            if not section.name.startswith("f@"):
                continue
            line = section.line
            func = Function()
            func.findex = fIndex(_parse_ref(section.name, "f", line))

            regs_section = section.find("regs")
            func.regs = (
                [tIndex(_parse_ref(t, "t", ln)) for t, ln in self._flat(regs_section)] if regs_section else []
            )

            type_section = section.find("type")
            returns_section = section.find("returns")
            args_section = section.find("args")
            if type_section is not None:
                if returns_section is not None or args_section is not None:
                    raise AsmError("Use either '.type' or '.returns'/'.args', not both", type_section.line)
                func.type = tIndex(self._single_ref(type_section, "t"))
            elif returns_section is not None:
                ret = tIndex(self._single_ref(returns_section, "t"))
                # `.args <n>` declares how many of the leading registers are parameters
                # (default 0, i.e. a no-argument function like a typical entrypoint).
                nargs = 0
                if args_section is not None:
                    tokens = list(self._flat(args_section))
                    if len(tokens) != 1:
                        raise AsmError("'.args' expects the number of arguments", args_section.line)
                    nargs = _parse_int(tokens[0][0], tokens[0][1])
                if nargs > len(func.regs):
                    raise AsmError("More args than declared registers!", line)
                func.type = self._intern_fun_type(code, func.regs[:nargs], ret)
            else:
                raise AsmError(f"'.{section.name}' needs a '.type' or a '.returns'", line)

            ops_section = section.find("ops")
            if ops_section is None:
                raise AsmError(f"'.{section.name}' has no '.ops'", line)
            func.ops, positions = self._assemble_ops(ops_section, debug)
            func.has_debug = debug
            func.version = code.version.value
            if debug:
                func.debuginfo = DebugInfo()
                func.debuginfo.value = positions
                assigns_section = section.find("assigns")
                if assigns_section is not None:
                    if code.version.value < 3:
                        raise AsmError("'.assigns' needs bytecode version 3 or later", assigns_section.line)
                    assigns = []
                    for tokens, ln in self._entries(assigns_section):
                        if len(tokens) != 2:
                            raise AsmError("Expected an assign: <name> <opcode index>", ln)
                        assigns.append((self._string(tokens[0], ln), VarInt(_parse_int(tokens[1], ln))))
                    func.assigns = assigns
                    func.nassigns = VarInt(len(assigns))
            elif section.find("assigns") is not None:
                raise AsmError("'.assigns' needs a '.debugfiles' section", line)

            known = {"regs", "type", "returns", "args", "ops", "assigns"}
            for val in section.body:
                if isinstance(val, AsmSection) and val.name not in known:
                    raise AsmError(f"Unknown subsection '.{val.name}' in '.{section.name}'", val.line)
            code.functions.append(func)
        code.invalidate_findex_cache()

    def _get_single_val(self, name: str) -> str:
        values = [v for v in self.raw_sections[name].value if isinstance(v, AsmValueStr)]
        if len(values) != 1 or len(self.raw_sections[name].value) != 1:
            raise AsmError(f"Expected exactly one value for '.{name}'!", self.raw_sections[name].line)
        return values[0].value

    def assemble(self) -> Bytecode:
        sections = self.raw_sections
        for req in ("version", "entrypoint"):
            if req not in sections:
                raise AsmError(f"Missing '.{req}' section")
        known = {
            "version",
            "debugfiles",
            "strings",
            "ints",
            "floats",
            "bytes",
            "types",
            "globals",
            "natives",
            "constants",
            "entrypoint",
        }
        for name, section in sections.items():
            if name not in known and not name.startswith("f@"):
                raise AsmError(f"Unknown section '.{name}'", section.line)

        version = _parse_int(self._get_single_val("version"), sections["version"].line, "a version number")
        code = Bytecode.create_empty(no_extra_types=True, version=version)
        code.has_debug_info = "debugfiles" in sections
        if code.has_debug_info:
            assert code.debugfiles is not None
            for token, line in self._flat(sections["debugfiles"]):
                if not isinstance(token, _Str):
                    raise AsmError(f"Expected a file name string, got {_show(token)}", line)
                self._debugfile_index.setdefault(token, len(code.debugfiles.value))
                code.debugfiles.value.append(token)
        else:
            code.debugfiles = None
            code.ndebugfiles = None

        self._add_pools()
        if "types" in sections:
            self._add_types(code, sections["types"])
        if "globals" in sections:
            self._add_globals(code, sections["globals"])
        if "natives" in sections:
            self._add_natives(code, sections["natives"])
        self._add_functions(code)
        if "constants" in sections:
            if version < 4:
                raise AsmError("'.constants' needs bytecode version 4 or later", sections["constants"].line)
            self._add_constants(code, sections["constants"])
        code.entrypoint = fIndex(
            _parse_ref(self._get_single_val("entrypoint"), "f", sections["entrypoint"].line)
        )

        code.strings.value = list(self.strings)
        for word in self.ints:
            code.add_i32(word)
        for val in self.floats:
            sf = SerialisableF64()
            sf.value = val
            code.floats.append(sf)
        if version >= 5:
            code.bytes = BytesBlock()
            code.bytes.value = list(self.bytes)
            code.nbytes = VarInt()
        elif self.bytes:
            raise AsmError("A bytes pool needs bytecode version 5 or later")
        else:
            code.bytes = None
            code.nbytes = None

        code.set_meta()
        code._validate_structure()
        # Finish the same way loading a file does, so the result is ready for analysis.
        code.init_globals()
        code._build_virtual_tables()
        code.map_statics()
        return code


# ── Writer ────────────────────────────────────────────────────────────────────


class _HlasmWriter:
    def __init__(self, code: Bytecode) -> None:
        self.code = code
        self.out: List[str] = []
        self.first_string: Dict[str, int] = {}
        for i, s in enumerate(code.strings.value):
            self.first_string.setdefault(s, i)
        self.first_int: Dict[int, int] = {}
        for i, n in enumerate(code.ints):
            self.first_int.setdefault(n.value & 0xFFFFFFFF, i)
        self.first_float: Dict[int, int] = {}
        for i, f in enumerate(code.floats):
            self.first_float.setdefault(_float_bits(f.value), i)

    def s(self, ref: int) -> str:
        """A string operand: a literal when that resolves back to `ref`, else s@N."""
        strings = self.code.strings.value
        if 0 <= ref < len(strings) and self.first_string.get(strings[ref]) == ref:
            return _quote(strings[ref])
        return f"s@{ref}"

    def int_literal(self, ref: int) -> str:
        ints = self.code.ints
        if 0 <= ref < len(ints):
            word = ints[ref].value & 0xFFFFFFFF
            if self.first_int.get(word) == ref:
                return str(word - (1 << 32) if word >= 1 << 31 else word)
        return f"i@{ref}"

    def float_literal(self, ref: int) -> str:
        floats = self.code.floats
        if 0 <= ref < len(floats) and self.first_float.get(_float_bits(floats[ref].value)) == ref:
            return _format_float(floats[ref].value)
        return f"d@{ref}"

    def write(self) -> str:
        code, out = self.code, self.out
        version = code.version.value
        out.append(f".version {version}")
        if code.has_debug_info and code.debugfiles is not None:
            out.append("")
            out.append(".debugfiles")
            out.extend(f"    {_quote(name)}  # {i}" for i, name in enumerate(code.debugfiles.value))
        if code.strings.value:
            out.append("")
            out.append(".strings")
            out.extend(f"    {_quote(s)}  # s@{i}" for i, s in enumerate(code.strings.value))
        if code.ints:
            out.append("")
            out.append(".ints")
            for i, n in enumerate(code.ints):
                word = n.value & 0xFFFFFFFF
                out.append(f"    {word - (1 << 32) if word >= 1 << 31 else word}  # i@{i}")
        if code.floats:
            out.append("")
            out.append(".floats")
            out.extend(f"    {_format_float(f.value)}  # d@{i}" for i, f in enumerate(code.floats))
        if version >= 5 and code.bytes is not None and code.bytes.value:
            out.append("")
            out.append(".bytes")
            out.extend(f'    x"{b.hex()}"  # b@{i}' for i, b in enumerate(code.bytes.value))
        self._write_types()
        if code.global_types:
            out.append("")
            out.append(".globals")
            out.extend(f"    t@{t.value}  # g@{i}" for i, t in enumerate(code.global_types))
        if code.natives:
            out.append("")
            out.append(".natives")
            out.extend(
                f"    f@{n.findex.value} (t@{n.type.value}) {self.s(n.lib.value)} {self.s(n.name.value)}"
                for n in code.natives
            )
        for func in code.functions:
            self._write_function(func)
        if version >= 4 and code.constants:
            out.append("")
            out.append(".constants")
            out.extend(
                f"    g@{c._global.value} {' '.join(str(v.value) for v in c.fields)}".rstrip()
                for c in code.constants
            )
        out.append("")
        out.append(f".entrypoint f@{code.entrypoint.value}")
        return "\n".join(out) + "\n"

    def _write_types(self) -> None:
        types = self.code.types
        out = self.out
        novoid = not types or type(types[0].definition) is not Void
        out.append("")
        out.append(".types novoid" if novoid else ".types  # t@0 is Void")
        for i, typ in enumerate(types):
            if i == 0 and not novoid:
                continue
            defn = typ.definition
            kind = typ.kind.value
            if kind in _SIMPLE_TYPE_NAMES:
                out.append(f"    {_SIMPLE_TYPE_NAMES[kind]}  # t@{i}")
            elif isinstance(defn, Fun):
                args = ", ".join(f"t@{a.value}" for a in defn.args)
                name = "Method" if isinstance(defn, Method) else "Fun"
                out.append(f"    {name} ({args}) -> t@{defn.ret.value}  # t@{i}")
            elif isinstance(defn, (Ref, Null)):
                out.append(f"    {type(defn).__name__} t@{defn.type.value}  # t@{i}")
            elif isinstance(defn, Packed):
                out.append(f"    Packed t@{defn.inner.value}  # t@{i}")
            elif isinstance(defn, Abstract):
                out.append(f"    Abstract {self.s(defn.name.value)}  # t@{i}")
            elif isinstance(defn, Obj):
                out.append(
                    f"    .{'struct' if isinstance(defn, Struct) else 'obj'} {self.s(defn.name.value)}  # t@{i}"
                )
                if defn.super.value >= 0:
                    out.append(f"        .super t@{defn.super.value}")
                if defn._global.value > 0:
                    out.append(f"        .global g@{defn._global.value - 1}")
                if defn.fields:
                    out.append("        .fields")
                    out.extend(f"            {self.s(f.name.value)} t@{f.type.value}" for f in defn.fields)
                if defn.protos:
                    out.append("        .protos")
                    out.extend(
                        f"            {self.s(p.name.value)} f@{p.findex.value} {p.pindex.value}"
                        for p in defn.protos
                    )
                if defn.bindings:
                    out.append("        .bindings")
                    out.extend(f"            {b.field.value} f@{b.findex.value}" for b in defn.bindings)
            elif isinstance(defn, Virtual):
                out.append(f"    .virtual  # t@{i}")
                out.extend(f"        {self.s(f.name.value)} t@{f.type.value}" for f in defn.fields)
            elif isinstance(defn, Enum):
                out.append(f"    .enum {self.s(defn.name.value)}  # t@{i}")
                if defn._global.value > 0:
                    out.append(f"        .global g@{defn._global.value - 1}")
                for c in defn.constructs:
                    params = f" ({', '.join(f't@{p.value}' for p in c.params)})" if c.params else ""
                    out.append(f"        {self.s(c.name.value)}{params}")
            else:
                raise ValueError(f"Can't write type t@{i} of kind {kind}")

    def _operand(self, value: Any, kind: str, index: int, labels: Set[int], nops: int) -> str:
        if kind == "Reg":
            return f"reg{value.value}"
        if kind == "Regs":
            return "[" + ", ".join(f"reg{r.value}" for r in value.value) + "]"
        if kind == "RefString":
            return self.s(value.value)
        if kind == "RefInt":
            return self.int_literal(value.value)
        if kind == "RefFloat":
            return self.float_literal(value.value)
        if kind == "RefBytes":
            return f"b@{value.value}"
        if kind == "InlineBool":
            return "true" if value.value else "false"
        if kind == "RefFun":
            return f"f@{value.value}"
        if kind == "RefGlobal":
            return f"g@{value.value}"
        if kind == "RefType":
            return f"t@{value.value}"
        if kind == "JumpOffset":
            target = index + value.value + 1
            return f"L{target}" if 0 <= target <= nops else str(value.value)
        if kind == "JumpOffsets":
            return (
                "["
                + ", ".join(self._operand(v, "JumpOffset", index, labels, nops) for v in value.value)
                + "]"
            )
        return str(value.value)

    def _write_function(self, func: Function) -> None:
        code, out = self.code, self.out
        try:
            name = code.full_func_name(func)
        except Exception:
            name = "<none>"
        comment = f"  # {name}" if name != "<none>" else ""
        out.append("")
        out.append(f".f@{func.findex.value}{comment}")
        out.append(f"    .type t@{func.type.value}")
        out.append("    .regs" + "".join(f" t@{r.value}" for r in func.regs))
        if func.has_debug and func.assigns:
            out.append("    .assigns")
            out.extend(f"        {self.s(name.value)} {pos.value}" for name, pos in func.assigns)
        out.append("    .ops")

        nops = len(func.ops)
        labels: Set[int] = set()
        for i, op in enumerate(func.ops):
            for key, kind in opcodes[cast(str, op.op)].items():
                if kind == "JumpOffset":
                    labels.add(i + op.df[key].value + 1)
                elif kind == "JumpOffsets":
                    labels.update(i + v.value + 1 for v in op.df[key].value)
        labels = {t for t in labels if 0 <= t <= nops}

        positions = func.debuginfo.value if func.has_debug and func.debuginfo else None
        current = (-1, 0)
        for i, op in enumerate(func.ops):
            if i in labels:
                out.append(f"        .label L{i}")
            name = cast(str, op.op)
            operands = ", ".join(
                self._operand(op.df[key], kind, i, labels, nops) for key, kind in opcodes[name].items()
            )
            text = f"{name} {operands}" if operands else name
            if positions is not None:
                ref = positions[i]
                if (ref.value, ref.line) != current:
                    current = (ref.value, ref.line)
                    text += f"  @{ref.value}:{ref.line}"
            out.append("        " + text.rstrip())
        if nops in labels:
            out.append(f"        .label L{nops}")


def to_hlasm(code: Bytecode) -> str:
    """
    Writes a whole bytecode image as `.hlasm` source. Assembling the result with `AsmFile`
    reproduces the image byte for byte.
    """
    code.require_executable("write executable bytecode as .hlasm")
    return _HlasmWriter(code).write()


class X86AsmError(Exception):
    pass


_LABEL_RE = re.compile(r"^([A-Za-z_.$][\w.$]*):$")
_DATA_RE = re.compile(r"^(times|db|dd|dq)\b(.*)$", re.IGNORECASE)
_RIP_RE = re.compile(r"\[\s*rip\s*((?:[+-])[^\]]*)?\]", re.IGNORECASE)
_SIZE_PTR_RE = re.compile(r"\b(byte|word|dword|qword)\s+\[", re.IGNORECASE)
_EXPR_SAFE_RE = re.compile(r"^[0-9xXa-fA-F\s+\-()]+$")

_WIDTHS = {"db": 1, "dd": 4, "dq": 8}


def _eval_expr(expr: str) -> int:
    expr = expr.strip()
    if not expr or not _EXPR_SAFE_RE.match(expr):
        raise X86AsmError(
            f"Cannot evaluate expression '{expr}' (only integer constants, + and - are allowed)"
        )
    try:
        return int(eval(expr, {"__builtins__": {}}, {}))
    except Exception as e:
        raise X86AsmError(f"Failed to evaluate expression '{expr}': {e}") from e


def _data_bytes(line: str) -> bytes:
    """Handles `db/dw/dq a, b, ...` and `times N db|dd|dq v` without keystone."""
    m = _DATA_RE.match(line)
    assert m is not None
    op = m.group(1).lower()
    rest = m.group(2).strip()
    count = 1
    if op == "times":
        m2 = re.match(r"^(.+?)\s+(db|dd|dq)\s+(.+)$", rest, re.IGNORECASE)
        if not m2:
            raise X86AsmError(f"Malformed data directive '{line}' (expected 'times N db|dd|dq value')")
        count = _eval_expr(m2.group(1))
        op = m2.group(2).lower()
        rest = m2.group(3)
    width = _WIDTHS[op]
    out = bytearray()
    for part in rest.split(","):
        if not part.strip():
            continue
        value = _eval_expr(part)
        out += int(value & ((1 << (width * 8)) - 1)).to_bytes(width, "little")
    return bytes(out) * count


def _parse_x86_items(source: str) -> List[Tuple[str, object]]:
    """Splits source into ('label', name) | ('data', bytes) | ('insn', text) items."""
    items: List[Tuple[str, object]] = []
    for raw in source.splitlines():
        line = raw.strip()
        if not line:
            continue
        label = _LABEL_RE.match(line)
        if label:
            items.append(("label", label.group(1)))
            continue
        if _DATA_RE.match(line):
            items.append(("data", _data_bytes(line)))
            continue
        # keystone 0.9.2 chokes on 'dword [r]' but accepts 'dword ptr [r]'
        line = _SIZE_PTR_RE.sub(lambda m: f"{m.group(1)} ptr [", line)
        items.append(("insn", line))
    return items


def _ks() -> Any:
    try:
        from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # type: ignore[import-untyped]
    except ImportError as e:
        raise X86AsmError(
            "X86 mnemonic assembly requires keystone-engine. "
            "Install it with `pip install keystone-engine` or `pip install crashlink[extras]`."
        ) from e
    return Ks(KS_ARCH_X86, KS_MODE_64)


def _ks_asm(ks: Any, text: str, addr: int) -> bytes:
    try:
        encoding, _ = ks.asm(text, addr=addr)
    except Exception as e:
        raise X86AsmError(f"Failed to assemble '{text}': {e}") from e
    if encoding is None:
        raise X86AsmError(f"Failed to assemble '{text}' (keystone returned no encoding)")
    return bytes(encoding)


def _cs() -> Any:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # noqa: F401
    except ImportError as e:
        raise X86AsmError(
            "X86 disassembly requires capstone. Install it with `pip install capstone` or `pip install crashlink[extras]`."
        ) from e
    return Cs(CS_ARCH_X86, CS_MODE_64)


def disassemble_x86(data: bytes, addr: int = 0) -> List[Tuple[int, int, str]]:
    """
    Disassembles raw x86-64 bytes into a list of (offset, size, text) tuples, one per
    decoded instruction. Trailing bytes that don't form a complete instruction are
    reported as a single `db 0x..., ...` entry covering the remainder.
    """
    cs = _cs()
    out: List[Tuple[int, int, str]] = []
    consumed = 0
    for insn in cs.disasm(data, addr):
        offset = insn.address - addr
        out.append((offset, insn.size, f"{insn.mnemonic} {insn.op_str}".strip()))
        consumed = offset + insn.size
    if consumed < len(data):
        rest = data[consumed:]
        out.append((consumed, len(rest), "db " + ", ".join(f"0x{b:02X}" for b in rest)))
    return out


def _substitute_labels(text: str, labels: Dict[str, int]) -> str:
    for name, offset in labels.items():
        text = re.sub(rf"\b{re.escape(name)}\b", str(offset), text)
    return text


def _assemble_insn(ks: Any, text: str, addr: int, labels: Dict[str, int]) -> bytes:
    text = _substitute_labels(text, labels)
    rip = _RIP_RE.search(text)
    if rip:
        # keystone encodes [rip+N] with N as the literal displacement, ignoring addr,
        # so compute the real displacement ourselves. The instruction length is
        # independent of the displacement value (always disp32), so probe first.
        target = _eval_expr(rip.group(1) or "0")
        probe = _ks_asm(ks, _RIP_RE.sub("[rip+0]", text), addr)
        disp = target - (addr + len(probe))
        final = _RIP_RE.sub(f"[rip{disp:+d}]", text)
        encoded = _ks_asm(ks, final, addr)
        if len(encoded) != len(probe):
            raise X86AsmError(f"Instruction '{text}' changed size when resolving [rip] displacement")
        return encoded
    # branches take an absolute target which keystone encodes relative to addr
    return _ks_asm(ks, text, addr)


def assemble_x86(source: str) -> bytes:
    """
    Assembles an x86-64 source block (one instruction or label per line) into bytes.

    Keystone has no symbol resolution, so labels are handled with a small fixpoint
    loop: every line is assembled individually with `ks.asm(addr=<offset>)` so
    relative branches are encoded against their real address, `[rip+label]`
    displacements are computed manually (keystone treats `[rip+N]` as a literal
    displacement), and the process repeats until instruction sizes stabilise
    (short vs. near jumps).

    Supported extensions over plain keystone input:
      - labels (`name:` on their own line), usable in branches and `[rip+label]`
      - data directives: `db/dd/dq v, ...` and `times N db|dd|dq v`
      - `dword [r]` style size annotations (rewritten to `dword ptr [r]`)
    """
    ks = _ks()
    items = _parse_x86_items(source)
    names = [cast(str, name) for kind, name in items if kind == "label"]
    if len(names) != len(set(names)):
        raise X86AsmError("Duplicate label in X86 block")

    # Start with labels far away so every label-dependent instruction takes its
    # largest encoding, then shrink to a fixpoint (shrinking is monotonic, so
    # this always converges for real-world blocks).
    labels: Dict[str, int] = {name: 0x7FFF0000 for name in names}
    for _ in range(8):
        offset = 0
        new_labels: Dict[str, int] = {}
        for kind, payload in items:
            if kind == "label":
                new_labels[cast(str, payload)] = offset
                continue
            if kind == "data":
                size = len(cast(bytes, payload))
            else:
                size = len(_assemble_insn(ks, cast(str, payload), offset, labels))
            offset += size
        if new_labels == labels:
            break
        labels = new_labels
    else:
        raise X86AsmError("X86 block failed to converge (unstable instruction sizes)")

    out = bytearray()
    offset = 0
    for kind, payload in items:
        if kind == "label":
            continue
        if kind == "data":
            chunk = cast(bytes, payload)
        else:
            chunk = _assemble_insn(ks, cast(str, payload), offset, labels)
        out += chunk
        offset += len(chunk)
    return bytes(out)


__all__ = [
    "AsmError",
    "AsmValue",
    "AsmValueStr",
    "AsmFile",
    "AsmSection",
    "assemble_x86",
    "disassemble_x86",
    "to_hlasm",
    "X86AsmError",
]
