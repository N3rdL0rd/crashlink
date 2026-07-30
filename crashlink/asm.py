"""
Prettier HashLink bytecode notation.
"""

from __future__ import annotations

import re
from abc import ABC
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, cast

from .core import (
    F32,
    F64,
    GUID,
    I32,
    I64,
    U8,
    U16,
    Array,
    Bool,
    Bytecode,
    Bytes,
    Dyn,
    Fun,
    Function,
    InlineBool,
    Native,
    Opcode,
    Reg,
    Ref,
    ResolvableVarInt,
    SerialisableF64,
    SerialisableInt,
    Type,
    TypeType,
    VarInt,
    Void,
    bytesRef,
    fIndex,
    floatRef,
    gIndex,
    intRef,
    strRef,
    tIndex,
)
from .opcodes import opcodes


@dataclass
class AsmValue(ABC):
    value: Any


class AsmValueStr(AsmValue):
    value: str


@dataclass
class AsmSection(AsmValue):
    name: str = ""
    value: "List[AsmValueStr|AsmSection]" = field(default_factory=list)

    def get(self, subsection_name: str) -> "AsmSection":
        for val in self.value:
            if isinstance(val, AsmSection) and val.name == subsection_name:
                return val
        raise KeyError(f"No subsection '{subsection_name}' found!")


class AsmFile:
    def __init__(self, content: str) -> None:
        self.content = content
        self.raw_sections: Dict[str, AsmSection] = {}
        self.strings: List[str] = []
        self.ints: List[int] = []
        self.floats: List[float] = []
        self._parse()

    @classmethod
    def from_path(cls, path: str) -> "AsmFile":
        with open(path, "r", encoding="utf-8") as file:
            content = file.read()
        return cls(content)

    @staticmethod
    def _strip_comment(line: str) -> str:
        """Strips a trailing `# ...` comment, ignoring '#' characters inside quoted strings."""
        in_quotes = False
        for i, char in enumerate(line):
            if char == '"':
                in_quotes = not in_quotes
            elif char == "#" and not in_quotes:
                return line[:i]
        return line

    def _parse(self) -> None:
        self.content = self.content.replace("    ", "\t")  # for consistency
        lines = self.content.splitlines()
        section_stack: List[AsmSection] = []
        for raw_line in lines:
            line = self._strip_comment(raw_line).rstrip()
            if not line.strip():
                continue
            indent_level = len(line) - len(line.lstrip("\t"))
            # pop extra sections if we decreased the indent level
            while len(section_stack) > indent_level:
                section_stack.pop()
            stripped = line.lstrip("\t")
            if stripped.startswith("."):
                tokens = stripped.split()
                section_name = tokens[0][1:]
                new_section = AsmSection(value=[])
                new_section.name = section_name
                if len(tokens) > 1:
                    for token in tokens[1:]:
                        new_section.value.append(AsmValueStr(token))
                if section_stack:
                    section_stack[-1].value.append(new_section)
                else:
                    self.raw_sections[section_name] = new_section
                section_stack.append(new_section)
            else:
                if not section_stack:
                    raise SyntaxError("Encountered a value outside any section!")
                section_stack[-1].value.append(AsmValueStr(stripped))

    def _add_types(self, code: Bytecode, section: AsmSection) -> None:
        name_to_def = {
            "Void": Void,
            "U8": U8,
            "U16": U16,
            "I32": I32,
            "I64": I64,
            "F32": F32,
            "F64": F64,
            "Bool": Bool,
            "Bytes": Bytes,
            "Dyn": Dyn,
            "Array": Array,
            "Type": TypeType,
            "GUID": GUID,
        }
        def_to_kind = {
            Void: 0,
            U8: 1,
            U16: 2,
            I32: 3,
            I64: 4,
            F32: 5,
            F64: 6,
            Bool: 7,
            Bytes: 8,
            Dyn: 9,
            Array: 12,
            TypeType: 13,
            GUID: 23,
        }
        for val in section.value:
            if not isinstance(val, AsmValueStr):
                continue
            parts = val.value.split()
            if parts[0] == "Ref":
                inner = self._parse_ref(parts[1])
                assert isinstance(inner, tIndex), "Expected a type reference inside Ref!"
                ref = Ref()
                ref.type = inner
                typ = Type()
                typ.kind.value = 14  # Ref
                typ.definition = ref
                code.types.append(typ)
                code.invalidate_proto_field_cache()
            elif parts[0] in name_to_def:
                typedef = name_to_def[parts[0]]
                m_def = typedef()
                typ = Type()
                typ.kind.value = def_to_kind[typedef]
                typ.definition = m_def
                code.types.append(typ)
                code.invalidate_proto_field_cache()
            elif parts[0] == "Fun":
                fun = Fun()
                tokens = re.findall(r"\([^)]*\)|\S+", val.value)
                _, args, _, ret = tokens
                r = self._parse_ref(ret)
                assert isinstance(r, tIndex), "Expected a type reference for return!"
                fun.ret = r
                args_s = args.strip("()").split(",")
                if len(args_s) == 1 and not args_s[0]:
                    fun.args = []
                else:
                    a = [self._parse_ref(arg.strip()) for arg in args.strip("()").split(",")]
                    assert all([isinstance(arg, tIndex) for arg in a]), "Expected a type reference in args!"
                    fun.args = a  # type: ignore
                typ = Type()
                typ.kind.value = 10  # Fun
                typ.definition = fun
                code.types.append(typ)
                code.invalidate_proto_field_cache()

    def _parse_ref(self, val: str) -> ResolvableVarInt:
        if val[1] != "@":
            raise SyntaxError("Expected a reference!")
        match val[0]:  # TODO: float, field support
            case "f":
                return fIndex(int(val[2:]))
            case "t":
                return tIndex(int(val[2:]))
            case "s":
                return strRef(int(val[2:]))
            case "g":
                return gIndex(int(val[2:]))
            case "i":
                return intRef(int(val[2:]))
            case "b":
                return bytesRef(int(val[2:]))
        raise SyntaxError(f"Unknown prefix '{val[0]}'!")

    def _parse_opcode_ref(self, val: str, expected: type) -> Any:
        if val[0] == '"':
            return self._get_str_idx(val[1:-1])
        if val.startswith("reg"):
            return Reg(int(val[3:]))
        if expected is InlineBool and val in ("true", "false"):
            inline_bool = InlineBool()
            inline_bool.value = val == "true"
            return inline_bool

        # Bare numeric literals: jump offsets and other InlineInt-style operands are embedded
        # directly, while RefInt/RefFloat operands are pool references, so the literal gets
        # auto-interned (mirroring how quoted string literals are auto-interned above).
        if re.fullmatch(r"-?\d+", val):
            if expected is intRef:
                return self._get_int_idx(int(val))
            if expected is floatRef:
                return self._get_float_idx(float(val))
            return VarInt(int(val))
        if re.fullmatch(r"-?\d+\.\d+", val) and expected is floatRef:
            return self._get_float_idx(float(val))

        if len(val) > 1 and val[1] == "@":
            match val[0]:  # TODO: field support
                case "f":
                    return fIndex(int(val[2:]))
                case "t":
                    return tIndex(int(val[2:]))
                case "s":
                    return strRef(int(val[2:]))
                case "g":
                    return gIndex(int(val[2:]))
                case "i":
                    return intRef(int(val[2:]))
                case "b":
                    return bytesRef(int(val[2:]))
            raise SyntaxError(f"Unknown prefix '{val[0]}'!")

        raise SyntaxError(f"Could not parse operand '{val}' as a {expected.__name__}!")

    def _get_single_val(self, name: str) -> str:
        if len(self.raw_sections[name].value) != 1:
            raise SyntaxError(f"Expected exactly one value for '{name}'!")
        val = self.raw_sections[name].value[0]
        if isinstance(val, AsmValueStr):
            return val.value
        raise SyntaxError(f"Expected a string value for '{name}'!")

    def _get_str_idx(self, val: str) -> strRef:
        if val not in self.strings:
            self.strings.append(val)
        return strRef(self.strings.index(val))

    def _get_int_idx(self, val: int) -> intRef:
        if val not in self.ints:
            self.ints.append(val)
        return intRef(self.ints.index(val))

    def _get_float_idx(self, val: float) -> floatRef:
        if val not in self.floats:
            self.floats.append(val)
        return floatRef(self.floats.index(val))

    def _validate(self, code: Bytecode) -> None:
        if not code.entrypoint:
            raise SyntaxError("No entrypoint specified!")
        if not code.types:
            raise SyntaxError("No types specified!")
        code.entrypoint.resolve(code)

    def _add_natives(self, code: Bytecode, section: AsmSection) -> None:
        for n in section.value:
            if not isinstance(n, AsmValueStr):
                continue
            parts = n.value.split()
            assert len(parts) == 3, "Incorrect native structure!"
            assert parts[1].startswith("("), f"Unexpected token {parts[1][0]}"
            idx, typ, name = parts
            _idx = self._parse_ref(idx)
            assert isinstance(_idx, fIndex), "Native index must be a function reference!"
            _typ = self._parse_ref(typ.strip("()"))
            assert isinstance(_typ, tIndex), "Native Fun type must be a type reference!"
            lib, name = name.split(".")
            _lib = self._get_str_idx(lib)
            _name = self._get_str_idx(name)
            obj = Native()
            obj.findex = _idx
            obj.lib = _lib
            obj.name = _name
            obj.type = _typ
            code.natives.append(obj)
            code.invalidate_findex_cache()

    def _opcode(self, val: str) -> Opcode:
        def remove_commas_outside_quotes(text: str) -> str:
            result = ""
            in_quotes = False
            for char in text:
                if char == '"':
                    in_quotes = not in_quotes
                if char == "," and not in_quotes:
                    result += " "
                else:
                    result += char
            return result

        val = remove_commas_outside_quotes(val)

        parts = re.findall(r"\"[^\"]*\"|\S+", val)
        assert len(parts) >= 1, "Opcode must have at least one part!"

        op = Opcode()
        name = parts[0]
        assert name in opcodes, f"Unknown opcode '{name}'!"
        op.op = name
        op.df = {}

        for i, (k, v) in enumerate(opcodes[name].items()):
            if i + 1 >= len(parts):
                raise SyntaxError(f"Not enough arguments for opcode {name}, expected {k}")
            typ = Opcode.TYPE_MAP[v]
            parsed = self._parse_opcode_ref(parts[i + 1], typ)
            assert isinstance(parsed, typ), f"Expected type {typ} for argument {k} of opcode {name}, got {type(parsed)}"
            op.df[k] = parsed

        return op

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
        typ = Type()
        typ.kind.value = 10  # Fun
        typ.definition = fun
        code.types.append(typ)
        code.invalidate_proto_field_cache()
        return tIndex(len(code.types) - 1)

    def _make_asm_opcode(self, mode: int, value: int) -> Opcode:
        """Builds a raw `Asm` opcode (see docs/asm for mode semantics)."""
        if not 0 <= value <= 0xFF:
            raise SyntaxError(f"Asm byte value {value} out of range (0-255)!")
        op = Opcode()
        op.op = "Asm"
        op.df = {"mode": VarInt(mode), "value": VarInt(value), "reg": Reg(0)}
        return op

    def _assemble_ops(self, lines: List[str]) -> List[Opcode]:
        """
        Parses `.ops` lines into opcodes, handling the assembly pseudo-ops:

        - `AsmNaked`        -> `Asm 4, 0, reg0`: marks a naked function (raw x86 body)
        - `AsmByte <v>`     -> `Asm 0, <v>, reg0`: emit a single raw byte
        - `X86 <mnemonic>`  -> assembled with keystone-engine into `Asm 0, ...` bytes
        - `<label>:`        -> label for the surrounding X86 block
        """
        ops: List[Opcode] = []
        x86_block: List[str] = []

        def flush_x86() -> None:
            if not x86_block:
                return
            try:
                data = assemble_x86("\n".join(x86_block))
            except X86AsmError as e:
                raise SyntaxError(f"X86 assembly failed: {e}") from e
            for byte in data:
                ops.append(self._make_asm_opcode(0, byte))
            x86_block.clear()

        for line in lines:
            stripped = line.strip()
            if stripped == "X86" or stripped.startswith("X86 "):
                x86_block.append(stripped[3:].strip())
                continue
            if re.fullmatch(r"[A-Za-z_.$][\w.$]*:", stripped):
                x86_block.append(stripped)
                continue
            flush_x86()
            if stripped == "AsmNaked":
                ops.append(self._make_asm_opcode(4, 0))
            elif stripped.startswith("AsmByte"):
                parts = stripped.split()
                if len(parts) != 2:
                    raise SyntaxError("AsmByte expects exactly one byte value!")
                ops.append(self._make_asm_opcode(0, int(parts[1], 0)))
            else:
                ops.append(self._opcode(stripped))
        flush_x86()
        return ops

    def _add_functions(self, code: Bytecode) -> None:
        for section in self.raw_sections.values():
            if section.name.startswith("f@"):
                func = Function()
                returns_section = section.get("returns")
                if isinstance(returns_section.value[0], AsmValueStr):
                    ret = self._parse_ref(returns_section.value[0].value)
                else:
                    raise SyntaxError("Return type must be a string reference!")
                assert isinstance(ret, tIndex), "Return type must be a type reference!"

                findex = self._parse_ref(section.name)
                assert isinstance(findex, fIndex), "Function index must be a function reference!"
                func.findex = findex

                regs_section = section.get("regs")
                regs: List[tIndex] = []
                for reg in regs_section.value:
                    if isinstance(reg, AsmValueStr):
                        res = self._parse_ref(reg.value)
                        assert isinstance(res, tIndex), "Register must be a type index!"
                        regs.append(res)
                    else:
                        raise SyntaxError("Register must be a string reference!")

                assert all(isinstance(r, tIndex) for r in regs), "All registers must be types!"
                func.regs = regs

                # `.args <n>` declares how many of the leading registers are parameters
                # (default 0, i.e. a no-argument function like a typical entrypoint).
                nargs = 0
                try:
                    args_section = section.get("args")
                    if args_section.value and isinstance(args_section.value[0], AsmValueStr):
                        nargs = int(args_section.value[0].value)
                except KeyError:
                    pass
                assert nargs <= len(regs), "More args than declared registers!"
                func.type = self._intern_fun_type(code, regs[:nargs], ret)

                ops_section = section.get("ops")
                raw_ops: List[str] = []
                for op in ops_section.value:
                    if isinstance(op, AsmValueStr):
                        raw_ops.append(op.value)
                    else:
                        raise SyntaxError("Operation must be a string!")
                func.ops = self._assemble_ops(raw_ops)
                func.has_debug = False
                func.version = code.version.value
                code.functions.append(func)
                code.invalidate_findex_cache()

    def _add_strings(self, code: Bytecode) -> None:
        for s in self.strings:
            code.strings.value.append(s)

    def _add_ints(self, code: Bytecode) -> None:
        for n in self.ints:
            si = SerialisableInt()
            si.value = n
            code.ints.append(si)

    def _add_floats(self, code: Bytecode) -> None:
        for n in self.floats:
            sf = SerialisableF64()
            sf.value = n
            code.floats.append(sf)

    def assemble(self) -> Bytecode:
        required = ["version", "types", "entrypoint"]
        for req in required:
            assert req in self.raw_sections
        code = Bytecode.create_empty(
            no_extra_types=True,
            version=int(self._get_single_val("version")),
        )
        self._add_types(code, self.raw_sections["types"])
        e = self._parse_ref(self._get_single_val("entrypoint"))
        assert isinstance(e, fIndex), "Entrypoint must be a function reference!"
        code.entrypoint = e
        if "natives" in self.raw_sections:
            self._add_natives(code, self.raw_sections["natives"])
        self._add_functions(code)
        self._add_strings(code)
        self._add_ints(code)
        self._add_floats(code)
        self._validate(code)
        return code


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
        raise X86AsmError(f"Cannot evaluate expression '{expr}' (only integer constants, + and - are allowed)")
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
            "Install it with `pip install keystone-engine` or `pip install crashlink[x86]`."
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
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # type: ignore[import-untyped]
    except ImportError as e:
        raise X86AsmError(
            "X86 disassembly requires capstone. Install it with `pip install capstone` or `pip install crashlink[x86]`."
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


__all__ = ["AsmValue", "AsmValueStr", "AsmFile", "AsmSection", "assemble_x86", "disassemble_x86", "X86AsmError"]
