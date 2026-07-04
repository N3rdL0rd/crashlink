"""
Prettier HashLink bytecode notation.
"""

from __future__ import annotations

import re
from abc import ABC
from dataclasses import dataclass, field
from typing import Any, Dict, List

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
            if parts[0] in name_to_def:
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
                ops = []
                for op in ops_section.value:
                    if isinstance(op, AsmValueStr):
                        ops.append(self._opcode(op.value))
                    else:
                        raise SyntaxError("Operation must be a string!")

                func.ops = ops
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


__all__ = ["AsmValue", "AsmValueStr", "AsmFile", "AsmSection"]
