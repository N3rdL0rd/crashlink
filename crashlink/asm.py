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
    Native,
    Opcode,
    Reg,
    ResolvableVarInt,
    Type,
    TypeType,
    Void,
    bytesRef,
    fIndex,
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
        self._parse()

    @classmethod
    def from_path(cls, path: str) -> "AsmFile":
        with open(path, "r", encoding="utf-8") as file:
            content = file.read()
        return cls(content)

    def _parse(self) -> None:
        self.content = self.content.replace("    ", "\t")  # for consistency
        lines = self.content.splitlines()
        section_stack: List[AsmSection] = []
        for line in lines:
            if not line.strip() or line.strip().startswith("#"):
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
        }
        for val in section.value:
            print(val.value)
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
            elif parts[0] == "Fun":
                print("Adding Fun...")
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
                typ.definition = m_def
                code.types.append(typ)

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

    def _parse_opcode_ref(self, val: str) -> Any:
        if val[1] != "@":
            if val[0] == '"':
                return self._get_str_idx(val[1:-1])
            elif val.startswith("reg"):
                return Reg(int(val[3:]))
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
            parsed = self._parse_opcode_ref(parts[i + 1])
            assert isinstance(parsed, typ), f"Expected type {typ} for argument {k} of opcode {name}, got {type(parsed)}"
            op.df[k] = parsed

        return op

    def _add_functions(self, code: Bytecode) -> None:
        for section in self.raw_sections.values():
            if section.name.startswith("f@"):
                func = Function()
                returns_section = section.get("returns")
                if isinstance(returns_section.value[0], AsmValueStr):
                    typ = self._parse_ref(returns_section.value[0].value)
                else:
                    raise SyntaxError("Return type must be a string reference!")

                assert isinstance(typ, tIndex), "Return type must be a type reference!"
                func.type = typ
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

    def _add_strings(self, code: Bytecode) -> None:
        for s in self.strings:
            code.strings.value.append(s)

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
        self._validate(code)
        return code


__all__ = ["AsmValue", "AsmValueStr", "AsmFile", "AsmSection"]
