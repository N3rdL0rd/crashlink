"""
Core classes.
"""

import ctypes
import struct
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from tqdm import tqdm

    USE_TQDM = True
except ImportError:
    USE_TQDM = False

from .errors import FailedSerialisation, InvalidOpCode, MalformedBytecode, NoMagic
from .globals import dbg_print, tell
from .opcodes import opcodes


class Serialisable:
    def __init__(self):
        self.value: Any = None
        raise NotImplementedError(
            "Serialisable is an abstract class and should not be instantiated."
        )

    def deserialise(self, f, *args, **kwargs) -> "Serialisable":
        raise NotImplementedError("deserialise is not implemented for this class.")

    def serialise(self) -> bytes:
        raise NotImplementedError("serialise is not implemented for this class.")

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)

    def __eq__(self, other) -> bool:
        return self.value == other.value

    def __ne__(self, other) -> bool:
        return self.value != other.value

    def __lt__(self, other) -> bool:
        return self.value < other.value


class RawData(Serialisable):
    """
    A block of raw data.
    """

    def __init__(self, length: int):
        self.value = b""
        self.length = length

    def deserialise(self, f) -> "RawData":
        self.value = f.read(self.length)
        return self

    def serialise(self) -> bytes:
        return self.value


class SerialisableInt(Serialisable):
    """
    Integer of the specified byte length.
    """

    def __init__(self):
        self.value = -1
        self.length = 4
        self.byteorder = "little"
        self.signed = False

    def deserialise(
        self, f, length: int = 4, byteorder: str = "little", signed: bool = False
    ) -> "SerialisableInt":
        self.length = length
        self.byteorder = byteorder
        self.signed = signed
        bytes = f.read(length)
        if all(b == 0 for b in bytes):
            self.value = 0
            return self
        while bytes[-1] == 0:
            bytes = bytes[:-1]
        self.value = int.from_bytes(bytes, byteorder, signed=signed)
        return self

    def serialise(self) -> bytes:
        return self.value.to_bytes(self.length, self.byteorder, signed=self.signed)


class SerialisableF64(Serialisable):
    """
    A standard 64-bit float.
    """

    def __init__(self):
        self.value = 0.0

    def deserialise(self, f) -> "SerialisableF64":
        self.value = struct.unpack("<d", f.read(8))[0]
        return self

    def serialise(self) -> bytes:
        return struct.pack("<d", self.value)


class VarInt(Serialisable):
    def __init__(self, value: int = 0):
        self.value = value

    def deserialise(self, f) -> "VarInt":
        # Read first byte to determine format
        b = int.from_bytes(f.read(1), "big")

        # Single byte format (0xxxxxxx)
        if not (b & 0x80):
            self.value = b
            return self

        # Two byte format (10xxxxxx)
        if not (b & 0x40):
            second = int.from_bytes(f.read(1), "big")

            # Combine bytes and handle sign
            self.value = ((b & 0x1F) << 8) | second
            if b & 0x20:
                self.value = -self.value
            return self

        # Four byte format (11xxxxxx)
        remaining = int.from_bytes(f.read(3), "big")

        # Combine all bytes and handle sign
        self.value = ((b & 0x1F) << 24) | remaining
        if b & 0x20:
            self.value = -self.value
        return self

    def serialise(self) -> bytes:
        if self.value < 0:
            value = -self.value
            if value < 0x2000:  # 13 bits
                return bytes([(value >> 8) | 0xA0, value & 0xFF])
            if value >= 0x20000000:
                raise MalformedBytecode("value can't be >= 0x20000000")
            # Optimized 4-byte case
            return bytes(
                [
                    (value >> 24) | 0xE0,
                    (value >> 16) & 0xFF,
                    (value >> 8) & 0xFF,
                    value & 0xFF,
                ]
            )

        if self.value < 0x80:  # 7 bits
            return bytes([self.value])
        if self.value < 0x2000:  # 13 bits
            return bytes([(self.value >> 8) | 0x80, self.value & 0xFF])
        if self.value >= 0x20000000:
            raise MalformedBytecode("value can't be >= 0x20000000")
        # Optimized 4-byte case
        return bytes(
            [
                (self.value >> 24) | 0xC0,
                (self.value >> 16) & 0xFF,
                (self.value >> 8) & 0xFF,
                self.value & 0xFF,
            ]
        )


class fIndex(VarInt):
    """
    Abstract class based on VarInt to represent a distinct function index instead of just an arbitrary number.
    """

    def resolve(self, code: "Bytecode") -> "Function":
        for function in code.functions:
            if function.findex.value == self.value:
                return function
        raise MalformedBytecode(f"Function index {self.value} not found.")


class tIndex(VarInt):
    """
    Abstract class based on VarInt to represent a distinct type by index instead of an arbitrary number.
    """

    def resolve(self, code: "Bytecode") -> "Type":
        return code.types[self.value]


class gIndex(VarInt):
    """
    Global index reference, based on VarInt.
    """

    def resolve(self, code: "Bytecode") -> "Type":
        return code.global_types[self.value].resolve(code)


class strRef(VarInt):
    """
    Abstract class to represent a string index.
    """

    def resolve(self, code: "Bytecode") -> str:
        return code.strings.value[self.value]


class intRef(VarInt):
    def resolve(self, code: "Bytecode") -> SerialisableInt:
        return code.ints[self.value]


class floatRef(VarInt):
    def resolve(self, code: "Bytecode") -> SerialisableF64:
        return code.floats[self.value]


class bytesRef(VarInt):
    def resolve(self, code: "Bytecode") -> bytes:
        return code.bytes.value[self.value]


class fieldRef(VarInt):
    """
    Abstract class to represent a field index.
    """

    def resolve(self, code: "Bytecode", obj: "Obj") -> "Field":
        fields = obj.resolve_fields(code)
        return fields[self.value]


class Reg(VarInt):
    """
    Abstract class to represent a register index in a function.
    """

    def resolve(self, code: "Bytecode") -> "Type":
        return code.types[self.value]


class InlineBool(Serialisable):
    def __init__(self):
        self.varint = VarInt()
        self.value: Optional[bool] = False

    def deserialise(self, f) -> "InlineBool":
        self.varint.deserialise(f)
        self.value = bool(self.varint.value)
        return self

    def serialise(self) -> bytes:
        self.varint.value = int(self.value)
        return self.varint.serialise()


class VarInts(Serialisable):
    """
    List of VarInts.
    """

    def __init__(self):
        self.n = VarInt()
        self.value: List[VarInt] = []

    def deserialise(self, f) -> "VarInts":
        self.n.deserialise(f)
        for _ in range(self.n.value):
            self.value.append(VarInt().deserialise(f))
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [self.n.serialise(), b"".join([value.serialise() for value in self.value])]
        )


class Regs(Serialisable):
    """
    List of Regs.
    """

    def __init__(self):
        self.n = VarInt()
        self.value: List[Reg] = []

    def deserialise(self, f) -> "Regs":
        self.n.deserialise(f)
        for _ in range(self.n.value):
            self.value.append(Reg().deserialise(f))
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [self.n.serialise(), b"".join([value.serialise() for value in self.value])]
        )


def fmt_bytes(bytes: int) -> str:
    if bytes < 0:
        raise MalformedBytecode("Bytes cannot be negative.")

    size_units = ["B", "Kb", "Mb", "Gb", "Tb"]
    index = 0

    while bytes >= 1000 and index < len(size_units) - 1:
        bytes /= 1000
        index += 1

    return f"{bytes:.1f}{size_units[index]}"


class StringsBlock(Serialisable):
    def __init__(self):
        self.length = SerialisableInt()
        self.length.length = 4
        self.value: List[str] = []
        self.lengths: List[int] = []
        self.embedded_lengths: List[VarInt] = []

    def deserialise(self, f) -> "StringsBlock":
        self.length.deserialise(f, length=4)
        strings_size = self.length.value
        dbg_print(f"Found {fmt_bytes(strings_size)} of strings")
        strings_data: bytes = f.read(strings_size)

        index = 0
        while index < strings_size:
            string_length = 0
            while (
                index + string_length < strings_size
                and strings_data[index + string_length] != 0
            ):
                string_length += 1

            if index + string_length >= strings_size:
                raise MalformedBytecode("Invalid string: no null terminator found")

            string = strings_data[index : index + string_length].decode(
                "utf-8", errors="surrogateescape"
            )
            self.value.append(string)
            self.lengths.append(string_length)

            index += string_length + 1  # Skip the null terminator

        for _ in self.value:
            self.embedded_lengths.append(VarInt().deserialise(f))

        return self

    def serialise(self) -> bytes:
        strings_data = b""
        for string in self.value:
            strings_data += string.encode("utf-8", errors="surrogateescape") + b"\x00"
        self.length.value = len(strings_data)
        self.lengths = [len(string) for string in self.value]
        self.embedded_lengths = [VarInt(length) for length in self.lengths]
        return b"".join(
            [
                self.length.serialise(),
                strings_data,
                b"".join([i.serialise() for i in self.embedded_lengths]),
            ]
        )


class BytesBlock(Serialisable):
    def __init__(self):
        self.size = SerialisableInt()
        self.size.length = 4
        self.value: List[bytes] = []
        self.nbytes = 0

    def deserialise(self, f, nbytes: int) -> "BytesBlock":
        self.nbytes = nbytes
        self.size.deserialise(f, length=4)
        raw = f.read(self.size.value)
        positions: List[VarInt] = []
        for _ in range(nbytes):
            pos = VarInt()
            pos.deserialise(f)
            positions.append(pos)
        positions = [pos.value for pos in positions]
        for i in range(len(positions)):
            start = positions[i]
            end = positions[i + 1] if i + 1 < len(positions) else len(raw)
            self.value.append(raw[start:end])  # Append the extracted byte string
        return self

    def serialise(self) -> bytes:
        raw_data = b"".join(self.value)
        self.size.value = len(raw_data)
        size_serialised = self.size.serialise()
        positions = []
        current_pos = 0
        for byte_str in self.value:
            positions.append(VarInt(current_pos))
            current_pos += len(byte_str)
        positions_serialised = b"".join([pos.serialise() for pos in positions])
        return size_serialised + raw_data + positions_serialised


class TypeDef(Serialisable):
    """
    Abstract class for all type definition fields.
    """


class _NoDataType(TypeDef):
    """
    Base typedef for types with no data.
    """

    def __init__(self):
        pass

    def deserialise(self, f) -> "_NoDataType":
        return self

    def serialise(self) -> bytes:
        return b""


class Void(_NoDataType):
    pass


class U8(_NoDataType):
    pass


class U16(_NoDataType):
    pass


class I32(_NoDataType):
    pass


class I64(_NoDataType):
    pass


class F32(_NoDataType):
    pass


class F64(_NoDataType):
    pass


class Bool(_NoDataType):
    pass


class Bytes(_NoDataType):
    pass


class Dyn(_NoDataType):
    pass


class Fun(TypeDef):
    def __init__(self):
        self.nargs = VarInt()
        self.args: List[tIndex] = []
        self.ret = tIndex()

    def deserialise(self, f) -> "Fun":
        self.nargs.deserialise(f)
        for _ in range(self.nargs.value):
            self.args.append(tIndex().deserialise(f))
        self.ret.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [
                self.nargs.serialise(),
                b"".join([idx.serialise() for idx in self.args]),
                self.ret.serialise(),
            ]
        )


class Field(Serialisable):
    def __init__(self):
        self.name = strRef()
        self.type = tIndex()

    def deserialise(self, f) -> "Field":
        self.name.deserialise(f)
        self.type.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return b"".join([self.name.serialise(), self.type.serialise()])


class Proto(Serialisable):
    def __init__(self):
        self.name = strRef()
        self.findex = fIndex()
        self.pindex = VarInt()  # unknown use

    def deserialise(self, f) -> "Proto":
        self.name.deserialise(f)
        self.findex.deserialise(f)
        self.pindex.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [self.name.serialise(), self.findex.serialise(), self.pindex.serialise()]
        )


class Binding(Serialisable):
    def __init__(self):
        self.field = fieldRef()
        self.findex = fIndex()

    def deserialise(self, f) -> "Binding":
        self.field.deserialise(f)
        self.findex.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return b"".join([self.field.serialise(), self.findex.serialise()])


class Obj(TypeDef):
    def __init__(self):
        self.name = strRef()
        self.super = tIndex()
        self._global = gIndex()
        self.nfields = VarInt()
        self.nprotos = VarInt()
        self.nbindings = VarInt()
        self.fields: List[Field] = []
        self.protos: List[Proto] = []
        self.bindings: List[Binding] = []

    def deserialise(self, f) -> "Obj":
        self.name.deserialise(f)
        self.super.deserialise(f)
        self._global.deserialise(f)
        self.nfields.deserialise(f)
        self.nprotos.deserialise(f)
        self.nbindings.deserialise(f)
        for _ in range(self.nfields.value):
            self.fields.append(Field().deserialise(f))
        for _ in range(self.nprotos.value):
            self.protos.append(Proto().deserialise(f))
        for _ in range(self.nbindings.value):
            self.bindings.append(Binding().deserialise(f))
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [
                self.name.serialise(),
                self.super.serialise(),
                self._global.serialise(),
                self.nfields.serialise(),
                self.nprotos.serialise(),
                self.nbindings.serialise(),
                b"".join([field.serialise() for field in self.fields]),
                b"".join([proto.serialise() for proto in self.protos]),
                b"".join([binding.serialise() for binding in self.bindings]),
            ]
        )

    def resolve_fields(self, code: "Bytecode") -> List[Field]:
        # field references are relative to the entire class hierarchy - for instance:
        # class A {
        #     var a: Int;
        # }
        # class B extends A {
        #     var b: Int;
        # }
        # where a is field 0 and b is field 1
        if self.super.value < 0:  # no superclass
            return self.fields
        fields = []
        visited_types = set()
        current_type = self
        while current_type:
            if id(current_type) in visited_types:
                raise ValueError("Cyclic inheritance detected in class hierarchy.")
            visited_types.add(id(current_type))
            fields = current_type.fields + fields
            if current_type.super.value < 0:
                current_type = None
            else:
                current_type: Optional[Obj] = current_type.super.resolve(
                    code
                ).definition
        return fields


class Array(_NoDataType):
    pass


class TypeType(_NoDataType):
    pass


class Ref(TypeDef):
    def __init__(self):
        self.type = tIndex()

    def deserialise(self, f) -> "Ref":
        self.type.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return self.type.serialise()


class Virtual(TypeDef):
    def __init__(self):
        self.nfields = VarInt()
        self.fields: List[Field] = []

    def deserialise(self, f) -> "Virtual":
        self.nfields.deserialise(f)
        for _ in range(self.nfields.value):
            self.fields.append(Field().deserialise(f))
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [
                self.nfields.serialise(),
                b"".join([field.serialise() for field in self.fields]),
            ]
        )


class DynObj(_NoDataType):
    pass


class Abstract(TypeDef):
    def __init__(self):
        self.name = strRef()

    def deserialise(self, f) -> "Abstract":
        self.name.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return self.name.serialise()


class EnumConstruct(Serialisable):
    def __init__(self):
        self.name = strRef()
        self.nparams = VarInt()
        self.params: List[tIndex] = []

    def deserialise(self, f) -> "EnumConstruct":
        self.name.deserialise(f)
        self.nparams.deserialise(f)
        for _ in range(self.nparams.value):
            self.params.append(tIndex().deserialise(f))
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [
                self.name.serialise(),
                self.nparams.serialise(),
                b"".join([param.serialise() for param in self.params]),
            ]
        )


class Enum(TypeDef):
    def __init__(self):
        self.name = strRef()
        self._global = gIndex()
        self.nconstructs = VarInt()
        self.constructs: List[EnumConstruct] = []

    def deserialise(self, f) -> "Enum":
        self.name.deserialise(f)
        self._global.deserialise(f)
        self.nconstructs.deserialise(f)
        for _ in range(self.nconstructs.value):
            self.constructs.append(EnumConstruct().deserialise(f))
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [
                self.name.serialise(),
                self._global.serialise(),
                self.nconstructs.serialise(),
                b"".join([construct.serialise() for construct in self.constructs]),
            ]
        )


class Null(TypeDef):
    def __init__(self):
        self.type = tIndex()

    def deserialise(self, f) -> "Null":
        self.type.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return self.type.serialise()


class Method(Fun):
    pass


class Struct(Obj):
    pass


class Packed(TypeDef):
    def __init__(self):
        self.inner = tIndex()

    def deserialise(self, f) -> "Packed":
        self.inner.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return self.inner.serialise()


class Type(Serialisable):
    # fmt: off
    TYPEDEFS: List[TypeDef] = [
        Void,     # 0, no data
        U8,       # 1, no data
        U16,      # 2, no data
        I32,      # 3, no data
        I64,      # 4, no data
        F32,      # 5, no data
        F64,      # 6, no data
        Bool,     # 7, no data
        Bytes,    # 8, no data
        Dyn,      # 9, no data
        Fun,      # 10
        Obj,      # 11
        Array,    # 12, no data
        TypeType, # 13, no data
        Ref,      # 14
        Virtual,  # 15
        DynObj,   # 16, no data
        Abstract, # 17
        Enum,     # 18
        Null,     # 19
        Method,   # 20
        Struct,   # 21
        Packed,   # 22
    ]
    # fmt: on

    def __init__(self):
        self.kind = SerialisableInt()
        self.kind.length = 1
        self.definition: Optional[TypeDef] = None

    def deserialise(self, f) -> "Type":
        # dbg_print(f"Type @ {tell(f)}")
        self.kind.deserialise(f, length=1)
        try:
            self.TYPEDEFS[self.kind.value]
            _def = self.TYPEDEFS[self.kind.value]()
            self.definition = _def.deserialise(f)
        except IndexError:
            raise MalformedBytecode(f"Invalid type kind found @{tell(f)}")
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [
                self.kind.serialise(),
                self.definition.serialise() if self.definition else b"",
            ]
        )


class Native(Serialisable):
    def __init__(self):
        self.lib = strRef()
        self.name = strRef()
        self.type = tIndex()
        self.findex = fIndex()

    def deserialise(self, f) -> "Native":
        self.lib.deserialise(f)
        self.name.deserialise(f)
        self.type.deserialise(f)
        self.findex.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [
                self.lib.serialise(),
                self.name.serialise(),
                self.type.serialise(),
                self.findex.serialise(),
            ]
        )


class Opcode(Serialisable):
    """
    Represents an opcode.
    """

    TYPE_MAP: Dict[str, Serialisable] = {
        "Reg": Reg,
        "Regs": Regs,
        "RefInt": intRef,
        "RefFloat": floatRef,
        "InlineBool": InlineBool,
        "RefBytes": bytesRef,
        "RefString": strRef,
        "RefFun": fIndex,
        "RefField": fieldRef,
        "RefGlobal": gIndex,
        "JumpOffset": VarInt,
        "JumpOffsets": VarInts,
        "RefType": tIndex,
        "RefEnumConstant": VarInt,
        "RefEnumConstruct": VarInt,
        "InlineInt": VarInt,
    }

    def __init__(self):
        self.code = VarInt()
        self.op = None
        self.definition = {}

    def deserialise(self, f) -> "Opcode":
        # dbg_print(f"Deserialising opcode at {tell(f)}... ", end="")
        self.code.deserialise(f)
        # dbg_print(f"{self.code.value}... ", end="")
        try:
            _def = opcodes[list(opcodes.keys())[self.code.value]]
        except IndexError:
            # dbg_print()
            raise InvalidOpCode(f"Unknown opcode at {tell(f)}")
        for param, _type in _def.items():
            if _type in self.TYPE_MAP:
                self.definition[param] = self.TYPE_MAP[_type]().deserialise(f)
                continue
            raise InvalidOpCode(
                f"Invalid opcode definition for {param, _type} at {tell(f)}"
            )
        self.op = list(opcodes.keys())[self.code.value]
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [
                self.code.serialise(),
                b"".join(
                    [
                        definition.serialise()
                        for name, definition in self.definition.items()
                    ]
                ),
            ]
        )


def read_u8(f) -> int:
    return int.from_bytes(f.read(1), byteorder="little", signed=False)


def write_u8(f, val: int) -> None:
    try:
        f.write(val.to_bytes(1, byteorder="little", signed=False))
    except OverflowError:
        raise FailedSerialisation(f"Overflow when writing u8 {val} @ {tell(f)}")


class fileRef(int):
    def resolve(self, code: "Bytecode") -> str:
        return code.debugfiles.value[self]


class DebugInfo(Serialisable):
    def __init__(self):
        self.debug_info: List[Tuple[fileRef, int]] = []  # file index, line number

    def deserialise(self, f, nops: int) -> "DebugInfo":
        tmp = []
        currfile: int = -1
        currline: int = 0
        i = 0
        while i < nops:
            c = ctypes.c_uint8(ord(f.read(1))).value
            if c & 1 != 0:
                c >>= 1
                currfile = (c << 8) | ctypes.c_uint8(ord(f.read(1))).value
            elif c & 2 != 0:
                delta = c >> 6
                count = (c >> 2) & 15
                while count > 0:
                    count -= 1
                    tmp.append((fileRef(currfile), currline))
                    i += 1
                currline += delta
            elif c & 4 != 0:
                currline += c >> 3
                tmp.append((fileRef(currfile), currline))
                i += 1
            else:
                b2 = ctypes.c_uint8(ord(f.read(1))).value
                b3 = ctypes.c_uint8(ord(f.read(1))).value
                currline = (c >> 3) | (b2 << 5) | (b3 << 13)
                tmp.append((fileRef(currfile), currline))
                i += 1
        self.debug_info = tmp
        return self

    def flush_repeat(
        self, w: BytesIO, curpos: ctypes.c_size_t, rcount: ctypes.c_size_t, pos: int
    ):
        """Helper function to handle repeat encoding."""
        if rcount.value > 0:
            if rcount.value > 15:
                w.write(ctypes.c_uint8((15 << 2) | 2).value.to_bytes(1, "little"))
                rcount.value -= 15
                self.flush_repeat(w, curpos, rcount, pos)
            else:
                delta = pos - curpos.value
                delta = delta if 0 < delta < 4 else 0
                w.write(
                    ctypes.c_uint8(
                        ((delta << 6) | (rcount.value << 2) | 2)
                    ).value.to_bytes(1, "little")
                )
                rcount.value = 0
                curpos.value += delta

    def serialise(self) -> bytes:
        w = BytesIO()
        curfile = -1
        curpos = ctypes.c_size_t(0)
        rcount = ctypes.c_size_t(0)

        for f, p in self.debug_info:
            if f != curfile:
                self.flush_repeat(w, curpos, rcount, p)
                curfile = f
                w.write(ctypes.c_uint8(((f >> 7) | 1)).value.to_bytes(1, "little"))
                w.write(ctypes.c_uint8(f & 0xFF).value.to_bytes(1, "little"))

            if p != curpos.value:
                self.flush_repeat(w, curpos, rcount, p)

            if p == curpos.value:
                rcount.value += 1
            else:
                delta = p - curpos.value
                if 0 < delta < 32:
                    w.write(
                        ctypes.c_uint8((delta << 3) | 4).value.to_bytes(1, "little")
                    )
                else:
                    w.write(ctypes.c_uint8((p << 3) & 0xFF).value.to_bytes(1, "little"))
                    w.write(ctypes.c_uint8((p >> 5) & 0xFF).value.to_bytes(1, "little"))
                    w.write(
                        ctypes.c_uint8((p >> 13) & 0xFF).value.to_bytes(1, "little")
                    )
                curpos.value = p

        self.flush_repeat(w, curpos, rcount, curpos.value)

        return w.getvalue()


class Function(Serialisable):
    def __init__(self):
        self.type = tIndex()
        self.findex = fIndex()
        self.nregs = VarInt()
        self.nops = VarInt()
        self.regs: List[tIndex] = []
        self.ops: List[Opcode] = []
        self.has_debug: Optional[bool] = None
        self.version: Optional[int] = None
        self.debuginfo: Optional[DebugInfo] = None
        self.nassigns: Optional[VarInt] = None
        self.assigns: Optional[List[Tuple[VarInt, VarInt]]] = None

    def resolve_file(self, code: "Bytecode") -> str:
        if not self.has_debug:
            raise ValueError("Cannot get file from non-debug bytecode!")
        return self.debuginfo.debug_info[0][0].resolve(code)

    def deserialise(self, f, has_debug: bool, version: int) -> "Function":
        self.has_debug = has_debug
        self.version = version
        self.type.deserialise(f)
        self.findex.deserialise(f)
        # dbg_print(f"----- {self.findex.value} ({tell(f)}) -----")
        self.nregs.deserialise(f)
        self.nops.deserialise(f)
        for _ in range(self.nregs.value):
            self.regs.append(tIndex().deserialise(f))  # type: ignore
        for _ in range(self.nops.value):
            self.ops.append(Opcode().deserialise(f))
        if self.has_debug:
            self.debuginfo = DebugInfo().deserialise(f, self.nops.value)
            if self.version >= 3:
                self.nassigns = VarInt().deserialise(f)
                self.assigns = []
                for _ in range(self.nassigns.value):
                    self.assigns.append(
                        (strRef().deserialise(f), VarInt().deserialise(f))
                    )
        return self

    def serialise(self) -> bytes:
        res = b"".join(
            [
                self.type.serialise(),
                self.findex.serialise(),
                self.nregs.serialise(),
                self.nops.serialise(),
                b"".join([reg.serialise() for reg in self.regs]),
                b"".join([op.serialise() for op in self.ops]),
            ]
        )
        if self.has_debug:
            res += self.debuginfo.serialise()
            if self.version >= 3:
                res += self.nassigns.serialise()
                res += b"".join(
                    [
                        b"".join([v.serialise() for v in assign])
                        for assign in self.assigns
                    ]
                )
        return res


class Constant(Serialisable):
    def __init__(self):
        self._global = gIndex()
        self.nfields = VarInt()
        self.fields: List[VarInt] = []

    def deserialise(self, f) -> "Constant":
        self._global.deserialise(f)
        self.nfields.deserialise(f)
        for _ in range(self.nfields.value):
            self.fields.append(VarInt().deserialise(f))
        return self

    def serialise(self) -> bytes:
        return b"".join(
            [
                self._global.serialise(),
                self.nfields.serialise(),
                b"".join([field.serialise() for field in self.fields]),
            ]
        )


class Bytecode(Serialisable):
    def __init__(self):
        self.deserialised = False
        self.magic = RawData(3)
        self.version = SerialisableInt()
        self.version.length = 1
        self.flags = VarInt()
        self.has_debug_info: Optional[bool] = None
        self.nints = VarInt()
        self.nfloats = VarInt()
        self.nstrings = VarInt()
        self.nbytes: Optional[VarInt] = VarInt()
        self.ntypes = VarInt()
        self.nglobals = VarInt()
        self.nnatives = VarInt()
        self.nfunctions = VarInt()
        self.nconstants: Optional[VarInt] = VarInt()
        self.entrypoint = fIndex()

        self.ints: List[SerialisableInt] = []
        self.floats: List[SerialisableF64] = []
        self.strings = StringsBlock()
        self.bytes: Optional[BytesBlock] = BytesBlock()

        self.ndebugfiles: Optional[VarInt] = VarInt()
        self.debugfiles: Optional[StringsBlock] = StringsBlock()

        self.types: List[Type] = []
        self.global_types: List[tIndex] = []
        self.natives: List[Native] = []
        self.functions: List[Function] = []
        self.constants: List[Constant] = []

        self.section_offsets: Dict[str, tuple] = {}

    def find_magic(self, f, magic=b"HLB"):
        buffer_size = 1024
        offset = 0
        while True:
            chunk = f.read(buffer_size)
            if not chunk:
                raise NoMagic("Reached the end of file without finding magic bytes.")
            index = chunk.find(magic)
            if index != -1:
                f.seek(offset + index)
                dbg_print(f"Found bytecode at {tell(f)}... ", end="")
                return
            offset += buffer_size

    @classmethod
    def from_path(cls, path):
        f = open(path, "rb")
        instance = cls().deserialise(f)
        f.close()
        return instance

    def deserialise(self, f, search_magic=True):
        start_time = datetime.now()
        dbg_print("---- Deserialise ----")
        if search_magic:
            dbg_print("Searching for magic...")
            self.find_magic(f)
        self.track_section(f, "magic")
        self.magic.deserialise(f)
        assert self.magic.value == b"HLB", "Incorrect magic found!"
        self.track_section(f, "version")
        self.version.deserialise(f, length=1)
        dbg_print(f"with version {self.version.value}... ", end="")
        self.track_section(f, "flags")
        self.flags.deserialise(f)
        self.has_debug_info = bool(self.flags.value & 1)
        dbg_print(f"debug info: {self.has_debug_info}. ")
        self.track_section(f, "nints")
        self.nints.deserialise(f)
        self.track_section(f, "nfloats")
        self.nfloats.deserialise(f)
        self.track_section(f, "nstrings")
        self.nstrings.deserialise(f)

        if self.version.value >= 5:
            dbg_print(f"Found nbytes (version >= 5) at {tell(f)}")
            self.track_section(f, "nbytes")
            self.nbytes.deserialise(f)
        else:
            self.nbytes = None

        self.track_section(f, "ntypes")
        self.ntypes.deserialise(f)
        self.track_section(f, "nglobals")
        self.nglobals.deserialise(f)
        self.track_section(f, "nnatives")
        self.nnatives.deserialise(f)
        self.track_section(f, "nfunctions")
        self.nfunctions.deserialise(f)

        if self.version.value >= 4:
            dbg_print(f"Found nconstants (version >= 4) at {tell(f)}")
            self.track_section(f, "nconstants")
            self.nconstants.deserialise(f)
        else:
            self.nconstants = None

        self.track_section(f, "entrypoint")
        self.entrypoint.deserialise(f)
        dbg_print(f"Entrypoint: f@{self.entrypoint.value}")

        self.track_section(f, "ints")
        for i in range(self.nints.value):
            self.track_section(f, f"int {i}")
            self.ints.append(SerialisableInt().deserialise(f, length=4))

        self.track_section(f, "floats")
        for i in range(self.nfloats.value):
            self.track_section(f, f"float {i}")
            self.floats.append(SerialisableF64().deserialise(f))

        dbg_print(f"Strings section starts at {tell(f)}")
        self.track_section(f, "strings")
        self.strings.deserialise(f)
        dbg_print(f"Strings section ends at {tell(f)}")
        assert self.nstrings.value == len(
            self.strings.value
        ), "nstrings and len of strings don't match!"

        if self.version.value >= 5:
            dbg_print("Deserialising bytes... >=5")
            self.track_section(f, f"bytes")
            self.bytes.deserialise(f, self.nbytes.value)
        else:
            self.bytes = None

        if self.has_debug_info:
            dbg_print(f"Deserialising debug files... (at {tell(f)})")
            self.track_section(f, f"ndebugfiles")
            self.ndebugfiles.deserialise(f)
            dbg_print(f"Number of debug files: {self.ndebugfiles.value}")
            self.track_section(f, f"debugfiles")
            self.debugfiles.deserialise(f)
        else:
            self.ndebugfiles = None
            self.debugfiles = None

        dbg_print(f"Starting main blobs at {tell(f)}")
        dbg_print(f"Types starting at {tell(f)}")
        self.track_section(f, "types")
        for i in range(self.ntypes.value):
            self.track_section(f, f"type {i}")
            self.types.append(Type().deserialise(f))
        dbg_print(f"Globals starting at {tell(f)}")
        self.track_section(f, "globals")
        for i in range(self.nglobals.value):
            self.track_section(f, f"global {i}")
            self.global_types.append(tIndex().deserialise(f))
        dbg_print(f"Natives starting at {tell(f)}")
        self.track_section(f, "natives")
        for i in range(self.nnatives.value):
            self.track_section(f, f"native {i}")
            self.natives.append(Native().deserialise(f))
        dbg_print(f"Functions starting at {tell(f)}")
        self.track_section(f, "functions")
        if not USE_TQDM:
            for i in range(self.nfunctions.value):
                self.track_section(f, f"function {i}")
                self.functions.append(
                    Function().deserialise(f, self.has_debug_info, self.version.value)
                )
        else:
            for i in tqdm(range(self.nfunctions.value)):
                self.track_section(f, f"function {i}")
                self.functions.append(
                    Function().deserialise(f, self.has_debug_info, self.version.value)
                )
        if self.nconstants is not None:
            dbg_print(f"Constants starting at {tell(f)}")
            self.track_section(f, "constants")
            for i in range(self.nconstants.value):
                self.track_section(f, f"constant {i}")
                self.constants.append(Constant().deserialise(f))
        dbg_print(f"Bytecode end at {tell(f)}.")
        self.deserialised = True
        dbg_print(f"{(datetime.now() - start_time).total_seconds()}s elapsed.")
        return self

    def serialise(self, auto_set_meta: bool = True) -> bytes:
        start_time = datetime.now()
        dbg_print("---- Serialise ----")
        if auto_set_meta:
            dbg_print("Setting meta...")
            self.flags.value = 1 if self.has_debug_info else 0
            self.nints.value = len(self.ints)
            self.nfloats.value = len(self.floats)
            self.nstrings.value = len(self.strings.value)
            if self.version.value >= 5:
                self.nbytes.value = len(self.bytes.value)
            self.ntypes.value = len(self.types)
            self.nglobals.value = len(self.global_types)
            self.nnatives.value = len(self.natives)
            self.nfunctions.value = len(self.functions)
            if self.version.value >= 4:
                self.nconstants.value = len(self.constants)
            if self.has_debug_info:
                self.ndebugfiles.value = len(self.debugfiles.value)
        res = b"".join(
            [
                self.magic.serialise(),
                self.version.serialise(),
                self.flags.serialise(),
                self.nints.serialise(),
                self.nfloats.serialise(),
                self.nstrings.serialise(),
            ]
        )
        dbg_print(f"VarInt block 1 at {hex(len(res))}")
        if self.version.value >= 5:
            res += self.nbytes.serialise()
        res += b"".join(
            [
                self.ntypes.serialise(),
                self.nglobals.serialise(),
                self.nnatives.serialise(),
                self.nfunctions.serialise(),
            ]
        )
        dbg_print(f"VarInt block 2 at {hex(len(res))}")
        if self.version.value >= 4:
            res += self.nconstants.serialise()
        res += self.entrypoint.serialise()
        res += b"".join([i.serialise() for i in self.ints])
        res += b"".join([f.serialise() for f in self.floats])
        res += self.strings.serialise()
        if self.version.value >= 5:
            res += self.bytes.serialise()
        if self.has_debug_info:
            res += b"".join([self.ndebugfiles.serialise(), self.debugfiles.serialise()])
        res += b"".join(
            [
                b"".join([typ.serialise() for typ in self.types]),
                b"".join([typ.serialise() for typ in self.global_types]),
                b"".join([native.serialise() for native in self.natives]),
                b"".join([func.serialise() for func in self.functions]),
                b"".join([constant.serialise() for constant in self.constants]),
            ]
        )
        dbg_print(f"Final size: {hex(len(res))}")
        dbg_print(f"{(datetime.now() - start_time).total_seconds()}s elapsed.")
        return res

    def is_ok(self) -> bool:
        if len(self.ints) != self.nints.value:
            return False

        if len(self.floats) != self.nfloats.value:
            return False

        if len(self.strings.value) != self.nstrings.value:
            return False

        if self.version.value >= 5:
            if self.nbytes is None or self.bytes is None:
                return False
            if len(self.bytes.value) != self.nbytes.value:
                return False

        if len(self.types) != self.ntypes.value:
            return False

        if len(self.global_types) != self.nglobals.value:
            return False

        if len(self.natives) != self.nnatives.value:
            return False

        if len(self.functions) != self.nfunctions.value:
            return False

        if self.version.value >= 4:
            if self.nconstants is None:
                return False
            if len(self.constants) != self.nconstants.value:
                return False

        if self.has_debug_info:
            if self.ndebugfiles is None or self.debugfiles is None:
                return False
            if len(self.debugfiles.value) != self.ndebugfiles.value:
                return False

        return True

    def function(self, id: int) -> Function:
        for function in self.functions:
            if function.findex.value == id:
                return function
        raise IndexError(f"Function f@{id} not found!")

    def track_section(self, f, section_name):
        self.section_offsets[section_name] = f.tell()

    def section_at(self, offset):
        # returns the name of the section at the offset:
        # if the offset is after a section start and before the next section start, it's still in the first section
        for section_name, section_offset in list(
            reversed(self.section_offsets.items())
        ):
            if offset >= section_offset:
                return section_name
        return None
