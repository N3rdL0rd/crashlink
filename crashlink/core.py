"""
Core bytecode format definitions.

This module contains the definitions for HashLink bytecode structures, as well as the serialisation
and deserialisation methods for them. You probably don't need to use too much of this file directly,
besides Bytecode, Opcode, and Function. The decompiler will take care of a lot of abstraction for
you.
"""

import ctypes
import struct
from abc import ABC, abstractmethod
from datetime import datetime
from io import BytesIO
from typing import Any, BinaryIO, Dict, List, Literal, Optional, Tuple, TypeVar

T = TypeVar("T", bound="VarInt")  # easier than reimplementing deserialise for each subclass

from .errors import (FailedSerialisation, InvalidOpCode, MalformedBytecode,
                     NoMagic)
from .globals import dbg_print, fmt_bytes, tell
from .opcodes import opcodes

try:
    from tqdm import tqdm

    USE_TQDM = True
except ImportError:
    dbg_print("Could not find tqdm. Progress bars will not be displayed.")
    USE_TQDM = False


class Serialisable(ABC):
    """
    Base class for all serialisable objects.
    """

    @abstractmethod
    def __init__(self) -> None:
        self.value: Any = None

    @abstractmethod
    def deserialise(self, f: BinaryIO | BytesIO, *args: Any, **kwargs: Any) -> "Serialisable":
        pass

    @abstractmethod
    def serialise(self) -> bytes:
        pass

    def __str__(self) -> str:
        try:
            return str(self.value)
        except AttributeError:
            return super().__repr__()

    def __repr__(self) -> str:
        try:
            return str(self.value)
        except AttributeError:
            return super().__repr__()

    def __eq__(self, other: object) -> Any:
        if not isinstance(other, Serialisable):
            return NotImplemented
        return self.value == other.value

    def __ne__(self, other: object) -> Any:
        if not isinstance(other, Serialisable):
            return NotImplemented
        return self.value != other.value

    def __lt__(self, other: object) -> Any:
        if not isinstance(other, Serialisable):
            return NotImplemented
        return self.value < other.value


class RawData(Serialisable):
    """
    A block of raw data.
    """

    def __init__(self, length: int):
        self.value: bytes = b""
        self.length = length

    def deserialise(self, f: BinaryIO | BytesIO) -> "RawData":
        self.value = f.read(self.length)
        return self

    def serialise(self) -> bytes:
        return self.value


class SerialisableInt(Serialisable):
    """
    Integer of the specified byte length.
    """

    def __init__(self) -> None:
        self.value: int = -1
        self.length = 4
        self.byteorder: Literal["little", "big"] = "little"
        self.signed = False

    def deserialise(
        self,
        f: BinaryIO | BytesIO,
        length: int = 4,
        byteorder: Literal["little", "big"] = "little",
        signed: bool = False,
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

    def __init__(self) -> None:
        self.value = 0.0

    def deserialise(self, f: BinaryIO | BytesIO) -> "SerialisableF64":
        self.value = struct.unpack("<d", f.read(8))[0]
        return self

    def serialise(self) -> bytes:
        return struct.pack("<d", self.value)


_struct_short = struct.Struct(">H")  # big-endian unsigned short
_struct_medium = struct.Struct(">I")  # big-endian unsigned int (for 3 bytes)

class VarInt(Serialisable):
    """
    Variable-length integer - can be 1, 2, or 4 bytes.
    """

    def __init__(self, value: int = 0):
        self.value: int = value

    def deserialise(self: T, f: BinaryIO | BytesIO) -> T:
        # Read first byte - keep int.from_bytes for single byte
        b = int.from_bytes(f.read(1), "big")

        # Single byte format (0xxxxxxx)
        if not (b & 0x80):
            self.value = b
            return self

        # Two byte format (10xxxxxx)
        if not (b & 0x40):
            # Read 2 bytes as unsigned short
            second = f.read(1)[0]  # Faster than int.from_bytes for single byte

            # Combine bytes and handle sign
            self.value = ((b & 0x1F) << 8) | second
            if b & 0x20:
                self.value = -self.value
            return self

        # Four byte format (11xxxxxx)
        remaining = _struct_medium.unpack(b"\x00" + f.read(3))[0]

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


class ResolvableVarInt(VarInt, ABC):
    """
    Base class for resolvable VarInts. Call `resolve` to get a direct reference to the object it points to.
    """

    @abstractmethod
    def resolve(self, code: "Bytecode") -> Any:
        """
        Resolve this reference to a specific reference in the bytecode.
        """
        pass


class fIndex(ResolvableVarInt):
    """
    Abstract class based on VarInt to represent a distinct function index instead of just an arbitrary number.
    """

    def resolve(self, code: "Bytecode") -> "Function|Native":
        for function in code.functions:
            if function.findex.value == self.value:
                return function
        for native in code.natives:
            if native.findex.value == self.value:
                return native
        raise MalformedBytecode(f"Function index {self.value} not found.")


class tIndex(ResolvableVarInt):
    """
    Reference to a type in the bytecode.
    """

    def resolve(self, code: "Bytecode") -> "Type":
        return code.types[self.value]


class gIndex(ResolvableVarInt):
    """
    Reference to a global object in the bytecode.
    """

    def resolve(self, code: "Bytecode") -> "Type":
        return code.global_types[self.value].resolve(code)

    def resolve_str(self, code: "Bytecode") -> str:
        return code.const_str(self.value)


class strRef(ResolvableVarInt):
    """
    Reference to a string in the bytecode.
    """

    def resolve(self, code: "Bytecode") -> str:
        return code.strings.value[self.value]


class intRef(ResolvableVarInt):
    """
    Reference to an integer in the bytecode.
    """

    def resolve(self, code: "Bytecode") -> SerialisableInt:
        return code.ints[self.value]


class floatRef(ResolvableVarInt):
    """
    Reference to a float in the bytecode.
    """

    def resolve(self, code: "Bytecode") -> SerialisableF64:
        return code.floats[self.value]


class bytesRef(ResolvableVarInt):
    """
    Reference to a byte string in the bytecode.
    """

    def resolve(self, code: "Bytecode") -> bytes:
        if code.bytes:
            return code.bytes.value[self.value]
        else:
            raise MalformedBytecode("No bytes block found.")


class fieldRef(ResolvableVarInt):
    """
    Reference to a field in an object definition.
    """

    obj: Optional["Obj"] = None

    def resolve(self, code: "Bytecode") -> "Field":
        if self.obj:
            return self.obj.resolve_fields(code)[self.value]
        raise ValueError(
            "Cannot resolve field without context. Try setting `field.obj` to an instance of `Obj`, or use `field.resolve_obj(code, obj)` instead."
        )

    def resolve_obj(self, code: "Bytecode", obj: "Obj") -> "Field":
        self.obj = obj
        return obj.resolve_fields(code)[self.value]


class Reg(ResolvableVarInt):
    """
    Reference to a register in the bytecode.
    """

    def resolve(self, code: "Bytecode") -> "Type":
        return code.types[self.value]


class InlineBool(Serialisable):
    """
    Inline boolean value.
    """

    def __init__(self) -> None:
        self.varint = VarInt()
        self.value: bool = False

    def deserialise(self, f: BinaryIO | BytesIO) -> "InlineBool":
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

    def __init__(self) -> None:
        self.n = VarInt()
        self.value: List[VarInt] = []

    def deserialise(self, f: BinaryIO | BytesIO) -> "VarInts":
        self.n.deserialise(f)
        for _ in range(self.n.value):
            self.value.append(VarInt().deserialise(f))
        return self

    def serialise(self) -> bytes:
        return b"".join([self.n.serialise(), b"".join([value.serialise() for value in self.value])])


class Regs(Serialisable):
    """
    List of references to registers.
    """

    def __init__(self) -> None:
        self.n = VarInt()
        self.value: List[Reg] = []

    def deserialise(self, f: BinaryIO | BytesIO) -> "Regs":
        self.n.deserialise(f)
        for _ in range(self.n.value):
            self.value.append(Reg().deserialise(f))
        return self

    def serialise(self) -> bytes:
        return b"".join([self.n.serialise(), b"".join([value.serialise() for value in self.value])])


class StringsBlock(Serialisable):
    """
    Block of strings in the bytecode. Contains a list of strings and their lengths.
    """

    def __init__(self) -> None:
        self.length = SerialisableInt()
        self.length.length = 4
        self.value: List[str] = []
        self.lengths: List[VarInt] = []

    def deserialise(self, f: BinaryIO | BytesIO, nstrings: int) -> "StringsBlock":
        self.length.deserialise(f, length=4)
        size = self.length.value
        sdata: bytes = f.read(size)
        strings: List[str] = []
        lengths: List[VarInt] = []
        curpos = 0

        for _ in range(nstrings):
            sz = VarInt().deserialise(f)
            # Check if we can read string + null terminator
            if curpos + sz.value + 1 > size:
                raise ValueError("Invalid string")

            # Verify null terminator
            if sdata[curpos + sz.value] != 0:
                raise ValueError("Invalid string")

            str_value = sdata[curpos : curpos + sz.value]
            strings.append(str_value.decode("utf-8", errors="surrogateescape"))
            lengths.append(sz)

            curpos += sz.value + 1  # Move past string and null terminator

        self.value = strings
        self.lengths = lengths
        return self

    def serialise(self) -> bytes:
        strings_data = bytearray()
        for string in self.value:
            encoded = string.encode("utf-8", errors="surrogateescape")
            strings_data.extend(encoded)
            strings_data.append(0)  # null terminator

        self.length.value = len(strings_data)
        self.lengths = [VarInt(len(string.encode("utf-8", errors="surrogateescape"))) for string in self.value]

        result = bytearray(self.length.serialise())
        result.extend(strings_data)
        for length in self.lengths:
            result.extend(length.serialise())

        return bytes(result)


class BytesBlock(Serialisable):
    """
    Block of bytes in the bytecode. Contains a list of byte strings and their lengths.
    """

    def __init__(self) -> None:
        self.size = SerialisableInt()
        self.size.length = 4
        self.value: List[bytes] = []
        self.nbytes = 0

    def deserialise(self, f: BinaryIO | BytesIO, nbytes: int) -> "BytesBlock":
        self.nbytes = nbytes
        self.size.deserialise(f, length=4)
        raw = f.read(self.size.value)
        positions: List[VarInt] = []
        for _ in range(nbytes):
            pos = VarInt()
            pos.deserialise(f)
            positions.append(pos)
        positions_int = [pos.value for pos in positions]
        for i in range(len(positions_int)):
            start = positions_int[i]
            end = positions_int[i + 1] if i + 1 < len(positions_int) else len(raw)
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

    def __init__(self) -> None:
        pass

    def deserialise(self, f: BinaryIO | BytesIO) -> "_NoDataType":
        return self

    def serialise(self) -> bytes:
        return b""


class Void(_NoDataType):
    """
    Void type, no data. Used to discard data (eg. reg: Void = call f@**).
    """

    pass


class U8(_NoDataType):
    """
    Unsigned 8-bit integer type, no data.
    """

    pass


class U16(_NoDataType):
    """
    Unsigned 16-bit integer type, no data.
    """

    pass


class I32(_NoDataType):
    """
    Signed 32-bit integer type, no data.
    """

    pass


class I64(_NoDataType):
    """
    Signed 64-bit integer type, no data.
    """

    pass


class F32(_NoDataType):
    """
    32-bit float type, no data.
    """

    pass


class F64(_NoDataType):
    """
    64-bit float type, no data.
    """

    pass


class Bool(_NoDataType):
    """
    Boolean type, no data.
    """

    pass


class Bytes(_NoDataType):
    """
    Bytes type, no data.
    """

    pass


class Dyn(_NoDataType):
    """
    Dynamic type, no data. Can store any type of data in a typed register as a pointer.
    """

    pass


class Fun(TypeDef):
    """
    Stores metadata about a function (signatures). When referenced in conjunction with a Proto or Method, it can be used to reconstruct the full function signature. See `crashlink.disasm.func_header` for a working reference.
    """

    def __init__(self) -> None:
        self.nargs = VarInt()
        self.args: List[tIndex] = []
        self.ret = tIndex()

    def deserialise(self, f: BinaryIO | BytesIO) -> "Fun":
        self.nargs.deserialise(f)
        for _ in range(self.nargs.value):
            self.args.append(tIndex().deserialise(f))
        self.ret.deserialise(f)
        return self

    def serialise(self) -> bytes:
        self.nargs.value = len(self.args)
        return b"".join(
            [
                self.nargs.serialise(),
                b"".join([idx.serialise() for idx in self.args]),
                self.ret.serialise(),
            ]
        )


class Field(Serialisable):
    """
    Represents a field in a class definition.
    """

    def __init__(self) -> None:
        self.name = strRef()
        self.type = tIndex()

    def deserialise(self, f: BinaryIO | BytesIO) -> "Field":
        self.name.deserialise(f)
        self.type.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return b"".join([self.name.serialise(), self.type.serialise()])


class Proto(Serialisable):
    """
    Represents a prototype of a function
    """

    def __init__(self) -> None:
        self.name = strRef()
        self.findex = fIndex()
        self.pindex = VarInt()  # unknown use

    def deserialise(self, f: BinaryIO | BytesIO) -> "Proto":
        self.name.deserialise(f)
        self.findex.deserialise(f)
        self.pindex.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return b"".join([self.name.serialise(), self.findex.serialise(), self.pindex.serialise()])


class Binding(Serialisable):
    """
    Represents a binding of a field to a class.
    """

    def __init__(self) -> None:
        self.field = fieldRef()
        self.findex = fIndex()

    def deserialise(self, f: BinaryIO | BytesIO) -> "Binding":
        self.field.deserialise(f)
        self.findex.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return b"".join([self.field.serialise(), self.findex.serialise()])


class Obj(TypeDef):
    """
    Represents a class definition. Contains:

    - name: strRef
    - super: tIndex
    - _global: gIndex
    - nfields: VarInt
    - nprotos: VarInt
    - nbindings: VarInt
    - fields: List[Field]
    - protos: List[Proto]
    - bindings: List[Binding]
    """

    def __init__(self) -> None:
        self.name = strRef()
        self.super = tIndex()
        self._global = gIndex()
        self.nfields = VarInt()
        self.nprotos = VarInt()
        self.nbindings = VarInt()
        self.fields: List[Field] = []
        self.protos: List[Proto] = []
        self.bindings: List[Binding] = []

    def deserialise(self, f: BinaryIO | BytesIO) -> "Obj":
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
        """
        Resolves all fields across the class heirarchy. For instance:
        class A {
            var a: Int;
        }
        class B extends A {
            var b: Int;
        }
        Where a is field 0 and b is field 1
        """
        if self.super.value < 0:  # no superclass
            return self.fields
        fields: List[Field] = []
        visited_types = set()
        current_type: Optional[Obj] = self
        while current_type:
            if id(current_type) in visited_types:
                raise ValueError("Cyclic inheritance detected in class hierarchy.")
            visited_types.add(id(current_type))
            fields = current_type.fields + fields
            if current_type.super.value < 0:
                current_type = None
            else:
                defn = current_type.super.resolve(code).definition
                if not isinstance(defn, Obj):
                    raise ValueError("Invalid superclass type.")
                current_type = defn
        return fields

    def __str__(self) -> str:
        return f"<Obj: f@{self.name}>"

    def __repr__(self) -> str:
        return self.__str__()

    def str_resolve(self, code: "Bytecode") -> str:
        return f"<Obj: {self.name.resolve(code)}>"


class Array(_NoDataType):
    """
    Array type, no data.
    """

    pass


class TypeType(_NoDataType):
    """
    Type wrapping a type, no data.
    """

    pass


class Ref(TypeDef):
    """
    Memory reference to an instance of a type.
    """

    def __init__(self) -> None:
        self.type = tIndex()

    def deserialise(self, f: BinaryIO | BytesIO) -> "Ref":
        self.type.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return self.type.serialise()


class Virtual(TypeDef):
    """
    Virtual type, used for virtual/abstract classes.
    """

    def __init__(self) -> None:
        self.nfields = VarInt()
        self.fields: List[Field] = []

    def deserialise(self, f: BinaryIO | BytesIO) -> "Virtual":
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
    """
    Dynamic object type, no data.
    """

    pass


class Abstract(TypeDef):
    """
    Abstract class type.
    """

    def __init__(self) -> None:
        self.name = strRef()

    def deserialise(self, f: BinaryIO | BytesIO) -> "Abstract":
        self.name.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return self.name.serialise()


class EnumConstruct(Serialisable):
    """
    Construct of an enum.
    """

    def __init__(self) -> None:
        self.name = strRef()
        self.nparams = VarInt()
        self.params: List[tIndex] = []

    def deserialise(self, f: BinaryIO | BytesIO) -> "EnumConstruct":
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
    """
    Enum type.
    """

    def __init__(self) -> None:
        self.name = strRef()
        self._global = gIndex()
        self.nconstructs = VarInt()
        self.constructs: List[EnumConstruct] = []

    def deserialise(self, f: BinaryIO | BytesIO) -> "Enum":
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
    """
    Null of a certain type.
    """

    def __init__(self) -> None:
        self.type = tIndex()

    def deserialise(self, f: BinaryIO | BytesIO) -> "Null":
        self.type.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return self.type.serialise()


class Method(Fun):
    """
    Method type, identical to Fun.
    """

    pass


class Struct(Obj):
    """
    Struct type, identical to Obj.
    """

    pass


class Packed(TypeDef):
    """
    Holds an inner type index.
    """

    def __init__(self) -> None:
        self.inner = tIndex()

    def deserialise(self, f: BinaryIO | BytesIO) -> "Packed":
        self.inner.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return self.inner.serialise()


class Type(Serialisable):
    """
    Type definition:

    - kind: SerialisableInt
    - definition: TypeDef
    """

    # fmt: off
    TYPEDEFS: List[type] = [
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

    def __init__(self) -> None:
        self.kind = SerialisableInt()
        self.kind.length = 1
        self.definition: Optional[TypeDef] = None

    def deserialise(self, f: BinaryIO | BytesIO) -> "Type":
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

    def __str__(self) -> str:
        return f"<Type: {self.kind.value} ({self.definition.__class__.__name__})>"

    def __repr__(self) -> str:
        return self.__str__()

    def str_resolve(self, code: "Bytecode") -> str:
        if isinstance(self.definition, Obj):
            return self.definition.str_resolve(code)
        return f"<Type: {self.kind.value} ({self.definition.__class__.__name__})>"


class Native(Serialisable):
    """
    Represents a native function.

    - lib: strRef
    - name: strRef
    - type: tIndex
    - findex: fIndex
    """

    def __init__(self) -> None:
        self.lib = strRef()
        self.name = strRef()
        self.type = tIndex()
        self.findex = fIndex()

    def deserialise(self, f: BinaryIO | BytesIO) -> "Native":
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

    TYPE_MAP: Dict[str, type] = {
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

    def __init__(self) -> None:
        self.code = VarInt()
        self.op: Optional[str] = None
        self.definition: Dict[Any, Any] = {}

    def deserialise(self, f: BinaryIO | BytesIO) -> "Opcode":
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
            raise InvalidOpCode(f"Invalid opcode definition for {param, _type} at {tell(f)}")
        self.op = list(opcodes.keys())[self.code.value]
        return self

    def serialise(self) -> bytes:
        if self.op:
            self.code.value = list(opcodes.keys()).index(self.op)
        return b"".join(
            [
                self.code.serialise(),
                b"".join([definition.serialise() for name, definition in self.definition.items()]),
            ]
        )

    def __repr__(self) -> str:
        return f"<Opcode: {self.op} {self.definition}>"

    def __str__(self) -> str:
        return self.__repr__()


class fileRef(ResolvableVarInt):
    """
    Reference to a file in the debug info.
    """

    def __init__(self, fid: int = 0, line: int = -1) -> None:
        super().__init__(fid)
        self.line = line

    def resolve(self, code: "Bytecode") -> str:
        """
        Resolve to the filename of the reference.
        """
        if not code.debugfiles:
            raise MalformedBytecode("No debug files found.")
        return code.debugfiles.value[self.value]

    def resolve_line(self, code: "Bytecode") -> int:
        """
        Resolve to the line number in the file of the reference.
        """
        return self.line

    def resolve_pretty(self, code: "Bytecode") -> str:
        """
        Resolve a pretty-printed string: <filename>:<line number>
        """
        return f"{self.resolve(code)}:{self.line}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, fileRef):
            return NotImplemented
        return self.value == other.value and self.line == other.line


class DebugInfo(Serialisable):
    """
    Represents debug information for a function, encoded with a delta encoding scheme for compression.
    """

    def __init__(self) -> None:
        self.value: List[fileRef] = []

    def deserialise(self, f: BinaryIO | BytesIO, nops: int) -> "DebugInfo":
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
                    tmp.append(fileRef(currfile, currline))
                    i += 1
                currline += delta
            elif c & 4 != 0:
                currline += c >> 3
                tmp.append(fileRef(currfile, currline))
                i += 1
            else:
                b2 = ctypes.c_uint8(ord(f.read(1))).value
                b3 = ctypes.c_uint8(ord(f.read(1))).value
                currline = (c >> 3) | (b2 << 5) | (b3 << 13)
                tmp.append(fileRef(currfile, currline))
                i += 1
        self.value = tmp
        return self

    def _flush_repeat(self, w: BinaryIO | BytesIO, curpos: ctypes.c_size_t, rcount: ctypes.c_size_t, pos: int) -> None:
        if rcount.value > 0:
            if rcount.value > 15:
                w.write(ctypes.c_uint8((15 << 2) | 2).value.to_bytes(1, "little"))
                rcount.value -= 15
                self._flush_repeat(w, curpos, rcount, pos)
            else:
                delta = pos - curpos.value
                delta = delta if 0 < delta < 4 else 0
                w.write(ctypes.c_uint8(((delta << 6) | (rcount.value << 2) | 2)).value.to_bytes(1, "little"))
                rcount.value = 0
                curpos.value += delta

    def serialise(self) -> bytes:
        w = BytesIO()
        curfile = -1
        curpos = ctypes.c_size_t(0)
        rcount = ctypes.c_size_t(0)

        for ref in self.value:
            f = ref.value
            p = ref.line
            if f != curfile:
                self._flush_repeat(w, curpos, rcount, p)
                curfile = f
                w.write(ctypes.c_uint8(((f >> 7) | 1)).value.to_bytes(1, "little"))
                w.write(ctypes.c_uint8(f & 0xFF).value.to_bytes(1, "little"))

            if p != curpos.value:
                self._flush_repeat(w, curpos, rcount, p)

            if p == curpos.value:
                rcount.value += 1
            else:
                delta = p - curpos.value
                if 0 < delta < 32:
                    w.write(ctypes.c_uint8((delta << 3) | 4).value.to_bytes(1, "little"))
                else:
                    w.write(ctypes.c_uint8((p << 3) & 0xFF).value.to_bytes(1, "little"))
                    w.write(ctypes.c_uint8((p >> 5) & 0xFF).value.to_bytes(1, "little"))
                    w.write(ctypes.c_uint8((p >> 13) & 0xFF).value.to_bytes(1, "little"))
                curpos.value = p

        self._flush_repeat(w, curpos, rcount, curpos.value)

        return w.getvalue()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DebugInfo):
            return NotImplemented
        return self.value == other.value


class Function(Serialisable):
    """
    Represents a function in the bytecode. Due to the interesting ways in which HashLink works, this does not have a name or a signature, but rather a return type and a list of registers and opcodes.
    """

    def __init__(self) -> None:
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
        self.assigns: Optional[List[Tuple[strRef, VarInt]]] = None

    def resolve_file(self, code: "Bytecode") -> str:
        """
        Resolves (in the Bytecode's debugfiles blob) the name of the file this function originates from. Note that this assumes the first opcode's file is the only file this Function was derived from - Functions that derive from multiple files (such as compiler-generated closures or entrypoints) will be resolved to a single file, sometimes incorrectly.
        """
        if not self.has_debug or not self.debuginfo:
            raise ValueError("Cannot get file from non-debug bytecode!")
        return self.debuginfo.value[0].resolve(code)

    def deserialise(self, f: BinaryIO | BytesIO, has_debug: bool, version: int) -> "Function":
        self.has_debug = has_debug
        self.version = version
        self.type.deserialise(f)
        self.findex.deserialise(f)
        # dbg_print(f"----- {self.findex.value} ({tell(f)}) -----")
        self.nregs.deserialise(f)
        self.nops.deserialise(f)
        for _ in range(self.nregs.value):
            self.regs.append(tIndex().deserialise(f))
        for _ in range(self.nops.value):
            self.ops.append(Opcode().deserialise(f))
        if self.has_debug:
            self.debuginfo = DebugInfo().deserialise(f, self.nops.value)
            if self.version >= 3:
                self.nassigns = VarInt().deserialise(f)
                self.assigns = []
                for _ in range(self.nassigns.value):
                    self.assigns.append((strRef().deserialise(f), VarInt().deserialise(f)))
        return self

    def serialise(self) -> bytes:
        self.nops.value = len(self.ops)
        self.nregs.value = len(self.regs)
        if self.assigns:
            self.nassigns = VarInt(len(self.assigns) if self.assigns else 0)
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
        if self.has_debug and self.debuginfo:
            res += self.debuginfo.serialise()
            if self.version and self.version >= 3 and self.nassigns and self.assigns is not None:
                res += self.nassigns.serialise()
                res += b"".join([b"".join([v.serialise() for v in assign]) for assign in self.assigns])
        return res


class Constant(Serialisable):
    """
    Represents a bytecode constant.
    """

    def __init__(self) -> None:
        self._global = gIndex()
        self.nfields = VarInt()
        self.fields: List[VarInt] = []

    def deserialise(self, f: BinaryIO | BytesIO) -> "Constant":
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
    """
    The main bytecode class. To read a bytecode file, use the `from_path` class method.

    For more information about the overall structure, see [here](https://n3rdl0rd.github.io/ModDocCE/files/hlboot)
    """

    def __init__(self) -> None:
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

        self.initialized_globals: Dict[int, Any] = {}

        self.section_offsets: Dict[str, int] = {}

    def _find_magic(self, f: BinaryIO | BytesIO, magic: bytes = b"HLB") -> None:
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
    def from_path(cls, path: str, search_magic: bool = True) -> "Bytecode":
        """
        Create a new Bytecode instance from a file path.
        """
        f = open(path, "rb")
        instance = cls().deserialise(f, search_magic=search_magic)
        f.close()
        return instance

    @classmethod
    def from_bytes(cls, data: bytes, search_magic: bool = True) -> "Bytecode":
        """
        Create a new Bytecode instance from a `bytes` object.
        """
        f = BytesIO(data)
        instance = cls().deserialise(f, search_magic=search_magic)
        f.close()
        return instance

    @classmethod
    def create_empty(cls, version: int = 4, no_extra_types: bool = False) -> "Bytecode":
        """
        Creates an empty HashLink bytecode object, ideal for adding custom functions or code to for testing. By default, contains the following types already defined:

        - t@0: Void
        - t@1: I32
        - t@2: F64
        - t@3: Bool

        Optionally, it can be created with only the Void type defined by passing `no_extra_types=True`. Note that for the bytecode to be valid and executable, there must be at least a single function, and this function must have a valid return type, meaning that the bytecode must contain **at least** 1 type.
        """
        instance = Bytecode()
        instance.magic.value = b"HLB"
        instance.version.value = version
        instance.has_debug_info = False
        instance.entrypoint.value = 22

        void = Type()
        void.kind.value = 0  # Void (_NoDataType)
        void.definition = Void()

        if not no_extra_types:
            i32 = Type()
            i32.kind.value = 3
            i32.definition = I32()

            f64 = Type()
            f64.kind.value = 6
            f64.definition = F64()

            bool_t = Type()
            bool_t.kind.value = 7
            bool_t.definition = Bool()

        func = Function()
        func.type.value = 0  # Void return type
        func.findex.value = 22
        func.has_debug = False
        func.version = version

        instance.types.append(void)
        instance.functions.append(func)

        if not no_extra_types:
            instance.types.append(i32)
            instance.types.append(f64)
            instance.types.append(bool_t)

        instance.set_meta()

        return instance

    def deserialise(self, f: BinaryIO | BytesIO, search_magic: bool = True) -> "Bytecode":
        """
        Deserialise the bytecode in-place from an open binary file handle or a BytesIO object. By default will search for the bytecode magic (b'HLB') anywhere in the file, pass `search_magic=False` to disable.
        """
        start_time = datetime.now()
        dbg_print("---- Deserialise ----")
        if search_magic:
            dbg_print("Searching for magic...")
            self._find_magic(f)
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

        if self.version.value >= 5 and self.nbytes:
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

        if self.version.value >= 4 and self.nconstants:
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
        self.strings.deserialise(f, self.nstrings.value)
        dbg_print(f"Strings section ends at {tell(f)}")
        assert self.nstrings.value == len(self.strings.value), "nstrings and len of strings don't match!"

        if self.version.value >= 5 and self.bytes and self.nbytes:
            dbg_print("Deserialising bytes... >=5")
            self.track_section(f, "bytes")
            self.bytes.deserialise(f, self.nbytes.value)
        else:
            self.bytes = None

        if self.has_debug_info and self.ndebugfiles and self.debugfiles:
            dbg_print(f"Deserialising debug files... (at {tell(f)})")
            self.track_section(f, "ndebugfiles")
            self.ndebugfiles.deserialise(f)
            dbg_print(f"Number of debug files: {self.ndebugfiles.value}")
            self.track_section(f, "debugfiles")
            self.debugfiles.deserialise(f, self.ndebugfiles.value)
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
        if not USE_TQDM or self.nfunctions.value < 1000:
            for i in range(self.nfunctions.value):
                self.track_section(f, f"function {i}")
                self.functions.append(Function().deserialise(f, self.has_debug_info, self.version.value))
        else:
            for i in tqdm(range(self.nfunctions.value)):
                self.track_section(f, f"function {i}")
                self.functions.append(Function().deserialise(f, self.has_debug_info, self.version.value))
        if self.nconstants is not None:
            dbg_print(f"Constants starting at {tell(f)}")
            self.track_section(f, "constants")
            for i in range(self.nconstants.value):
                self.track_section(f, f"constant {i}")
                self.constants.append(Constant().deserialise(f))
        dbg_print(f"Bytecode end at {tell(f)}.")
        self.deserialised = True
        dbg_print("Initializing globals...")
        self.init_globals()
        dbg_print(f"{(datetime.now() - start_time).total_seconds()}s elapsed.")
        return self

    def init_globals(self) -> None:
        """
        Internal method to initialize global instances of objects.
        """
        final: Dict[int, Any] = {}
        for const in self.constants:
            res: Dict[str, Any] = {}
            obj = const._global.resolve(self).definition
            if not isinstance(obj, Obj):
                dbg_print("WARNING: Skipping non-Obj constant.")
                continue
            obj_fields = obj.resolve_fields(self)
            for i, field in enumerate(const.fields):
                # Field has:
                # - name: strRef
                # - type: tIndex
                # we need to use the type to know how to resolve the const ref to the actual value
                typ = obj_fields[i].type.resolve(self).definition
                name = obj_fields[i].name.resolve(self)
                if isinstance(typ, I32) or isinstance(typ, U8) or isinstance(typ, U16) or isinstance(typ, I64):
                    res[name] = self.ints[field.value].value
                elif isinstance(typ, F32) or isinstance(typ, F64):
                    res[name] = self.floats[field.value].value
                elif isinstance(typ, Bytes):
                    res[name] = self.strings.value[field.value]
                else:
                    res[name] = field.value
            final[const._global.value] = res
        assert len(final) == len(self.constants), "Not all constants were resolved! Somehow..."
        self.initialized_globals = final

    def fn(self, findex: int, native: bool = True) -> Function | Native:
        """
        Shorthand to to get a Function or a Native by its fIndex.
        """
        for f in self.functions:
            if f.findex.value == findex:
                return f
        if native:
            for n in self.natives:
                if n.findex.value == findex:
                    return n
        raise ValueError(f"Function {findex} not found!")

    def t(self, tindex: int) -> Type:
        """
        Shorthand to get a Type by its index. Equivalent to code.types[tindex]
        """
        return self.types[tindex]

    def g(self, gindex: int) -> Type:
        """
        Shorthand to get a global's type by gIndex.
        """
        for g in self.global_types:
            if g.value == gindex:
                return g.resolve(self)
        raise ValueError(f"Global {gindex} not found!")

    def const_str(self, gindex: int) -> str:
        """
        Gets the value of an initialized global constant `String`.
        """
        # TODO: is this overcomplicated?
        if gindex not in self.initialized_globals:
            if gindex < 0 or gindex >= len(self.global_types):
                raise ValueError(f"Global {gindex} not found!")
            raise ValueError(f"Global {gindex} does not have a constant value!")
        obj = self.global_types[gindex].resolve(self).definition
        if not isinstance(obj, Obj):
            raise TypeError(f"Global {gindex} is not an object!")
        if not obj.name.resolve(self) == "String":
            raise TypeError(f"Global {gindex} is not a string!")
        obj_fields = obj.resolve_fields(self)
        if len(obj_fields) != 2:
            raise ValueError(f"Global {gindex} seems malformed!")
        res = self.initialized_globals[gindex][obj_fields[0].name.resolve(self)]
        if not isinstance(res, str):
            raise TypeError(f"This should never happen!")
        return res

    def serialise(self, auto_set_meta: bool = True) -> bytes:
        """
        Serialise the bytecode to a `bytes` object.
        """
        start_time = datetime.now()
        dbg_print("---- Serialise ----")
        if auto_set_meta:
            dbg_print("Setting meta...")
            self.set_meta()
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
        if self.version.value >= 5 and self.nbytes:
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
        if self.version.value >= 4 and self.nconstants:
            res += self.nconstants.serialise()
        res += self.entrypoint.serialise()
        res += b"".join([i.serialise() for i in self.ints])
        res += b"".join([f.serialise() for f in self.floats])
        res += self.strings.serialise()
        if self.version.value >= 5 and self.bytes:
            res += self.bytes.serialise()
        if self.has_debug_info and self.ndebugfiles and self.debugfiles:
            res += b"".join([self.ndebugfiles.serialise(), self.debugfiles.serialise()])
        res += b"".join(
            [
                b"".join([typ.serialise() for typ in self.types]),
                b"".join([typ.serialise() for typ in self.global_types]),
                b"".join([native.serialise() for native in self.natives]),
            ]
        )
        if USE_TQDM:
            res += b"".join([func.serialise() for func in tqdm(self.functions)])
        else:
            res += b"".join([func.serialise() for func in self.functions])
        res += b"".join([constant.serialise() for constant in self.constants])
        dbg_print(f"Final size: {hex(len(res))}")
        dbg_print(f"{(datetime.now() - start_time).total_seconds()}s elapsed.")
        return res

    def set_meta(self) -> None:
        """
        Sets bytecode metadata automatically.
        """
        self.flags.value = 1 if self.has_debug_info else 0
        self.nints.value = len(self.ints)
        self.nfloats.value = len(self.floats)
        self.nstrings.value = len(self.strings.value)
        if self.version.value >= 5 and self.bytes and self.nbytes:
            self.nbytes.value = len(self.bytes.value)
        self.ntypes.value = len(self.types)
        self.nglobals.value = len(self.global_types)
        self.nnatives.value = len(self.natives)
        self.nfunctions.value = len(self.functions)
        if self.version.value >= 4 and self.nconstants:
            self.nconstants.value = len(self.constants)
        if self.has_debug_info and self.ndebugfiles and self.debugfiles:
            self.ndebugfiles.value = len(self.debugfiles.value)

    def repair(self) -> None:
        """
        Alternate notation for code.set_meta() for the purpose of clarity.
        """
        self.set_meta()

    def get_test_main(self) -> Function:
        for f in self.functions:
            if full_func_name(self, f).endswith("main"):
                return f
        raise ValueError("No main function found!")

    def is_ok(self) -> bool:
        """
        Runs a set of basic sanity checks to make sure the bytecode is correct-ish.
        """
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

    def track_section(self, f: BinaryIO | BytesIO, section_name: str) -> None:
        """
        Internal helper function to denote the location of a data section at a given offset.
        """
        self.section_offsets[section_name] = f.tell()

    def section_at(self, offset: int) -> Optional[str]:
        """
        Returns the name of the bytecode data section at the offset.
        """
        # returns the name of the section at the offset:
        # if the offset is after a section start and before the next section start, it's still in the first section
        for section_name, section_offset in list(reversed(self.section_offsets.items())):
            if offset >= section_offset:
                return section_name
        return None


def get_field_for(code: Bytecode, idx: int) -> Optional[Field]:
    """
    Gets the field for a standalone function index.
    """
    for type in code.types:
        if type.kind.value == Type.TYPEDEFS.index(Obj):
            if not isinstance(type.definition, Obj):
                raise TypeError(f"Expected Obj, got {type.definition}")
            definition: Obj = type.definition
            fields = definition.resolve_fields(code)
            for binding in definition.bindings:  # binding binds a field to a function
                if binding.findex.value == idx:
                    return fields[binding.field.value]
    return None


def get_proto_for(code: Bytecode, idx: int) -> Optional[Proto]:
    """
    Gets the proto for a standalone function index.
    """
    for type in code.types:
        if type.kind.value == Type.TYPEDEFS.index(Obj):
            if not isinstance(type.definition, Obj):
                raise TypeError(f"Expected Obj, got {type.definition}")
            definition: Obj = type.definition
            for proto in definition.protos:
                if proto.findex.value == idx:
                    return proto
    return None


def full_func_name(code: Bytecode, func: Function | Native) -> str:
    """
    Generates a human-readable name for a function or native.
    """
    proto = get_proto_for(code, func.findex.value)
    if proto:
        name = proto.name.resolve(code)
        for type in code.types:
            if type.kind.value == Type.TYPEDEFS.index(Obj):
                if not isinstance(type.definition, Obj):
                    continue
                obj_def: Obj = type.definition
                for fun in obj_def.protos:
                    if fun.findex.value == func.findex.value:
                        return f"{obj_def.name.resolve(code)}.{name}"
    else:
        name = "<none>"
        field = get_field_for(code, func.findex.value)
        if field:
            name = field.name.resolve(code)
            for type in code.types:
                if type.kind.value == Type.TYPEDEFS.index(Obj):
                    if not isinstance(type.definition, Obj):
                        continue
                    _obj_def: Obj = type.definition
                    fields = _obj_def.resolve_fields(code)
                    for binding in _obj_def.bindings:
                        if binding.findex.value == func.findex.value:
                            return f"{_obj_def.name.resolve(code)}.{name}"
    return name


__all__ = [
    "full_func_name",
    "get_field_for",
    "get_proto_for",
    "Abstract",
    "Array",
    "Binding",
    "Bool",
    "Bytecode",
    "Bytes",
    "BytesBlock",
    "Constant",
    "DebugInfo",
    "Dyn",
    "DynObj",
    "Enum",
    "EnumConstruct",
    "F32",
    "F64",
    "Field",
    "Fun",
    "Function",
    "I32",
    "I64",
    "InlineBool",
    "Method",
    "Native",
    "Null",
    "Obj",
    "Opcode",
    "Packed",
    "Proto",
    "RawData",
    "Ref",
    "Reg",
    "Regs",
    "ResolvableVarInt",
    "Serialisable",
    "SerialisableF64",
    "SerialisableInt",
    "StringsBlock",
    "Struct",
    "Type",
    "TypeDef",
    "TypeType",
    "U16",
    "U8",
    "VarInt",
    "VarInts",
    "Virtual",
    "Void",
    "bytesRef",
    "fIndex",
    "fieldRef",
    "fileRef",
    "floatRef",
    "gIndex",
    "intRef",
    "strRef",
    "tIndex",
]
