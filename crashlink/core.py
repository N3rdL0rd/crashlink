"""
Core bytecode format definitions.

This module contains the definitions for HashLink bytecode structures, as well as the serialisation
and deserialisation methods for them. You probably don't need to use too much of this file directly,
besides Bytecode, Opcode, and Function. The decompiler will take care of a lot of abstraction for
you.
"""

from __future__ import annotations

import ctypes
import struct
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum as _Enum
from io import BytesIO
from typing import Any, BinaryIO, Dict, List, Literal, Optional, Tuple, TypeVar

T = TypeVar("T", bound="VarInt")  # easier than reimplementing deserialise for each subclass

from .errors import InvalidOpCode, MalformedBytecode, NoMagic
from .globals import dbg_print, tell
from .opcodes import opcodes, simple_calls

try:
    import platform

    if platform.python_implementation() == "PyPy":
        dbg_print("Using PyPy, tqdm will only use ASCII chars")

        def tqdm(*args: Any, **kwargs: Any) -> Any:
            """
            A wrapper around tqdm that uses ASCII characters for PyPy compatibility.
            """
            from tqdm import tqdm as _tqdm

            return _tqdm(*args, **kwargs, ascii=True)  # type: ignore[call-overload]
    else:
        from tqdm import tqdm

    USE_TQDM = True
except ImportError:
    dbg_print("Could not find tqdm. Progress bars will not be displayed.")
    USE_TQDM = False


def destaticify(s: str) -> str:
    """
    Transforms a static Obj's name into the normal class name.
    """
    path, _, class_name = s.rpartition(".")
    if class_name.startswith("$"):
        class_name = class_name[1:]
    return f"{path}.{class_name}" if path else class_name


def is_static_name(s: str) -> bool:
    """
    Checks if the last qualifier of a name (the class name) is prefixed with a '$'.
    """
    return s.rpartition(".")[-1].startswith("$")


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
        try:
            return self.value == other.value
        except AttributeError:
            # Fallback if a subclass doesn't define .value but also doesn't override __eq__
            return NotImplemented

    def __ne__(self, other: object) -> Any:
        if not isinstance(other, Serialisable):
            return NotImplemented
        try:
            return self.value != other.value
        except AttributeError:
            return NotImplemented

    def __lt__(self, other: object) -> Any:
        if not isinstance(other, Serialisable):
            return NotImplemented
        try:
            return self.value < other.value
        except AttributeError:
            return NotImplemented


class RawData(Serialisable):
    """
    A block of raw data.
    """
    __slots__ = ('value', 'length')

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
    __slots__ = ('value', 'length', 'byteorder', 'signed')

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
        bytes_read = f.read(length)
        if all(b == 0 for b in bytes_read):
            self.value = 0
            return self
        while len(bytes_read) > 1 and bytes_read[-1] == 0:
            bytes_read = bytes_read[:-1]
        self.value = int.from_bytes(bytes_read, byteorder, signed=signed)
        return self

    def serialise(self) -> bytes:
        return self.value.to_bytes(self.length, self.byteorder, signed=self.signed)


class SerialisableF64(Serialisable):
    """
    A standard 64-bit float.
    """
    __slots__ = ('value',)

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
    __slots__ = ('value',)

    def __init__(self, value: int = 0):
        self.value: int = value

    def deserialise(self: T, f: BinaryIO | BytesIO) -> T:
        b = f.read(1)[0]
        if b < 0x80:
            self.value = b
            return self
        if b < 0xC0:
            second = f.read(1)[0]
            val = ((b & 0x1F) << 8) | second
            self.value = (val ^ -((b >> 5) & 1)) + ((b >> 5) & 1)
            return self
        remaining_bytes = f.read(3)
        if len(remaining_bytes) < 3:
            raise ValueError("Incomplete VarInt at end of stream")
        remaining = int.from_bytes(remaining_bytes, "big")
        val = ((b & 0x1F) << 24) | remaining
        self.value = (val ^ -((b >> 5) & 1)) + ((b >> 5) & 1)
        return self

    def serialise(self) -> bytes:
        value = self.value
        sign_bit = 0
        if value < 0:
            sign_bit = 0x20
            value = -value
        if value < 0x80:
            return bytes([value])
        if value < 0x2000:
            return bytes([(value >> 8) | 0x80 | sign_bit, value & 0xFF])
        if value >= 0x20000000:
            raise ValueError("Value out of range for VarInt")
        return bytes([(value >> 24) | 0xC0 | sign_bit, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


class ResolvableVarInt(VarInt, ABC):
    """
    Base class for resolvable VarInts. Call `resolve` to get a direct reference to the object it points to.
    """
    __slots__ = ()

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
    __slots__ = ()

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
    __slots__ = ()

    def resolve(self, code: "Bytecode") -> "Type":
        return code.types[self.value]


class gIndex(ResolvableVarInt):
    """
    Reference to a global object in the bytecode.
    """
    __slots__ = ()

    def resolve(self, code: "Bytecode") -> "Type":
        return code.global_types[self.value].resolve(code)

    def partial_resolve(self, code: "Bytecode") -> tIndex:
        return code.global_types[self.value]

    def resolve_str(self, code: "Bytecode") -> str:
        return code.const_str(self.value)


class strRef(ResolvableVarInt):
    """
    Reference to a string in the bytecode.
    """
    __slots__ = ()

    def resolve(self, code: "Bytecode") -> str:
        return code.strings.value[self.value]


class intRef(ResolvableVarInt):
    """
    Reference to an integer in the bytecode.
    """
    __slots__ = ()

    def resolve(self, code: "Bytecode") -> SerialisableInt:
        return code.ints[self.value]


class floatRef(ResolvableVarInt):
    """
    Reference to a float in the bytecode.
    """
    __slots__ = ()

    def resolve(self, code: "Bytecode") -> SerialisableF64:
        return code.floats[self.value]


class bytesRef(ResolvableVarInt):
    """
    Reference to a byte string in the bytecode.
    """
    __slots__ = ()

    def resolve(self, code: "Bytecode") -> bytes:
        if code.bytes:
            return code.bytes.value[self.value]
        else:
            raise MalformedBytecode("No bytes block found.")


class fieldRef(ResolvableVarInt):
    """
    Reference to a field in an object definition.
    """
    obj: Optional["Obj|Virtual"] = None

    def resolve(self, code: "Bytecode") -> "Field":
        if self.obj:
            return self.obj.resolve_fields(code)[self.value]
        raise ValueError(
            "Cannot resolve field without context. Try setting `field.obj` to an instance of `Obj`, or use `field.resolve_obj(code, obj)` instead."
        )

    def resolve_obj(self, code: "Bytecode", obj: "Obj|Virtual") -> "Field":
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
        self.n.value = len(self.value)
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
        self.n.value = len(self.value)
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

    def find_or_add(self, val: str) -> int:
        """
        Finds and returns the index of a string value in this block, or adds it to this block and returns its index.
        """
        try:
            return self.value.index(val)
        except ValueError:
            self.value.append(val)
            return len(self.value) - 1


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


class TypeDef(Serialisable, ABC):
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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _NoDataType):
            return NotImplemented
        # Two _NoDataType objects are equal if they are of the same specific class.
        return type(self) is type(other)


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

    def str_resolve(self, code: "Bytecode") -> str:
        """
        Returns a pretty-printed string representation of the function signature.
        """
        args_str = ", ".join([arg.resolve(code).str_resolve(code) for arg in self.args])
        return f"({args_str}) -> {self.ret.resolve(code).str_resolve(code)}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Fun):
            return NotImplemented
        return self.nargs == other.nargs and self.args == other.args and self.ret == other.ret


class Field(Serialisable):
    """
    Represents a field in a class definition.
    """

    def __init__(self, name: Optional[strRef] = None, type: Optional[tIndex] = None) -> None:
        if not name:
            self.name = strRef()
        else:
            self.name = name
        if not type:
            self.type = tIndex()
        else:
            self.type = type

    def deserialise(self, f: BinaryIO | BytesIO) -> "Field":
        self.name.deserialise(f)
        self.type.deserialise(f)
        return self

    def serialise(self) -> bytes:
        return b"".join([self.name.serialise(), self.type.serialise()])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Field):
            return NotImplemented
        res = self.name == other.name and self.type == other.type
        assert isinstance(res, bool), "Field equality check must return a boolean"
        return res


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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Proto):
            return NotImplemented
        res = self.name == other.name and self.findex == other.findex and self.pindex == other.pindex
        assert isinstance(res, bool), "Proto equality check must return a boolean"
        return res


class Binding(Serialisable):
    """
    Represents a binding of a function to a field in an object.
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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Binding):
            return NotImplemented
        res = self.field == other.field and self.findex == other.findex
        assert isinstance(res, bool), "Binding equality check must return a boolean"
        return res


class Obj(TypeDef):
    """
    Represents a class definition.
    """

    def __init__(self) -> None:
        self.name = strRef()
        """The name of this object type."""
        self.super = tIndex()
        """The superclass of this object type, or -1 if it has no superclass."""
        self._global = gIndex()
        """The global object index of this type."""
        self.nfields = VarInt()
        """Number of fields"""
        self.nprotos = VarInt()
        """Number of prototypes"""
        self.nbindings = VarInt()
        """Number of bindings"""
        self.fields: List[Field] = []
        """List of fields in this object type."""
        self.protos: List[Proto] = []
        """List of prototypes for this object type."""
        self.bindings: List[Binding] = []
        """List of bindings for this object type."""
        self._virtuals: List[int] = []
        self._virtual_map: Dict[str, int] = {}
        self.virtuals_initialized: bool = False

        self._is_static: Optional[bool] = None
        self._static: "Optional[Obj]" = None
        self._dynamic: "Optional[Obj]" = None

    def get_containing_type(self, code: Bytecode) -> Type:
        """Finds the Type object that contains this Obj definition."""
        for t in code.types:
            if t.definition is self:
                return t
        raise RuntimeError("Could not find containing Type for Obj instance.")

    @property
    def virtuals(self) -> List[int]:
        """Returns the list of virtual function indices for this object type."""
        if not self.virtuals_initialized:
            raise ValueError("Virtuals not initialized. Call `code.init_virtuals()` after deserialisation.")
        return self._virtuals

    @property
    def virtual_map(self) -> Dict[str, int]:
        """Returns the map of method names to their virtual ID for this object type."""
        if not self.virtuals_initialized:
            raise ValueError("Virtuals not initialized. Call `code.init_virtuals()` after deserialisation.")
        return self._virtual_map

    @property
    def is_static(self) -> bool:
        """True if this Obj is static, else False. If True, you can get this Obj's dynamic counterpart with `Obj.dynamic`."""
        if self._is_static is not None:
            return self._is_static
        raise ValueError(
            "Static-dynamic object mapping not initialized. Call `code.map_statics()` after deserialisation."
        )

    @property
    def static(self) -> "Obj":
        """This Obj's static counterpart. Accessing will raise an exception if `Obj.is_static` is True."""
        if self._static is not None:
            return self._static
        if self._is_static is not None and self._is_static:
            raise ValueError("This Obj is static! Try `Obj.dynamic` for its counterpart instead.")
        raise ValueError(
            "Static-dynamic object mapping not initialized. Call `code.map_statics()` after deserialisation."
        )

    @property
    def dynamic(self) -> "Obj":
        """This Obj's dynamic counterpart. Accessing will raise an exception if `Obj.is_static` is False."""
        if self._dynamic is not None:
            return self._dynamic
        if self._is_static is not None and not self._is_static:
            raise ValueError("This Obj is static! Try `Obj.dynamic` for its counterpart instead.")
        raise ValueError(
            "Static-dynamic object mapping not initialized. Call `code.map_statics()` after deserialisation."
        )

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
        self.nfields.value = len(self.fields)
        self.nprotos.value = len(self.protos)
        self.nbindings.value = len(self.bindings)
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
        Resolves all fields across the class hierarchy. For instance:
        class A {
            var a: Int;
        }
        class B extends A {
            var b: Int;
        }
        Where a is field 0 and b is field 1.
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
        return f"<Obj: s@{self.name}>"

    def __repr__(self) -> str:
        return self.__str__()

    def str_resolve(self, code: "Bytecode") -> str:
        return f"<Obj: {self.name.resolve(code)}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Obj):
            return NotImplemented
        return (
            self.name == other.name
            and self.super == other.super
            and self._global == other._global
            and self.fields == other.fields
            and self.protos == other.protos
            and self.bindings == other.bindings
        )


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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ref):
            return NotImplemented
        res = self.type == other.type
        assert isinstance(res, bool), "Ref equality check must return a boolean"
        return res


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
        self.nfields.value = len(self.fields)
        return b"".join(
            [
                self.nfields.serialise(),
                b"".join([field.serialise() for field in self.fields]),
            ]
        )

    def resolve_fields(self, code: "Bytecode") -> List[Field]:
        return self.fields

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Virtual):
            return NotImplemented
        return self.fields == other.fields


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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Abstract):
            return NotImplemented
        res = self.name == other.name
        assert isinstance(res, bool), "Abstract equality check must return a boolean"
        return res


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
        self.nparams.value = len(self.params)
        return b"".join(
            [
                self.name.serialise(),
                self.nparams.serialise(),
                b"".join([param.serialise() for param in self.params]),
            ]
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EnumConstruct):
            return NotImplemented
        return self.name == other.name and self.params == other.params


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
        self.nconstructs.value = len(self.constructs)
        return b"".join(
            [
                self.name.serialise(),
                self._global.serialise(),
                self.nconstructs.serialise(),
                b"".join([construct.serialise() for construct in self.constructs]),
            ]
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Enum):
            return NotImplemented
        return self.name == other.name and self.constructs == other.constructs


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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Null):
            return NotImplemented
        res = self.type == other.type
        assert isinstance(res, bool), "Null equality check must return a boolean"
        return res


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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Packed):
            return NotImplemented
        res = self.inner == other.inner
        assert isinstance(res, bool), "Packed equality check must return a boolean"
        return res


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

    class Kind(_Enum):
        VOID = 0
        U8 = 1
        U16 = 2
        I32 = 3
        I64 = 4
        F32 = 5
        F64 = 6
        BOOL = 7
        BYTES = 8
        DYN = 9
        FUN = 10
        OBJ = 11
        ARRAY = 12
        TYPETYPE = 13
        REF = 14
        VIRTUAL = 15
        DYNOBJ = 16
        ABSTRACT = 17
        ENUM = 18
        NULL = 19
        METHOD = 20
        STRUCT = 21
        PACKED = 22

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
            if isinstance(_def, TypeDef):
                deserialised = _def.deserialise(f)
                if isinstance(deserialised, TypeDef):
                    self.definition = deserialised
                else:
                    raise MalformedBytecode(f"Invalid type definition found @{tell(f)}")
            else:
                raise MalformedBytecode(f"Invalid type definition found @{tell(f)}")
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
        if isinstance(self.definition, Fun):
            return self.definition.str_resolve(code)
        return f"<Type: {self.kind.value} ({self.definition.__class__.__name__})>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Type):
            return NotImplemented
        if self is other:
            return True
        # Definitions can be None
        if self.definition is None and other.definition is None:
            res = self.kind == other.kind
            return res if isinstance(res, bool) else False
        if self.definition is None or other.definition is None:
            return False
        res = self.kind == other.kind and self.definition == other.definition
        assert isinstance(res, bool), "Type equality check must return a boolean"
        return res

    def __hash__(self) -> int:
        return hash(self.serialise())


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

    def called_by(self, code: "Bytecode") -> List[fIndex]:
        """
        Resolves all functions that call this native.
        """
        caller_indices = []
        for func in code.functions:
            if any(call_idx.value == self.findex.value for call_idx in func.calls):
                caller_indices.append(func.findex)
        return caller_indices

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

    def __init__(self, op: Optional[str] = None, df: Optional[Dict[Any, Any]] = None) -> None:
        self.code = VarInt()
        self.op: Optional[str] = None
        if op:
            self.op = op
        self.df: Dict[Any, Any] = {}
        if df:
            self.df = df

    def deserialise(self, f: BinaryIO | BytesIO) -> "Opcode":
        # dbg_print(f"Deserialising opcode at {tell(f)}... ", end="")
        self.code.deserialise(f)
        # dbg_print(f"{self.code.value}... ", end="")
        try:
            _def = opcodes[list(opcodes.keys())[self.code.value]]
        except IndexError:
            raise InvalidOpCode(f"Unknown opcode at {tell(f)} - {self.code.value}")
        for param, _type in _def.items():
            if _type in self.TYPE_MAP:
                self.df[param] = self.TYPE_MAP[_type]().deserialise(f)
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
                b"".join([definition.serialise() for name, definition in self.df.items()]),
            ]
        )

    def __repr__(self) -> str:
        return f"<Opcode: {self.op} {self.df}>"

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
            try:
                c_byte = f.read(1)
                if not c_byte:
                    break
                c = ctypes.c_uint8(ord(c_byte)).value
                if c & 1 != 0:
                    c >>= 1
                    b2_byte = f.read(1)
                    if not b2_byte:
                        break
                    currfile = (c << 8) | ctypes.c_uint8(ord(b2_byte)).value
                elif c & 2 != 0:
                    delta = c >> 6
                    count = (c >> 2) & 15
                    for _ in range(count):
                        tmp.append(fileRef(currfile, currline))
                        i += 1
                    currline += delta
                elif c & 4 != 0:
                    currline += c >> 3
                    tmp.append(fileRef(currfile, currline))
                    i += 1
                else:
                    b2_byte, b3_byte = f.read(1), f.read(1)
                    if not b2_byte or not b3_byte:
                        break
                    b2 = ctypes.c_uint8(ord(b2_byte)).value
                    b3 = ctypes.c_uint8(ord(b3_byte)).value
                    currline = (c >> 3) | (b2 << 5) | (b3 << 13)
                    tmp.append(fileRef(currfile, currline))
                    i += 1
            except (IOError, IndexError):
                break
        self.value = tmp
        return self

    def _flush_repeat(
        self,
        w: BinaryIO | BytesIO,
        curpos: ctypes.c_size_t,
        rcount: ctypes.c_size_t,
        pos: int,
    ) -> None:
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
    __slots__ = ('type', 'findex', 'nregs', 'nops', 'regs', 'ops', 'has_debug', 'version', 'debuginfo', 'nassigns', 'assigns', 'calls')

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
        self.calls: List[fIndex] = []

    def called_by(self, code: "Bytecode") -> List[fIndex]:
        """
        Resolves all functions that call this function.
        """
        caller_indices = []
        for func in code.functions:
            if any(call_idx.value == self.findex.value for call_idx in func.calls):
                caller_indices.append(func.findex)
        return caller_indices

    def resolve_fun(self, code: "Bytecode") -> Fun:
        """
        Resolves the function signature of this function.
        """
        ret = self.type.resolve(code).definition
        assert ret is not None
        assert isinstance(ret, Fun)
        return ret

    def resolve_file(self, code: "Bytecode") -> str:
        """
        Resolves (in the Bytecode's debugfiles blob) the name of the file this function originates from. Note that this assumes the first opcode's file is the only file this Function was derived from - Functions that derive from multiple files (such as compiler-generated closures or entrypoints) will be resolved to a single file, sometimes incorrectly.
        """
        if not self.has_debug or not self.debuginfo or not self.debuginfo.value:
            raise ValueError("Cannot get file from non-debug or empty-debuginfo bytecode!")
        return self.debuginfo.value[0].resolve(code)

    def resolve_nargs(self, code: "Bytecode") -> int:
        """
        Resolves the number of arguments this function takes.
        """
        fun_type = self.type.resolve(code).definition
        if isinstance(fun_type, Fun):
            return fun_type.nargs.value
        return 0

    def deserialise(self, f: BinaryIO | BytesIO, has_debug: bool, version: int) -> "Function":
        self.has_debug = has_debug
        self.version = version
        self.type.deserialise(f)
        self.findex.deserialise(f)
        self.nregs.deserialise(f)
        self.nops.deserialise(f)
        for _ in range(self.nregs.value):
            self.regs.append(tIndex().deserialise(f))
        for _ in range(self.nops.value):
            self.ops.append(Opcode().deserialise(f))
            if self.ops[-1].op in simple_calls and "fun" in self.ops[-1].df:
                self.calls.append(self.ops[-1].df["fun"])
        if self.has_debug:
            self.debuginfo = DebugInfo().deserialise(f, self.nops.value)
            if self.version >= 3:
                self.nassigns = VarInt().deserialise(f)
                self.assigns = []
                for _ in range(self.nassigns.value):
                    self.assigns.append((strRef().deserialise(f), VarInt().deserialise(f)))
        return self

    def insert_op(self, code: "Bytecode", idx: int, op: Opcode, debugRef: Optional[fileRef] = None) -> None:
        """
        Insert an Opcode into this function at the given position, adding a blank debug fileRef if none is passed.
        """
        self.ops.insert(idx, op)
        if code.debugfiles and code.has_debug_info and self.has_debug and self.debuginfo:  # fucking typing...
            if not debugRef:
                debugRef = fileRef(fid=code.debugfiles.find_or_add("?"), line=42)  # life, the universe, and everything
            self.debuginfo.value.insert(idx, debugRef)

    def push_op(self, code: "Bytecode", op: Opcode, debugRef: Optional[fileRef] = None) -> int:
        """
        Push an Opcode into this function at the start.
        """
        self.insert_op(code, 0, op, debugRef=debugRef)
        return 0

    def append_op(self, code: "Bytecode", op: Opcode, debugRef: Optional[fileRef] = None) -> int:
        """
        Append an Opcode to the end of this function.
        """
        self.insert_op(code, len(self.ops), op, debugRef=debugRef)
        return len(self.ops) - 1

    def serialise(self) -> bytes:
        self.nops.value = len(self.ops)
        self.nregs.value = len(self.regs)
        if self.assigns:
            self.nassigns = VarInt(len(self.assigns) if self.assigns else 0)
        if self.has_debug and self.debuginfo:
            assert len(self.debuginfo.value) == self.nops.value, (
                f"Invalid number of debugrefs - {len(self.debuginfo.value)} (debuginfo) != {self.nops.value} (nops) - did you use insert_op?"
            )
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
    __slots__ = ('_global', 'nfields', 'fields')

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
        self.nfields.value = len(self.fields)
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
        self.cached_all: List[Type] | None = None

        self.virtuals_built = False

    def _build_virtual_tables(self) -> None:
        """
        Reconstructs the virtual method table (v-table) for all Obj types.
        This is an internal method called at the end of deserialization.
        """
        if self.virtuals_built:
            return

        processed_class_ids = set()

        def get_all_parent_methods(obj_def: Obj) -> Dict[str, int]:
            # This helper is likely okay, but let's make it safer
            parent_methods = {}
            if obj_def.super and obj_def.super.value is not None:
                try:
                    super_type = obj_def.super.resolve(self)
                    # *** Add a check to prevent cycles in this helper too ***
                    if id(super_type) == id(obj_def.get_containing_type(self)):  # Prevent self-inheritance loops
                        return {}
                    if isinstance(super_type.definition, Obj):
                        super_def = super_type.definition
                        parent_methods.update(get_all_parent_methods(super_def))
                        for proto in super_def.protos:
                            parent_methods[proto.name.resolve(self)] = proto.findex.value
                except (IndexError, AttributeError):
                    dbg_print(f"Warning: Could not resolve superclass for {obj_def.name.resolve(self)}")
            return parent_methods

        def process_class(class_type: Type) -> None:
            class_id = id(class_type)
            if class_id in processed_class_ids:
                return

            obj_def = class_type.definition
            if not isinstance(obj_def, Obj):
                processed_class_ids.add(class_id)
                return

            virtuals = []
            virtual_map = {}

            if obj_def.super is None or obj_def.super.value == -1:
                pass  # virtuals and virtual_map are already empty
            else:
                try:
                    super_type = obj_def.super.resolve(self)
                except IndexError:
                    raise MalformedBytecode(
                        f"Class '{obj_def.name.resolve(self)}' has an invalid superclass index: {obj_def.super.value}"
                    )

                process_class(super_type)

                if isinstance(super_type.definition, Obj):
                    super_def = super_type.definition
                    virtuals.extend(super_def._virtuals)
                    virtual_map.update(super_def._virtual_map)
                else:
                    dbg_print(f"Warning: Superclass of '{obj_def.name.resolve(self)}' is not an Obj.")

            all_parent_method_names = set(get_all_parent_methods(obj_def).keys())

            for proto in obj_def.protos:
                method_name = proto.name.resolve(self)
                findex = proto.findex.value

                is_override = method_name in virtual_map
                is_new_virtual = not is_override and method_name in all_parent_method_names

                if is_override:
                    vid = virtual_map[method_name]
                    virtuals[vid] = findex
                elif is_new_virtual:
                    vid = len(virtuals)
                    virtuals.append(findex)
                    virtual_map[method_name] = vid

            obj_def._virtuals = virtuals
            obj_def._virtual_map = virtual_map
            obj_def.virtuals_initialized = True
            processed_class_ids.add(class_id)

        for t in self.types:
            process_class(t)

        self.virtuals_built = True

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

        void = Type()
        void.kind.value = 0  # Void (_NoDataType)
        void.definition = Void()
        instance.types.append(void)

        if not no_extra_types:
            i32 = Type()
            i32.kind.value = 3
            i32.definition = I32()
            instance.types.append(i32)

            f64 = Type()
            f64.kind.value = 6
            f64.definition = F64()
            instance.types.append(f64)

            bool_t = Type()
            bool_t.kind.value = 7
            bool_t.definition = Bool()
            instance.types.append(bool_t)

        instance.set_meta()

        return instance

    def deserialise(
        self,
        f: BinaryIO | BytesIO,
        search_magic: bool = True,
        init_globals: bool = True,
    ) -> "Bytecode":
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
        if init_globals:
            dbg_print("Initializing globals...")
            self.init_globals()
            dbg_print("Building virtual tables...")
            self._build_virtual_tables()
            dbg_print("Mapping statics...")
            self.map_statics()
        dbg_print(f"{(datetime.now() - start_time).total_seconds()}s elapsed.")
        return self

    def init_globals(self) -> None:
        """
        Internal method to initialize global instances of objects.
        """
        final: Dict[int, Any] = {}
        if self.constants:
            for const in self.constants:
                res: Dict[str, Any] = {}
                obj = const._global.resolve(self).definition
                if not isinstance(obj, Obj):
                    dbg_print("WARNING: Skipping non-Obj constant.")  # should literally never happen
                    continue
                obj_fields = obj.resolve_fields(self)
                for i, field in enumerate(const.fields):
                    # Field has:
                    # - name: strRef
                    # - type: tIndex
                    # we need to use the type to know how to resolve the const ref to the actual value
                    typ = obj_fields[i].type.resolve(self).definition
                    name = obj_fields[i].name.resolve(self)
                    if isinstance(typ, (I32, U8, U16, I64)):
                        res[name] = self.ints[field.value].value
                    elif isinstance(typ, (F32, F64)):
                        res[name] = self.floats[field.value].value
                    elif isinstance(typ, Bytes):
                        res[name] = self.strings.value[field.value]
                    else:
                        res[name] = field.value
                final[const._global.value] = res
            assert len(final) == len(self.constants), (
                "Not all constants were resolved! This is often due to bad DebugInfo blocks causing buffer overrun, try passing -N to troubleshoot."
            )
        self.initialized_globals = final

    def map_statics(self) -> None:
        """
        Maps Haxe compiler-generated static Obj types to their dynamic counterparts, and vice versa. This makes pairing sets of Obj datastructures into full decompiled class definitions much easier later on.
        """
        names: Dict[str, List[Obj]] = {}
        objs: List[Obj] = []
        for typ in self.types:
            if isinstance(typ.definition, Obj):
                assert isinstance(typ.definition, Obj)  # for typechecking to shut up
                objs.append(typ.definition)

        for obj in objs:
            names[destaticify(obj.name.resolve(self))] = []
        for obj in objs:
            names[destaticify(obj.name.resolve(self))].append(obj)

        for _, v in names.items():
            assert len(v) <= 2, "There should only be two matching Objs for each name!"
            s = None
            d = None
            for obj in v:
                if is_static_name(obj.name.resolve(self)):
                    if s is not None:
                        raise MalformedBytecode("Duplicate static classes!")
                    s = obj
                else:
                    if d is not None:
                        raise MalformedBytecode("Duplicate dynamic classes!")
                    d = obj
            if s:
                s._is_static = True
                if d:
                    s._dynamic = d
            if d:
                d._is_static = False
                if s:
                    d._static = s

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
            raise TypeError("This should never happen!")
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
        if self.constants:
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
        if self.version.value >= 4:
            if self.nconstants is None:
                self.nconstants = VarInt()
            self.nconstants.value = len(self.constants)
        if self.has_debug_info:
            if self.ndebugfiles is None:
                self.ndebugfiles = VarInt()
            if self.debugfiles is None:
                self.debugfiles = StringsBlock()
            self.ndebugfiles.value = len(self.debugfiles.value)

    def repair(self) -> None:
        """
        Alternate notation for code.set_meta() for the purpose of clarity.
        """
        self.set_meta()

    def get_test_main(self) -> Function:
        for f in self.functions:
            if self.full_func_name(f).endswith("main"):
                return f
        raise ValueError("No main function found!")

    def get_test_obj(self, test_name: str) -> Obj:
        for t in self.types:
            if isinstance(t.definition, Obj):
                if t.definition.name.resolve(self) == test_name:
                    return t.definition
        raise ValueError("No test class found!")

    def is_ok(self) -> bool:
        """
        Runs a set of basic sanity checks to make sure the bytecode is correct-ish.
        """

        def fail(msg: str) -> None:
            print(f"--- FAILED CHECK ---\n{msg}")

        if len(self.ints) != self.nints.value:
            fail("ints != nints")
            return False

        if len(self.floats) != self.nfloats.value:
            fail("floats != nfloats")
            return False

        if len(self.strings.value) != self.nstrings.value:
            fail("strings != nstrings")
            print(len(self.strings.value), self.nstrings.value)
            return False

        if self.version.value >= 5:
            if self.nbytes is None or self.bytes is None:
                fail("nbytes or bytes is None and version >= 5")
                return False
            if len(self.bytes.value) != self.nbytes.value:
                fail("bytes != nbytes")
                return False

        if len(self.types) != self.ntypes.value:
            fail("types != ntypes")
            return False

        if len(self.global_types) != self.nglobals.value:
            fail("globals != nglobals")
            return False

        if len(self.natives) != self.nnatives.value:
            fail("natives != nnatives")
            return False

        if len(self.functions) != self.nfunctions.value:
            fail("functions != nfunctions")
            return False

        if self.version.value >= 4:
            if self.nconstants is None:
                fail("nconstants is None and version >= 4")
                return False
            if len(self.constants) != self.nconstants.value:
                fail("constants != nconstants")
                return False

        if self.has_debug_info:
            if self.ndebugfiles is None or self.debugfiles is None:
                fail("ndebugfiles or debugfiles is None and has_debug_info")
                return False
            if len(self.debugfiles.value) != self.ndebugfiles.value:
                fail("debugfiles != ndebugfiles")
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

    def add_string(self, string: str) -> strRef:
        """
        Adds a string to the bytecode's string block and returns a reference to it.
        """
        return strRef(self.strings.find_or_add(string))

    def add_i32(self, value: int) -> intRef:
        """
        Adds an integer to the bytecode's integer block and returns a reference to it.
        """
        val = SerialisableInt()
        val.value = value
        self.ints.append(val)
        return intRef(len(self.ints) - 1)

    def next_free_findex(self) -> fIndex:
        """
        Find the next available fIndex that is not already used by any function or native.
        """
        used_indexes = set()
        for function in self.functions:
            used_indexes.add(function.findex.value)
        for native in self.natives:
            used_indexes.add(native.findex.value)

        index = 0
        while index in used_indexes:
            index += 1

        return fIndex(index)

    def find_prim_type(self, kind: Type.Kind) -> tIndex:
        """
        Finds the index of a primitive type in the bytecode.
        """
        assert kind.value in [
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            12,
            13,
            16,
        ], f"This method can only find primitive types! Got: {kind}"
        for i, typ in enumerate(self.types):
            if typ.kind.value == kind.value:
                return tIndex(i)
        raise ValueError(f"Primitive type {kind} not found!")

    def add_type(self, typ: Type) -> tIndex:
        """
        Adds a type and returns its tIndex.
        """
        self.types.append(typ)
        return tIndex(len(self.types) - 1)

    def gather_types(self) -> List[Type]:
        """
        Traverses the entire bytecode to find all unique types referenced, returning
        them as a new list. This is a reimplementation of the `gather_types`
        function from the official hlc compiler.

        The traversal starts from "root" references (globals, natives, functions)
        and recursively explores all types contained within them.
        """
        if self.cached_all is not None:
            return self.cached_all
        unique_types: List[Type] = []
        # We use the serialized form of a type as a key to check for structural uniqueness.
        seen_types: Dict[bytes, int] = {}

        dbg_print("Gathering all types...")

        def _get_type(typ: Optional[Type]) -> None:
            if typ is None:
                return

            # OCaml: `match t with HObj { psuper = Some p } -> get_type (HObj p)`
            # Ensure superclasses are processed first to maintain a logical order.
            if isinstance(typ.definition, (Obj, Struct)) and typ.definition.super:
                # Need to be careful not to resolve if super is None/invalid
                if typ.definition.super.value is not None and typ.definition.super.value >= 0:
                    _get_type(typ.definition.super.resolve(self))

            type_key = typ.serialise()
            if type_key in seen_types:
                return  # Already processed this type structure

            # Add the new unique type to our lists
            seen_types[type_key] = len(unique_types)
            unique_types.append(typ)

            # Deconstruct the type and recurse on inner types
            # This mirrors the `match t with ...` block in the OCaml code.
            defn = typ.definition
            if isinstance(defn, (Fun, Method)):
                for arg_type_ref in defn.args:
                    _get_type(arg_type_ref.resolve(self))
                _get_type(defn.ret.resolve(self))
            elif isinstance(defn, (Obj, Struct)):
                # Super was handled above. Now do fields.
                for field in defn.fields:
                    _get_type(field.type.resolve(self))
                # The OCaml version doesn't seem to traverse protos/bindings,
                # as their function types will be gathered when iterating functions.
            elif isinstance(defn, Enum):
                for construct in defn.constructs:
                    for param_type_ref in construct.params:
                        _get_type(param_type_ref.resolve(self))
            elif isinstance(defn, Virtual):
                for field in defn.fields:
                    _get_type(field.type.resolve(self))
            elif isinstance(defn, (Null, Ref, Packed)):
                # These types all wrap a single inner type.
                # getattr is used to handle the different attribute names ('type' vs 'inner').
                inner_type_ref = getattr(defn, "type", getattr(defn, "inner", None))
                if inner_type_ref:
                    _get_type(inner_type_ref.resolve(self))
            # Primitive types (Void, I32, etc.) and types like Array, Dyn, etc.
            # have no inner types to recurse on.

        # The OCaml code seeds the process with primitives to ensure they get low indices.
        # We'll do the same by creating temporary instances of them.
        primitives_to_seed = [Void, U8, U16, I32, I64, F32, F64, Bool, TypeType, Dyn]
        primitive_kind_map = {p: i for i, p in enumerate(Type.TYPEDEFS)}

        for prim_class in tqdm(primitives_to_seed, desc="Seeding primitives...") if USE_TQDM else primitives_to_seed:
            kind_val = primitive_kind_map.get(prim_class)
            if kind_val is not None:
                # Create a temporary Type object just for the traversal
                temp_type = Type()
                temp_type.kind.value = kind_val
                temp_type.definition = prim_class()
                _get_type(temp_type)

        # OCaml: `Array.iter (fun g -> get_type g) code.globals;`
        for g_type_ref in tqdm(self.global_types, desc="Global roots") if USE_TQDM else self.global_types:
            _get_type(g_type_ref.resolve(self))

        # OCaml: `Array.iter (fun (_,_,t,_) -> get_type t) code.natives;`
        for native in tqdm(self.natives, desc="Natives") if USE_TQDM else self.natives:
            _get_type(native.type.resolve(self))

        # OCaml: `Array.iter (fun f -> ...`
        for func in tqdm(self.functions, desc="Functions") if USE_TQDM else self.functions:
            # `get_type f.ftype;`
            _get_type(func.type.resolve(self))
            # `Array.iter (fun r -> get_type r) f.regs;`
            for reg_type_ref in func.regs:
                _get_type(reg_type_ref.resolve(self))
            # `Array.iter (function OType (_,t) -> get_type t ...`
            for op in func.ops:
                if op.op == "Type":
                    _get_type(op.df["ty"].resolve(self))

        self.cached_all = unique_types
        dbg_print(f"Gathered {len(unique_types)} unique types.")
        return unique_types

    def get_field_for(self, idx: int) -> Optional[Field]:
        """
        Gets the field for a standalone function index.
        """
        for type in self.types:
            if isinstance(type.definition, Obj):
                definition: Obj = type.definition
                fields = definition.resolve_fields(self)
                for binding in definition.bindings:  # binding binds a field to a function
                    if binding.findex.value == idx:
                        return fields[binding.field.value]
        return None

    def get_proto_for(self, idx: int) -> Optional[Proto]:
        """
        Gets the proto for a standalone function index.
        """
        for type in self.types:
            if isinstance(type.definition, Obj):
                definition: Obj = type.definition
                for proto in definition.protos:
                    if proto.findex.value == idx:
                        return proto
        return None

    def full_func_name(self, func: Function | Native) -> str:
        """
        Generates a human-readable name for a function or native.
        """
        proto = self.get_proto_for(func.findex.value)
        if proto:
            name = proto.name.resolve(self)
            for type in self.types:
                if isinstance(type.definition, Obj):
                    obj_def: Obj = type.definition
                    for fun in obj_def.protos:
                        if fun.findex.value == func.findex.value:
                            return f"{obj_def.name.resolve(self)}.{name}"
        else:
            name = "<none>"
            field = self.get_field_for(func.findex.value)
            if field:
                name = field.name.resolve(self)
                for type in self.types:
                    if isinstance(type.definition, Obj):
                        _obj_def: Obj = type.definition
                        fields = _obj_def.resolve_fields(self)
                        for binding in _obj_def.bindings:
                            if binding.findex.value == func.findex.value:
                                return f"{_obj_def.name.resolve(self)}.{name}"
        return name

    def partial_func_name(self, func: Function | Native) -> str:
        """
        Generates a human-readable name for a function or native. Does not qualify the name with the object it belongs to.
        """
        proto = self.get_proto_for(func.findex.value)
        if proto:
            return proto.name.resolve(self)
        else:
            field = self.get_field_for(func.findex.value)
            if field:
                return field.name.resolve(self)
        return "<none>"


__all__ = [
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
