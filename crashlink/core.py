"""
Core classes.
"""

import string
import struct
from typing import List, Optional

from .globals import dbg_print, tell
from .errors import MalformedBytecode, NoMagic


class Serialisable:
    def __init__(self):
        raise NotImplementedError("Serialisable is an abstract class and should not be instantiated.")

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

    def deserialise(self, f, length: int = 4, byteorder: str = "little", signed: bool = False) -> "SerialisableInt":
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
    """
    Variable-length integer, unique to HashLink.
    """

    def __init__(self, value: int = 0):
        self.value = value

    def deserialise(self, f) -> "VarInt":
        b = int.from_bytes(f.read(1), "big")
        if b & 0x80 == 0:
            # Single byte value
            self.value = b & 0x7F
        elif b & 0x40 == 0:
            # Two-byte value
            v = int.from_bytes(f.read(1), "big") | ((b & 0x3F) << 8)
            self.value = v if b & 0x20 == 0 else -v
        else:
            # Four-byte value
            c = int.from_bytes(f.read(1), "big")
            d = int.from_bytes(f.read(1), "big")
            e = int.from_bytes(f.read(1), "big")
            v = ((b & 0x3F) << 24) | (c << 16) | (d << 8) | e
            self.value = v if b & 0x20 == 0 else -v
        return self

    def serialise(self) -> bytes:
        if self.value < 0:
            value = -self.value
            if value < 0x2000:
                return bytes([(value >> 8) | 0xA0, value & 0xFF])
            elif value >= 0x20000000:
                raise MalformedBytecode("value can't be >= 0x20000000")
            else:
                return bytes(
                    [
                        (value >> 24) | 0xE0,
                        (value >> 16) & 0xFF,
                        (value >> 8) & 0xFF,
                        value & 0xFF,
                    ]
                )
        else:
            if self.value < 0x80:
                return bytes([self.value])
            elif self.value < 0x2000:
                return bytes([(self.value >> 8) | 0x80, self.value & 0xFF])
            elif self.value >= 0x20000000:
                raise MalformedBytecode("value can't be >= 0x20000000")
            else:
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


class tIndex(VarInt):
    """
    Abstract class based on VarInt to represent a distinct type by index instead of an arbitrary number.
    """


class gIndex(VarInt):
    """
    Global index reference, based on VarInt.
    """


class strRef(VarInt):
    """
    Abstract class to represent a string index.
    """

    def resolve(self, code: "Bytecode") -> str:
        return code.strings.value[self.value]


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
        dbg_print(f"StringsBlock: Found {fmt_bytes(strings_size)} of strings")
        strings_data = f.read(strings_size)

        index = 0
        while index < strings_size:
            string_length = 0
            while index + string_length < strings_size and strings_data[index + string_length] != 0:
                string_length += 1

            if index + string_length >= strings_size:
                raise MalformedBytecode("Invalid string: no null terminator found")

            string = strings_data[index : index + string_length].decode("utf-8", errors="ignore")
            self.value.append(string)
            self.lengths.append(string_length)

            index += string_length + 1  # Skip the null terminator

        for _ in self.value:
            self.embedded_lengths.append(VarInt().deserialise(f))

        return self

    def serialise(self) -> bytes:
        strings_data = b""
        for string in self.value:
            strings_data += string.encode("utf-8") + b"\x00"
        self.length.value = len(strings_data)
        self.lengths = [len(string) for string in self.value]
        self.embedded_lengths = [VarInt(length) for length in self.lengths]
        return b"".join(self.length.serialise(), strings_data, b"".join([i.serialise() for i in self.embedded_lengths]))


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


def create_type(_def: int, f):
    """
    Creates a TypeDef for the given int index, reading from the buffer in f.
    """


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
            [self.nargs.serialise(), b"".join([idx.serialise() for idx in self.args]), self.ret.serialise()]
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
        return b"".join([self.name.serialise(), self.findex.serialise(), self.pindex.serialise()])


class Binding(Serialisable):
    def __init__(self):
        self.field = VarInt()  # field ref, not deserving of its own separate type
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
        return b"".join([self.nfields.serialise(), [field.serialise() for field in self.fields]])


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
        return b"".join([
            self.name.serialise(),
            self.nparams.serialise(),
            b"".join([param.serialise() for param in self.params])
        ])


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
            self.constructs.append([EnumConstruct().deserialise(f)])
        return self

    def serialise(self) -> bytes:
        return b"".join([
            self.name.serialise(),
            self._global.serialise(),
            self.nconstructs.serialise(),
            b"".join([construct.serialise() for construct in self.constructs])
        ])


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
    TYPEDEFS: List[TypeDef] = [
        Void,  # 0
        U8,  # 1
        U16,  # 2
        I32,  # 3
        I64,  # 4
        F32,  # 5
        F64,  # 6
        Bool,  # 7
        Bytes,  # 8
        Dyn,  # 9
        Fun,  # 10
        Obj,  # 11
        Array,  # 12
        TypeType,  # 13
        Ref,  # 14
        Virtual,  # 15
        DynObj,  # 16
        Abstract,  # 17
        Enum,  # 18
        Null,  # 19
        Method,  # 20
        Struct,  # 21
        Packed,  # 22
    ]

    def __init__(self):
        self.kind = SerialisableInt()
        self.kind.length = 1
        self.definition: Optional[TypeDef] = None

    def deserialise(self, f) -> "Type":
        self.kind.deserialise(f, length=1)
        try:
            self.TYPEDEFS[self.kind.value]
            _def = self.TYPEDEFS[self.kind.value]()
            self.definition = _def.deserialise(f)
        except IndexError:
            raise MalformedBytecode(f"Invalid type kind found @{tell(f)}")
        return self

    def serialise(self) -> bytes:
        return b"".join([self.kind.serialise(), self.definition.serialise()])


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
        return b"".join([
            self.lib.serialise(),
            self.name.serialise(),
            self.type.serialise(),
            self.findex.serialise()
        ])

class Opcode(Serialisable):
    


class Function(Serialisable):
    def __init__(self):
        self.type = tIndex()
        self.findex = fIndex()
        self.nregs = VarInt()
        self.nops = VarInt()
        self.regs: List[tIndex] = []
        self.ops: List[Opcode] = []
        # self.debuginfo
        # self.nassigns
        # self.assigns
        

class Bytecode(Serialisable):
    def __init__(self):
        self.magic = RawData(3)
        self.version = SerialisableInt()
        self.version.length = 1
        self.flags = VarInt()
        self.has_debug_info = False
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

    def deserialise(self, f, search_magic=True):
        if search_magic:
            dbg_print("Searching for magic...")
            self.find_magic(f)
        self.magic.deserialise(f)
        assert self.magic.value == b"HLB", "Incorrect magic found!"
        self.version.deserialise(f, length=1)
        dbg_print(f"with version {self.version.value}... ", end="")
        self.flags.deserialise(f)
        self.has_debug_info = bool(self.flags.value & 1)
        dbg_print(f"debug info: {self.has_debug_info}. ")
        self.nints.deserialise(f)
        self.nfloats.deserialise(f)
        self.nstrings.deserialise(f)

        if self.version.value >= 5:
            dbg_print("Found nbytes")
            self.nbytes.deserialise(f)
        else:
            self.nbytes = None

        self.ntypes.deserialise(f)
        self.nglobals.deserialise(f)
        self.nnatives.deserialise(f)
        self.nfunctions.deserialise(f)

        if self.version.value >= 4:
            dbg_print("Found nconstants")
            self.nconstants.deserialise(f)
        else:
            self.nconstants = None

        self.entrypoint.deserialise(f)
        dbg_print(f"Entrypoint: f@{self.entrypoint.value}")

        for _ in range(self.nints.value):
            self.ints.append(SerialisableInt().deserialise(f, length=4))

        for _ in range(self.nfloats.value):
            self.floats.append(SerialisableF64().deserialise(f))

        self.strings.deserialise(f)
        dbg_print(
            f"Found {len(self.strings.value)} strings. nstrings: {self.nstrings.value}. Strings section ends at {tell(f)}"
        )

        if self.version.value >= 5:
            dbg_print("Deserialising bytes... >=5")
            self.bytes.deserialise(f, self.nbytes.value)
        else:
            self.bytes = None

        if self.has_debug_info:
            dbg_print(f"Deserialising debug files... (at {tell(f)})")
            self.ndebugfiles.deserialise(f)
            dbg_print(f"Number of debug files: {self.ndebugfiles.value}")
            self.debugfiles.deserialise(f)
        else:
            self.ndebugfiles = None
            self.debugfiles = None

        dbg_print(f"Starting main blobs at {tell(f)}")
        for _ in range(self.ntypes.value):
            self.types.append(Type().deserialise(f))
        dbg_print(f"Globals starting at {tell(f)}")
        for _ in range(self.nglobals.value):
            self.global_types.append(tIndex().deserialise(f))
        dbg_print(f"Natives starting at {tell(f)}")
        for _ in range(self.nnatives.value):
            self.natives.append(Native().deserialise(f))
        


    def serialise(self) -> bytes:
        # TODO: dynamically set n**** variables to their correct values given their respective **** object - eg. set nfloats to len(floats)
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
        if self.version.value >= 5:
            res += self.nbytes.serialise()
        res.join(
            [
                self.ntypes.serialise(),
                self.nglobals.serialise(),
                self.nnatives.serialise(),
                self.nfunctions.serialise(),
            ]
        )
        if self.version.value >= 4:
            res += self.nconstants.serialise()
        res += self.entrypoint.serialise()
        res.join([i.serialise() for i in self.ints])
        res.join([f.serialise() for f in self.floats])
        res += self.strings.serialise()
        if self.version.value >= 5:
            res += self.bytes.serialise()
        if self.has_debug_info:
            res.join([self.ndebugfiles.serialise(), self.debugfiles.serialise()])
        res.join([
            b"".join([typ.serialise() for typ in self.types]),
            b"".join([typ.serialise() for typ in self.global_types]),
            b"".join([native.serialise() for native in self.natives])
        ])
        return res
