"""
Core classes.
"""

from typing import Optional, List
import struct
import string

PRINTABLE_ASCII = set(string.printable.encode("ascii"))


class Serialisable:
    def __init__(self):
        raise NotImplementedError(
            "Serialisable is an abstract class and should not be instantiated."
        )

    def deserialise(self, f) -> "Serialisable":
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
    def __init__(self, length: int):
        self.value = b""
        self.length = length

    def deserialise(self, f) -> "RawData":
        self.value = f.read(self.length)
        return self

    def serialise(self) -> bytes:
        return self.value


class SerialisableInt(Serialisable):
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
    def __init__(self):
        self.value = 0.0

    def deserialise(self, f) -> "SerialisableF64":
        self.value = struct.unpack("<d", f.read(8))[0]
        return self

    def serialise(self) -> bytes:
        return struct.pack("<d", self.value)


class VarInt(Serialisable):
    def __init__(self, value: int=0):
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
                raise ValueError("value can't be >= 0x20000000")
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
                raise ValueError("value can't be >= 0x20000000")
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


def fmt_bytes(bytes: int) -> str:
    if bytes < 0:
        raise ValueError("Bytes cannot be negative.")

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
        print(f"StringsBlock: Found {fmt_bytes(strings_size)} of strings")
        strings_data = f.read(strings_size)

        index = 0
        while index < strings_size:
            string_length = 0
            while (
                index + string_length < strings_size
                and strings_data[index + string_length] != 0
            ):
                string_length += 1

            if index + string_length >= strings_size:
                raise ValueError("Invalid string: no null terminator found")

            string = strings_data[index : index + string_length].decode(
                "utf-8", errors="ignore"
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
            strings_data += string.encode("utf-8") + b"\x00"
        self.length.value = len(strings_data)
        self.lengths = [len(string) for string in self.value]
        self.embedded_lengths = [VarInt(length) for length in self.lengths]
        return b"".join(
            self.length.serialise(),
            strings_data,
            b"".join([i.serialise() for i in self.embedded_lengths])
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


def tell(f):
    return hex(f.tell())


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

    def find_magic(self, f, magic=b"HLB"):
        buffer_size = 1024
        offset = 0
        while True:
            chunk = f.read(buffer_size)
            if not chunk:
                raise EOFError("Reached the end of file without finding magic bytes.")
            index = chunk.find(magic)
            if index != -1:
                f.seek(offset + index)
                print(f"Found bytecode at {tell(f)}... ", end="")
                return
            offset += buffer_size

    def deserialise(self, f):
        print("Searching for magic...")
        self.find_magic(f)
        self.magic.deserialise(f)
        assert (
            self.magic.value == b"HLB"
        ), "Incorrect magic found, is this actually HLB?"
        self.version.deserialise(f, length=1)
        print(f"with version {self.version.value}... ", end="")
        self.flags.deserialise(f)
        self.has_debug_info = bool(self.flags.value & 1)
        print(f"debug info: {self.has_debug_info}. ")
        self.nints.deserialise(f)
        self.nfloats.deserialise(f)
        self.nstrings.deserialise(f)

        if self.version.value >= 5:
            print("Found nbytes")
            self.nbytes.deserialise(f)
        else:
            self.nbytes = None

        self.ntypes.deserialise(f)
        self.nglobals.deserialise(f)
        self.nnatives.deserialise(f)
        self.nfunctions.deserialise(f)

        if self.version.value >= 4:
            print("Found nconstants")
            self.nconstants.deserialise(f)
        else:
            self.nconstants = None

        self.entrypoint.deserialise(f)
        print(f"Entrypoint: f@{self.entrypoint.value}")

        for _ in range(self.nints.value):
            self.ints.append(SerialisableInt().deserialise(f, length=4))

        for _ in range(self.nfloats.value):
            self.floats.append(SerialisableF64().deserialise(f))

        self.strings.deserialise(f)
        print(
            f"Found {len(self.strings.value)} strings. nstrings: {self.nstrings.value}. Strings section ends at {tell(f)}"
        )

        if self.version.value >= 5:
            print("Deserialising bytes... >=5")
            self.bytes.deserialise(f, self.nbytes.value)
        else:
            self.bytes = None

        if self.has_debug_info:
            print(f"Deserialising debug files... (at {tell(f)})")
            self.ndebugfiles.deserialise(f)
            print(f"Number of debug files: {self.ndebugfiles.value}")
            self.debugfiles.deserialise(f)
        else:
            self.ndebugfiles = None
            self.debugfiles = None

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
        return res
