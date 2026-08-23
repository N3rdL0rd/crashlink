"""
Binary image access: symbol views, memory reads, call-target resolution (ELF/PE).
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: F401
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM, X86_OP_REG, X86_REG_RDI, X86_REG_EDI  # noqa: F401
    from capstone.arm64 import (  # noqa: F401
        ARM64_OP_IMM,
        ARM64_OP_REG,
        ARM64_OP_MEM,
        ARM64_REG_X0,
        ARM64_REG_X17,
    )
    import lief  # noqa: F401
except ImportError:
    raise NotImplementedError(
        "Cannot run dehl without lief and capstone installed. Try `pip install crashlink[extras]` or `pip install lief capstone`."
    )

from ..core import Type


# Struct layouts (x86-64), mirrored from hashlink/src/hl.h
# ---------------------------------------------------------------------------
PTR = 8  # pointer / address size

HL_TYPE_UNION_OFFSET = 8  # hl_type.<union> (abs_name|fun|obj|tenum|virt|tparam)

HL_TYPE_FUN_NARGS_OFFSET = 16  # hl_type_fun.nargs

HL_TYPE_OBJ_NFIELDS_OFFSET = 0  # hl_type_obj.nfields
HL_TYPE_OBJ_NAME_OFFSET = 16  # hl_type_obj.name
HL_TYPE_OBJ_SUPER_OFFSET = 24  # hl_type_obj.super
HL_TYPE_OBJ_FIELDS_OFFSET = 32  # hl_type_obj.fields
HL_TYPE_OBJ_PROTOS_OFFSET = 40  # hl_type_obj.proto
HL_TYPE_OBJ_BINDINGS_OFFSET = 48  # hl_type_obj.bindings
HL_TYPE_OBJ_GLOBAL_VALUE_OFFSET = 56  # hl_type_obj.global_value
HL_TYPE_ENUM_GLOBAL_VALUE_OFFSET = 24  # hl_type_enum.global_value (name(8) nconstructs(4+pad4) constructs(8))

HL_OBJ_FIELD_SIZE = 24  # hl_obj_field: name(8) t(8) hashed_name(4) pad(4)
HL_OBJ_PROTO_SIZE = 24  # hl_obj_proto: name(8) findex(4) pindex(4) hashed_name(4)
HL_BINDING_SIZE = 8  # binding pair: field(4) findex(4)

HL_TYPE_VIRT_FIELDS_OFFSET = 0  # hl_type_virtual.fields
HL_TYPE_VIRT_NFIELDS_OFFSET = 8  # hl_type_virtual.nfields

HL_TYPE_ENUM_NAME_OFFSET = 0  # hl_type_enum.name
HL_TYPE_ENUM_NCONSTRUCTS_OFFSET = 8  # hl_type_enum.nconstructs
HL_TYPE_ENUM_CONSTRUCTS_OFFSET = 16  # hl_type_enum.constructs
HL_ENUM_CONSTRUCT_SIZE = (
    40  # hl_enum_construct: name(8) nparams(4) pad(4) params(8) size(4) hasptr(4) offsets(8)
)

HL_TYPE_GLOBAL_PREFIX = "t$"
HL_STRING_GLOBAL_PREFIX = "s$"
HL_VALUE_GLOBAL_PREFIX = "g$"
HL_CONST_STRING_PREFIX = "const_s$"

# Types with no sub-structure: never appear in hl_init_types
SIMPLE_KINDS = {
    Type.Kind.VOID,
    Type.Kind.U8,
    Type.Kind.U16,
    Type.Kind.I32,
    Type.Kind.I64,
    Type.Kind.F32,
    Type.Kind.F64,
    Type.Kind.BOOL,
    Type.Kind.BYTES,
    Type.Kind.DYN,
    Type.Kind.ARRAY,
    Type.Kind.TYPETYPE,
    Type.Kind.DYNOBJ,
}


class _SymSection:
    """Minimal `.section` shim so ELF-style `sym.section.type` checks work for PE symbols."""

    def __init__(self, type_str: str, name: str = ""):
        self.type = type_str
        self.name = name


class _SymView:
    """Format-neutral symbol view (name / absolute address / size / section info)."""

    __slots__ = ("name", "value", "size", "section")

    def __init__(self, name: str, value: int, size: int, sec_type: str, sec_name: str = ""):
        self.name = name
        self.value = value
        self.size = size
        self.section = _SymSection(sec_type, sec_name)


class HLCBinary:
    """
    A thin wrapper over a LIEF binary providing symbol lookup and typed memory reads
    for HL/C-compiled images.
    """

    def __init__(self, path: Optional[str] = None, data: Optional[bytes] = None):
        read: Optional[bytes] = None
        if path is not None:
            try:
                with open(path, "rb") as f:
                    read = f.read()
            except Exception:
                read = None
        elif data is not None:
            read = data
        assert read is not None and len(read) > 2, "Failed to read binary!"
        # Single non-Optional assignment site keeps the attribute type clean.
        self.data: bytes = read

        if self.data[:2] == b"MZ":
            parsed = lief.PE.parse(self.data)
            assert parsed is not None, "Failed to parse PE binary!"
            self.binary = parsed
            self.format = "pe"
        else:
            parsed = lief.parse(self.data)
            assert parsed is not None, "Failed to parse binary!"
            assert isinstance(parsed, lief.ELF.Binary), f"Unsupported format: {type(parsed)}"
            self.binary = parsed
            self.format = "elf"

        self.PTR = PTR
        raw_symbols = list(self.binary.symbols)
        if self.format == "pe":
            raw_symbols = self._normalize_pe_symbols()
        self._symbols = raw_symbols

        self.symbols_by_name: Dict[str, "_SymView"] = {}
        self.symbols_by_addr: Dict[int, List["_SymView"]] = {}
        seen = set()
        for symbol in raw_symbols:
            name = str(symbol.name)
            if not name or (name, symbol.value) in seen:
                continue
            seen.add((name, symbol.value))
            self.symbols_by_name.setdefault(name, symbol)  # ty: ignore[no-matching-overload]
            self.symbols_by_addr.setdefault(symbol.value, []).append(symbol)  # ty: ignore[invalid-argument-type]

        # Architecture detection - drives capstone engine choice and code analysis.
        machine = getattr(getattr(self.binary, "header", None), "machine_type", None)
        if machine is None and self.format == "pe":
            machine = getattr(self.binary.header, "machine", None)
        arch_name = str(machine).rsplit(".", 1)[-1] if machine else ""
        if arch_name in ("AARCH64", "ARM64"):
            self.arch = "aarch64"
        elif arch_name in ("X86_64", "AMD64"):
            self.arch = "x86_64"
        elif arch_name == "I386":
            self.arch = "x86"
        else:
            self.arch = arch_name.lower() or "unknown"
        if self.arch == "x86":
            self.PTR = 4
        # PE images store absolute preferred-base addresses in data; normalize
        # pointer reads down to RVAs so they compare directly against symbol views.
        self.image_base = 0
        if self.format == "pe":
            try:
                self.image_base = int(self.binary.optional_header.imagebase)  # ty: ignore[unresolved-attribute]
            except Exception:
                self.image_base = 0

    @property
    def symbols(self) -> List["_SymView"]:
        """Format-normalized symbol views (absolute addresses, derived sizes)."""
        return self._symbols  # ty: ignore[invalid-return-type]

    def _normalize_pe_symbols(self) -> List["_SymView"]:
        """
        COFF symbols carry section-relative values without sizes. Normalizes them
        into absolute RVAs, derives effective sizes from same-section neighbours,
        and maps the COFF section index to a shim exposing `.section.type` with
        ELF-like "NOBITS" for .bss so downstream layout heuristics work unchanged.
        """
        sections = list(self.binary.sections)
        by_sec: Dict[int, List[Tuple[int, str]]] = {}
        for s in self.binary.symbols:
            name = str(s.name)
            if not name or s.section_idx <= 0 or s.section_idx > len(sections):  # ty: ignore[unresolved-attribute]
                continue
            sec = sections[s.section_idx - 1]  # ty: ignore[unresolved-attribute]
            rva = sec.virtual_address + s.value
            by_sec.setdefault(s.section_idx, []).append((rva, name))  # ty: ignore[unresolved-attribute]
        out: List["_SymView"] = []
        for idx, lst in by_sec.items():
            sec = sections[idx - 1]
            end = sec.virtual_address + sec.size
            lst.sort()
            for i, (rva, name) in enumerate(lst):
                nxt = lst[i + 1][0] if i + 1 < len(lst) else end
                out.append(
                    _SymView(
                        name,
                        rva,
                        max(0, nxt - rva),
                        "NOBITS" if ".bss" in sec.name else "PROGBITS",  # ty: ignore[unsupported-operator]
                        sec.name,  # ty: ignore[invalid-argument-type]
                    )
                )
        return out

    def _capstone(self):
        """Returns a configured capstone engine for this binary's architecture."""
        if self.arch == "aarch64":
            md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        return md

    SCAN_SECTIONS = {".data", ".data.rel.ro", ".rdata", ".rodata", ".bss"}

    def is_static_data(self, sym) -> bool:
        """True when the symbol lives in an initialised/uninitialised data section."""
        try:
            if self.format == "pe":
                return getattr(sym.section, "name", "") in self.SCAN_SECTIONS
            return True
        except Exception:
            return True

    def _build_synth_elf(self) -> Optional[bytes]:
        """
        Wraps a PE image's DWARF sections (emitted by MinGW as COFF long-name
        sections) into a minimal in-memory ELF64 so pyelftools can consume them.
        Returns None when no debug sections exist (e.g. MSVC default builds).
        """
        import struct as _struct

        if self.format != "pe":
            return None
        try:
            (pe_off,) = _struct.unpack("<I", self.data[0x3C:0x40])
            coff = pe_off + 4
            (nsec,) = _struct.unpack("<H", self.data[coff + 2 : coff + 4])
            (opt_size,) = _struct.unpack("<H", self.data[coff + 16 : coff + 18])
            (nsyms,) = _struct.unpack("<I", self.data[coff + 12 : coff + 16])
            (symtab_ptr,) = _struct.unpack("<I", self.data[coff + 8 : coff + 12])
            strtab = symtab_ptr + nsyms * 18
            sec0 = coff + 20 + opt_size
            secs = []  # (real_name, raw_bytes)
            for i in range(nsec):
                e = sec0 + 40 * i
                raw_name = self.data[e : e + 8].rstrip(b"\0").decode(errors="replace")
                if raw_name.startswith("/"):
                    off = int(raw_name[1:])
                    end = self.data.index(b"\0", strtab + off)
                    real = self.data[strtab + off : end].decode(errors="replace")
                else:
                    real = raw_name
                if not real.startswith(".debug"):
                    continue
                (size,) = _struct.unpack("<I", self.data[e + 8 : e + 12])
                (raw_sz,) = _struct.unpack("<I", self.data[e + 16 : e + 20])
                (raw_ptr,) = _struct.unpack("<I", self.data[e + 20 : e + 24])
                if size == 0 or raw_sz == 0:
                    continue
                secs.append((real, self.data[raw_ptr : raw_ptr + min(size, raw_sz)]))
            if not secs:
                return None

            names = [n for n, _ in secs] + [".shstrtab"]
            shstr = b"\0" + b"\0".join(n.encode() for n in names) + b"\0"
            name_offs = {}
            cur = 1
            for n in names:
                name_offs[n] = cur
                cur += len(n.encode()) + 1

            ehsize, shentsize = 64, 64
            data_off = ehsize
            layout = []
            blob = bytearray()
            for _, raw in secs:
                layout.append((data_off + len(blob), len(raw)))
                blob += raw
            while len(blob) % 8:
                blob += b"\0"
            shstr_off = ehsize + len(blob)
            blob += shstr
            while len(blob) % 8:
                blob += b"\0"
            shoff = ehsize + len(blob)

            eh = bytearray(ehsize)
            eh[0:4] = b"\x7fELF"
            eh[4], eh[5], eh[6] = 2, 1, 1  # 64-bit, little-endian
            _struct.pack_into("<H", eh, 16, 1)  # ET_REL
            _struct.pack_into("<H", eh, 18, 0x3E)  # EM_X86_64
            _struct.pack_into("<Q", eh, 40, shoff)  # e_shoff
            _struct.pack_into("<H", eh, 52, ehsize)
            _struct.pack_into("<H", eh, 58, shentsize)
            _struct.pack_into("<H", eh, 60, len(names) + 1)
            _struct.pack_into("<H", eh, 62, len(names))  # .shstrtab index

            def _sh(name_idx: int, s_type: int, off: int, size: int) -> bytes:
                h = bytearray(shentsize)
                _struct.pack_into("<I", h, 0, name_idx)
                _struct.pack_into("<I", h, 4, s_type)
                _struct.pack_into("<Q", h, 24, off)
                _struct.pack_into("<Q", h, 32, size)
                _struct.pack_into("<Q", h, 48, 1)  # addralign
                return bytes(h)

            out = bytearray(eh) + blob
            out += _sh(0, 0, 0, 0)
            for i, (n, raw) in enumerate(secs):
                out += _sh(name_offs[n], 1, layout[i][0], layout[i][1])  # SHT_PROGBITS
            out += _sh(name_offs[".shstrtab"], 3, shstr_off, len(shstr))
            return bytes(out)
        except Exception:
            return None

    def _elffile(self):
        """Returns an ELFFile over the image; PE images are re-wrapped with their DWARF sections."""
        from elftools.elf.elffile import ELFFile  # noqa: F401
        import io as _io

        if self.format == "pe":
            if not hasattr(self, "_synth_elf"):
                self._synth_elf = self._build_synth_elf()
            if self._synth_elf is not None:
                return ELFFile(_io.BytesIO(self._synth_elf))
            return None
        return ELFFile(_io.BytesIO(self.data)) if self.data else None

    def symbol(self, name: str):
        return self.symbols_by_name.get(name)

    def symbol_at(self, address: int) -> Optional[str]:
        syms = self.symbols_by_addr.get(address)
        return str(syms[0].name) if syms else None

    def _build_containing_index(self) -> None:
        """Builds a sorted index of interesting symbols for containing-address lookups."""
        prefixes = (HL_TYPE_GLOBAL_PREFIX, "objt$", "enumt$", "virtt$", "tfunt$")
        entries = []
        seen = set()
        for s in self._symbols:
            n = str(s.name)
            if n.startswith(prefixes) and s.value != 0 and n not in seen:
                seen.add(n)
                entries.append((s.value, s.size, n))
        entries.sort()
        self._containing = entries

    def containing_symbol(self, address: int) -> Optional[Tuple[str, int]]:
        """Returns (name, offset) for the symbol whose storage contains `address`."""
        if not hasattr(self, "_containing"):
            self._build_containing_index()
        lo, hi = 0, len(self._containing)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._containing[mid][0] <= address:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return None
        base, size, name = self._containing[lo - 1]
        if address >= base and (size == 0 or address < base + max(size, PTR)):
            return name, address - base
        return None

    def read_int(self, address: int, size: int) -> int:
        try:
            raw = self.read_bytes(address, size)
            return int.from_bytes(raw, "little")
        except Exception:
            return 0

    def read_ptr(self, address: int) -> int:
        val = self.read_int(address, self.PTR)
        return val - self.image_base if val else 0

    def read_bytes(self, address: int, size: int) -> bytes:
        if size <= 0:
            return b""
        # Clamp to the backing section; unmapped/BSS tails read as zeroes instead of
        # triggering LIEF warnings.
        for section in self.binary.sections:
            va, ssz = section.virtual_address, section.size
            if va <= address < va + ssz:
                avail = min(size, va + ssz - address)
                try:
                    val = self.binary.get_content_from_virtual_address(address, avail)
                    out = bytes(val)
                except Exception:
                    out = b"\x00" * avail
                return out + b"\x00" * (size - avail)
        return b"\x00" * size

    def read_utf16(self, address: int, char_count: int) -> str:
        raw = self.read_bytes(address, char_count * 2)
        return raw.decode("utf-16-le", errors="replace")

    def read_cstr_utf16(self, address: int, max_chars: int = 4096) -> str:
        """Reads a null-terminated UTF-16 string."""
        out = []
        for i in range(max_chars):
            ch = self.read_int(address + i * 2, 2)
            if ch == 0:
                break
            out.append(ch)
        return "".join(chr(c) for c in out)


def disasm_function(bin_view: HLCBinary, name: str) -> list:
    """Disassembles a named function, returning capstone instructions."""
    sym = bin_view.symbol(name)
    if sym is None or sym.size == 0:
        return []
    code_bytes = bin_view.read_bytes(sym.value, sym.size)
    return list(bin_view._capstone().disasm(code_bytes, sym.value))


def _resolve_mem_target(insn, op) -> int:
    """Returns the effective address of a RIP-relative or absolute memory operand."""
    if op.type != X86_OP_MEM:
        return 0
    if op.mem.base == X86_REG_RIP:
        return insn.address + insn.size + op.mem.disp
    if op.mem.base == 0:
        return op.mem.disp
    return 0


def _find_source_symbol(bin_view: HLCBinary, instructions: list, index: int, src_op) -> Optional[str]:
    """Resolves the symbol referenced by an immediate operand or a lea-loaded register."""
    if src_op.type == X86_OP_IMM:
        return bin_view.symbol_at(src_op.imm)
    if src_op.type == X86_OP_REG and index > 0:
        prev = instructions[index - 1]
        if prev.mnemonic.startswith("lea") and len(prev.operands) == 2:
            lea_dest, lea_src = prev.operands
            if lea_dest.reg == src_op.reg and lea_src.type == X86_OP_MEM:
                return bin_view.symbol_at(_resolve_mem_target(prev, lea_src))
    return None


def _resolve_plt_targets(bin_view: "HLCBinary") -> Dict[int, str]:
    """
    Maps PLT stub addresses to the symbol names they resolve to, so calls through the
    PLT can be identified. x86-64: follows each stub's `jmp [GOT]` to its JUMP_SLOT
    relocation. aarch64: scans .plt stubs (adrp/ldr/br) and maps entries to GOT slots.
    """
    plt_map: Dict[int, str] = {}
    binary = bin_view.binary

    if bin_view.arch == "aarch64":
        return _resolve_plt_targets_arm64(bin_view)

    # Precise path: pair each JUMP_SLOT relocation with the `jmp [rip+disp]`
    # stub inside .plt/.plt.sec whose computed GOT address matches.
    try:
        import io as _io

        from elftools.elf.elffile import ELFFile  # noqa: F401

        elf = ELFFile(_io.BytesIO(bin_view.data))
        got_to_name: Dict[int, int] = {}
        symtab = None
        from elftools.elf.relocation import RelocationSection

        for sec in elf.iter_sections():
            if isinstance(sec, RelocationSection):
                symtab = elf.get_section(sec["sh_link"])
                for rel in sec.iter_relocations():
                    if rel["r_info_type"] in (7, 373):  # R_X86_64_JUMP_SLOT / IRELATIVE-safe
                        sname = symtab.get_symbol(rel["r_info_sym"]).name if symtab else ""  # ty: ignore[unresolved-attribute]
                        if sname:
                            got_to_name[rel["r_offset"]] = (
                                sname.decode() if isinstance(sname, bytes) else sname
                            )
        if got_to_name:
            for secname in (".plt", ".plt.sec"):
                pltsec = binary.get_section(secname)
                if pltsec is None:
                    continue
                raw = bytes(pltsec.content)
                base = pltsec.virtual_address
                for off in range(0, len(raw) - 6):
                    if raw[off] == 0xFF and raw[off + 1] == 0x25:
                        disp = struct.unpack("<i", raw[off + 2 : off + 6])[0]
                        got = base + off + 6 + disp
                        nm = got_to_name.get(got)
                        if nm:
                            # attribute the stub start (back up over endbr64)
                            start = base + off
                            if off >= 4 and raw[off - 4 : off] == b"\xf3\x0f\x1e\xfa":
                                start -= 4
                            plt_map[start] = nm  # ty: ignore[invalid-assignment]
            if plt_map:
                return plt_map
    except Exception:
        pass

    # GOT slot -> symbol name
    got_to_name2: Dict[int, str] = {}
    try:
        for r in binary.pltgot_relocations:  # ty: ignore[unresolved-attribute]
            if r.symbol is not None and str(r.symbol.name):
                got_to_name2[r.address] = str(r.symbol.name)
    except Exception:
        pass

    try:
        for entry in binary.plt_entries:  # ty: ignore[unresolved-attribute]
            name = str(entry.symbol.name) if getattr(entry, "symbol", None) is not None else ""
            if name:
                plt_map[entry.address] = name
    except Exception:
        pass
    if plt_map:
        return plt_map

    # Fallback: disassemble stubs reachable from relocations' vicinity is unreliable;
    # instead scan executable segments for `jmp [rip+X]` stubs whose X is in got_to_name.
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    try:
        for segment in binary.segments:  # ty: ignore[unresolved-attribute]
            if not (segment.type == lief.ELF.Segment.TYPE.PH_LOAD and segment.flags & 1):  # ty: ignore[unresolved-attribute, unsupported-operator]
                continue  # executable only
            data = bytes(segment.content)
            for insn in md.disasm(data, segment.virtual_address):  # ty: ignore[invalid-argument-type, missing-argument]
                if insn.mnemonic == "jmp" and len(insn.operands) == 1 and insn.operands[0].type == X86_OP_MEM:
                    got = _resolve_mem_target(insn, insn.operands[0])
                    name = got_to_name2.get(got)
                    if name:
                        plt_map[insn.address] = name
    except Exception:
        pass
    return plt_map


def _resolve_plt_targets_arm64(bin_view: "HLCBinary") -> Dict[int, str]:
    """
    aarch64 PLT resolution: each 16/32-byte stub does `adrp x16, <page>; ldr x17,
    [x16, <off>]; br x17`. We scan the .plt section tracking the GOT address each
    stub loads from, then map it to JUMP_SLOT relocations.
    """
    plt_map: Dict[int, str] = {}

    got_to_name: Dict[int, str] = {}
    try:
        for r in bin_view.binary.relocations:
            if r.symbol is not None and str(r.symbol.name):  # ty: ignore[unresolved-attribute]
                got_to_name[r.address] = str(r.symbol.name)  # ty: ignore[unresolved-attribute]
    except Exception:
        pass

    try:
        import io

        plt = bin_view.binary.get_section(".plt")
        _stream = io.BytesIO(bin_view.data)
        elffile = None
        try:
            from elftools.elf.elffile import ELFFile  # noqa: F401

            elffile = bin_view._elffile()
            sec = elffile.get_section_by_name(".plt")
            if sec is not None:
                code = sec.data()
                va = sec["sh_addr"]
            else:
                code = b""
        except ImportError:
            code = b""
        if not code:
            # Fall back to lief's file offset view.
            raw = bin_view.data
            code = raw[plt.offset : plt.offset + plt.size]
            va = plt.virtual_address

        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        entry_start = None
        page = 0
        loaded_got = 0
        for insn in md.disasm(code, va):  # ty: ignore[invalid-argument-type, missing-argument]
            if insn.mnemonic == "adrp" and len(insn.operands) == 2 and insn.operands[1].type == ARM64_OP_IMM:
                # Each PLT stub opens with adrp x16, <got-page> (the PLT0 header
                # opens with stp instead, which we simply skip over).
                entry_start = insn.address
                page = insn.operands[1].imm
            elif insn.mnemonic == "ldr" and len(insn.operands) == 2 and insn.operands[1].type == ARM64_OP_MEM:
                base = insn.operands[1].mem.base
                # base register of the ldr was set by the preceding adrp into x16
                loaded_got = page + insn.operands[1].mem.disp if base else 0
            elif insn.mnemonic == "br" and entry_start is not None and loaded_got:
                name = got_to_name.get(loaded_got)
                if name:
                    plt_map[entry_start] = name
                entry_start = None
                page = 0
                loaded_got = 0
    except Exception:
        pass
    return plt_map


def _resolve_call_target_name(bin_view: "HLCBinary", plt_map: Dict[int, str], target: int) -> Optional[str]:
    """Resolves a call target to a symbol name, following one PLT indirection."""
    direct = bin_view.symbol_at(target)
    if direct:
        return direct
    if target in plt_map:
        return plt_map[target]
    if bin_view.arch == "aarch64":
        return None
    # Disassemble the stub and follow its jmp into the GOT.
    try:
        data = bin_view.read_bytes(target, 16)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        for insn in md.disasm(data, target):  # ty: ignore[invalid-argument-type, missing-argument]
            if insn.mnemonic == "jmp" and len(insn.operands) == 1 and insn.operands[0].type == X86_OP_MEM:
                got = _resolve_mem_target(insn, insn.operands[0])
                for r in bin_view.binary.pltgot_relocations:  # ty: ignore[unresolved-attribute]
                    if r.address == got and r.symbol is not None:
                        return str(r.symbol.name)
            break
    except Exception:
        pass
    return None


def _elf_imports(bin_view: "HLCBinary") -> set:
    """Names of undefined (imported) symbols - the dynamic-link surface."""
    out = set()
    try:
        for s in bin_view.symbols:
            try:
                if getattr(s, "shndx", None) == 0 and s.value == 0 and s.size == 0 and str(s.name):
                    out.add(str(s.name))
            except Exception:
                continue
    except Exception:
        pass
    return out


def _relocated_table_slots(bin_view: "HLCBinary", sym_name: str) -> Dict[int, str]:
    """
    Maps table-entry index -> target symbol name for entries of the given pointer
    array that carry dynamic relocations. HL/C emits one entry per native in
    `hl_functions_ptrs[]`, relocated to its libhl primitive (`hl_obj_get_field`,
    ...), which recovers the native table exactly - order included.
    """
    out: Dict[int, str] = {}
    try:
        from elftools.elf.relocation import RelocationSection

        sym = bin_view.symbol(sym_name)
        if sym is None or sym.size == 0:
            return out
        lo, hi = sym.value, sym.value + sym.size
        elf = bin_view._elffile()
        if elf is None:
            return out
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            symtab = elf.get_section(sec["sh_link"])
            if symtab is None:
                continue
            for r in sec.iter_relocations():
                off = r["r_offset"]
                if lo <= off < hi and (off - lo) % PTR == 0:
                    s = symtab.get_symbol(r["r_info_sym"])
                    if s.name:
                        out[(off - lo) // PTR] = s.name
    except Exception:
        pass
    return out


def _pe_import_map(bin_view: "HLCBinary") -> Dict[int, str]:
    """
    Maps addresses to `dll!symbol` import names for PE images. Covers both linkage
    styles: slots holding the IAT entry address directly (MSVC __declspec(dllimport))
    and slots holding a jump thunk whose target is the IAT (MinGW).
    """
    out: Dict[int, str] = {}
    try:
        pe = bin_view.binary
        for lib in getattr(pe, "imports", []):
            lname = str(lib.name)
            for e in lib.entries:
                nm = str(e.name) if e.name else ""
                if not nm:
                    continue
                tag = f"{lname}!{nm}"
                if e.iat_address:
                    out.setdefault(e.iat_address, tag)
        # Resolve jmp [rip+disp32] thunks pointing into the IAT.
        text = next((s for s in pe.sections if s.name == ".text"), None)
        if text is not None:
            raw = bytes(text.content)
            base = text.virtual_address
            for off in range(0, len(raw) - 6):
                if raw[off] == 0xFF and raw[off + 1] == 0x25:
                    disp = struct.unpack("<i", raw[off + 2 : off + 6])[0]
                    target = base + off + 6 + disp
                    if target in out:
                        out.setdefault(base + off, out[target])
    except Exception:
        pass
    return out
