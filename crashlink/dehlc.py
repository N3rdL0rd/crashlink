"""
Dump information from HL/C compiled binaries, and get an approximate reconstruction of the original bytecode.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from .core import (
    Binding,
    Bytecode,
    Field,
    Fun,
    Null,
    Obj,
    Packed,
    Proto,
    Ref,
    Type,
    VarInt,
    Virtual,
    fIndex,
    fieldRef,
    strRef,
    tIndex,
    Abstract,
    Enum,
    EnumConstruct,
)
from .globals import dbg_print

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM, X86_OP_REG
    import lief
except ImportError:
    raise NotImplementedError(
        "Cannot run dehl without lief and capstone installed. Try `pip install crashlink[extras]` or `pip install lief capstone`."
    )

KIND_TO_FIELD_MAP = {
    Type.Kind.FUN: "fun",
    Type.Kind.OBJ: "obj",
    Type.Kind.REF: "tparam",
    Type.Kind.VIRTUAL: "virt",
    Type.Kind.ABSTRACT: "abs_name",
    Type.Kind.ENUM: "tenum",
    Type.Kind.NULL: "tparam",
    Type.Kind.METHOD: "fun",
    Type.Kind.STRUCT: "obj",
    Type.Kind.PACKED: "tparam",
}


def code_from_bin(
    path: str | None = None,
    data: bytes | None = None,
    address_size: int = 8,
    fieldt_length: int = 24,
    protot_length: int = 24,
    bindingt_length: int = 8,
    enumconstruct_length: int = 40,
    union_offset: int = 8,
) -> Bytecode:
    """
    Dumps extracted information from the HL/C binary located on the filesystem at `path` or from the bytes in `data` to a new Bytecode instance.
    """

    print("Parsing binary...")
    code = Bytecode.create_empty(no_extra_types=True)
    if path is not None:
        binary = lief.parse(path)
    elif data is not None:
        binary = lief.parse(data)
    else:
        raise ValueError("One of `path` or `data` must be passed.")

    assert binary is not None, "Failed to parse binary!"
    assert isinstance(binary, (lief.PE.Binary, lief.ELF.Binary, lief.MachO.Binary))

    def get_symbol(name: str) -> lief.Symbol:
        for symbol in binary.symbols:
            if str(symbol.name) == name:
                # dbg_print(f"Symbol {name} -> 0x{symbol.value:x}")
                return symbol
        raise ValueError("No such symbol!")

    def read_int(address: int, size: int) -> int:
        val = binary.get_int_from_virtual_address(address, size)
        # dbg_print(f"Reading int sized {size:x} from 0x{address:x} -> {val}")
        if val is not None:
            return val
        return 0

    def read_bytes(address: int, size: int) -> bytes:
        val = binary.get_content_from_virtual_address(address, size)
        res = bytes(val)
        return res

    def read_chars(address: int, char_size: int) -> bytes:
        """
        Reads a string with characters of length `char_size` until a null terminator. `char_size` is 1 for UTF-8, 2 for UTF-16.
        """
        i = 0
        out = b""
        while True:
            new = read_bytes(address + (i * char_size), char_size)
            out += new
            if not any(new):
                #dbg_print(
                #    f"Read bytes {out.decode('utf-8' if char_size == 1 else 'utf-16', errors='replace')} from 0x{address:x}"
                #)
                return out
            i += 1

    strs: List[str] = []

    def add_str(val: str) -> int:
        """
        Adds a string and returns its index. If it already exists, returns the existing index.
        """
        if not val in strs:
            strs.append(val)
            return len(strs) - 1
        return strs.index(val)

    types: List[Type] = []
    offset_to_tindex: Dict[int, tIndex] = {}
    symbol_name_to_tindex: Dict[str, tIndex] = {}
    print("Pass 1: Types")
    print("Pass 1.1: Remapping types to tIndex space...")
    for i, symbol in enumerate(binary.symbols):
        name = str(symbol.name)
        if name.startswith("t$"):
            idx = tIndex(i)
            offset_to_tindex[symbol.value] = idx
            symbol_name_to_tindex[name] = idx
    print(f"Found {len(offset_to_tindex)} types.")

    print("Pass 1.2: Analyzing hl_init_types...")
    type_assignments: Dict[str, Tuple[str, str]] = {}

    addr_to_symbol_name: Dict[int, str] = {s.value: str(s.name) for s in binary.symbols if s.value != 0}
    sorted_symbols = sorted(
        [(s.value, s) for s in binary.symbols if s.value != 0 and str(s.name).startswith("t$")],
        key=lambda item: item[0],
        reverse=True,
    )

    def find_containing_symbol(address: int) -> Optional[lief.Symbol]:
        for sym_addr, symbol in sorted_symbols:
            if address >= sym_addr and address < sym_addr + symbol.size:
                return symbol
        return None

    try:
        init_func_addr = binary.get_function_address("hl_init_types")
        assert isinstance(init_func_addr, int), "Something goofed while reading the `hl_init_types` symbol!"
        func_symbol = get_symbol("hl_init_types")

        code_bytes = bytes(binary.get_content_from_virtual_address(init_func_addr, func_symbol.size))
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        instructions = list(md.disasm(code_bytes, init_func_addr))

        for i, curr_insn in enumerate(instructions):
            if not (curr_insn.mnemonic.startswith("mov") and len(curr_insn.operands) == 2):
                continue
            dest_op, src_op = curr_insn.operands
            if dest_op.type != X86_OP_MEM:
                continue

            dest_effective_addr = 0
            if dest_op.mem.base == X86_REG_RIP:
                dest_effective_addr = curr_insn.address + curr_insn.size + dest_op.mem.disp
            elif dest_op.mem.base == 0:
                dest_effective_addr = dest_op.mem.disp
            else:
                continue

            dest_symbol = find_containing_symbol(dest_effective_addr)
            if not dest_symbol:
                continue
            if (dest_effective_addr - dest_symbol.value) != union_offset:
                continue

            field_name = None
            try:
                kind_byte = binary.get_content_from_virtual_address(dest_symbol.value, 1)[0]
                field_name = KIND_TO_FIELD_MAP.get(Type.Kind(kind_byte))
            except (TypeError, IndexError):
                continue
            if not field_name:
                continue

            source_symbol_name = None
            if src_op.type == X86_OP_IMM:
                source_symbol_name = addr_to_symbol_name.get(src_op.imm)
            elif src_op.type == X86_OP_REG and i > 0:
                prev_insn = instructions[i - 1]
                if prev_insn.mnemonic.startswith("lea") and len(prev_insn.operands) == 2:
                    lea_dest_op, lea_src_op = prev_insn.operands
                    if (
                        lea_dest_op.reg == src_op.reg
                        and lea_src_op.type == X86_OP_MEM
                        and lea_src_op.mem.base == X86_REG_RIP
                    ):
                        source_addr = prev_insn.address + prev_insn.size + lea_src_op.mem.disp
                        source_symbol_name = addr_to_symbol_name.get(source_addr)

            if source_symbol_name:
                type_assignments[str(dest_symbol.name)] = (field_name, source_symbol_name)

    except Exception as e:
        print(f"Warning: Could not analyze 'hl_init_types'. Some type info may be missing. Reason: {e}")

    print(f"Found {len(type_assignments)} type assignments.")

    print("Pass 1.3: Reading type data...")
    for i, symbol in enumerate(binary.symbols):
        name = str(symbol.name)
        if name.startswith("t$"):
            typ = Type()
            typ.kind.value = read_int(symbol.value, 1)
            match Type.Kind(typ.kind.value):
                case (
                    Type.Kind.VOID
                    | Type.Kind.U8
                    | Type.Kind.U16
                    | Type.Kind.I32
                    | Type.Kind.I64
                    | Type.Kind.F32
                    | Type.Kind.F64
                    | Type.Kind.BOOL
                    | Type.Kind.BYTES
                    | Type.Kind.DYN
                    | Type.Kind.ARRAY
                    | Type.Kind.TYPETYPE
                    | Type.Kind.DYNOBJ
                ):
                    typ.definition = Type.TYPEDEFS[typ.kind.value]()  # _NoDataType

                case Type.Kind.FUN:
                    # first, we need to find the tfunt$... that corresponds to this
                    tfunt = get_symbol("tfun" + name)
                    # then we read the struct like normal...
                    offset_fargst = read_int(tfunt.value, address_size)
                    offset_ret = read_int(tfunt.value + address_size, address_size)
                    nargs = read_int(tfunt.value + (address_size * 2), 1)
                    args: List[tIndex] = []
                    for i in range(nargs):
                        args.append(offset_to_tindex[read_int(offset_fargst + (address_size * i), address_size)])
                    typ.definition = Fun()
                    typ.definition.nargs.value = nargs
                    typ.definition.ret = offset_to_tindex[offset_ret]
                    typ.definition.args = args

                case Type.Kind.OBJ:
                    objt = get_symbol("obj" + name)
                    nfields = read_int(objt.value, 4)
                    nprotos = read_int(objt.value + 4, 4)
                    nbindings = read_int(objt.value + 8, 4)
                    ptr_name = read_int(objt.value + 16, 8)
                    ptr_super = read_int(objt.value + 16 + address_size, 4)
                    ptr_fields = read_int(objt.value + 16 + (address_size * 2), address_size)
                    ptr_protos = read_int(objt.value + 16 + (address_size * 3), address_size)
                    ptr_bindings = read_int(objt.value + 16 + (address_size * 4), address_size)
                    # ptr_global_value = read_int(objt.value + 16 + (address_size * 5), address_size)
                    # TODO: global

                    obj_name = read_chars(ptr_name, 2).decode("utf-16")
                    super = offset_to_tindex[ptr_super] if ptr_super in offset_to_tindex else None
                    fields: List[Field] = []
                    for i in range(nfields):
                        field_base_addr = ptr_fields + (fieldt_length * i)
                        f_name_ptr = read_int(field_base_addr, address_size)
                        f_type_ptr = read_int(field_base_addr + address_size, address_size)
                        if f_name_ptr:
                            f_name = read_chars(f_name_ptr, 2).decode("utf-16")
                        else:
                            f_name = "null"
                        fields.append(Field(name=strRef(add_str(f_name)), type=offset_to_tindex[f_type_ptr]))

                    protos: List[Proto] = []
                    for i in range(nprotos):
                        proto_base_addr = ptr_protos + (protot_length * i)
                        p_name_ptr = read_int(proto_base_addr, address_size)
                        p_findex = read_int(proto_base_addr + 8, 4)
                        p_pindex = read_int(proto_base_addr + 12, 4)
                        # p_hashed_name = read_int(proto_base_addr + 16, 4)
                        if p_name_ptr:
                            p_name = read_chars(p_name_ptr, 2).decode("utf-16").strip()
                        else:
                            p_name = "null"
                        prot = Proto()
                        prot.findex = fIndex(p_findex)
                        prot.pindex = VarInt(p_pindex)
                        prot.name = strRef(add_str(p_name))
                        protos.append(prot)

                    bindings: List[Binding] = []
                    for i in range(nbindings):
                        binding_base_addr = ptr_bindings + (bindingt_length * i)
                        b_field = read_int(binding_base_addr, 4)
                        b_findex = read_int(binding_base_addr + 4, 4)
                        bind = Binding()
                        bind.field = fieldRef(b_field)
                        bind.findex = fIndex(b_findex)
                        bindings.append(bind)

                    typ.definition = Obj()
                    typ.definition.name = strRef(add_str(obj_name))
                    typ.definition.super = super if super else tIndex(-1)
                    typ.definition.nfields.value = nfields
                    typ.definition.nprotos.value = nprotos
                    typ.definition.nbindings.value = nbindings
                    typ.definition.fields = fields
                    typ.definition.protos = protos
                    typ.definition.bindings = bindings

                case Type.Kind.REF | Type.Kind.NULL | Type.Kind.PACKED:
                    field_name, source_symbol_name = type_assignments.get(name, (None, None))

                    if field_name == "tparam" and source_symbol_name:
                        target_tindex = symbol_name_to_tindex.get(source_symbol_name)

                        if target_tindex is not None:
                            if typ.kind.value == Type.Kind.REF.value:
                                ref_def = Ref()
                                ref_def.type = target_tindex
                                typ.definition = ref_def
                            elif typ.kind.value == Type.Kind.NULL.value:
                                null_def = Null()
                                null_def.type = target_tindex
                                typ.definition = null_def
                            elif typ.kind.value == Type.Kind.PACKED.value:
                                packed_def = Packed()
                                packed_def.inner = target_tindex
                                typ.definition = packed_def
                        else:
                            print(
                                f"Warning: Could not find tIndex for source symbol '{source_symbol_name}' referenced by {name}."
                            )
                    else:
                        print(f"Warning: No valid '.tparam' assignment found for ref-like type '{name}'.")

                case Type.Kind.VIRTUAL:
                    field_name, source_symbol_name = type_assignments.get(name, (None, None))

                    if field_name == "virt" and source_symbol_name:
                        virt_t_sym = get_symbol(source_symbol_name)

                        ptr_fields = read_int(virt_t_sym.value, address_size)
                        nfields = read_int(virt_t_sym.value + address_size, 4)

                        fields = []
                        for i in range(nfields):
                            field_base_addr = ptr_fields + (fieldt_length * i)
                            f_name_ptr = read_int(field_base_addr, address_size)
                            f_type_ptr = read_int(field_base_addr + address_size, address_size)

                            f_name = read_chars(f_name_ptr, 2).decode("utf-16") if f_name_ptr else "null"

                            if f_type_ptr in offset_to_tindex:
                                f_type = offset_to_tindex[f_type_ptr]
                                fields.append(Field(name=strRef(add_str(f_name)), type=f_type))
                            else:
                                print(f"Warning: Could not find type for field '{f_name}' in virtual '{name}'")

                        virt_def = Virtual()
                        virt_def.nfields.value = nfields
                        virt_def.fields = fields
                        typ.definition = virt_def

                    else:
                        print(f"Warning: No valid '.virt' assignment found for virtual type '{name}'.")
                        typ.definition = Virtual()

                case Type.Kind.ABSTRACT:
                    abstract_def = Abstract()
                    abstract_def.name = strRef(add_str(name[2:]))
                    typ.definition = abstract_def

                case Type.Kind.ENUM:
                    field_name, source_symbol_name = type_assignments.get(name, (None, None))

                    if field_name == "tenum" and source_symbol_name:
                        enum_t_sym = get_symbol(source_symbol_name)

                        ptr_name = read_int(enum_t_sym.value, address_size)
                        nconstructs = read_int(enum_t_sym.value + address_size, 4)
                        ptr_constructs = read_int(enum_t_sym.value + address_size * 2, address_size)

                        enum_name = (
                            read_chars(ptr_name, 2).decode("utf-16").strip() if ptr_name else f"unknown_enum_{name}"
                        )

                        enum_def = Enum()
                        enum_def.name = strRef(add_str(enum_name))
                        enum_def.nconstructs.value = nconstructs

                        constructs: List[EnumConstruct] = []
                        for i in range(nconstructs):
                            construct_base_addr = ptr_constructs + (enumconstruct_length * i)

                            c_name_ptr = read_int(construct_base_addr, address_size)
                            c_nparams = read_int(construct_base_addr + address_size, 4)
                            c_params_ptr = read_int(construct_base_addr + address_size * 2, address_size)

                            c_name = (
                                read_chars(c_name_ptr, 2).decode("utf-16").strip()
                                if c_name_ptr
                                else f"unknown_construct_{i}"
                            )

                            construct = EnumConstruct()
                            construct.name = strRef(add_str(c_name))
                            construct.nparams.value = c_nparams

                            params: List[tIndex] = []
                            for j in range(c_nparams):
                                param_type_addr_ptr = c_params_ptr + (address_size * j)
                                param_type_addr = read_int(param_type_addr_ptr, address_size)
                                if param_type_addr in offset_to_tindex:
                                    params.append(offset_to_tindex[param_type_addr])
                                else:
                                    print(
                                        f"Warning: Could not find type for param {j} of constructor '{c_name}' in enum '{enum_name}'"
                                    )

                            construct.params = params
                            constructs.append(construct)

                        enum_def.constructs = constructs
                        typ.definition = enum_def
                    else:
                        print(f"Warning: No valid '.tenum' assignment found for enum type '{name}'.")
                        typ.definition = Enum()

                case _:
                    print(f"Unsupported (for now...) type kind: {Type.Kind(typ.kind.value)}")
            types.append(typ)

    code.ntypes.value = len(types)
    code.types = types
    vd = Type()
    vd.kind.value = Type.Kind.VOID.value
    vd.definition = None
    code.types.insert(0, vd)

    # TODO: functions, stubs, strings, bytes, ints, and a whole buncha other stuff

    return code
