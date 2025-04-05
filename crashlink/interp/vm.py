# type: ignore
# ^ Currently flawed and not ready for typing. Ignore it for now, and fix it later.

"""
Core VM types, values, and the VM itself.
"""

from abc import ABC, abstractmethod
from typing import Any, List, Optional

from ..core import (
    F32,
    F64,
    I32,
    I64,
    U8,
    U16,
    Bool,
    Bytecode,
    Bytes,
    Function,
    Obj,
    Type,
)
from ..globals import bcolors, dbg_print
from .std import BINDINGS as NATIVE_BINDINGS
from .std import StdBinding


class VMValue(ABC):
    """
    Abstract base class for all VM values.
    """

    @abstractmethod
    def __init__(self) -> None:
        pass

    @classmethod
    def from_type_empty(cls, typ: Type, code: Bytecode) -> Optional["VMValue"]:
        """
        Creates a new empty VMValue from a type with a placeholder value.
        """
        def_type = type(typ.definition)
        if def_type is Obj:
            obj: Obj = typ.definition
            created = VMObj.create_empty(obj, code)
            return created
        elif def_type in [I32, U8, U16, I64]:
            return VMInt(0)
        elif def_type in [F32, F64]:
            return VMFloat(0.0)
        elif def_type is Bool:
            return VMBool(False)
        elif def_type is Bytes:
            return VMBytes(b"")
        elif def_type is type(None):
            return None
        return None

    @classmethod
    def from_constant(cls, typ: Type, code: Bytecode, gIndex: int) -> Optional["VMValue"]:
        """
        Creates a VMValue from an initialized global (constant).
        """
        def_type = type(typ.definition)
        if def_type is Obj:
            obj: Obj = typ.definition
            obj_fields = obj.resolve_fields(code)
            fields = [VMValue.from_type_empty(t.type.resolve(code), code) for t in obj_fields]
            values = code.initialized_globals[gIndex]
            for name, value in values.items():
                for i, field in enumerate(obj_fields):
                    if field.name.resolve(code) == name:
                        fields[i] = prim_from_value(value)
                        break
            created = VMObj.create_with_fields(obj, code, fields)
            return created
        else:
            raise ValueError(f"Cannot create constant from {def_type} - {typ} - non-obj constants not supported")

    def typeof(self, code: Bytecode) -> Type:
        """
        Returns the bytecode Type of this object.
        """
        return NotImplemented

    def is_null(self) -> bool:
        """
        Is this object null or uninitialized?
        """
        return True


class VMObj(VMValue):
    """
    Object instance value for the VM.
    """

    def __init__(self, *args, **kwargs) -> None:
        """
        Do not use this constructor directly - use VMObj.create_empty() or VMObj.create_with_fields() instead.
        """
        raise ValueError("Please use VMObj.create_empty() or VMObj.create_with_fields()")

    @classmethod
    def create_empty(cls, obj: Obj, code: Bytecode) -> "VMObj":
        """
        Create an empty object instance
        """
        self = cls.__new__(cls)
        self.obj = obj
        self.code = code
        self.field_meta = obj.resolve_fields(code)
        self.field_values = [VMValue.from_type_empty(t.type.resolve(code), code) for t in self.field_meta]
        return self

    @classmethod
    def create_with_fields(cls, obj: Obj, code: Bytecode, fields: List[VMValue]) -> "VMObj":
        """
        Create an object instance with a given set of fields
        """
        self = cls.__new__(cls)
        self.obj = obj
        self.code = code
        self.field_meta = obj.resolve_fields(code)
        self.field_values = fields
        return self

    def _fields_to_dict(self) -> dict:
        return {f.name.resolve(self.code): v for f, v in zip(self.field_meta, self.field_values)}

    def typeof(self, code: Bytecode) -> Type:
        return self.obj

    def is_null(self):
        return True if all(f.is_null() for f in self.field_values) else False

    def __repr__(self) -> str:
        return f"<Class {self.obj.name.resolve(self.code)} - {self.fields}>"


class VMPrim(VMValue):
    """
    Abstract base class for primitive VM values (ints, floats, bools, byte arrays, etc.).
    """

    def __repr__(self) -> str:
        return f"<VMPrim {self.value}>"

    def __str__(self) -> str:
        return self.__repr__()

    def is_null(self):
        return False


class VMInt(VMPrim):
    """
    VM int primitive.
    """

    def __init__(self, value: int) -> None:
        self.value = value


class VMFloat(VMPrim):
    """
    VM float primitive.
    """

    def __init__(self, value: float) -> None:
        self.value = value


class VMBool(VMPrim):
    """
    VM bool primitive.
    """

    def __init__(self, value: bool) -> None:
        self.value = value


class VMBytes(VMPrim):
    """
    VM byte array primitive.
    """

    def __init__(self, value: bytes) -> None:
        self.value = value


class VMString(VMPrim):
    """
    VM string primitive. TODO: not needed? only byte arrays are primitive
    """

    # TODO
    pass


class VMType(VMPrim):
    """
    VM primitive for the type of an object. (See core.TypeType)
    """

    def __init__(self, value: Type) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f"<VMType {self.value}>"


def prim_from_value(value: Any) -> VMPrim:
    """
    Creates a primitive from a Python object.
    int -> VMInt
    float -> VMFloat
    bool -> VMBool
    bytes -> VMBytes
    str -> VMBytes (encoded as utf-8)
    """
    if isinstance(value, int):
        return VMInt(value)
    if isinstance(value, float):
        return VMFloat(value)
    if isinstance(value, bool):
        return VMBool(value)
    if isinstance(value, bytes) or isinstance(value, bytearray):
        return VMBytes(value)
    if isinstance(value, str):
        return VMBytes(value.encode("utf-8"))
    raise ValueError(f"Cannot convert {value} to VMPrim")


class VMFunction:
    """
    Represents a function in the VM, and wraps a Function object from the bytecode.
    """

    def __init__(self, code: Bytecode, func: Function) -> None:
        self.func = func
        self.code = code
        self.regs: List[Optional[VMObj]] = [None] * len(func.regs)
        self.ops = func.ops
        self.findex = func.findex.value

    def __repr__(self) -> str:
        return f"f@{self.findex}"

    def __str__(self) -> str:
        return self.__repr__()


def cast_prim(value: VMPrim, target: Type) -> VMPrim:
    """
    Casts a VMPrim to another target type - only supports numeric types (and bools) for now, but will eventually support Dyn/Obj casts.
    """
    match target.kind.value:
        case 1:  # U8
            return VMInt(int(value.value) & 0xFF)
        case 2:  # U16
            return VMInt(int(value.value) & 0xFFFF)
        case 3:  # I32
            return VMInt(int(value.value))
        case 4:  # I64
            return VMInt(int(value.value))
        case 5:  # F32
            return VMFloat(float(value.value))
        case 6:  # F64
            return VMFloat(float(value.value))
        case 7:  # Bool
            return VMBool(bool(value.value))
    return None


class VM:
    """
    HashLink VM implementation.
    """

    def __init__(self, code: Bytecode) -> None:
        dbg_print("---- Interp ----")
        self.code = code
        self.callstack: List[VMFunction] = []
        dbg_print("Wrapping functions...")
        self.funcs = [VMFunction(code, func) for func in code.functions]
        self.globals: List[Optional[VMValue]] = []
        dbg_print("Initializing and allocating globals...")
        for i, g in enumerate(code.global_types):
            if i in code.initialized_globals:
                self.globals.append(VMValue.from_constant(g.resolve(code), code, i))
            else:
                self.globals.append(VMValue.from_type_empty(g.resolve(code), code))

    def find_by_findex(self, findex: int) -> VMFunction | StdBinding:
        """
        Finds a wrapped VMFunction or a binding to a native by its findex in the bytecode.
        """
        for func in self.funcs:
            if func.func.findex.value == findex:
                return func
        for native in self.code.natives:
            if native.findex.value == findex:
                name = native.name.resolve(self.code)
                lib = native.lib.resolve(self.code)
                for binding in NATIVE_BINDINGS:
                    if binding.name == name and binding.lib == lib:
                        return binding
                raise NameError(f"Native {name} (from {lib}) not found in crashlink std implementation.")

    def run(self, entry: Optional[int] = None) -> None:
        """
        Runs the VM from the bytecode's entrypoint, or from an arbitrary findex.
        """
        if entry is None:
            entry = self.code.entrypoint.value
        fn = self.find_by_findex(entry)
        self.callstack.append(fn)
        self._call(fn)

    def _call(self, fn: VMFunction, *args: VMValue) -> Optional[VMObj]:
        ip = 0
        dbg_print(f"{'-' * 30} Calling {fn.func.findex.value} {'-' * 30}")
        dbg_print(self.callstack)
        for i, arg in enumerate(args):
            fn.regs[i] = arg
        dbg_print(f"Regs: {fn.regs}")
        while ip < len(fn.ops):
            op = fn.ops[ip]
            s = op.op
            df = op.df
            dbg_print(op)
            match s:
                case "Bool":
                    fn.regs[df["dst"].value] = VMBool(df["value"].value)

                case "Mov":
                    fn.regs[df["dst"].value] = fn.regs[df["src"].value]

                case "Ret":
                    self.callstack.pop()
                    dbg_print(f"{'-' * 30} Returning from {fn.func.findex.value} {'-' * 30}")
                    print(self.callstack)
                    return fn.regs[df["ret"].value]

                case "Call0" | "Call1" | "Call2" | "Call3" | "Call4":
                    args = [fn.regs[df[f"arg{i}"].value] for i in range(int(s[-1]))]
                    callee = self.find_by_findex(df["fun"].value)
                    if isinstance(callee, StdBinding):
                        print("---- Native Call:", callee.name, "----")
                        fn.regs[df["dst"].value] = callee.func(self.code, self, *args)
                    else:
                        self.callstack.append(callee)
                        fn.regs[df["dst"].value] = self._call(callee, *args)

                case "GetGlobal":
                    fn.regs[df["dst"].value] = self.globals[df["global"].value]

                case "SetGlobal":
                    self.globals[df["global"].value] = fn.regs[df["src"].value]

                case "NullCheck":
                    if fn.regs[df["reg"].value] is None or fn.regs[df["reg"].value].is_null():
                        raise ValueError(f"Null check failed on reg {df['reg'].value}")

                case "JNull":
                    if fn.regs[df["reg"].value] is None or fn.regs[df["reg"].value].is_null():
                        ip += df["offset"].value
                        dbg_print(f"{bcolors.OKBLUE}ip += {df['offset'].value}{bcolors.ENDC}")

                case "Type":
                    fn.regs[df["dst"].value] = VMType(df["ty"].resolve(self.code))

                case "String":
                    fn.regs[df["dst"].value] = VMBytes(df["ptr"].resolve(self.code).encode("utf-8"))
                    dbg_print(
                        bcolors.OKBLUE + "Loaded string:",
                        "'" + df["ptr"].resolve(self.code) + "'" + bcolors.ENDC,
                    )

                case "SafeCast":
                    original_type: Type = fn.func.regs[df["src"].value].resolve(self.code)
                    target_type: Type = fn.func.regs[df["dst"].value].resolve(self.code)
                    if original_type is target_type:
                        fn.regs[df["dst"].value] = fn.regs[df["src"].value]
                    else:
                        fn.regs[df["dst"].value] = cast_prim(fn.regs[df["src"].value], target_type)
                    dbg_print(f"{bcolors.OKBLUE}SafeCast: {original_type} -> {target_type}{bcolors.ENDC}")

                case _:
                    dbg_print(f"{bcolors.WARNING}---- UNKNOWN OP: {s} ----{bcolors.ENDC}")
                    pass
            ip += 1
        dbg_print("Warning: implicit return!")
        self.callstack.pop()
        return None
