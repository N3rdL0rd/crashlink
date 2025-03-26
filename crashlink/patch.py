"""
A Python-based system for patching and hooking of bytecode, similar to [DCCM](https://github.com/dead-cells-core-modding/core).
"""

from .core import *
from .disasm import func_header
from typing import Any, Callable, TypeVar, Dict, Optional, Iterable, BinaryIO, List, Tuple
from io import BytesIO

T = TypeVar('T')

class Args:
    """
    Wrapper for function arguments that tracks their types.
    Allows accessing arguments by index and supports type tracking.
    """
    def __init__(self, values: List[Any], types: List[Any]) -> None:
        self._values = values
        self._types = types
    
    def __getitem__(self, index: int) -> Any:
        return self._values[index]
    
    def __setitem__(self, index: int, value: Any) -> None:
        self._values[index] = value
    
    def get_type(self, index: int) -> Any:
        """Get the type object for the argument at the given index"""
        return self._types[index]
    
    def set_type(self, index: int, type_obj: Any) -> None:
        """Set the type object for the argument at the given index"""
        # TODO: enforce type
        self._types[index] = type_obj
    
    def __len__(self) -> int:
        return len(self._values)
    
    # TODO: iter

class Patch:
    """
    Main patching class that manages bytecode hooks and patches.
    """
    def __init__(self, name: Optional[str] = None, author: Optional[str] = None, sha256: Optional[str] = None):
        """
        Initialize a new patch.
        
        Args:
            name: Descriptive name of the patch
            author: Author of the patch
            sha256: SHA256 hash of the input bytecode file
        """
        self.name = name
        self.author = author
        self.sha256 = sha256
        self.interceptions: Dict[str|int, Callable[[Args], Args]] = {}
        self.needs_pyhl = True
        self.custom_fns: Dict[str, fIndex] = {}
    
    def intercept(self, fn: str|int) -> Callable[[Callable[[Args], Args]], Callable[[Args], Args]]:
        """
        Decorator to intercept function calls.
        
        Args:
            target_path: Path to the target function (e.g., "$PatchMe.thing")
            
        Returns:
            Decorator function
        """
        def decorator(func: Callable[[Args], Args]) -> Callable[[Args], Args]:
            self.interceptions[fn] = func
            return func
        return decorator
    
    def _intercept(self, code: Bytecode, fn: Function, interceptor: Callable[[Args], Args]) -> None:
        """
        Apply an interception.
        """
        # HACK: finds arg regs by looking at where the first Void arg appears. terrible and i hate it but... probably the best way to do this w/out looking at xrefs
        arg_regs: List[tIndex] = []
        for reg in fn.regs:
            if reg.resolve(code).kind.value == Type.Kind.VOID.value:
                break
            arg_regs.append(reg)
        
        arg_virt = Virtual()
        arg_virt.fields.extend([
            Field(
                code.add_string(f"arg_{i}"),
                typ
            )
            for i, typ in enumerate(arg_regs)
        ])
        arg_typ = Type()
        arg_typ.kind.value = Type.Kind.VIRTUAL.value
        arg_typ.definition = arg_virt
        #arg_tid = code.add_type(arg_typ)
        # TODO: why does this cause overruns???
                
        fn.regs.append(code.find_prim_type(Type.Kind.VOID))
        void_reg = Reg(len(fn.regs) - 1)
        bytes_type = code.find_prim_type(Type.Kind.BYTES)
        fn.regs.extend([bytes_type, bytes_type])
        mod_reg = Reg(len(fn.regs) - 2)
        fn_reg = Reg(len(fn.regs) - 1)
        
        op = Opcode()
        op.op = "Call2"
        op.definition = {
            "dst": void_reg,
            "fun": self.custom_fns["call"],
            "arg0": mod_reg,
            "arg1": fn_reg
        }
        fn.insert_op(code, 0, op)
        
        op = Opcode()
        op.op = "String"
        op.definition = {
            "dst": mod_reg,
            "ptr": code.add_string("mod")
        }
        fn.insert_op(code, 0, op)
        
        op = Opcode()
        op.op = "String"
        op.definition = {
            "dst": fn_reg,
            "ptr": code.add_string("test")
        }
        fn.insert_op(code, 0, op)

        
    def _apply_pyhl(self, code: Bytecode) -> None:
        print("Installing pyhl native...")
        pyhl_funcs: Dict[str, Optional[tIndex]] = {
            "init": None,
            "deinit": None,
            "call": None
        }
        indices: Dict[str, Optional[fIndex]] = {
            "init": None,
            "deinit": None,
            "call": None
        }
        for func in pyhl_funcs.keys():
            print(f"Generating types for pyhl.{func}")
            voi = code.find_prim_type(Type.Kind.VOID)
            match func:
                case "init" | "deinit":
                    typ = Type()
                    typ.kind.value = Type.Kind.FUN.value
                    fun = Fun()
                    fun.args = []
                    fun.ret = voi
                    typ.definition = fun
                    pyhl_funcs[func] = code.add_type(typ)
                case "call":
                    typ = Type()
                    typ.kind.value = Type.Kind.FUN.value
                    fun = Fun()
                    byt = code.find_prim_type(Type.Kind.BYTES)
                    fun.args = [byt, byt]
                    fun.ret = code.find_prim_type(Type.Kind.BOOL)
                    typ.definition = fun
                    pyhl_funcs[func] = code.add_type(typ)
                case _:
                    raise NameError("No such pyhl function typedefs: " + func)
                    
        for func, tid in pyhl_funcs.items():
            print(f"Injecting pyhl.{func}")
            native = Native()
            native.lib = code.add_string("pyhl")
            native.name = code.add_string(func)
            assert tid is not None, "Something goofed!"
            native.type = tid
            native.findex = code.next_free_findex()
            indices[func] = native.findex
            code.natives.append(native)
            
        assert all(tid is not None for tid in indices.values()), "Some indices are None!"
        for k, v in indices.items():
            self.custom_fns[k] = v # type: ignore

    def apply(self, code: Bytecode) -> None:
        """
        Apply all registered hooks and patches.
        """
        assert code.is_ok()
        print(f"----- Applying patch:{' ' + self.name if self.name else ''} -----")
        
        if self.needs_pyhl:
            self._apply_pyhl(code)
            
            print("Applying entrypoint patches")
            entry = code.entrypoint.resolve(code)
            assert isinstance(entry, Function), "Entry can't be a native!"

            entry.regs.append(code.find_prim_type(Type.Kind.VOID))
            void_reg = Reg(len(entry.regs) - 1)
            op = Opcode()
            op.op = "Call0"
            assert self.custom_fns["init"] is not None, "Invalid fIndex!"
            op.definition = {
                'dst': void_reg,
                'fun': self.custom_fns["init"]
            }
            entry.insert_op(code, 0, op)

        for identifier, interceptor in self.interceptions.items():
            if isinstance(identifier, int):
                fn = fIndex(identifier).resolve(code)
            else:
                match: Optional[Function] = None
                for fn in code.functions:
                    if full_func_name(code, fn) == identifier:
                        match = fn
                if not match:
                    raise NameError(f"No such function '{identifier}'")
                fn = match
            assert not isinstance(fn, Native), "Cannot intercept a native! (Yet...)" # TODO: native intercept
            print(f"(Intercept) {func_header(code, fn)}\n\tTO -> pyhl") # TODO: other handlers than pyhl, custom hdll injection, etc.
            self._intercept(code, fn, interceptor)
        
        code.set_meta()
        assert code.is_ok()

__all__ = [
    "Patch",
    "Args"
]