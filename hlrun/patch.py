"""
A Python-based system for patching and hooking of bytecode, similar to [DCCM](https://github.com/dead-cells-core-modding/core).
"""

from typing import Callable, Dict, Optional, TypeVar

from .globals import is_runtime

from .core import Args
from .globals import dbg_print

if is_runtime():
    USE_CRASHLINK = False
else:
    USE_CRASHLINK = True

    from crashlink.core import *
    from crashlink.disasm import func_header

T = TypeVar("T")

# HACK: sorry to future me and anyone who has to read this code. this was my way
# of getting around issues with importing crashlink from pyhl at runtime, and I
# settled on just defining a second Patch class that's stubbed out a bunch,
# but this is really ugly. ideally, i'll come back and fix this some day.

if USE_CRASHLINK:

    class Patch:
        """
        Main patching class that manages bytecode hooks and patches.
        """

        def __init__(
            self,
            name: Optional[str] = None,
            author: Optional[str] = None,
            sha256: Optional[str] = None,
        ):
            """
            Initialize a new patch.

            Note: sha256 is hash of input file
            """
            self.name = name
            self.author = author
            self.sha256 = sha256
            self.interceptions: Dict[str | int, Callable[[Args], Args]] = {}
            self.patches: Dict[str | int, Callable[[Bytecode, Function], None]] = {}
            self.needs_pyhl = False
            self.custom_fns: Dict[str, fIndex] = {}

        def intercept(self, fn: str | int) -> Callable[[Callable[[Args], Args]], Callable[[Args], Args]]:
            """
            Decorator to intercept and modify a function's arguments at call-time.
            """

            self.needs_pyhl = True

            def decorator(
                func: Callable[[Args], Args],
            ) -> Callable[[Args], Args]:
                self.interceptions[fn] = func
                return func

            return decorator

        def patch(
            self, fn: str | int
        ) -> Callable[[Callable[[Bytecode, Function], None]], Callable[[Bytecode, Function], None]]:
            """
            Decorator to patch a function's opcodes directly.
            """

            def decorator(
                func: Callable[[Bytecode, Function], None],
            ) -> Callable[[Bytecode, Function], None]:
                self.patches[fn] = func
                return func

            return decorator

        def _intercept(self, code: Bytecode, fn: Function, identifier: str | int) -> None:
            """
            Apply an interception.
            """
            arg_regs = fn.resolve_fun(code).args
            arg_virt = Virtual()
            arg_virt.fields.extend([Field(code.add_string(f"arg_{i}"), typ) for i, typ in enumerate(arg_regs)])
            arg_typ = Type()
            arg_typ.kind.value = Type.Kind.VIRTUAL.value
            arg_typ.definition = arg_virt
            arg_tid = code.add_type(arg_typ)

            types_str = ",".join([str(arg.resolve(code).kind.value) for arg in arg_regs])

            # fn.regs.append(code.find_prim_type(Type.Kind.VOID))
            # void_reg = Reg(len(fn.regs) - 1)
            bytes_type = code.find_prim_type(Type.Kind.BYTES)
            fn.regs.append(bytes_type)
            fn_name_reg = Reg(len(fn.regs) - 1)
            fn.regs.append(code.find_prim_type(Type.Kind.I32))
            nargs_reg = Reg(len(fn.regs) - 1)
            fn.regs.append(arg_tid)
            virt_reg = Reg(len(fn.regs) - 1)
            fn.regs.append(code.find_prim_type(Type.Kind.BOOL))
            ret_reg = Reg(len(fn.regs) - 1)
            fn.regs.append(code.find_prim_type(Type.Kind.BYTES))
            types_reg = Reg(len(fn.regs) - 1)

            # since we insert at the start, we place in the ops backwards.
            # therefore, we start by reading back from the virt and we end setting up the virt

            for i in reversed(range(len(arg_regs))):
                op = Opcode()
                op.op = "Field"
                op.df = {"dst": Reg(i), "obj": virt_reg, "field": fieldRef(i)}
                fn.push_op(code, op)

            op = Opcode()
            op.op = "Call4"
            op.df = {
                "dst": ret_reg,
                "fun": self.custom_fns["intercept"],
                "arg0": virt_reg,
                "arg1": nargs_reg,
                "arg2": fn_name_reg,
                "arg3": types_reg,
            }
            fn.push_op(code, op)

            op = Opcode()
            op.op = "String"
            op.df = {"dst": fn_name_reg, "ptr": code.add_string(str(identifier))}
            fn.push_op(code, op)

            op = Opcode()
            op.op = "String"
            op.df = {"dst": types_reg, "ptr": code.add_string(types_str)}
            fn.push_op(code, op)

            op = Opcode()
            op.op = "Int"
            op.df = {"dst": nargs_reg, "ptr": code.add_i32(len(arg_regs))}
            fn.push_op(code, op)

            for i in reversed(range(len(arg_regs))):
                op = Opcode()
                op.op = "SetField"
                op.df = {"obj": virt_reg, "field": fieldRef(i), "src": Reg(i)}
                fn.push_op(code, op)

            op = Opcode()
            op.op = "New"
            op.df = {"dst": virt_reg}
            fn.push_op(code, op)

        def _apply_pyhl(self, code: Bytecode) -> None:
            print("Installing pyhl native...")
            pyhl_funcs: Dict[str, Optional[tIndex]] = {
                "init": None,
                "deinit": None,
                "call": None,
                "intercept": None,
            }
            indices: Dict[str, Optional[fIndex]] = {
                "init": None,
                "deinit": None,
                "call": None,
                "intercept": None,
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
                    case "intercept":
                        typ = Type()
                        typ.kind.value = Type.Kind.FUN.value
                        fun = Fun()
                        fun.args = [
                            code.find_prim_type(Type.Kind.DYN),
                            code.find_prim_type(Type.Kind.I32),
                            code.find_prim_type(Type.Kind.BYTES),
                            code.find_prim_type(Type.Kind.BYTES),
                        ]
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
                self.custom_fns[k] = v  # type: ignore

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
                op.df = {"dst": void_reg, "fun": self.custom_fns["init"]}
                entry.insert_op(code, 0, op)

            for identifier, interceptor in self.interceptions.items():
                if isinstance(identifier, int):
                    fn = fIndex(identifier).resolve(code)
                else:
                    mtch: Optional[Function] = None
                    for fn in code.functions:
                        if code.full_func_name(fn) == identifier:
                            mtch = fn
                    if not mtch:
                        raise NameError(f"No such function '{identifier}'")
                    fn = mtch
                assert not isinstance(fn, Native), "Cannot intercept a native! (Yet...)"  # TODO: native intercept
                print(f"(Intercept) {func_header(code, fn)}")  # TODO: other handlers than pyhl
                self._intercept(code, fn, identifier)

            for identifier, patch in self.patches.items():
                if isinstance(identifier, int):
                    fn = fIndex(identifier).resolve(code)
                else:
                    mtch = None
                    for fn in code.functions:
                        if code.full_func_name(fn) == identifier:
                            mtch = fn
                    if not mtch:
                        raise NameError(f"No such function '{identifier}'")
                    fn = mtch
                assert not isinstance(fn, Native), "Cannot patch a native!"
                print(f"(Patch) {func_header(code, fn)}")
                patch(code, fn)

            code.set_meta()  # just to be safe
            assert code.is_ok()

        def do_intercept(self, args: Args, identifier: str | int) -> Args:
            """
            Called at runtime by pyhl to intercept a call. Do not call manually!
            """
            return self.interceptions[identifier](args)
else:

    class Patch:  # type: ignore
        """
        Runtime stub version of the Patch class.
        Maintains API compatibility but provides no patching functionality in runtime mode.
        """

        def __init__(
            self,
            name: Optional[str] = None,
            author: Optional[str] = None,
            sha256: Optional[str] = None,
        ):
            """
            Initialize a new patch (runtime stub).
            """
            self.name = name
            self.author = author
            self.sha256 = sha256
            self.interceptions: Dict[str | int, Callable[[Args], Args]] = {}
            self.patches: Dict[str | int, Callable[[Bytecode, Function], None]] = {}

        def intercept(self, fn: str | int) -> Callable[[Callable[[Args], Args]], Callable[[Args], Args]]:
            """
            Intercept (and modify arguments to) function calls at runtime.
            """

            def decorator(
                func: Callable[[Args], Args],
            ) -> Callable[[Args], Args]:
                self.interceptions[fn] = func
                return func

            return decorator

        def patch(
            self, fn: str | int
        ) -> Callable[[Callable[[object, object], None]], Callable[[object, object], None]]:
            """
            Patch bytecode statically before runtime.
            """

            def decorator(
                func: Callable[[object, object], None],
            ) -> Callable[[object, object], None]:
                self.patches[fn] = func
                return func

            return decorator

        def apply(self, code: object) -> None:
            """
            Runtime stub for applying patches.
            """
            # No-op in runtime mode
            pass

        def do_intercept(self, args: Args, identifier: str | int) -> Args:
            """
            Runtime handler for interception. The only function in this runtime class that does something!
            """
            if identifier in self.interceptions:
                return self.interceptions[identifier](args)
            print(f"\033[33m[pyhl WARNING] [py] No interceptor found in patch definition for '{identifier}'.\033[0m")
            return args


__all__ = ["Patch"]
