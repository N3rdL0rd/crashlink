"""
Entrypoint for the crashlink CLI.
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import os
import platform
import subprocess
import sys
import tempfile
import traceback
import webbrowser
from typing import Callable, Dict, List, Tuple, Set
from functools import wraps

from crashlink.hlc import code_to_c

from . import decomp, disasm, globals
from .asm import AsmFile
from .core import (
    Bytecode,
    Function,
    Native,
    Virtual,
    tIndex,
    strRef,
    gIndex,
    Enum,
    Type,
    Fun,
    Obj,
    Ref,
    Null,
    Packed,
    Abstract,
)
from .globals import VERSION
from .interp.vm import VM  # type: ignore
from .opcodes import opcode_docs, opcodes
from .pseudo import pseudo
from hlrun.patch import Patch


def primary(
    name: str,
) -> Callable[[Callable[[Commands, List[str]], None]], Callable[[Commands, List[str]], None]]:
    """Decorator to set the primary name for a command method, for names that are invalid Python identifiers."""

    def decorator(
        func: Callable[[Commands, List[str]], None],
    ) -> Callable[[Commands, List[str]], None]:
        func._primary_alias = name  # type: ignore
        return func

    return decorator


def alias(
    *aliases: str,
) -> Callable[[Callable[[Commands, List[str]], None]], Callable[[Commands, List[str]], None]]:
    """Decorator to add aliases to command methods"""

    def decorator(
        func: Callable[[Commands, List[str]], None],
    ) -> Callable[[Commands, List[str]], None]:
        func._aliases = aliases  # type: ignore
        return func

    return decorator


class BaseCommands:
    """
    Base class for all command containers.
    """

    def __init__(self, code: Bytecode):
        self.code = code

    def _format_help(self, doc: str, cmd: str) -> Tuple[str, str]:
        """Formats the docstring for a command. Returns (usage, description)"""
        s = doc.strip().split("`")
        if len(s) == 1:
            return cmd, " ".join(s)
        return s[1], s[0]

    def exit(self, args: List[str]) -> None:
        """Exit the program"""
        sys.exit()

    def help(self, args: List[str]) -> None:
        """Prints this help message or information on a specific command. `help (command)`"""
        commands = self._get_commands()
        if args:
            for command in args:
                if command in commands:
                    doc: str = commands[command].__doc__ or ""
                    usage, desc = self._format_help(doc, command)
                    print(f"{usage} - {desc}")
                else:
                    print(f"Unknown command: {command}")
            return

        print("Available commands:")

        # Group commands by their primary name (avoid showing aliases as separate entries)
        primary_commands = self._get_primary_commands()
        command_aliases = self._get_command_aliases()

        for cmd, func in sorted(primary_commands.items()):
            usage, desc = self._format_help(func.__doc__ or "", cmd)
            aliases = command_aliases.get(cmd, [])
            if aliases:
                alias_str = f" (aliases: {', '.join(sorted(aliases))})"
                print(f"\t{usage}{alias_str} - {desc}")
            else:
                print(f"\t{usage} - {desc}")
        print("Type 'help <command>' for information on a specific command.")

    def _get_commands(self) -> Dict[str, Callable[[List[str]], None]]:
        """Get all command methods using reflection, including primary aliases and other aliases."""
        commands: Dict[str, Callable[[List[str]], None]] = {}

        for name, func in inspect.getmembers(self, predicate=inspect.ismethod):
            primary_alias = getattr(func, "_primary_alias", None)

            # Determine the primary command name to register, if any
            primary_cmd_name = None
            if primary_alias:
                primary_cmd_name = primary_alias
            elif not name.startswith("_"):
                primary_cmd_name = name

            # If we identified a primary name, this is a command function.
            # Register its primary name and all of its aliases.
            if primary_cmd_name:
                commands[primary_cmd_name] = func
                if hasattr(func, "_aliases"):
                    for alias_name in func._aliases: # pyright: ignore[reportAttributeAccessIssue]
                        commands[alias_name] = func

        return commands

    def _get_primary_commands(self) -> Dict[str, Callable[[List[str]], None]]:
        """Get only the primary command methods (no aliases), respecting primary aliases."""
        primary_commands: Dict[str, Callable[[List[str]], None]] = {}

        for name, func in inspect.getmembers(self, predicate=inspect.ismethod):
            primary_alias = getattr(func, "_primary_alias", None)

            if primary_alias:
                # Has @primary decorator, use that as the name
                primary_commands[primary_alias] = func
            elif not name.startswith("_"):
                # Regular public method
                primary_commands[name] = func
            # else: internal method without @primary, skip

        return primary_commands

    def _get_command_aliases(self) -> Dict[str, List[str]]:
        """Get a mapping of primary command names to their aliases, respecting primary aliases."""
        alias_map = {}

        for name, func in inspect.getmembers(self, predicate=inspect.ismethod):
            if hasattr(func, "_aliases"):
                primary_name = getattr(func, "_primary_alias", name)
                alias_map[primary_name] = list(func._aliases) # pyright: ignore[reportAttributeAccessIssue]

        return alias_map


class Commands(BaseCommands):
    """Container class for all CLI commands"""

    def __init__(self, code: Bytecode):
        self.code = code

    def exit(self, args: List[str]) -> None:
        """Exit the program"""
        sys.exit()

    def wiki(self, args: List[str]) -> None:
        """Open the ModDocCE wiki page on Hashlink bytecode in your default browser"""
        webbrowser.open("https://n3rdl0rd.github.io/ModDocCE/files/hlboot")

    def op(self, args: List[str]) -> None:
        """Prints the documentation for a given opcode. `op <opcode>`"""

        def _args(args: Dict[str, str]) -> str:
            return "Args -> " + ", ".join(f"{k}: {v}" for k, v in args.items())

        if len(args) == 0:
            print("Usage: op <opcode>")
            return

        query = args[0].lower()

        for opcode in opcode_docs:
            if opcode.lower() == query:
                print()
                print("--- " + opcode + " ---")
                print(_args(opcodes[opcode]))
                print("Desc -> " + opcode_docs[opcode])
                print()
                return

        matches = [opcode for opcode in opcode_docs if query in opcode.lower()]

        if not matches:
            print("Unknown opcode.")
            return

        if len(matches) == 1:
            print()
            print(f"--- {matches[0]} ---")
            print(_args(opcodes[matches[0]]))
            print(f"Desc -> {opcode_docs[matches[0]]}")
            print()
        else:
            print()
            print(f"Found {len(matches)} matching opcodes:")
            for match in matches:
                print(f"- {match}")
            print("\nUse 'op <exact_opcode>' to see documentation for a specific opcode.")
            print()

    @alias("fns")
    def funcs(self, args: List[str]) -> None:
        """List all functions in the bytecode - pass 'std' to not exclude stdlib `funcs [std]`"""
        std = args and args[0] == "std"
        for func in self.code.functions:
            if disasm.is_std(self.code, func) and not std:
                continue
            print(disasm.func_header(self.code, func))
        for native in self.code.natives:
            if disasm.is_std(self.code, native) and not std:
                continue
            print(disasm.native_header(self.code, native))

    def entry(self, args: List[str]) -> None:
        """Prints the entrypoint of the bytecode."""
        entry = self.code.entrypoint.resolve(self.code)
        if isinstance(entry, Native):
            print("Entrypoint: Native")
            print("    Name:", entry.name.resolve(self.code))
        else:
            print("    Entrypoint:", disasm.func_header(self.code, entry))

    @alias("f")
    def fn(self, args: List[str]) -> None:
        """Disassembles a function to pseudocode by findex. `fn <idx>`"""
        if len(args) == 0:
            print("Usage: fn <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        for func in self.code.functions:
            if func.findex.value == index:
                print(disasm.func(self.code, func))
                return
        for native in self.code.natives:
            if native.findex.value == index:
                print(disasm.native_header(self.code, native))
                return
        print("Function not found.")

    def cfg(self, args: List[str]) -> None:
        """Renders a control flow graph for a given findex and attempts to open it in the default image viewer. `cfg <idx>`"""
        if len(args) == 0:
            print("Usage: cfg <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        for func in self.code.functions:
            if func.findex.value == index:
                cfg = decomp.CFGraph(func)
                print("Building control flow graph...")
                cfg.build()
                print("DOT:")
                dot = cfg.graph(self.code)
                print(dot)
                print("Attempting to render graph...")
                with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as f:
                    f.write(dot.encode())
                    dot_file = f.name

                png_file = dot_file.replace(".dot", ".png")
                try:
                    subprocess.run(
                        ["dot", "-Tpng", dot_file, "-o", png_file, "-Gdpi=300"],
                        check=True,
                    )
                except FileNotFoundError:
                    print("Graphviz not found. Install Graphviz to generate PNGs.")
                    return

                try:
                    if platform.system() == "Windows":
                        subprocess.run(["start", png_file], shell=True)
                    elif platform.system() == "Darwin":
                        subprocess.run(["open", png_file])
                    else:
                        subprocess.run(["xdg-open", png_file])
                    os.unlink(dot_file)
                except:
                    print(f"Control flow graph saved to {png_file}. Use your favourite image viewer to open it.")
                return
        print("Function not found.")

    def ir(self, args: List[str]) -> None:
        """Prints the IR of a function in object-notation. `ir <idx>`"""
        if len(args) == 0:
            print("Usage: ir <index>")
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        for func in self.code.functions:
            if func.findex.value == index:
                ir = decomp.IRFunction(self.code, func)
                ir.print()
                return
        print("Function not found.")

    @alias("decompile", "dec", "pseudo")
    def decomp(self, args: List[str]) -> None:
        """Prints the pseudocode decompilation of a function. `decomp <idx>`"""
        if len(args) == 0:
            print("Usage: decomp <index>")
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        for func in self.code.functions:
            if func.findex.value == index:
                ir = decomp.IRFunction(self.code, func)
                res = pseudo(ir)

                print("\n")

                try:
                    from pygments import highlight
                    from pygments.lexers import HaxeLexer
                    from pygments.formatters import Terminal256Formatter

                    lexer = HaxeLexer()
                    formatter = Terminal256Formatter(style="dracula")
                    highlighted_output = highlight(res, lexer, formatter)
                    print(highlighted_output)
                except ImportError:
                    print("[warning] pygments not found.")
                    print(res)
                return
        print("Function not found.")

    @alias("edit")
    def patch(self, args: List[str]) -> None:
        """Patches a function's raw opcodes. `patch <idx>`"""
        if len(args) == 0:
            print("Usage: patch <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            func = self.code.fn(index)
        except ValueError:
            print("Function not found.")
            return
        if isinstance(func, Native):
            print("Cannot patch native.")
            return
        content = f"""{disasm.func(self.code, func)}

###### Modify the opcodes below this line. Any edits above this line will be ignored, and removing this line will cause patching to fail. #####
{disasm.to_asm(func.ops)}"""
        with tempfile.NamedTemporaryFile(suffix=".hlasm", mode="w", encoding="utf-8", delete=False) as f:
            f.write(content)
            file = f.name
        try:
            import tkinter as tk
            from tkinter import scrolledtext

            def save_and_exit() -> None:
                with open(file, "w", encoding="utf-8") as f:
                    f.write(text.get("1.0", tk.END))
                root.destroy()

            root = tk.Tk()
            root.title(f"Editing function f@{index}")
            text = scrolledtext.ScrolledText(root, width=200, height=50)
            text.pack()
            text.insert("1.0", content)

            button = tk.Button(root, text="Save and Exit", command=save_and_exit)
            button.pack()

            root.mainloop()
        except ImportError:
            if os.name == "nt":
                os.system(f'notepad "{file}"')
            elif os.name == "posix":
                os.system(f'nano "{file}"')
            else:
                print("No suitable editor found")
                os.unlink(file)
                return
        try:
            with open(file, "r", encoding="utf-8") as f2:  # why mypy, why???
                modified = f2.read()

            lines = modified.split("\n")
            sep_idx = next(i for i, line in enumerate(lines) if "######" in line)
            new_asm = "\n".join(lines[sep_idx + 1 :])
            new_ops = disasm.from_asm(new_asm)

            func.ops = new_ops
            print(f"Function f@{index} updated successfully")

        except Exception as e:
            print(f"Failed to patch function: {e}")
        finally:
            os.unlink(file)

    def save(self, args: List[str]) -> None:
        """Saves the modified bytecode to a given path. `save <path>`"""
        if len(args) == 0:
            print("Usage: save <path>")
            return
        print("Serialising... (don't panic if it looks stuck!)")
        ser = self.code.serialise()
        print("Saving...")
        with open(args[0], "wb") as f:
            f.write(ser)
        print("Done!")

    @alias("libs")
    def nativelibs(self, args: List[str]) -> None:
        """Prints all unique native dynlibs used by the bytecode. `nativelibs`"""
        native_libs: Set[str] = set()
        for native in self.code.natives:
            if native.lib.value:
                native_libs.add(native.lib.resolve(self.code))
        if not native_libs:
            print("No native libraries found.")
            return
        print("Native libraries used by the bytecode:")
        for lib in sorted(native_libs):
            print(f"- {lib}")

    def hlc(self, args: List[str]) -> None:
        """Transpiles the loaded bytecode to crashlink cHL/C code. `hlc <output path>`"""
        if len(args) == 0:
            print("Usage: hlc <output path>")
            return
        output_path = args[0]
        print("Transpiling to cHL/C...")
        with open(output_path, "w") as f:
            f.write(code_to_c(self.code))
        print(f"cHL/C code written to {output_path}")

    @alias("strs")
    def strings(self, args: List[str]) -> None:
        """List all strings in the bytecode."""
        for i, string in enumerate(self.code.strings.value):
            print(f"String {i}: {string}")

    def types(self, args: List[str]) -> None:
        """List all types in the bytecode."""
        for i, type in enumerate(self.code.types):
            print(f"Type t@{i}: ", end="")
            dfn = type.definition
            if isinstance(dfn, Obj):
                print(f"Obj {dfn.name.resolve(self.code)}")
            elif isinstance(dfn, Fun):
                print(f"Fun {dfn.str_resolve(self.code)}")
            else:
                print(type.kind)
                
    def objs(self, args: List[str]) -> None:
        """List all Objs in the bytecode. `objs`"""
        for i, type in enumerate(self.code.types):
            dfn = type.definition
            if isinstance(dfn, Obj):
                print(f"Type t@{i}: {dfn.name.resolve(self.code)}")
                
    @alias("tn")
    def typenamed(self, args: List[str]) -> None:
        """Finds the type named n. `tn <n>`"""
        if len(args) < 1:
            print("You need to pass a name!")
            return
        for i, type in enumerate(self.code.types):
            if not hasattr(type.definition, "name"):
                continue
            if type.definition.name.resolve(self.code) == args[0]:
                print(f"Found it at t@{i}!")
                    
    @alias("object")
    def obj(self, args: List[str]) -> None:
        """Prints a short overview of a class's fields, protos, and bindings. `obj <tIndex>`"""
        if len(args) == 0:
            print("Usage: obj <tIndex>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid tIndex.")
            return

        try:
            typ = self.code.types[index]
            if not isinstance(typ.definition, Obj):
                print(f"Type t@{index} is not a class (Obj).")
                return

            obj_def: Obj = typ.definition
            class_name = obj_def.name.resolve(self.code)

            print(f"--- Overview for class {class_name} (t@{index}) ---")

            if obj_def.super and obj_def.super.value is not None:
                try:
                    super_name = disasm.type_name(self.code, obj_def.super.resolve(self.code))
                    print(f"Inherits from: {super_name}")
                except Exception:
                     print(f"Inherits from: t@{obj_def.super.value} (Error resolving)")

            print("\nFields:")
            if obj_def.fields:
                for field in obj_def.fields:
                    field_name = field.name.resolve(self.code)
                    field_type_name = disasm.type_name(self.code, field.type.resolve(self.code))
                    print(f"  - {field_name}: {field_type_name}")
            else:
                print("  (No fields)")

            print("\nProtos (Instance Methods):")
            if obj_def.protos:
                for proto in obj_def.protos:
                    # func_header can sometimes include 'static' which is incorrect for protos, so we clean it
                    header = disasm.func_header(self.code, proto.findex.resolve(self.code))
                    print(f"  - {header.replace(' static ', ' ')}")
            else:
                print("  (No protos)")


            print("\nBindings (Static Methods):")
            if obj_def.bindings:
                for binding in obj_def.bindings:
                    header = disasm.func_header(self.code, binding.findex.resolve(self.code))
                    print(f"  - {header}")
            else:
                print("  (No bindings)")

        except IndexError:
            print(f"Type t@{index} not found.")
        except Exception as e:
            print(f"An error occurred: {e}")
            if "-t" in sys.argv or "--traceback" in sys.argv:
                traceback.print_exc()

    @primary("type")
    @alias("t")
    def type_command(self, args: List[str]) -> None:
        """Prints information about a type by tIndex. `type <tIndex>`"""
        if not args:
            print("Usage: type <tIndex>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid tIndex: must be an integer.")
            return

        try:
            resolved_type = self.code.types[index]
        except IndexError:
            print(f"Type t@{index} not found (index out of range).")
            return

        print(f"Type t@{index}:")
        kind_val = resolved_type.kind.value
        kind_name = "Unknown"
        try:
            kind_name = Type.Kind(kind_val).name
        except ValueError:
            # This can happen if kind_val is not a valid member of the Type.Kind enum
            pass

        print(f"  Kind: {kind_val} ({kind_name})")

        definition = resolved_type.definition
        print(f"  Definition Class: {definition.__class__.__name__}")

        # Specific details based on definition type
        if isinstance(definition, Fun):
            fun_def: Fun = definition
            arg_type_names = []
            for arg_tidx in fun_def.args:
                try:
                    arg_type_names.append(disasm.type_name(self.code, arg_tidx.resolve(self.code)))
                except Exception:
                    arg_type_names.append(f"t@{arg_tidx.value}(Error resolving)")

            ret_type_name = f"t@{fun_def.ret.value}(Error resolving)"
            try:
                ret_type_name = disasm.type_name(self.code, fun_def.ret.resolve(self.code))
            except Exception:
                pass

            print(f"  Function Signature: ({', '.join(arg_type_names)}) -> {ret_type_name}")
            print(f"    Argument Count: {fun_def.nargs.value}")

        elif isinstance(definition, Obj):
            obj_def: Obj = definition
            try:
                print(f"  Object Name: {obj_def.name.resolve(self.code)}")
            except Exception:
                print(f"  Object Name: s@{obj_def.name.value}(Error resolving string)")
            print(f"    Number of Fields: {obj_def.nfields.value}")
            print(f"    Number of Prototypes: {obj_def.nprotos.value}")
            if obj_def.super and obj_def.super.value is not None:
                try:
                    super_type_name = disasm.type_name(self.code, obj_def.super.resolve(self.code))
                    print(f"    Super Type: {super_type_name} (t@{obj_def.super.value})")
                except Exception:
                    print(f"    Super Type: t@{obj_def.super.value}(Error resolving)")

        elif isinstance(definition, Ref):
            ref_def: Ref = definition
            inner_type_name = f"t@{ref_def.type.value}(Error resolving)"
            try:
                inner_type_name = disasm.type_name(self.code, ref_def.type.resolve(self.code))
            except Exception:
                pass
            print(f"  References Type: {inner_type_name} (t@{ref_def.type.value})")

        elif isinstance(definition, Null):
            null_def: Null = definition
            inner_type_name = f"t@{null_def.type.value}(Error resolving)"
            try:
                inner_type_name = disasm.type_name(self.code, null_def.type.resolve(self.code))
            except Exception:
                pass
            print(f"  Null of Type: {inner_type_name} (t@{null_def.type.value})")

        elif isinstance(definition, Packed):
            packed_def: Packed = definition
            inner_type_name = f"t@{packed_def.inner.value}(Error resolving)"
            try:
                inner_type_name = disasm.type_name(self.code, packed_def.inner.resolve(self.code))
            except Exception:
                pass
            print(f"  Packed Inner Type: {inner_type_name} (t@{packed_def.inner.value})")

        elif isinstance(definition, Abstract):
            abs_def: Abstract = definition
            try:
                print(f"  Abstract Name: {abs_def.name.resolve(self.code)}")
            except Exception:
                print(f"  Abstract Name: s@{abs_def.name.value}(Error resolving string)")

    @alias("search")
    def ss(self, args: List[str]) -> None:
        """
        Search for a string in the bytecode by substring. `ss <query>`
        """
        if len(args) == 0:
            print("Usage: ss <query>")
            return
        query = " ".join(args)
        for i, string in enumerate(self.code.strings.value):
            if query.lower() in string.lower():
                print(f"String {i}: {string}")

    @alias("s")
    def string(self, args: List[str]) -> None:
        """
        Print a string by index. `string <index>`
        """
        if len(args) == 0:
            print("Usage: string <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            print(self.code.strings.value[index])
        except IndexError:
            print("String not found.")

    @alias("i")
    def int(self, args: List[str]) -> None:
        """
        Print an int by index. `int <index>`
        """
        if len(args) == 0:
            print("Usage: int <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            print(self.code.ints[index].value)
        except IndexError:
            print("Int not found.")

    @primary("global")
    @alias("g")
    def global_command(self, args: List[str]) -> None:
        """Gets a specific global by its gIndex, then shows all its initialized values. `global <gIndex>`"""
        if not args:
            print("Usage: global <gIndex>")
            return

        try:
            gidx = int(args[0])
        except ValueError:
            print("Invalid gIndex: must be an integer.")
            return

        if not (0 <= gidx < len(self.code.global_types)):
            print(f"Global {gidx} not found (index out of range).")
            return

        # Attempt to get the type string for more context
        global_type_str = "Unknown Type"
        try:
            # self.code.global_types[gidx] is a tIndex
            # .resolve(self.code) gets the actual Type object
            global_type_obj = self.code.global_types[gidx].resolve(self.code)
            global_type_str = str(global_type_obj)
        except Exception as e:
            # This might happen if resolve fails or gidx is somehow problematic
            # or if str(global_type_obj) fails.
            if globals.DEBUG:  # Assuming 'globals' is the imported module
                print(f"Error resolving global type for gIndex {gidx}: {e}")
            # Keep "Unknown Type" or default if resolution fails

        initialized_global_data = self.code.initialized_globals.get(gidx)

        if initialized_global_data is not None:
            print(f"Global {gidx} (Type: {global_type_str}):")
            if isinstance(initialized_global_data, dict):
                if initialized_global_data:
                    for field_name, value in initialized_global_data.items():
                        print(f"  {field_name}: {value!r}")  # Use !r for better string representation
                else:
                    # This means it's an object but has no initialized fields, or it's an empty {}
                    print("  (Initialized as an empty object or has no constant-initialized fields)")
            else:
                # This case implies the global was initialized to a non-dict value.
                # Based on Bytecode.init_globals, this is unlikely for the objects it processes.
                print(f"  Initialized Value: {initialized_global_data!r}")
        else:
            # The global gIndex is valid, but it's not in initialized_globals
            print(f"Global {gidx} (Type: {global_type_str}) exists, but has no initialized constant values recorded.")

    def setstring(self, args: List[str]) -> None:
        """
        Set a string by index. `setstring <index> <string>`
        """
        if len(args) < 2:
            print("Usage: setstring <index> <string>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            self.code.strings.value[index] = " ".join(args[1:])
        except IndexError:
            print("String not found.")
        print("String set.")

    def xref(self, args: List[str]) -> None:
        """Prints all function cross-references to a given fIndex. `xref <idx>`"""
        if len(args) == 0:
            print("Usage: xref <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return

        target_func: Function | Native | None = None
        for func in self.code.functions:
            if func.findex.value == index:
                target_func = func
                break
        for native in self.code.natives:
            if native.findex.value == index:
                target_func = native
                break

        if not target_func:
            print("Function not found.")
            return

        xrefs = target_func.called_by(self.code)

        if not xrefs:
            print(f"No cross-references found for function f@{index}.")
            return

        print(f"Cross-references to f@{index} ({self.code.full_func_name(target_func)}):")
        for i, caller_findex in enumerate(xrefs):
            caller = caller_findex.resolve(self.code)
            print(f"  {i}. {disasm.func_header(self.code, caller)}")

    def enum(self, args: List[str]) -> None:
        """Prints information about an enum by tIndex. `enum <index>`"""
        if len(args) == 0:
            print("Usage: enum <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            enum_type = tIndex(index).resolve(self.code)
        except IndexError:
            print("Type not found.")
            return
        if not isinstance(enum_type.definition, Enum):
            print("Type is not an Enum.")
            return
        defn = enum_type.definition
        print(f"Enum t@{index} - {defn.name.resolve(self.code)}")
        print("nconstructs:", defn.nconstructs.value)
        print("Constructs:")
        for i, construct in enumerate(defn.constructs):
            print(f"  {i}: {construct.name.resolve(self.code)}")

    @alias("pkl")
    def pickle(self, args: List[str]) -> None:
        """Pickle the bytecode to a given path. `pickle <path>`"""
        if len(args) == 0:
            print("Usage: pickle <path>")
            return
        try:
            import dill  # type: ignore

            with open(args[0], "wb") as f:
                dill.dump(self.code, f)
            print("Bytecode pickled.")
        except ImportError:
            print("dill not found. Install dill to pickle bytecode, or install crashlink with the [extras] option.")

    def stub(self, args: List[str]) -> None:
        """Generate files in the same structure as the original Haxe source. Requires debuginfo. `stub <path>`"""
        if len(args) == 0:
            print("Usage: stub <path>")
            return
        if not self.code.has_debug_info:
            print("Debug info not found.")
            return
        path = args[0]
        if not os.path.exists(path):
            os.makedirs(path)
        if not self.code.debugfiles:
            print("No debug files found.")
            return
        for file in self.code.debugfiles.value:
            if (
                file == "std" or file == "?" or file.startswith("C:") or file.startswith("D:") or file.startswith("/")
            ):  # FIXME: lazy sanitization
                continue
            try:
                os.makedirs(os.path.join(path, os.path.dirname(file)), exist_ok=True)
                with open(os.path.join(path, file), "w") as f:
                    f.write("")
            except OSError:
                print(f"Failed to write to {os.path.join(path, file)}")
        print(f"Files generated in {os.path.abspath(path)}")

    @alias("run")
    def interp(self, args: List[str]) -> None:
        """Run the bytecode in crashlink's integrated interpreter."""
        if len(args) == 0:
            idx = self.code.entrypoint.value
        else:
            try:
                idx = int(args[0])
            except ValueError:
                print("Invalid index.")
                return

        vm = VM(self.code)
        vm.run(entry=idx)

    def repl(self, args: List[str]) -> None:
        """Drop into a Python REPL with direct access to the Bytecode object."""
        code = self.code

        banner = (
            "Interactive crashlink Python REPL\n"
            "Available globals:\n"
            "  - code: The Bytecode object\n"
            "  - disasm: The crashlink.disasm module\n"
            "  - decomp: The crashlink.decomp module\n"
        )

        local_vars = {
            "code": code,
            "disasm": disasm,
            "decomp": decomp,
        }

        try:
            import IPython

            IPython.embed(banner1=banner, user_ns=local_vars)  # type: ignore
        except ImportError:
            import code as cd

            cd.interact(banner=banner, local=local_vars)

    def offset(self, args: List[str]) -> None:
        """Print the bytecode section at a given offset. `offset <offset in hex>`"""
        if len(args) == 0:
            print("Usage: offset <offset in hex>")
            return
        try:
            offset = int(args[0], 16)
        except ValueError:
            print("Invalid offset.")
            return
        print(self.code.section_at(offset))

    def floats(self, args: List[str]) -> None:
        """List all floats in the bytecode."""
        for i, float in enumerate(self.code.floats):
            print(f"Float {i}: {float.value}")

    def infile(self, args: List[str]) -> None:
        """Finds all functions from a given file in the bytecode. `infile <file>`"""
        if len(args) == 0:
            print("Usage: infile <file>")
            return
        file = args[0]
        if not self.code.has_debug_info:
            print("Debug info not found.")
            return
        for func in self.code.functions:
            if func.resolve_file(self.code) == file:
                print(disasm.func_header(self.code, func))

    def debugfiles(self, args: List[str]) -> None:
        """List all debug files in the bytecode."""
        if self.code.debugfiles and self.code.has_debug_info:
            for i, file in enumerate(self.code.debugfiles.value):
                print(f"{i}: {file}")
        else:
            print("No debug info in bytecode!")
            return

    def virt(self, args: List[str]) -> None:
        """Prints a virtual type by tIndex. `virt <index>`"""
        if len(args) == 0:
            print("Usage: virt <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            virt = tIndex(index).resolve(self.code)
        except IndexError:
            print("Type not found.")
            return
        if not isinstance(virt.definition, Virtual):
            print("Type is not a Virtual.")
            return
        print(f"Virtual t@{index}")
        print("Fields:")
        assert isinstance(virt.definition, Virtual), "Virtual type is not a Virtual."
        for field in virt.definition.fields:
            print(f"  {field.name.resolve(self.code)}: {disasm.type_name(self.code, field.type.resolve(self.code))}")
            
    def enum(self, args: List[str]) -> None:
        """Prints information about an enum by tIndex. `enum <index>`"""
        if len(args) == 0:
            print("Usage: enum <index>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return

        try:
            enum_type = self.code.types[index]
        except IndexError:
            print(f"Type t@{index} not found.")
            return

        if not isinstance(enum_type.definition, Enum):
            print(f"Type t@{index} is not an Enum.")
            return

        defn: Enum = enum_type.definition

        print(f"--- Enum: {defn.name.resolve(self.code)} (t@{index}) ---")
        print(f"Global index: g@{defn._global.value}")
        print(f"Constructs ({defn.nconstructs.value}):")

        if not defn.constructs:
            print("  (No constructs defined)")
        else:
            for i, construct in enumerate(defn.constructs):
                construct_name = construct.name.resolve(self.code)
                if construct.params:
                    # Resolve the type name for each parameter
                    param_types = [disasm.type_name(self.code, p.resolve(self.code)) for p in construct.params]
                    print(f"  {i}: {construct_name}({', '.join(param_types)})")
                else:
                    print(f"  {i}: {construct_name}")


    def fnn(self, args: List[str]) -> None:
        """Prints a function by name. `fnn <name>`"""
        if len(args) == 0:
            print("Usage: fnn <name>")
            return
        name = " ".join(args[0:])
        for func in self.code.functions:
            if self.code.full_func_name(func) == name:
                print(disasm.func_header(self.code, func))
                return
        print("Function not found.")

    def apidocs(self, args: List[str]) -> None:
        """Generate API documentation for all classes in the bytecode based on what can be inferred. Outputs to the given path. `apidocs <path>`"""
        if len(args) == 0:
            print("Usage: apidocs <path>")
            return
        path = args[0]
        if not os.path.exists(path):
            os.makedirs(path)
        if not self.code.debugfiles:
            print("No debug files found.")
            return
        docs: Dict[str, str] = disasm.gen_docs(self.code)
        for file, content in docs.items():
            try:
                os.makedirs(os.path.join(path, os.path.dirname(file)), exist_ok=True)
                with open(os.path.join(path, file), "w") as f:
                    f.write(content)
            except OSError:
                print(f"Failed to write to {os.path.join(path, file)}")
        print(f"Files generated in {os.path.abspath(path)}")

    def info(self, args: List[str]) -> None:
        """Prints information about the bytecode."""
        print(f"Bytecode version: {self.code.version}")
        print(f"Has debug info: {self.code.has_debug_info}")
        print(f"nints: {len(self.code.ints)}")
        print(f"nstrings: {len(self.code.strings.value)}")
        print(f"nfunctions: {len(self.code.functions)}")
        print(f"nnatives: {len(self.code.natives)}")
        print(f"nfloats: {len(self.code.floats)}")
        print(f"ntypes: {len(self.code.types)}")

    @alias("check")
    def verify(self, args: List[str]) -> None:
        """Runs a set of basic sanity checks to make sure the bytecode is correct-ish. `check`"""
        if not self.code.is_ok():
            print("Bytecode verification failed!")
            return
        print("Bytecode verification succeeded!")

    @alias("sref")
    def strref(self, args: List[str]) -> None:
        """
        Find cross-references to a string by index.
        Shows all opcodes that directly reference the string,
        and opcodes that reference global variables initialized with this string.
        `strref <index>`
        """
        if len(args) == 0:
            print("Usage: strref <index>")
            return
        try:
            string_idx_to_find = int(args[0])
        except ValueError:
            print("Invalid index.")
            return

        try:
            target_string = self.code.strings.value[string_idx_to_find]
        except IndexError:
            print(f"String at index {string_idx_to_find} not found in strings table.")
            return

        print(f'Finding references to string {string_idx_to_find}: "{target_string}"')
        print("-" * 30)

        direct_references_found = 0
        print("Direct string references:")
        for func in self.code.functions:
            if func.ops:
                for op_index, opcode in enumerate(func.ops):
                    for param_name, param_value in opcode.df.items():
                        if isinstance(param_value, strRef):
                            if param_value.value == string_idx_to_find:
                                direct_references_found += 1
                                func_name = self.code.full_func_name(func)
                                print(f"  Function {func.findex.value} ({func_name}):")
                                print(
                                    f"    Opcode {op_index}: {opcode.op} - parameter '{param_name}' references string {string_idx_to_find}"
                                )
                                print()

        if direct_references_found == 0:
            print("  No direct references found to this string.")
        print("-" * 30)

        global_refs_to_this_string_found = 0
        globals_containing_string_details = []

        for g_idx in range(len(self.code.global_types)):
            try:
                global_string_value = self.code.const_str(g_idx)
                if global_string_value == target_string:
                    globals_containing_string_details.append((g_idx, global_string_value))
            except (ValueError, TypeError):
                # Not a constant string global, or g_idx out of bounds / not initialized as const string.
                continue

        print("References via global variables:")
        if not globals_containing_string_details:
            print(f'  No global variables found initialized with the string "{target_string}".')
        else:
            for g_idx, global_str_val in globals_containing_string_details:
                printable_global_str_val = global_str_val.replace('"', '\\"')
                print(
                    f'  Global g@{g_idx} is initialized to "{printable_global_str_val}". Searching for references to g@{g_idx}:'
                )
                found_refs_for_this_global = 0
                for func in self.code.functions:
                    if func.ops:
                        for op_index, opcode in enumerate(func.ops):
                            for param_name, param_value in opcode.df.items():
                                if isinstance(param_value, gIndex):
                                    if param_value.value == g_idx:
                                        global_refs_to_this_string_found += 1
                                        found_refs_for_this_global += 1
                                        func_name = self.code.full_func_name(func)
                                        print(f"    Function {func.findex.value} ({func_name}):")
                                        print(
                                            f"      Opcode {op_index}: {opcode.op} - parameter '{param_name}' references global g@{g_idx}"
                                        )
                                        print()
                if found_refs_for_this_global == 0:
                    print(f"    No opcode references found for global g@{g_idx}.")
                print()

        print("-" * 30)
        total_references = direct_references_found + global_refs_to_this_string_found
        if total_references == 0:
            print(f'No references found for string "{target_string}" (index {string_idx_to_find}).')
        else:
            print(
                f"Total references found: {total_references} (Direct: {direct_references_found}, Via Globals: {global_refs_to_this_string_found})"
            )
            
    @primary("class")
    @alias("cls")
    @alias("c")
    def class_(self, args: List[str]) -> None:
        """Decompiles an entire class by its type index. `class <tIndex>`"""
        if len(args) == 0:
            print("Usage: class <tIndex>")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid tIndex.")
            return

        try:
            typ = self.code.types[index]
            if not isinstance(typ.definition, Obj):
                print(f"Type t@{index} is not a class (Obj).")
                return

            ir_class = decomp.IRClass(self.code, typ.definition)
            res = ir_class.pseudo()

            print("\n")

            try:
                from pygments import highlight
                from pygments.lexers import HaxeLexer
                from pygments.formatters import Terminal256Formatter

                lexer = HaxeLexer()
                formatter = Terminal256Formatter(style="dracula")
                highlighted_output = highlight(res, lexer, formatter)
                print(highlighted_output)
            except ImportError:
                print("[warning] pygments not found.")
                print(res)
        except IndexError:
            print(f"Type t@{index} not found.")
        except Exception as e:
            print(f"An error occurred during class decompilation: {e}")
            # A simple way is to check the main args, but ideally it's passed during init.
            if "-t" in sys.argv or "--traceback" in sys.argv:
                traceback.print_exc()


def handle_cmd(code: Bytecode, cmd: str) -> None:
    """Handles a command."""
    cmd_list: List[str] = cmd.split(" ")
    if not cmd_list[0]:
        return

    commands = Commands(code)
    available_commands = commands._get_commands()

    if cmd_list[0] in available_commands:
        if len(cmd_list) > 1:
            available_commands[cmd_list[0]](cmd_list[1:])
        else:
            available_commands[cmd_list[0]]([])
    else:
        print("Unknown command.")


def main() -> None:
    """
    Main entrypoint.
    """
    parser = argparse.ArgumentParser(description=f"crashlink CLI ({VERSION})", prog="crashlink")
    parser.add_argument(
        "file",
        help="The file to open - can be HashLink bytecode, a Haxe source file or a crashlink assembly file.",
    )
    parser.add_argument(
        "-a",
        "--assemble",
        help="Assemble the passed crashlink assembly file",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="The output filename for the assembled or patched bytecode.",
    )
    parser.add_argument("-c", "--command", help="The command to run on startup")
    parser.add_argument(
        "-p",
        "--patch",
        help="Patch the passed file with the following patch definition",
    )
    parser.add_argument(
        "-t",
        "--traceback",
        help="Print tracebacks for debugging when catching exceptions",
        action="store_true",
    )
    parser.add_argument(
        "-N",
        "--no-constants",
        help="Don't resolve constants during deserialisation - helpful for problematic or otherwise weird bytecode files",
        action="store_true",
    )
    parser.add_argument("-d", "--debug", help="Enable addtional debug output", action="store_true")
    parser.add_argument(
        "-D",
        "--no-debug",
        help="Disable debug output that may have been implicitly activted somewhere else",
        action="store_true",
    )
    args = parser.parse_args()

    if args.debug:
        globals.DEBUG = True

    if args.no_debug:
        globals.DEBUG = False

    if args.assemble:
        out = (
            args.output
            if args.output
            else os.path.join(
                os.path.dirname(args.file),
                ".".join(os.path.basename(args.file).split(".")[:-1]) + ".hl",
            )
        )
        with open(out, "wb") as f:
            f.write(AsmFile.from_path(args.file).assemble().serialise())
            print(f"{args.file} -> {'.'.join(os.path.basename(args.file).split('.')[:-1]) + '.hl'}")
            return

    is_haxe = True
    with open(args.file, "rb") as f:
        if f.read(3) == b"HLB":
            is_haxe = False
        else:
            f.seek(0)
            try:
                f.read(128).decode("utf-8")
            except UnicodeDecodeError:
                is_haxe = False
    if is_haxe:
        stripped = args.file.split(".")[0]
        os.system(f"haxe -hl {stripped}.hl -main {args.file}")
        with open(f"{stripped}.hl", "rb") as f:
            code = Bytecode().deserialise(f, init_globals=True if not args.no_constants else False)
    elif not args.file.endswith(".pkl"):
        with open(args.file, "rb") as f:
            code = Bytecode().deserialise(f, init_globals=True if not args.no_constants else False)
    elif args.file.endswith(".pkl"):
        try:
            import dill

            with open(args.file, "rb") as f:
                code = dill.load(f)
        except ImportError:
            print("Dill not found. Install dill to unpickle bytecode, or install crashlink with the [extras] option.")
            return
    else:
        print("Unknown file format.")
        return

    if args.patch:
        print(f"Loading patch: {args.patch}")
        patch_dir = os.path.dirname(args.patch)
        patch_name = os.path.basename(args.patch)

        if patch_name.endswith(".py"):
            patch_name = patch_name[:-3]

        sys.path.insert(0, patch_dir)

        try:
            patch_module = importlib.import_module(patch_name)
            with open(args.patch, "r") as f:
                content = f.read()
            print(f"Successfully loaded patch module: {patch_module}")
            assert isinstance(patch_module.patch, Patch), "`patch` is not an instance of hlrun.patch.Patch!"
            patch_module.patch.apply(code)
            if not args.output:
                args.output = args.file + ".patch"
            with open(args.output, "wb") as f:
                f.write(code.serialise())
            with open(os.path.join(os.path.dirname(args.output), "crashlink_patch.py"), "w") as f:
                f.write(content)
        except ImportError as e:
            print(f"Failed to import patch module: {e}")
            if args.traceback:
                traceback.print_exc()
        except AttributeError:
            print("Could not find `patch`, did you define it?")
            if args.traceback:
                traceback.print_exc()
        finally:
            sys.path.pop(0)
        return

    if args.command:
        handle_cmd(code, args.command)
    else:
        while True:
            try:
                handle_cmd(code, input("crashlink> "))
            except KeyboardInterrupt:
                print()
                continue


if __name__ == "__main__":
    main()

__all__: List[str] = []
