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
from typing import Callable, Dict, List, Tuple

from . import decomp, disasm, globals
from .asm import AsmFile
from .core import Bytecode, Native, Virtual, full_func_name, tIndex
from .globals import VERSION
from .interp.vm import VM  # type: ignore
from .opcodes import opcode_docs, opcodes
from .pseudo import pseudo
from hlrun.patch import Patch


class Commands:
    """Container class for all CLI commands"""

    def __init__(self, code: Bytecode):
        self.code = code

    def _format_help(self, doc: str, cmd: str) -> Tuple[str, str]:
        """Formats the docstring for a command. Returns (usage, description)"""
        s = doc.strip().split("`")
        if len(s) == 1:
            return cmd, " ".join(s)
        return s[1], s[0]

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
        for cmd, func in commands.items():
            usage, desc = self._format_help(func.__doc__ or "", cmd)
            print(f"\t{usage} - {desc}")
        print("Type 'help <command>' for information on a specific command.")

    def exit(self, args: List[str]) -> None:
        """Exit the program"""
        sys.exit()

    def wiki(self, args: List[str]) -> None:
        """Open the HLBC wiki in your default browser"""
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

    def funcs(self, args: List[str]) -> None:
        """List all functions in the bytecode - pass 'std' to not exclude stdlib"""
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

    def strings(self, args: List[str]) -> None:
        """List all strings in the bytecode."""
        for i, string in enumerate(self.code.strings.value):
            print(f"String {i}: {string}")

    def types(self, args: List[str]) -> None:
        """List all types in the bytecode."""
        for i, type in enumerate(self.code.types):
            print(f"Type {i}: {type}")

    def savestrings(self, args: List[str]) -> None:
        """Save all strings in the bytecode to a given path. `savestrings <path>`"""
        if len(args) == 0:
            print("Usage: savestrings <path>")
            return
        with open(args[0], "wb") as f:
            for string in self.code.strings.value:
                f.write(string.encode("utf-8", errors="surrogateescape") + b"\n")
        print("Strings saved.")

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

    def int(self, args: List[str]) -> None:
        """
        Print an int by index. `int <index>`
        """
        if len(args) == 0:
            print("Usage: int <index>")
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        try:
            print(self.code.ints[index].value)
        except IndexError:
            print("Int not found.")

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
            print(f"  {field.name.resolve(self.code)}: {field.type.resolve(self.code)}")

    def fnn(self, args: List[str]) -> None:
        """Prints a function by name. `fnn <name>`"""
        if len(args) == 0:
            print("Usage: fnn <name>")
            return
        name = " ".join(args[0:])
        for func in self.code.functions:
            if full_func_name(self.code, func) == name:
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

    def _get_commands(self) -> Dict[str, Callable[[List[str]], None]]:
        """Get all command methods using reflection"""
        return {
            name: func
            for name, func in inspect.getmembers(self, predicate=inspect.ismethod)
            if not name.startswith("_")
        }


def handle_cmd(code: Bytecode, is_hlbc: bool, cmd: str) -> None:
    """Handles a command."""
    cmd_list: List[str] = cmd.split(" ")
    if not cmd_list[0]:
        return

    if is_hlbc:
        raise NotImplementedError("HLBC compatibility mode is not yet implemented.")

    commands = Commands(code)
    available_commands = commands._get_commands()

    if cmd_list[0] in available_commands:
        available_commands[cmd_list[0]](cmd_list[1:])
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
    parser.add_argument("-a", "--assemble", help="Assemble the passed file", action="store_true")
    parser.add_argument(
        "-o",
        "--output",
        help="The output filename for the assembled or patched bytecode.",
    )
    parser.add_argument("-c", "--command", help="The command to run on startup")
    parser.add_argument("-H", "--hlbc", help="Run in HLBC compatibility mode", action="store_true")
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
        handle_cmd(code, args.hlbc, args.command)
    else:
        while True:
            try:
                handle_cmd(code, args.hlbc, input("crashlink> "))
            except KeyboardInterrupt:
                print()
                continue


if __name__ == "__main__":
    main()

__all__: List[str] = []
