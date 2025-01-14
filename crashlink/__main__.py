"""
Entrypoint for the crashlink CLI.
"""

import argparse
import inspect
import os
import platform
import subprocess
import sys
import tempfile
import webbrowser
from typing import Callable, Dict, List, Optional, Tuple

from . import decomp, disasm
from .core import Bytecode, Native
from .globals import VERSION


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
        webbrowser.open("https://github.com/Gui-Yom/hlbc/wiki/Bytecode-file-format")

    def opcodes(self, args: List[str]) -> None:
        """Open the HLBC source to opcodes.rs in your default browser"""
        webbrowser.open("https://github.com/Gui-Yom/hlbc/blob/master/crates/hlbc/src/opcodes.rs")

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
                    subprocess.run(["dot", "-Tpng", dot_file, "-o", png_file, "-Gdpi=300"], check=True)
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

    def pseudo(self, args: List[str]) -> None:
        """Generate pseudocode for a function with the given index. Optionally, specify target language backend. `pseudo <idx> (target: haxe)`"""
        if len(args) == 0:
            print("Usage: pseudo <index> (target: haxe)")
            return
        try:
            index = int(args[0])
        except ValueError:
            print("Invalid index.")
            return
        target = args[1] if len(args) > 1 else "haxe"
        for func in self.code.functions:
            if func.findex.value == index:
                f = decomp.IRFunction(self.code, func)
                if not target in decomp.TARGETS:
                    print(f"Unknown target language: {target}")
                    return
                print(decomp.TARGETS[target](self.code).translate(f))
                return
        print("Function not found.")

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

    def entrypoint(self, args: List[str]) -> None:
        """Get the entrypoint of the bytecode. `entrypoint`"""
        print(self.code.entrypoint)
    
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
    parser.add_argument("file", help="The file to open - can be HashLink bytecode or a Haxe source file")
    parser.add_argument("-c", "--command", help="The command to run on startup")
    parser.add_argument("-H", "--hlbc", help="Run in HLBC compatibility mode", action="store_true")
    args = parser.parse_args()

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
            code = Bytecode().deserialise(f)
    elif not args.file.endswith(".pkl"):
        with open(args.file, "rb") as f:
            code = Bytecode().deserialise(f)
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
