"""
Entrypoint for the crashlink CLI.
"""

import argparse
import os
import platform
import subprocess
import sys
import tempfile
import webbrowser
from collections.abc import Callable
from typing import Dict, List, Tuple

from . import decomp, disasm
from .core import Bytecode, Native
from .globals import VERSION


def cmd_help(args: List[str], code: Bytecode) -> None:
    """
    Help command, lists available commands from `COMMANDS`.
    """
    if args:
        for command in args:
            if command in COMMANDS:
                print(f"{command} - {COMMANDS[command][1]}")
            else:
                print(f"Unknown command: {command}")
        return
    print("Available commands:")
    for cmd in COMMANDS:
        print(f"\t{cmd} - {COMMANDS[cmd][1]}")
    print("Type 'help <command>' for information on a specific command.")


def cmd_funcs(args: List[str], code: Bytecode) -> None:
    """
    Prints all functions and natives in the bytecode. If `std` is passed as an argument, it will include stdlib functions.
    """
    std = args and args[0] == "std"
    for func in code.functions:
        if disasm.is_std(code, func) and not std:
            continue
        print(disasm.func_header(code, func))
    for native in code.natives:
        if disasm.is_std(code, native) and not std:
            continue
        print(disasm.native_header(code, native))


def cmd_entry(args: List[str], code: Bytecode) -> None:
    """
    Prints the entrypoint of the bytecode.
    """
    entry = code.entrypoint.resolve(code)
    print("    Entrypoint:", disasm.func_header(code, entry))


def cmd_fn(args: List[str], code: Bytecode) -> None:
    """
    Disassembles a function to pseudocode by findex.
    """
    if not args:
        print("Usage: fn <index>")
        return
    try:
        index = int(args[0])
    except ValueError:
        print("Invalid index.")
        return
    for func in code.functions:
        if func.findex.value == index:
            print(disasm.func(code, func))
            return
    for native in code.natives:
        if native.findex.value == index:
            print(disasm.native_header(code, native))
            return
    print("Function not found.")


def cmd_cfg(args: List[str], code: Bytecode) -> None:
    """
    Renders a control flow graph for a given findex and attempts to open it in the default image viewer.s
    """
    if not args:
        print("Usage: cfg <index>")
        return
    try:
        index = int(args[0])
    except ValueError:
        print("Invalid index.")
        return
    for func in code.functions:
        if func.findex.value == index:
            cfg = decomp.CFGraph(func)
            print("Building control flow graph...")
            cfg.build()
            print("DOT:")
            dot = cfg.graph(code)
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


def cmd_ir(args: List[str], code: Bytecode) -> None:
    if not args:
        print("Usage: ir <index>")
    try:
        index = int(args[0])
    except ValueError:
        print("Invalid index.")
        return
    for func in code.functions:
        if func.findex.value == index:
            ir = decomp.IRFunction(code, func)
            ir.print()
            return
    print("Function not found.")


def cmd_patch(args: List[str], code: Bytecode) -> None:
    if not args:
        print("Usage: patch <index>")
        return
    try:
        index = int(args[0])
    except ValueError:
        print("Invalid index.")
        return
    try:
        func = code.fn(index)
    except ValueError:
        print("Function not found.")
        return
    if isinstance(func, Native):
        print("Cannot patch native.")
        return
    content = f"""{disasm.func(code, func)}

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
        with open(file, "r", encoding="utf-8") as f2:  # whyyyy mypy, whyyyy???
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


def cmd_save(args: List[str], code: Bytecode) -> None:
    if not args:
        print("Usage: save <path>")
        return
    print("Serialising...")
    ser = code.serialise()
    print("Saving...")
    with open(args[0], "wb") as f:
        f.write(ser)
    print("Done!")


# typing is ignored for lambdas because webbrowser.open returns a bool instead of None
COMMANDS: Dict[str, Tuple[Callable[[List[str], Bytecode], None], str]] = {
    "exit": (lambda _, __: sys.exit(), "Exit the program"),
    "help": (cmd_help, "Show this help message"),
    "wiki": (
        lambda _, __: webbrowser.open("https://github.com/Gui-Yom/hlbc/wiki/Bytecode-file-format"),  # type: ignore
        "Open the HLBC wiki in your default browser",
    ),
    "opcodes": (
        lambda _, __: webbrowser.open("https://github.com/Gui-Yom/hlbc/blob/master/crates/hlbc/src/opcodes.rs"),  # type: ignore
        "Open the HLBC source to opcodes.rs in your default browser",
    ),
    "funcs": (
        cmd_funcs,
        "List all functions in the bytecode - pass 'std' to not exclude stdlib",
    ),
    "entry": (cmd_entry, "Show the entrypoint of the bytecode"),
    "fn": (cmd_fn, "Show information about a function"),
    # "decomp": (cmd_decomp, "Decompile a function"),
    "cfg": (cmd_cfg, "Graph the control flow graph of a function"),
    "patch": (cmd_patch, "Patch a function's raw opcodes"),
    "save": (cmd_save, "Save the modified bytecode to a given path"),
    "ir": (cmd_ir, "Display the IR of a function in object-notation"),
}
"""
List of CLI commands.
"""


def handle_cmd(code: Bytecode, is_hlbc: bool, cmd: str) -> None:
    """
    Handles a command.
    """
    cmd_list: List[str] = cmd.split(" ")
    if not is_hlbc:
        for command in COMMANDS:
            if cmd_list[0] == command:
                COMMANDS[command][0](cmd_list[1:], code)
                return
    else:
        raise NotImplementedError("HLBC compatibility mode is not yet implemented.")
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
    else:
        with open(args.file, "rb") as f:
            code = Bytecode().deserialise(f)

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
