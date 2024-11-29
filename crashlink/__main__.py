import argparse
import os
import subprocess
import sys
import tempfile
import webbrowser
from typing import Dict, List, Tuple
from collections.abc import Callable

from . import decomp, disasm
from .core import Bytecode
from .globals import VERSION


def cmd_help(args: List[str], code: Bytecode) -> None:
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
    entry = code.entrypoint.resolve(code)
    print("    Entrypoint:", disasm.func_header(code, entry))


def cmd_fn(args: List[str], code: Bytecode) -> None:
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


# def cmd_decomp(args, code: Bytecode):
#     if not args:
#         print("Usage: decomp <index>")
#         return
#     try:
#         index = int(args[0])
#     except ValueError:
#         print("Invalid index.")
#         return
#     for func in code.functions:
#         if func.findex.value == index:
#             decomp = decomp.Decompiler(code)
#             decomp.func(func)
#             for i, layer in enumerate(decomp.ir_layers):
#                 print(f"--- IR Layer {i} ---")
#                 print(layer)
#             return


def cmd_cfg(args: List[str], code: Bytecode) -> None:
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
                os.startfile(png_file)
                os.unlink(dot_file)
            except:
                print(f"Control flow graph saved to {png_file}. Use your favourite image viewer to open it.")
            return

# typing is ignored for lambdas because webbrowser.open returns a bool instead of None
COMMANDS: Dict[str, Tuple[Callable[[List[str], Bytecode], None], str]] = {
    "exit": (lambda _, __: sys.exit(), "Exit the program"),
    "help": (cmd_help, "Show this help message"),
    "wiki": (
        lambda _, __: webbrowser.open("https://github.com/Gui-Yom/hlbc/wiki/Bytecode-file-format"), # type: ignore
        "Open the HLBC wiki in your default browser",
    ),
    "opcodes": (
        lambda _, __: webbrowser.open("https://github.com/Gui-Yom/hlbc/blob/master/crates/hlbc/src/opcodes.rs"), # type: ignore
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
}


def handle_cmd(code: Bytecode, is_hlbc: bool, cmd: str) -> None:
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
            handle_cmd(code, args.hlbc, input("crashlink> "))


if __name__ == "__main__":
    main()
