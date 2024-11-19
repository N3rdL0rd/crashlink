import argparse
from .globals import VERSION
import os
from .core import Bytecode
from . import fmt
from typing import List, Dict, Tuple, Callable
import sys
import webbrowser

def cmd_help(args, code):
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

def cmd_funcs(args, code: Bytecode):
    for func in code.functions:
        print(fmt.disasm.func_header(code, func))

COMMANDS: Dict[str, Tuple[Callable, str]] = {
    "exit": (lambda _, __: sys.exit(), "Exit the program"),
    "help": (cmd_help, "Show this help message"),
    "wiki": (lambda _, __: webbrowser.open("https://github.com/Gui-Yom/hlbc/wiki/Bytecode-file-format"), "Open the HLBC wiki in your default browser"),
    "funcs": (cmd_funcs, "List all functions in the bytecode")
}

def handle_cmd(code: Bytecode, is_hlbc: bool, cmd: str):
    cmd: List[str] = cmd.split(" ")
    if not is_hlbc:
        for command in COMMANDS:
            if cmd[0] == command:
                COMMANDS[command][0](cmd[1:], code)
                return
    else:
        raise NotImplementedError("HLBC compatibility mode is not yet implemented.")
    print("Unknown command.")

def main():
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
        
    while True:
        handle_cmd(code, args.hlbc, input("crashlink> "))
        
if __name__ == "__main__":
    main()