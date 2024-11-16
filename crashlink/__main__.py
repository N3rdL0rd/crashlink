import argparse
from .globals import VERSION
import os
from .core import Bytecode

def handle_cmd(code, is_hlbc, cmd):
    print(is_hlbc, cmd)
    # TODO

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
        cmd = input("crashlink> ")
        if cmd == "exit":
            break
        handle_cmd(code, args.hlbc, cmd)
        
if __name__ == "__main__":
    main()