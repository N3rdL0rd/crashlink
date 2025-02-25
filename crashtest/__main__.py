"""
Main entry point.
"""

import argparse

from .build import build
from .run import run
from crashlink.globals import VERSION

def main() -> None:
    parser = argparse.ArgumentParser(
        description="crashtest - crashlink's decompiler test runner")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("command", choices=["run", "build", "auto"], help="Command to run")
    args = parser.parse_args()
    if args.command == "run":
        run()
    elif args.command == "build":
        build()
    elif args.command == "auto":
        print("Running tests...")
        run()
        print("Building site...")
        build()

if __name__ == "__main__":
    main()
