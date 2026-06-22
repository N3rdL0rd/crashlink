"""
Main entry point.
"""

import argparse

from crashlink.globals import VERSION

from .build import build
from .run import run, run_single_case


def main() -> None:
    parser = argparse.ArgumentParser(description="crashtest - crashlink's decompiler test runner")
    parser.add_argument("--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True, help="Command to run")

    run_parser = subparsers.add_parser("run", help="Run one or all test cases")
    run_parser.add_argument("name", nargs="?", help="Test case name (file name or display name); omit to run all")
    run_parser.add_argument("--show-orig", "-o", action="store_true", help="Print the original Haxe source")
    run_parser.add_argument(
        "--show-decompiled", "-d", action="store_true", default=True, help="Print decompiled output"
    )
    run_parser.add_argument(
        "--no-decompiled", action="store_false", dest="show_decompiled", help="Hide decompiled output"
    )
    run_parser.add_argument("--show-ir", "-i", action="store_true", help="Print the lifted IR")
    run_parser.add_argument(
        "--no-recompile", "-n", action="store_true", help="Skip recompilation and opcode comparison"
    )
    run_parser.add_argument("--no-diff", action="store_true", help="Skip opcode diff output")
    run_parser.add_argument("--verbose", "-v", action="store_true", help="Show all available details")

    subparsers.add_parser("build", help="Build the result site")
    auto_parser = subparsers.add_parser("auto", help="Run all tests and build the site")

    args = parser.parse_args()
    if args.command == "run":
        if args.name:
            run_single_case(args)
        else:
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
