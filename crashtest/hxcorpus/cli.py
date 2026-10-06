"""`crashtest hxcorpus ...`"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ..hxsmith.quality import Quality
from ..hxsmith.runner import lint_jobs, run_jobs
from .cases import DEFAULT_HAXE, discover, job_for


def add_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("hxcorpus", help="Run the decompiler over the Haxe compiler's unit tests")
    sub = parser.add_subparsers(dest="hxcorpus_command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--haxe", type=Path, default=DEFAULT_HAXE, help="Haxe checkout (default: ~/code/haxe)")
        p.add_argument("--filter", "-k", help="only test classes whose name contains this")
        p.add_argument("--limit", type=int, help="only the first N")
        p.add_argument("--jobs", "-j", type=int, default=0)

    common(sub.add_parser("list", help="List the test classes"))
    common(sub.add_parser("lint", help="Which classes build and run standalone (no decompiling)"))
    run = sub.add_parser("run", help="Decompile, recompile and compare every class")
    common(run)
    run.add_argument("--out", type=Path)
    run.add_argument("--keep", choices=[q.name.lower() for q in Quality], default="behaves")


def main(args: argparse.Namespace) -> int:
    cases = discover(args.haxe, args.filter)[: args.limit]
    if args.hxcorpus_command == "list":
        for case in cases:
            print(case.fqn)
        print(f"{len(cases)} classes")
        return 0
    jobs = [job_for(c) for c in cases]
    if args.hxcorpus_command == "lint":
        problems = lint_jobs(jobs, args.jobs)
        for name, why in problems:
            print(f"{name}: {why}")
        print(f"{len(jobs) - len(problems)}/{len(jobs)} classes build and run standalone")
        return 0

    def progress(done: int, total: int, result: Any) -> None:
        mark = result.verdict.quality.name if result.verdict else "INVALID"
        print(f"\r[{done}/{total}] {result.name:<24} {mark:<10}", end="", file=sys.stderr, flush=True)

    report, out = run_jobs(jobs, args.jobs, args.out, Quality[args.keep.upper()], progress)
    print(file=sys.stderr)
    print(report.render(top=25))
    print(f"\nartifacts and report.json: {out}")
    return 0
