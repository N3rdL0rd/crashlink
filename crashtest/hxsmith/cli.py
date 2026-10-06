"""`crashtest hxsmith ...`: generate, fuzz, and inspect coverage."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .coverage import DEFAULT_HAXE, measure
from .feature import REGISTRY, resolve
from .gen import Config
from .program import generate
from .quality import Quality
from .runner import fuzz, lint


def add_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("hxsmith", help="Fuzz the decompiler with random Haxe programs")
    sub = parser.add_subparsers(dest="hxsmith_command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--features", "-f", help="comma-separated features to enable (default: all)")
        p.add_argument("--exclude", "-x", default="", help="comma-separated features to disable")
        p.add_argument("--expr-depth", type=int, default=Config.max_expr_depth)
        p.add_argument("--stmt-depth", type=int, default=Config.max_stmt_depth)
        p.add_argument(
            "--swarm",
            type=float,
            default=0.0,
            metavar="P",
            help="enable each feature per seed with probability P (swarm testing); default: all features",
        )

    gen = sub.add_parser("gen", help="Print the program for a seed")
    gen.add_argument("seed", type=int)
    common(gen)

    run = sub.add_parser("run", help="Fuzz many seeds and report decompilation quality")
    run.add_argument("count", type=int, nargs="?", default=50, help="number of programs")
    run.add_argument("--start", type=int, default=0, help="first seed")
    run.add_argument("--jobs", "-j", type=int, default=0, help="parallel workers (default: half the CPUs)")
    run.add_argument("--out", type=Path, help="artifact directory (default: crashtest/hxsmith-runs/<time>)")
    run.add_argument(
        "--keep",
        choices=[q.name.lower() for q in Quality],
        default="behaves",
        help="keep artifacts of programs below this rung (default: behaves)",
    )
    common(run)

    lint_p = sub.add_parser("lint", help="Check generated programs compile, run and repeat (no decompiling)")
    lint_p.add_argument("count", type=int, nargs="?", default=100)
    lint_p.add_argument("--start", type=int, default=0)
    lint_p.add_argument("--jobs", "-j", type=int, default=0)
    common(lint_p)

    one = sub.add_parser("check", help="Evaluate one seed and print its verdict")
    one.add_argument("seed", type=int)
    common(one)

    show = sub.add_parser("report", help="Re-render a saved report.json")
    show.add_argument("path", type=Path, help="report.json, or the run folder containing it")
    show.add_argument("--top", type=int, default=25)

    sub.add_parser("features", help="List the features")
    cov = sub.add_parser("coverage", help="Which Haxe AST constructors the features generate")
    cov.add_argument("--haxe", type=Path, default=DEFAULT_HAXE, help="Haxe checkout (default: ~/code/haxe)")


def _names(text: str | None) -> list:
    return [n for n in (text or "").replace(" ", "").split(",") if n]


def _config(args: argparse.Namespace) -> Config:
    return Config(max_expr_depth=args.expr_depth, max_stmt_depth=args.stmt_depth)


def main(args: argparse.Namespace) -> int:
    command = args.hxsmith_command
    if command == "features":
        resolve()
        for feature in sorted(REGISTRY.values(), key=lambda f: (f.order, f.name)):
            print(f"{feature.name:<14} {feature.summary}")
        return 0
    if command == "report":
        import json

        from .runner import Report

        path = args.path / "report.json" if args.path.is_dir() else args.path
        print(Report.from_json(json.loads(path.read_text(encoding="utf-8"))).render(args.top))
        return 0
    if command == "coverage":
        report = measure(args.haxe)
        print(report.render())
        return 0
    only, exclude, config = _names(args.features) or None, _names(args.exclude), _config(args)
    if command == "gen":
        sys.stdout.write(generate(args.seed, only, exclude, config, args.swarm).source)
        return 0
    if command == "lint":
        problems = lint(
            range(args.start, args.start + args.count), only, exclude, args.jobs, config, args.swarm
        )
        for seed, why in problems:
            print(f"seed {seed}: {why}")
        print(f"{len(problems)}/{args.count} programs are not valid tests")
        return 1 if problems else 0
    if command == "check":
        report, out = fuzz(
            [args.seed], only, exclude, 1, config=config, keep_above=Quality.IDENTICAL, swarm=args.swarm
        )
        result = report.results[0]
        print(f"{result.class_name}: {result.verdict.quality.name if result.verdict else 'INVALID'}")
        detail = result.verdict.detail if result.verdict else result.invalid
        if detail:
            print(detail)
        print(f"artifacts: {out / f'seed{args.seed}'}")
        return 0 if result.verdict and result.verdict.quality >= Quality.BEHAVES else 1

    def progress(done: int, total: int, result: Any) -> None:
        mark = result.verdict.quality.name if result.verdict else "INVALID"
        print(f"\r[{done}/{total}] {result.name:<10} {mark:<10}", end="", file=sys.stderr, flush=True)

    report, out = fuzz(
        range(args.start, args.start + args.count),
        only,
        exclude,
        args.jobs,
        args.out,
        config,
        Quality[args.keep.upper()],
        args.swarm,
        progress,
    )
    print(file=sys.stderr)
    print(report.render())
    print(f"\nartifacts and report.json: {out}")
    return 0
