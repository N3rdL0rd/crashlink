"""hxsmith: a Csmith-style random Haxe program generator for fuzzing crashlink's decompiler.

    generate(seed)  ->  a deterministic, terminating Haxe program that prints its state
    pipeline        ->  compile, decompile the bytecode back to a project, recompile, run both
    quality         ->  where on the `Quality` ladder the decompilation landed
    runner          ->  many seeds in parallel, with a ladder histogram and failure clusters

Language coverage is split into plug-in `Feature`s under `features/`.
"""

from .feature import REGISTRY, Choice, Feature, register, resolve
from .gen import Config, Gen, GenError
from .program import Program, generate
from .quality import Observation, Quality, Verdict, classify

__all__ = [
    "REGISTRY",
    "Choice",
    "Config",
    "Feature",
    "Gen",
    "GenError",
    "Observation",
    "Program",
    "Quality",
    "Verdict",
    "classify",
    "generate",
    "register",
    "resolve",
]
