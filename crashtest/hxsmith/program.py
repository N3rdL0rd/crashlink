"""Assemble a whole Haxe module from a seed."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

from .feature import resolve
from .gen import Config, Gen, GenError


@dataclass(frozen=True)
class Program:
    seed: int
    class_name: str
    source: str
    features: Tuple[str, ...]  # features that contributed to the output

    @property
    def filename(self) -> str:
        return f"{self.class_name}.hx"


def generate(
    seed: int,
    only: Optional[Iterable[str]] = None,
    exclude: Iterable[str] = (),
    config: Optional[Config] = None,
    swarm: float = 0.0,
) -> Program:
    """The program for `seed`. The same arguments always give the same source.

    With `swarm` > 0 each feature is enabled for this seed with that probability (always keeping
    `variables`, so there is output). Swarm testing keeps programs small and makes a failure
    attributable: a feature missing from every failing program is not the cause."""
    features = resolve(only, exclude)
    if swarm > 0:
        rng = random.Random(f"swarm{seed}")
        names = {f.name for f in features}
        chosen = {n for n in sorted(names) if rng.random() < swarm} | ({"variables"} & names)
        features = resolve(chosen, exclude)
    g = Gen(seed, features, config)
    g.ready = set()
    for feature in g.features:
        g.ready.add(feature.name)
        feature.declare(g)

    with g.capture(level=2) as main:
        with g.function([], None):
            lo, hi = g.cfg.main_statements
            g.statements(g.between(lo, hi))
            g.observe()

    parts = [*g.decls]
    cls = [f"class {g.class_name} {{", *g.members]
    cls += ["\tstatic function main() {", "\t\ttry {", *("\t" + line if line else line for line in main)]
    cls += [
        "\t\t} catch (e:Dynamic) {",
        '\t\t\tSys.println("uncaught: " + Std.string(e));',
        "\t\t}",
        "\t}",
        "}",
    ]
    parts.append("\n".join(cls))
    return Program(seed, g.class_name, "\n\n".join(parts) + "\n", tuple(sorted(g.used)))


__all__ = ["Program", "generate", "GenError"]
