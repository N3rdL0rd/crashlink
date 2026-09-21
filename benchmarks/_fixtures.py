"""Shared fixture-path and class-iteration helpers for the benchmark suite.

Not itself a benchmark module - asv only collects `time_*`/`mem_*`/
`track_*`/`peakmem_*` methods on classes here, so this file is ignored by
benchmark discovery. Note that asv's discovery walks every non-underscore
name in each module's namespace, including imported ones, looking for
classes with methods matching those prefixes - so `crashlink` types are
imported as modules (`core.Bytecode`, not `from crashlink.core import
Bytecode`) everywhere in this suite. `Bytecode.track_section` would
otherwise be misidentified as a `track_` benchmark.
"""

import os
from typing import List

from crashlink import core

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HAXE_DIR = os.path.join(_ROOT, "tests", "haxe")

# Fixture tiers used across the suite, from a handful of opcodes to the
# largest real Haxe source committed under tests/haxe. Kept small on purpose:
# these run on every push, in full (non-`--quick`) mode, in CI.
SMALL = "BigControlFlow"
MEDIUM = "BigCombo"
LARGE = "HeapsSkinSplit"
FIXTURES = [SMALL, MEDIUM, LARGE]


def fixture(name: str) -> str:
    """Absolute path to a prebuilt tests/haxe/<name>.hl image."""
    path = os.path.join(_HAXE_DIR, f"{name}.hl")
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"benchmark fixture {path!r} is missing - build it first with "
            f"`haxe -hl {name}.hl -main {name}` (run from tests/haxe)"
        )
    return path


def load(name: str) -> "core.Bytecode":
    return core.Bytecode.from_path(fixture(name))


def classes_of(code: "core.Bytecode") -> List["core.Obj"]:
    """Every class worth decompiling once: all dynamic Objs, plus any
    static-only Obj that has no dynamic counterpart. Mirrors
    `disasm.gen_docs`'s dedup so a static/dynamic pair isn't rendered twice.
    """
    out = []
    for t in code.types:
        obj = t.definition
        if not isinstance(obj, core.Obj):
            continue
        if obj.is_static:
            try:
                has_dynamic = obj.dynamic is not None
            except (ValueError, AttributeError):
                has_dynamic = False
            if has_dynamic:
                continue
        out.append(obj)
    return out
