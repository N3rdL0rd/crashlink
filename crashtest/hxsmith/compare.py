"""Opcode-level comparison of the user functions of two images of the same program."""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Collection, List, Tuple

from crashlink import project
from crashlink.core import Bytecode, Function


def _ops(func: Function) -> List[str]:
    return [str(op.op) for op in func.ops if op.op is not None]


def user_functions(code: Bytecode, modules: Collection[str]) -> dict:
    """The functions whose code is mostly in one of `<module>.hx`, by full name. Std code, which
    the generated program pulls in and inlines, would only add noise."""
    found = {}
    for func in code.functions:
        located = project._function_file(code, func)
        if located is not None and project._stem(located[0]) in modules:
            found[code.full_func_name(func)] = func
    return found


def compare(
    original: Bytecode, recompiled: Bytecode, modules: Collection[str]
) -> Tuple[float, List[Tuple[str, float]]]:
    """Mean opcode-sequence similarity over the original's user functions (a function the
    recompiled image lacks counts as 0), and the ones that are not identical, worst first."""
    before = user_functions(original, modules)
    after = user_functions(recompiled, modules)
    scores: List[Tuple[str, float]] = []
    for name, func in before.items():
        other = after.get(name)
        if other is None:
            scores.append((name, 0.0))
        elif _ops(func) == _ops(other):
            scores.append((name, 1.0))
        else:
            scores.append((name, SequenceMatcher(None, _ops(func), _ops(other), autojunk=False).ratio()))
    if not scores:
        return 1.0, []
    mean = sum(s for _, s in scores) / len(scores)
    # Extra functions in the recompiled image (a split closure, a lost inline) are a difference too.
    extra = sorted(set(after) - set(before))
    differing = sorted([(n, s) for n, s in scores if s < 1.0] + [(n, 0.0) for n in extra], key=lambda t: t[1])
    if extra:
        mean = min(mean, 0.999)
    return mean, differing
