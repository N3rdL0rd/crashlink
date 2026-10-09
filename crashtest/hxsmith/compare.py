"""Opcode-level comparison of the user functions of two images of the same program."""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Collection, Dict, List, Optional, Tuple

from crashlink import project
from crashlink.core import Bytecode, Function

ANON = "<anon>#"


def _ops(func: Function) -> List[str]:
    return [str(op.op) for op in func.ops if op.op is not None]


def _is_anonymous(name: str) -> bool:
    """A closure body: the compiler leaves it unnamed, and the decompiler names it `__anon_N`."""
    last = name.rpartition(".")[2]
    return name == "<none>" or last.startswith("__anon_") or last == "<none>"


def user_functions(code: Bytecode, modules: Collection[str]) -> Dict[str, Function]:
    """The functions whose code is mostly in one of `<module>.hx`, by full name. Std code, which
    the generated program pulls in and inlines, would only add noise. Anonymous functions share
    no usable name between the two images, so they get `<anon>#k` in findex order."""
    found: Dict[str, Function] = {}
    anonymous = 0
    for func in code.functions:
        located = project._function_file(code, func)
        if located is None or project._stem(located[0]) not in modules:
            continue
        name = code.full_func_name(func)
        if _is_anonymous(name):
            found[f"{ANON}{anonymous}"] = func
            anonymous += 1
        else:
            found[name] = func
    return found


def pair(
    before: Dict[str, Function], after: Dict[str, Function]
) -> Tuple[List[Tuple[str, Function, Optional[Function]]], List[str]]:
    """Match the two images' functions: by name, and the anonymous ones to their most similar
    counterpart (a closure's findex order differs between the images). Returns the original's
    functions with their match (None when the recompiled image has none) and the names of the
    recompiled functions nothing matched."""
    paired: List[Tuple[str, Function, Optional[Function]]] = []
    for name, func in before.items():
        if not name.startswith(ANON):
            paired.append((name, func, after.get(name)))
    spare = {name: func for name, func in after.items() if name.startswith(ANON)}
    originals = [(name, func) for name, func in before.items() if name.startswith(ANON)]
    # Most similar pairs first, so a closure is not stolen by a lookalike.
    scored = sorted(
        (
            (SequenceMatcher(None, _ops(func), _ops(other), autojunk=False).ratio(), name, other_name)
            for name, func in originals
            for other_name, other in spare.items()
        ),
        key=lambda item: -item[0],
    )
    taken_before: set = set()
    taken_after: set = set()
    matches: Dict[str, str] = {}
    for _, name, other_name in scored:
        if name in taken_before or other_name in taken_after:
            continue
        taken_before.add(name)
        taken_after.add(other_name)
        matches[name] = other_name
    for name, func in originals:
        other_name = matches.get(name)
        paired.append((name, func, spare[other_name] if other_name is not None else None))
    extra = sorted(name for name in after if not name.startswith(ANON) and name not in before)
    extra += sorted(name for name in spare if name not in taken_after)
    return paired, extra


def compare(
    original: Bytecode, recompiled: Bytecode, modules: Collection[str]
) -> Tuple[float, List[Tuple[str, float]]]:
    """Mean opcode-sequence similarity over the original's user functions (a function the
    recompiled image lacks counts as 0), and the ones that are not identical, worst first."""
    paired, extra = pair(user_functions(original, modules), user_functions(recompiled, modules))
    scores: List[Tuple[str, float]] = []
    for name, func, other in paired:
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
    differing = sorted([(n, s) for n, s in scores if s < 1.0] + [(n, 0.0) for n in extra], key=lambda t: t[1])
    if extra:
        mean = min(mean, 0.999)
    return mean, differing
