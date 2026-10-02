from pathlib import Path

from crashlink import disasm
from crashlink.core import Bytecode, Function, fIndex

CLAZZ = str(Path(__file__).parent / "haxe" / "Clazz.hl")


def _brute_force_callers(code: Bytecode, findex: int) -> list[int]:
    return [f.findex.value for f in code.functions if any(c.value == findex for c in f.calls)]


def test_called_by_lists_each_caller_once_in_function_order():
    code = Bytecode.from_path(CLAZZ)
    targets = [*code.functions, *code.natives]
    assert any(_brute_force_callers(code, t.findex.value) for t in targets)
    for target in targets:
        assert [c.value for c in target.called_by(code)] == _brute_force_callers(code, target.findex.value)


def test_called_by_follows_edits_after_cache_invalidation():
    code = Bytecode.from_path(CLAZZ)
    callee, caller = code.functions[0], code.functions[1]
    before = [c.value for c in callee.called_by(code)]
    assert caller.findex.value not in before

    # Same call twice must still list the caller once.
    caller.calls = [*caller.calls, fIndex(callee.findex.value), fIndex(callee.findex.value)]
    code.invalidate_findex_cache()

    after = [c.value for c in callee.called_by(code)]
    assert after.count(caller.findex.value) == 1
    assert sorted(after) == sorted([*before, caller.findex.value])


def test_called_by_result_can_be_mutated_without_corrupting_the_cache():
    code = Bytecode.from_path(CLAZZ)
    target = next(f for f in code.functions if isinstance(f, Function) and f.called_by(code))
    target.called_by(code).clear()
    assert target.called_by(code)


def test_disasm_xrefs_section_matches_callers():
    code = Bytecode.from_path(CLAZZ)
    target = next(f for f in code.functions if f.called_by(code))
    text = disasm.func(code, target)
    xrefs = text.split("\nXrefs:\n", 1)[1].strip().splitlines()
    assert len(xrefs) == len(target.called_by(code))
