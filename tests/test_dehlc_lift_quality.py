"""
Regression gate for de-HL/C opcode lifting.

Scores the lifter per-instruction against the ground-truth oracle
(`local/dehlc-tests/oracle.py`, which recovers the instruction -> HL opcode
mapping from haxe's generated C plus DWARF) and fails if accuracy drops below
the level already reached. The floors sit a little under the measured numbers so
normal noise does not fail the build, but a real regression does.

Skipped unless the local corpus is present - it is a large build tree that does
not ship with the repo.
"""

import os
import sys

import pytest

CORPUS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "local", "dehlc-tests")

pytestmark = pytest.mark.skipif(
    not os.path.exists(os.path.join(CORPUS, "Arithmetic.elf")),
    reason="de-HL/C corpus not built (see local/dehlc-tests/build_all.sh)",
)


@pytest.fixture(scope="module")
def harness():
    sys.path.insert(0, CORPUS)
    # Both live in the gitignored local corpus tree, added to sys.path above.
    import lift_confusion  # ty: ignore[unresolved-import]
    import oracle  # ty: ignore[unresolved-import]

    return oracle, lift_confusion


def test_oracle_alignment_is_exact(harness):
    """Arithmetic_main is straight-line, so every opcode must align 1:1."""
    oracle, _ = harness
    _base, body = oracle._bodies_by_function()["Arithmetic_main"]
    mapped = oracle.op_index_by_line(body, 20)
    assert set(mapped.values()) == set(range(20))


def _accuracy(lift_confusion, elf_sub=""):
    confusion, totals, _extras = lift_confusion.score("Arithmetic", elf_sub)
    order = [t for t in totals if t != lift_confusion.PHANTOM]
    seen = sum(totals[t] for t in order)
    return sum(confusion[(t, t)] for t in order), seen, confusion, totals


def test_lift_accuracy_floor(harness):
    """Per-instruction accuracy on a representative optimised sample."""
    _, lift_confusion = harness
    hit, seen, _c, _t = _accuracy(lift_confusion)
    assert seen > 2000, f"oracle produced too few labels ({seen})"
    assert hit / seen >= 0.78, f"lift accuracy regressed to {100 * hit / seen:.1f}%"


@pytest.mark.parametrize("tier,floor", [("elf-O2", 0.74), ("elf-O3", 0.71)])
def test_optimised_accuracy_floor(harness, tier, floor):
    """
    -O2/-O3 are the production shapes: shipped games are built this way, and
    they are where inlining and branch rewriting bite hardest.
    """
    if not os.path.exists(os.path.join(CORPUS, tier, "Arithmetic.elf")):
        pytest.skip(f"{tier} not built (./build_all.sh {tier[4:]})")
    _, lift_confusion = harness
    hit, seen, _c, _t = _accuracy(lift_confusion, tier)
    assert hit / seen >= floor, f"{tier} accuracy regressed to {100 * hit / seen:.1f}%"


@pytest.mark.skipif(
    not os.path.exists(os.path.join(CORPUS, "elf-O0", "Arithmetic.elf")),
    reason="-O0 tier not built (./build_all.sh O0)",
)
def test_unoptimised_accuracy_floor(harness):
    """
    -O0 isolates rule gaps from optimiser damage: with nothing destroyed, a
    shortfall here is squarely the lifter's own.
    """
    _, lift_confusion = harness
    hit, seen, _c, _t = _accuracy(lift_confusion, "elf-O0")
    assert hit / seen >= 0.85, f"unoptimised lift accuracy regressed to {100 * hit / seen:.1f}%"


@pytest.mark.parametrize(
    "opcode,floor",
    [
        ("NullCheck", 0.95),  # guard idiom: zero-test + branch into hl_null_access
        ("GetThis", 0.85),  # field access off argument 0
        ("GetGlobal", 0.95),
        ("New", 0.95),
        ("Ret", 0.75),
        ("Call2", 0.80),  # arity from the callee's signature, by findex
        ("CallMethod", 0.90),  # indirect dispatch through the proto table
        ("JNotNull", 0.90),  # pointer-width compare against zero
        ("JNotEq", 0.85),
        ("SafeCast", 0.65),  # hl_dyn_cast* family
        ("SetArray", 0.60),  # indexed addressing => array/buffer, not a field
        ("Mul", 0.90),  # lea [r + r*k] is r*(k+1), not an add
        ("InstanceClosure", 0.90),  # hl_alloc_closure_ptr
        ("SetI16", 0.85),  # 16-bit access, whatever the addressing form
        ("Incr", 0.85),  # store of "that same location + 1"
    ],
)
def test_per_opcode_floor(harness, opcode, floor):
    """Individual recoveries that cost real work - keep them from silently rotting."""
    _, lift_confusion = harness
    _hit, _seen, confusion, totals = _accuracy(lift_confusion)
    n = totals[opcode]
    assert n > 0, f"no {opcode} instances labelled"
    got = confusion[(opcode, opcode)] / n
    assert got >= floor, f"{opcode} recovery regressed to {100 * got:.0f}% (floor {100 * floor:.0f}%)"


@pytest.mark.parametrize("opcode", ["Int", "Null", "Bool", "Incr", "Mov"])
def test_constant_materialisation_unoptimised(harness, opcode):
    """
    Constants written straight into a vreg's stack slot. Unoptimised builds
    spell every Int/Null/Bool that way, and they used to be swallowed whole as
    spill noise.
    """
    if not os.path.exists(os.path.join(CORPUS, "elf-O0", "Arithmetic.elf")):
        pytest.skip("-O0 tier not built")
    _, lift_confusion = harness
    _hit, _seen, confusion, totals = _accuracy(lift_confusion, "elf-O0")
    n = totals[opcode]
    assert n > 0, f"no {opcode} instances labelled"
    assert confusion[(opcode, opcode)] / n >= 0.85
