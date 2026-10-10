"""Lift a function's opcodes into a canonical control-flow graph.

Everything that does not change what the function does is removed here, so that two functions
that differ only in layout get the same graph:

- blocks that only jump are threaded away and straight-line blocks are merged;
- a conditional jump is rewritten onto one of a pair of complementary predicates, and its two
  successors are ordered by that predicate (true edge first), so `if (a < b)` laid out as a
  jump-if-not-less looks the same as the jump-if-less form;
- blocks are numbered by a depth-first walk that follows successors in that order.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from ..core import Opcode
from ..opcodes import opcodes as OPCODE_SCHEMA
from .names import Namer, is_int_like

CONDITIONALS = {
    "JTrue", "JFalse", "JNull", "JNotNull", "JSLt", "JSGte", "JSGt", "JSLte", "JULt", "JUGte",
    "JNotLt", "JNotGte", "JEq", "JNotEq",
}  # fmt: skip
TERMINATORS = CONDITIONALS | {"JAlways", "Switch", "Ret", "Throw", "Rethrow", "Trap", "EndTrap"}
INERT = {"Label", "Nop", "Prefetch"}
"""Opcodes with no observable effect that are dropped from block bodies."""


class Unsupported(Exception):
    """The function uses something the canonicaliser cannot model soundly."""


@dataclass
class Term:
    """How a block ends. `succs` are block ids, ordered canonically."""

    kind: str
    """ret, throw, rethrow, jump, cond, switch, trap"""
    regs: Tuple[int, ...] = ()
    pred: str = ""
    negated: bool = False
    succs: Tuple[int, ...] = ()


@dataclass
class Block:
    start: int
    ops: List[Opcode] = field(default_factory=list)
    term: Term = field(default_factory=lambda: Term("ret"))
    ends_trap: bool = False


@dataclass
class TrapInfo:
    """The protected region of one `Trap`."""

    region: Set[int]
    """Blocks that run while the handler is installed."""
    needed: Set[int]
    """Registers the handler reads that the region writes: which value it sees depends on where
    the exception was raised."""


@dataclass
class Lifted:
    blocks: List[Block]
    """In canonical order; block 0 is the entry."""
    preds: List[List[int]]
    """Canonical ids of each block's distinct predecessors, ascending."""
    traps: Dict[int, TrapInfo] = field(default_factory=dict)
    """By the id of the block that ends in the `Trap`."""


def uses_defs(op: Opcode) -> Tuple[List[int], List[int]]:
    """Registers an opcode reads and writes."""
    name = op.op
    assert name is not None
    uses: List[int] = []
    defs: List[int] = []
    for field_name, kind in OPCODE_SCHEMA[name].items():
        value = op.df[field_name]
        if kind == "Reg":
            if field_name == "dst":
                if name in ("Incr", "Decr"):
                    uses.append(value.value)
                    defs.append(value.value)
                elif name == "Setref":
                    uses.append(value.value)  # `dst` is the reference written through
                else:
                    defs.append(value.value)
            else:
                uses.append(value.value)
        elif kind == "Regs":
            uses.extend(r.value for r in value.value)
    return uses, defs


def _normalise_cond(op: Opcode, namer: Namer, regs: List[int]) -> Tuple[str, Tuple[int, ...], bool]:
    """(predicate, operands, negated) with `negated` meaning the jump is taken when it is false."""
    name = op.op
    assert name is not None
    df = op.df
    if name in ("JTrue", "JFalse"):
        return "true", (df["cond"].value,), name == "JFalse"
    if name in ("JNull", "JNotNull"):
        return "null", (df["reg"].value,), name == "JNotNull"
    a, b = df["a"].value, df["b"].value
    if name in ("JEq", "JNotEq"):
        return "eq", (a, b), name == "JNotEq"
    ints = is_int_like(namer.kind_of(regs[a]))
    if ints:
        table = {
            "JSLt": ("slt", (a, b), False),
            "JSGte": ("slt", (a, b), True),
            "JSGt": ("slt", (b, a), False),
            "JSLte": ("slt", (b, a), True),
            "JULt": ("ult", (a, b), False),
            "JUGte": ("ult", (a, b), True),
            "JNotLt": ("slt", (a, b), True),
            "JNotGte": ("slt", (a, b), False),
        }
    else:
        # Without a total order the negation of `a < b` is not `a >= b` (NaN, uncomparable
        # dynamics), so only operand swaps are folded and negation stays explicit.
        table = {
            "JSLt": ("lt", (a, b), False),
            "JSGt": ("lt", (b, a), False),
            "JSGte": ("lte", (b, a), False),
            "JSLte": ("lte", (a, b), False),
            "JNotLt": ("lt", (a, b), True),
            "JNotGte": ("lte", (b, a), True),
            "JULt": ("ult", (a, b), False),
            "JUGte": ("ugte", (a, b), False),
        }
    return table[name]


def _int_value(value: int, kind: int) -> int:
    """An int constant as its register holds it (signed for I32/I64, masked for U8/U16)."""
    width = {3: 32, 4: 64}.get(kind)
    if width is not None:
        value &= (1 << width) - 1
        return value - (1 << width) if value >> (width - 1) else value
    if kind == 1:
        return value & 0xFF
    if kind == 2:
        return value & 0xFFFF
    return value


def _facts(
    ops: List[Opcode], code: object, address_taken: Set[int], kind_of: Callable[[int], int]
) -> Dict[int, object]:
    """What is known about registers at the end of a block: "null", "nonnull" or an int constant.

    Only facts that follow from the block's own opcodes are kept, so a condition on a value built
    in the same block (a constant, a string, a closure) can be decided here, before blocks are
    numbered, instead of leaving a branch that can only go one way."""
    facts: Dict[int, object] = {}
    nonnull = {
        "String",
        "Bytes",
        "StaticClosure",
        "InstanceClosure",
        "VirtualClosure",
        "New",
        "EnumAlloc",
        "MakeEnum",
        "Type",
    }
    for op in ops:
        name = op.op
        assert name is not None
        _uses, defs = uses_defs(op)
        for d in defs:
            facts.pop(d, None)
        dst = op.df["dst"].value if "dst" in op.df else None
        if dst is None or dst in address_taken:
            continue
        if name == "Null":
            facts[dst] = "null"
        elif name in nonnull:
            facts[dst] = "nonnull"
        elif name == "ToDyn" and kind_of(op.df["src"].value) in (1, 2, 3, 4, 5, 6, 7):
            facts[dst] = "nonnull"  # boxing a basic value makes a fresh, non-null dynamic
        elif name == "Bool":
            facts[dst] = int(op.df["value"].value)
        elif name == "Int":
            facts[dst] = _int_value(int(op.df["ptr"].resolve(code).value), kind_of(dst))  # type: ignore[attr-defined]
        elif name == "Mov" and op.df["src"].value in facts and op.df["src"].value not in address_taken:
            facts[dst] = facts[op.df["src"].value]
    return facts


def _decide(
    pred: str, operands: Tuple[int, ...], negated: bool, facts: Dict[int, object], bits: int = 0
) -> Optional[bool]:
    """Whether the jump is certainly taken (True) or certainly not (False), if the facts settle it."""
    known = [facts.get(r) for r in operands]
    base: Optional[bool] = None
    if pred == "null" and known[0] in ("null", "nonnull"):
        base = known[0] == "null"
    elif pred == "true" and isinstance(known[0], int):
        base = known[0] != 0
    elif pred == "eq" and isinstance(known[0], int) and isinstance(known[1], int):
        base = known[0] == known[1]
    elif pred == "eq" and {known[0], known[1]} == {"null", "nonnull"}:
        base = False
    elif pred in ("slt", "ult") and isinstance(known[0], int) and isinstance(known[1], int) and bits:
        mask = (1 << bits) - 1
        x, y = known[0], known[1]
        base = x < y if pred == "slt" else (x & mask) < (y & mask)
    if base is None:
        return None
    return base != negated


PURE_OPS = frozenset(
    {
        "Mov", "Int", "Float", "Bool", "Bytes", "String", "Null", "Neg", "Not", "Incr", "Decr",
        "Add", "Sub", "Mul", "SDiv", "UDiv", "SMod", "UMod", "Shl", "SShr", "UShr", "And", "Or", "Xor",
        "StaticClosure", "InstanceClosure", "GetGlobal", "Type", "GetType", "GetTID",
        "ToDyn", "ToSFloat", "ToUFloat", "ToInt", "ToVirtual", "UnsafeCast",
    }
)  # fmt: skip
"""Opcodes whose only effect is the register they write."""


def _drop_dead_values(
    raw: Dict[int, "Block"],
    successors: Dict[int, List[int]],
    address_taken: Set[int],
    cond_regs: Dict[int, Tuple[int, ...]],
) -> None:
    """Remove pure opcodes whose result nothing reads, so a block that only computed such values
    is empty and can be threaded away like any other."""
    use: Dict[int, Set[int]] = {}
    defs: Dict[int, Set[int]] = {}
    for start, block in raw.items():
        u: Set[int] = set()
        d: Set[int] = set()
        for op in block.ops:
            ou, od = uses_defs(op)
            u.update(r for r in ou if r not in d)
            d.update(od)
        u.update(r for r in block.term.regs + cond_regs.get(start, ()) if r not in d)
        use[start], defs[start] = u, d
    live_in: Dict[int, Set[int]] = {s: set() for s in raw}
    changed = True
    while changed:
        changed = False
        for start in raw:
            out: Set[int] = set()
            for s in successors[start]:
                out |= live_in.get(s, set())
            new = use[start] | (out - defs[start])
            if new != live_in[start]:
                live_in[start] = new
                changed = True
    for start, block in raw.items():
        live: Set[int] = set(block.term.regs) | set(cond_regs.get(start, ()))
        for s in successors[start]:
            live |= live_in.get(s, set())
        kept: List[Opcode] = []
        for op in reversed(block.ops):
            ou, od = uses_defs(op)
            if op.op in PURE_OPS and od and all(r not in live and r not in address_taken for r in od):
                continue
            live = (live - set(od)) | set(ou)
            kept.append(op)
        kept.reverse()
        block.ops = kept


def lift(func_ops: List[Opcode], regs: List[int], namer: Namer) -> Lifted:
    ops = func_ops
    count = len(ops)
    if not count:
        raise Unsupported("empty function")

    # -- split into raw blocks ----------------------------------------------------------------
    leaders: Set[int] = {0}
    for i, op in enumerate(ops):
        name = op.op
        assert name is not None
        if name in CONDITIONALS or name in ("JAlways", "Trap"):
            leaders.add(i + op.df["offset"].value + 1)
        if name == "Switch":
            for offset in op.df["offsets"].value:
                leaders.add(i + offset.value + 1)
        if name in TERMINATORS and i + 1 < count:
            leaders.add(i + 1)
    if any(t < 0 or t > count for t in leaders):
        raise Unsupported("jump outside the function")
    leaders.discard(count)
    starts = sorted(leaders)

    raw: Dict[int, Block] = {}
    pending_cond: Dict[int, Tuple[str, Tuple[int, ...], bool, int, int]] = {}
    decided: Dict[int, Optional[bool]] = {}
    address_taken = {op.df["src"].value for op in ops if op.op == "Ref"}
    for n, start in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else count
        block = Block(start)
        last: Optional[Opcode] = None
        last_index = end - 1
        for i in range(start, end):
            op = ops[i]
            assert op.op is not None
            if op.op in TERMINATORS:
                last = op
                last_index = i
                break
            if op.op in INERT:
                continue
            if op.op in ("Asm", "Catch", "RefData", "RefOffset"):
                raise Unsupported(f"opcode {op.op}")
            block.ops.append(op)
        nxt = end
        if last is None:
            block.term = Term("jump", succs=(nxt,)) if nxt < count else Term("ret")
            if nxt >= count:
                raise Unsupported("falls off the end")
        else:
            name = last.op
            assert name is not None
            target = last_index + 1 + last.df["offset"].value if "offset" in last.df else -1
            fall = last_index + 1
            if name in CONDITIONALS:
                pred, operands, negated = _normalise_cond(last, namer, regs)
                facts = _facts(block.ops, namer.code, address_taken, lambda reg: namer.kind_of(regs[reg]))
                if pred == "eq" and "null" in (facts.get(operands[0]), facts.get(operands[1])):
                    # `x == null` is a test for null, however it was written.
                    other = operands[1] if facts.get(operands[0]) == "null" else operands[0]
                    pred, operands = "null", (other,)
                pending_cond[start] = (pred, operands, negated, target, fall)
                decided[start] = _decide(
                    pred, operands, negated, facts, {3: 32, 4: 64}.get(namer.kind_of(regs[operands[0]]), 0)
                )
                block.term = Term("cond")
            elif name == "JAlways":
                block.term = Term("jump", succs=(target,))
            elif name == "Ret":
                block.term = Term("ret", regs=(last.df["ret"].value,))
            elif name in ("Throw", "Rethrow"):
                block.term = Term(name.lower(), regs=(last.df["exc"].value,))
            elif name == "EndTrap":
                block.ends_trap = True
                block.term = Term("jump", succs=(fall,))
            elif name == "Trap":
                block.term = Term("trap", regs=(last.df["exc"].value,), succs=(fall, target))
            elif name == "Switch":
                cases = [
                    last_index + 1 + o.value if o.value else last_index + 1 for o in last.df["offsets"].value
                ]
                default = last_index + 1  # no case matched: execution continues after the switch
                block.term = Term("switch", regs=(last.df["reg"].value,), succs=tuple(cases) + (default,))
        raw[start] = block

    raw_succs: Dict[int, List[int]] = {}
    for start, block in raw.items():
        if block.term.kind == "cond":
            _p, _o, _n, target, fall = pending_cond[start]
            raw_succs[start] = [target, fall]
        else:
            raw_succs[start] = list(block.term.succs)
    if not any(
        op.op == "Trap" for op in ops
    ):  # a handler reads registers the body wrote, which liveness over normal edges misses
        _drop_dead_values(raw, raw_succs, address_taken, {s: c[1] for s, c in pending_cond.items()})

    # -- thread empty jump-only blocks ----------------------------------------------------------
    def is_empty(b: Block) -> bool:
        return not b.ops and b.term.kind == "jump" and not b.ends_trap

    def resolve(target: int) -> int:
        seen: Set[int] = set()
        while target in raw and is_empty(raw[target]) and target not in seen:
            seen.add(target)
            target = raw[target].term.succs[0]
        return target

    def successors(start: int) -> Tuple[int, ...]:
        block = raw[start]
        if block.term.kind == "cond":
            _pred, _operands, negated, target, fall = pending_cond[start]
            t, f = resolve(target), resolve(fall)
            if decided.get(start) is not None:
                return ((t if decided[start] else f),) * 2
            return (f, t) if negated else (t, f)
        return tuple(resolve(s) for s in block.term.succs)

    # Rebuild terms with resolved, canonically ordered successors.
    for start, block in raw.items():
        succs = successors(start)
        if block.term.kind == "cond":
            pred, operands, _negated, _target, _fall = pending_cond[start]
            if succs[0] == succs[1]:
                block.term = Term("jump", succs=(succs[0],))
            else:
                block.term = Term("cond", regs=operands, pred=pred, negated=False, succs=succs)
        else:
            block.term.succs = succs

    entry = resolve(0)
    if entry not in raw:
        raise Unsupported("bad entry")

    # -- reachable set and predecessor counts ---------------------------------------------------
    def reach() -> Tuple[List[int], Dict[int, int]]:
        order: List[int] = []
        seen: Set[int] = set()
        stack = [entry]
        preds: Dict[int, int] = {entry: 1}  # the function entry counts as a predecessor
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            order.append(cur)
            for s in dict.fromkeys(raw[cur].term.succs):
                preds[s] = preds.get(s, 0) + 1
                stack.append(s)
        return order, preds

    def merge_blocks() -> None:
        """Merge straight-line chains, then blocks that are copies of each other."""
        changed = True
        while changed:
            changed = False
            order, preds = reach()
            for a in order:
                block = raw[a]
                if block.term.kind != "jump" or block.ends_trap:
                    continue
                b = block.term.succs[0]
                if b == a or b == entry or preds.get(b, 0) != 1 or b not in raw:
                    continue
                nxt = raw[b]
                block.ops.extend(nxt.ops)
                block.term = nxt.term
                block.ends_trap = nxt.ends_trap
                del raw[b]
                changed = True
                break
        changed = True
        while changed:
            changed = False
            seen_blocks: Dict[Tuple[object, ...], int] = {}
            for start in reach()[0]:
                if start == entry:
                    seen_blocks[("entry",)] = start
                    continue
                block = raw[start]
                term = block.term
                key = (
                    tuple(bytes(op.serialise()) for op in block.ops),
                    term.kind,
                    term.regs,
                    term.pred,
                    term.negated,
                    term.succs,
                    block.ends_trap,
                )
                twin = seen_blocks.get(key)
                if twin is None:
                    seen_blocks[key] = start
                    continue
                for other in raw.values():
                    other.term.succs = tuple(twin if s == start else s for s in other.term.succs)
                del raw[start]
                changed = True
                break

    merge_blocks()
    # A condition on a value built in the blocks just merged in can now be decided.
    again = True
    while again:
        again = False
        for start in reach()[0]:
            block = raw[start]
            term = block.term
            if term.kind != "cond":
                continue
            facts = _facts(block.ops, namer.code, address_taken, lambda reg: namer.kind_of(regs[reg]))
            bits = {3: 32, 4: 64}.get(namer.kind_of(regs[term.regs[0]]), 0)
            taken = _decide(term.pred, term.regs, False, facts, bits)
            if taken is not None:
                block.term = Term("jump", succs=(term.succs[0] if taken else term.succs[1],))
                again = True
        if again:
            merge_blocks()

    # -- canonical numbering ---------------------------------------------------------------------
    order: List[int] = []
    seen_ids: Set[int] = set()
    stack = [entry]
    while stack:
        cur = stack.pop()
        if cur in seen_ids:
            continue
        seen_ids.add(cur)
        order.append(cur)
        for s in reversed(raw[cur].term.succs):
            stack.append(s)
    index = {start: i for i, start in enumerate(order)}
    blocks: List[Block] = []
    for start in order:
        b = raw[start]
        b.term = Term(
            b.term.kind, b.term.regs, b.term.pred, b.term.negated, tuple(index[s] for s in b.term.succs)
        )
        blocks.append(b)
    preds_list: List[Set[int]] = [set() for _ in blocks]
    for i, b in enumerate(blocks):
        for s in b.term.succs:
            preds_list[s].add(i)
    lifted = Lifted(blocks, [sorted(p) for p in preds_list])
    lifted.traps = trap_regions(lifted)
    return lifted


def liveness(lifted: Lifted) -> Tuple[List[Set[int]], List[Set[int]], List[Set[int]]]:
    """Registers live on entry to and on exit from each block, and those each block writes."""
    blocks = lifted.blocks
    n = len(blocks)
    use: List[Set[int]] = [set() for _ in range(n)]
    defs: List[Set[int]] = [set() for _ in range(n)]
    for i, block in enumerate(blocks):
        for op in block.ops:
            u, d = uses_defs(op)
            use[i].update(r for r in u if r not in defs[i])
            defs[i].update(d)
        use[i].update(r for r in block.term.regs if r not in defs[i])
    live_in: List[Set[int]] = [set() for _ in range(n)]
    live_out: List[Set[int]] = [set() for _ in range(n)]
    changed = True
    while changed:
        changed = False
        for i in reversed(range(n)):
            out: Set[int] = set()
            for s in blocks[i].term.succs:
                out |= live_in[s]
            new = use[i] | (out - defs[i])
            live_out[i] = out
            if new != live_in[i]:
                live_in[i] = new
                changed = True
    return live_in, live_out, defs


def trap_regions(lifted: Lifted) -> Dict[int, TrapInfo]:
    """For each `Trap`: the blocks it protects and the registers its handler needs that they write."""
    blocks = lifted.blocks
    live_in, _live_out, defs = liveness(lifted)
    infos: Dict[int, TrapInfo] = {}
    for trap_id, block in enumerate(blocks):
        if block.term.kind != "trap":
            continue
        body, handler = block.term.succs
        region: Set[int] = set()
        written: Set[int] = set()
        seen: Set[Tuple[int, int]] = set()
        stack = [(body, 0)]
        while stack:
            cur, depth = stack.pop()
            if (cur, depth) in seen:
                continue
            seen.add((cur, depth))
            region.add(cur)
            written |= defs[cur]
            cb = blocks[cur]
            if cb.ends_trap:
                if depth == 0:
                    continue
                depth -= 1
            if cb.term.kind == "trap":
                stack.append((cb.term.succs[0], depth + 1))
                stack.append((cb.term.succs[1], depth))
            else:
                for s in cb.term.succs:
                    stack.append((s, depth))
        needed = (set(live_in[handler]) - {block.term.regs[0]}) & written
        infos[trap_id] = TrapInfo(region, needed)
    return infos
