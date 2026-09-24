"""
Find function bodies the Haxe compiler inlined, from per-opcode debug positions.

An inlined body keeps the callee's source positions: its opcodes point at the file
and lines of the `inline` function, not of the caller. So inside a function whose
own code sits in `en/Hero.hx`, opcodes positioned in `tool/Cooldown.hx` line 225 are
a copy of whatever Cooldown method is written on that line, even when that method no
longer exists as a function in the bytecode.

`InlineFinder` recovers those copies:

* every function's *home* file (where its own code is written), from its class name;
* *sites*: the copies in one function. A copy is the callee-positioned opcodes plus
  any caller-positioned ones in between that belong to it (arguments the compiler
  evaluated in place), and it may contain other bodies inlined into it (lines of the
  same site far apart from the rest);
* *inlined functions*: sites grouped across the image by overlapping lines in the
  same file, and *shapes*: sites of one function whose bodies compile to the same
  opcodes, with what they share. A shape gives the parameters (registers the body
  reads before writing), their types across call sites, the results (registers it
  writes that are read afterwards), and the constants that change per call site.

Generated code is reported apart: macro sources stamp their own positions on the code
they build, and the compiler's `?` file marks synthesised code. Neither is inlining.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .core import Bytecode, Function, Opcode, Reg, Regs, Void
from .decomp.cfg import CFGraph, CFNode
from .opcodes import opcodes

#: Lines further apart than this within one site belong to different bodies (one
#: inlined into the other).
BODY_LINE_GAP = 12

#: At most this many caller-positioned opcodes may sit between two parts of one copy.
MAX_ARGUMENT_OPS = 12

#: Operand kinds holding a value that can differ from call site to call site.
_VALUE_KINDS = frozenset({"RefInt", "RefFloat", "RefString", "RefBytes", "InlineBool"})
_JUMP_KINDS = frozenset({"JumpOffset", "JumpOffsets"})

#: `dst` is read by these (Incr/Decr also write it; Setref writes through it).
_DST_READ = frozenset({"Setref", "Incr", "Decr"})
_DST_NOT_WRITTEN = frozenset({"Setref"})


def _reads(op: Opcode) -> List[int]:
    regs: List[int] = []
    for key, operand in op.df.items():
        if key == "dst" and op.op not in _DST_READ:
            continue
        if isinstance(operand, Reg):
            regs.append(operand.value)
        elif isinstance(operand, Regs):
            regs.extend(r.value for r in operand.value)
    return regs


def _writes(op: Opcode) -> Optional[int]:
    dst = op.df.get("dst")
    if isinstance(dst, Reg) and op.op not in _DST_NOT_WRITTEN:
        return dst.value
    return None


def _jump_targets(op: Opcode, index: int) -> List[int]:
    kinds = opcodes.get(op.op or "", {})
    targets = []
    for key, operand in op.df.items():
        kind = kinds.get(key)
        if kind == "JumpOffset":
            targets.append(index + operand.value + 1)
        elif kind == "JumpOffsets":
            targets.extend(index + offset.value + 1 for offset in operand.value)
    return targets


def file_kind(path: str) -> str:
    """`compiler` for the compiler's `?` file, `macro` for macro sources (their positions
    mark generated code), else `source`."""
    if path == "?":
        return "compiler"
    if re.search(r"(^|/)macro/|Macros?\.hx$", path):
        return "macro"
    return "source"


@dataclass
class InlineSite:
    """One copy of an inlined body inside a caller."""

    findex: int
    #: Inclusive opcode range of the copy.
    start: int
    end: int
    #: Debug file index and line span of the inlined function's own lines.
    file: int
    first_line: int
    last_line: int
    #: Opcodes of the copy positioned in the callee (its own lines and nested bodies'),
    #: in order. Everything else in [start, end] is caller code evaluated in place.
    ops: List[int] = field(default_factory=list)
    #: (file, first line, last line) of bodies inlined into this one.
    nested: List[Tuple[int, int, int]] = field(default_factory=list)
    #: Registers the body reads before writing them (its arguments), in order of first use.
    inputs: List[int] = field(default_factory=list)
    #: Registers the body writes that are read after the copy (its result), by last write.
    outputs: List[int] = field(default_factory=list)
    #: The copy is the caller's entire code: typically a method a build macro wrote into
    #: many classes (the macro's positions), not an inlined call.
    whole_function: bool = False

    @property
    def caller_ops(self) -> int:
        """Caller-positioned opcodes inside the copy."""
        return self.end - self.start + 1 - len(self.ops)


@dataclass
class InlinedFunction:
    """Every copy of one inlined function."""

    file: int
    path: str
    kind: str
    first_line: int
    last_line: int
    sites: List[InlineSite] = field(default_factory=list)
    #: A function still in the bytecode whose own lines are these, when the inlined
    #: method also exists outright.
    real_name: Optional[str] = None


@dataclass
class Shape:
    """Copies of one inlined function whose bodies compile to the same opcodes."""

    key: Tuple
    sites: List[InlineSite]
    #: Per parameter: type names across the sites.
    input_types: List[Counter]
    #: Per parameter: how the body first reads it ("Field.obj", "Call2.arg1", ...).
    input_uses: List[str]
    #: Per result: type names across the sites.
    output_types: List[Counter]
    #: (index among the body's constants, where, distinct values) for constants that differ per site.
    varying_constants: List[Tuple[int, str, List[str]]]


class InlineFinder:
    def __init__(self, code: Bytecode) -> None:
        if not code.debugfiles:
            raise ValueError("bytecode has no debug info")
        self.code = code
        self.files: List[str] = [str(f) for f in code.debugfiles.value]
        self.kinds = [file_kind(p) for p in self.files]
        # Every trailing run of path components -> file indices, to match class paths
        # against absolute std paths and relative game paths alike.
        self._by_suffix: Dict[str, List[int]] = defaultdict(list)
        for index, path in enumerate(self.files):
            parts = path.replace("\\", "/").split("/")
            for i in range(len(parts)):
                self._by_suffix["/".join(parts[i:])].append(index)
        self._homes: Dict[int, Optional[int]] = {}
        #: Functions whose home file matched their class path (not a guess).
        self._named_homes: Set[int] = set()
        self._spans: Optional[Dict[int, List[Tuple[int, int, str]]]] = None
        self._found: Optional[List[InlinedFunction]] = None
        self._shapes: Dict[int, List[Shape]] = {}

    # --- home file -------------------------------------------------------------

    def _class_paths(self, func: Function) -> List[str]:
        name = self.code.full_func_name(func)
        if name == "<none>" or "." not in name:
            return []
        parts = [p.lstrip("$") for p in name.split(".")[:-1]]
        paths: List[str] = []
        # `pkg._Module.Type` is a private type of module `pkg/Module.hx`.
        for i, part in enumerate(parts[:-1]):
            if part.startswith("_"):
                paths.append("/".join(parts[:i] + [part[1:]]) + ".hx")
                break
        paths.append("/".join(parts) + ".hx")
        return paths

    def home_file(self, func: Function) -> Optional[int]:
        """Debug file index holding `func`'s own code."""
        key = func.findex.value
        if key in self._homes:
            return self._homes[key]
        refs = func.debuginfo.value if func.has_debug and func.debuginfo else []
        home: Optional[int] = None
        if refs:
            counts = Counter(r.value for r in refs)
            for rel in self._class_paths(func):
                candidates = self._by_suffix.get(rel, [])
                used = [f for f in candidates if counts[f]]
                if used:
                    home = max(used, key=lambda f: counts[f])
                    self._named_homes.add(key)
                    break
                if len(candidates) == 1:
                    # Its class's file, even though every opcode is some inlined body's.
                    home = candidates[0]
                    self._named_homes.add(key)
                    break
            if home is None:
                # Closures and oddly named types: the function returns from its own code.
                rets = Counter(refs[i].value for i, op in enumerate(func.ops) if op.op == "Ret")
                home = (rets or counts).most_common(1)[0][0]
        self._homes[key] = home
        return home

    # --- sites -----------------------------------------------------------------

    @staticmethod
    def _bodies(positions: List[Tuple[int, int]]) -> List[Tuple[int, int, int]]:
        """Split (file, line) positions into bodies: (file, first, last) spans whose lines
        are within BODY_LINE_GAP of each other."""
        by_file: Dict[int, Set[int]] = defaultdict(set)
        for file, line in positions:
            by_file[file].add(line)
        bodies = []
        for file, values in by_file.items():
            ordered = sorted(values)
            first = previous = ordered[0]
            for line in ordered[1:]:
                if line - previous > BODY_LINE_GAP:
                    bodies.append((file, first, previous))
                    first = line
                previous = line
            bodies.append((file, first, previous))
        return bodies

    @staticmethod
    def _body_of(bodies: List[Tuple[int, int, int]], file: int, line: int) -> Tuple[int, int, int]:
        return next(b for b in bodies if b[0] == file and b[1] <= line <= b[2])

    def _outer(
        self, func: Function, ops: List[int]
    ) -> Tuple[Tuple[int, int, int], List[Tuple[int, int, int]]]:
        """The body `ops` mostly belong to (the one the caller inlined), and the others."""
        assert func.debuginfo is not None
        refs = func.debuginfo.value
        bodies = self._bodies([(refs[k].value, refs[k].line) for k in ops])
        weight: Counter = Counter()
        first_op: Dict[Tuple[int, int, int], int] = {}
        for k in ops:
            body = self._body_of(bodies, refs[k].value, refs[k].line)
            weight[body] += 1
            first_op.setdefault(body, k)
        outer = max(bodies, key=lambda b: (weight[b], -first_op[b]))
        return outer, [b for b in bodies if b != outer]

    def sites(
        self, func: Function, cfg: Optional[CFGraph] = None, same_file: Optional[Set[int]] = None
    ) -> List[InlineSite]:
        """The copies of inlined bodies in `func`, in opcode order. `same_file` holds
        opcodes in the home file that belong to an inlined body too (see `find`)."""
        if not (func.has_debug and func.debuginfo and func.debuginfo.value):
            return []
        refs = func.debuginfo.value
        home = self.home_file(func)
        extra = same_file or set()

        def own(k: int) -> bool:
            return refs[k].value == home and k not in extra

        runs: List[Tuple[int, int]] = []
        i = 0
        while i < len(refs):
            if own(i):
                i += 1
                continue
            j = i
            while j + 1 < len(refs) and not own(j + 1):
                j += 1
            runs.append((i, j))
            i = j + 1
        if not runs:
            return []

        # Join runs into copies: a later run continues the current copy when it is the
        # same body and reads a value the copy computed (a separate call to the same
        # function never sees another call's internals).
        groups: List[List[Tuple[int, int]]] = [[runs[0]]]
        for run in runs[1:]:
            group = groups[-1]
            last_end = group[-1][1]
            if run[0] - last_end - 1 <= MAX_ARGUMENT_OPS and self._continues(func, group, run):
                group.append(run)
            else:
                groups.append([run])

        found = []
        for group in groups:
            ops = [k for start, end in group for k in range(start, end + 1)]
            outer, nested = self._outer(func, ops)
            found.append(
                InlineSite(
                    findex=func.findex.value,
                    start=group[0][0],
                    end=group[-1][1],
                    file=outer[0],
                    first_line=outer[1],
                    last_line=outer[2],
                    ops=ops,
                    nested=nested,
                    whole_function=len(ops) == len(func.ops),
                )
            )
        self._fill_dataflow(func, found, cfg)
        return found

    def _continues(self, func: Function, group: List[Tuple[int, int]], run: Tuple[int, int]) -> bool:
        group_ops = [k for start, end in group for k in range(start, end + 1)]
        outer, _ = self._outer(func, group_ops)
        run_outer, _ = self._outer(func, list(range(run[0], run[1] + 1)))
        if (
            run_outer[0] != outer[0]
            or run_outer[1] > outer[2] + BODY_LINE_GAP
            or run_outer[2] < outer[1] - BODY_LINE_GAP
        ):
            return False
        # Values the copy has computed so far, still unchanged.
        live: Set[int] = set()
        for k in group_ops:
            dst = _writes(func.ops[k])
            if dst is not None:
                live.add(dst)
        for k in range(group[-1][1] + 1, run[1] + 1):
            op = func.ops[k]
            if any(reg in live for reg in _reads(op)):
                return True
            dst = _writes(op)
            if dst is not None:
                live.discard(dst)
        return False

    def _fill_dataflow(self, func: Function, sites: List[InlineSite], cfg: Optional[CFGraph]) -> None:
        if cfg is None:
            cfg = CFGraph(func)
            cfg.build(do_optimize=False)
        where: Dict[int, Tuple[CFNode, int]] = {}
        for node in cfg.nodes:
            for offset in range(len(node.ops)):
                where[node.base_offset + offset] = (node, offset)
        for site in sites:
            written: Set[int] = set()
            inputs: List[int] = []
            last_write: Dict[int, int] = {}
            for k in site.ops:
                op = func.ops[k]
                for reg in _reads(op):
                    if reg not in written and reg not in inputs:
                        inputs.append(reg)
                dst = _writes(op)
                if dst is not None:
                    written.add(dst)
                    last_write[dst] = k
            site.inputs = inputs
            site.outputs = sorted(
                (
                    reg
                    for reg in written
                    if not isinstance(func.regs[reg].resolve(self.code).definition, Void)
                    and self._live_after(where, site.end, reg)
                ),
                key=lambda reg: last_write[reg],
            )

    @staticmethod
    def _live_after(where: Dict[int, Tuple[CFNode, int]], index: int, reg: int) -> bool:
        """Whether a path from opcode `index + 1` reads `reg` before overwriting it."""
        located = where.get(index)
        if located is None:
            return False
        node, offset = located
        pending: List[Tuple[CFNode, int]] = []
        if offset + 1 < len(node.ops):
            pending.append((node, offset + 1))
        else:
            pending.extend((target, 0) for target, _ in node.branches)
        seen: Set[CFNode] = set()
        while pending:
            current, start = pending.pop()
            if start == 0:
                if current in seen:
                    continue
                seen.add(current)
            for op in current.ops[start:]:
                if reg in _reads(op):
                    return True
                if _writes(op) == reg:
                    break
            else:
                pending.extend((target, 0) for target, _ in current.branches)
        return False

    # --- grouping --------------------------------------------------------------

    def find(self, functions: Optional[Sequence[Function]] = None) -> List[InlinedFunction]:
        """Every inlined function copied into `functions` (all functions by default, which
        is computed once and cached), most copied first."""
        if functions is None:
            if self._found is None:
                self._found = self._find(None)
            return self._found
        return self._find(functions)

    def _find(self, functions: Optional[Sequence[Function]]) -> List[InlinedFunction]:
        funcs = [
            f
            for f in (functions if functions is not None else self.code.functions)
            if isinstance(f, Function)
        ]
        per_function = {func.findex.value: self.sites(func) for func in funcs}
        # A body inlined into another file can also be inlined into its own file, where
        # the file alone does not give it away: look for its lines there too.
        known: Dict[int, Set[int]] = defaultdict(set)
        for sites in per_function.values():
            for site in sites:
                if not site.whole_function and self.kinds[site.file] == "source":
                    func = self.code.fn(site.findex)
                    assert isinstance(func, Function) and func.debuginfo is not None
                    known[site.file].update(
                        func.debuginfo.value[k].line
                        for k in site.ops
                        if func.debuginfo.value[k].value == site.file
                    )
        for func in funcs:
            home = self.home_file(func)
            if home in known:
                extra = self._same_file_copies(func, home, known[home])
                if extra:
                    per_function[func.findex.value] = self.sites(func, same_file=extra)
        by_file: Dict[int, List[InlineSite]] = defaultdict(list)
        for sites in per_function.values():
            for site in sites:
                by_file[site.file].append(site)
        # Sites of one file whose line spans overlap are one inlined function.
        result: List[InlinedFunction] = []
        for file, sites in by_file.items():
            sites.sort(key=lambda s: (s.first_line, s.last_line))
            group: List[InlineSite] = []
            end = -1
            for site in sites:
                if group and site.first_line > end:
                    result.append(self._inlined(file, group))
                    group = []
                group.append(site)
                end = max(end, site.last_line)
            if group:
                result.append(self._inlined(file, group))
        result.sort(key=lambda f: -len(f.sites))
        return result

    @classmethod
    def _same_file_copies(cls, func: Function, home: int, body_lines: Set[int]) -> Set[int]:
        """Home-file opcodes of `func` on lines where copies in other files put an inlined
        body, as long as `func` also has code of its own away from those bodies. The
        definition of an inline method has code on its bodies' lines and right next to
        them (a first statement copies place at the call site), and gets none."""
        assert func.debuginfo is not None
        refs = func.debuginfo.value
        copies = {k for k, ref in enumerate(refs) if ref.value == home and ref.line in body_lines}
        if not copies:
            return set()
        clusters = cls._bodies([(home, refs[k].line) for k in copies])
        own = {ref.line for k, ref in enumerate(refs) if ref.value == home and k not in copies}
        if not any(all(not first - 2 <= line <= last + 2 for _, first, last in clusters) for line in own):
            return set()
        return copies

    def _inlined(self, file: int, sites: List[InlineSite]) -> InlinedFunction:
        first = min(s.first_line for s in sites)
        last = max(s.last_line for s in sites)
        return InlinedFunction(
            file,
            self.files[file],
            self.kinds[file],
            first,
            last,
            sites,
            self._real_function_at(file, first, last),
        )

    def _real_function_at(self, file: int, first: int, last: int) -> Optional[str]:
        """A function still in the bytecode whose own lines are [first, last] (give or
        take a line for its declaration and closing brace)."""
        if self._spans is None:
            spans: Dict[int, List[Tuple[int, int, str]]] = defaultdict(list)
            for func in self.code.functions:
                if not (
                    isinstance(func, Function) and func.has_debug and func.debuginfo and func.debuginfo.value
                ):
                    continue
                name = self.code.full_func_name(func)
                # Constructors also hold every field initialiser of the class.
                if name == "<none>" or name.endswith(".__constructor__"):
                    continue
                home = self.home_file(func)
                if home is None or func.findex.value not in self._named_homes:
                    continue
                own = [r.line for r in func.debuginfo.value if r.value == home]
                if own:
                    spans[home].append((min(own), max(own), name))
            self._spans = spans
        for lo, hi, name in self._spans.get(file, ()):
            if lo - 1 <= first and last <= hi + 1 and first - lo <= 2 and hi - last <= 2:
                return name
        return None

    # --- shapes ----------------------------------------------------------------

    def _canonical(self, site: InlineSite) -> Tuple[Tuple, List[Tuple[str, str]], List[str]]:
        """The body's opcodes with registers renamed by role (parameters `in0..`, body
        temporaries `t0..`), jumps as positions within the body, and per-site constants
        replaced by their kind; plus those constants' values in order and how each
        parameter is first read."""
        func = self.code.fn(site.findex)
        assert isinstance(func, Function)
        position = {k: n for n, k in enumerate(site.ops)}
        roles: Dict[int, str] = {reg: f"in{i}" for i, reg in enumerate(site.inputs)}
        temporaries = 0
        uses: Dict[str, str] = {}
        constants: List[Tuple[str, str]] = []
        seq = []
        for k in site.ops:
            op = func.ops[k]
            kinds = opcodes.get(op.op or "", {})
            operands = []
            for key, operand in op.df.items():
                kind = kinds.get(key)
                if isinstance(operand, (Reg, Regs)):
                    regs = [operand.value] if isinstance(operand, Reg) else [r.value for r in operand.value]
                    names = []
                    for reg in regs:
                        if reg not in roles:
                            roles[reg] = f"t{temporaries}"
                            temporaries += 1
                        role = roles[reg]
                        if role.startswith("in") and (key != "dst" or op.op in _DST_READ):
                            uses.setdefault(role, f"{op.op}.{key}")
                        names.append(role)
                    operands.append((key, tuple(names)))
                elif kind in _JUMP_KINDS:
                    targets = _jump_targets(op, k)
                    operands.append(
                        (
                            key,
                            tuple(
                                f"@{position[t]}" if t in position else ("exit" if t > site.end else "caller")
                                for t in targets
                            ),
                        )
                    )
                elif kind in _VALUE_KINDS:
                    constants.append((f"{op.op}.{key}", self._constant(operand)))
                    operands.append((key, kind))
                else:
                    operands.append((key, str(operand.value)))
            seq.append((op.op, tuple(operands)))
        return tuple(seq), constants, [uses.get(f"in{i}", "?") for i in range(len(site.inputs))]

    def _constant(self, operand) -> str:
        try:
            value = operand.resolve(self.code) if hasattr(operand, "resolve") else operand.value
        except Exception:
            value = operand.value
        return repr(getattr(value, "value", value))

    def shapes(self, inlined: InlinedFunction) -> List[Shape]:
        """Group the copies of `inlined` by body shape, most common first, with each
        shape's parameter and result types and the constants that differ per site."""
        cached = self._shapes.get(id(inlined))
        if cached is None:
            cached = self._shapes[id(inlined)] = self._compute_shapes(inlined)
        return cached

    def _compute_shapes(self, inlined: InlinedFunction) -> List[Shape]:
        groups: Dict[Tuple, List[Tuple[InlineSite, List[Tuple[str, str]], List[str]]]] = defaultdict(list)
        for site in inlined.sites:
            key, constants, uses = self._canonical(site)
            groups[key].append((site, constants, uses))
        shapes = []
        for key, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            sites = [m[0] for m in members]
            input_types: List[Counter] = [Counter() for _ in sites[0].inputs]
            output_types: List[Counter] = [Counter() for _ in range(max(len(s.outputs) for s in sites))]
            for site in sites:
                func = self.code.fn(site.findex)
                assert isinstance(func, Function)
                for i, reg in enumerate(site.inputs):
                    input_types[i][self._type_name(func, reg)] += 1
                for i, reg in enumerate(site.outputs):
                    output_types[i][self._type_name(func, reg)] += 1
            varying = []
            for index, (where, _) in enumerate(members[0][1]):
                values = sorted({m[1][index][1] for m in members})
                if len(values) > 1:
                    varying.append((index, where, values))
            shapes.append(Shape(key, sites, input_types, members[0][2], output_types, varying))
        return shapes

    def annotate(self, site: InlineSite, context: int = 2) -> str:
        """Disassembly of a copy (with `context` opcodes around it), each opcode tagged with
        where it comes from: the inlined body, a body nested in it, or the caller."""
        from .disasm import pseudo_from_op

        func = self.code.fn(site.findex)
        assert isinstance(func, Function) and func.debuginfo is not None
        refs = func.debuginfo.value
        own = set(site.ops)
        roles = {reg: f"in{i}" for i, reg in enumerate(site.inputs)}
        roles.update({reg: f"out{i}" for i, reg in enumerate(site.outputs)})
        lines = []
        for k in range(max(0, site.start - context), min(len(func.ops), site.end + context + 1)):
            ref = refs[k]
            if k in own:
                inner = ref.value == site.file and site.first_line <= ref.line <= site.last_line
                tag = "body  " if inner else "nested"
            else:
                tag = "caller" if site.start <= k <= site.end else "      "
            where = f"{self.files[ref.value].rsplit('/', 1)[-1]}:{ref.line}"
            text = pseudo_from_op(func.ops[k], k, func.regs, self.code)
            regs = sorted({r for r in _reads(func.ops[k]) + [_writes(func.ops[k])] if r in roles}, key=str)
            note = (
                "  ; " + ", ".join(f"reg{r}={roles[r]}" for r in regs)
                if regs and site.start <= k <= site.end
                else ""
            )
            lines.append(f"{k:5d} {tag} {where:<24} {text}{note}")
        return "\n".join(lines)

    def _type_name(self, func: Function, reg: int) -> str:
        from .disasm import type_name

        return type_name(self.code, func.regs[reg].resolve(self.code))


_CONSTANT_OPS = frozenset({"Int", "Float", "Bool", "String", "Bytes", "Null"})


def location(fn: InlinedFunction) -> str:
    """`path:line` or `path:first-last` of an inlined function (std paths from `std/`)."""
    path = fn.path.split("/std/", 1)[1] if "/std/" in fn.path else fn.path
    lines = str(fn.first_line) if fn.first_line == fn.last_line else f"{fn.first_line}-{fn.last_line}"
    return f"{path}:{lines}"


def signature(shape: Shape) -> str:
    """`(param types) -> result` of a shape, each position's most common type. A result
    shows only when most of the shape's sites read it afterwards."""
    params = ", ".join(types.most_common(1)[0][0] for types in shape.input_types)
    majority = len(shape.sites) / 2
    results = [types.most_common(1)[0][0] for types in shape.output_types if sum(types.values()) > majority]
    if not results:
        return f"({params})"
    return f"({params}) -> " + (results[0] if len(results) == 1 else "(" + ", ".join(results) + ")")


def is_constant(shape: Shape) -> bool:
    """A body that only loads a constant: a `static inline var` or a constant getter."""
    return len(shape.key) == 1 and not shape.input_types and shape.key[0][0] in _CONSTANT_OPS


def find_at(finder: InlineFinder, spec: str) -> List[InlinedFunction]:
    """Inlined functions at `path:line` (or every one in `path`); `path` may be any
    trailing part of the debug file path, e.g. `Cooldown.hx:225`."""
    path, _, line_text = spec.rpartition(":")
    if not path or not line_text.isdigit():
        path, line = spec, None
    else:
        line = int(line_text)
    path = path.replace("\\", "/").lstrip("/")
    return [
        fn
        for fn in finder.find()
        if (fn.path == path or fn.path.endswith("/" + path))
        and (line is None or fn.first_line <= line <= fn.last_line)
    ]


def describe(
    finder: InlineFinder, fn: InlinedFunction, shapes: Optional[int] = 2, annotate: bool = False
) -> str:
    """An inlined function's copies and shapes (the first `shapes`, or all for None):
    parameter and result types, per-site constants, an example caller, and with
    `annotate` the disassembly of one copy per shape."""
    code = finder.code
    callers = {s.findex for s in fn.sites}
    label = location(fn)
    if fn.real_name:
        label += f"  (also exists as {fn.real_name})"
    whole = sum(1 for s in fn.sites if s.whole_function)
    note = f", {whole} of them a caller's entire code (build macro?)" if whole else ""
    out = [f"{label}  [{fn.kind}] {len(fn.sites)} copies in {len(callers)} functions{note}"]
    nested: Counter = Counter()
    for site in fn.sites:
        for file, first, last in site.nested:
            nested[f"{finder.files[file].rsplit('/', 1)[-1]}:{first}-{last}"] += 1
    if nested:
        out.append("  inlines in turn: " + ", ".join(f"{name} x{n}" for name, n in nested.most_common(4)))
    all_shapes = finder.shapes(fn)
    for shape in all_shapes if shapes is None else all_shapes[:shapes]:
        ops = " ".join(op for op, _ in shape.key)
        kind = " (a constant: static inline var or constant getter)" if is_constant(shape) else ""
        out.append(f"  shape x{len(shape.sites)} {signature(shape)}: {len(shape.key)} ops: {ops[:150]}{kind}")
        for i, types in enumerate(shape.input_types):
            common = ", ".join(f"{t} x{n}" for t, n in types.most_common(3))
            out.append(f"    in{i}: {common}   first read by {shape.input_uses[i]}")
        for i, types in enumerate(shape.output_types):
            common = ", ".join(f"{t} x{n}" for t, n in types.most_common(3))
            out.append(f"    out{i}: {common}")
        for index, where, values in shape.varying_constants[:3]:
            sample = ", ".join(values[:6]) + (" ..." if len(values) > 6 else "")
            out.append(f"    per-site constant #{index} ({where}): {sample}")
        example = shape.sites[0]
        caller = code.full_func_name(code.fn(example.findex))
        out.append(f"    e.g. {caller} f@{example.findex} ops {example.start}-{example.end}")
        if annotate:
            out.extend("      " + line for line in finder.annotate(example).splitlines())
    if shapes is not None and len(all_shapes) > shapes:
        out.append(f"  ... {len(all_shapes) - shapes} more shapes")
    return "\n".join(out)


def describe_function(finder: InlineFinder, findex: int) -> str:
    """The inlined bodies copied into function `findex`, each annotated."""
    code = finder.code
    out = []
    for fn in finder.find():
        for site in fn.sites:
            if site.findex == findex:
                out.append(
                    (site.start, f"{location(fn)}  ops {site.start}-{site.end}\n{finder.annotate(site)}")
                )
    header = f"{code.full_func_name(code.fn(findex))} f@{findex}: {len(out)} inlined copies"
    return "\n\n".join([header] + [text for _, text in sorted(out)])


def report(
    code: Bytecode,
    limit: int = 30,
    shapes_per_function: int = 2,
    include_generated: bool = False,
    finder: Optional[InlineFinder] = None,
) -> str:
    """Human-readable summary of the most copied inlined functions."""
    finder = finder or InlineFinder(code)
    inlined = finder.find()
    by_kind: Counter = Counter()
    for fn in inlined:
        by_kind[fn.kind] += len(fn.sites)
    out = [
        f"{len(inlined)} inlined bodies; copies: "
        + ", ".join(f"{n} from {kind} files" for kind, n in by_kind.most_common())
    ]
    shown = [fn for fn in inlined if fn.kind == "source" or include_generated][:limit]
    for fn in shown:
        out.append("")
        out.append(describe(finder, fn, shapes_per_function))
    return "\n".join(out)
