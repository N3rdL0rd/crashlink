"""Behavioural signatures of HashLink functions.

`signature(code, func)` summarises what a function does as a hash. If two functions get the same
signature they behave the same; if they get different signatures nothing is known, because the
signature is only a canonical form and two equivalent functions can still be written in ways it
does not identify.

What the signature abstracts away: register numbers and reuse, copies, the order of independent
pure computations, constant materialisation and folding, dead code, jump layout and branch
polarity, and the numbering of types, functions, globals and fields (these are replaced by names).

What it keeps, in order: every call, store, allocation, and every check that can throw (null
dereferences, checked casts). The following are what "same behaviour" is relative to:

- a call to a function with a name is taken to be the same function in both images, so compare the
  callees' signatures as well;
- a lifted closure is identified by its own signature, not its name;
- integer division and modulo are treated as pure (HashLink defines division by zero);
- `strict=False` drops the checks that can throw, giving equality for executions in which none
  of them fails.

A function the model cannot cover (inline assembly, an exception handler that reads a register
written in the protected block, references with no stable name) gets no signature at all, and
never compares equal to anything.
"""

from __future__ import annotations

import weakref
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple

from ..core import Bytecode, Function
from .build import build
from .digest import digest
from .lift import Unsupported, check_trap_handlers, lift
from .names import Namer

__all__ = ["Signature", "Signer", "signature", "equivalent", "Unsupported"]

_VERSION = 1


@dataclass(frozen=True)
class Signature:
    digest: Optional[str]
    """Hex digest, or None when the function could not be summarised."""
    reason: Optional[str] = None
    """Why there is no digest."""

    def __bool__(self) -> bool:
        return self.digest is not None

    def matches(self, other: "Signature") -> bool:
        return self.digest is not None and self.digest == other.digest

    def __str__(self) -> str:
        return self.digest if self.digest is not None else f"<none: {self.reason}>"


class Signer:
    """Signatures for the functions of one bytecode image."""

    def __init__(self, code: Bytecode, strict: bool = True, ignore_positions: bool = True) -> None:
        self.code = code
        self.strict = strict
        self.ignore_positions = ignore_positions
        self._done: Dict[int, Signature] = {}
        self._active: Set[int] = set()

    def signature(self, func: Function) -> Signature:
        key = func.findex.value
        done = self._done.get(key)
        if done is not None:
            return done
        self._active.add(key)
        try:
            result = self._compute(func)
        finally:
            self._active.discard(key)
        self._done[key] = result
        return result

    def _anon_digest(self, func: Function) -> str:
        key = func.findex.value
        if key in self._active:
            return "recursive"
        sig = self.signature(func)
        if sig.digest is None:
            raise Unsupported(f"a lifted closure has no signature ({sig.reason})")
        return sig.digest

    def _compute(self, func: Function) -> Signature:
        code = self.code
        namer = Namer(code, self._anon_digest)
        try:
            regs = [t.value for t in func.regs]
            lifted = lift(func.ops, regs, namer)
            check_trap_handlers(lifted)
            built = build(code, func, lifted, namer, self.strict, self.ignore_positions)
            if namer.unstable:
                raise Unsupported("a reference with no stable name")
            header = (_VERSION, self.strict, self.ignore_positions, namer.type_index(func.type.value))
            return Signature(digest(built, header))
        except Unsupported as exc:
            return Signature(None, str(exc))


_signers: Dict[Tuple[int, bool, bool], Signer] = {}


def _signer(code: Bytecode, strict: bool, ignore_positions: bool) -> Signer:
    key = (id(code), strict, ignore_positions)
    signer = _signers.get(key)
    if signer is None or signer.code is not code:
        signer = Signer(code, strict, ignore_positions)
        _signers[key] = signer
        weakref.finalize(code, _signers.pop, key, None)
    return signer


def signature(
    code: Bytecode, func: Function, *, strict: bool = True, ignore_positions: bool = True
) -> Signature:
    """The behavioural signature of `func`.

    `ignore_positions` makes the source file and line a `haxe.PosInfos` was built with irrelevant: they
    record where code sat in the source, which recompiling decompiled output always changes."""
    return _signer(code, strict, ignore_positions).signature(func)


def equivalent(
    code_a: Bytecode,
    func_a: Function,
    code_b: Bytecode,
    func_b: Function,
    *,
    strict: bool = True,
    ignore_positions: bool = True,
) -> bool:
    """True when the signatures match, which proves the functions behave the same. False only
    means that is not shown."""
    a = signature(code_a, func_a, strict=strict, ignore_positions=ignore_positions)
    return a.matches(signature(code_b, func_b, strict=strict, ignore_positions=ignore_positions))
