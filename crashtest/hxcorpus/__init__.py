"""Run the decompiler pipeline over a real Haxe corpus: the compiler's own unit tests.

Each test class in `tests/unit/src/unit` (and `unit/issues`) becomes one program: a small
harness constructs the class and calls its `test*` methods, printing every assertion through
a deterministic stand-in for utest (`shim/`). The result goes through the same ladder as
`hxsmith` programs. A class that does not build standalone (needs macros, another target's
API, or the real utest runner) is reported as invalid, never as a decompiler failure.
"""

from .cases import DEFAULT_HAXE, Case, discover, job_for

__all__ = ["DEFAULT_HAXE", "Case", "discover", "job_for"]
