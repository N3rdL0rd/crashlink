"""IR lifting: raw opcodes to the optimized IR tree, without pseudocode rendering.

Separated from `pseudo_rendering.py` so a regression in the optimizer
pipeline (`IRFunction.optimizers`) is distinguishable from one in the
Haxe-source printer.
"""

from crashlink import decomp

from ._fixtures import FIXTURES, load


class TimeLiftAll:
    params = FIXTURES
    param_names = ["fixture"]

    def setup(self, name: str) -> None:
        self.code = load(name)

    def time_lift_optimized(self, name: str) -> None:
        for func in self.code.functions:
            decomp.IRFunction(self.code, func)

    def time_lift_unoptimized(self, name: str) -> None:
        for func in self.code.functions:
            decomp.IRFunction(self.code, func, do_optimize=False)
