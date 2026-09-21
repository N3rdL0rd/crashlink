"""Benchmarks targeting specific convoluted-control-flow shapes rather than
whole modules: CFG construction/jump-threading cost on branch-heavy
functions, and a short-circuit `&&`/`||` guard chain of the kind that used
to duplicate lifted IR per link (fixed in e630824, "stop exponential IR
duplication in short-circuit chains", see tests/test_cf.py)."""

from crashlink import core, decomp
from crashlink import pseudo as pseudo_mod
from crashlink.decomp import cfg as cfg_mod

from ._fixtures import fixture, load


class TimeCFGraphBuild:
    """`BigControlFlow.main` mixes if/else, switch, for, while, do-while and
    try/catch in one function body - CFGraph.build's branch/loop-detection
    walks every one of those shapes."""

    params = ["BigControlFlow", "BigCombo"]
    param_names = ["fixture"]

    def setup(self, name: str) -> None:
        code = load(name)
        self.func = code.get_test_main()

    def time_build(self, name: str) -> None:
        graph = cfg_mod.CFGraph(self.func)
        graph.build()

    def time_build_unthreaded_then_thread(self, name: str) -> None:
        graph = cfg_mod.CFGraph(self.func)
        graph.build(do_optimize=False)
        cfg_mod.CFJumpThreader(graph).optimize()


class TimeShortCircuitChain:
    """12-link `(a && b) || (c && d) || ...` guard, each link independently
    reachable from the entry - the shape whose lifted-IR size used to double
    per additional link (~152k nodes from 59 opcodes at 12 links)."""

    def setup(self) -> None:
        self.code = core.Bytecode.from_path(fixture("BenchShortCircuitChain"))
        self.func = self._guard_function()

    def _guard_function(self) -> "core.Function":
        for f in self.code.functions:
            if self.code.full_func_name(f).endswith("guard"):
                return f
        raise AssertionError("guard function not found in BenchShortCircuitChain fixture")

    def time_lift(self) -> None:
        decomp.IRFunction(self.code, self.func)

    def time_pseudo(self) -> None:
        pseudo_mod.pseudo(decomp.IRFunction(self.code, self.func))
