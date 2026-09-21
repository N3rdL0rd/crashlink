"""Human-readable disassembly rendering (`crashlink disasm`'s per-function path)."""

from crashlink import disasm

from ._fixtures import FIXTURES, load


class TimeDisassembleAll:
    params = FIXTURES
    param_names = ["fixture"]

    def setup(self, name: str) -> None:
        self.code = load(name)

    def time_disassemble_all(self, name: str) -> None:
        for func in self.code.functions:
            disasm.func(self.code, func)
