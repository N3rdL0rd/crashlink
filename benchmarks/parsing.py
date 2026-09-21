"""Bytecode deserialisation: raw `.hl` bytes to the full typed object graph,
including static/dynamic class pairing (`Bytecode.map_statics`)."""

from crashlink import core

from ._fixtures import FIXTURES, fixture


class TimeFromPath:
    params = FIXTURES
    param_names = ["fixture"]

    def setup(self, name: str) -> None:
        self.path = fixture(name)

    def time_from_path(self, name: str) -> None:
        core.Bytecode.from_path(self.path)
