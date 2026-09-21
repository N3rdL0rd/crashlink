"""Whole-module HL/C transpilation (`crashlink to-c`'s `hlc.code_to_c`)."""

from crashlink import hlc as hlc_mod

from ._fixtures import FIXTURES, load


class TimeCodeToC:
    params = FIXTURES
    param_names = ["fixture"]

    def setup(self, name: str) -> None:
        self.code = load(name)

    def time_code_to_c(self, name: str) -> None:
        hlc_mod.code_to_c(self.code)
