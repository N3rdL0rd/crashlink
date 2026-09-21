"""End-to-end decompile-to-Haxe rendering: the path `crashlink decompile --class`
and the GUI's class view both run, for every class in a module."""

from crashlink import decomp

from ._fixtures import FIXTURES, classes_of, load


class TimeDecompileAllClasses:
    params = FIXTURES
    param_names = ["fixture"]

    def setup(self, name: str) -> None:
        self.code = load(name)
        self.classes = classes_of(self.code)

    def time_decompile_all_classes(self, name: str) -> None:
        for obj in self.classes:
            decomp.IRClass(self.code, obj).pseudo()
