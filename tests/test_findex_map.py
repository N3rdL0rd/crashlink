from pathlib import Path

from crashlink.core import Bytecode

HAXE_DIR = Path(__file__).parent / "haxe"


class _ReaderMidIteration(list):
    """Function list that lets a reader call get_findex_map() once, halfway through the map build."""

    def __init__(self, items, code: Bytecode):
        super().__init__(items)
        self.code = code
        self.fired = False
        self.seen: dict | None = None

    def __iter__(self):
        for i, item in enumerate(list.__iter__(self)):
            if i == len(self) // 2 and not self.fired:
                self.fired = True
                self.seen = dict(self.code.get_findex_map())
            yield item


def test_findex_map_is_never_visible_half_built():
    code = Bytecode.from_path(str(HAXE_DIR / "Clazz.hl"))
    assert len(code.functions) > 4
    expected = len(code.functions) + len(code.natives)
    code.functions = _ReaderMidIteration(code.functions, code)  # type: ignore[assignment]
    code.invalidate_findex_cache()

    code.get_findex_map()

    assert code.functions.seen is not None  # type: ignore[attr-defined]
    assert len(code.functions.seen) == expected  # type: ignore[attr-defined]
