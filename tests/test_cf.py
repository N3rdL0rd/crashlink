from typing import Tuple

from crashlink import *


def test_switch():
    code = Bytecode.from_path("tests/haxe/Switch.hl")
    func = code.get_test_main()
    cfg = decomp.CFGraph(func)
    cfg.build()
    assert cfg.nodes[0].ops[-1].op == "Switch"
    assert cfg.nodes[-1].ops[-1].op == "Ret"
