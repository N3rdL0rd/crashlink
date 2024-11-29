from crashlink import *

from typing import Tuple

def load_test(path) -> Tuple[Bytecode, Function]:
    code = Bytecode.from_path(path)
    assert code is not None
    func = None
    for f in code.functions:
        if "main" in fmt.disasm.full_func_name(code, f):
            func = f
            break
    assert func is not None
    return code, func

def test_switch():
    code, func = load_test("tests/haxe/Switch.hl")
    cfg = fmt.decomp.CFGraph(func)
    cfg.build()
    assert cfg.nodes[0].ops[-1].op == "Switch"
    assert cfg.nodes[-1].ops[-1].op == "Ret"
