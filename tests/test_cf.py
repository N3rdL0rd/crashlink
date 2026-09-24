import shutil
import subprocess

import pytest

from crashlink import *
from crashlink.decomp import IRFunction

# Distinct `x && y` links OR-ed together: each link's "true" arm jumps to the
# shared bail-out tail while its "false" arm falls into the next link, so no
# link's arms post-dominate one another.
_LINKS = [
    "a == b && i < 1",
    'b == "x" && j > 2',
    "a != null && i != 3",
    "o == null && j <= 4",
    'a == "y" && i >= 5',
    "b != null && j == 6",
    "a != b && i > 7",
    'b == "z" && j < 8',
    "o != null && i <= 9",
    "a == null && j >= 10",
    'b != "w" && i == 11',
    'a != "v" && j != 12',
]

_CHAIN_SOURCE = """class Chain {{
    static var sink:Int = 0;
    public static function main() {{ guard("a", "b", 1, 2, null); }}
    static function guard(a:String, b:String, i:Int, j:Int, o:Dynamic):Int {{
        if ({condition}) {{
            sink += 1;
            report("bail", a, b);
            return -1;
        }}
        sink += 2;
        report("pass", b, a);
        return 1;
    }}
    static function report(tag:String, x:String, y:String):Void {{
        sink += tag.length + x.length + y.length;
    }}
}}
"""


def _lifted_node_count(path, findex_suffix):
    code = Bytecode.from_path(str(path))
    for func in code.functions:
        if not code.full_func_name(func).endswith(findex_suffix):
            continue
        ir = IRFunction(code, func, do_optimize=False)
        seen: set[int] = set()
        pending: list[decomp.IRStatement] = [ir.block]
        while pending:
            node = pending.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            pending.extend(node.get_children())
        return len(seen), pseudo.pseudo(IRFunction(code, func))
    raise AssertionError(f"no function ending in {findex_suffix!r}")


def _build_chain(haxe, directory, links):
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "Chain.hx"
    source.write_text(_CHAIN_SOURCE.format(condition=" || ".join(f"({link})" for link in links)))
    compiled = subprocess.run(
        [haxe, "-hl", "Chain.hl", "-main", "Chain.hx"],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    return directory / "Chain.hl"


def test_short_circuit_chain_lifts_linearly(tmp_path):
    # Every link used to lift the enclosing continuation again, because its
    # convergence candidate sat past the boundary the caller had established.
    # That doubled the lifted IR per link: a 12-link chain lifted to ~152k IR
    # nodes from 59 opcodes (and real 900-opcode functions to millions, which
    # exhausted memory before rendering anything).
    haxe = shutil.which("haxe")
    if not haxe:
        pytest.skip("short-circuit chain regression requires Haxe")
    short, _ = _lifted_node_count(_build_chain(haxe, tmp_path / "short", _LINKS[:4]), "guard")
    full, rendered = _lifted_node_count(_build_chain(haxe, tmp_path / "full", _LINKS), "guard")

    assert full < short * 4, f"lifting is superlinear in chain length: {short} -> {full} nodes"
    # Every link shares the one bail-out block and the one fall-through tail, so
    # each is emitted exactly once.
    assert rendered.count('"bail"') == 1
    assert rendered.count('"pass"') == 1


_STRING_SWITCH_SOURCE = """class StringSwitch {{
    public static function main() {{ pick("case3"); }}
    static function pick(s:String):Void {{
        switch (s) {{
{cases}
            default: trace("miss");
        }}
        trace("after");
    }}
}}
"""


def _build_string_switch(haxe, directory, count):
    directory.mkdir(parents=True, exist_ok=True)
    cases = "\n".join(f'            case "case{i}": trace("hit{i}");' for i in range(count))
    (directory / "StringSwitch.hx").write_text(_STRING_SWITCH_SOURCE.format(cases=cases))
    compiled = subprocess.run(
        [haxe, "-hl", "StringSwitch.hl", "-main", "StringSwitch.hx"],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    return directory / "StringSwitch.hl"


def test_string_switch_lifts_linearly(tmp_path):
    # Each string case is a null check, a length check and a string_compare, all
    # failing over to the next case. With case bodies falling through to a shared
    # end, lifting those as plain conditionals re-lifted the rest of the chain
    # under each failure edge: 3^n IR, and ~20s for just 8 cases.
    haxe = shutil.which("haxe")
    if not haxe:
        pytest.skip("string switch regression requires Haxe")
    short, _ = _lifted_node_count(_build_string_switch(haxe, tmp_path / "short", 4), "pick")
    full, rendered = _lifted_node_count(_build_string_switch(haxe, tmp_path / "full", 12), "pick")

    assert full < short * 4, f"lifting is superlinear in case count: {short} -> {full} nodes"
    assert rendered.count("switch (s)") == 1, rendered
    for i in range(12):
        assert rendered.count(f'case "case{i}":') == 1, rendered
        assert rendered.count(f'"hit{i}"') == 1, rendered
    assert rendered.count('"miss"') == 1, rendered
    assert rendered.count('"after"') == 1, rendered


def test_switch():
    code = Bytecode.from_path("tests/haxe/Switch.hl")
    func = code.get_test_main()
    cfg = decomp.CFGraph(func)
    cfg.build()
    assert cfg.nodes[0].ops[-1].op == "Switch"
    assert cfg.nodes[-1].ops[-1].op == "Ret"
