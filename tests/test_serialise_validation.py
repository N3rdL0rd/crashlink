from pathlib import Path

import pytest

from crashlink.core import Bytecode, InvalidOpCode, Opcode

CLAZZ = str(Path(__file__).parent / "haxe" / "Clazz.hl")


def test_bytecode_serialise_checks_each_opcode_once(monkeypatch):
    code = Bytecode.from_path(CLAZZ)
    total_ops = sum(len(f.ops) for f in code.functions)
    calls = 0
    real_validate = Opcode.validate

    def counting_validate(self):
        nonlocal calls
        calls += 1
        return real_validate(self)

    monkeypatch.setattr(Opcode, "validate", counting_validate)

    assert code.serialise() == Path(CLAZZ).read_bytes()
    assert calls == total_ops


def test_bytecode_serialise_still_rejects_a_malformed_opcode():
    code = Bytecode.from_path(CLAZZ)
    victim = next(f for f in code.functions if f.ops)
    victim.ops[0].df.clear()

    with pytest.raises(InvalidOpCode):
        code.serialise()


def test_function_serialise_validates_when_called_directly():
    code = Bytecode.from_path(CLAZZ)
    victim = next(f for f in code.functions if f.ops)
    victim.ops[0].df.clear()

    with pytest.raises(InvalidOpCode):
        victim.serialise()
