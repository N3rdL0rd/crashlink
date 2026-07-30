import pytest

keystone = pytest.importorskip("keystone")

from crashlink.asm import X86AsmError, assemble_x86  # noqa: E402


def test_simple_instructions():
    assert assemble_x86("nop") == b"\x90"
    assert assemble_x86("ret") == b"\xc3"
    assert assemble_x86("xor edx, edx") == b"\x31\xd2"
    assert assemble_x86("inc dword [rcx]") == b"\xff\x01"  # 'dword [' auto-rewritten to 'dword ptr ['


def test_data_directives():
    assert assemble_x86("db 1, 2, 0xFF") == b"\x01\x02\xff"
    assert assemble_x86("dd 0") == b"\x00" * 4
    assert assemble_x86("dq 1") == (1).to_bytes(8, "little")
    assert assemble_x86("times 4 db 7") == b"\x07" * 4
    assert assemble_x86("times 2 dd 1") == (1).to_bytes(4, "little") * 2


def test_labels_and_branches():
    code = assemble_x86("loop:\ninc dword [rcx]\njnz loop\nret")
    assert code == bytes.fromhex("ff 01 75 fc c3")


def test_rip_relative_label():
    # lea rcx, [rip+data] at 0 (7 bytes) -> disp = 8 - 7 = 1
    code = assemble_x86("lea rcx, [rip+data]\nret\ndata:\ndb 0")
    assert code == bytes.fromhex("48 8d 0d 01 00 00 00 c3 00")


def test_rip_relative_arithmetic():
    # buf at offset 8, buf+2 -> disp = 10 - 7 = 3
    code = assemble_x86("lea rcx, [rip+buf+2]\nret\nbuf:\ndb 0")
    assert code == bytes.fromhex("48 8d 0d 03 00 00 00 c3 00")


def test_duplicate_label_rejected():
    with pytest.raises(X86AsmError):
        assemble_x86("x:\nnop\nx:\nret")


def test_bad_mnemonic_rejected():
    with pytest.raises(X86AsmError):
        assemble_x86("not_an_instruction rax")
