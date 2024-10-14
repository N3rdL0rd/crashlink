from crashlink import *
from typing import Callable
import os

def for_each_test(routine: Callable):
    for test in os.listdir("tests/haxe"):
        if test.endswith(".hl"):
            code = Bytecode()
            code.deserialise(open(os.path.join("tests/haxe", test), "rb"))
            print(f"------{test}------")
            routine(code) # type: ignore

def test_deser():
    code = Bytecode()
    with open("tests/haxe/Clazz.hl", "rb") as f:
        code.deserialise(f)
    assert code.is_ok()

def deser_all(code: Bytecode):
    assert code.is_ok()

def test_deser_all():
    for_each_test(deser_all)