"""
Definitions of all 98 supported opcodes in the HashLink VM.
"""

opcodes = {
    "Mov": {"dst": "Reg", "src": "Reg"},  # 0
    "Int": {"dst": "Reg", "ptr": "RefInt"},  # 1
    "Float": {"dst": "Reg", "ptr": "RefFloat"},  # 2
    "Bool": {"dst": "Reg", "value": "InlineBool"},  # 3
    "Bytes": {"dst": "Reg", "ptr": "RefBytes"},  # 4
    "String": {"dst": "Reg", "ptr": "RefString"},  # 5
    "Null": {"dst": "Reg"},  # 6
    "Add": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 7
    "Sub": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 8
    "Mul": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 9
    "SDiv": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 10
    "UDiv": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 11
    "SMod": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 12
    "UMod": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 13
    "Shl": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 14
    "SShr": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 15
    "UShr": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 16
    "And": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 17
    "Or": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 18
    "Xor": {"dst": "Reg", "a": "Reg", "b": "Reg"},  # 19
    "Neg": {"dst": "Reg", "src": "Reg"},  # 20
    "Not": {"dst": "Reg", "src": "Reg"},  # 21
    "Incr": {"dst": "Reg"},  # 22
    "Decr": {"dst": "Reg"},  # 23
    "Call0": {"dst": "Reg", "fun": "RefFun"},  # 24
    "Call1": {"dst": "Reg", "fun": "RefFun", "arg0": "Reg"},  # 25
    "Call2": {"dst": "Reg", "fun": "RefFun", "arg0": "Reg", "arg1": "Reg"},  # 26
    "Call3": {
        "dst": "Reg",
        "fun": "RefFun",
        "arg0": "Reg",
        "arg1": "Reg",
        "arg2": "Reg",
    },  # 27
    "Call4": {
        "dst": "Reg",
        "fun": "RefFun",
        "arg0": "Reg",
        "arg1": "Reg",
        "arg2": "Reg",
        "arg3": "Reg",
    },  # 28
    "CallN": {"dst": "Reg", "fun": "RefFun", "args": "Regs"},  # 29
    "CallMethod": {"dst": "Reg", "field": "RefField", "args": "Regs"},  # 30
    "CallThis": {"dst": "Reg", "field": "RefField", "args": "Regs"},  # 31
    "CallClosure": {"dst": "Reg", "fun": "Reg", "args": "Regs"},  # 32
    "StaticClosure": {"dst": "Reg", "fun": "RefFun"},  # 33
    "InstanceClosure": {"dst": "Reg", "fun": "RefFun", "obj": "Reg"},  # 34
    "VirtualClosure": {"dst": "Reg", "obj": "Reg", "field": "Reg"},  # 35
    "GetGlobal": {"dst": "Reg", "global": "RefGlobal"},  # 36
    "SetGlobal": {"global": "RefGlobal", "src": "Reg"},  # 37
    "Field": {"dst": "Reg", "obj": "Reg", "field": "RefField"},  # 38
    "SetField": {"obj": "Reg", "field": "RefField", "src": "Reg"},  # 39
    "GetThis": {"dst": "Reg", "field": "RefField"},  # 40
    "SetThis": {"field": "RefField", "src": "Reg"},  # 41
    "DynGet": {"dst": "Reg", "obj": "Reg", "field": "RefString"},  # 42
    "DynSet": {"obj": "Reg", "field": "RefString", "src": "Reg"},  # 43
    "JTrue": {"cond": "Reg", "offset": "JumpOffset"},  # 44
    "JFalse": {"cond": "Reg", "offset": "JumpOffset"},  # 45
    "JNull": {"reg": "Reg", "offset": "JumpOffset"},  # 46
    "JNotNull": {"reg": "Reg", "offset": "JumpOffset"},  # 47
    "JSLt": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 48
    "JSGte": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 49
    "JSGt": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 50
    "JSLte": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 51
    "JULt": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 52
    "JUGte": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 53
    "JNotLt": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 54
    "JNotGte": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 55
    "JEq": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 56
    "JNotEq": {"a": "Reg", "b": "Reg", "offset": "JumpOffset"},  # 57
    "JAlways": {"offset": "JumpOffset"},  # 58
    "ToDyn": {"dst": "Reg", "src": "Reg"},  # 59
    "ToSFloat": {"dst": "Reg", "src": "Reg"},  # 60
    "ToUFloat": {"dst": "Reg", "src": "Reg"},  # 61
    "ToInt": {"dst": "Reg", "src": "Reg"},  # 62
    "SafeCast": {"dst": "Reg", "src": "Reg"},  # 63
    "UnsafeCast": {"dst": "Reg", "src": "Reg"},  # 64
    "ToVirtual": {"dst": "Reg", "src": "Reg"},  # 65
    "Label": {},  # 66
    "Ret": {"ret": "Reg"},  # 67
    "Throw": {"exc": "Reg"},  # 68
    "Rethrow": {"exc": "Reg"},  # 69
    "Switch": {"reg": "Reg", "offsets": "JumpOffsets", "end": "JumpOffset"},  # 70
    "NullCheck": {"reg": "Reg"},  # 71
    "Trap": {"exc": "Reg", "offset": "JumpOffset"},  # 72
    "EndTrap": {"exc": "Reg"},  # 73
    "GetI8": {"dst": "Reg", "bytes": "Reg", "index": "Reg"},  # 74
    "GetI16": {"dst": "Reg", "bytes": "Reg", "index": "Reg"},  # 75
    "GetMem": {"dst": "Reg", "bytes": "Reg", "index": "Reg"},  # 76
    "GetArray": {"dst": "Reg", "array": "Reg", "index": "Reg"},  # 77
    "SetI8": {"bytes": "Reg", "index": "Reg", "src": "Reg"},  # 78
    "SetI16": {"bytes": "Reg", "index": "Reg", "src": "Reg"},  # 79
    "SetMem": {"bytes": "Reg", "index": "Reg", "src": "Reg"},  # 80
    "SetArray": {"array": "Reg", "index": "Reg", "src": "Reg"},  # 81
    "New": {"dst": "Reg"},  # 82
    "ArraySize": {"dst": "Reg", "array": "Reg"},  # 83
    "Type": {"dst": "Reg", "ty": "RefType"},  # 84
    "GetType": {"dst": "Reg", "src": "Reg"},  # 85
    "GetTID": {"dst": "Reg", "src": "Reg"},  # 86
    "Ref": {"dst": "Reg", "src": "Reg"},  # 87
    "Unref": {"dst": "Reg", "src": "Reg"},  # 88
    "Setref": {"dst": "Reg", "value": "Reg"},  # 89
    "MakeEnum": {"dst": "Reg", "construct": "RefEnumConstruct", "args": "Regs"},  # 90
    "EnumAlloc": {"dst": "Reg", "construct": "RefEnumConstruct"},  # 91
    "EnumIndex": {"dst": "Reg", "value": "Reg"},  # 92
    "EnumField": {
        "dst": "Reg",
        "value": "Reg",
        "construct": "RefEnumConstruct",
        "field": "RefField",
    },  # 93
    "SetEnumField": {"value": "Reg", "field": "RefField", "src": "Reg"},  # 94
    "Assert": {},  # 95
    "RefData": {"dst": "Reg", "src": "Reg"},  # 96
    "RefOffset": {"dst": "Reg", "reg": "Reg", "offset": "Reg"},  # 97
    "Nop": {},  # 98
    "Prefetch": {"value": "Reg", "field": "RefField", "mode": "InlineInt"},  # 99
    "Asm": {"mode": "InlineInt", "value": "InlineInt", "reg": "Reg"},  # 100
}
"""
Opcodes.
"""
