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
Definitions of all 98 supported opcodes in the HashLink VM.

Basic Operations:
- Mov: Copy value from src into dst register (dst = src) 
- Int: Load i32 constant from pool into dst (dst = @ptr)
- Float: Load f64 constant from pool into dst (dst = @ptr)
- Bool: Set boolean value in dst (dst = true/false)
- Bytes: Load byte array from constant pool into dst (dst = @ptr)
- String: Load string from constant pool into dst (dst = @ptr)
- Null: Set dst register to null (dst = null)

Arithmetic:
- Add: Add two numbers (dst = a + b)
- Sub: Subtract two numbers (dst = a - b) 
- Mul: Multiply two numbers (dst = a * b)
- SDiv: Signed division (dst = a / b)
- UDiv: Unsigned division (dst = a / b)
- SMod: Signed modulo (dst = a % b)
- UMod: Unsigned modulo (dst = a % b)

Bitwise:
- Shl: Left shift (dst = a << b)
- SShr: Signed right shift (dst = a >> b)
- UShr: Unsigned right shift (dst = a >>> b)
- And: Bitwise AND (dst = a & b)
- Or: Bitwise OR (dst = a | b)
- Xor: Bitwise XOR (dst = a ^ b)
- Neg: Negate value (dst = -src)
- Not: Boolean NOT (dst = !src)

Increment/Decrement:
- Incr: Increment value (dst++)
- Decr: Decrement value (dst--)

Function Calls:
- Call0: Call function with no args (dst = fun())
- Call1: Call function with 1 arg (dst = fun(arg0))
- Call2: Call function with 2 args (dst = fun(arg0, arg1))
- Call3: Call function with 3 args (dst = fun(arg0, arg1, arg2))
- Call4: Call function with 4 args (dst = fun(arg0, arg1, arg2, arg3))
- CallN: Call function with N args (dst = fun(args...))
- CallMethod: Call method with N args (dst = obj.field(args...))
- CallThis: Call this method with N args (dst = this.field(args...))
- CallClosure: Call closure with N args (dst = fun(args...))

Closures:
- StaticClosure: Create closure from function (dst = fun)
- InstanceClosure: Create closure from object method (dst = obj.fun)
- VirtualClosure: Create closure from object field (dst = obj.field)

Global Variables:
- GetGlobal: Get global value (dst = @global)
- SetGlobal: Set global value (@global = src)

Fields:
- Field: Get object field (dst = obj.field)  
- SetField: Set object field (obj.field = src)
- GetThis: Get this field (dst = this.field)
- SetThis: Set this field (this.field = src)
- DynGet: Get dynamic field (dst = obj[field])
- DynSet: Set dynamic field (obj[field] = src)

Control Flow:
- JTrue: Jump if true (if cond jump by offset)
- JFalse: Jump if false (if !cond jump by offset)
- JNull: Jump if null (if reg == null jump by offset)
- JNotNull: Jump if not null (if reg != null jump by offset)
- JSLt/JSGte/JSGt/JSLte: Signed comparison jumps
- JULt/JUGte: Unsigned comparison jumps 
- JNotLt/JNotGte: Negated comparison jumps
- JEq: Jump if equal (if a == b jump by offset)
- JNotEq: Jump if not equal (if a != b jump by offset)
- JAlways: Unconditional jump
- Label: Target for backward jumps (loops)
- Switch: Multi-way branch based on integer value

Type Conversions:
- ToDyn: Convert to dynamic type (dst = (dyn)src)
- ToSFloat: Convert to signed float (dst = (float)src)
- ToUFloat: Convert to unsigned float (dst = (float)src) 
- ToInt: Convert to int (dst = (int)src)
- SafeCast: Safe type cast with runtime check
- UnsafeCast: Unchecked type cast
- ToVirtual: Convert to virtual type

Exception Handling:
- Ret: Return from function (return ret)
- Throw: Throw exception 
- Rethrow: Rethrow exception
- Trap: Setup try-catch block
- EndTrap: End try-catch block
- NullCheck: Throw if null (if reg == null throw)

Memory Operations:
- GetI8: Read i8 from bytes (dst = bytes[index])
- GetI16: Read i16 from bytes (dst = bytes[index])
- GetMem: Read from memory (dst = bytes[index])
- GetArray: Get array element (dst = array[index])
- SetI8: Write i8 to bytes (bytes[index] = src)
- SetI16: Write i16 to bytes (bytes[index] = src) 
- SetMem: Write to memory (bytes[index] = src)
- SetArray: Set array element (array[index] = src)

Objects:
- New: Allocate new object (dst = new typeof(dst))
- ArraySize: Get array length (dst = len(array))
- Type: Get type object (dst = type ty)
- GetType: Get value's type (dst = typeof src)
- GetTID: Get type ID (dst = typeof src)

References:
- Ref: Create reference (dst = &src)
- Unref: Read reference (dst = *src)
- Setref: Write reference (*dst = src)
- RefData: Get reference data
- RefOffset: Get reference with offset

Enums:
- MakeEnum: Create enum variant (dst = construct(args...))
- EnumAlloc: Create enum with defaults (dst = construct())
- EnumIndex: Get enum tag (dst = variantof value)
- EnumField: Get enum field (dst = (value as construct).field)
- SetEnumField: Set enum field (value.field = src)

Other:
- Assert: Debug break
- Nop: No operation
- Prefetch: CPU memory prefetch hint
- Asm: Inline x86 assembly

If you want to see a more detailed pseudocode for any given instance of `Opcode`, you can use `crashlink.disasm.pseudo_from_op()` to get a human-readable representation of the operation.
"""
