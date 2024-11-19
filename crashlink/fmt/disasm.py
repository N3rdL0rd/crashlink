from ..core import *

from typing import Optional

def get_proto_for(code: Bytecode, idx: int) -> Optional[Proto]:
    for type in code.types:
        if type.kind.value == Type.TYPEDEFS.index(Obj):
            definition: Obj = type.definition
            for proto in definition.protos:
                if proto.findex.value == idx:
                    return proto
    return None


def type_name(code: Bytecode, typ: Type):
    typedef = type(typ.definition)
    defn = typ.definition
    if typedef == Obj:
        defn: Obj = defn
        return defn.name.resolve(code)
    elif typedef == Virtual:
        defn: Virtual = defn
        fields = []
        for field in defn.fields:
            fields.append(field.name.resolve(code))
        return f"Virtual[{', '.join(fields)}]"
    return typedef.__name__

def func_header(code: Bytecode, func: Function):
    proto = get_proto_for(code, func.findex.value)
    if proto:
        name = proto.name.resolve(code)
    else:
        name = "<none>"
    try:
        fun: Fun = func.type.resolve(code).definition
    except:
        fun = None
    if fun:
        return f"f@{func.findex.value} {name} ({', '.join([type_name(code, arg.resolve(code)) for arg in fun.args])}) -> {type_name(code, fun.ret.resolve(code))}"
    return f"f@{func.findex.value} {name} (no fun found, this is a bug!)"
