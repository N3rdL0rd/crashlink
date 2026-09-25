"""Methods the Haxe std declares `inline`: `type path -> methods`.

Generated from the Haxe std (`std/hl`, `std/hl/_std`, and the generic modules HashLink
doesn't override). A std method that survives in the bytecode but isn't called is inline
only if it is listed here: others are kept for reflection.
"""

from typing import Dict, FrozenSet

STD_INLINE_METHODS: Dict[str, FrozenSet[str]] = {
    "Any": frozenset({"__promote", "toString"}),
    "Array": frozenset({"filter", "iterator", "keyValueIterator", "map"}),
    "DateTools": frozenset({"days", "delta", "hours", "makeUtc", "minutes", "seconds"}),
    "IntIterator": frozenset({"hasNext", "new", "next"}),
    "Lambda": frozenset({"flatMap", "flatten", "map", "mapi"}),
    "Reflect": frozenset({"isFunction"}),
    "Std": frozenset({"instance", "int", "is"}),
    "String": frozenset({"__alloc__", "findChar", "fromUCS2"}),
    "StringBuf": frozenset({"__add", "__expand", "get_length"}),
    "StringTools": frozenset(
        {
            "_charAt",
            "contains",
            "endsWith",
            "fastCodeAt",
            "isEof",
            "iterator",
            "keyValueIterator",
            "ltrim",
            "rtrim",
            "startsWith",
            "trim",
            "unsafeCodeAt",
            "urlDecode",
            "urlEncode",
            "utf16CodePointAt",
        }
    ),
    "Type": frozenset({"get_allTypes"}),
    "UInt": frozenset(
        {
            "add",
            "addWithFloat",
            "and",
            "div",
            "divFloat",
            "floatDiv",
            "floatGt",
            "floatGte",
            "floatLt",
            "floatLte",
            "floatMod",
            "floatSub",
            "gtFloat",
            "gteFloat",
            "ltFloat",
            "lteFloat",
            "modFloat",
            "mul",
            "mulWithFloat",
            "negBits",
            "or",
            "postfixDecrement",
            "postfixIncrement",
            "prefixDecrement",
            "prefixIncrement",
            "shl",
            "shr",
            "sub",
            "subFloat",
            "toFloat",
            "toInt",
            "toString",
            "ushr",
            "xor",
        }
    ),
    "UnicodeString": frozenset({"iterator", "keyValueIterator", "new"}),
    "Xml": frozenset(
        {
            "ensureElementType",
            "firstChild",
            "get_nodeName",
            "get_nodeValue",
            "iterator",
            "set_nodeName",
            "set_nodeValue",
            "toString",
        }
    ),
    "haxe.CallStack": frozenset({"asArray", "copy", "get", "get_length"}),
    "haxe.DynamicAccess": frozenset(
        {"copy", "exists", "get", "iterator", "keyValueIterator", "keys", "new", "remove", "set"}
    ),
    "haxe.EntryPoint.Lock": frozenset({"release", "wait"}),
    "haxe.EntryPoint.Mutex": frozenset({"acquire", "release"}),
    "haxe.EnumFlags": frozenset({"has", "new", "ofInt", "set", "setTo", "toInt", "unset"}),
    "haxe.EnumTools": frozenset({"createAll", "createByIndex", "createByName", "getConstructors", "getName"}),
    "haxe.EnumTools.EnumValueTools": frozenset({"equals", "getIndex", "getName", "getParameters"}),
    "haxe.Exception": frozenset({"__shiftStack", "__unshiftStack"}),
    "haxe.Int32": frozenset(
        {
            "add",
            "addInt",
            "clamp",
            "complement",
            "intShl",
            "intShr",
            "intSub",
            "mul",
            "mulInt",
            "negate",
            "or",
            "orInt",
            "postDecrement",
            "postIncrement",
            "preDecrement",
            "preIncrement",
            "shl",
            "shlInt",
            "shr",
            "shrInt",
            "sub",
            "subInt",
            "toFloat",
            "xor",
            "xorInt",
        }
    ),
    "haxe.Int64": frozenset(
        {
            "add",
            "addInt",
            "and",
            "complement",
            "copy",
            "div",
            "divInt",
            "eq",
            "eqInt",
            "getHigh",
            "getLow",
            "get_high",
            "get_low",
            "get_val",
            "intDiv",
            "intGte",
            "intMod",
            "intSub",
            "is",
            "isInt64",
            "isNeg",
            "lt",
            "make",
            "mod",
            "modInt",
            "mul",
            "mulInt",
            "neg",
            "neq",
            "neqInt",
            "new",
            "ofInt",
            "or",
            "postDecrement",
            "postIncrement",
            "preDecrement",
            "preIncrement",
            "set_high",
            "set_low",
            "set_val",
            "shl",
            "shr",
            "sub",
            "subInt",
            "toInt",
            "ushr",
            "xor",
        }
    ),
    "haxe.Int64.___Int64": frozenset({"new"}),
    "haxe.Json": frozenset({"parse", "stringify"}),
    "haxe.MainLoop": frozenset({"get_threadCount"}),
    "haxe.MainLoop.MainEvent": frozenset({"call"}),
    "haxe.NativeStackTrace": frozenset({"callStack", "saveStack"}),
    "haxe.Rest": frozenset(
        {"get", "get_length", "iterator", "keyValueIterator", "new", "of", "toArray", "toString"}
    ),
    "haxe.Timer": frozenset({"stamp"}),
    "haxe.Ucs2": frozenset(
        {
            "charAt",
            "charCodeAt",
            "fromCharCode",
            "get_length",
            "indexOf",
            "lastIndexOf",
            "new",
            "split",
            "substr",
            "substring",
            "toLowerCase",
            "toNativeString",
            "toUpperCase",
        }
    ),
    "haxe.Unserializer": frozenset({"fastCharAt", "fastCharCodeAt", "fastLength", "fastSubstr", "get"}),
    "haxe.Unserializer.DefaultResolver": frozenset({"resolveClass", "resolveEnum"}),
    "haxe.Unserializer.NullResolver": frozenset({"get_instance", "resolveClass", "resolveEnum"}),
    "haxe.Utf8": frozenset({"addChar", "charCodeAt", "length", "sub", "toString", "validate"}),
    "haxe.atomic.AtomicBool": frozenset(
        {"compareExchange", "exchange", "load", "new", "store", "toBool", "toInt"}
    ),
    "haxe.atomic.AtomicInt": frozenset(
        {"add", "and", "compareExchange", "exchange", "load", "new", "or", "store", "sub", "xor"}
    ),
    "haxe.crypto.Crc32": frozenset({"byte", "get", "new", "update"}),
    "haxe.crypto.Hmac": frozenset({"doHash"}),
    "haxe.crypto.Sha224": frozenset(
        {"Ch", "Gamma0", "Gamma1", "Maj", "ROTR", "SHR", "Sigma0", "Sigma1", "safeAdd"}
    ),
    "haxe.crypto.Sha256": frozenset(
        {"Ch", "Gamma0256", "Gamma1256", "Maj", "R", "S", "Sigma0256", "Sigma1256", "safeAdd"}
    ),
    "haxe.display.FsPath": frozenset({"new", "toString"}),
    "haxe.display.Protocol.HaxeNotificationMethod": frozenset({"new"}),
    "haxe.display.Protocol.HaxeRequestMethod": frozenset({"new"}),
    "haxe.ds.ArraySort": frozenset({"compare"}),
    "haxe.ds.BalancedTree": frozenset({"keyValueIterator"}),
    "haxe.ds.BalancedTree.TreeNode": frozenset({"get_height"}),
    "haxe.ds.GenericStack": frozenset({"add", "first", "isEmpty", "pop"}),
    "haxe.ds.IntMap": frozenset({"keyValueIterator"}),
    "haxe.ds.List": frozenset({"iterator", "keyValueIterator"}),
    "haxe.ds.List.ListIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.ds.List.ListKeyValueIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.ds.List.ListNode": frozenset({"create", "get_item", "get_next", "set_item", "set_next"}),
    "haxe.ds.ListSort": frozenset({"sort", "sortSingleLinked"}),
    "haxe.ds.Map": frozenset(
        {
            "arrayWrite",
            "clear",
            "copy",
            "exists",
            "fromIntMap",
            "fromObjectMap",
            "fromStringMap",
            "get",
            "iterator",
            "keyValueIterator",
            "keys",
            "remove",
            "set",
            "toEnumValueMapMap",
            "toIntMap",
            "toObjectMap",
            "toString",
            "toStringMap",
        }
    ),
    "haxe.ds.ReadOnlyArray": frozenset({"concat", "get", "get_length"}),
    "haxe.ds.StringMap": frozenset({"keyValueIterator"}),
    "haxe.ds.StringMap.StringMapKeysIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.ds.Vector": frozenset(
        {
            "blit",
            "copy",
            "fill",
            "fromArrayCopy",
            "fromData",
            "get",
            "get_length",
            "join",
            "map",
            "new",
            "set",
            "sort",
            "toArray",
            "toData",
        }
    ),
    "haxe.format.JsonParser": frozenset({"nextChar", "parse", "parseNumber"}),
    "haxe.format.JsonPrinter": frozenset({"add", "addChar", "ipad", "newl", "objString"}),
    "haxe.io.ArrayBufferView": frozenset(
        {"fromData", "getData", "get_buffer", "get_byteLength", "get_byteOffset", "new", "sub", "subarray"}
    ),
    "haxe.io.Bytes": frozenset(
        {"fastGet", "getData", "getUInt16", "out", "outRange", "readString", "setInt64", "setUInt16"}
    ),
    "haxe.io.BytesBuffer": frozenset(
        {
            "add",
            "addByte",
            "addBytes",
            "addDouble",
            "addFloat",
            "addInt32",
            "addInt64",
            "addString",
            "get_length",
        }
    ),
    "haxe.io.BytesData.BytesDataAbstract": frozenset({"get", "new", "set", "toBytes"}),
    "haxe.io.BytesInput": frozenset({"get_length", "get_position"}),
    "haxe.io.BytesOutput": frozenset({"get_length"}),
    "haxe.io.Float32Array": frozenset(
        {"get", "getData", "get_length", "get_view", "new", "set", "sub", "subarray"}
    ),
    "haxe.io.Float64Array": frozenset(
        {"get", "getData", "get_length", "get_view", "new", "set", "sub", "subarray"}
    ),
    "haxe.io.Int32Array": frozenset(
        {"get", "getData", "get_length", "get_view", "new", "set", "sub", "subarray"}
    ),
    "haxe.io.UInt16Array": frozenset(
        {"get", "getData", "get_length", "get_view", "new", "set", "sub", "subarray"}
    ),
    "haxe.io.UInt32Array": frozenset(
        {"get", "getData", "get_length", "get_view", "new", "set", "sub", "subarray"}
    ),
    "haxe.io.UInt8Array": frozenset(
        {"get", "getData", "get_length", "get_view", "new", "set", "sub", "subarray"}
    ),
    "haxe.iterators.ArrayIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.iterators.ArrayKeyValueIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.iterators.DynamicAccessIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.iterators.DynamicAccessKeyValueIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.iterators.MapKeyValueIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.iterators.RestIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.iterators.RestKeyValueIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.iterators.StringIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.iterators.StringIteratorUnicode": frozenset({"hasNext", "new", "next", "unicodeIterator"}),
    "haxe.iterators.StringKeyValueIterator": frozenset({"hasNext", "new", "next"}),
    "haxe.iterators.StringKeyValueIteratorUnicode": frozenset(
        {"hasNext", "new", "next", "unicodeKeyValueIterator"}
    ),
    "haxe.macro.Compiler": frozenset({"load"}),
    "haxe.macro.ExampleJSGenerator": frozenset({"genExpr", "newline", "print"}),
    "haxe.macro.ExprTools": frozenset({"opt", "opt2"}),
    "haxe.macro.TypeTools": frozenset({"followWithAbstracts", "unify"}),
    "haxe.xml.Access": frozenset(
        {
            "get_att",
            "get_elements",
            "get_has",
            "get_hasNode",
            "get_name",
            "get_node",
            "get_nodes",
            "get_x",
            "new",
        }
    ),
    "haxe.xml.Parser": frozenset({"isValidChar"}),
    "haxe.xml.Printer": frozenset({"newline", "write"}),
    "hl.Api": frozenset({"rethrow"}),
    "hl.Bytes": frozenset(
        {
            "fromAddress",
            "fromBytes",
            "getArray",
            "getF32",
            "getF64",
            "getI32",
            "getUI16",
            "getUI8",
            "new",
            "setF32",
            "setF64",
            "setI32",
            "setUI16",
            "setUI8",
            "toBytes",
        }
    ),
    "hl.BytesAccess": frozenset({"blit", "get", "get_nullValue", "get_sizeBits", "set"}),
    "hl.CArray": frozenset({"get", "get_length"}),
    "hl.I64": frozenset({"compl", "implicitToInt", "toInt"}),
    "hl.NativeArray": frozenset({"get", "getRef", "get_length", "new", "set", "sub"}),
    "hl.NativeArray.NativeArrayIterator": frozenset({"hasNext", "new", "next"}),
    "hl.NativeArray.NativeArrayKeyValueIterator": frozenset({"hasNext", "new", "next"}),
    "hl.Ref": frozenset({"get", "make", "new", "offset", "set"}),
    "hl.Type": frozenset({"get", "getDynamic", "getTypeName", "get_kind", "void"}),
    "hl.types.ArrayDyn": frozenset({"get_length"}),
    "hl.types.ArrayObj.ArrayObjIterator": frozenset({"new"}),
    "hl.types.BytesMap": frozenset({"iterator", "new"}),
    "hl.types.Int64Map": frozenset({"iterator", "new"}),
    "hl.types.IntMap": frozenset({"iterator", "new"}),
    "hl.types.ObjectMap": frozenset({"iterator", "new"}),
    "sys.FileSystem": frozenset({"makeCompatiblePath"}),
    "sys.Http": frozenset({"fileTransfert"}),
    "sys.thread.EventLoop": frozenset({"__progress"}),
    "sys.thread.Thread": frozenset(
        {"create", "createWithEventLoop", "readMessage", "runWithEventLoop", "sendMessage"}
    ),
}


def _aliases() -> Dict[str, FrozenSet[str]]:
    """Also key a module's secondary types by `pkg.Name`, as the bytecode names them."""
    table = dict(STD_INLINE_METHODS)
    for path, methods in STD_INLINE_METHODS.items():
        parts = path.split(".")
        if len(parts) >= 2 and parts[-2][:1].isupper():
            alias = ".".join(parts[:-2] + parts[-1:])
            table.setdefault(alias, methods)
    return table


_BY_BYTECODE_NAME = _aliases()


def is_std_inline(class_name: str, method: str) -> bool:
    """Whether std declares `class_name.method` inline, for a class as the bytecode
    names it: abstracts as `pkg._Mod.Name_Impl_`, `@:generic` specializations with
    a `_Type` suffix."""
    candidates = [class_name]
    parts = class_name.split(".")
    if parts[-1].endswith("_Impl_"):
        name = parts[-1][: -len("_Impl_")]
        package = [p for p in parts[:-1] if not p.startswith("_")]
        candidates.append(".".join(package + [name]))
    if "_" in parts[-1]:
        candidates.append(".".join(parts[:-1] + [parts[-1].rsplit("_", 1)[0]]))
    return any(method in _BY_BYTECODE_NAME.get(c, ()) for c in candidates)
