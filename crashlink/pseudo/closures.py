"""
Closure and capture analysis: lambda detection, context hoisting and adapter helpers.
"""

from __future__ import annotations

import re
from typing import Optional, List, Dict, Tuple, cast, Iterator
from .doc import OPEN, CLOSE, strip
from ..core import Bytecode, Function, Fun, Enum
from .. import disasm
from ..decomp import (
    IRCast,
    IRBoundClosure,
    IRFunction,
    IRBlock,
    IRStatement,
    IRExpression,
    IRAssign,
    IRLocal,
    IRConst,
    IRBoolExpr,
    IRCall,
    IRConditional,
    IRRefGet,
    IREnumConstruct,
    IREnumField,
    IRReturn,
)


_LAMBDA_START = re.compile(r"\([^()]*\) -> ")


def _is_lambda_text(rendered: str) -> bool:
    """A rendered `(args) -> body`, whose body would swallow a following operator."""
    return _LAMBDA_START.match(strip(rendered)) is not None


_LAMBDA_START = re.compile(r"(\([^()]*\)|\w+) -> ")


def _paren_lambda(rendered: str) -> str:
    """A lambda written as an operand or callee extends as far right as it can: parenthesise it."""
    return f"({rendered})" if _LAMBDA_START.match(strip(rendered)) else rendered


def _inline_closure(
    expr: "IRBoundClosure",
    obj_str: str,
    extra_arg_count: int,
    code: Bytecode,
    ir_function: Optional[IRFunction],
) -> Optional[str]:
    """Render a captured closure as the lambda it came from.

    Only a body that is one expression qualifies: `() -> Sys.println(x)` reads
    better than a lifted helper plus `.bind`, while a multi-statement body in
    expression position would fight the line-based renderer. The capture must
    also reach the lambda under its own name, so that the closure keeps
    referring to the same environment instead of a copy.
    """
    if ir_function is None:
        return None
    helpers = getattr(ir_function, "_inline_closure_bodies", None)
    if not helpers:
        return None
    entry = helpers.get(expr.fun.findex.value)
    if entry is None:
        return None
    params, body = entry
    # The environment reaches the lambda by closing over the very same local;
    # any other binding expression would capture a copy.
    if not params or len(params) - 1 != extra_arg_count:
        return None
    if strip(params[0]) != strip(obj_str):
        # The captured local is named differently here than in the closure (a shadowing
        # `var r` became `r1`): the lambda closes over the same local under its new name.
        old = strip(params[0])
        obj_name = strip(obj_str)
        if (
            not (old.isidentifier() and obj_name.isidentifier())
            or obj_name == "this"
            or old in [strip(p) for p in params[1:]]
            or obj_name in [strip(p) for p in params]
            or re.search(rf"\b{re.escape(obj_name)}\b|\bvar\s+{re.escape(old)}\b", strip(body))
        ):
            return None
        body = _plain_sub(re.compile(rf"(?<![\w.]){re.escape(old)}\b"), obj_str, body)
    getattr(ir_function, "_inlined_closures", set()).add(expr.fun.findex.value)
    return f"({', '.join(params[1:])}) -> {body}"


_CTX_MARK = "\x00"


def _written_after(expr: "IRBoundClosure", ir_function: Optional[IRFunction]) -> bool:
    """Whether the local `expr` binds is assigned after `expr` in the function."""
    if ir_function is None or not isinstance(expr.obj, IRLocal):
        return False
    seen = False
    for node in _walk_ir(ir_function.block):
        if node is expr:
            seen = True
        elif seen and isinstance(node, IRAssign) and isinstance(node.target, IRLocal):
            if node.target.name == expr.obj.name:
                return True
    return False


def _walk_ir(node: Optional[IRStatement]) -> Iterator[IRStatement]:
    if node is None:
        return
    yield node
    if isinstance(node, IRBlock):
        for stmt in node.statements:
            yield from _walk_ir(stmt)
    else:
        for child in node.get_children():
            yield from _walk_ir(child)


_CTX_REF = re.compile(_CTX_MARK + r"(\d+)" + _CTX_MARK)


def _is_capture_variable(value: IRExpression, ir_func: IRFunction) -> bool:
    """Whether a capture-context argument is a variable the source named: a local, or a read of
    the enclosing closure's own context (a variable it captured itself). A constant or any other
    computation is not captured by a lambda: it comes from a `.bind` argument instead."""
    if isinstance(value, IRLocal):
        return True
    ctx_param = getattr(ir_func, "_ctx_param_name", None)
    return (
        isinstance(value, IREnumField)
        and isinstance(value.value, IRLocal)
        and value.value.name == ctx_param
        and value.field_name.startswith("param")
    )


def _captures_stable(ir_func: IRFunction, block: IRBlock, idx: int, captured: List[IRExpression]) -> bool:
    """Whether every write to a captured variable runs before `block.statements[idx]` on every path to it."""

    def ancestry(node: IRBlock) -> Optional[List[Tuple[IRBlock, int]]]:
        if node is block:
            return [(node, idx)]
        for child_idx, child in enumerate(node.statements):
            for sub in [child] if isinstance(child, IRBlock) else child.get_children():
                if isinstance(sub, IRBlock):
                    found = ancestry(sub)
                    if found is not None:
                        return [(node, child_idx), *found]
        return None

    path = ancestry(ir_func.block)
    if path is None:
        return False
    settled = {id(s) for owner, at in path for s in owner.statements[:at]}
    variables = [c for c in captured if isinstance(c, IRLocal)]
    for node in _walk_ir(ir_func.block):
        if isinstance(node, IRAssign) and isinstance(node.target, IRLocal) and node.target in variables:
            if id(node) not in settled:
                return False
    return True


def _parameters_shadow(params: List[str], captured: List[IRExpression]) -> bool:
    """Whether a lambda's own parameter has the name of a captured variable. The body names both
    the same way, so the two can no longer be told apart."""
    # A capture can be a read of a local (the enclosing closure's own context) as well as a local.
    names = {n.name for c in captured for n in _walk_ir(c) if isinstance(n, IRLocal)}
    return bool(names & {p.lstrip("?").split(" = ")[0].split(":")[0].strip() for p in params[1:]})


def _unshadow_captures(body: str, captured: List[str]) -> str:
    """Rename what a lambda body declares (locals, loop and catch variables) when the name is also
    used by a captured expression: inside the lambda the declaration would hide the captured
    variable it was meant to read."""
    declared = {m for m in re.findall(r"\bvar (\w+)", strip(body))}
    declared.update(
        m for pair in re.findall(r"\bfor \((\w+)(?: => (\w+))? in", strip(body)) for m in pair if m
    )
    declared.update(re.findall(r"\bcatch \((\w+)", strip(body)))
    used = {w for text in captured for w in re.findall(r"[A-Za-z_]\w*", strip(text))}
    taken = used | set(re.findall(r"[A-Za-z_]\w*", strip(body))) | declared
    for name in sorted(declared & used):
        fresh, n = f"{name}_", 1
        while fresh in taken:
            n += 1
            fresh = f"{name}_{n}"
        taken.add(fresh)
        pattern = re.compile(rf"(?<![\w.]){re.escape(name)}(?!\w)")
        body = disasm.outside_literals(body, lambda chunk: _plain_sub(pattern, fresh, chunk))
    return body


def _capture_context_in_place(ir_func: IRFunction, ctx_bodies: Dict[int, Tuple[List[str], str]]) -> None:
    """The same as `_hoist_closure_contexts` for a context the optimizer already folded into the
    closure that is bound to it."""
    for block in [n for n in _walk_ir(ir_func.block) if isinstance(n, IRBlock)]:
        for idx, stmt in enumerate(block.statements):
            for node in _walk_ir(stmt):
                if not (
                    isinstance(node, IRBoundClosure)
                    and node.captures is None
                    and node.fun.findex.value in ctx_bodies
                    and isinstance(node.obj, IREnumConstruct)
                    and isinstance(node.obj.get_type().definition, Enum)
                    and cast(Enum, node.obj.get_type().definition).name.value == 0
                    and all(_is_capture_variable(a, ir_func) for a in node.obj.args)
                ):
                    continue
                captured = node.obj.args
                params, body = ctx_bodies[node.fun.findex.value]
                if any(int(m) >= len(captured) for m in re.findall(_CTX_MARK + r"(\d+)" + _CTX_MARK, body)):
                    continue
                if _parameters_shadow(params, captured):
                    continue
                if _captures_stable(ir_func, block, idx, captured):
                    node.captures = list(captured)


def _hoist_closure_contexts(ir_func: IRFunction, ctx_bodies: Dict[int, Tuple[List[str], str]]) -> None:
    """Bind closures to the values their capture context holds, and drop the context.

    The compiler builds the context from the captured variables right before the closures that
    share it; the source only named the variables, so the closures are rendered as lambdas
    over them (`IRBoundClosure.captures`) and the context's construction disappears."""
    if not ctx_bodies:
        return
    _capture_context_in_place(ir_func, ctx_bodies)
    progress = True
    while progress:
        progress = False
        for block in [n for n in _walk_ir(ir_func.block) if isinstance(n, IRBlock)]:
            for idx, stmt in enumerate(block.statements):
                if not (
                    isinstance(stmt, IRAssign)
                    and isinstance(stmt.target, IRLocal)
                    and isinstance(stmt.expr, IREnumConstruct)
                    and isinstance(stmt.expr.get_type().definition, Enum)
                    and cast(Enum, stmt.expr.get_type().definition).name.value == 0
                    and all(_is_capture_variable(a, ir_func) for a in stmt.expr.args)
                ):
                    continue
                if _hoist_one_context(ir_func, block, idx, ctx_bodies):
                    progress = True
                    break
            if progress:
                break


def _hoist_one_context(
    ir_func: IRFunction, block: IRBlock, idx: int, ctx_bodies: Dict[int, Tuple[List[str], str]]
) -> bool:
    stmt = cast(IRAssign, block.statements[idx])
    ctx = cast(IRLocal, stmt.target)
    captured = cast(IREnumConstruct, stmt.expr).args
    closures: List[IRBoundClosure] = []
    last_use = -1
    for j, later in enumerate(block.statements):
        if later is stmt:
            continue
        for node in _walk_ir(later):
            if isinstance(node, IRBoundClosure) and node.obj == ctx:
                closures.append(node)
                last_use = max(last_use, j)
    others = 0

    def count(node: Optional[IRStatement]) -> None:
        nonlocal others
        if node is None or node is stmt:
            return
        if isinstance(node, IRBoundClosure) and node.obj == ctx:
            count(node.fun_const)
            return
        if isinstance(node, IRLocal) and node == ctx:
            others += 1
        if isinstance(node, IRBlock):
            for s in node.statements:
                count(s)
        else:
            for child in node.get_children():
                count(child)

    count(ir_func.block)
    if others or not closures:
        return False
    # Every closure must come after the context, in the same block, with the captured
    # variables unchanged in between.
    seen = sum(1 for n in _walk_ir(ir_func.block) if isinstance(n, IRBoundClosure) and n.obj == ctx)
    if seen != len(closures) or any(
        isinstance(n, IRBoundClosure) and n.obj == ctx
        for s in block.statements[: idx + 1]
        for n in _walk_ir(s)
    ):
        return False

    # The context holds the values as they were when it was built; a lambda reads its variables
    # when it runs. They agree only if each captured variable is written (at most) by a statement
    # that runs before the context on every path to it.
    if not _captures_stable(ir_func, block, idx, captured):
        return False
    for closure in closures:
        entry = ctx_bodies.get(closure.fun.findex.value)
        if entry is None:
            return False
        params, body = entry
        if any(int(m) >= len(captured) for m in re.findall(_CTX_MARK + r"(\d+)" + _CTX_MARK, body)):
            return False
        if _parameters_shadow(params, captured):
            return False
    for closure in closures:
        closure.captures = list(captured)
    del block.statements[idx]
    return True


def _void_return_adapter(helper_ir: IRFunction) -> bool:
    """Whether a helper only calls its first parameter with the others and returns nothing (null).

    Passing a function that returns Void where one returning Dynamic is expected wraps it in such
    a helper (`Reflect.makeVarArgs(f)` with `f:Array<Dynamic>->Void`); source wrote the function."""
    signature = helper_ir.func.type.resolve(helper_ir.code).definition
    if not isinstance(signature, Fun) or not signature.args:
        return False
    statements = list(helper_ir.block.statements)
    if (
        statements
        and isinstance(statements[-1], IRReturn)
        and (
            statements[-1].value is None
            or (
                isinstance(statements[-1].value, IRConst)
                and statements[-1].value.const_type == IRConst.ConstType.NULL
            )
        )
    ):
        statements.pop()
    if len(statements) != 1 or not isinstance(statements[0], IRCall):
        return False
    call = statements[0]
    names = [local.name for local in helper_ir.locals[: len(signature.args)]]
    return (
        len(names) == len(signature.args)
        and isinstance(call.target, IRLocal)
        and call.target.name == names[0]
        and [a.name if isinstance(a, IRLocal) else None for a in call.args] == names[1:]
    )


def _optional_ref_adapter(helper_ir: IRFunction) -> Optional[List[bool]]:
    """Whether a helper only passes its optional arguments on to the function it is bound to.

    HashLink passes an optional argument of a basic type through a function type as an
    `hl.Ref`, so assigning a function value to such a type wraps it in a helper that
    unboxes each reference (`r != null ? r.get() : null`) and calls the function with the
    values. Source wrote a function with optional parameters; returns, per forwarded parameter,
    whether it is one of those."""
    statements = list(helper_ir.block.statements)
    call: Optional[IRCall] = None
    if statements and isinstance(statements[-1], IRReturn):
        last = cast(IRReturn, statements.pop())
        if isinstance(last.value, IRCall):
            call = last.value
        elif last.value is not None:
            return None  # it also converts the return value: more than an argument adapter
    if call is None:
        if not statements or not isinstance(statements[-1], IRCall):
            return None
        call = cast(IRCall, statements.pop())
    names = [local.name for local in helper_ir.locals]
    signature = helper_ir.func.type.resolve(helper_ir.code).definition
    if not isinstance(signature, Fun) or not isinstance(call.target, IRLocal):
        return None
    params = names[: len(signature.args)]
    if len(params) < 2 or call.target.name != params[0]:
        return None
    unboxed: Dict[str, str] = {}  # temporary -> the reference parameter it reads
    for stmt in statements:
        if not (
            isinstance(stmt, IRConditional)
            and isinstance(stmt.condition, IRBoolExpr)
            and stmt.condition.op == IRBoolExpr.CompareType.NOT_NULL
            and isinstance(stmt.condition.left, IRLocal)
            and len(stmt.true_block.statements) == 1
            and len(stmt.false_block.statements) == 1
        ):
            return None
        read, null = stmt.true_block.statements[0], stmt.false_block.statements[0]
        if not (isinstance(read, IRAssign) and isinstance(null, IRAssign) and read.target == null.target):
            return None
        value = read.expr.expr if isinstance(read.expr, IRCast) else read.expr
        if not (
            isinstance(value, IRRefGet)
            and value.ref == stmt.condition.left
            and isinstance(null.expr, IRConst)
            and null.expr.const_type == IRConst.ConstType.NULL
            and isinstance(read.target, IRLocal)
        ):
            return None
        unboxed[read.target.name] = stmt.condition.left.name
    forwarded = []
    for arg in call.args:
        if not isinstance(arg, IRLocal):
            return None
        forwarded.append(unboxed.get(arg.name, arg.name))
    if forwarded != params[1:]:
        return None
    return [name in unboxed.values() for name in params[1:]]


class _FunctionHeader:
    def __init__(self, params: str, returns: Optional[str]) -> None:
        self.params, self.returns = params, returns

    def group(self, index: int) -> str:
        return self.params if index == 1 else self.returns or ""


def _function_header(line: str) -> Optional[_FunctionHeader]:
    """The parameter list and return type of a rendered `function name(params): ret {` line. The
    return type may itself contain braces (an anonymous structure)."""
    # The name may carry a span mark; the mark chars surround it without changing the text.
    opening = re.search(rf"function (?:{OPEN}.)?[\w$]+(?:{CLOSE})?\(", line)
    if opening is None or not line.rstrip().endswith("{"):
        return None
    depth, at = 1, opening.end()
    while at < len(line) and depth:
        depth += {"(": 1, ")": -1}.get(line[at], 0)
        at += 1
    if depth:
        return None
    rest = line[at:].rstrip()[:-1].rstrip()
    if rest and not rest.startswith(":"):
        return None
    return _FunctionHeader(line[opening.end() : at - 1], rest[1:].strip() if rest else None)


def _split_params(text: str) -> List[str]:
    """The top-level comma-separated parts of a parameter list (types may contain commas and arrows)."""
    parts, depth, current = [], 0, ""
    for i, ch in enumerate(text):
        if ch in "(<[{":
            depth += 1
        elif ch in ")]}" or (ch == ">" and text[i - 1 : i] != "-"):
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current)
    return parts


_SPAN_MARKER = re.compile(f"{OPEN}.|{CLOSE}", re.DOTALL)


def _unwrap_span(text: str) -> str:
    """`text` without outer whole-text marker layers (a type span wraps the whole rendering).

    Inner marks survive, so prefix/suffix checks and slices see the same text as the plain
    rendering without dropping the spans inside."""
    while text.startswith(OPEN) and text.endswith(CLOSE) and len(text) >= 3:
        depth, i = 0, 0
        while i < len(text):
            ch = text[i]
            if ch == OPEN:
                depth += 1
                i += 2
                continue
            if ch == CLOSE:
                depth -= 1
                if depth == 0:
                    break
                i += 1
                continue
            i += 1
        if depth == 0 and i == len(text) - 1:
            text = text[2:-1]
        else:
            return text
    return text


def _plain_sub(pattern: "re.Pattern[str]", repl: str, text: str) -> str:
    """`pattern.sub(repl, text)`, with matches found in the marker-free text.

    A span marker must neither fake a match's context (a `.` before a marked token still
    defeats `(?<![\\w.])`) nor break one, and markers outside the matches survive."""
    plain = strip(text)
    if plain == text:
        return pattern.sub(repl, text)
    index: List[int] = []
    pos = 0
    for m in _SPAN_MARKER.finditer(text):
        index.extend(range(pos, m.start()))
        pos = m.end()
    index.extend(range(pos, len(text)))

    def orig(p: int) -> int:
        return index[p] if p < len(index) else len(text)

    out: List[str] = []
    last = 0
    for m in pattern.finditer(plain):
        out.append(text[orig(last) : orig(m.start())])
        out.append(m.expand(repl))
        last = m.end()
    out.append(text[orig(last) :])
    return "".join(out)


def _closure_adapter(
    expr: "IRBoundClosure", obj_str: str, code: Bytecode, ir_function: Optional[IRFunction]
) -> Optional[str]:
    """The captured function itself, when the bound helper only forwards to it.

    Haxe converts a function value to a function type that differs only in a
    return (or Dynamic argument) type by wrapping it in a helper that calls the
    original with the same arguments. The source wrote the function value; Haxe
    adapts it again when the result is recompiled.
    """
    optional = getattr(ir_function, "_optional_adapters", {}).get(expr.fun.findex.value)
    if optional is not None:
        getattr(ir_function, "_inlined_closures", set()).add(expr.fun.findex.value)
        names = [f"a{i}" for i in range(len(optional))]
        params = ", ".join(f"?{n}" if flag else n for n, flag in zip(names, optional))
        callee = f"({obj_str})" if _is_lambda_text(obj_str) else obj_str
        return f"({params}) -> {callee}({', '.join(names)})"
    if expr.fun.findex.value in getattr(ir_function, "_return_adapters", ()):
        getattr(ir_function, "_inlined_closures", set()).add(expr.fun.findex.value)
        return obj_str
    helpers = getattr(ir_function, "_inline_closure_bodies", None)
    entry = helpers.get(expr.fun.findex.value) if helpers else None
    if entry is None:
        return None
    params, body = entry
    if not params:
        return None
    captured = expr.obj.get_type().definition
    helper_type = expr.fun.type.resolve(code).definition
    if (
        isinstance(captured, Fun)
        and isinstance(helper_type, Fun)
        and [disasm.type_name(code, a.resolve(code)) for a in captured.args]
        == [disasm.type_name(code, a.resolve(code)) for a in helper_type.args[1:]]
        and disasm.type_name(code, captured.ret.resolve(code))
        == disasm.type_name(code, helper_type.ret.resolve(code))
    ):
        return None  # nothing is converted: the source wrote the lambda that calls it
    # A Dynamic argument handed on as a basic type is converted by the adapter itself.
    forwarded = ", ".join(
        rf"(?:{re.escape(strip(p))}|cast\({re.escape(strip(p))}, (?:Int|Float|Bool)\))" for p in params[1:]
    )
    if not re.fullmatch(re.escape(strip(params[0])) + r"\(" + forwarded + r"\)", strip(body)):
        return None
    getattr(ir_function, "_inlined_closures", set()).add(expr.fun.findex.value)
    return obj_str


def _inline_anonymous(func: "Function", code: Bytecode, ir_function: Optional[IRFunction]) -> Optional[str]:
    """Render a reference to a capture-free anonymous function as a lambda."""
    if ir_function is None or getattr(ir_function, "_bind_head", False):
        return None
    helpers = getattr(ir_function, "_inline_closure_bodies", None)
    if not helpers:
        return None
    entry = helpers.get(func.findex.value)
    if entry is None:
        return None
    params, body = entry
    getattr(ir_function, "_inlined_closures", set()).add(func.findex.value)
    return f"({', '.join(params)}) -> {body}"
