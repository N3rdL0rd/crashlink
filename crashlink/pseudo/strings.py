"""
Text emission helpers: concatenation flattening, interpolation, indentation, grouping and comments.
"""

from __future__ import annotations

import re
from typing import Optional, List, Tuple, Any
from .annotate import annotate_type
from .doc import strip
from ..core import Bytecode, Function, destaticify
from .. import disasm
from ..decomp import IRFunction, IRExpression, IRLocal, IRConst, IRCall, IRPosInfos
from .naming import _is_std_function


def _indent_str(level: int) -> str:
    return "    " * level  # 4 spaces for indentation


def _grouped(rendered: str, expr: Optional[IRExpression], code: Bytecode) -> str:
    """`(rendered)`; while typing spans, tagged as the expression it groups so that
    hovering a parenthesis shows what the whole group produces."""
    text = f"({rendered})"
    return annotate_type(expr, text, code) if expr is not None else text


def _elided_position(arg: IRExpression, ir_function: Optional[IRFunction], code: Bytecode) -> Optional[str]:
    """`file:line` of an auto-filled position argument that names the enclosing function itself."""
    if not isinstance(arg, IRPosInfos) or ir_function is None or not isinstance(ir_function.func, Function):
        return None
    containing = getattr(ir_function, "_containing_class", None)
    primary = (containing.dynamic or containing.static) if containing is not None else None
    if getattr(ir_function, "_rendered_as_lambda", False) and primary is not None:
        # A lambda is lifted out of the function that wrote it: its position names that
        # function (not the lifted body), of the same class.
        owner = primary.name.resolve(code)
        method = arg.value_of("methodName")
    else:
        owner, _, method = code.full_func_name(ir_function.func).rpartition(".")
    if arg.value_of("className") != destaticify(owner).replace("._", ".").lstrip("$"):
        # The class a private module declares is named `pkg._Module.Name` in the bytecode.
        if arg.value_of("className") != destaticify(owner):
            return None
    if arg.value_of("methodName") != (method if method != "__constructor__" else "new"):
        return None
    file, line = arg.value_of("fileName"), arg.value_of("lineNumber")
    if not isinstance(file, str) or not isinstance(line, int):
        return None
    return f"{file}:{line}"


def _with_comment(rendered: List[str], comment: str) -> List[str]:
    """`rendered` with `comment` after its last element (alone when there are none)."""
    if not comment:
        return rendered
    if not rendered:
        return [comment]
    return [*rendered[:-1], f"{rendered[-1]} {comment}"]


def _flatten_string_concat(expr: IRExpression, code: Bytecode) -> Optional[List[IRExpression]]:
    """Flatten a nested chain of String.__add__ calls into an ordered operand list.

    `(((a + b) + c) + d)` is stored as nested two-arg __add__ calls; return
    `[a, b, c, d]`. Returns None if `expr` is not a String.__add__ call.
    """
    if not (
        isinstance(expr, IRCall)
        and isinstance(expr.target, IRConst)
        and isinstance(expr.target.value, Function)
        and _is_std_function(expr.target.value, code)
        and code.partial_func_name(expr.target.value) == "__add__"
        and len(expr.args) == 2
    ):
        return None
    operands: List[IRExpression] = []
    left, right = expr.args[0], expr.args[1]
    left_flat = _flatten_string_concat(left, code)
    if left_flat is not None:
        operands.extend(left_flat)
    else:
        operands.append(left)
    right_flat = _flatten_string_concat(right, code)
    if right_flat is not None:
        operands.extend(right_flat)
    else:
        operands.append(right)
    return operands


_INTERP_SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _render_interpolated(parts: List[Tuple[str, Any]]) -> str:
    """Build a single-quoted Haxe interpolation string from classified parts."""
    out = ["'"]
    for index, (kind, payload) in enumerate(parts):
        if kind == "lit":
            text = payload
            # Escape for single-quoted interpolation context: control
            # characters first (so a raw newline can't split the literal
            # and expose a `/`-heavy remainder as a real `//` comment on
            # the next line), then Haxe's `$$` doubling for literal `$`.
            text = disasm._escape_str(text, "'").replace("$", "$$")
            out.append(text)
        else:
            operand, simple = payload
            # `$name` swallows any identifier characters that follow it, so a
            # literal continuing with one forces the braced form.
            following = parts[index + 1] if index + 1 < len(parts) else None
            merges = (
                following is not None
                and following[0] == "lit"
                and bool(following[1])
                and (following[1][0].isalnum() or following[1][0] == "_")
            )
            if isinstance(operand, IRLocal) and _INTERP_SAFE_IDENT.match(strip(simple)) and not merges:
                out.append(f"${simple}")
            else:
                out.append("${" + simple + "}")
    out.append("'")
    return "".join(out)
