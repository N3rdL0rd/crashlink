"""Hover text for rendered pseudocode: what a token names and what an expression produces.

Built purely from the spans `pseudo_spans(..., types=True)` recorded, so a tooltip
never guesses from the spelling of a word. A symbol shows its declaration; any
expression (including a parenthesised group, hovered on its parenthesis) shows the type
it produces and the source it was rendered from.
"""

from __future__ import annotations

import html
from typing import Optional

from ... import disasm
from ...core import Bytecode, Enum, Obj
from ...pseudo.doc import RenderedSource
from ...pseudo.symbols import SymbolKind, SymbolRef, SymbolSpan, TypeSpan
from ...pseudo.typetext import describe
from .ref_info import RefInfo

_MUTED = "opacity:0.7"
# Longest source snippet quoted in a tooltip.
_SNIPPET_MAX = 90


def _code(text: str) -> str:
    return f"<code>{html.escape(text)}</code>"


def _muted(text: str) -> str:
    return f"<span style='{_MUTED}'>{html.escape(text)}</span>"


def _type_line(span: TypeSpan) -> str:
    kind = f" {_muted('(' + span.type.kind + ')')}" if span.type.kind else ""
    return f"<b>Type:</b> {_code(span.type.source)}{kind}"


def _symbol_html(refs: RefInfo, ref: SymbolRef) -> Optional[str]:
    code = refs.code
    if ref.kind == SymbolKind.FUNCTION:
        return refs.function_tooltip(ref.index)
    if ref.kind == SymbolKind.GLOBAL:
        return refs.global_tooltip(ref.index)
    if ref.kind == SymbolKind.TYPE:
        return refs.type_tooltip(ref.index)
    if ref.kind == SymbolKind.FIELD:
        return _field_html(code, ref)
    if ref.kind == SymbolKind.ENUM_CONSTRUCT:
        return _construct_html(code, ref)
    if ref.kind == SymbolKind.LOCAL:
        return f"<b>local</b> {_code(ref.name)}<br>{_muted(f'in f@{ref.scope}')}"
    return None


def _field_html(code: Bytecode, ref: SymbolRef) -> Optional[str]:
    owner = code.types[ref.index]
    defn = owner.definition
    if not isinstance(defn, Obj):
        return None
    field = defn.fields[ref.slot]
    declared, kind = describe(code, field.type.resolve(code))
    owner_name = disasm.type_to_haxe(disasm.type_name(code, owner))
    return (
        f"<b>field</b> {_code(owner_name + '.' + field.name.resolve(code))}<br>"
        f"<b>Declared as:</b> {_code(declared)} {_muted('(' + kind + ')')}"
    )


def _construct_html(code: Bytecode, ref: SymbolRef) -> Optional[str]:
    owner = code.types[ref.index]
    defn = owner.definition
    if not isinstance(defn, Enum):
        return None
    construct = defn.constructs[ref.slot]
    params = ", ".join(describe(code, p.resolve(code))[0] for p in construct.params)
    owner_name = disasm.type_to_haxe(disasm.type_name(code, owner))
    name = f"{owner_name}.{construct.name.resolve(code)}"
    return f"<b>enum constructor</b> {_code(name + ('(' + params + ')' if params else ''))}"


def _snippet(rendered: RenderedSource, span: TypeSpan) -> str:
    line = rendered.text.split("\n")[span.line]
    text = line[span.start : span.end]
    return text if len(text) <= _SNIPPET_MAX else text[: _SNIPPET_MAX - 1] + "…"


def hover_html(refs: RefInfo, rendered: RenderedSource, line: int, col: int) -> Optional[str]:
    """Tooltip for the character at `col` (a str column) of text line `line`, or None
    when nothing there names a symbol or produces a value."""
    symbol: Optional[SymbolSpan] = rendered.span_at(line, col)
    exprs = rendered.type_spans_at(line, col)
    parts = []

    if symbol is not None:
        body = _symbol_html(refs, symbol.ref)
        if body is not None:
            parts.append(body)
            # The expression that is exactly this token tells the type it has here.
            same = next((e for e in exprs if (e.start, e.end) == (symbol.start, symbol.end)), None)
            if same is not None and symbol.ref.kind in (SymbolKind.LOCAL, SymbolKind.FIELD):
                parts.append(_type_line(same))
            return "<br>".join(parts)

    if not exprs:
        return None
    innermost = exprs[0]
    ch = rendered.text.split("\n")[line][col : col + 1]
    on_paren = ch in ("(", ")") and col in (innermost.start, innermost.end - 1)
    label = "Group" if on_paren else "Expression"
    parts.append(f"<b>{label}:</b> {_code(_snippet(rendered, innermost))}")
    parts.append(_type_line(innermost))
    if len(exprs) > 1:
        outer = exprs[1]
        parts.append(_muted(f"inside {_snippet(rendered, outer)}"))
    return "<br>".join(parts)
