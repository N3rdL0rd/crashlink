"""Hover text for rendered pseudocode: what a token names and what an expression produces.

Built purely from the spans `pseudo_spans(..., types=True)` recorded, so a tooltip
never guesses from the spelling of a word. A symbol shows its declaration; any
expression (including a parenthesised group, hovered on its parenthesis) shows the type
it produces and the source it was rendered from.

The text uses the colours of the code panes' syntax highlighting (types teal, methods
pink, identifiers green, ...) in a small font on one line per fact, so a tooltip reads at
a glance instead of wrapping into a narrow column.
"""

from __future__ import annotations

import html
from typing import Optional

from ... import disasm
from ...core import Bytecode, Enum, Fun, Native, Obj
from ...pseudo.doc import RenderedSource
from ...pseudo.symbols import SymbolKind, SymbolRef, SymbolSpan, TypeSpan
from ...pseudo.typetext import describe
from ..themes import Theme
from .ref_info import RefInfo

# Longest source snippet quoted in a tooltip.
_SNIPPET_MAX = 90
# Longest list of fields or parameters spelled out.
_LIST_MAX = 8

# Used when no theme has been applied yet (Catppuccin Mocha, the default theme's palette).
_FALLBACK = {
    "text": "#cdd6f4",
    "muted": "#9399b2",
    "dim": "#6c7086",
    "ident": "#a6e3a1",
    "type": "#94e2d5",
    "method": "#f5c2e7",
    "keyword": "#cba6f7",
    "const": "#fab387",
}


class _Palette:
    """Colours for the parts of a tooltip, taken from the active theme."""

    def __init__(self, theme: Optional[Theme]) -> None:
        if theme is None:
            self.text, self.muted, self.dim = _FALLBACK["text"], _FALLBACK["muted"], _FALLBACK["dim"]
            self.ident, self.type, self.method = _FALLBACK["ident"], _FALLBACK["type"], _FALLBACK["method"]
            self.keyword, self.const = _FALLBACK["keyword"], _FALLBACK["const"]
        else:
            self.text, self.muted, self.dim = theme.text, theme.subtext, theme.overlay
            self.ident, self.type, self.method = theme.green, theme.teal, theme.pink
            self.keyword, self.const = theme.mauve, theme.peach


def _span(text: str, color: str, bold: bool = False) -> str:
    weight = "font-weight:600;" if bold else ""
    return f"<span style='color:{color};{weight}'>{html.escape(text)}</span>"


def _label(p: _Palette, text: str) -> str:
    """The small dim word that says what the colored text after it is."""
    return _span(text, p.dim)


def _page(rows: list[str]) -> str:
    """One row per line, never wrapped, in a smaller font than the code pane's."""
    body = "<br>".join(rows)
    return f"<div style='white-space:nowrap; font-size:9pt;'>{body}</div>"


def _type_row(p: _Palette, span: TypeSpan, label: str = "Type") -> str:
    kind = f" {_span('(' + span.type.kind + ')', p.dim)}" if span.type.kind else ""
    return f"{_label(p, label + ':')} {_span(span.type.source, p.type, bold=True)}{kind}"


def _signature(code: Bytecode, refs: RefInfo, findex: int, p: _Palette) -> list[str]:
    """Rows for a function: its name and `(parameter types) -> return type`."""
    fn = code.get_findex_map().get(findex)
    if fn is None:
        return [f"{_label(p, 'function')} {_span(f'f@{findex}', p.method, bold=True)}"]
    name = refs.function_name(findex) or f"f@{findex}"
    head = (
        f"{_label(p, 'native' if isinstance(fn, Native) else 'function')} {_span(name, p.method, bold=True)}"
    )
    head += f" {_span(f'f@{findex}', p.dim)}"
    rows = [head]
    fun = fn.type.resolve(code).definition
    if isinstance(fun, Fun):
        args = ", ".join(describe(code, a.resolve(code))[0] for a in fun.args)
        ret = describe(code, fun.ret.resolve(code))[0]
        rows.append(f"{_span('(' + args + ')', p.type)} {_span('→', p.dim)} {_span(ret, p.type, bold=True)}")
    return rows


def _field_rows(code: Bytecode, ref: SymbolRef, p: _Palette) -> Optional[list[str]]:
    owner = code.types[ref.index]
    defn = owner.definition
    if not isinstance(defn, Obj):
        return None
    field = defn.fields[ref.slot]
    declared, kind = describe(code, field.type.resolve(code))
    owner_name = disasm.type_to_haxe(disasm.type_name(code, owner))
    return [
        f"{_label(p, 'field')} {_span(owner_name + '.' + field.name.resolve(code), p.ident, bold=True)}",
        f"{_label(p, 'Declared as:')} {_span(declared, p.type, bold=True)} {_span('(' + kind + ')', p.dim)}",
    ]


def _construct_rows(code: Bytecode, ref: SymbolRef, p: _Palette) -> Optional[list[str]]:
    owner = code.types[ref.index]
    defn = owner.definition
    if not isinstance(defn, Enum):
        return None
    construct = defn.constructs[ref.slot]
    params = ", ".join(describe(code, t.resolve(code))[0] for t in construct.params)
    owner_name = disasm.type_to_haxe(disasm.type_name(code, owner))
    rows = [
        f"{_label(p, 'enum constructor')} "
        f"{_span(owner_name + '.' + construct.name.resolve(code), p.keyword, bold=True)}"
    ]
    if params:
        rows.append(f"{_label(p, 'takes')} {_span('(' + params + ')', p.type)}")
    return rows


def _global_rows(code: Bytecode, refs: RefInfo, gindex: int, p: _Palette) -> Optional[list[str]]:
    if not 0 <= gindex < len(code.global_types):
        return None
    declared = describe(code, code.global_types[gindex].resolve(code))[0]
    rows = [
        f"{_label(p, 'global')} {_span(f'g@{gindex}', p.const, bold=True)} "
        f"{_label(p, ':')} {_span(declared, p.type, bold=True)}"
    ]
    value = refs.global_string(gindex)
    if value is not None:
        rows.append(f"{_label(p, '=')} {_span(repr(value[:200]), p.const)}")
    return rows


def _type_rows(code: Bytecode, tindex: int, p: _Palette) -> Optional[list[str]]:
    if not 0 <= tindex < len(code.types):
        return None
    typ = code.types[tindex]
    text, kind = describe(code, typ)
    rows = [
        f"{_label(p, 'type')} {_span(text, p.type, bold=True)} "
        f"{_span('(' + kind + ')', p.dim)} {_span(f't@{tindex}', p.dim)}"
    ]
    if isinstance(typ.definition, Obj):
        try:
            names = [f.name.resolve(code) for f in typ.definition.resolve_fields(code)]
        except (IndexError, ValueError):  # a corrupt or cyclic hierarchy: show the type without its fields
            names = []
        if names:
            shown = ", ".join(names[:_LIST_MAX]) + (" …" if len(names) > _LIST_MAX else "")
            rows.append(f"{_label(p, 'fields:')} {_span(shown, p.ident)}")
    return rows


def _symbol_rows(refs: RefInfo, ref: SymbolRef, p: _Palette) -> Optional[list[str]]:
    code = refs.code
    if ref.kind == SymbolKind.FUNCTION:
        return _signature(code, refs, ref.index, p)
    if ref.kind == SymbolKind.GLOBAL:
        return _global_rows(code, refs, ref.index, p)
    if ref.kind == SymbolKind.TYPE:
        return _type_rows(code, ref.index, p)
    if ref.kind == SymbolKind.FIELD:
        return _field_rows(code, ref, p)
    if ref.kind == SymbolKind.ENUM_CONSTRUCT:
        return _construct_rows(code, ref, p)
    if ref.kind == SymbolKind.LOCAL:
        return [
            f"{_label(p, 'local')} {_span(ref.name, p.ident, bold=True)} {_span(f'in f@{ref.scope}', p.dim)}"
        ]
    return None


def _snippet(rendered: RenderedSource, span: TypeSpan) -> str:
    line = rendered.text.split("\n")[span.line]
    text = line[span.start : span.end]
    return text if len(text) <= _SNIPPET_MAX else text[: _SNIPPET_MAX - 1] + "…"


def hover_html(
    refs: RefInfo, rendered: RenderedSource, line: int, col: int, theme: Optional[Theme] = None
) -> Optional[str]:
    """Tooltip for the character at `col` (a str column) of text line `line`, or None
    when nothing there names a symbol or produces a value."""
    p = _Palette(theme)
    symbol: Optional[SymbolSpan] = rendered.span_at(line, col)
    exprs = rendered.type_spans_at(line, col)

    if symbol is not None:
        rows = _symbol_rows(refs, symbol.ref, p)
        if rows is not None:
            # The expression that is exactly this token tells the type it has here.
            same = next((e for e in exprs if (e.start, e.end) == (symbol.start, symbol.end)), None)
            if same is not None and symbol.ref.kind in (SymbolKind.LOCAL, SymbolKind.FIELD):
                rows.append(_type_row(p, same))
            return _page(rows)

    if not exprs:
        return None
    innermost = exprs[0]
    ch = rendered.text.split("\n")[line][col : col + 1]
    on_paren = ch in ("(", ")") and col in (innermost.start, innermost.end - 1)
    label = "Group" if on_paren else "Expression"
    rows = [
        f"{_label(p, label + ':')} {_span(_snippet(rendered, innermost), p.text)}",
        _type_row(p, innermost),
    ]
    if len(exprs) > 1:
        rows.append(f"{_label(p, 'inside')} {_span(_snippet(rendered, exprs[1]), p.muted)}")
    return _page(rows)
