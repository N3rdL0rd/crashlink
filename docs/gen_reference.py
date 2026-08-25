"""Generates the Markdown API reference under docs/content/reference/ from
crashlink/hlrun/crashtest docstrings, via griffe static analysis.

Griffe parses source with the AST - it never imports the packages - so this
works without any optional dependency (PySide6, mcp, capstone, ...)
installed, unlike the old pdoc3 pipeline.

Run via `just docs` (or `uv run python docs/gen_reference.py` directly from
the repo root).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Iterable

import griffe

OUT_DIR = Path(__file__).parent / "content" / "reference"
PACKAGES = ["crashlink", "hlrun", "crashtest"]


def is_public(name: str) -> bool:
    return name == "__init__" or not name.startswith("_")


def own_submodules(mod: griffe.Module) -> list[griffe.Module]:
    """Direct submodules actually defined in this package - not aliases
    pulled in by `from . import x` or `from .x import *`."""
    return [m for m in mod.members.values() if isinstance(m, griffe.Module) and is_public(m.name)]


def own_classes(mod_or_class: griffe.Module | griffe.Class) -> list[griffe.Class]:
    return [m for m in mod_or_class.members.values() if isinstance(m, griffe.Class) and is_public(m.name)]


def own_functions(mod_or_class: griffe.Module | griffe.Class) -> list[griffe.Function]:
    return [m for m in mod_or_class.members.values() if isinstance(m, griffe.Function) and is_public(m.name)]


def own_attributes(mod_or_class: griffe.Module | griffe.Class) -> list[griffe.Attribute]:
    return [m for m in mod_or_class.members.values() if isinstance(m, griffe.Attribute) and is_public(m.name)]


def fmt_annotation(annotation: object) -> str:
    return str(annotation) if annotation is not None else ""


def fmt_params(params: Iterable[griffe.Parameter]) -> str:
    parts = []
    for p in params:
        if p.name in ("self", "cls"):
            continue
        prefix = {
            griffe.ParameterKind.var_positional: "*",
            griffe.ParameterKind.var_keyword: "**",
        }.get(p.kind, "")
        piece = prefix + p.name
        if p.annotation is not None:
            piece += f": {fmt_annotation(p.annotation)}"
        # *args/**kwargs never have a meaningful "default" - griffe just
        # reports the empty tuple/dict it built them into.
        if p.default is not None and p.kind not in (
            griffe.ParameterKind.var_positional,
            griffe.ParameterKind.var_keyword,
        ):
            piece += f" = {p.default}"
        parts.append(piece)
    return ", ".join(parts)


def fmt_signature(func: griffe.Function) -> str:
    prefix = "async def" if "async" in func.labels else "def"
    sig = f"{prefix} {func.name}({fmt_params(func.parameters)})"
    if func.returns is not None:
        sig += f" -> {fmt_annotation(func.returns)}"
    return sig


def render_function(func: griffe.Function, level: int) -> str:
    heading = "#" * level
    lines = [f"{heading} {func.name}", ""]
    decorators = [d.value for d in func.decorators if d.value not in ("staticmethod", "classmethod")]
    badges = " ".join(f"`{label}`" for label in sorted(func.labels))
    if badges:
        lines.append(badges)
        lines.append("")
    lines.append("```python")
    for d in decorators:
        lines.append(f"@{d}")
    lines.append(fmt_signature(func))
    lines.append("```")
    lines.append("")
    if func.docstring:
        lines.append(func.docstring.value)
        lines.append("")
    return "\n".join(lines)


def render_attribute(attr: griffe.Attribute, level: int) -> str:
    heading = "#" * level
    piece = f"{heading} {attr.name}"
    if attr.annotation is not None:
        piece += f": `{fmt_annotation(attr.annotation)}`"
    lines = [piece, ""]
    if attr.docstring:
        lines.append(attr.docstring.value)
        lines.append("")
    elif attr.value is not None:
        lines.append(f"```python\n{attr.name} = {attr.value}\n```")
        lines.append("")
    return "\n".join(lines)


def render_class(cls: griffe.Class, level: int) -> str:
    heading = "#" * level
    bases = ", ".join(str(b) for b in cls.bases if str(b) != "object")
    title = f"{heading} class {cls.name}"
    if bases:
        title += f"({bases})"
    lines = [title, ""]
    if cls.docstring:
        lines.append(cls.docstring.value)
        lines.append("")
    attrs = own_attributes(cls)
    if attrs:
        for attr in attrs:
            lines.append(render_attribute(attr, level + 1))
    methods = own_functions(cls)
    if methods:
        for method in methods:
            lines.append(render_function(method, level + 1))
    return "\n".join(lines)


def render_module_page(mod: griffe.Module, submodules: list[griffe.Module]) -> str:
    lines = [
        "---",
        f"title: {mod.path}",
        f"sidebar_label: {mod.name}",
        "---",
        "",
        f"# {mod.path}",
        "",
    ]
    if mod.docstring:
        lines.append(mod.docstring.value)
        lines.append("")
    if submodules:
        lines.append("## Submodules")
        lines.append("")
        for sub in sorted(submodules, key=lambda m: m.name):
            summary = (sub.docstring.value.strip().splitlines() or [""])[0] if sub.docstring else ""
            lines.append(f"- [`{mod.path}.{sub.name}`](./{sub.name}) — {summary}")
        lines.append("")
    for cls in sorted(own_classes(mod), key=lambda c: c.name):
        lines.append(render_class(cls, 2))
    for func in sorted(own_functions(mod), key=lambda f: f.name):
        lines.append(render_function(func, 2))
    for attr in sorted(own_attributes(mod), key=lambda a: a.name):
        lines.append(render_attribute(attr, 2))
    return "\n".join(lines)


def write_module(mod: griffe.Module, out_dir: Path) -> None:
    submodules = own_submodules(mod)
    out_dir.mkdir(parents=True, exist_ok=True)
    if submodules:
        # Package: index page + a subdirectory per submodule package, or a
        # sibling file per leaf submodule.
        (out_dir / "index.md").write_text(render_module_page(mod, submodules), encoding="utf-8")
        for sub in submodules:
            if own_submodules(sub):
                write_module(sub, out_dir / sub.name)
            else:
                (out_dir / f"{sub.name}.md").write_text(render_module_page(sub, []), encoding="utf-8")
    else:
        (out_dir / "index.md").write_text(render_module_page(mod, []), encoding="utf-8")


def main() -> None:
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    for pkg_name in PACKAGES:
        pkg = griffe.load(pkg_name)
        assert isinstance(pkg, griffe.Module), f"{pkg_name} resolved to an alias, not a real package"
        write_module(pkg, OUT_DIR / pkg_name)
        (OUT_DIR / pkg_name / "_category_.json").write_text(
            f'{{\n  "label": "{pkg_name}",\n  "collapsed": true\n}}\n', encoding="utf-8"
        )
    print(f"Wrote reference docs to {OUT_DIR}")


if __name__ == "__main__":
    main()
