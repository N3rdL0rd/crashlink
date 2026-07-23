"""
Plugin optimizers: custom IR passes that apply only to certain codebases.

The built-in decompiler pipeline is fixed and general. Real games, though, have
their own compiler macros and idioms — a logging macro that inlines source
position info, a custom assert, an entity-system boilerplate — that decompile
correctly but verbosely, and that only make sense to clean up for *that* game.

This module lets you register extra optimizers that the decompiler appends to its
pipeline, gated by when they should apply:

  * `sha=` — only for a bytecode whose SHA-256 matches (so a plugin written for
    one game's `hlboot.dat` auto-applies to exactly that image and no other);
  * `when=` — a custom predicate over the Bytecode (e.g. "has a function named
    tool.log.LogUtils.logInformation"), for codebase-wide rather than exact-image
    matching;
  * neither — always applies.

Plugins are plain Python files. They're auto-discovered from, in order:
  * every dir on `$CRASHLINK_PLUGINS` (os.pathsep-separated),
  * `~/.crashlink/plugins/`,
  * `./.crashlink/plugins/` (project-local).
Each file registers optimizers at import time via `@optimizer(...)` /
`register_optimizer(...)`. A broken plugin logs and is skipped, never crashing a
decompile.

Example (`~/.crashlink/plugins/deadcells.py`):

    from crashlink.plugins import optimizer
    from crashlink.decomp import TraversingIROptimizer

    @optimizer(sha="7d1f…the image's sha…")
    class StripLogPositions(TraversingIROptimizer):
        def visit_expression(self, expr): ...
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Set, Type, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import Bytecode
    from .decomp.opt import IROptimizer

Predicate = Callable[["Bytecode"], bool]


@dataclass
class PluginEntry:
    optimizer_cls: Type["IROptimizer"]
    predicate: Predicate
    position: str  # "start" (before built-ins) or "end" (after built-ins)
    name: str


_registry: List[PluginEntry] = []
_loaded_dirs: Set[str] = set()


def bytecode_sha(code: "Bytecode") -> Optional[str]:
    """SHA-256 of the loaded image, or None if it wasn't loaded from bytes/path."""
    return getattr(code, "sha256", None)


def _make_predicate(sha: Optional[Union[str, Sequence[str]]], when: Optional[Predicate]) -> Predicate:
    preds: List[Predicate] = []
    if sha is not None:
        shas = {sha.lower()} if isinstance(sha, str) else {s.lower() for s in sha}
        preds.append(lambda code: (bytecode_sha(code) or "").lower() in shas)
    if when is not None:
        preds.append(when)
    if not preds:
        return lambda code: True
    return lambda code: all(p(code) for p in preds)


def register_optimizer(
    optimizer_cls: Type["IROptimizer"],
    *,
    sha: Optional[Union[str, Sequence[str]]] = None,
    when: Optional[Predicate] = None,
    position: str = "end",
    name: Optional[str] = None,
) -> Type["IROptimizer"]:
    """Register a plugin optimizer. Returns the class (usable as a decorator too).

    `sha` and `when` gate when it applies (both → must satisfy both). `position`
    is "end" (after the built-in pipeline, the usual choice for cleanup passes) or
    "start" (before it, for passes that must see the raw lowering)."""
    if position not in ("start", "end"):
        raise ValueError(f"position must be 'start' or 'end', got {position!r}")
    _registry.append(
        PluginEntry(optimizer_cls, _make_predicate(sha, when), position, name or optimizer_cls.__name__)
    )
    return optimizer_cls


def optimizer(
    *,
    sha: Optional[Union[str, Sequence[str]]] = None,
    when: Optional[Predicate] = None,
    position: str = "end",
    name: Optional[str] = None,
) -> Callable[[Type["IROptimizer"]], Type["IROptimizer"]]:
    """Decorator form of `register_optimizer`."""

    def deco(cls: Type["IROptimizer"]) -> Type["IROptimizer"]:
        register_optimizer(cls, sha=sha, when=when, position=position, name=name)
        return cls

    return deco


def registered() -> List[PluginEntry]:
    """All registered plugin entries (after ensuring discovery has run)."""
    ensure_loaded()
    return list(_registry)


def clear() -> None:
    """Drop all registered plugins and reset discovery (mainly for tests)."""
    _registry.clear()
    _loaded_dirs.clear()


def optimizers_for(code: "Bytecode", position: str) -> List[Type["IROptimizer"]]:
    """Optimizer classes that apply to `code` at the given pipeline position."""
    ensure_loaded()
    return [e.optimizer_cls for e in _registry if e.position == position and e.predicate(code)]


# --- discovery -------------------------------------------------------------


def plugin_dirs() -> List[str]:
    dirs: List[str] = []
    env = os.environ.get("CRASHLINK_PLUGINS")
    if env:
        dirs.extend(d for d in env.split(os.pathsep) if d)
    dirs.append(os.path.join(os.path.expanduser("~"), ".crashlink", "plugins"))
    dirs.append(os.path.join(os.getcwd(), ".crashlink", "plugins"))
    return dirs


def ensure_loaded() -> None:
    """Import plugin files from the discovery dirs once. Idempotent."""
    for d in plugin_dirs():
        if d in _loaded_dirs:
            continue
        _loaded_dirs.add(d)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".py") and not fn.startswith("_"):
                _load_file(os.path.join(d, fn))


def load_file(path: str) -> None:
    """Explicitly import a single plugin file (bypassing discovery)."""
    _load_file(path)


def _load_file(path: str) -> None:
    mod_name = "crashlink_plugin_" + os.path.splitext(os.path.basename(path))[0]
    try:
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            return
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
    except Exception as e:  # a broken plugin must never crash a decompile
        from .globals import dbg_print

        dbg_print(f"[plugins] failed to load {path}: {e}")
