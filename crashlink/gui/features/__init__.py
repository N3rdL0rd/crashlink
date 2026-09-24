"""Optional GUI features (windows, docks, menu actions) built on MainWindow's public API.

Each module exposes `install(mw)`; they're installed in this order at startup."""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import (
    exports,
    file_info,
    globals_window,
    hlasm_edit,
    inlines_window,
    internals,
    lookups,
    strings_window,
)

if TYPE_CHECKING:
    from ..main_window import MainWindow

_FEATURES = (
    strings_window,
    globals_window,
    inlines_window,
    file_info,
    internals,
    exports,
    lookups,
    hlasm_edit,
)


def install_all(mw: "MainWindow") -> None:
    for feature in _FEATURES:
        feature.install(mw)
