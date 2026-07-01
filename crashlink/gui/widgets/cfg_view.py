"""Embedded control-flow-graph viewer, rendered via Graphviz when available.

Both the `graphviz` Python package and the `dot` executable it shells out to are
optional — if either is missing we show a clear message instead of crashing.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QWheelEvent
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtSvgWidgets import QGraphicsSvgItem
from PySide6.QtWidgets import QGraphicsScene, QGraphicsView, QLabel, QStackedWidget, QVBoxLayout, QWidget

from ..themes import Theme

try:
    import graphviz

    GRAPHVIZ_IMPORT_ERROR: Optional[str] = None
except ImportError as e:
    graphviz = None  # type: ignore[assignment]
    GRAPHVIZ_IMPORT_ERROR = str(e)

_PAGE_MESSAGE = 0
_PAGE_GRAPH = 1


class _GraphView(QGraphicsView):
    """A QGraphicsView with mouse-wheel zoom and click-drag panning."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)

    def wheelEvent(self, event: QWheelEvent) -> None:  # type: ignore[override]
        factor = 1.25 if event.angleDelta().y() > 0 else 1 / 1.25
        self.scale(factor, factor)


class CfgView(QWidget):
    """Renders a function's control-flow graph as a zoomable/pannable SVG."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._theme: Optional[Theme] = None
        self._svg_renderer: Optional[QSvgRenderer] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._stack = QStackedWidget()
        layout.addWidget(self._stack)

        self._message = QLabel()
        self._message.setObjectName("cfgMessage")
        self._message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._message.setWordWrap(True)
        self._message.setContentsMargins(16, 16, 16, 16)
        self._stack.addWidget(self._message)  # page 0

        self._scene = QGraphicsScene(self)
        self._view = _GraphView()
        self._view.setScene(self._scene)
        self._stack.addWidget(self._view)  # page 1

        self._show_message("Select a function to view its control-flow graph.")

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme

    def clear_view(self) -> None:
        self._show_message("Select a function to view its control-flow graph.")

    def show_pending(self) -> None:
        self._show_message("Decompiling…")

    def show_native(self) -> None:
        self._show_message("Native function — no control-flow graph.")

    def load_dot(self, dot_source: str) -> None:
        if graphviz is None:
            self._show_message(
                "The 'graphviz' Python package isn't installed.\n\n"
                "Install it with:  pip install crashlink[cfg]\n"
                "(or: pip install graphviz)\n\n"
                f"Import error: {GRAPHVIZ_IMPORT_ERROR}"
            )
            return

        try:
            svg_bytes = graphviz.Source(dot_source).pipe(format="svg")
        except Exception as e:
            self._show_message(
                "Couldn't render the CFG — is the Graphviz 'dot' executable installed and on PATH?\n\n"
                "Install Graphviz from https://graphviz.org/download/\n\n"
                f"Error: {e}"
            )
            return

        renderer = QSvgRenderer(svg_bytes)
        if not renderer.isValid():
            self._show_message("Graphviz produced an SVG that couldn't be parsed.")
            return

        self._scene.clear()
        item = QGraphicsSvgItem()
        # setSharedRenderer only keeps a raw C++ pointer, not a refcounted one — without
        # this instance reference the renderer is GC'd as soon as load_dot() returns and
        # the item is left holding a dangling pointer, segfaulting on the next repaint.
        self._svg_renderer = renderer
        item.setSharedRenderer(renderer)
        self._scene.addItem(item)
        self._scene.setSceneRect(item.boundingRect())
        self._view.resetTransform()
        self._view.fitInView(item, Qt.AspectRatioMode.KeepAspectRatio)
        self._stack.setCurrentIndex(_PAGE_GRAPH)

    def _show_message(self, text: str) -> None:
        self._message.setText(text)
        self._stack.setCurrentIndex(_PAGE_MESSAGE)
