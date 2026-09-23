"""Embedded control-flow-graph viewer, rendered via Graphviz when available.

Both the `graphviz` Python package and the `dot` executable it shells out to are
optional — if either is missing we show a clear message instead of crashing.

Layout runs on a worker thread (it takes seconds for large functions); only the
newest request is displayed. Clicking a block emits `op_activated` with the
block's first opcode, and `highlight_op` outlines the block containing an op.
"""

from __future__ import annotations

import re
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import QObject, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QKeyEvent, QMouseEvent, QPainter, QPen, QWheelEvent
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtSvgWidgets import QGraphicsSvgItem
from PySide6.QtWidgets import (
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsView,
    QLabel,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ... import disasm
from ...decomp.function import IRFunction
from ..themes import DEFAULT_THEME, Theme

try:
    import graphviz  # type: ignore[import-untyped]

    GRAPHVIZ_IMPORT_ERROR: Optional[str] = None
except ImportError as e:
    graphviz: Any = None
    GRAPHVIZ_IMPORT_ERROR = str(e)

_PAGE_MESSAGE = 0
_PAGE_GRAPH = 1

# Smallest zoom the graph opens at: below this, block text is unreadable, so a big
# graph opens legible at its entry block instead of shrunk to fit.
_MIN_READABLE_SCALE = 0.6
# Cap on opcode lines drawn per block; longer blocks end with a "… N more" line.
_MAX_BLOCK_LINES = 40

_SVG_NS = "{http://www.w3.org/2000/svg}"


@dataclass
class _Block:
    rect: QRectF  # scene coordinates
    first_op: int
    n_ops: int


class _RenderSignals(QObject):
    done = Signal(int, int, bytes, object)  # generation, findex, svg, {node id: _Block}
    failed = Signal(int, str)  # generation, message


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _build_dot(ir: IRFunction, theme: Theme) -> Tuple[str, Dict[str, Tuple[int, int]]]:
    """DOT for `ir`'s CFG in `theme`'s colours, plus node id -> (first op, op count)."""
    cfg = ir.cfg
    assert cfg is not None
    code, func = ir.code, ir.func
    ids = {id(node): f"n{i}" for i, node in enumerate(cfg.nodes)}
    spans: Dict[str, Tuple[int, int]] = {}
    lines = [
        "digraph CFG {",
        f'  graph [bgcolor="{theme.base}", nodesep=0.35, ranksep=0.45];',
        f'  node [shape=box, style="rounded,filled", fontname="monospace", fontsize=10, '
        f'margin="0.12,0.06", fillcolor="{theme.surface0}", fontcolor="{theme.text}", color="{theme.surface2}"];',
        f'  edge [fontname="monospace", fontsize=9, color="{theme.overlay}", fontcolor="{theme.subtext}"];',
    ]
    for node in cfg.nodes:
        node_id = ids[id(node)]
        spans[node_id] = (node.base_offset, len(node.ops))
        rows = []
        for i, op in enumerate(node.ops[:_MAX_BLOCK_LINES]):
            try:
                text = disasm.pseudo_from_op(op, node.base_offset + i, func.regs, code, terse=True)
            except Exception:
                text = op.op or "?"
            rows.append(f"{node.base_offset + i:>4}  {text}")
        if len(node.ops) > _MAX_BLOCK_LINES:
            rows.append(f"      … {len(node.ops) - _MAX_BLOCK_LINES} more")
        label = "\\l".join(_escape(row) for row in rows) + "\\l"
        extra = ""
        if node is cfg.entry:
            extra = f', color="{theme.green}", penwidth=2'
        elif any(op.op == "Ret" for op in node.ops):
            extra = f', color="{theme.teal}", penwidth=2'
        lines.append(f'  {node_id} [label="{label}"{extra}];')
    edge_colours = {"true": theme.green, "false": theme.red, "trap": theme.yellow}
    for node in cfg.nodes:
        for target, edge_type in node.branches:
            if id(target) not in ids:
                continue
            attrs = ""
            if edge_type in edge_colours:
                colour = edge_colours[edge_type]
                attrs = f' [color="{colour}", fontcolor="{colour}", label="{edge_type}"]'
            elif edge_type.startswith("switch: "):
                case = edge_type.split("switch: ", 1)[1].strip()
                attrs = f' [color="{theme.mauve}", fontcolor="{theme.mauve}", label="{_escape(case)}"]'
            lines.append(f"  {ids[id(node)]} -> {ids[id(target)]}{attrs};")
    lines.append("}")
    return "\n".join(lines), spans


def _node_boxes(svg: bytes, spans: Dict[str, Tuple[int, int]]) -> Dict[str, _Block]:
    """Scene-space rectangles of every node in graphviz's SVG output."""
    root = ET.fromstring(svg)
    graph = root.find(f"{_SVG_NS}g")
    sx = sy = 1.0
    tx = ty = 0.0
    if graph is not None:
        transform = graph.get("transform", "")
        scale = re.search(r"scale\(([-\d.]+)[ ,]*([-\d.]*)\)", transform)
        if scale:
            sx = float(scale.group(1))
            sy = float(scale.group(2) or scale.group(1))
        translate = re.search(r"translate\(([-\d.]+)[ ,]+([-\d.]+)\)", transform)
        if translate:
            tx, ty = float(translate.group(1)), float(translate.group(2))
    boxes: Dict[str, _Block] = {}
    for group in root.iter(f"{_SVG_NS}g"):
        if group.get("class") != "node":
            continue
        title = group.find(f"{_SVG_NS}title")
        if title is None or title.text not in spans:
            continue
        xs: List[float] = []
        ys: List[float] = []
        for shape in group.iter():
            points = shape.get("points") or shape.get("d")
            if not points:
                continue
            numbers = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", points)]
            xs.extend(numbers[0::2])
            ys.extend(numbers[1::2])
        if not xs:
            continue
        rect = QRectF(
            QPointF((min(xs) + tx) * sx, (min(ys) + ty) * sy),
            QPointF((max(xs) + tx) * sx, (max(ys) + ty) * sy),
        )
        first, count = spans[title.text]
        boxes[title.text] = _Block(rect.normalized(), first, count)
    return boxes


class _GraphView(QGraphicsView):
    """A QGraphicsView with wheel zoom, drag panning, click reporting and zoom keys."""

    clicked = Signal(QPointF)  # scene position of a click that wasn't a drag
    zoom_key = Signal(str)  # "fit", "100", "in", "out"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self._press_pos: Optional[QPointF] = None

    def wheelEvent(self, event: QWheelEvent) -> None:
        factor = 1.25 if event.angleDelta().y() > 0 else 1 / 1.25
        self.scale(factor, factor)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        self._press_pos = event.position()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        super().mouseReleaseEvent(event)
        press, self._press_pos = self._press_pos, None
        if press is not None and (event.position() - press).manhattanLength() < 5:
            self.clicked.emit(self.mapToScene(event.position().toPoint()))

    def keyPressEvent(self, event: QKeyEvent) -> None:
        keys = {
            Qt.Key.Key_0: "fit",
            Qt.Key.Key_1: "100",
            Qt.Key.Key_Plus: "in",
            Qt.Key.Key_Equal: "in",
            Qt.Key.Key_Minus: "out",
        }
        action = keys.get(Qt.Key(event.key()))
        if action is not None:
            self.zoom_key.emit(action)
            return
        super().keyPressEvent(event)


class CfgView(QWidget):
    """Renders a function's control-flow graph as a zoomable/pannable SVG."""

    #: (findex, first opcode of the clicked block)
    op_activated = Signal(int, int)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._theme: Theme = DEFAULT_THEME
        self._svg_renderer: Optional[QSvgRenderer] = None
        self._generation = 0
        self._findex: Optional[int] = None
        self._ir: Optional[IRFunction] = None
        self._blocks: Dict[str, _Block] = {}
        self._highlight: Optional[QGraphicsRectItem] = None
        self._signals = _RenderSignals()
        self._signals.done.connect(self._on_rendered)
        self._signals.failed.connect(self._on_failed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

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
        self._view.clicked.connect(self._on_clicked)
        self._view.zoom_key.connect(self._zoom)
        self._stack.addWidget(self._view)  # page 1

        self._show_message("Select a function to view its control-flow graph.")

    def set_theme(self, theme: Theme) -> None:
        changed = theme is not self._theme
        self._theme = theme
        self._view.setBackgroundBrush(QColor(theme.base))
        if changed and self._ir is not None and self._findex is not None:
            self.request(self._findex, self._ir)

    def clear_view(self) -> None:
        self._generation += 1
        self._findex = None
        self._ir = None
        self._show_message("Select a function to view its control-flow graph.")

    def show_pending(self) -> None:
        self._generation += 1
        self._show_message("Decompiling…")

    def show_native(self) -> None:
        self._generation += 1
        self._findex = None
        self._ir = None
        self._show_message("Native function — no control-flow graph.")

    def request(self, findex: int, ir: IRFunction) -> None:
        """Lay out `ir`'s CFG off the UI thread; supersedes any pending request."""
        if graphviz is None:
            self._show_message(
                "The 'graphviz' Python package isn't installed.\n\n"
                "Install it with:  pip install crashlink[cfg]\n"
                "(or: pip install graphviz)\n\n"
                f"Import error: {GRAPHVIZ_IMPORT_ERROR}"
            )
            return
        if ir.cfg is None:
            self.show_native()
            return
        self._generation += 1
        generation = self._generation
        self._findex = findex
        self._ir = ir
        self._show_message("Rendering control-flow graph…")
        theme = self._theme
        signals = self._signals

        def work() -> None:
            try:
                dot, spans = _build_dot(ir, theme)
                svg = graphviz.Source(dot).pipe(format="svg")
                signals.done.emit(generation, findex, svg, _node_boxes(svg, spans))
            except Exception as e:
                signals.failed.emit(generation, str(e))

        threading.Thread(target=work, name=f"cfg f@{findex}", daemon=True).start()

    def highlight_op(self, findex: int, op_idx: int) -> None:
        """Outline the block containing `op_idx` and bring it into view."""
        if findex != self._findex or self._stack.currentIndex() != _PAGE_GRAPH:
            return
        block = next(
            (b for b in self._blocks.values() if b.first_op <= op_idx < b.first_op + max(1, b.n_ops)), None
        )
        if block is None:
            return
        if self._highlight is None:
            self._highlight = QGraphicsRectItem()
            self._highlight.setZValue(10)
            self._scene.addItem(self._highlight)
        pen = QPen(QColor(self._theme.accent))
        pen.setWidthF(3.0)
        self._highlight.setPen(pen)
        self._highlight.setRect(block.rect.adjusted(-3, -3, 3, 3))
        self._view.ensureVisible(block.rect, 40, 40)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _on_failed(self, generation: int, message: str) -> None:
        if generation != self._generation:
            return
        self._show_message(
            "Couldn't render the CFG. Is the Graphviz 'dot' executable installed and on PATH?\n\n"
            "Install Graphviz from https://graphviz.org/download/\n\n"
            f"Error: {message}"
        )

    def _on_rendered(self, generation: int, findex: int, svg: bytes, blocks: Dict[str, _Block]) -> None:
        if generation != self._generation or findex != self._findex:
            return
        renderer = QSvgRenderer(svg)
        if not renderer.isValid():
            self._show_message("Graphviz produced an SVG that couldn't be parsed.")
            return
        self._scene.clear()
        self._highlight = None
        item = QGraphicsSvgItem()
        # setSharedRenderer only keeps a raw C++ pointer, not a refcounted one — without
        # this instance reference the renderer is GC'd as soon as this returns and
        # the item is left holding a dangling pointer, segfaulting on the next repaint.
        self._svg_renderer = renderer
        item.setSharedRenderer(renderer)
        self._scene.addItem(item)
        self._scene.setSceneRect(item.boundingRect())
        self._blocks = blocks
        self._stack.setCurrentIndex(_PAGE_GRAPH)
        self._initial_zoom()

    def _initial_zoom(self) -> None:
        rect = self._scene.sceneRect()
        viewport = self._view.viewport().rect()
        if rect.isEmpty() or viewport.isEmpty():
            return
        fit = min(viewport.width() / rect.width(), viewport.height() / rect.height())
        self._view.resetTransform()
        if fit >= _MIN_READABLE_SCALE:
            self._view.scale(min(fit, 1.0), min(fit, 1.0))
            self._view.centerOn(rect.center())
            return
        # Too big to fit legibly: open readable, at the entry block (the topmost).
        scale = max(_MIN_READABLE_SCALE, min(1.0, viewport.width() / rect.width()))
        self._view.scale(scale, scale)
        entry = min(self._blocks.values(), key=lambda b: b.rect.top(), default=None)
        if entry is not None:
            self._view.centerOn(
                entry.rect.center().x(), entry.rect.top() + viewport.height() / (2 * scale) - 20
            )

    def _zoom(self, action: str) -> None:
        if action == "fit":
            self._view.fitInView(self._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        elif action == "100":
            self._view.resetTransform()
        elif action == "in":
            self._view.scale(1.25, 1.25)
        elif action == "out":
            self._view.scale(0.8, 0.8)

    def _on_clicked(self, pos: QPointF) -> None:
        if self._findex is None:
            return
        for block in self._blocks.values():
            if block.rect.contains(pos):
                self.op_activated.emit(self._findex, block.first_op)
                return

    def _show_message(self, text: str) -> None:
        self._message.setText(text)
        self._stack.setCurrentIndex(_PAGE_MESSAGE)
