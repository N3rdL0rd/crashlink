"""Theme definitions and QSS generation for the crashlink GUI."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class Theme:
    name: str
    base: str       # main window / editor background
    mantle: str     # sidebar / panel background
    crust: str      # status bar / deepest background
    surface0: str   # widget backgrounds (list items, table rows)
    surface1: str   # hover state
    surface2: str   # selection / active
    text: str       # primary text
    subtext: str    # secondary / dimmed text
    overlay: str    # placeholders / disabled
    accent: str     # highlights, active tabs, focus rings
    green: str      # identifiers / success
    yellow: str     # literals / warnings
    red: str        # errors / keywords
    teal: str       # types
    mauve: str      # keywords
    peach: str      # numbers / constants
    pink: str       # methods


_ICON_DIR = os.path.join(tempfile.gettempdir(), "crashlink_qss_icons")


def _arrow_urls(color: str) -> Tuple[str, str]:
    """Write right/down SVG arrows in *color* and return (right_url, down_url)."""
    os.makedirs(_ICON_DIR, exist_ok=True)
    safe = color.lstrip("#")
    right = os.path.join(_ICON_DIR, f"arr_r_{safe}.svg")
    down  = os.path.join(_ICON_DIR, f"arr_d_{safe}.svg")
    if not os.path.exists(right):
        with open(right, "w") as f:
            f.write(f'<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8">'
                    f'<polygon points="1,1 7,4 1,7" fill="{color}"/></svg>')
    if not os.path.exists(down):
        with open(down, "w") as f:
            f.write(f'<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8">'
                    f'<polygon points="1,1 7,1 4,7" fill="{color}"/></svg>')
    # QSS url() needs forward slashes on all platforms
    return right.replace("\\", "/"), down.replace("\\", "/")


def generate_qss(t: Theme) -> str:
    arr_right, arr_down = _arrow_urls(t.overlay)
    return f"""
/* ── Base ──────────────────────────────────────────────── */
QMainWindow, QDialog, QWidget {{
    background-color: {t.base};
    color: {t.text};
    font-family: "JetBrains Mono", "Fira Code", "Cascadia Code", monospace;
    font-size: 13px;
}}

/* ── Menu bar ───────────────────────────────────────────── */
QMenuBar {{
    background-color: {t.mantle};
    color: {t.text};
    border-bottom: 1px solid {t.surface0};
    padding: 2px;
}}
QMenuBar::item:selected {{
    background-color: {t.surface1};
    border-radius: 4px;
}}
QMenu {{
    background-color: {t.mantle};
    color: {t.text};
    border: 1px solid {t.surface0};
    border-radius: 6px;
    padding: 4px;
}}
QMenu::item:selected {{
    background-color: {t.surface2};
    border-radius: 4px;
}}
QMenu::separator {{
    height: 1px;
    background: {t.surface0};
    margin: 4px 8px;
}}

/* ── Splitter ───────────────────────────────────────────── */
QSplitter::handle {{
    background-color: {t.surface0};
}}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical   {{ height: 1px; }}

/* ── Panels / frames ────────────────────────────────────── */
QFrame#sidebar {{
    background-color: {t.mantle};
    border-right: 1px solid {t.surface0};
}}
QFrame#bottomPanel {{
    background-color: {t.mantle};
    border-top: 1px solid {t.surface0};
}}

/* ── Labels ─────────────────────────────────────────────── */
QLabel {{
    color: {t.text};
    background: transparent;
}}
QMainWindow::separator {{
    background-color: {t.overlay};
    width: 2px;
    height: 2px;
}}
QMainWindow::separator:hover {{
    background-color: {t.accent};
    width: 2px;
    height: 2px;
}}
QDockWidget {{
    color: {t.text};
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
}}
QDockWidget::title {{
    background-color: {t.mantle};
    color: {t.subtext};
    padding: 5px 8px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.06em;
    border-bottom: 1px solid {t.surface1};
}}
QDockWidget::close-button, QDockWidget::float-button {{
    background: transparent;
    border: none;
    padding: 2px;
}}
QDockWidget::close-button:hover, QDockWidget::float-button:hover {{
    background-color: {t.surface1};
    border-radius: 3px;
}}
QFrame#panelHeaderBar {{
    background-color: {t.mantle};
    border-bottom: 1px solid {t.surface1};
}}
QLabel#panelHeader {{
    color: {t.subtext};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.08em;
    padding: 6px 8px;
    background: transparent;
}}

/* ── Search / line edit ─────────────────────────────────── */
QLineEdit {{
    background-color: {t.surface0};
    color: {t.text};
    border: 1px solid {t.surface1};
    border-radius: 6px;
    padding: 4px 8px;
    selection-background-color: {t.accent};
    selection-color: {t.base};
}}
QLineEdit:focus {{
    border-color: {t.accent};
}}
QLineEdit::placeholder {{
    color: {t.overlay};
}}

/* ── Tree widget ─────────────────────────────────────────── */
QTreeWidget {{
    background-color: transparent;
    color: {t.text};
    border: none;
    outline: none;
}}
QTreeWidget::item {{
    padding: 3px 4px;
    min-height: 20px;
}}
QTreeWidget::item:hover {{
    background-color: {t.surface0};
}}
QTreeWidget::item:selected {{
    background-color: {t.surface2};
    color: {t.text};
}}
QTreeWidget::branch:selected {{
    background-color: {t.surface2};
}}
QTreeWidget::branch:has-children:!has-siblings:closed,
QTreeWidget::branch:closed:has-children:has-siblings {{
    image: url({arr_right});
}}
QTreeWidget::branch:open:has-children:!has-siblings,
QTreeWidget::branch:open:has-children:has-siblings {{
    image: url({arr_down});
}}

/* ── List widget ─────────────────────────────────────────── */
QListWidget {{
    background-color: transparent;
    color: {t.text};
    border: none;
    outline: none;
}}
QListWidget::item {{
    padding: 4px 8px;
    border-radius: 4px;
}}
QListWidget::item:hover {{
    background-color: {t.surface0};
}}
QListWidget::item:selected {{
    background-color: {t.surface2};
    color: {t.text};
}}

/* ── Table widget ────────────────────────────────────────── */
QTableWidget {{
    background-color: transparent;
    color: {t.text};
    border: none;
    outline: none;
    gridline-color: {t.surface0};
}}
QTableWidget::item {{
    padding: 3px 6px;
}}
QTableWidget::item:selected {{
    background-color: {t.surface2};
    color: {t.text};
}}
QHeaderView {{
    background-color: {t.surface0};
}}
QHeaderView::section {{
    background-color: {t.surface0};
    color: {t.subtext};
    border: none;
    border-right: 1px solid {t.surface1};
    border-bottom: 1px solid {t.surface1};
    padding: 4px 8px;
    font-size: 11px;
    letter-spacing: 0.06em;
}}
QHeaderView::section:last {{
    border-right: none;
}}

/* ── Tab widget ──────────────────────────────────────────── */
QTabWidget {{
    background-color: {t.mantle};
    border: none;
}}
QTabWidget::pane {{
    border: none;
    border-top: 1px solid {t.surface0};
    background-color: {t.base};
}}
QTabBar {{
    background-color: {t.mantle};
    border: none;
    border-bottom: 1px solid {t.surface0};
}}
QTabBar::scroller {{
    background-color: {t.mantle};
}}
QTabBar::tab {{
    background-color: {t.mantle};
    color: {t.subtext};
    border: none;
    border-right: 1px solid {t.surface0};
    padding: 5px 10px 5px 14px;
    font-size: 12px;
}}
QTabBar::tab:selected {{
    background-color: {t.base};
    color: {t.text};
    border-bottom: 2px solid {t.accent};
}}
QTabBar::tab:hover:!selected {{
    background-color: {t.surface0};
    color: {t.text};
}}
QTabBar::close-button {{
    subcontrol-position: right;
    padding: 0;
}}

/* ── Tab close button ────────────────────────────────────── */
QToolButton#tabCloseBtn {{
    background: transparent;
    border: none;
    color: {t.overlay};
    font-size: 14px;
    font-weight: bold;
    padding: 0px 2px;
    margin: 0;
}}
QToolButton#tabCloseBtn:hover {{
    color: {t.red};
    background-color: {t.surface0};
    border-radius: 3px;
}}

/* ── Checkbox ────────────────────────────────────────────── */
QCheckBox {{
    color: {t.subtext};
    spacing: 4px;
    font-size: 11px;
    background: transparent;
}}
QCheckBox::indicator {{
    width: 12px;
    height: 12px;
    border: 1px solid {t.surface2};
    border-radius: 2px;
    background-color: {t.surface0};
}}
QCheckBox::indicator:checked {{
    background-color: {t.accent};
    border-color: {t.accent};
}}
QCheckBox::indicator:hover {{
    border-color: {t.text};
}}

/* ── Plain text / code view ─────────────────────────────── */
QPlainTextEdit {{
    background-color: {t.base};
    color: {t.text};
    border: none;
    selection-background-color: {t.surface2};
    selection-color: {t.text};
    padding: 8px;
}}

/* ── Scrollbars ──────────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {t.surface1};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {t.surface2};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {t.surface1};
    border-radius: 4px;
    min-width: 20px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {t.surface2};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Status bar ──────────────────────────────────────────── */
QStatusBar {{
    background-color: {t.crust};
    color: {t.subtext};
    border-top: 1px solid {t.surface0};
    font-size: 11px;
}}
QStatusBar::item {{ border: none; }}

/* ── Progress bar ────────────────────────────────────────── */
QProgressBar {{
    background-color: {t.surface0};
    border: none;
    border-radius: 3px;
    height: 4px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {t.accent};
    border-radius: 3px;
}}

/* ── Push buttons ────────────────────────────────────────── */
QPushButton {{
    background-color: {t.surface0};
    color: {t.text};
    border: 1px solid {t.surface1};
    border-radius: 6px;
    padding: 4px 12px;
}}
QPushButton:hover {{
    background-color: {t.surface1};
    border-color: {t.accent};
}}
QPushButton:pressed {{
    background-color: {t.surface2};
}}
QPushButton#smallBtn {{
    background: transparent;
    border: none;
    color: {t.overlay};
    font-size: 14px;
    padding: 0px;
}}
QPushButton#smallBtn:hover {{
    color: {t.accent};
    background: transparent;
}}
QPushButton#modeBtn {{
    background-color: {t.surface0};
    color: {t.subtext};
    border: 1px solid {t.surface1};
    border-radius: 4px;
    padding: 2px 10px;
    font-size: 11px;
}}
QPushButton#modeBtn:checked {{
    background-color: {t.surface2};
    color: {t.text};
    border-color: {t.accent};
}}
QPushButton#modeBtn:hover:!checked {{
    background-color: {t.surface1};
    color: {t.text};
}}
QFrame#modeBar {{
    background-color: {t.mantle};
    border-bottom: 1px solid {t.surface0};
}}

/* ── Combo box ───────────────────────────────────────────── */
QComboBox {{
    background-color: {t.surface0};
    color: {t.text};
    border: 1px solid {t.surface1};
    border-radius: 6px;
    padding: 3px 8px;
    min-width: 120px;
}}
QComboBox:focus {{ border-color: {t.accent}; }}
QComboBox QAbstractItemView {{
    background-color: {t.mantle};
    color: {t.text};
    border: 1px solid {t.surface0};
    selection-background-color: {t.surface2};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}

/* ── Tool tips ───────────────────────────────────────────── */
QToolTip {{
    background-color: {t.mantle};
    color: {t.text};
    border: 1px solid {t.surface0};
    border-radius: 4px;
    padding: 4px 8px;
}}
"""


# ── Catppuccin ────────────────────────────────────────────────────────────────

MOCHA = Theme(
    name="Catppuccin Mocha",
    base="#1e1e2e", mantle="#181825", crust="#11111b",
    surface0="#313244", surface1="#45475a", surface2="#585b70",
    text="#cdd6f4", subtext="#a6adc8", overlay="#6c7086",
    accent="#b4befe", green="#a6e3a1", yellow="#f9e2af",
    red="#f38ba8", teal="#94e2d5", mauve="#cba6f7", peach="#fab387", pink="#f5c2e7",
)

MACCHIATO = Theme(
    name="Catppuccin Macchiato",
    base="#24273a", mantle="#1e2030", crust="#181926",
    surface0="#363a4f", surface1="#494d64", surface2="#5b6078",
    text="#cad3f5", subtext="#a5adcb", overlay="#6e738d",
    accent="#b7bdf8", green="#a6da95", yellow="#eed49f",
    red="#ed8796", teal="#8bd5ca", mauve="#c6a0f6", peach="#f5a97f", pink="#f5bde6",
)

FRAPPE = Theme(
    name="Catppuccin Frappé",
    base="#303446", mantle="#292c3c", crust="#232634",
    surface0="#414559", surface1="#51576d", surface2="#626880",
    text="#c6d0f5", subtext="#a5adce", overlay="#737994",
    accent="#babbf1", green="#a6d189", yellow="#e5c890",
    red="#e78284", teal="#81c8be", mauve="#ca9ee6", peach="#ef9f76", pink="#f4b8e4",
)

LATTE = Theme(
    name="Catppuccin Latte",
    base="#eff1f5", mantle="#e6e9ef", crust="#dce0e8",
    surface0="#ccd0da", surface1="#bcc0cc", surface2="#acb0be",
    text="#4c4f69", subtext="#5c5f77", overlay="#7c7f93",
    accent="#7287fd", green="#40a02b", yellow="#df8e1d",
    red="#d20f39", teal="#179299", mauve="#8839ef", peach="#fe640b", pink="#ea76cb",
)

# ── Nord ──────────────────────────────────────────────────────────────────────

NORD = Theme(
    name="Nord",
    base="#2e3440", mantle="#272c36", crust="#1f2329",
    surface0="#3b4252", surface1="#434c5e", surface2="#4c566a",
    text="#eceff4", subtext="#d8dee9", overlay="#7b88a1",
    accent="#88c0d0", green="#a3be8c", yellow="#ebcb8b",
    red="#bf616a", teal="#8fbcbb", mauve="#b48ead", peach="#d08770", pink="#b48ead",
)

# ── Gruvbox ───────────────────────────────────────────────────────────────────

GRUVBOX = Theme(
    name="Gruvbox Dark",
    base="#282828", mantle="#1d2021", crust="#141617",
    surface0="#3c3836", surface1="#504945", surface2="#665c54",
    text="#ebdbb2", subtext="#d5c4a1", overlay="#928374",
    accent="#83a598", green="#b8bb26", yellow="#fabd2f",
    red="#fb4934", teal="#8ec07c", mauve="#d3869b", peach="#fe8019", pink="#d3869b",
)

THEMES: Dict[str, Theme] = {
    t.name: t for t in [MOCHA, MACCHIATO, FRAPPE, LATTE, NORD, GRUVBOX]
}

DEFAULT_THEME = MOCHA
