"""Convert ANSI SGR colour codes (as printed by the CLI) into theme colour roles."""

from __future__ import annotations

import re
from typing import List, Tuple

# CSI sequences: SGR (`m`) is mapped to colours; every other one is dropped.
_CSI = re.compile(r"\x1b\[([0-9;?]*)([A-Za-z])")
# Stray escapes that are not CSI (e.g. OSC, lone ESC) are removed outright.
_OTHER_ESC = re.compile(r"\x1b(?:\][^\x07]*\x07|.)?")

# Basic and bright foreground colours -> Theme attribute names.
_FG_ROLES = {
    30: "overlay",
    31: "red",
    32: "green",
    33: "yellow",
    34: "accent",
    35: "mauve",
    36: "teal",
    37: "text",
}


def split_ansi(text: str, default_role: str) -> List[Tuple[str, str, bool]]:
    """Split `text` into (segment, theme role, bold) runs, consuming SGR codes.

    Unknown or unsupported escape sequences are stripped, so the result never
    contains an escape character."""
    runs: List[Tuple[str, str, bool]] = []
    role, bold = default_role, False
    pos = 0
    for match in _CSI.finditer(text):
        if match.start() > pos:
            runs.append((text[pos : match.start()], role, bold))
        pos = match.end()
        if match.group(2) != "m":
            continue
        params = [int(p) for p in match.group(1).split(";") if p.isdigit()] or [0]
        for code in params:
            if code == 0:
                role, bold = default_role, False
            elif code == 1:
                bold = True
            elif code == 22:
                bold = False
            elif code == 39:
                role = default_role
            elif code in _FG_ROLES:
                role = _FG_ROLES[code]
            elif 90 <= code <= 97:
                role = _FG_ROLES[code - 60]
    if pos < len(text):
        runs.append((text[pos:], role, bold))
    return [(_OTHER_ESC.sub("", seg), r, b) for seg, r, b in runs if seg]


def strip_ansi(text: str) -> str:
    """`text` with every escape sequence removed."""
    return "".join(segment for segment, _, _ in split_ansi(text, "text"))
