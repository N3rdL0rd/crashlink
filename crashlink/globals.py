"""
Global configuration.
"""

import os
from io import BytesIO
from typing import Any, BinaryIO


def _is_debug() -> bool:
    """
    Determine whether or not to enable debug mode.
    """
    return (
        bool(os.getenv("CRASHLINK_DEBUG", False))
        or bool(os.getenv("DEBUG", False))
        or os.path.exists(".crashlink_debug")
    )


VERSION: str = "v0.0.2a"
"""
The version of crashlink.
"""

LONG_VERSION: str = "crashlink - Pure Python HashLink bytecode multitool - " + VERSION
"""
String displayed in the help message for the CLI.
"""

DEBUG: bool = False or _is_debug()
"""
Whether to enable certain features meant only for development or debugging of crashlink.
"""


def dbg_print(*args: Any, **kwargs: Any) -> None:
    """
    Print a message if DEBUG is True.
    """
    if DEBUG:
        print(*args, **kwargs)


def tell(f: BinaryIO | BytesIO) -> str:
    """
    Hex-formatted tell of a file.
    """
    return hex(f.tell())


def fmt_bytes(bytes: int | float) -> str:
    """
    Format bytes into a human-readable string.
    """
    if bytes < 0:
        raise ValueError("Bytes cannot be negative.")

    size_units = ["B", "Kb", "Mb", "Gb", "Tb"]
    index = 0

    while bytes >= 1000 and index < len(size_units) - 1:
        bytes /= 1000
        index += 1

    return f"{bytes:.1f}{size_units[index]}"
