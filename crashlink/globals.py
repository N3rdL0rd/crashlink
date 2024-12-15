"""
Global configuration.
"""

from io import BytesIO
from typing import Any, BinaryIO

VERSION: str = "pre-alpha"
"""
The version of crashlink.
"""

LONG_VERSION: str = "crashlink - Pure Python HashLink bytecode parser/disassembler/decompiler/modding tool - " + VERSION
"""
String displayed in the help message for the CLI.
"""

DEBUG: bool = False
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
