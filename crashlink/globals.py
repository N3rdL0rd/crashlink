"""
Global configuration.
"""

from typing import BinaryIO, Any
from io import BytesIO

VERSION: str = "pre-alpha"
"""
The version of crashlink.
"""

LONG_VERSION: str = "crashlink - Pure Python HashLink bytecode parser/disassembler/decompiler/modding tool - " + VERSION

DEBUG: bool = True
"""
Whether to enable certain features meant only for development or debugging of crashlink.
"""


def dbg_print(*args: Any, **kwargs: Any) -> None:
    """
    Print a message if DEBUG is True.
    """
    if DEBUG:
        print(*args, **kwargs)


def tell(f: BinaryIO|BytesIO) -> str:
    """
    Hex-formatted tell of a file.
    """
    return hex(f.tell())
