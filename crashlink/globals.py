"""
Global configuration.
"""

VERSION: str = "pre-alpha"
"""
The version of crashlink.
"""

LONG_VERSION: str = "crashlink - Pure Python HashLink bytecode parser/disassembler/decompiler/modding tool - " + VERSION

DEBUG: bool = True
"""
Whether to enable certain features meant only for development or debugging of crashlink.
"""


def dbg_print(*args, **kwargs):
    """
    Print a message if DEBUG is True.
    """
    if DEBUG:
        print(*args, **kwargs)


def tell(f):
    """
    Hex-formatted tell of a file.
    """
    return hex(f.tell())
