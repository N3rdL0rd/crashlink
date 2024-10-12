"""
Global configuration.
"""

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
