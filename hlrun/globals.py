"""
Global constants and utility functions.
"""

from typing import Any


def dbg_print(*args: Any, **kwargs: Any) -> None:
    global DEBUG
    try:
        if DEBUG:  # type: ignore
            print("[pyhl] [py] ", end="")
            print(*args, **kwargs)
    except NameError:
        pass
