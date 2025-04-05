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


def is_runtime() -> bool:
    """
    Checks if the environment hlrun is running in is the pyhl runtime.
    """
    global RUNTIME
    try:
        assert isinstance(RUNTIME, bool) # type: ignore
        return RUNTIME # type: ignore
    except NameError:
        return False


def is_debug() -> bool:
    """
    Checks if pyhl has DEBUG enabled in this runtime.
    """
    if not is_runtime():
        return False
    global DEBUG
    try:
        assert isinstance(DEBUG, bool) # type: ignore
        return DEBUG # type: ignore
    except NameError:
        return False
