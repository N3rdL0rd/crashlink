"""
Global constants and utility functions.
"""

from typing import Any

# Injected into module globals at runtime by the embedded pyhl interpreter;
# not bound here, hence the NameError guards below.
DEBUG: bool
RUNTIME: bool


def dbg_print(*args: Any, **kwargs: Any) -> None:
    global DEBUG
    try:
        if DEBUG:
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
        assert isinstance(RUNTIME, bool)
        return RUNTIME
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
        assert isinstance(DEBUG, bool)
        return DEBUG
    except NameError:
        return False
