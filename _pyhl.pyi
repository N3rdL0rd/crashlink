"""
Hashlink bindings for Python.
"""

# Note that this file exists at the root of the repo so vscode finds it when editing hlrun.

from typing import Any

def hl_obj_getfield(obj: Any, field_name: str) -> Any:
    """
    Get a field from an HL object.

    Args:
        obj: A capsule containing a pointer to an HL object
        field_name: The name of the field to get

    Returns:
        The value of the field, or None if the field doesn't exist

    Raises:
        TypeError: If the arguments have incorrect types
        ValueError: If the capsule is invalid or contains a NULL pointer
    """
    ...

def hl_obj_setfield(obj: Any, field_name: str, value: Any) -> None:
    """
    Set a field in an HL object.

    Args:
        obj: A capsule containing a pointer to an HL object
        field_name: The name of the field to set
        value: The value to set the field to

    Returns:
        None

    Raises:
        TypeError: If the arguments have incorrect types
        ValueError: If the capsule is invalid or contains a NULL pointer,
                   or if the Python value can't be converted to an HL value
    """
    ...

def hl_obj_classname(obj: Any) -> str:
    """
    Gets the class name of an HL object.

    Args:
        obj: A capsule containing a pointer to an HL object

    Returns:
        str

    Raises:
        ValueError: If the capsule is invalid or contains a NULL pointer.
    """
    ...

def hl_closure_call(closure: Any, *args: Any) -> Any:
    """
    Calls an HL closure.

    Args:
        closure: A capsule containing a pointer to an HL closure
        *args: Any arguments to pass to the closure.

    Returns:
        Any (whatever the closure returns)

    Raise:
        ValueError: If the capsule is invalid or contains a NULL pointer.
    """
    ...

def hl_obj_field_type(obj: Any, field_name: str) -> int:
    """
    Get the type of a field in an HL object.

    Args:
        obj: A capsule containing a pointer to an HL object
        field_name: The name of the field to get the type of
    Returns:
        int: The type of the field, or -1 if the field doesn't exist
    """
    ...
