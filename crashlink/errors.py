"""
crashlink-specific errors.
"""

from __future__ import annotations


class CrashlinkError(Exception):
    """
    Base exception class for most specific errors raised by crashlink.
    """


class MalformedBytecode(CrashlinkError):
    """
    Raised when malformed bytecode is deserialised.
    """


class NoMagic(CrashlinkError, EOFError):
    """
    Raised when no magic b"HLB" can be found in a file.
    """


class InvalidOpCode(CrashlinkError, ValueError):
    """
    Raised when an invalid opcode is encountered.
    """


class FailedSerialisation(CrashlinkError):
    """
    Raised when reserialisation of bytecode fails.
    """


class DecompError(CrashlinkError):
    """
    Raised when an error occurs during decompilation.
    """
