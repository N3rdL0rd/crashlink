"""
crashlink-specific errors.
"""


class CrashlinkError(Exception):
    """
    Base exception class for all errors raised by crashlink.
    """


class MalformedBytecode(CrashlinkError):
    """
    Raised when malformed bytecode is deserialised.
    """


class NoMagic(CrashlinkError):
    """
    Raised when no magic b"HLB" can be found in a file.
    """


class InvalidOpCode(CrashlinkError):
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
