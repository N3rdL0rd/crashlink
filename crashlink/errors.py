
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