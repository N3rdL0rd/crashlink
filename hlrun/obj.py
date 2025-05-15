from .core import HlObj
from typing import Optional, List, Dict, Type, TypeVar, Callable, Any
from functools import wraps
from typing import TypeVar, Callable, Any, ParamSpec, cast

R = TypeVar("R")
P = ParamSpec("P")

OBJ_MAP: Dict[str, type] = {}

T = TypeVar("T", bound=Type[Any])


def obj(type_name: str) -> Callable[[T], T]:
    """
    Decorator to register a class in the OBJ_MAP dictionary.
    """

    def decorator(cls: T) -> T:
        OBJ_MAP[type_name] = cls
        return cls

    return decorator


def method(func: Callable[..., R]) -> Callable[..., R]:
    """
    Decorator that forwards method calls to the underlying HashLink object.

    Preserves the original function's return type and parameter types.
    """
    method_name = func.__name__

    @wraps(func)
    def wrapper(self: HlObj, *args: Any) -> R:
        return cast(R, self.__getattr__(method_name)(self, *args))

    return wrapper


@obj("String")
class HlString(HlObj):
    """
    Proxy to a Hashlink string.
    """

    bytes: bytes
    """
    Internal byte array.
    """

    length: int
    """
    The number of characters in `this` String.
    """

    @method
    def toUpperCase(self) -> "HlString":
        """
        Returns a String where all characters of `this` String are upper case.
        """
        raise NotImplementedError()

    @method
    def toLowerCase(self) -> "HlString":
        """
        Returns a String where all characters of `this` String are lower case.
        """
        raise NotImplementedError()

    @method
    def charAt(self, index: int) -> "HlString":
        """
        Returns the character at position `index` of `this` String.

        If `index` is negative or exceeds `this.length`, the empty String `""` is returned.
        """
        raise NotImplementedError()

    @method
    def charCodeAt(self, index: int) -> Optional[int]:
        """
        Returns the character code at position `index` of `this` String.

        If `index` is negative or exceeds `this.length`, `null` is returned.

        To obtain the character code of a single character, `"x".code` can be
        used instead to inline the character code at compile time. Note that
        this only works on String literals of length 1.
        """
        raise NotImplementedError()

    @method
    def findChar(self, start: int, len: int, src: HlObj, srcLen: int) -> int:
        """
        Undocumented private inline function that only exists in Hashlink. Probably not worth using.
        """
        raise NotImplementedError()

    @method
    def indexOf(self, str: "HlString", startIndex: Optional[int]) -> int:
        """
        Returns the position of the leftmost occurrence of `str` within `this` String.

        If `str` is the empty String `""`, then:
            * If `startIndex` is not specified or < 0, 0 is returned.
            * If `startIndex >= this.length`, `this.length` is returned.
            * Otherwise, `startIndex` is returned,

        Otherwise, if `startIndex` is not specified or < 0, it is treated as 0.

        If `startIndex >= this.length`, -1 is returned.

        Otherwise the search is performed within the substring of `this` String starting
        at `startIndex`. If `str` is found, the position of its first character in `this`
        String relative to position 0 is returned.

        If `str` cannot be found, -1 is returned.
        """
        raise NotImplementedError()

    @method
    def lastIndexOf(self, str: "HlString", startIndex: Optional[int]) -> int:
        """
        Returns the position of the rightmost occurrence of `str` within `this`
        String.

        If `startIndex` is given, the search is performed within the substring
        of `this` String from 0 to `startIndex + str.length`. Otherwise the search
        is performed within `this` String. In either case, the returned position
        is relative to the beginning of `this` String.

        If `startIndex` is negative, the result is unspecified.

        If `str` cannot be found, -1 is returned.
        """
        raise NotImplementedError()

    @method
    def split(self, delimiter: "HlString") -> List[HlString]:
        """
        Splits `this` String at each occurrence of `delimiter`.

        If `this` String is the empty String `""`, the result is not consistent
        across targets and may either be `[]` (on Js, Cpp) or `[""]`.

        If `delimiter` is the empty String `""`, `this` String is split into an
        Array of `this.length` elements, where the elements correspond to the
        characters of `this` String.

        If `delimiter` is not found within `this` String, the result is an Array
        with one element, which equals `this` String.

        If `delimiter` is null, the result is unspecified.

        Otherwise, `this` String is split into parts at each occurrence of
        `delimiter`. If `this` String starts (or ends) with `delimiter`, the
        result `Array` contains a leading (or trailing) empty String `""` element.
        Two subsequent delimiters also result in an empty String `""` element.
        """
        raise NotImplementedError()

    @method
    def substr(self, pos: int, len: Optional[int]) -> HlString:
        """
        Returns `len` characters of `this` String, starting at position `pos`.

        If `len` is omitted, all characters from position `pos` to the end of
        `this` String are included.

        If `pos` is negative, its value is calculated from the end of `this`
        String by `this.length + pos`. If this yields a negative value, 0 is
        used instead.

        If the calculated position + `len` exceeds `this.length`, the characters
        from that position to the end of `this` String are returned.

        If `len` is negative, the result is unspecified.
        """
        raise NotImplementedError()

    @method
    def substring(self, startIndex: int, endIndex: Optional[int]) -> HlString:
        """
        Returns the part of `this` String from `startIndex` to but not including `endIndex`.

        If `startIndex` or `endIndex` are negative, 0 is used instead.

        If `startIndex` exceeds `endIndex`, they are swapped.

        If the (possibly swapped) `endIndex` is omitted or exceeds
        `this.length`, `this.length` is used instead.

        If the (possibly swapped) `startIndex` exceeds `this.length`, the empty
        String `""` is returned.
        """
        raise NotImplementedError()

    @method
    def toString(self) -> HlString:
        """
        Returns the String itself.
        """
        raise NotImplementedError()

    @method
    def fromCharCode(self, code: int) -> HlString:
        """
        Returns the String corresponding to the character code `code`.

        If `code` is negative or has another invalid value, the result is
        unspecified.
        """
        raise NotImplementedError()
