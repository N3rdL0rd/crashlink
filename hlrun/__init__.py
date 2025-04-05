"""
Runtime tools for instrumenting Hashlink bytecode. See `crashlink.patch`.

WARNING: This module should never be used alone - you should use it in conjunction with pyhl, or, better yet, just use `crashlink.patch`.
"""

from .core import *
from .globals import *
from .obj import *
