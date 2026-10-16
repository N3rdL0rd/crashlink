"""Method mixins composed into `crashlink.gui.main_window.MainWindow`, one area each."""

from .annotate import AnnotateMixin as AnnotateMixin
from .fileio import FileIoMixin as FileIoMixin
from .menus import MenusMixin as MenusMixin
from .navigation import NavigationMixin as NavigationMixin
from .tabs import TabsMixin as TabsMixin
from .views import ViewsMixin as ViewsMixin
from .xrefs import XrefMixin as XrefMixin

__all__ = [
    "AnnotateMixin",
    "FileIoMixin",
    "MenusMixin",
    "NavigationMixin",
    "TabsMixin",
    "ViewsMixin",
    "XrefMixin",
]
