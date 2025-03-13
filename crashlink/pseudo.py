from abc import ABC, abstractmethod
from typing import Optional


class Translatable(ABC):
    @abstractmethod
    def translate(self, comment: Optional[str] = None) -> str:
        pass


__all__ = ["Translatable"]
