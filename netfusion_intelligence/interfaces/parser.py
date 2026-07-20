"""
ParserInterface definition.
"""

from abc import ABC, abstractmethod
from typing import Any


class ParserInterface(ABC):
    """
    Abstract interface for converting raw data into parsed structures.
    """

    @abstractmethod
    def parse(self, raw_data: Any) -> Any:
        """Parse raw content into Python data structures."""
        pass
