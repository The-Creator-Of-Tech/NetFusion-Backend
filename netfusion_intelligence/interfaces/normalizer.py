"""
NormalizerInterface definition.
"""

from abc import ABC, abstractmethod
from typing import Any


class NormalizerInterface(ABC):
    """
    Abstract interface for normalizing parsed structures into canonical entities.
    """

    @abstractmethod
    def normalize(self, parsed_data: Any) -> Any:
        """Transform parsed data into normalized representations."""
        pass
