from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseNmapParser(ABC):
    """Abstract Base Class for all Nmap Output Parsers."""

    @abstractmethod
    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parse raw Nmap execution output into structured host dictionaries.
        """
        pass
