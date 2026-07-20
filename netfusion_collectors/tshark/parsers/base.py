from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseTSharkParser(ABC):
    """Abstract interface for TShark output format parsers."""

    @abstractmethod
    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parses raw stdout from TShark into a list of normalized packet dictionary representations."""
        pass
