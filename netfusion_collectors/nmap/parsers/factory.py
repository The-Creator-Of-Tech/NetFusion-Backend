from ..config import NmapOutputFormat
from .base import BaseNmapParser
from .xml_parser import XMLNmapParser
from .json_parser import JSONNmapParser
from .grepable_parser import GrepableNmapParser


class NmapParserFactory:
    """Factory selecting Nmap output parser implementation by output format."""

    @staticmethod
    def get_parser(fmt: NmapOutputFormat) -> BaseNmapParser:
        if fmt == NmapOutputFormat.XML:
            return XMLNmapParser()
        elif fmt == NmapOutputFormat.JSON:
            return JSONNmapParser()
        elif fmt == NmapOutputFormat.GREPABLE:
            return GrepableNmapParser()
        else:
            return XMLNmapParser()
