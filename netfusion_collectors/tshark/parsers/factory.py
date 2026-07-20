from typing import Dict, Type
from netfusion_collectors.tshark.config import TSharkOutputFormat
from .base import BaseTSharkParser
from .json_parser import JSONTSharkParser
from .ek_json_parser import EKJSONTSharkParser
from .pdml_parser import PDMLTSharkParser
from .psml_parser import PSMLTSharkParser


class TSharkParserFactory:
    """Factory for selecting the appropriate TShark output parser."""

    _parsers: Dict[TSharkOutputFormat, Type[BaseTSharkParser]] = {
        TSharkOutputFormat.JSON: JSONTSharkParser,
        TSharkOutputFormat.EK_JSON: EKJSONTSharkParser,
        TSharkOutputFormat.PDML: PDMLTSharkParser,
        TSharkOutputFormat.PSML: PSMLTSharkParser,
    }

    @classmethod
    def get_parser(cls, output_format: TSharkOutputFormat) -> BaseTSharkParser:
        parser_cls = cls._parsers.get(output_format, JSONTSharkParser)
        return parser_cls()
