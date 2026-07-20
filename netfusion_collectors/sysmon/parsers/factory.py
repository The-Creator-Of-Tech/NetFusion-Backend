from typing import Union
from .base import BaseSysmonParser
from .xml_parser import XmlSysmonParser
from .win_xml_parser import WindowsEventXmlParser
from .evtx_parser import EvtxSysmonParser


class SysmonParserFactory:
    """
    Factory creating appropriate Sysmon parser instance based on event source type or format string.
    """

    @staticmethod
    def get_parser(source_type: Union[str, Any] = "xml") -> BaseSysmonParser:
        if isinstance(source_type, str):
            st = source_type.upper()
            if "EVTX" in st:
                return EvtxSysmonParser()
            elif "WIN" in st or "WINDOWS" in st:
                return WindowsEventXmlParser()
            elif "XML" in st:
                return XmlSysmonParser()
        
        # Default fallback parser
        return XmlSysmonParser()
