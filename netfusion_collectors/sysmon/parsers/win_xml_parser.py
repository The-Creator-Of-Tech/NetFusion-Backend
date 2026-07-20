from typing import Any, Dict, List, Union
from .xml_parser import XmlSysmonParser


class WindowsEventXmlParser(XmlSysmonParser):
    """
    Parser specialized for Windows Event Log rendered XML format (e.g. wevtutil /f:RenderedXml).
    Extends XmlSysmonParser with additional handling for Windows-specific namespaces and attributes.
    """

    def parse(self, raw_data: Union[str, bytes, List[Dict[str, Any]], Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Delegates to XmlSysmonParser which properly handles namespace stripping and System/EventData structures.
        return super().parse(raw_data)
