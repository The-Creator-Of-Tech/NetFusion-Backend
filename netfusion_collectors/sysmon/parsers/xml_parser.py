import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Union
from .base import BaseSysmonParser


class XmlSysmonParser(BaseSysmonParser):
    """
    Parser for Sysmon XML Event representations.
    Supports single or multiple XML event strings, XML elements, and dict structures.
    """

    def parse(self, raw_data: Union[str, bytes, List[Dict[str, Any]], Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        if isinstance(raw_data, list):
            for item in raw_data:
                if isinstance(item, dict):
                    results.append(self.standardize_event_dict(item))
                elif isinstance(item, (str, bytes)):
                    results.extend(self._parse_xml_string(item))
            return results

        if isinstance(raw_data, dict):
            return [self.standardize_event_dict(raw_data)]

        if isinstance(raw_data, (str, bytes)):
            return self._parse_xml_string(raw_data)

        return results

    def _parse_xml_string(self, xml_content: Union[str, bytes]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if isinstance(xml_content, bytes):
            xml_str = xml_content.decode("utf-8", errors="replace")
        else:
            xml_str = xml_content

        xml_str = xml_str.strip()
        if not xml_str:
            return results

        # Wrap multiple root elements if needed
        if not xml_str.startswith("<Events>") and not xml_str.startswith("<?xml"):
            xml_wrapper = f"<Events>{xml_str}</Events>"
        else:
            xml_wrapper = xml_str

        try:
            root = ET.fromstring(xml_wrapper)
        except ET.ParseError:
            try:
                root = ET.fromstring(f"<Events>{xml_str}</Events>")
            except ET.ParseError:
                return results

        # Gather all nodes whose tag ends with 'Event'
        event_nodes: List[ET.Element] = []
        def find_events(node: ET.Element):
            tag_name = node.tag.split("}")[-1] if "}" in node.tag else node.tag
            if tag_name == "Event":
                event_nodes.append(node)
            for child in node:
                find_events(child)

        find_events(root)

        for elem in event_nodes:
            event_dict = self._parse_event_node(elem)
            if event_dict:
                results.append(self.standardize_event_dict(event_dict))

        return results

    def _parse_event_node(self, elem: ET.Element) -> Dict[str, Any]:
        event_dict: Dict[str, Any] = {}

        def get_tag_name(tag: str) -> str:
            return tag.split("}")[-1] if "}" in tag else tag

        for child in elem:
            tag = get_tag_name(child.tag)
            if tag == "System":
                system_dict: Dict[str, Any] = {}
                for s_child in child:
                    s_tag = get_tag_name(s_child.tag)
                    if s_tag == "EventID":
                        system_dict["EventID"] = s_child.text or ""
                    elif s_tag == "TimeCreated":
                        system_dict["TimeCreated"] = s_child.attrib.get("SystemTime", s_child.text or "")
                    elif s_tag == "Computer":
                        system_dict["Computer"] = s_child.text or ""
                    elif s_tag == "EventRecordID":
                        system_dict["EventRecordID"] = s_child.text or ""
                    elif s_child.text:
                        system_dict[s_tag] = s_child.text
                    for attr_k, attr_v in s_child.attrib.items():
                        system_dict[f"{s_tag}_{attr_k}"] = attr_v
                event_dict["System"] = system_dict
                if "EventID" in system_dict:
                    event_dict["EventID"] = system_dict["EventID"]
                if "Computer" in system_dict:
                    event_dict["Computer"] = system_dict["Computer"]
                if "TimeCreated" in system_dict:
                    event_dict["TimeCreated"] = system_dict["TimeCreated"]
                if "EventRecordID" in system_dict:
                    event_dict["EventRecordID"] = system_dict["EventRecordID"]

            elif tag == "EventData":
                event_data: Dict[str, Any] = {}
                for d_child in child:
                    d_tag = get_tag_name(d_child.tag)
                    if d_tag == "Data":
                        name = d_child.attrib.get("Name")
                        val = d_child.text or ""
                        if name:
                            event_data[name] = val
                        else:
                            event_data[d_child.attrib.get("Key", f"Data_{len(event_data)}")] = val
                    else:
                        event_data[d_tag] = d_child.text or ""
                event_dict["EventData"] = event_data

        return event_dict
