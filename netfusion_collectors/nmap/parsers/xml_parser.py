import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from .base import BaseNmapParser


class XMLNmapParser(BaseNmapParser):
    """Parses Nmap XML output (-oX -) into structured records."""

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        if not raw_output or not raw_output.strip():
            return []

        try:
            root = ET.fromstring(raw_output.strip())
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse Nmap XML output: {e}")

        hosts: List[Dict[str, Any]] = []

        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
            reason = status_elem.get("reason", "") if status_elem is not None else ""

            # Addresses
            ipv4_addr = None
            ipv6_addr = None
            mac_addr = None
            mac_vendor = None

            for addr_elem in host_elem.findall("address"):
                addr_type = addr_elem.get("addrtype", "")
                addr_val = addr_elem.get("addr", "")
                if addr_type == "ipv4":
                    ipv4_addr = addr_val
                elif addr_type == "ipv6":
                    ipv6_addr = addr_val
                elif addr_type == "mac":
                    mac_addr = addr_val
                    mac_vendor = addr_elem.get("vendor", None)

            primary_ip = ipv4_addr or ipv6_addr or "127.0.0.1"

            # Hostnames
            hostnames: List[Dict[str, str]] = []
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                for hn_elem in hostnames_elem.findall("hostname"):
                    hostnames.append({
                        "name": hn_elem.get("name", ""),
                        "type": hn_elem.get("type", "user")
                    })

            # Ports & Services
            ports: List[Dict[str, Any]] = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    p_num = int(port_elem.get("portid", 0))
                    p_proto = port_elem.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    p_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                    p_reason = state_elem.get("reason", "") if state_elem is not None else ""

                    service_info: Dict[str, Any] = {}
                    service_elem = port_elem.find("service")
                    if service_elem is not None:
                        service_info = {
                            "name": service_elem.get("name", "unknown"),
                            "product": service_elem.get("product"),
                            "version": service_elem.get("version"),
                            "extrainfo": service_elem.get("extrainfo"),
                            "ostype": service_elem.get("ostype"),
                            "cpe": [cpe.text for cpe in service_elem.findall("cpe") if cpe.text]
                        }

                    # NSE Scripts on Ports
                    port_scripts: List[Dict[str, Any]] = []
                    for script_elem in port_elem.findall("script"):
                        s_id = script_elem.get("id", "")
                        s_output = script_elem.get("output", "")
                        s_tables: List[Dict[str, Any]] = []

                        for table_elem in script_elem.findall("table"):
                            t_key = table_elem.get("key", "")
                            t_elements = {elem.get("key", ""): elem.text for elem in table_elem.findall("elem")}
                            s_tables.append({"key": t_key, "elements": t_elements})

                        port_scripts.append({
                            "id": s_id,
                            "output": s_output,
                            "tables": s_tables
                        })

                    ports.append({
                        "port_number": p_num,
                        "protocol": p_proto,
                        "state": p_state,
                        "reason": p_reason,
                        "service": service_info,
                        "scripts": port_scripts
                    })

            # OS Matches
            os_matches: List[Dict[str, Any]] = []
            os_elem = host_elem.find("os")
            if os_elem is not None:
                for match_elem in os_elem.findall("osmatch"):
                    m_name = match_elem.get("name", "")
                    m_accuracy = int(match_elem.get("accuracy", "100"))
                    m_cpe: List[str] = []
                    m_vendor = None
                    m_family = None
                    m_gen = None

                    for osclass_elem in match_elem.findall("osclass"):
                        m_vendor = osclass_elem.get("vendor", m_vendor)
                        m_family = osclass_elem.get("osfamily", m_family)
                        m_gen = osclass_elem.get("osgen", m_gen)
                        for cpe_elem in osclass_elem.findall("cpe"):
                            if cpe_elem.text:
                                m_cpe.append(cpe_elem.text)

                    os_matches.append({
                        "name": m_name,
                        "accuracy": m_accuracy,
                        "vendor": m_vendor,
                        "osfamily": m_family,
                        "osgen": m_gen,
                        "cpe": m_cpe
                    })

            # Host-level NSE Scripts
            host_scripts: List[Dict[str, Any]] = []
            hostscript_elem = host_elem.find("hostscript")
            if hostscript_elem is not None:
                for script_elem in hostscript_elem.findall("script"):
                    s_id = script_elem.get("id", "")
                    s_output = script_elem.get("output", "")
                    host_scripts.append({
                        "id": s_id,
                        "output": s_output
                    })

            hosts.append({
                "ip_address": primary_ip,
                "mac_address": mac_addr,
                "mac_vendor": mac_vendor,
                "status": status,
                "reason": reason,
                "hostnames": hostnames,
                "ports": ports,
                "os_matches": os_matches,
                "host_scripts": host_scripts
            })

        return hosts
