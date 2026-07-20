import re
from typing import Any, Dict, List
from .base import BaseNmapParser


class GrepableNmapParser(BaseNmapParser):
    """Parses legacy Nmap Grepable output (-oG -)."""

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        if not raw_output or not raw_output.strip():
            return []

        hosts: List[Dict[str, Any]] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if not line.startswith("Host:"):
                continue

            host_dict: Dict[str, Any] = {
                "ip_address": "127.0.0.1",
                "status": "up",
                "reason": "grepable-parsed",
                "hostnames": [],
                "ports": [],
                "os_matches": [],
                "host_scripts": [],
            }

            # Parse Host section: Host: <ip> (<hostname>)
            host_match = re.match(r"^Host:\s+([^\s]+)\s+\(([^)]*)\)\s*(.*)$", line)
            if host_match:
                ip_str = host_match.group(1)
                hn_str = host_match.group(2).strip()
                rest = host_match.group(3)

                host_dict["ip_address"] = ip_str
                if hn_str:
                    host_dict["hostnames"].append({"name": hn_str, "type": "user"})

                # Parse fields separated by tabs or \t
                fields = rest.split("\t")
                for field in fields:
                    field = field.strip()
                    if field.startswith("Status:"):
                        status_val = field.replace("Status:", "").strip().lower()
                        host_dict["status"] = "up" if "up" in status_val else "down"

                    elif field.startswith("Ports:"):
                        ports_str = field.replace("Ports:", "").strip()
                        port_tokens = ports_str.split(",")
                        for token in port_tokens:
                            parts = token.strip().split("/")
                            if len(parts) >= 5:
                                try:
                                    p_num = int(parts[0])
                                    p_state = parts[1]
                                    p_proto = parts[2]
                                    p_owner = parts[3]
                                    p_service = parts[4]

                                    host_dict["ports"].append({
                                        "port_number": p_num,
                                        "protocol": p_proto or "tcp",
                                        "state": p_state or "unknown",
                                        "reason": "grepable-output",
                                        "service": {"name": p_service} if p_service else {},
                                        "scripts": []
                                    })
                                except ValueError:
                                    pass

                    elif field.startswith("OS:"):
                        os_str = field.replace("OS:", "").strip()
                        if os_str:
                            host_dict["os_matches"].append({
                                "name": os_str,
                                "accuracy": 100,
                                "vendor": None,
                                "osfamily": None,
                                "osgen": None,
                                "cpe": []
                            })

                hosts.append(host_dict)

        return hosts
