import pytest
from netfusion_collectors.nmap.parsers import XMLNmapParser, NmapParserFactory
from netfusion_collectors.nmap import NmapOutputFormat

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV -O -oX - 192.168.1.50" version="7.92">
  <host status="up">
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Cisco Systems"/>
    <hostnames>
      <hostname name="web-server.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)">
          <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="98">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.x">
          <cpe>cpe:/o:linux:linux_kernel:5.4</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""


def test_xml_parser_basic():
    parser = XMLNmapParser()
    hosts = parser.parse(SAMPLE_NMAP_XML)

    assert len(hosts) == 1
    host = hosts[0]

    assert host["ip_address"] == "192.168.1.50"
    assert host["mac_address"] == "00:11:22:33:44:55"
    assert host["mac_vendor"] == "Cisco Systems"
    assert host["status"] == "up"
    assert len(host["hostnames"]) == 1
    assert host["hostnames"][0]["name"] == "web-server.local"

    assert len(host["ports"]) == 2
    p80 = host["ports"][0]
    assert p80["port_number"] == 80
    assert p80["state"] == "open"
    assert p80["service"]["name"] == "http"
    assert p80["service"]["product"] == "Apache httpd"

    assert len(host["os_matches"]) == 1
    os_match = host["os_matches"][0]
    assert os_match["name"] == "Linux 5.4"
    assert os_match["accuracy"] == 98
    assert os_match["osfamily"] == "Linux"


def test_parser_factory_xml():
    parser = NmapParserFactory.get_parser(NmapOutputFormat.XML)
    assert isinstance(parser, XMLNmapParser)
    hosts = parser.parse(SAMPLE_NMAP_XML)
    assert len(hosts) == 1
