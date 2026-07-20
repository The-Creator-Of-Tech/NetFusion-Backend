import pytest
from netfusion_collectors.sysmon.parsers import (
    XmlSysmonParser,
    WindowsEventXmlParser,
    EvtxSysmonParser,
    SysmonParserFactory,
)

SAMPLE_SYSMON_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770B935-9541-5492-9930-C582F0C24276}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-20T12:00:00.0000000Z"/>
    <EventRecordID>1001</EventRecordID>
    <Execution ProcessID="1000" ThreadID="1004"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>DESKTOP-TEST</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-07-20 12:00:00.000</Data>
    <Data Name="ProcessGuid">{A1B2C3D4-1111-2222-3333-444455556666}</Data>
    <Data Name="ProcessId">4321</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="FileVersion">10.0.19041.1</Data>
    <Data Name="Description">Windows Command Processor</Data>
    <Data Name="Product">Microsoft® Windows® Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">Cmd.Exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="CurrentDirectory">C:\\Users\\Administrator\\</Data>
    <Data Name="User">DESKTOP-TEST\\Administrator</Data>
    <Data Name="LogonGuid">{A1B2C3D4-0000-0000-0000-000000000000}</Data>
    <Data Name="LogonId">0x3e7</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">MD5=11112222333344445555666677778888,SHA256=A1B2C3D4E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF</Data>
    <Data Name="ParentProcessGuid">{A1B2C3D4-1111-2222-3333-000000000000}</Data>
    <Data Name="ParentProcessId">1234</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="ParentCommandLine">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>
"""


class TestSysmonParsers:
    def test_xml_sysmon_parser(self):
        parser = XmlSysmonParser()
        events = parser.parse(SAMPLE_SYSMON_XML)
        assert len(events) == 1
        ev = events[0]

        assert ev["EventID"] == 1
        assert ev["Computer"] == "DESKTOP-TEST"
        assert ev["EventRecordID"] == "1001"
        assert ev["ProcessId"] == 4321
        assert ev["Image"] == "C:\\Windows\\System32\\cmd.exe"
        assert ev["CommandLine"] == "cmd.exe /c whoami"
        assert ev["User"] == "DESKTOP-TEST\\Administrator"
        assert ev["ParentProcessId"] == 1234
        assert ev["ParsedHashes"]["MD5"] == "11112222333344445555666677778888"
        assert ev["ParsedHashes"]["SHA256"] == "A1B2C3D4E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"

    def test_windows_event_xml_parser(self):
        parser = WindowsEventXmlParser()
        events = parser.parse(SAMPLE_SYSMON_XML)
        assert len(events) == 1
        assert events[0]["EventID"] == 1

    def test_evtx_sysmon_parser_dict_input(self):
        parser = EvtxSysmonParser()
        raw_dict = {
            "System": {"EventID": 3, "Computer": "HOST01", "EventRecordID": 200},
            "EventData": {
                "ProcessId": "5000",
                "Image": "C:\\Program Files\\app.exe",
                "SourceIp": "192.168.1.10",
                "DestinationIp": "93.184.216.34",
                "DestinationPort": "443",
            },
        }
        events = parser.parse([raw_dict])
        assert len(events) == 1
        assert events[0]["EventID"] == 3
        assert events[0]["ProcessId"] == 5000
        assert events[0]["DestinationIp"] == "93.184.216.34"

    def test_parser_factory(self):
        p1 = SysmonParserFactory.get_parser("XML")
        assert isinstance(p1, XmlSysmonParser)

        p2 = SysmonParserFactory.get_parser("EVTX")
        assert isinstance(p2, EvtxSysmonParser)

        p3 = SysmonParserFactory.get_parser("WIN_XML")
        assert isinstance(p3, WindowsEventXmlParser)
