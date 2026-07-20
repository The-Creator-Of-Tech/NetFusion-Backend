import pytest
from netfusion_collector_sdk import CollectorContext
from netfusion_collectors.sysmon.config import SysmonConfig, HashAlgorithm
from netfusion_collectors.sysmon.mapper import SysmonCanonicalMapper
from netfusion_collectors.sysmon.canonical import (
    ProcessObserved,
    ProcessRelationshipObserved,
    NetworkConnectionObserved,
    DNSQueryObserved,
    RegistryObserved,
    FileObserved,
    DriverObserved,
    ModuleObserved,
    PipeObserved,
    ClipboardObserved,
    WMIObserved,
    ServiceObserved,
    RiskObserved,
)


class TestEventMapping:
    @pytest.fixture
    def mapper(self):
        return SysmonCanonicalMapper()

    @pytest.fixture
    def context(self):
        return CollectorContext(collector_id="sysmon-test-col")

    @pytest.fixture
    def config(self):
        return SysmonConfig()

    def test_map_event_1_process_creation(self, mapper, config, context):
        ev = {
            "EventID": 1,
            "Computer": "HOST01",
            "User": "DOMAIN\\user1",
            "ProcessId": 100,
            "ProcessGuid": "{GUID-100}",
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -enc AAAA...",
            "ParentProcessId": 50,
            "ParentProcessGuid": "{GUID-50}",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParsedHashes": {"SHA256": "123456"},
        }
        objs = mapper.map_event(ev, config, context)
        assert len(objs) >= 4  # Evidence, Confidence, ProcessObserved, ProcessRelationshipObserved
        proc_objs = [o for o in objs if isinstance(o, ProcessObserved)]
        assert len(proc_objs) == 1
        assert proc_objs[0].pid == 100
        assert proc_objs[0].image_path == "C:\\Windows\\System32\\powershell.exe"
        assert proc_objs[0].hashes == {"SHA256": "123456"}

    def test_map_event_3_network_connection(self, mapper, config, context):
        ev = {
            "EventID": 3,
            "Computer": "HOST01",
            "User": "DOMAIN\\user1",
            "ProcessId": 200,
            "ProcessGuid": "{GUID-200}",
            "Image": "C:\\Program Files\\Browser\\browser.exe",
            "SourceIp": "10.0.0.15",
            "SourcePort": 54321,
            "DestinationIp": "1.1.1.1",
            "DestinationPort": 443,
            "DestinationHostname": "one.one.one.one",
            "Protocol": "tcp",
            "Initiated": "true",
        }
        objs = mapper.map_event(ev, config, context)
        net_objs = [o for o in objs if isinstance(o, NetworkConnectionObserved)]
        assert len(net_objs) == 1
        assert net_objs[0].dst_ip == "1.1.1.1"
        assert net_objs[0].dst_port == 443
        assert net_objs[0].dst_hostname == "one.one.one.one"

    def test_map_event_8_create_remote_thread(self, mapper, config, context):
        ev = {
            "EventID": 8,
            "Computer": "HOST01",
            "SourceProcessId": 1000,
            "SourceImage": "C:\\malware.exe",
            "TargetProcessId": 500,
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        }
        objs = mapper.map_event(ev, config, context)
        risk_objs = [o for o in objs if isinstance(o, RiskObserved)]
        assert len(risk_objs) == 1
        assert risk_objs[0].risk_level == "HIGH"
        assert risk_objs[0].risk_score == 85.0

    def test_map_event_12_13_14_registry(self, mapper, config, context):
        ev12 = {"EventID": 12, "Computer": "H1", "ProcessId": 10, "TargetObject": "HKLM\\Software\\Run", "EventType": "CreateKey"}
        ev13 = {"EventID": 13, "Computer": "H1", "ProcessId": 10, "TargetObject": "HKLM\\Software\\Run\\Malware", "Details": "c:\\malware.exe"}
        ev14 = {"EventID": 14, "Computer": "H1", "ProcessId": 10, "TargetObject": "HKLM\\Software\\Old", "NewName": "HKLM\\Software\\New"}

        reg12 = [o for o in mapper.map_event(ev12, config, context) if isinstance(o, RegistryObserved)][0]
        reg13 = [o for o in mapper.map_event(ev13, config, context) if isinstance(o, RegistryObserved)][0]
        reg14 = [o for o in mapper.map_event(ev14, config, context) if isinstance(o, RegistryObserved)][0]

        assert reg12.event_type == "CREATE_DELETE"
        assert reg13.event_type == "VALUE_SET"
        assert reg14.event_type == "RENAME"

    def test_map_event_19_20_21_wmi(self, mapper, config, context):
        ev19 = {"EventID": 19, "Computer": "H1", "EventNamespace": "root\\subscription", "Name": "PersistenceFilter", "Query": "SELECT * FROM __InstanceCreationEvent"}
        ev20 = {"EventID": 20, "Computer": "H1", "Name": "PersistenceConsumer", "Type": "CommandLineEventConsumer", "Destination": "c:\\script.vbs"}
        ev21 = {"EventID": 21, "Computer": "H1", "Operation": "Bind", "Filter": "PersistenceFilter", "Consumer": "PersistenceConsumer"}

        wmi19 = [o for o in mapper.map_event(ev19, config, context) if isinstance(o, WMIObserved)][0]
        wmi20 = [o for o in mapper.map_event(ev20, config, context) if isinstance(o, WMIObserved)][0]
        wmi21 = [o for o in mapper.map_event(ev21, config, context) if isinstance(o, WMIObserved)][0]

        assert wmi19.operation_type == "FILTER"
        assert wmi20.operation_type == "CONSUMER"
        assert wmi21.operation_type == "BINDING"

    def test_map_event_22_dns_query(self, mapper, config, context):
        ev = {
            "EventID": 22,
            "Computer": "HOST01",
            "ProcessId": 300,
            "Image": "C:\\app.exe",
            "QueryName": "malicious.com",
            "QueryStatus": "0",
            "QueryResults": "1.2.3.4;5.6.7.8",
        }
        dns_objs = [o for o in mapper.map_event(ev, config, context) if isinstance(o, DNSQueryObserved)]
        assert len(dns_objs) == 1
        assert dns_objs[0].query_name == "malicious.com"
        assert dns_objs[0].query_results == ["1.2.3.4", "5.6.7.8"]

    def test_map_event_25_process_tampering(self, mapper, config, context):
        ev = {
            "EventID": 25,
            "Computer": "HOST01",
            "ProcessId": 888,
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "Type": "Process hollowing",
        }
        objs = mapper.map_event(ev, config, context)
        tamp_proc = [o for o in objs if isinstance(o, ProcessObserved)][0]
        tamp_risk = [o for o in objs if isinstance(o, RiskObserved)][0]

        assert tamp_proc.status == "TAMPERED"
        assert tamp_risk.risk_level == "CRITICAL"
        assert tamp_risk.risk_score == 95.0

    def test_filtering_rules(self, mapper, context):
        cfg_host = SysmonConfig(filter_host="HOST01")
        assert len(mapper.map_event({"EventID": 1, "Computer": "HOST01"}, cfg_host, context)) > 0
        assert len(mapper.map_event({"EventID": 1, "Computer": "OTHER_HOST"}, cfg_host, context)) == 0

        cfg_proc = SysmonConfig(filter_process_name="cmd.exe")
        assert len(mapper.map_event({"EventID": 1, "Image": "C:\\cmd.exe"}, cfg_proc, context)) > 0
        assert len(mapper.map_event({"EventID": 1, "Image": "C:\\notepad.exe"}, cfg_proc, context)) == 0

        cfg_hash = SysmonConfig(filter_hash_algorithm=HashAlgorithm.SHA256)
        assert len(mapper.map_event({"EventID": 1, "ParsedHashes": {"SHA256": "abc"}}, cfg_hash, context)) > 0
        assert len(mapper.map_event({"EventID": 1, "ParsedHashes": {"MD5": "abc"}}, cfg_hash, context)) == 0
