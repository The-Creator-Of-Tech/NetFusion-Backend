# NetFusion Microsoft Sysmon Collector

Enterprise-grade Microsoft Sysmon collector extending `BaseCollector` for ingesting live Windows Event Logs and offline EVTX telemetry files into the NetFusion Canonical Data Model.

## Architecture

```
                  ┌─────────────────────────────────────┐
                  │    Windows Event Log / EVTX File    │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │  SysmonEventRunner  │
                          └──────────┬──────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │  SysmonParserFactory  │
                         └───────────┬───────────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         ▼                           ▼                           ▼
┌──────────────────┐    ┌──────────────────────────┐    ─────────────────┐
│ XmlSysmonParser  │    │  WindowsEventXmlParser   │    │ EvtxSysmonParser│
└────────┬─────────┘    └────────────┬─────────────┘    ─────────┬───────┘
         │                           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     │
                                     ▼
                        ┌─────────────────────────┐
                        │  SysmonCanonicalMapper  │
                        └────────────┬────────────┘
                                     │
                                     ▼
                       ┌───────────────────────────┐
                       │ Canonical Domain Objects  │
                       │   (Process, File, Net,    │
                       │   Registry, WMI, etc.)    │
                       └─────────────┬─────────────┘
                                     │
                                     ▼
                      ┌─────────────────────────────┐
                      │  CanonicalValidator & DLQ   │
                      └─────────────────────────────┘
```

The collector implements the frozen NetFusion Collector SDK lifecycle:
1. `on_configure()`: Resolves configuration and initializes runners & health probes.
2. `on_pre_execute()`: Executes environmental health checks.
3. `execute_collection()`: Ingests, parses, maps, validates, and emits canonical domain objects.
4. `on_post_execute()`: Records completion metrics and logs execution summaries.
5. `on_cleanup()`: Persists incremental state bookmarks and releases resources.

---

## Configuration

Configuration is managed via `SysmonConfig(CollectorConfig)`:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `event_source` | `EventSourceType` | `WINDOWS_EVENT_LOG` | Event source (`WINDOWS_EVENT_LOG` or `EVTX_FILE`) |
| `collection_mode` | `CollectionMode` | `LIVE_EVENT_LOG` | Mode (`LIVE_EVENT_LOG`, `OFFLINE_EVTX`, `INCREMENTAL`, `HISTORICAL_REPLAY`, `STREAMING`) |
| `evtx_file_path` | `Optional[str]` | `None` | Path to offline `.evtx` log file |
| `event_ids` | `List[int]` | `[1..26]` | List of Sysmon Event IDs to ingest |
| `batch_size` | `int` | `100` | Processing batch size |
| `poll_interval` | `float` | `1.0` | Polling interval in seconds |
| `bookmark_path` | `Optional[str]` | `None` | Persistent bookmark storage path |
| `persist_bookmark` | `bool` | `True` | Enable stateful record ID bookmarking |
| `channel` | `str` | `"Microsoft-Windows-Sysmon/Operational"` | Sysmon Windows Event Log channel |
| `remote_server` | `Optional[str]` | `None` | Remote Windows server address |
| `auth_mode` | `AuthMode` | `DEFAULT` | Auth mode (`DEFAULT`, `KERBEROS`, `NTLM`, `NEGOTIATE`) |
| `filter_host` | `Optional[str]` | `None` | Filter by computer host name |
| `filter_process_name`| `Optional[str]`| `None` | Filter by process name substring |
| `filter_command_line`| `Optional[str]`| `None` | Filter by command line substring |
| `filter_hash_algorithm`| `Optional[HashAlgorithm]`| `None` | Require presence of hash algorithm (`SHA256`, `MD5`, etc.) |

---

## Supported Event IDs

The collector maps all standard Sysmon Event IDs:

- **Event ID 1**: Process Creation
- **Event ID 2**: File Creation Time Changed
- **Event ID 3**: Network Connection
- **Event ID 5**: Process Terminated
- **Event ID 6**: Driver Loaded
- **Event ID 7**: Image Loaded (DLL Load)
- **Event ID 8**: CreateRemoteThread
- **Event ID 10**: Process Access
- **Event ID 11**: File Create
- **Event ID 12**: Registry Object Create/Delete
- **Event ID 13**: Registry Value Set
- **Event ID 14**: Registry Rename
- **Event ID 15**: FileCreateStreamHash (Alternate Data Stream)
- **Event ID 17**: Pipe Created
- **Event ID 18**: Pipe Connected
- **Event ID 19**: WMI Event Filter
- **Event ID 20**: WMI Consumer
- **Event ID 21**: WMI Binding
- **Event ID 22**: DNS Query
- **Event ID 23**: File Delete
- **Event ID 24**: Clipboard Change
- **Event ID 25**: Process Tampering (Process Hollowing/Doppelganging)
- **Event ID 26**: File Delete Detected

---

## Canonical Mapping

Events map to NetFusion Canonical Endpoint Domain Objects:

| Sysmon Event ID | Canonical Domain Objects |
|-----------------|----------------────────--|
| 1 (Process Create) | `ProcessObserved`, `ProcessRelationshipObserved`, `EvidenceObserved`, `ConfidenceObserved` |
| 2 (File Time) | `FileObserved`, `EvidenceObserved` |
| 3 (Network Conn) | `NetworkConnectionObserved`, `RelationshipObserved`, `EvidenceObserved` |
| 5 (Process Term) | `ProcessObserved`, `EvidenceObserved` |
| 6 (Driver Load) | `DriverObserved`, `EvidenceObserved` |
| 7 (Image Load) | `ModuleObserved`, `EvidenceObserved` |
| 8 (Remote Thread) | `ProcessRelationshipObserved`, `RiskObserved`, `EvidenceObserved` |
| 10 (Process Access) | `ProcessRelationshipObserved`, `EvidenceObserved` |
| 11 (File Create) | `FileObserved`, `EvidenceObserved` |
| 12, 13, 14 (Registry)| `RegistryObserved`, `EvidenceObserved` |
| 15 (Stream Hash) | `FileObserved`, `RiskObserved`, `EvidenceObserved` |
| 17, 18 (Pipes) | `PipeObserved`, `EvidenceObserved` |
| 19, 20, 21 (WMI) | `WMIObserved`, `ServiceObserved`, `EvidenceObserved` |
| 22 (DNS Query) | `DNSQueryObserved`, `EvidenceObserved` |
| 23, 26 (File Delete) | `FileObserved`, `EvidenceObserved` |
| 24 (Clipboard) | `ClipboardObserved`, `EvidenceObserved` |
| 25 (Process Tamper)| `ProcessObserved`, `RiskObserved`, `EvidenceObserved` |

---

## Usage Examples

### Python Live Collection Example
```python
from netfusion_collectors.sysmon import SysmonCollector, SysmonConfig, CollectionMode

config = {
    "collection_mode": CollectionMode.LIVE_EVENT_LOG,
    "event_ids": [1, 3, 8, 22, 25],
    "batch_size": 50,
}

collector = SysmonCollector()
collector.configure(config)
result = collector.execute_collection()

print(f"Ingested {result.packets_captured} events, generated {result.objects_generated} canonical objects.")
```

### Offline EVTX File Replay Example
```python
from netfusion_collectors.sysmon import SysmonCollector, EventSourceType, CollectionMode

config = {
    "event_source": EventSourceType.EVTX_FILE,
    "collection_mode": CollectionMode.OFFLINE_EVTX,
    "evtx_file_path": "C:\\Logs\\Sysmon_Sample.evtx",
}

collector = SysmonCollector()
collector.configure(config)
result = collector.execute_collection()
```

---

## Troubleshooting

- **Event Log Service Not Reachable**: Ensure the `Microsoft-Windows-Sysmon/Operational` log channel is enabled and running.
- **Permission Denied**: Run with administrative or Event Log Reader permissions.
- **Missing python-evtx**: For offline binary `.evtx` files without standard XML fallback, install `python-evtx` (`pip install python-evtx`).

---

## Performance Notes

- Batch processing reduces IPC overhead when emitting canonical events.
- Stateful bookmarking ensures seamless incremental collection across system restarts.
- Structured JSON logging provides zero-overhead telemetry and context tracing.
