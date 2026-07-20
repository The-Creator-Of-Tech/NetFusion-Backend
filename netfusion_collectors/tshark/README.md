# NetFusion TShark Collector

Production-grade TShark packet capture and canonical extraction collector extending `BaseCollector` within the NetFusion Enterprise Framework.

---

## 1. Architecture Overview

The **TShark Collector** ingests raw network packet telemetry from live capture interfaces or offline PCAP/PCAPNG files, parses protocol layers using format-specific parsers (JSON, EK JSON, PDML, PSML), and converts packet fields into strongly-typed **Canonical Network Domain Objects** via declarative mapping contracts.

```
+-----------------------------------------------------------------------------------+
|                              TSharkCollector Execution Pipeline                  |
+-----------------------------------------------------------------------------------+
|  1. Configuration & Validation (TSharkConfig, ConfigurationManager)               |
|  2. Pre-Execution Health Probes (TSharkHealthChecker: binary, Npcap, permissions) |
|  3. Subprocess Execution (TSharkProcessRunner -> SubprocessRunner)               |
|  4. Format Output Parsing (TSharkParserFactory -> JSON/EK/PDML/PSML Parser)      |
|  5. Declarative Canonical Mapping (TSharkCanonicalMapper -> Canonical Objects)    |
|  6. Normalization & Validation (CanonicalValidator -> Event Bus / DLQ)            |
+-----------------------------------------------------------------------------------+
```

---

## 2. Component Integration

- **Collector SDK (`netfusion_collector_sdk`)**: Extends `BaseCollector`, inherits deterministic lifecycle management (`on_configure`, `on_pre_execute`, `execute_collection`, `on_post_execute`, `on_cleanup`).
- **Runtime Engine**: Uses `SubprocessRunner` for safe non-shell process execution, cross-platform signal handling, and timeout enforcement.
- **Canonical Data Model (`netfusion_canonical`)**: Generates canonical network domain objects (`PacketObserved`, `NetworkFlowObserved`, `DNSTransactionObserved`, `HTTPRequestObserved`, `TLSHandshakeObserved`, `CertificateObserved`, `SessionObserved`, `ServiceObserved`).
- **Normalization Pipeline**: Enforces type invariants, UUIDv4 validation, and routes invalid objects to `DeadLetterQueue` (DLQ).
- **Event Bus**: Emits `CollectorStartedEvent`, `ProgressEvent`, `CanonicalObjectEvent`, `CompletedEvent`, and `FailureEvent`.
- **Telemetry**: Records OpenTelemetry-compliant metrics (`packets_captured`, `packets_processed`, `flows_generated`, `objects_generated`, `cpu_percent`, `memory_peak_bytes`).

---

## 3. Configuration Reference

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `capture_interface` | `Optional[str]` | `None` | Network interface name (e.g. `eth0`, `Wi-Fi`, `1`). |
| `pcap_filepath` | `Optional[str]` | `None` | Absolute file path to offline PCAP/PCAPNG file. |
| `capture_mode` | `Enum` | `pcap` | Mode: `live`, `pcap`, `pcapng`, `streaming`. |
| `capture_duration` | `Optional[int]` | `None` | Duration in seconds (`-a duration:N`). |
| `packet_limit` | `Optional[int]` | `None` | Maximum packet count to process (`-c N`). |
| `bpf_filter` | `Optional[str]` | `None` | Berkeley Packet Filter expression (`-f filter`). |
| `display_filter` | `Optional[str]` | `None` | TShark display filter expression (`-Y filter`). |
| `promiscuous_mode` | `bool` | `True` | Enable NIC promiscuous mode (`-p`). |
| `monitor_mode` | `bool` | `False` | Enable Wi-Fi monitor mode (`-I`). |
| `output_format` | `Enum` | `json` | Output format: `json`, `ek`, `pdml`, `psml`. |
| `tshark_path` | `str` | `"tshark"` | Path to `tshark` executable binary. |
| `timeout` | `int` | `300` | Process execution timeout in seconds. |

---

## 4. Usage Examples

### 4.1 Offline PCAP Collection (Unit & Integration Testing)

```python
from netfusion_collector_sdk import MockCollectorRuntimeHost
from netfusion_collectors.tshark import TSharkCollector

config = {
    "capture_mode": "pcap",
    "pcap_filepath": "/path/to/sample.pcap",
    "output_format": "json",
    "packet_limit": 100,
}

host = MockCollectorRuntimeHost(TSharkCollector, config)
result = host.execute()

print(f"Captured: {result.packets_captured}, Objects Emitted: {result.objects_generated}")
```

### 4.2 Live Interface Streaming Capture

```python
from netfusion_collectors.tshark import TSharkCollector
from netfusion_collector_sdk import CollectorContext

context = CollectorContext(investigation_id="inv-20260720-001")
collector = TSharkCollector(context=context)

collector.configure({
    "capture_mode": "live",
    "capture_interface": "eth0",
    "bpf_filter": "tcp port 80 or tcp port 443",
    "capture_duration": 30,
    "output_format": "json",
})

result = collector.execute_collection()
```

---

## 5. Health Probes & Troubleshooting

- **Dependency Check**: Verifies Python packages (`psutil`, `pydantic`).
- **TShark Binary Availability**: Checks executable path in `$PATH` via `tshark -v`.
- **Npcap Driver Check (Windows)**: Verifies presence of `wpcap.dll` / `Npcap` driver.
- **Capture Permissions**: Validates root/admin privileges on Linux/Windows.

### Troubleshooting Common Errors

1. **`TShark executable 'tshark' not found in PATH`**:
   - Ensure Wireshark / TShark is installed on the system and added to system `PATH` (e.g. `C:\Program Files\Wireshark`).
2. **`Npcap packet capture driver not found`**:
   - Install Npcap driver on Windows with WinPcap compatibility enabled.
3. **`Permission Denied on Live Capture`**:
   - On Linux, execute with elevated capabilities (`setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap`) or run as root.
