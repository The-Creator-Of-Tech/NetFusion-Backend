# NetFusion Nmap Collector

Production-ready Nmap Collector for NetFusion Enterprise Architecture. Extends `BaseCollector` and reuses the Runtime Engine, SDK, Event Bus, Canonical Validation Pipeline, and Dead Letter Queue (DLQ).

## Architecture

```
                                  ┌────────────────────────┐
                                  │     NmapCollector      │
                                  └───────────┬────────────┘
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
              ▼                               ▼                               ▼
  ┌───────────────────────┐       ┌───────────────────────┐       ┌───────────────────────┐
  │   NmapProcessRunner   │       │   NmapParserFactory   │       │  NmapCanonicalMapper  │
  └───────────┬───────────┘       └───────────┬───────────┘       └───────────┬───────────┘
              │                               │                               │
              ▼                               ▼                               ▼
  ┌───────────────────────┐       ┌───────────────────────┐       ┌───────────────────────┐
  │    SubprocessRunner   │       │     XML/JSON Parser   │       │ Canonical Validation  │
  └───────────────────────┘       └───────────────────────┘       └───────────────────────┘
```

The Nmap Collector follows the deterministic NetFusion Collector Lifecycle:
1. `on_configure(config)`: Validates and binds `NmapConfig`.
2. `on_pre_execute()`: Executes pre-flight health checks and creates isolated workspace.
3. `execute_collection()`: Invokes Nmap binary asynchronously via `SubprocessRunner` (without `shell=True`), streams progress, parses output, and emits canonical domain objects.
4. `on_post_execute()`: Records final metrics and duration.
5. `on_cleanup()`: Cleans up temporary workspace files.

---

## Configuration (`NmapConfig`)

| Option | Type | Default | Description |
|---|---|---|---|
| `targets` | `Union[List[str], str]` | `["127.0.0.1"]` | Targets (single host, CIDR, subnets) |
| `target_file` | `Optional[str]` | `None` | Path to target list file (`-iL`) |
| `scan_type` | `NmapScanType` | `SYN` | Scan type (`SYN`, `CONNECT`, `UDP`, `ACK`, `PING`, etc.) |
| `ports` | `Optional[str]` | `None` | Port spec (e.g. `'80,443'`, `'1-1024'`) |
| `timing_template` | `NmapTimingTemplate` | `T3` | Timing template (`T0`–`T5`) |
| `skip_host_discovery` | `bool` | `False` | Skip ping discovery (`-Pn`) |
| `ping_scan_only` | `bool` | `False` | Host discovery only (`-sn`) |
| `service_version_detection` | `bool` | `True` | Enable service version detection (`-sV`) |
| `version_intensity` | `Optional[int]` | `None` | Version scan intensity (0–9) |
| `os_detection` | `bool` | `False` | Enable OS fingerprinting (`-O`) |
| `script_categories` | `List[str]` | `[]` | NSE script categories (`['default', 'vuln']`) |
| `scripts` | `List[str]` | `[]` | Individual NSE scripts (`['http-headers']`) |
| `output_format` | `NmapOutputFormat` | `XML` | Output format (`xml`, `json`, `grepable`) |
| `ipv6` | `bool` | `False` | Enable IPv6 scanning (`-6`) |
| `dns_resolution` | `NmapDNSResolution` | `DEFAULT` | DNS resolution (`always`, `never`, `default`) |
| `min_rate` | `Optional[int]` | `None` | Minimum packet rate (`--min-rate`) |
| `max_rate` | `Optional[int]` | `None` | Maximum packet rate (`--max-rate`) |
| `timeout` | `int` | `300` | Subprocess execution timeout in seconds |
| `binary_path` | `str` | `'nmap'` | Path to `nmap` executable binary |

---

## Scan Examples

### 1. Fast SYN Discovery Scan
```python
from netfusion_collectors.nmap import NmapCollector, NmapConfig, NmapScanType

config = NmapConfig(
    targets=["192.168.1.0/24"],
    scan_type=NmapScanType.SYN,
    timing_template="T4",
    ports="80,443,22,3389",
)

collector = NmapCollector()
collector.configure(config.model_dump())
result = collector.execute_collection()
```

### 2. Comprehensive Service & OS Enumeration Scan
```python
config = NmapConfig(
    targets=["10.0.0.5"],
    scan_type=NmapScanType.SYN,
    service_version_detection=True,
    os_detection=True,
    script_categories=["vuln", "safe"],
)
```

---

## Canonical Mapping

Parsed output is converted into standard NetFusion Canonical Objects:

- **Asset Domain**: `HostDiscovered`, `HostFingerprint`, `OperatingSystemObserved`, `PortObserved`, `ServiceFingerprint`, `DeviceObserved`, `InterfaceObserved`, `MACAddressObserved`, `HostnameObserved`
- **Threat Domain**: `VulnerabilityDetected` (extracted from NSE script outputs), `ToolObserved`, `TechniqueObserved`
- **Network Domain**: `ServiceObserved`

All canonical objects are passed through the `CanonicalValidator`. Invalid objects are automatically routed to the Dead Letter Queue (DLQ).

---

## Troubleshooting

1. **`Nmap binary not found`**: Ensure `nmap` is installed and in system `PATH`, or set `binary_path` explicitly.
2. **`Permission Denied for RAW sockets`**: OS fingerprinting (`-O`) and SYN scans (`-sS`) require Administrator (Windows) or root / `CAP_NET_RAW` privileges (Linux). Fallback to TCP Connect (`-sT`).

---

## Performance Notes

- Use `timing_template="T4"` for fast local subnet scanning.
- Specify exact port ranges (`ports="80,443,8080"`) rather than scanning all 65,535 ports on broad CIDRs.
- Set `--max-rate` to throttle scanner bandwidth when scanning production subnets.
