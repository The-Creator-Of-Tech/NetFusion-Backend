import re
from typing import Any, Dict, List, Optional
from netfusion_collector_sdk.base import CollectorContext
from netfusion_canonical import (
    CanonicalDomainObject,
    IPAddress,
    Port,
    Hostname,
    MACAddress,
    Protocol,
    Severity,
    ConfidenceScore,
    HostDiscovered,
    HostFingerprint,
    OperatingSystemObserved,
    PortObserved,
    ServiceFingerprint,
    DeviceObserved,
    InterfaceObserved,
    MACAddressObserved,
    HostnameObserved,
    VulnerabilityDetected,
    ToolObserved,
    TechniqueObserved,
    ServiceObserved,
)


class NmapCanonicalMapper:
    """
    Maps parsed Nmap host dictionary structures into universal Canonical Data Model objects.
    Enforces lineage tracking, contextual correlation, metadata preservation, and validation readiness.
    """

    def map_host_to_canonical(
        self, host_dict: Dict[str, Any], context: CollectorContext
    ) -> List[CanonicalDomainObject]:
        canonical_objects: List[CanonicalDomainObject] = []

        ip_str = host_dict.get("ip_address", "127.0.0.1")
        try:
            ip_obj = IPAddress(ip_str)
        except Exception:
            ip_obj = IPAddress("127.0.0.1")

        mac_str = host_dict.get("mac_address")
        mac_vendor = host_dict.get("mac_vendor")
        mac_obj: Optional[MACAddress] = None
        if mac_str:
            try:
                mac_obj = MACAddress(mac_str)
            except Exception:
                mac_obj = None

        status = host_dict.get("status", "up")
        reason = host_dict.get("reason", "nmap-scan")

        # 1. HostDiscovered
        parsed_hostnames: List[Hostname] = []
        raw_hostnames = host_dict.get("hostnames", [])
        for hn in raw_hostnames:
            h_name = hn.get("name") if isinstance(hn, dict) else str(hn)
            if h_name:
                try:
                    parsed_hostnames.append(Hostname(h_name))
                except Exception:
                    pass

        host_discovered = HostDiscovered(
            ip_address=ip_obj,
            mac_address=mac_obj,
            hostnames=parsed_hostnames,
            status=status,
            reason=reason,
            collector_id=context.collector_id,
            collector_type=context.collector_type,
            tenant_id=context.tenant_id,
            correlation_id=context.correlation_id,
            trace_id=context.trace_id,
            source_metadata={"nmap_raw_host": host_dict},
        )
        canonical_objects.append(host_discovered)

        # 2. HostnameObserved (for each hostname)
        for hn in raw_hostnames:
            h_name = hn.get("name") if isinstance(hn, dict) else str(hn)
            h_type = hn.get("type", "user") if isinstance(hn, dict) else "user"
            if h_name:
                try:
                    hn_observed = HostnameObserved(
                        hostname=Hostname(h_name),
                        associated_ip=ip_obj,
                        name_type=h_type,
                        collector_id=context.collector_id,
                        collector_type=context.collector_type,
                        tenant_id=context.tenant_id,
                        correlation_id=context.correlation_id,
                        trace_id=context.trace_id,
                    )
                    canonical_objects.append(hn_observed)
                except Exception:
                    pass

        # 3. MACAddressObserved & DeviceObserved (if MAC is available)
        if mac_obj:
            mac_observed = MACAddressObserved(
                mac_address=mac_obj,
                vendor=mac_vendor,
                associated_ip=ip_obj,
                collector_id=context.collector_id,
                collector_type=context.collector_type,
                tenant_id=context.tenant_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
            )
            canonical_objects.append(mac_observed)

            device_observed = DeviceObserved(
                mac_address=mac_obj,
                vendor=mac_vendor,
                device_type="Network Endpoint",
                collector_id=context.collector_id,
                collector_type=context.collector_type,
                tenant_id=context.tenant_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
            )
            canonical_objects.append(device_observed)

        # 4. InterfaceObserved
        if mac_obj or ip_obj:
            interface_observed = InterfaceObserved(
                ip_address=ip_obj,
                mac_address=mac_obj,
                interface_name="eth0",
                status=status,
                collector_id=context.collector_id,
                collector_type=context.collector_type,
                tenant_id=context.tenant_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
            )
            canonical_objects.append(interface_observed)

        # 5. OS Matches -> OperatingSystemObserved & HostFingerprint
        os_matches = host_dict.get("os_matches", [])
        if os_matches:
            host_fp = HostFingerprint(
                ip_address=ip_obj,
                os_matches=os_matches,
                collector_id=context.collector_id,
                collector_type=context.collector_type,
                tenant_id=context.tenant_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
            )
            canonical_objects.append(host_fp)

            for os_m in os_matches:
                os_obs = OperatingSystemObserved(
                    ip_address=ip_obj,
                    os_name=os_m.get("name", "Unknown OS"),
                    os_family=os_m.get("osfamily"),
                    vendor=os_m.get("vendor"),
                    os_generation=os_m.get("osgen"),
                    accuracy=os_m.get("accuracy", 100),
                    cpe=os_m.get("cpe", []),
                    collector_id=context.collector_id,
                    collector_type=context.collector_type,
                    tenant_id=context.tenant_id,
                    correlation_id=context.correlation_id,
                    trace_id=context.trace_id,
                )
                canonical_objects.append(os_obs)

        # 6. Ports & Services -> PortObserved, ServiceFingerprint, ServiceObserved, VulnerabilityDetected
        ports = host_dict.get("ports", [])
        for p in ports:
            p_num = p.get("port_number", 0)
            p_proto = p.get("protocol", "tcp")
            p_state = p.get("state", "open")
            p_reason = p.get("reason", "syn-ack")

            try:
                port_val = Port(p_num)
            except Exception:
                continue

            svc_dict = p.get("service", {})
            svc_name = svc_dict.get("name", "unknown")

            # PortObserved
            port_obs = PortObserved(
                ip_address=ip_obj,
                port_number=port_val,
                protocol=p_proto,
                state=p_state,
                reason=p_reason,
                service_name=svc_name,
                collector_id=context.collector_id,
                collector_type=context.collector_type,
                tenant_id=context.tenant_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
            )
            canonical_objects.append(port_obs)

            # ServiceObserved
            service_obs = ServiceObserved(
                ip_address=ip_obj,
                port=port_val,
                transport=Protocol(p_proto.upper()),
                service_name=svc_name,
                banner=svc_dict.get("extrainfo"),
                collector_id=context.collector_id,
                collector_type=context.collector_type,
                tenant_id=context.tenant_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
            )
            canonical_objects.append(service_obs)

            # ServiceFingerprint
            if svc_dict.get("product") or svc_dict.get("version") or svc_dict.get("cpe"):
                service_fp = ServiceFingerprint(
                    ip_address=ip_obj,
                    port_number=port_val,
                    protocol=p_proto,
                    service_name=svc_name,
                    product=svc_dict.get("product"),
                    version=svc_dict.get("version"),
                    extrainfo=svc_dict.get("extrainfo"),
                    ostype=svc_dict.get("ostype"),
                    cpe=svc_dict.get("cpe", []),
                    confidence=ConfidenceScore(0.9),
                    collector_id=context.collector_id,
                    collector_type=context.collector_type,
                    tenant_id=context.tenant_id,
                    correlation_id=context.correlation_id,
                    trace_id=context.trace_id,
                )
                canonical_objects.append(service_fp)

            # Script Output on Ports (NSE Vulnerabilities)
            port_scripts = p.get("scripts", [])
            for script in port_scripts:
                s_id = script.get("id", "")
                s_output = script.get("output", "")

                # Check if script output indicates vulnerability or CVE
                if "CVE-" in s_output.upper() or "VULNERABLE" in s_output.upper() or "vuln" in s_id.lower():
                    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", s_output, re.I)
                    cve_found = cve_match.group(0).upper() if cve_match else "CVE-UNKNOWN"

                    vuln_obj = VulnerabilityDetected(
                        vulnerability_id=cve_found if cve_found != "CVE-UNKNOWN" else f"VULN-{s_id.upper()}",
                        title=f"NSE Script {s_id} Detection",
                        severity=Severity.HIGH if "VULNERABLE" in s_output.upper() else Severity.MEDIUM,
                        description=s_output[:500],
                        ip_address=ip_obj,
                        port_number=port_val,
                        script_id=s_id,
                        cvss_score=7.5 if "VULNERABLE" in s_output.upper() else 5.0,
                        raw_output=s_output,
                        collector_id=context.collector_id,
                        collector_type=context.collector_type,
                        tenant_id=context.tenant_id,
                        correlation_id=context.correlation_id,
                        trace_id=context.trace_id,
                    )
                    canonical_objects.append(vuln_obj)

        # 7. Host-level Scripts (Threat Domain ToolObserved / TechniqueObserved)
        host_scripts = host_dict.get("host_scripts", [])
        for script in host_scripts:
            s_id = script.get("id", "")
            s_output = script.get("output", "")
            if "CVE-" in s_output.upper() or "VULNERABLE" in s_output.upper():
                cve_match = re.search(r"CVE-\d{4}-\d{4,7}", s_output, re.I)
                cve_found = cve_match.group(0).upper() if cve_match else f"VULN-{s_id.upper()}"

                vuln_obj = VulnerabilityDetected(
                    vulnerability_id=cve_found,
                    title=f"Host Script {s_id} Detection",
                    severity=Severity.HIGH,
                    description=s_output[:500],
                    ip_address=ip_obj,
                    script_id=s_id,
                    raw_output=s_output,
                    collector_id=context.collector_id,
                    collector_type=context.collector_type,
                    tenant_id=context.tenant_id,
                    correlation_id=context.correlation_id,
                    trace_id=context.trace_id,
                )
                canonical_objects.append(vuln_obj)

        # 8. Threat Domain ToolObserved & TechniqueObserved
        tool_obs = ToolObserved(
            tool_name="Nmap",
            tool_type="Scanner",
            category="Network Discovery",
            execution_metadata={
                "ip_scanned": ip_str,
                "ports_count": len(ports),
                "os_identified": len(os_matches) > 0,
            },
            collector_id=context.collector_id,
            collector_type=context.collector_type,
            tenant_id=context.tenant_id,
            correlation_id=context.correlation_id,
            trace_id=context.trace_id,
        )
        canonical_objects.append(tool_obs)

        tech_obs = TechniqueObserved(
            technique_id="T1046",
            technique_name="Network Service Discovery",
            tactic="Discovery",
            confidence=ConfidenceScore(1.0),
            details={"ip_address": ip_str, "status": status},
            collector_id=context.collector_id,
            collector_type=context.collector_type,
            tenant_id=context.tenant_id,
            correlation_id=context.correlation_id,
            trace_id=context.trace_id,
        )
        canonical_objects.append(tech_obs)

        return canonical_objects
