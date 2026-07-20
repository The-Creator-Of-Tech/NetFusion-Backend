import re
from typing import Any, Dict, List, Optional
from netfusion_canonical import (
    CanonicalDomainObject,
    PacketObserved,
    NetworkFlowObserved,
    DNSTransactionObserved,
    HTTPRequestObserved,
    TLSHandshakeObserved,
    CertificateObserved,
    SessionObserved,
    ServiceObserved,
    IPAddress,
    Port,
    Hostname,
    MACAddress,
    Protocol,
    Hash,
)


class TSharkCanonicalMapper:
    """
    Declarative Canonical Mapper for TShark output payloads.
    Translates parsed packet dictionaries into strongly-typed Canonical Network Domain Objects.
    """

    def map_packet_to_canonical(
        self, packet_dict: Dict[str, Any], context: Any
    ) -> List[CanonicalDomainObject]:
        canonical_objects: List[CanonicalDomainObject] = []

        collector_id = getattr(context, "collector_id", "")
        correlation_id = getattr(context, "correlation_id", "")
        tenant_id = getattr(context, "tenant_id", "default-tenant")

        # Extract Raw Field Values with Fallbacks
        frame_num_str = (
            packet_dict.get("frame.number")
            or packet_dict.get("num")
            or packet_dict.get("No.")
            or "1"
        )
        frame_len_str = (
            packet_dict.get("frame.len")
            or packet_dict.get("len")
            or packet_dict.get("Length")
            or "0"
        )
        cap_len_str = (
            packet_dict.get("frame.cap_len")
            or packet_dict.get("caplen")
            or frame_len_str
        )

        src_ip_str = packet_dict.get("ip.src") or packet_dict.get("ipv6.src") or packet_dict.get("Source")
        dst_ip_str = packet_dict.get("ip.dst") or packet_dict.get("ipv6.dst") or packet_dict.get("Destination")
        src_port_str = packet_dict.get("tcp.srcport") or packet_dict.get("udp.srcport")
        dst_port_str = packet_dict.get("tcp.dstport") or packet_dict.get("udp.dstport")
        src_mac_str = packet_dict.get("eth.src") or packet_dict.get("eth.src_resolved")
        dst_mac_str = packet_dict.get("eth.dst") or packet_dict.get("eth.dst_resolved")

        frame_num = int(frame_num_str) if str(frame_num_str).isdigit() else 1
        frame_len = int(frame_len_str) if str(frame_len_str).isdigit() else 0
        cap_len = int(cap_len_str) if str(cap_len_str).isdigit() else frame_len

        # Construct PacketObserved
        src_ip_obj = IPAddress(src_ip_str) if src_ip_str else None
        dst_ip_obj = IPAddress(dst_ip_str) if dst_ip_str else None
        src_port_obj = Port(int(src_port_str)) if src_port_str and str(src_port_str).isdigit() else None
        dst_port_obj = Port(int(dst_port_str)) if dst_port_str and str(dst_port_str).isdigit() else None
        src_mac_obj = MACAddress(src_mac_str) if src_mac_str else None
        dst_mac_obj = MACAddress(dst_mac_str) if dst_mac_str else None

        pkt_observed = PacketObserved(
            frame_number=frame_num,
            frame_length=frame_len,
            capture_length=cap_len,
            src_mac=src_mac_obj,
            dst_mac=dst_mac_obj,
            src_ip=src_ip_obj,
            dst_ip=dst_ip_obj,
            src_port=src_port_obj,
            dst_port=dst_port_obj,
            collector_id=collector_id,
            correlation_id=correlation_id,
            tenant_id=tenant_id,
        )
        canonical_objects.append(pkt_observed)

        # Construct NetworkFlowObserved if IP endpoints exist
        if src_ip_obj and dst_ip_obj:
            proto_name = "TCP" if "tcp.srcport" in packet_dict else ("UDP" if "udp.srcport" in packet_dict else "IP")
            flow_obj = NetworkFlowObserved(
                src_ip=src_ip_obj,
                dst_ip=dst_ip_obj,
                src_port=src_port_obj or Port(0),
                dst_port=dst_port_obj or Port(0),
                protocol=Protocol(proto_name),
                bytes_sent=frame_len,
                packets_sent=1,
                collector_id=collector_id,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
            )
            canonical_objects.append(flow_obj)

        # Construct DNSTransactionObserved if DNS payload exists
        dns_query = packet_dict.get("dns.qry.name") or packet_dict.get("dns.resp.name")
        if dns_query:
            dns_obj = DNSTransactionObserved(
                query_name=Hostname(dns_query),
                query_type=packet_dict.get("dns.qry.type", "A"),
                rcode=str(packet_dict.get("dns.flags.rcode", "0")),
                collector_id=collector_id,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
            )
            canonical_objects.append(dns_obj)

        # Construct HTTPRequestObserved if HTTP payload exists
        http_method = packet_dict.get("http.request.method")
        http_uri = packet_dict.get("http.request.uri") or packet_dict.get("http.request.full_uri")
        if http_method or http_uri:
            host_header = packet_dict.get("http.host")
            http_obj = HTTPRequestObserved(
                http_method=http_method or "GET",
                uri=http_uri or "/",
                host=Hostname(host_header) if host_header else None,
                user_agent=packet_dict.get("http.user_agent"),
                status_code=int(packet_dict.get("http.response.code", 200)),
                collector_id=collector_id,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
            )
            canonical_objects.append(http_obj)

        # Construct TLSHandshakeObserved if TLS payload exists
        tls_sni = packet_dict.get("tls.handshake.extensions_server_name") or packet_dict.get("ssl.handshake.extensions_server_name")
        ja3 = packet_dict.get("tls.ja3") or packet_dict.get("ssl.ja3")
        if tls_sni or ja3 or "tls.handshake.type" in packet_dict:
            tls_obj = TLSHandshakeObserved(
                tls_version=packet_dict.get("tls.record.version", "TLSv1.3"),
                server_name_indication=Hostname(tls_sni) if tls_sni else None,
                ja3_hash=Hash("MD5", ja3) if ja3 and len(ja3) == 32 else None,
                collector_id=collector_id,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
            )
            canonical_objects.append(tls_obj)

        # Construct CertificateObserved if X.509 cert data exists
        cert_issuer = packet_dict.get("tls.handshake.certificate_issuer") or packet_dict.get("x509sat.issuer")
        cert_subject = packet_dict.get("tls.handshake.certificate_subject") or packet_dict.get("x509sat.subject")
        if cert_issuer or cert_subject:
            cert_obj = CertificateObserved(
                issuer=cert_issuer,
                subject=cert_subject,
                collector_id=collector_id,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
            )
            canonical_objects.append(cert_obj)

        # Construct SessionObserved if high-level session exists
        session_id = packet_dict.get("ssh.session_id") or packet_dict.get("smb.tree_id")
        if session_id:
            session_type = "SSH" if "ssh.session_id" in packet_dict else "SMB"
            sess_obj = SessionObserved(
                session_id=str(session_id),
                session_type=session_type,
                collector_id=collector_id,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
            )
            canonical_objects.append(sess_obj)

        # Construct ServiceObserved if listening/active service port detected
        if dst_ip_obj and dst_port_obj:
            svc_name = packet_dict.get("frame.protocols", "").split(":")[-1] if packet_dict.get("frame.protocols") else "unknown"
            svc_obj = ServiceObserved(
                ip_address=dst_ip_obj,
                port=dst_port_obj,
                transport=Protocol("TCP" if "tcp.dstport" in packet_dict else "UDP"),
                service_name=svc_name,
                collector_id=collector_id,
                correlation_id=correlation_id,
                tenant_id=tenant_id,
            )
            canonical_objects.append(svc_obj)

        return canonical_objects
