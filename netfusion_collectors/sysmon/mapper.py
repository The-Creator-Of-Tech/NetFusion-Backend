import json
import time
from typing import Any, Dict, List, Optional
from netfusion_collector_sdk import CollectorContext
from .config import SysmonConfig
from .canonical import (
    EvidenceLineage,
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
    EvidenceObserved,
    RiskObserved,
    RelationshipObserved,
    ConfidenceObserved,
)


class SysmonCanonicalMapper:
    """
    Enterprise Canonical Mapper converting standardized Sysmon event dictionaries into Canonical Domain Objects.
    Enforces filtering rules and maintains ID, Host, User, PID, Parent PID, GUIDs, Hashes, Timestamps, and Lineage.
    """

    def map_event(
        self, event_dict: Dict[str, Any], config: SysmonConfig, context: CollectorContext
    ) -> List[Any]:
        if not self._passes_filters(event_dict, config):
            return []

        event_id = event_dict.get("EventID", 0)
        host = str(event_dict.get("Computer") or event_dict.get("host") or "")
        user = str(event_dict.get("User") or event_dict.get("user") or "")
        timestamp_obs = str(event_dict.get("UtcTime") or event_dict.get("TimeCreated") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        lineage = EvidenceLineage(
            provider="Sysmon",
            lookup_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            raw_reference=f"EventID={event_id},RecordID={event_dict.get('EventRecordID', 0)}",
            verification_method="SYS_LOG",
            collector_id=context.collector_id,
            investigation_id=context.investigation_id,
        ).to_dict()

        canonical_objects: List[Any] = []

        # EvidenceObserved for lineage traceability
        evidence_obj = EvidenceObserved(
            event_id=event_id,
            event_record_id=int(event_dict.get("EventRecordID") or 0),
            raw_xml=json.dumps(event_dict, default=str),
            host=host,
            user=user,
            evidence_type=f"SYSMON_EVENT_{event_id}",
            description=f"Sysmon Event ID {event_id} on {host}",
            evidence_lineage=[lineage],
            collector_id=context.collector_id,
            correlation_id=context.correlation_id,
            trace_id=context.trace_id,
            timestamp_observed=timestamp_obs,
        )
        canonical_objects.append(evidence_obj)

        # ConfidenceObserved for data quality assurance
        conf_obj = ConfidenceObserved(
            target_object_id=evidence_obj.object_id,
            score=1.0,
            rating="HIGH",
            provider="Sysmon",
            evidence_lineage=[lineage],
            collector_id=context.collector_id,
            correlation_id=context.correlation_id,
            trace_id=context.trace_id,
            timestamp_observed=timestamp_obs,
        )
        canonical_objects.append(conf_obj)

        # Event ID 1: Process Creation
        if event_id == 1:
            proc = ProcessObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                command_line=str(event_dict.get("CommandLine") or ""),
                user=user,
                host=host,
                hashes=event_dict.get("ParsedHashes", {}),
                current_directory=str(event_dict.get("CurrentDirectory") or ""),
                integrity_level=str(event_dict.get("IntegrityLevel") or ""),
                logon_id=str(event_dict.get("LogonId") or ""),
                terminal_session_id=str(event_dict.get("TerminalSessionId") or ""),
                parent_pid=int(event_dict.get("ParentProcessId") or 0),
                parent_guid=str(event_dict.get("ParentProcessGuid") or ""),
                parent_image=str(event_dict.get("ParentImage") or ""),
                parent_command_line=str(event_dict.get("ParentCommandLine") or ""),
                event_id=1,
                status="STARTED",
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(proc)

            rel = ProcessRelationshipObserved(
                parent_pid=int(event_dict.get("ParentProcessId") or 0),
                parent_guid=str(event_dict.get("ParentProcessGuid") or ""),
                parent_image=str(event_dict.get("ParentImage") or ""),
                child_pid=int(event_dict.get("ProcessId") or 0),
                child_guid=str(event_dict.get("ProcessGuid") or ""),
                child_image=str(event_dict.get("Image") or ""),
                relationship_type="CREATED",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(rel)

        # Event ID 2: File Creation Time Changed
        elif event_id == 2:
            file_obj = FileObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                target_filename=str(event_dict.get("TargetFilename") or ""),
                creation_utc_time=str(event_dict.get("CreationUtcTime") or ""),
                previous_creation_utc_time=str(event_dict.get("PreviousCreationUtcTime") or ""),
                event_type="TIME_CHANGED",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(file_obj)

        # Event ID 3: Network Connection
        elif event_id == 3:
            net_obj = NetworkConnectionObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                src_ip=str(event_dict.get("SourceIp") or "127.0.0.1"),
                src_port=int(event_dict.get("SourcePort") or 0),
                dst_ip=str(event_dict.get("DestinationIp") or "127.0.0.1"),
                dst_port=int(event_dict.get("DestinationPort") or 0),
                dst_hostname=str(event_dict.get("DestinationHostname")) if event_dict.get("DestinationHostname") else None,
                protocol=str(event_dict.get("Protocol") or "tcp"),
                initiated=str(event_dict.get("Initiated")).lower() == "true",
                source_is_ipv6=str(event_dict.get("SourceIsIpv6")).lower() == "true",
                destination_is_ipv6=str(event_dict.get("DestinationIsIpv6")).lower() == "true",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(net_obj)

            rel_net = RelationshipObserved(
                source_id=str(event_dict.get("ProcessGuid") or event_dict.get("ProcessId") or ""),
                source_type="Process",
                relationship_type="NETWORK_CONNECTED",
                target_id=f"{event_dict.get('DestinationIp')}:{event_dict.get('DestinationPort')}",
                target_type="NetworkEndpoint",
                provider="Sysmon",
                confidence=1.0,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(rel_net)

        # Event ID 5: Process Terminated
        elif event_id == 5:
            proc_term = ProcessObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                host=host,
                event_id=5,
                status="TERMINATED",
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(proc_term)

        # Event ID 6: Driver Loaded
        elif event_id == 6:
            drv = DriverObserved(
                image_loaded=str(event_dict.get("ImageLoaded") or ""),
                hashes=event_dict.get("ParsedHashes", {}),
                signed=str(event_dict.get("Signed")).lower() == "true",
                signature=str(event_dict.get("Signature") or ""),
                signature_status=str(event_dict.get("SignatureStatus") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(drv)

        # Event ID 7: Image Loaded
        elif event_id == 7:
            mod = ModuleObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                process_image=str(event_dict.get("Image") or ""),
                image_loaded=str(event_dict.get("ImageLoaded") or ""),
                hashes=event_dict.get("ParsedHashes", {}),
                signed=str(event_dict.get("Signed")).lower() == "true",
                signature=str(event_dict.get("Signature") or ""),
                signature_status=str(event_dict.get("SignatureStatus") or ""),
                original_file_name=str(event_dict.get("OriginalFileName") or ""),
                description=str(event_dict.get("Description") or ""),
                product=str(event_dict.get("Product") or ""),
                company=str(event_dict.get("Company") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(mod)

        # Event ID 8: CreateRemoteThread
        elif event_id == 8:
            rel_inj = ProcessRelationshipObserved(
                parent_pid=int(event_dict.get("SourceProcessId") or 0),
                parent_guid=str(event_dict.get("SourceProcessGuid") or ""),
                parent_image=str(event_dict.get("SourceImage") or ""),
                child_pid=int(event_dict.get("TargetProcessId") or 0),
                child_guid=str(event_dict.get("TargetProcessGuid") or ""),
                child_image=str(event_dict.get("TargetImage") or ""),
                relationship_type="INJECTED",
                target_pid=int(event_dict.get("TargetProcessId") or 0),
                target_guid=str(event_dict.get("TargetProcessGuid") or ""),
                target_image=str(event_dict.get("TargetImage") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(rel_inj)

            risk = RiskObserved(
                target_entity=str(event_dict.get("TargetImage") or event_dict.get("TargetProcessId") or ""),
                risk_score=85.0,
                risk_level="HIGH",
                factors=[
                    "CreateRemoteThread detected across processes",
                    f"Source: {event_dict.get('SourceImage')}",
                    f"Target: {event_dict.get('TargetImage')}",
                ],
                provider="Sysmon",
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(risk)

        # Event ID 10: Process Access
        elif event_id == 10:
            rel_acc = ProcessRelationshipObserved(
                parent_pid=int(event_dict.get("SourceProcessId") or 0),
                parent_guid=str(event_dict.get("SourceProcessGuid") or ""),
                parent_image=str(event_dict.get("SourceImage") or ""),
                child_pid=int(event_dict.get("TargetProcessId") or 0),
                child_guid=str(event_dict.get("TargetProcessGuid") or ""),
                child_image=str(event_dict.get("TargetImage") or ""),
                relationship_type="ACCESSED",
                target_pid=int(event_dict.get("TargetProcessId") or 0),
                target_guid=str(event_dict.get("TargetProcessGuid") or ""),
                target_image=str(event_dict.get("TargetImage") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(rel_acc)

        # Event ID 11: File Create
        elif event_id == 11:
            file_create = FileObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                target_filename=str(event_dict.get("TargetFilename") or ""),
                creation_utc_time=str(event_dict.get("CreationUtcTime") or ""),
                event_type="CREATED",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(file_create)

        # Event ID 12: Registry Object Create/Delete
        elif event_id == 12:
            reg = RegistryObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                event_type="CREATE_DELETE",
                target_object=str(event_dict.get("TargetObject") or ""),
                details=str(event_dict.get("EventType") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(reg)

        # Event ID 13: Registry Value Set
        elif event_id == 13:
            reg_val = RegistryObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                event_type="VALUE_SET",
                target_object=str(event_dict.get("TargetObject") or ""),
                details=str(event_dict.get("Details") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(reg_val)

        # Event ID 14: Registry Rename
        elif event_id == 14:
            reg_ren = RegistryObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                event_type="RENAME",
                target_object=str(event_dict.get("TargetObject") or ""),
                new_name=str(event_dict.get("NewName") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(reg_ren)

        # Event ID 15: FileCreateStreamHash
        elif event_id == 15:
            file_stream = FileObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                target_filename=str(event_dict.get("TargetFilename") or ""),
                hashes=event_dict.get("ParsedHashes", {}),
                stream_name=str(event_dict.get("TargetFilename") or ""),
                event_type="STREAM_HASH",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(file_stream)

            risk_stream = RiskObserved(
                target_entity=str(event_dict.get("TargetFilename") or ""),
                risk_score=60.0,
                risk_level="MEDIUM",
                factors=["Alternate Data Stream (ADS) created", f"Stream: {event_dict.get('TargetFilename')}"],
                provider="Sysmon",
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(risk_stream)

        # Event ID 17: Pipe Created
        elif event_id == 17:
            pipe_c = PipeObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                process_image=str(event_dict.get("Image") or ""),
                pipe_name=str(event_dict.get("PipeName") or ""),
                event_type="CREATED",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(pipe_c)

        # Event ID 18: Pipe Connected
        elif event_id == 18:
            pipe_conn = PipeObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                process_image=str(event_dict.get("Image") or ""),
                pipe_name=str(event_dict.get("PipeName") or ""),
                event_type="CONNECTED",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(pipe_conn)

        # Event ID 19: WMI Event Filter
        elif event_id == 19:
            wmi_f = WMIObserved(
                operation_type="FILTER",
                event_namespace=str(event_dict.get("EventNamespace") or ""),
                name=str(event_dict.get("Name") or ""),
                query=str(event_dict.get("Query") or ""),
                filter_path=str(event_dict.get("EventNamespace") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(wmi_f)

            srv_wmi = ServiceObserved(
                service_name=str(event_dict.get("Name") or ""),
                display_name=f"WMI Event Filter: {event_dict.get('Name')}",
                service_type="WMI_FILTER",
                binary_path=str(event_dict.get("Query") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(srv_wmi)

        # Event ID 20: WMI Consumer
        elif event_id == 20:
            wmi_c = WMIObserved(
                operation_type="CONSUMER",
                name=str(event_dict.get("Name") or ""),
                consumer_type=str(event_dict.get("Type") or ""),
                destination=str(event_dict.get("Destination") or ""),
                consumer_path=str(event_dict.get("Destination") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(wmi_c)

            srv_cons = ServiceObserved(
                service_name=str(event_dict.get("Name") or ""),
                display_name=f"WMI Event Consumer: {event_dict.get('Name')}",
                service_type=str(event_dict.get("Type") or "WMI_CONSUMER"),
                binary_path=str(event_dict.get("Destination") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(srv_cons)

        # Event ID 21: WMI Binding
        elif event_id == 21:
            wmi_b = WMIObserved(
                operation_type="BINDING",
                name=f"{event_dict.get('Operation', '')} {event_dict.get('Consumer', '')}",
                filter_path=str(event_dict.get("Filter") or ""),
                consumer_path=str(event_dict.get("Consumer") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(wmi_b)

            srv_bind = ServiceObserved(
                service_name=f"WMI Binding: {event_dict.get('Consumer')}",
                display_name=f"WMI Binding: {event_dict.get('Filter')} -> {event_dict.get('Consumer')}",
                service_type="WMI_BINDING",
                binary_path=str(event_dict.get("Consumer") or ""),
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(srv_bind)

        # Event ID 22: DNS Query
        elif event_id == 22:
            query_results_str = str(event_dict.get("QueryResults") or "")
            results_list = [r.strip() for r in query_results_str.split(";") if r.strip()] if query_results_str else []
            dns_obj = DNSQueryObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                query_name=str(event_dict.get("QueryName") or ""),
                query_status=str(event_dict.get("QueryStatus") or "0"),
                query_results=results_list,
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(dns_obj)

        # Event ID 23: File Delete
        elif event_id == 23:
            file_del = FileObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                target_filename=str(event_dict.get("TargetFilename") or ""),
                hashes=event_dict.get("ParsedHashes", {}),
                event_type="DELETED",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(file_del)

        # Event ID 24: Clipboard Change
        elif event_id == 24:
            clip = ClipboardObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                process_image=str(event_dict.get("Image") or ""),
                user=user,
                hashes=event_dict.get("ParsedHashes", {}),
                archived=str(event_dict.get("Archived")).lower() == "true",
                is_image=str(event_dict.get("IsImage")).lower() == "true",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(clip)

        # Event ID 25: Process Tampering
        elif event_id == 25:
            proc_tamp = ProcessObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                host=host,
                event_id=25,
                status="TAMPERED",
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(proc_tamp)

            risk_tamp = RiskObserved(
                target_entity=str(event_dict.get("Image") or event_dict.get("ProcessId") or ""),
                risk_score=95.0,
                risk_level="CRITICAL",
                factors=[
                    "Process tampering detected (process hollowing / image mismatch)",
                    f"Image: {event_dict.get('Image')}",
                    f"Type: {event_dict.get('Type')}",
                ],
                provider="Sysmon",
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(risk_tamp)

        # Event ID 26: File Delete Detected
        elif event_id == 26:
            file_del_det = FileObserved(
                pid=int(event_dict.get("ProcessId") or 0),
                process_guid=str(event_dict.get("ProcessGuid") or ""),
                image_path=str(event_dict.get("Image") or ""),
                user=user,
                target_filename=str(event_dict.get("TargetFilename") or ""),
                hashes=event_dict.get("ParsedHashes", {}),
                event_type="DELETE_DETECTED",
                host=host,
                evidence_lineage=[lineage],
                collector_id=context.collector_id,
                correlation_id=context.correlation_id,
                trace_id=context.trace_id,
                timestamp_observed=timestamp_obs,
            )
            canonical_objects.append(file_del_det)

        return canonical_objects

    def _passes_filters(self, event_dict: Dict[str, Any], config: SysmonConfig) -> bool:
        event_id = event_dict.get("EventID", 0)

        # Event ID whitelist check
        if config.event_ids and event_id not in config.event_ids:
            return False

        if config.filter_event_id and event_id not in config.filter_event_id:
            return False

        # Host filter
        if config.filter_host:
            comp = str(event_dict.get("Computer") or "").lower()
            if config.filter_host.lower() not in comp:
                return False

        # Username filter
        if config.filter_username:
            usr = str(event_dict.get("User") or "").lower()
            if config.filter_username.lower() not in usr:
                return False

        # Process name / Image path filter
        if config.filter_process_name:
            img = str(event_dict.get("Image") or "").lower()
            if config.filter_process_name.lower() not in img:
                return False

        if config.filter_image_path:
            img = str(event_dict.get("Image") or "").lower()
            if config.filter_image_path.lower() not in img:
                return False

        # Parent process filter
        if config.filter_parent_process:
            p_img = str(event_dict.get("ParentImage") or "").lower()
            if config.filter_parent_process.lower() not in p_img:
                return False

        # Command line filter
        if config.filter_command_line:
            cmd = str(event_dict.get("CommandLine") or "").lower()
            if config.filter_command_line.lower() not in cmd:
                return False

        # Hash algorithm filter
        if config.filter_hash_algorithm:
            parsed_h = event_dict.get("ParsedHashes", {})
            algo_key = config.filter_hash_algorithm.value if hasattr(config.filter_hash_algorithm, "value") else str(config.filter_hash_algorithm)
            if algo_key != "ANY" and algo_key.upper() not in parsed_h:
                return False

        # Network destination filter
        if config.filter_network_dest:
            dst_ip = str(event_dict.get("DestinationIp") or "").lower()
            dst_host = str(event_dict.get("DestinationHostname") or "").lower()
            target_filter = config.filter_network_dest.lower()
            if target_filter not in dst_ip and target_filter not in dst_host:
                return False

        return True
