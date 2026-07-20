import os
import shutil
import subprocess
from typing import List, Tuple, Callable, Optional
from netfusion_collector_sdk.subprocess_runner import SubprocessRunner
from .config import TSharkConfig, TSharkCaptureMode, TSharkOutputFormat


class TSharkProcessRunner:
    """
    Subprocess execution engine for TShark.
    Never calls shell directly. Cross-platform support for Windows and Linux.
    """

    def __init__(self, config: TSharkConfig):
        self.config = config

    def build_command(self) -> List[str]:
        cmd: List[str] = [self.config.tshark_path]

        # Mode Selection
        if self.config.capture_mode in (TSharkCaptureMode.OFFLINE_PCAP, TSharkCaptureMode.OFFLINE_PCAPNG):
            if not self.config.pcap_filepath or not os.path.exists(self.config.pcap_filepath):
                raise FileNotFoundError(f"Offline PCAP file not found: '{self.config.pcap_filepath}'")
            cmd.extend(["-r", self.config.pcap_filepath])
        elif self.config.capture_mode in (TSharkCaptureMode.LIVE_CAPTURE, TSharkCaptureMode.STREAMING):
            if not self.config.capture_interface:
                raise ValueError("Live capture mode requires 'capture_interface' configuration.")
            cmd.extend(["-i", self.config.capture_interface])

            if not self.config.promiscuous_mode:
                cmd.append("-p")
            if self.config.monitor_mode:
                cmd.append("-I")

        # Filters and Limits
        if self.config.packet_limit:
            cmd.extend(["-c", str(self.config.packet_limit)])

        if self.config.capture_duration:
            cmd.extend(["-a", f"duration:{self.config.capture_duration}"])

        if self.config.bpf_filter and self.config.capture_mode in (TSharkCaptureMode.LIVE_CAPTURE, TSharkCaptureMode.STREAMING):
            cmd.extend(["-f", self.config.bpf_filter])

        if self.config.display_filter:
            cmd.extend(["-Y", self.config.display_filter])

        # Output Format
        if self.config.output_format == TSharkOutputFormat.JSON:
            cmd.extend(["-T", "json"])
        elif self.config.output_format == TSharkOutputFormat.EK_JSON:
            cmd.extend(["-T", "ek"])
        elif self.config.output_format == TSharkOutputFormat.PDML:
            cmd.extend(["-T", "pdml"])
        elif self.config.output_format == TSharkOutputFormat.PSML:
            cmd.extend(["-T", "psml"])

        return cmd

    def execute(
        self,
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
    ) -> Tuple[int, str, str]:
        cmd = self.build_command()
        return SubprocessRunner.run_cmd(
            cmd=cmd,
            timeout=self.config.timeout,
            cwd=self.config.temporary_storage if os.path.exists(self.config.temporary_storage) else None,
            on_stdout=on_stdout,
            on_stderr=on_stderr,
        )
