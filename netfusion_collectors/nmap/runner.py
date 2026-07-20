from typing import List, Tuple, Optional, Callable
from netfusion_collector_sdk.subprocess_runner import SubprocessRunner
from .config import NmapConfig, NmapScanType, NmapOutputFormat, NmapDNSResolution


class NmapProcessRunner:
    """
    Subprocess manager for Nmap execution.
    Uses SubprocessRunner to execute commands cleanly across Windows and Linux without shell=True.
    """

    def __init__(self, config: NmapConfig):
        self.config = config

    def build_command(self) -> List[str]:
        cmd: List[str] = [self.config.binary_path]

        # Scan type selection
        if self.config.ping_scan_only or self.config.scan_type == NmapScanType.PING:
            cmd.append("-sn")
        elif self.config.scan_type == NmapScanType.SYN:
            cmd.append("-sS")
        elif self.config.scan_type == NmapScanType.CONNECT:
            cmd.append("-sT")
        elif self.config.scan_type == NmapScanType.UDP:
            cmd.append("-sU")
        elif self.config.scan_type == NmapScanType.ACK:
            cmd.append("-sA")
        elif self.config.scan_type == NmapScanType.NULL:
            cmd.append("-sN")
        elif self.config.scan_type == NmapScanType.FIN:
            cmd.append("-sF")
        elif self.config.scan_type == NmapScanType.XMAS:
            cmd.append("-sX")

        # Skip host discovery
        if self.config.skip_host_discovery and not self.config.ping_scan_only:
            cmd.append("-Pn")

        # Port specification
        if self.config.ports:
            cmd.extend(["-p", str(self.config.ports)])

        # Timing template
        if self.config.timing_template:
            cmd.append(f"-{self.config.timing_template.value}")

        # Service version detection
        if self.config.service_version_detection and not self.config.ping_scan_only:
            cmd.append("-sV")
            if self.config.version_intensity is not None:
                cmd.extend(["--version-intensity", str(self.config.version_intensity)])

        # OS detection
        if self.config.os_detection and not self.config.ping_scan_only:
            cmd.append("-O")
            if self.config.os_limit:
                cmd.append("--osscan-limit")

        # Scripts & Script categories
        script_elements: List[str] = []
        if self.config.script_categories:
            script_elements.extend(self.config.script_categories)
        if self.config.scripts:
            script_elements.extend(self.config.scripts)

        if script_elements:
            cmd.append(f"--script={','.join(script_elements)}")

        if self.config.script_args:
            args_str = ",".join(f"{k}={v}" for k, v in self.config.script_args.items())
            cmd.append(f"--script-args={args_str}")

        # IPv6
        if self.config.ipv6:
            cmd.append("-6")

        # DNS resolution
        if self.config.dns_resolution == NmapDNSResolution.NEVER:
            cmd.append("-n")
        elif self.config.dns_resolution == NmapDNSResolution.ALWAYS:
            cmd.append("-R")

        # Rate limits
        if self.config.min_rate:
            cmd.extend(["--min-rate", str(self.config.min_rate)])
        if self.config.max_rate:
            cmd.extend(["--max-rate", str(self.config.max_rate)])

        # Output format specification (write to stdout using '-')
        if self.config.output_format in (NmapOutputFormat.XML, NmapOutputFormat.JSON):
            cmd.extend(["-oX", "-"])
        elif self.config.output_format == NmapOutputFormat.GREPABLE:
            cmd.extend(["-oG", "-"])

        # Target specification
        if self.config.target_file:
            cmd.extend(["-iL", self.config.target_file])
        else:
            if isinstance(self.config.targets, list):
                cmd.extend(self.config.targets)
            elif isinstance(self.config.targets, str):
                cmd.append(self.config.targets)

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
            on_stdout=on_stdout,
            on_stderr=on_stderr,
        )
