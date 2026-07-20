"""
Tests for NetFusion MITREReasoner engine.
"""

import pytest

from netfusion_ai import MITREReasoner, ContextBuilder, TacticalPhase


def test_mitre_reasoner_inferences():
    reasoner = MITREReasoner()
    cb = ContextBuilder()

    context = cb.build_context(
        sysmon_events=[{"event_id": 1, "image": "powershell.exe", "command_line": "powershell -enc ..."}],
        nmap_scans=[{"host": "192.168.1.1", "open_ports": [80, 443]}],
        tshark_captures=[{"src_ip": "192.168.1.1", "dst_ip": "10.0.0.5", "protocol": "SMB"}],
    )

    inferences = reasoner.infer_mitre_tactics(context)

    assert len(inferences) >= 2
    tactics = [inf.tactic for inf in inferences]

    assert TacticalPhase.EXECUTION in tactics or TacticalPhase.RECONNAISSANCE in tactics
    for inf in inferences:
        assert inf.technique_id.startswith("T")
        assert inf.kill_chain_progression_stage >= 1
