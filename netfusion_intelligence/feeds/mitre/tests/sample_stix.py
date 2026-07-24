"""
Sample STIX 2.1 Enterprise ATT&CK fixture data for unit tests.
"""

SAMPLE_STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--11111111-2222-3333-4444-555555555555",
    "spec_version": "2.1",
    "objects": [
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--tactic-execution-uuid",
            "name": "Execution",
            "description": "The adversary is trying to run malicious code.",
            "x_mitre_shortname": "execution",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "TA0002",
                    "url": "https://attack.mitre.org/tactics/TA0002",
                }
            ],
            "x_mitre_version": "1.0",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1059-uuid",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command and script interpreters to execute commands.",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
            "x_mitre_platforms": ["Windows", "Linux", "macOS"],
            "x_mitre_is_subtechnique": False,
            "x_mitre_permissions_required": ["User", "Administrator"],
            "x_mitre_detection": "Monitor process execution for cmd.exe or powershell.exe",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "url": "https://attack.mitre.org/techniques/T1059",
                }
            ],
            "x_mitre_version": "1.4",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1059-001-uuid",
            "name": "PowerShell",
            "description": "Adversaries may abuse PowerShell to execute commands.",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_is_subtechnique": True,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1059.001",
                    "url": "https://attack.mitre.org/techniques/T1059/001",
                }
            ],
            "x_mitre_version": "1.2",
        },
        {
            "type": "intrusion-set",
            "id": "intrusion-set--apt28-uuid",
            "name": "APT28",
            "description": "APT28 is a cyber threat group attributed to Russia's GRU.",
            "aliases": ["APT28", "Fancy Bear", "Sednit"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "G0007",
                    "url": "https://attack.mitre.org/groups/G0007",
                }
            ],
            "x_mitre_version": "2.1",
        },
        {
            "type": "malware",
            "id": "malware--mimikatz-uuid",
            "name": "Mimikatz",
            "description": "Mimikatz is a credential dumper.",
            "aliases": ["Mimikatz"],
            "x_mitre_platforms": ["Windows"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "S0002",
                    "url": "https://attack.mitre.org/software/S0002",
                }
            ],
            "x_mitre_version": "1.1",
        },
        {
            "type": "tool",
            "id": "tool--psexec-uuid",
            "name": "PsExec",
            "description": "PsExec is a free Microsoft tool that lets you execute processes remotely.",
            "x_mitre_platforms": ["Windows"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "S0029",
                    "url": "https://attack.mitre.org/software/S0029",
                }
            ],
            "x_mitre_version": "1.0",
        },
        {
            "type": "campaign",
            "id": "campaign--solarwinds-uuid",
            "name": "SolarWinds Compromise",
            "description": "Campaign involving compromise of SolarWinds Orion supply chain.",
            "aliases": ["UNC2452"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "C0001",
                    "url": "https://attack.mitre.org/campaigns/C0001",
                }
            ],
            "x_mitre_version": "1.0",
        },
        {
            "type": "course-of-action",
            "id": "course-of-action--m1047-uuid",
            "name": "Execution Prevention",
            "description": "Block execution of unauthorized code.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "M1047",
                    "url": "https://attack.mitre.org/mitigations/M1047",
                }
            ],
            "x_mitre_version": "1.0",
        },
        {
            "type": "x-mitre-data-source",
            "id": "x-mitre-data-source--ds0009-uuid",
            "name": "Process",
            "description": "Information collected regarding processes executing on system.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "DS0009",
                    "url": "https://attack.mitre.org/datasources/DS0009",
                }
            ],
            "x_mitre_version": "1.0",
        },
        {
            "type": "relationship",
            "id": "relationship--apt28-uses-mimikatz-uuid",
            "source_ref": "intrusion-set--apt28-uuid",
            "target_ref": "malware--mimikatz-uuid",
            "relationship_type": "uses",
            "description": "APT28 has used Mimikatz to dump credentials.",
            "confidence": 90,
        },
        {
            "type": "relationship",
            "id": "relationship--apt28-uses-t1059-uuid",
            "source_ref": "intrusion-set--apt28-uuid",
            "target_ref": "attack-pattern--t1059-uuid",
            "relationship_type": "uses",
            "description": "APT28 has used command prompt and scripts.",
            "confidence": 95,
        },
        {
            "type": "relationship",
            "id": "relationship--m1047-mitigates-t1059-uuid",
            "source_ref": "course-of-action--m1047-uuid",
            "target_ref": "attack-pattern--t1059-uuid",
            "relationship_type": "mitigates",
            "description": "Execution prevention mitigates command execution.",
        },
        {
            "type": "relationship",
            "id": "relationship--t1059-001-subtechnique-of-t1059-uuid",
            "source_ref": "attack-pattern--t1059-001-uuid",
            "target_ref": "attack-pattern--t1059-uuid",
            "relationship_type": "subtechnique-of",
            "description": "PowerShell is a sub-technique of Command and Scripting Interpreter.",
        },
    ],
}
