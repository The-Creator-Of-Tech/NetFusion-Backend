"""
Sample CISA KEV JSON and CSV catalog datasets for unit and integration testing.
"""

SAMPLE_CISA_KEV_JSON = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.07.21",
    "dateReleased": "2024-07-21T10:00:00.000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains an unspecified vulnerability where JNDI features fail to protect against attacker-controlled LDAP.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        },
        {
            "cveID": "CVE-2023-23397",
            "vendorProject": "Microsoft",
            "product": "Outlook",
            "vulnerabilityName": "Microsoft Outlook Elevation of Privilege Vulnerability",
            "dateAdded": "2023-03-14",
            "shortDescription": "Microsoft Outlook contains an elevation of privilege vulnerability that allows NTLM hash exfiltration.",
            "requiredAction": "Apply mitigation or vendor patch.",
            "dueDate": "2023-04-04",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"
        },
        {
            "cveID": "CVE-2024-12345",
            "vendorProject": "ExampleCorp",
            "product": "TestGateway",
            "vulnerabilityName": "ExampleCorp TestGateway Authentication Bypass",
            "dateAdded": "2024-06-01",
            "shortDescription": "TestGateway allows unauthenticated attackers to bypass administrative login.",
            "requiredAction": "Upgrade to version 2.1 or higher.",
            "dueDate": "2024-06-15",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "https://example.com/sec-adv/CVE-2024-12345"
        }
    ]
}

SAMPLE_CISA_KEV_CSV = """cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes
CVE-2021-44228,Apache,Log4j,Apache Log4j2 RCE,2021-12-10,Log4j JNDI RCE,Apply update,2021-12-24,Known,https://nvd.nist.gov/vuln/detail/CVE-2021-44228
CVE-2023-23397,Microsoft,Outlook,Outlook EoP,2023-03-14,Outlook NTLM leak,Apply patch,2023-04-04,Known,https://msrc.microsoft.com
"""
