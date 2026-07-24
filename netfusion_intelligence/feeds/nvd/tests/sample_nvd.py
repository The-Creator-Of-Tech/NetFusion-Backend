"""
Sample NVD CVE JSON 2.0 API Data Fixtures for Unit and Integration Testing.
"""

SAMPLE_NVD_CVE_2024_1234 = {
    "id": "CVE-2024-1234",
    "sourceIdentifier": "nvd@nist.gov",
    "published": "2024-01-15T10:15:00.000Z",
    "lastModified": "2024-01-16T12:00:00.000Z",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {
            "lang": "en",
            "value": "An unauthenticated remote code execution vulnerability exists in Example Product 2.0 through SQL injection in the login parameter."
        },
        {
            "lang": "es",
            "value": "Existe una vulnerabilidad de ejecución remota de código en Ejemplo Producto 2.0."
        }
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "HIGH",
                    "availabilityImpact": "HIGH",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL"
                },
                "exploitabilityScore": 3.9,
                "impactScore": 5.9
            }
        ],
        "cvssMetricV2": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "2.0",
                    "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                    "accessVector": "NETWORK",
                    "accessComplexity": "LOW",
                    "authentication": "NONE",
                    "confidentialityImpact": "COMPLETE",
                    "integrityImpact": "COMPLETE",
                    "availabilityImpact": "COMPLETE",
                    "baseScore": 10.0
                },
                "baseSeverity": "HIGH",
                "exploitabilityScore": 10.0,
                "impactScore": 10.0
            }
        ]
    },
    "weaknesses": [
        {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "description": [
                {
                    "lang": "en",
                    "value": "CWE-89"
                }
            ]
        }
    ],
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:example:product:2.0:*:*:*:*:*:*:*",
                            "matchCriteriaId": "MC-1234-001",
                            "versionStartIncluding": "2.0",
                            "versionEndIncluding": "2.0.5"
                        }
                    ]
                }
            ]
        }
    ],
    "references": [
        {
            "url": "https://example.com/security/advisory-2024-1234",
            "source": "nvd@nist.gov",
            "tags": ["Vendor Advisory", "Exploit"]
        }
    ],
    "vendorComments": [
        {
            "organization": "Example Corp",
            "comment": "Patch is available in version 2.0.6",
            "lastModified": "2024-01-16T14:00:00.000Z"
        }
    ]
}

SAMPLE_NVD_CVE_2024_5678 = {
    "id": "CVE-2024-5678",
    "sourceIdentifier": "cve@mitre.org",
    "published": "2024-02-01T08:00:00.000Z",
    "lastModified": "2024-02-02T09:30:00.000Z",
    "vulnStatus": "Awaiting Analysis",
    "descriptions": [
        {
            "lang": "en",
            "value": "Cross-site scripting (XSS) vulnerability in Acme WebApp 1.5 allows remote attackers to inject script."
        }
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "REQUIRED",
                    "scope": "CHANGED",
                    "confidentialityImpact": "LOW",
                    "integrityImpact": "LOW",
                    "availabilityImpact": "NONE",
                    "baseScore": 6.1,
                    "baseSeverity": "MEDIUM"
                },
                "exploitabilityScore": 2.8,
                "impactScore": 2.7
            }
        ]
    },
    "weaknesses": [
        {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "description": [
                {
                    "lang": "en",
                    "value": "CWE-79"
                }
            ]
        }
    ],
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:acme:webapp:1.5:*:*:*:*:*:*:*",
                            "matchCriteriaId": "MC-5678-001"
                        }
                    ]
                }
            ]
        }
    ],
    "references": [
        {
            "url": "https://acme.com/advisories/CVE-2024-5678",
            "source": "cve@mitre.org",
            "tags": ["Third Party Advisory"]
        }
    ]
}

SAMPLE_NVD_JSON_RESPONSE = {
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2024-02-02T10:00:00.000Z",
    "totalResults": 2,
    "resultsPerPage": 2000,
    "startIndex": 0,
    "vulnerabilities": [
        {"cve": SAMPLE_NVD_CVE_2024_1234},
        {"cve": SAMPLE_NVD_CVE_2024_5678}
    ]
}
