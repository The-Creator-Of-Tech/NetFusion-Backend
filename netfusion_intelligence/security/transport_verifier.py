"""
Transport Verification module for NetFusion Intelligence feeds.
Validates HTTPS requirements, TLS certificate validity, expiration, and hostname alignment.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from netfusion_intelligence.core.exceptions import (
    CertificateValidationError,
    ExpiredCertificateError,
    HostnameMismatchError,
    InsecureTransportError,
    TransportSecurityError,
)
from netfusion_intelligence.security.trust_model import TrustProfile


class TransportVerifier:
    """
    Validates transport security policies for remote feed endpoints.
    """

    def verify_transport(self, url: str, trust_profile: TrustProfile, cert_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Runs comprehensive transport security verification on target URL and optional TLS cert info.
        Returns a detailed transport verification report dict.
        """
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme.lower()
        hostname = parsed_url.hostname or ""

        report = {
            "valid": True,
            "url": url,
            "scheme": scheme,
            "hostname": hostname,
            "https_verified": False,
            "hostname_verified": False,
            "certificate_verified": False,
            "reason": "Transport security requirements satisfied",
        }

        # 1. Enforce HTTPS & Secure Transport
        reqs = trust_profile.transport_requirements
        if reqs.require_https and scheme != "https":
            report["valid"] = False
            report["reason"] = f"Insecure transport scheme '{scheme}://' rejected; HTTPS required"
            raise InsecureTransportError(report["reason"])

        report["https_verified"] = (scheme == "https")

        # 2. Validate Hostname Alignment
        expected_domain = trust_profile.expected_domain.lower() if trust_profile.expected_domain else ""
        if expected_domain:
            allowed = [expected_domain] + [d.lower() for d in reqs.allowed_domains]
            if not self._is_domain_allowed(hostname.lower(), allowed):
                report["valid"] = False
                report["reason"] = f"Hostname '{hostname}' does not match expected domain '{expected_domain}' or allowed domains"
                raise HostnameMismatchError(report["reason"])

        report["hostname_verified"] = True

        # 3. Validate TLS Certificate Metadata (if certificate info provided)
        if cert_info:
            cert_result = self.verify_certificate_info(hostname, cert_info, trust_profile)
            report["certificate_verified"] = cert_result["valid"]
            if not cert_result["valid"]:
                report["valid"] = False
                report["reason"] = cert_result["reason"]
        else:
            # If no explicit cert passed, mark verified if scheme is HTTPS
            report["certificate_verified"] = (scheme == "https")

        return report

    def verify_certificate_info(
        self, hostname: str, cert_info: Dict[str, Any], trust_profile: TrustProfile
    ) -> Dict[str, Any]:
        """
        Validates TLS certificate attributes such as expiration, subject CN/SAN, fingerprint, and issuer authority.
        """
        now = datetime.now(timezone.utc)
        result = {"valid": True, "reason": "Certificate valid"}

        # Expiration Check
        if cert_info.get("is_expired", False):
            result["valid"] = False
            result["reason"] = f"Certificate for '{hostname}' has expired"
            raise ExpiredCertificateError(result["reason"])

        not_after_str = cert_info.get("not_after")
        if not_after_str:
            try:
                not_after_dt = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                if now > not_after_dt:
                    result["valid"] = False
                    result["reason"] = f"Certificate expired at {not_after_str}"
                    raise ExpiredCertificateError(result["reason"])
            except ValueError:
                pass

        not_before_str = cert_info.get("not_before")
        if not_before_str:
            try:
                not_before_dt = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
                if now < not_before_dt:
                    result["valid"] = False
                    result["reason"] = f"Certificate not yet valid (valid from {not_before_str})"
                    raise CertificateValidationError(result["reason"])
            except ValueError:
                pass

        # Hostname Matching in CN/SAN
        subject_cn = cert_info.get("subject_cn", "").lower()
        san_list = [san.lower() for san in cert_info.get("subject_alt_names", [])]
        if subject_cn or san_list:
            all_names = ([subject_cn] if subject_cn else []) + san_list
            if not any(self._is_domain_allowed(hostname.lower(), [name]) for name in all_names):
                result["valid"] = False
                result["reason"] = f"Hostname '{hostname}' does not match certificate CN '{subject_cn}' or SANs {san_list}"
                raise HostnameMismatchError(result["reason"])

        # Expected Certificate Fingerprint Verification
        expected_cert = trust_profile.expected_certificate
        if expected_cert:
            cert_fp = cert_info.get("fingerprint") or cert_info.get("sha256") or ""
            if cert_fp and cert_fp.lower() != expected_cert.lower():
                result["valid"] = False
                result["reason"] = f"Certificate fingerprint '{cert_fp}' does not match expected '{expected_cert}'"
                raise CertificateValidationError(result["reason"])

        # Expected Signing Authority / Issuer Verification
        expected_ca = trust_profile.expected_signing_authority
        if expected_ca:
            issuer = cert_info.get("issuer") or cert_info.get("signing_authority") or ""
            if expected_ca.lower() not in issuer.lower():
                result["valid"] = False
                result["reason"] = f"Certificate issuer '{issuer}' does not match expected CA '{expected_ca}'"
                raise CertificateValidationError(result["reason"])

        return result

    def _is_domain_allowed(self, hostname: str, allowed_list: list) -> bool:
        """
        Checks if hostname matches exact allowed domain or wildcard domain (e.g., *.example.com).
        """
        if not hostname:
            return False

        for pattern in allowed_list:
            if not pattern:
                continue
            if pattern.startswith("*."):
                suffix = pattern[1:]  # e.g., .example.com
                if hostname.endswith(suffix) and hostname.count(".") == pattern.count("."):
                    return True
            elif hostname == pattern:
                return True
        return False
