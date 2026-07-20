"""
Download Authenticity & Redirect Safety Verifier for NetFusion Intelligence feeds.
Guards against malicious mirrors, HTTP protocol downgrades, and redirect attacks.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from netfusion_intelligence.core.exceptions import DownloadAuthenticityError, RedirectSecurityError
from netfusion_intelligence.security.trust_model import TrustProfile


class DownloadVerifier:
    """
    Verifies download source authenticity, hostname alignment, and redirect safety.
    """

    def verify_source(self, url: str, trust_profile: TrustProfile) -> Dict[str, Any]:
        """
        Validates target download URL against expected domain and publisher requirements.
        """
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower()

        report = {
            "valid": True,
            "url": url,
            "hostname": hostname,
            "scheme": scheme,
            "reason": "Download source authenticity verified",
        }

        # Check expected domain
        expected_domain = trust_profile.expected_domain.lower() if trust_profile.expected_domain else ""
        if expected_domain:
            allowed = [expected_domain] + [d.lower() for d in trust_profile.transport_requirements.allowed_domains]
            if not self._is_domain_allowed(hostname, allowed):
                report["valid"] = False
                report["reason"] = f"Download URL hostname '{hostname}' is not authorized. Expected domain: '{expected_domain}'"
                raise DownloadAuthenticityError(report["reason"])

        return report

    def verify_redirects(self, initial_url: str, redirect_chain: List[str], trust_profile: TrustProfile) -> Dict[str, Any]:
        """
        Inspects redirect chain for security downgrades, unauthorized mirror redirects, and loop attacks.
        """
        if not redirect_chain:
            return {"valid": True, "redirect_count": 0, "reason": "No redirects occurred"}

        reqs = trust_profile.transport_requirements
        if not reqs.allow_redirects and len(redirect_chain) > 0:
            raise RedirectSecurityError(f"Redirect attack detected: {len(redirect_chain)} redirects occurred when redirects are disabled")

        if len(redirect_chain) > 5:
            raise RedirectSecurityError(f"Excessive redirect chain detected ({len(redirect_chain)} redirects)")

        seen_urls = set([initial_url])
        initial_scheme = urlparse(initial_url).scheme.lower()
        expected_domain = trust_profile.expected_domain.lower() if trust_profile.expected_domain else ""
        allowed_domains = [expected_domain] + [d.lower() for d in reqs.allowed_domains] if expected_domain else []

        current_scheme = initial_scheme

        for redirect_url in redirect_chain:
            # Detect loops
            if redirect_url in seen_urls:
                raise RedirectSecurityError(f"Redirect loop detected at '{redirect_url}'")
            seen_urls.add(redirect_url)

            parsed_redirect = urlparse(redirect_url)
            redirect_scheme = parsed_redirect.scheme.lower()
            redirect_host = (parsed_redirect.hostname or "").lower()

            # Detect Protocol Downgrade (HTTPS -> HTTP)
            if current_scheme == "https" and redirect_scheme == "http":
                raise RedirectSecurityError(
                    f"Security Downgrade Attack detected: HTTPS '{initial_url}' redirected to insecure HTTP '{redirect_url}'"
                )

            # Detect Unauthorized Mirror / Domain Change
            if allowed_domains and not self._is_domain_allowed(redirect_host, allowed_domains):
                raise DownloadAuthenticityError(
                    f"Unauthorized mirror redirect detected: Host '{redirect_host}' is not in allowed domains list"
                )

            current_scheme = redirect_scheme

        return {
            "valid": True,
            "redirect_count": len(redirect_chain),
            "final_url": redirect_chain[-1],
            "reason": f"Redirect chain of {len(redirect_chain)} hops verified safely",
        }

    def _is_domain_allowed(self, hostname: str, allowed_list: List[str]) -> bool:
        if not hostname:
            return False
        for pattern in allowed_list:
            if not pattern:
                continue
            if pattern.startswith("*."):
                suffix = pattern[1:]
                if hostname.endswith(suffix):
                    return True
            elif hostname == pattern:
                return True
        return False
