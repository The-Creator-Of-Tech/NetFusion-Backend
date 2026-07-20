"""
Core exceptions hierarchy for netfusion_intelligence.
"""

class IntelligenceException(Exception):
    """Base exception for all intelligence framework errors."""
    pass


class FeedRegistrationError(IntelligenceException):
    """Raised when a feed cannot be registered or validated during discovery."""
    pass


class FeedNotFoundError(IntelligenceException):
    """Raised when a requested feed ID is not found in the registry."""
    pass


class FeedExecutionError(IntelligenceException):
    """Raised when an error occurs during feed download or processing."""
    pass


class ChecksumVerificationError(IntelligenceException):
    """Raised when data checksum verification fails."""
    pass


class ParsingError(IntelligenceException):
    """Raised when raw feed data cannot be parsed."""
    pass


class NormalizationError(IntelligenceException):
    """Raised when parsed data fails normalization."""
    pass


class ValidationError(IntelligenceException):
    """Raised when dataset validation fails critical constraints."""
    pass


class StorageError(IntelligenceException):
    """Raised when storing normalized dataset fails."""
    pass


class DatasetActivationError(IntelligenceException):
    """Raised when dataset version activation fails."""
    pass


class RollbackError(IntelligenceException):
    """Raised when rolling back to a previous dataset version fails."""
    pass


class SchedulerError(IntelligenceException):
    """Raised when scheduler operations fail."""
    pass


class ConfigurationError(IntelligenceException):
    """Raised when invalid feed configuration is provided."""
    pass


# -------------------------------------------------------------------------
# Security & Trust Verification Exceptions
# -------------------------------------------------------------------------

class TrustVerificationError(IntelligenceException):
    """Base class for feed authenticity and trust verification errors."""
    pass


class TrustPolicyViolationError(TrustVerificationError):
    """Raised when a feed violates the active TrustPolicyEngine evaluation rules."""
    pass


class TransportSecurityError(TrustVerificationError):
    """Raised when transport security requirements are violated."""
    pass


class InsecureTransportError(TransportSecurityError):
    """Raised when insecure HTTP or prohibited transport protocols are detected."""
    pass


class CertificateValidationError(TransportSecurityError):
    """Raised when TLS certificate validation fails."""
    pass


class HostnameMismatchError(CertificateValidationError):
    """Raised when TLS certificate hostname does not match expected feed domain."""
    pass


class ExpiredCertificateError(CertificateValidationError):
    """Raised when TLS certificate has expired or is not yet valid."""
    pass


class SignatureVerificationError(TrustVerificationError):
    """Raised when cryptographic signature verification (GPG/PGP/Manifest) fails."""
    pass


class DownloadAuthenticityError(TrustVerificationError):
    """Raised when download authenticity checks fail (mirrors, unexpected domains)."""
    pass


class RedirectSecurityError(DownloadAuthenticityError):
    """Raised when unsafe HTTP downgrades or unauthorized redirects are detected."""
    pass

