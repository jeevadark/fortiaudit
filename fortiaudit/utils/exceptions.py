"""
Custom exceptions for FortiAudit
"""


class FortiAuditException(Exception):
    """Base exception for FortiAudit"""
    pass


class ConnectionError(FortiAuditException):
    """Raised when connection to firewall fails"""
    pass


class AuthenticationError(FortiAuditException):
    """Raised when authentication fails"""
    pass


class CommandError(FortiAuditException):
    """Raised when command execution fails"""
    pass


class ConfigurationError(FortiAuditException):
    """Raised when configuration is invalid"""
    pass


class ParsingError(FortiAuditException):
    """Raised when parsing fails"""
    pass


class APIError(FortiAuditException):
    """Raised when API request fails"""
    pass


class AuditError(FortiAuditException):
    """Raised when audit check fails"""
    pass


class ReportGenerationError(FortiAuditException):
    """Raised when report generation fails"""
    pass


class ValidationError(FortiAuditException):
    """Raised when input validation fails"""
    pass
