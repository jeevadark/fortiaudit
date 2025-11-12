"""
Core modules for FortiAudit

Provides connectivity, parsing, and orchestration functionality.
"""

from fortiaudit.core.ssh_connector import SSHConnector
from fortiaudit.core.api_connector import APIConnector
from fortiaudit.core.config_parser import ConfigParser

# AuditEngine and CredentialManager will be imported when implemented
# from fortiaudit.core.audit_engine import AuditEngine
# from fortiaudit.core.credential_manager import CredentialManager

__all__ = [
    'SSHConnector',
    'APIConnector',
    'ConfigParser',
    # 'AuditEngine',
    # 'CredentialManager',
]
