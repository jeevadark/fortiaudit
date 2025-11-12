"""
Base Check Module - All audit checks inherit from BaseCheck
"""

from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a security finding"""
    check_id: str
    title: str
    description: str
    severity: Severity
    section: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'check_id': self.check_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'section': self.section,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'timestamp': self.timestamp
        }


class BaseCheck:
    """Base class for all audit checks"""
    
    section_id = "X"
    section_name = "Base Check"
    
    def __init__(self, connector, config_parser=None):
        self.connector = connector
        self.config_parser = config_parser
        self.findings: List[Finding] = []
    
    def run(self) -> List[Finding]:
        """Execute all checks - override in subclass"""
        raise NotImplementedError("Subclasses must implement run()")
    
    def add_finding(self, check_id: str, title: str, description: str,
                   severity: Severity, evidence: Optional[Dict] = None,
                   remediation: str = "", references: Optional[List[str]] = None):
        """Helper to add a finding"""
        finding = Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            section=self.section_id,
            evidence=evidence or {},
            remediation=remediation,
            references=references or []
        )
        self.findings.append(finding)
    
    def get_findings(self) -> List[Finding]:
        return self.findings
    
    def summary(self) -> Dict[str, int]:
        """Get summary by severity"""
        return {
            'critical': len([f for f in self.findings if f.severity == Severity.CRITICAL]),
            'high': len([f for f in self.findings if f.severity == Severity.HIGH]),
            'medium': len([f for f in self.findings if f.severity == Severity.MEDIUM]),
            'low': len([f for f in self.findings if f.severity == Severity.LOW]),
            'info': len([f for f in self.findings if f.severity == Severity.INFO]),
            'total': len(self.findings)
        }
