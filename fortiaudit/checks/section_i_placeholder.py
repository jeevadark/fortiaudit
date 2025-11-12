"""
Section I: Placeholder

TODO: Implement checks for this section
"""

from fortiaudit.checks.base_check import BaseCheck, Severity
from fortiaudit.utils.logger import get_logger

logger = get_logger(__name__)


class SectionI_Placeholder(BaseCheck):
    """Section I: Placeholder checks"""
    
    section_id = "I"
    section_name = "Section I Placeholder"
    
    def run(self):
        logger.info(f"Running {self.section_name} checks...")
        logger.warning(f"Section I not yet implemented")
        
        # Add placeholder finding
        self.add_finding(
            check_id="I-000",
            title="Section not implemented",
            description="This section is under development",
            severity=Severity.INFO,
            evidence={'status': 'placeholder'}
        )
        
        return self.findings
