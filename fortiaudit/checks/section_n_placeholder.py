"""
Section N: Placeholder

TODO: Implement checks for this section
"""

from fortiaudit.checks.base_check import BaseCheck, Severity
from fortiaudit.utils.logger import get_logger

logger = get_logger(__name__)


class SectionN_Placeholder(BaseCheck):
    """Section N: Placeholder checks"""
    
    section_id = "N"
    section_name = "Section N Placeholder"
    
    def run(self):
        logger.info(f"Running {self.section_name} checks...")
        logger.warning(f"Section N not yet implemented")
        
        # Add placeholder finding
        self.add_finding(
            check_id="N-000",
            title="Section not implemented",
            description="This section is under development",
            severity=Severity.INFO,
            evidence={'status': 'placeholder'}
        )
        
        return self.findings
