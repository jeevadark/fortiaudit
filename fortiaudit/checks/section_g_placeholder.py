"""
Section G: Placeholder

TODO: Implement checks for this section
"""

from fortiaudit.checks.base_check import BaseCheck, Severity
from fortiaudit.utils.logger import get_logger

logger = get_logger(__name__)


class SectionG_Placeholder(BaseCheck):
    """Section G: Placeholder checks"""
    
    section_id = "G"
    section_name = "Section G Placeholder"
    
    def run(self):
        logger.info(f"Running {self.section_name} checks...")
        logger.warning(f"Section G not yet implemented")
        
        # Add placeholder finding
        self.add_finding(
            check_id="G-000",
            title="Section not implemented",
            description="This section is under development",
            severity=Severity.INFO,
            evidence={'status': 'placeholder'}
        )
        
        return self.findings
