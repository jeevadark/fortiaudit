"""
Check modules for FortiAudit
"""

from fortiaudit.checks.base_check import BaseCheck, Severity, Finding
from fortiaudit.checks.section_a_inventory import SectionA_Inventory

# Placeholder imports (update as sections are implemented)
# from fortiaudit.checks.section_b_authentication import SectionB_Authentication
# from fortiaudit.checks.section_c_management import SectionC_Management
# ... etc

__all__ = [
    'BaseCheck',
    'Severity', 
    'Finding',
    'SectionA_Inventory',
]
