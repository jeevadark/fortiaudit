"""
Section A: Asset Discovery & Inventory
"""

from fortiaudit.checks.base_check import BaseCheck, Severity
from fortiaudit.utils.logger import get_logger

logger = get_logger(__name__)


class SectionA_Inventory(BaseCheck):
    """Section A: Asset Discovery & Inventory checks"""
    
    section_id = "A"
    section_name = "Asset Discovery & Inventory"
    
    def run(self):
        logger.info(f"Running {self.section_name} checks...")
        
        self.check_firmware_version()
        self.check_license_status()
        self.check_ha_configuration()
        self.check_interfaces()
        
        logger.info(f"Completed {self.section_name}: {len(self.findings)} findings")
        return self.findings
    
    def check_firmware_version(self):
        """A-001: Check firmware version"""
        logger.debug("Checking firmware version...")
        
        try:
            status = self.connector.get_system_status()
            version = status.get('Version', 'Unknown')
            
            if 'v' in version:
                version_parts = version.split('v')[1].split(',')[0]
                major_minor = version_parts.split('.')[0:2]
                version_number = '.'.join(major_minor)
                
                latest_versions = {
                    '7.4': '7.4.1',
                    '7.2': '7.2.6',
                    '7.0': '7.0.13',
                    '6.4': '6.4.14'
                }
                
                current_branch = version_number
                recommended = latest_versions.get(current_branch, 'Unknown')
                
                if current_branch in ['6.2', '6.0', '5.6']:
                    self.add_finding(
                        check_id="A-001",
                        title="Firmware version is end-of-life",
                        description=f"Running FortiOS {version_number} which is no longer supported",
                        severity=Severity.CRITICAL,
                        evidence={'current_version': version, 'status': 'End-of-Life'},
                        remediation=f"Upgrade to FortiOS {latest_versions['7.2']} or later"
                    )
                else:
                    self.add_finding(
                        check_id="A-001",
                        title="Firmware version checked",
                        description=f"Running FortiOS {version_number}",
                        severity=Severity.INFO,
                        evidence={'version': version}
                    )
        except Exception as e:
            logger.error(f"Failed to check firmware: {e}")
    
    def check_license_status(self):
        """A-002: Check license status"""
        logger.debug("Checking license status...")
        
        try:
            status = self.connector.get_system_status()
            license_status = status.get('License Status', 'Unknown')
            
            if 'Valid' in license_status:
                self.add_finding(
                    check_id="A-002",
                    title="Licenses are valid",
                    description="All FortiGuard licenses are active",
                    severity=Severity.INFO,
                    evidence={'license_status': license_status}
                )
            else:
                self.add_finding(
                    check_id="A-002",
                    title="License status requires attention",
                    description=f"License status: {license_status}",
                    severity=Severity.HIGH,
                    evidence={'license_status': license_status}
                )
        except Exception as e:
            logger.error(f"Failed to check license: {e}")
    
    def check_ha_configuration(self):
        """A-003: Check HA configuration"""
        logger.debug("Checking HA configuration...")
        
        try:
            result = self.connector.execute_command('get system ha status')
            
            if result['success']:
                ha_output = result['output']
                
                if 'standalone' in ha_output.lower():
                    self.add_finding(
                        check_id="A-003",
                        title="No High Availability configured",
                        description="Firewall running in standalone mode",
                        severity=Severity.MEDIUM,
                        evidence={'ha_mode': 'standalone'}
                    )
                else:
                    self.add_finding(
                        check_id="A-003",
                        title="HA configured",
                        description="High availability is configured",
                        severity=Severity.INFO,
                        evidence={'ha_mode': 'configured'}
                    )
        except Exception as e:
            logger.error(f"Failed to check HA: {e}")
    
    def check_interfaces(self):
        """A-004: Check interfaces"""
        logger.debug("Checking interfaces...")
        
        try:
            result = self.connector.execute_command('show system interface')
            
            if result['success']:
                interface_count = result['output'].count('edit ')
                
                self.add_finding(
                    check_id="A-004",
                    title=f"Found {interface_count} network interfaces",
                    description="Interface inventory completed",
                    severity=Severity.INFO,
                    evidence={'interface_count': interface_count}
                )
        except Exception as e:
            logger.error(f"Failed to check interfaces: {e}")
