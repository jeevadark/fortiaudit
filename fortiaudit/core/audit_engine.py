"""
Audit Engine - Orchestrates the entire audit process

This is the brain that:
1. Connects to firewall
2. Runs all selected checks
3. Collects findings
4. Generates reports
"""

import json
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

from fortiaudit.core.ssh_connector import SSHConnector
from fortiaudit.core.api_connector import APIConnector
from fortiaudit.core.config_parser import ConfigParser

from fortiaudit.utils.logger import get_logger
from fortiaudit.utils.exceptions import AuditError, ConnectionError

logger = get_logger(__name__)


class AuditEngine:
    """
    Main audit orchestrator
    
    Coordinates the entire audit process from connection to report generation
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize audit engine
        
        Args:
            config: Audit configuration from wizard or file
        """
        self.config = config
        self.session_id = config.get('session_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        self.connector = None
        self.config_parser = None
        self.all_findings = []
        self.section_results = {}
        self.start_time = None
        self.end_time = None
        
        logger.info(f"Audit Engine initialized - Session: {self.session_id}")
    
    def run(self) -> Dict[str, Any]:
        """
        Execute the complete audit
        
        Returns:
            dict: Audit results summary
        """
        self.start_time = datetime.now()
        logger.info("=" * 70)
        logger.info("STARTING SECURITY AUDIT")
        logger.info("=" * 70)
        
        try:
            # Phase 1: Connection
            self._connect_to_firewall()
            
            # Phase 2: Configuration retrieval
            self._retrieve_configuration()
            
            # Phase 3: Run checks
            self._run_audit_checks()
            
            # Phase 4: Generate reports
            self._generate_reports()
            
            # Phase 5: Cleanup
            self._disconnect()
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            logger.info("=" * 70)
            logger.info(f"AUDIT COMPLETED in {duration:.1f} seconds")
            logger.info("=" * 70)
            
            return self._create_summary()
            
        except Exception as e:
            logger.error(f"Audit failed: {e}")
            self._disconnect()
            raise AuditError(f"Audit execution failed: {e}")
    
    def _connect_to_firewall(self):
        """Establish connection to firewall"""
        logger.info("\n[Phase 1/5] Connecting to firewall...")
        logger.info("-" * 70)
        
        fw_config = self.config['firewall']
        method = fw_config.get('connection_method', 'ssh')
        
        try:
            if method in ['ssh', 'both']:
                logger.info(f"Connecting via SSH to {fw_config['hostname']}...")
                self.connector = SSHConnector(
                    hostname=fw_config['hostname'],
                    username=fw_config['ssh_username'],
                    password=fw_config.get('ssh_password'),
                    key_file=fw_config.get('ssh_key_path'),
                    port=fw_config.get('ssh_port', 22),
                    timeout=30
                )
                self.connector.connect()
                logger.info("✓ SSH connection established")
                
            elif method == 'api':
                logger.info(f"Connecting via API to {fw_config['hostname']}...")
                self.connector = APIConnector(
                    hostname=fw_config['hostname'],
                    api_token=fw_config.get('api_token'),
                    username=fw_config.get('api_username'),
                    password=fw_config.get('api_password'),
                    port=fw_config.get('api_port', 443),
                    verify_ssl=fw_config.get('verify_ssl', True),
                    timeout=30
                )
                self.connector.connect()
                logger.info("✓ API connection established")
            
            # Verify connection with test command
            status = self.connector.get_system_status()
            logger.info(f"✓ Connected to {status.get('Hostname', 'Unknown')}")
            logger.info(f"  Version: {status.get('Version', 'Unknown')}")
            logger.info(f"  Serial: {status.get('Serial Number', 'Unknown')}")
            
        except ConnectionError as e:
            logger.error(f"Connection failed: {e}")
            raise
    
    def _retrieve_configuration(self):
        """Retrieve and parse firewall configuration"""
        logger.info("\n[Phase 2/5] Retrieving configuration...")
        logger.info("-" * 70)
        
        try:
            logger.info("Downloading full configuration...")
            config_text = self.connector.get_config('full')
            config_lines = len(config_text.split('\n'))
            logger.info(f"✓ Retrieved configuration ({config_lines} lines)")
            
            logger.info("Parsing configuration...")
            self.config_parser = ConfigParser(config_text)
            parsed = self.config_parser.parse()
            
            logger.info("✓ Configuration parsed successfully")
            logger.info(f"  Admin users: {len(self.config_parser.admin_users)}")
            logger.info(f"  Firewall policies: {len(self.config_parser.policies)}")
            logger.info(f"  Interfaces: {len(self.config_parser.interfaces)}")
            
            # Save config backup if requested
            if 'config_backup' in self.config['report_options']['selected_reports']:
                self._save_config_backup(config_text)
            
        except Exception as e:
            logger.error(f"Failed to retrieve configuration: {e}")
            raise
    
    def _run_audit_checks(self):
        """Run all selected audit checks"""
        logger.info("\n[Phase 3/5] Running security checks...")
        logger.info("-" * 70)
        
        selected_sections = self.config['audit_scope']['sections']
        testing_level = self.config['audit_scope'].get('testing_level', 2)
        
        logger.info(f"Selected sections: {', '.join(selected_sections)}")
        logger.info(f"Testing level: {testing_level}")
        logger.info("")
        
        # Map section IDs to check classes
        section_map = self._get_section_map()
        
        total_sections = len(selected_sections)
        for idx, section_id in enumerate(selected_sections, 1):
            logger.info(f"[{idx}/{total_sections}] Running Section {section_id}...")
            
            if section_id not in section_map:
                logger.warning(f"Section {section_id} not implemented yet, skipping...")
                continue
            
            try:
                # Instantiate check class
                CheckClass = section_map[section_id]
                check = CheckClass(self.connector, self.config_parser)
                
                # Run checks
                start = time.time()
                findings = check.run()
                duration = time.time() - start
                
                # Store results
                self.all_findings.extend(findings)
                self.section_results[section_id] = {
                    'section_name': check.section_name,
                    'findings': findings,
                    'summary': check.summary(),
                    'duration': duration
                }
                
                # Log summary
                summary = check.summary()
                logger.info(f"  ✓ Completed in {duration:.1f}s")
                logger.info(f"    Total: {summary['total']} findings")
                if summary['critical'] > 0:
                    logger.warning(f"    Critical: {summary['critical']}")
                if summary['high'] > 0:
                    logger.warning(f"    High: {summary['high']}")
                logger.info("")
                
            except Exception as e:
                logger.error(f"  ✗ Section {section_id} failed: {e}")
                continue
        
        # Overall summary
        total_findings = len(self.all_findings)
        critical = len([f for f in self.all_findings if f.severity.value == 'CRITICAL'])
        high = len([f for f in self.all_findings if f.severity.value == 'HIGH'])
        
        logger.info("=" * 70)
        logger.info("AUDIT CHECK RESULTS:")
        logger.info(f"  Total findings: {total_findings}")
        logger.info(f"  Critical: {critical}")
        logger.info(f"  High: {high}")
        logger.info("=" * 70)
    
    def _generate_reports(self):
        """Generate all requested reports"""
        logger.info("\n[Phase 4/5] Generating reports...")
        logger.info("-" * 70)
        
        selected_reports = self.config['report_options']['selected_reports']
        output_dir = Path(self.config['report_options']['output_dir'])
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Output directory: {output_dir}")
        logger.info(f"Generating {len(selected_reports)} report types...")
        logger.info("")
        
        # For now, generate simple JSON reports
        # Full report generators will be implemented later
        
        # 1. Summary JSON
        summary_file = output_dir / "audit_summary.json"
        summary_data = self._create_summary()
        with open(summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2)
        logger.info(f"✓ Generated: {summary_file}")
        
        # 2. Findings JSON
        findings_file = output_dir / "findings.json"
        findings_data = [f.to_dict() for f in self.all_findings]
        with open(findings_file, 'w') as f:
            json.dump(findings_data, f, indent=2)
        logger.info(f"✓ Generated: {findings_file}")
        
        # 3. Critical findings report
        critical_file = output_dir / "critical_findings.txt"
        with open(critical_file, 'w') as f:
            f.write("CRITICAL SECURITY FINDINGS\n")
            f.write("=" * 70 + "\n\n")
            critical = [f for f in self.all_findings if f.severity.value == 'CRITICAL']
            for finding in critical:
                f.write(f"[{finding.check_id}] {finding.title}\n")
                f.write(f"Description: {finding.description}\n")
                f.write(f"Remediation: {finding.remediation}\n")
                f.write("-" * 70 + "\n\n")
        logger.info(f"✓ Generated: {critical_file}")
        
        # 4. Section summaries
        sections_file = output_dir / "section_summaries.txt"
        with open(sections_file, 'w') as f:
            f.write("AUDIT SECTION SUMMARIES\n")
            f.write("=" * 70 + "\n\n")
            for section_id, results in self.section_results.items():
                f.write(f"Section {section_id}: {results['section_name']}\n")
                f.write(f"Duration: {results['duration']:.1f}s\n")
                summary = results['summary']
                f.write(f"Findings: {summary['total']} ")
                f.write(f"(Critical: {summary['critical']}, ")
                f.write(f"High: {summary['high']}, ")
                f.write(f"Medium: {summary['medium']}, ")
                f.write(f"Low: {summary['low']})\n")
                f.write("-" * 70 + "\n\n")
        logger.info(f"✓ Generated: {sections_file}")
        
        logger.info("")
        logger.info(f"✓ All reports saved to: {output_dir}")
    
    def _disconnect(self):
        """Disconnect from firewall"""
        logger.info("\n[Phase 5/5] Cleaning up...")
        logger.info("-" * 70)
        
        if self.connector:
            try:
                self.connector.disconnect()
                logger.info("✓ Disconnected from firewall")
            except Exception as e:
                logger.warning(f"Error during disconnect: {e}")
    
    def _save_config_backup(self, config_text: str):
        """Save configuration backup"""
        output_dir = Path(self.config['report_options']['output_dir'])
        backup_file = output_dir / "config_backup.conf"
        
        with open(backup_file, 'w') as f:
            f.write(config_text)
        
        logger.info(f"✓ Configuration backup saved: {backup_file}")
    
    def _create_summary(self) -> Dict[str, Any]:
        """Create audit summary"""
        return {
            'session_id': self.session_id,
            'firewall': {
                'hostname': self.config['firewall']['hostname'],
                'connection_method': self.config['firewall']['connection_method']
            },
            'audit_info': {
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'duration_seconds': (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else None,
                'sections_audited': list(self.section_results.keys()),
                'testing_level': self.config['audit_scope'].get('testing_level', 2)
            },
            'findings_summary': {
                'total': len(self.all_findings),
                'by_severity': {
                    'critical': len([f for f in self.all_findings if f.severity.value == 'CRITICAL']),
                    'high': len([f for f in self.all_findings if f.severity.value == 'HIGH']),
                    'medium': len([f for f in self.all_findings if f.severity.value == 'MEDIUM']),
                    'low': len([f for f in self.all_findings if f.severity.value == 'LOW']),
                    'info': len([f for f in self.all_findings if f.severity.value == 'INFO'])
                },
                'by_section': {
                    section_id: results['summary']
                    for section_id, results in self.section_results.items()
                }
            },
            'compliance': self.config.get('compliance', {}),
            'report_location': self.config['report_options']['output_dir']
        }
    
    def _get_section_map(self) -> Dict[str, type]:
        """Map section IDs to check classes"""
        section_map = {}
        
        try:
            from fortiaudit.checks.section_a_inventory import SectionA_Inventory
            section_map['A'] = SectionA_Inventory
        except ImportError:
            logger.warning("Section A not available")
        
        # Add other sections as they are implemented
        # try:
        #     from fortiaudit.checks.section_b_authentication import SectionB_Authentication
        #     section_map['B'] = SectionB_Authentication
        # except ImportError:
        #     pass
        
        return section_map
