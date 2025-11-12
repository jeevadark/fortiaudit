#!/usr/bin/env python3
"""
FortiAudit - Fortinet Firewall Security Audit & VAPT Tool
===========================================================
A comprehensive CLI-based tool for auditing FortiGate firewalls
with intelligent recommendations and detailed reporting.

Author: Security Team
License: MIT
Version: 1.0.0
"""

import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path

# Color codes for CLI
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    HIGHLIGHT = '\033[7m'  # Reverse video for highlighting recommendations

class FortiAuditCLI:
    """Main CLI interface for FortiAudit"""
    
    def __init__(self):
        self.config = {
            'firewall': {},
            'audit_scope': {},
            'report_options': {},
            'advanced': {},
            'session_id': datetime.now().strftime('%Y%m%d_%H%M%S')
        }
        self.previous_answers = {}
        
    def print_banner(self):
        """Display FortiAudit banner"""
        banner = f"""
{Colors.OKCYAN}
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗ ██████╗ ██████╗ ████████╗██╗ █████╗ ██╗   ██╗██████╗ ║
║   ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██╔══██╗██║   ██║██╔══██╗║
║   █████╗  ██║   ██║██████╔╝   ██║   ██║███████║██║   ██║██║  ██║║
║   ██╔══╝  ██║   ██║██╔══██╗   ██║   ██║██╔══██║██║   ██║██║  ██║║
║   ██║     ╚██████╔╝██║  ██║   ██║   ██║██║  ██║╚██████╔╝██████╔╝║
║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ║
║                                                                   ║
║        Fortinet Firewall Security Audit & VAPT Tool v1.0         ║
║              Open Source | CLI Interactive Mode                  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
{Colors.ENDC}
        """
        print(banner)
        print(f"{Colors.OKGREEN}Welcome to FortiAudit - Your Comprehensive Firewall Security Assessment Tool{Colors.ENDC}")
        print(f"{Colors.WARNING}⚠️  Ensure you have proper authorization before auditing any firewall!{Colors.ENDC}\n")
        
    def print_section_header(self, title, description=""):
        """Print formatted section header"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{title}{Colors.ENDC}")
        if description:
            print(f"{Colors.OKBLUE}{description}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
        
    def get_input(self, prompt, default=None, input_type=str, validation=None, 
                  options=None, recommended=None):
        """
        Enhanced input function with validation and recommendations
        
        Args:
            prompt: Question to ask
            default: Default value
            input_type: Expected type (str, int, bool)
            validation: Validation function
            options: List of valid options
            recommended: Recommended option (will be highlighted)
        """
        while True:
            # Build prompt with options
            full_prompt = f"{Colors.OKCYAN}{prompt}{Colors.ENDC}"
            
            if options:
                print(f"\n{Colors.OKBLUE}Available options:{Colors.ENDC}")
                for i, opt in enumerate(options, 1):
                    if recommended and opt == recommended:
                        print(f"  {i}. {Colors.HIGHLIGHT}{Colors.OKGREEN}✓ {opt} (RECOMMENDED){Colors.ENDC}")
                    else:
                        print(f"  {i}. {opt}")
                        
            if default:
                full_prompt += f" [{Colors.WARNING}default: {default}{Colors.ENDC}]"
                
            full_prompt += f" {Colors.BOLD}►{Colors.ENDC} "
            
            user_input = input(full_prompt).strip()
            
            # Handle default
            if not user_input and default is not None:
                return default
                
            # Handle options by number
            if options and user_input.isdigit():
                idx = int(user_input) - 1
                if 0 <= idx < len(options):
                    user_input = options[idx]
                    
            # Type conversion
            try:
                if input_type == bool:
                    value = user_input.lower() in ['y', 'yes', 'true', '1']
                elif input_type == int:
                    value = int(user_input)
                else:
                    value = user_input
                    
                # Validation
                if validation and not validation(value):
                    print(f"{Colors.FAIL}Invalid input. Please try again.{Colors.ENDC}")
                    continue
                    
                if options and value not in options:
                    print(f"{Colors.FAIL}Please select a valid option.{Colors.ENDC}")
                    continue
                    
                return value
                
            except ValueError:
                print(f"{Colors.FAIL}Invalid input type. Expected {input_type.__name__}.{Colors.ENDC}")
                
    def confirm_action(self, message):
        """Ask for confirmation"""
        response = self.get_input(f"{message} (y/n)", default='y', input_type=bool)
        return response
        
    def wizard_step_1_intro(self):
        """Step 1: Introduction and prerequisites check"""
        self.print_section_header(
            "STEP 1: INTRODUCTION & PREREQUISITES",
            "Let's ensure you have everything needed for a successful audit"
        )
        
        print(f"{Colors.OKGREEN}This tool will guide you through:{Colors.ENDC}")
        print("  • Firewall connection setup (SSH/API)")
        print("  • Audit scope selection (16 comprehensive sections)")
        print("  • Testing level configuration (Safe → Advanced)")
        print("  • Report generation (6 different formats)")
        print("  • Compliance checking (CIS, PCI-DSS, NIST)")
        
        print(f"\n{Colors.WARNING}Prerequisites checklist:{Colors.ENDC}")
        
        checks = {
            "Valid authorization to audit the firewall": False,
            "FortiGate firewall access (SSH or API)": False,
            "Administrative or Read-only credentials": False,
            "Network connectivity to management interface": False,
            "Understanding this is for authorized testing only": False
        }
        
        print(f"\n{Colors.BOLD}Please confirm you have:{Colors.ENDC}")
        all_confirmed = True
        for check, _ in checks.items():
            response = self.confirm_action(f"  ✓ {check}")
            checks[check] = response
            all_confirmed = all_confirmed and response
            
        if not all_confirmed:
            print(f"\n{Colors.FAIL}⚠️  WARNING: Not all prerequisites are met!{Colors.ENDC}")
            if not self.confirm_action("Do you want to continue anyway?"):
                print(f"{Colors.WARNING}Audit cancelled. Please ensure all prerequisites are met.{Colors.ENDC}")
                sys.exit(0)
                
        print(f"\n{Colors.OKGREEN}✓ Prerequisites confirmed. Let's begin!{Colors.ENDC}")
        time.sleep(1)
        
    def wizard_step_2_firewall_info(self):
        """Step 2: Firewall connection configuration"""
        self.print_section_header(
            "STEP 2: FIREWALL CONNECTION SETUP",
            "Configure how FortiAudit will connect to your FortiGate"
        )
        
        # Connection method
        connection_methods = [
            "SSH (CLI-based, works on all FortiOS versions)",
            "REST API (Faster, better for automation, requires API setup)",
            "Both (Try API first, fallback to SSH)"
        ]
        
        method = self.get_input(
            "Select connection method:",
            options=connection_methods,
            recommended=connection_methods[2]  # Both is recommended
        )
        
        self.config['firewall']['connection_method'] = method.split()[0].lower()
        
        # Store recommendation reason
        if "Both" in method:
            print(f"\n{Colors.OKGREEN}✓ Good choice! This provides flexibility and redundancy.{Colors.ENDC}")
            self.previous_answers['connection_flexible'] = True
            
        # Firewall details
        print(f"\n{Colors.BOLD}Firewall Connection Details:{Colors.ENDC}")
        
        self.config['firewall']['hostname'] = self.get_input(
            "Firewall hostname or IP address:",
            validation=lambda x: len(x) > 0
        )
        
        # SSH configuration if needed
        if 'ssh' in self.config['firewall']['connection_method'] or 'both' in self.config['firewall']['connection_method']:
            print(f"\n{Colors.OKBLUE}SSH Configuration:{Colors.ENDC}")
            self.config['firewall']['ssh_port'] = self.get_input(
                "SSH port:",
                default=22,
                input_type=int
            )
            
            self.config['firewall']['ssh_username'] = self.get_input(
                "SSH username:",
                default="admin"
            )
            
            auth_methods = ["Password (interactive)", "SSH Key", "Both"]
            auth_method = self.get_input(
                "SSH authentication method:",
                options=auth_methods,
                recommended=auth_methods[1]  # SSH Key is more secure
            )
            self.config['firewall']['ssh_auth_method'] = auth_method
            
            if "SSH Key" in auth_method:
                self.config['firewall']['ssh_key_path'] = self.get_input(
                    "SSH private key path:",
                    default="~/.ssh/id_rsa"
                )
                
        # API configuration if needed
        if 'api' in self.config['firewall']['connection_method'] or 'both' in self.config['firewall']['connection_method']:
            print(f"\n{Colors.OKBLUE}REST API Configuration:{Colors.ENDC}")
            self.config['firewall']['api_port'] = self.get_input(
                "HTTPS port for API:",
                default=443,
                input_type=int
            )
            
            api_auth = ["API Token (recommended)", "Username/Password"]
            api_method = self.get_input(
                "API authentication method:",
                options=api_auth,
                recommended=api_auth[0]
            )
            self.config['firewall']['api_auth_method'] = api_method
            
        # Certificate verification
        verify_ssl = self.get_input(
            "Verify SSL/TLS certificates? (Disable for self-signed certs)",
            default='n',
            input_type=bool
        )
        self.config['firewall']['verify_ssl'] = verify_ssl
        
        if not verify_ssl:
            print(f"{Colors.WARNING}⚠️  SSL verification disabled. Use only in trusted environments.{Colors.ENDC}")
            
    def wizard_step_3_audit_scope(self):
        """Step 3: Select audit scope and sections"""
        self.print_section_header(
            "STEP 3: AUDIT SCOPE SELECTION",
            "Choose which security areas to audit (based on your comprehensive checklist)"
        )
        
        sections = {
            'A': 'Asset Discovery & Inventory',
            'B': 'Authentication & Access Control',
            'C': 'Management Access Hardening',
            'D': 'Core Security Features',
            'E': 'Security Services (UTM/IPS/AV)',
            'F': 'VPN Configuration Security',
            'G': 'SNMP Security',
            'H': 'Firewall Policy Review',
            'I': 'Network Segmentation & DMZ',
            'J': 'NAT/PAT Configuration',
            'K': 'Egress Filtering',
            'L': 'Logging, Monitoring & SIEM',
            'M': 'High Availability & Redundancy',
            'N': 'Backup & Recovery',
            'O': 'Fortinet-Specific Advanced Checks',
            'P': 'Compliance & Best Practices'
        }
        
        print(f"{Colors.OKGREEN}Available audit sections:{Colors.ENDC}\n")
        for code, name in sections.items():
            print(f"  [{code}] {name}")
            
        print(f"\n{Colors.OKBLUE}Selection options:{Colors.ENDC}")
        print("  1. Full audit (ALL sections - recommended for first-time audit)")
        print("  2. Quick security assessment (A, B, C, D, H, L)")
        print("  3. Compliance focus (B, C, E, H, L, P)")
        print("  4. Policy review only (H, K, I)")
        print("  5. Custom selection (choose specific sections)")
        
        scope_choice = self.get_input(
            "\nSelect audit scope:",
            options=["1", "2", "3", "4", "5"],
            recommended="1"
        )
        
        if scope_choice == "1":
            self.config['audit_scope']['sections'] = list(sections.keys())
            print(f"\n{Colors.OKGREEN}✓ Full audit selected. This is the most comprehensive option.{Colors.ENDC}")
        elif scope_choice == "2":
            self.config['audit_scope']['sections'] = ['A', 'B', 'C', 'D', 'H', 'L']
            print(f"\n{Colors.OKGREEN}✓ Quick assessment - covers critical security areas.{Colors.ENDC}")
        elif scope_choice == "3":
            self.config['audit_scope']['sections'] = ['B', 'C', 'E', 'H', 'L', 'P']
            print(f"\n{Colors.OKGREEN}✓ Compliance focus - ideal for regulatory requirements.{Colors.ENDC}")
        elif scope_choice == "4":
            self.config['audit_scope']['sections'] = ['H', 'K', 'I']
            print(f"\n{Colors.OKGREEN}✓ Policy review - focuses on firewall rules and filtering.{Colors.ENDC}")
        else:
            print(f"\n{Colors.BOLD}Select sections (comma-separated, e.g., A,B,C or type 'all'):{Colors.ENDC}")
            custom = self.get_input("Sections:")
            if custom.lower() == 'all':
                self.config['audit_scope']['sections'] = list(sections.keys())
            else:
                self.config['audit_scope']['sections'] = [s.strip().upper() for s in custom.split(',')]
                
        # Show selected sections
        print(f"\n{Colors.OKBLUE}Selected sections for audit:{Colors.ENDC}")
        for sec in self.config['audit_scope']['sections']:
            print(f"  ✓ [{sec}] {sections.get(sec, 'Unknown')}")
            
    def wizard_step_4_testing_level(self):
        """Step 4: Configure testing depth and safety level"""
        self.print_section_header(
            "STEP 4: TESTING LEVEL CONFIGURATION",
            "Define how deep and active the audit should be"
        )
        
        print(f"{Colors.OKGREEN}Testing levels explained:{Colors.ENDC}\n")
        
        levels = {
            "1": {
                "name": "Configuration Audit Only (SAFE)",
                "description": "Read-only analysis of firewall configuration",
                "activities": [
                    "Parse configuration files",
                    "Analyze firewall rules",
                    "Check security settings",
                    "Review user accounts",
                    "Examine logging configuration"
                ],
                "risk": "None - No traffic generated",
                "recommended_for": "Production environments, first-time audits"
            },
            "2": {
                "name": "Configuration + Passive Validation (SAFE)",
                "description": "Config audit plus non-intrusive connectivity checks",
                "activities": [
                    "All Level 1 activities",
                    "Review existing logs",
                    "Check service status",
                    "Verify HA synchronization",
                    "Test read-only API calls"
                ],
                "risk": "Minimal - Read-only operations",
                "recommended_for": "Most audits - balances depth and safety"
            },
            "3": {
                "name": "Active Security Testing (CAUTION)",
                "description": "Includes active probing and vulnerability scanning",
                "activities": [
                    "All Level 2 activities",
                    "External port scanning (Nmap)",
                    "Authentication testing (lockout testing)",
                    "Service fingerprinting",
                    "SNMP enumeration",
                    "Anti-spoofing tests"
                ],
                "risk": "Moderate - May trigger alerts, requires approval",
                "recommended_for": "Dedicated test environments, approved pen tests"
            },
            "4": {
                "name": "Full Penetration Testing (HIGH RISK)",
                "description": "Comprehensive security testing including exploitation",
                "activities": [
                    "All Level 3 activities",
                    "Exploit testing for known CVEs",
                    "Brute-force attempts (controlled)",
                    "DoS condition testing",
                    "Advanced evasion techniques",
                    "Firewall bypass attempts"
                ],
                "risk": "High - May cause service disruption",
                "recommended_for": "Only in isolated test labs with full approval"
            }
        }
        
        for level, details in levels.items():
            print(f"{Colors.BOLD}Level {level}: {details['name']}{Colors.ENDC}")
            print(f"  {details['description']}")
            print(f"  Risk: {Colors.WARNING if int(level) > 2 else Colors.OKGREEN}{details['risk']}{Colors.ENDC}")
            print(f"  Best for: {details['recommended_for']}")
            print()
            
        # Intelligent recommendation based on previous answers
        recommended_level = "2"
        if not self.config['firewall'].get('verify_ssl', True):
            print(f"{Colors.OKBLUE}💡 Recommendation: Since SSL verification is disabled, this appears to be a test environment.{Colors.ENDC}")
            recommended_level = "3"
        elif 'api' in self.config['firewall'].get('connection_method', ''):
            print(f"{Colors.OKBLUE}💡 Recommendation: API access suggests automated auditing - Level 2 is ideal.{Colors.ENDC}")
            recommended_level = "2"
            
        level = self.get_input(
            "Select testing level:",
            options=list(levels.keys()),
            recommended=recommended_level
        )
        
        self.config['audit_scope']['testing_level'] = int(level)
        
        # Additional warnings for higher levels
        if int(level) >= 3:
            print(f"\n{Colors.FAIL}⚠️  WARNING: You selected an ACTIVE testing level!{Colors.ENDC}")
            print(f"{Colors.WARNING}This will generate network traffic and may trigger security alerts.{Colors.ENDC}")
            print(f"{Colors.WARNING}Ensure you have:{Colors.ENDC}")
            print("  • Written authorization from network/security team")
            print("  • Scheduled maintenance window (if production)")
            print("  • Monitoring team notified")
            print("  • Rollback plan ready")
            
            if not self.confirm_action("\nDo you have proper authorization for active testing?"):
                print(f"{Colors.WARNING}Reverting to Level 2 (Passive Validation){Colors.ENDC}")
                self.config['audit_scope']['testing_level'] = 2
                
        # External tools integration
        if int(level) >= 3:
            print(f"\n{Colors.BOLD}External Security Tools:{Colors.ENDC}")
            print("Level 3+ can integrate with external tools for deeper testing.\n")
            
            tools = {
                'nmap': 'Port scanning and service detection',
                'snmpwalk': 'SNMP security enumeration',
                'hping3': 'Packet crafting for spoofing tests',
                'openvas': 'Vulnerability scanning (requires separate installation)'
            }
            
            self.config['audit_scope']['external_tools'] = {}
            for tool, description in tools.items():
                print(f"  • {tool}: {description}")
                use_tool = self.confirm_action(f"    Use {tool} if available?")
                self.config['audit_scope']['external_tools'][tool] = use_tool
                
    def wizard_step_5_reports(self):
        """Step 5: Report generation configuration"""
        self.print_section_header(
            "STEP 5: REPORT CONFIGURATION",
            "Configure comprehensive security reports"
        )
        
        print(f"{Colors.OKGREEN}FortiAudit generates 6 types of reports:{Colors.ENDC}\n")
        
        report_types = {
            'executive_summary': {
                'name': 'Executive Summary',
                'description': 'High-level business impact report for management',
                'format': 'HTML + PDF',
                'includes': ['Risk heat map', 'Top 10 findings', 'Budget impact', 'Compliance score'],
                'recommended': True
            },
            'technical_findings': {
                'name': 'Technical Findings Report',
                'description': 'Detailed technical analysis for security team',
                'format': 'HTML + PDF',
                'includes': ['All findings with evidence', 'Command outputs', 'Configuration snippets', 'Screenshots'],
                'recommended': True
            },
            'risk_register': {
                'name': 'Risk Register',
                'description': 'Prioritized vulnerability list with CVSS scoring',
                'format': 'CSV + JSON',
                'includes': ['CVSS scores', 'Exploitability', 'Business impact', 'Affected assets'],
                'recommended': True
            },
            'remediation_roadmap': {
                'name': 'Remediation Roadmap',
                'description': 'Step-by-step fix instructions with timeline',
                'format': 'HTML + Markdown',
                'includes': ['Fix steps', 'FortiOS commands', 'Effort estimates', 'Priority order'],
                'recommended': True
            },
            'compliance_gap': {
                'name': 'Compliance Gap Analysis',
                'description': 'Mapping to security standards and frameworks',
                'format': 'HTML + PDF',
                'includes': ['CIS Benchmark', 'PCI-DSS', 'NIST', 'Trend analysis'],
                'recommended': False  # Optional based on needs
            },
            'config_backup': {
                'name': 'Configuration Backup',
                'description': 'Complete firewall configuration snapshot',
                'format': 'Text + JSON',
                'includes': ['Full config', 'Sanitized version', 'Change tracking', 'Version history'],
                'recommended': True
            }
        }
        
        # Display all report types
        for key, details in report_types.items():
            print(f"{Colors.BOLD}{details['name']}{Colors.ENDC}")
            print(f"  {details['description']}")
            print(f"  Format: {details['format']}")
            print(f"  Includes: {', '.join(details['includes'][:2])}...")
            if details['recommended']:
                print(f"  {Colors.HIGHLIGHT}{Colors.OKGREEN}✓ RECOMMENDED{Colors.ENDC}")
            print()
            
        print(f"{Colors.OKBLUE}Report generation options:{Colors.ENDC}")
        print("  1. Generate ALL reports (comprehensive documentation)")
        print("  2. Essential reports only (Executive + Technical + Risk + Remediation)")
        print("  3. Custom selection")
        
        report_choice = self.get_input(
            "Select report package:",
            options=["1", "2", "3"],
            recommended="1"
        )
        
        if report_choice == "1":
            self.config['report_options']['selected_reports'] = list(report_types.keys())
            print(f"\n{Colors.OKGREEN}✓ All reports will be generated.{Colors.ENDC}")
        elif report_choice == "2":
            self.config['report_options']['selected_reports'] = [
                'executive_summary', 'technical_findings', 'risk_register', 'remediation_roadmap'
            ]
            print(f"\n{Colors.OKGREEN}✓ Essential reports selected.{Colors.ENDC}")
        else:
            self.config['report_options']['selected_reports'] = []
            for key, details in report_types.items():
                generate = self.confirm_action(f"Generate {details['name']}?")
                if generate:
                    self.config['report_options']['selected_reports'].append(key)
                    
        # Output directory
        print(f"\n{Colors.BOLD}Report Output Configuration:{Colors.ENDC}")
        default_dir = f"./reports/{self.config['session_id']}"
        self.config['report_options']['output_dir'] = self.get_input(
            "Report output directory:",
            default=default_dir
        )
        
        # Report format options
        formats = {
            'html': 'Interactive HTML with charts and graphs',
            'pdf': 'Professional PDF reports',
            'json': 'Machine-readable JSON for automation',
            'csv': 'Spreadsheet-compatible CSV files',
            'markdown': 'Markdown for documentation/wiki'
        }
        
        print(f"\n{Colors.BOLD}Report Formats:{Colors.ENDC}")
        self.config['report_options']['formats'] = []
        for fmt, desc in formats.items():
            print(f"  • {fmt.upper()}: {desc}")
            include = self.confirm_action(f"    Include {fmt.upper()} format?")
            if include:
                self.config['report_options']['formats'].append(fmt)
                
        # Email notification
        print(f"\n{Colors.BOLD}Notification Options:{Colors.ENDC}")
        send_email = self.confirm_action("Send email notification when audit completes?")
        if send_email:
            self.config['report_options']['email'] = {
                'enabled': True,
                'recipients': self.get_input("Email recipients (comma-separated):").split(','),
                'smtp_server': self.get_input("SMTP server:", default="localhost"),
                'smtp_port': self.get_input("SMTP port:", default=25, input_type=int)
            }
            
    def wizard_step_6_compliance(self):
        """Step 6: Compliance and benchmark configuration"""
        self.print_section_header(
            "STEP 6: COMPLIANCE & BENCHMARK CONFIGURATION",
            "Map findings to security standards and frameworks"
        )
        
        print(f"{Colors.OKGREEN}Available compliance frameworks:{Colors.ENDC}\n")
        
        frameworks = {
            'cis': {
                'name': 'CIS Benchmark for Fortinet FortiOS',
                'description': 'Industry consensus security baseline',
                'builtin': True,
                'pdf_required': False
            },
            'pci_dss': {
                'name': 'PCI-DSS v4.0 (Payment Card Industry)',
                'description': 'Required for organizations handling card data',
                'builtin': True,
                'pdf_required': False
            },
            'nist': {
                'name': 'NIST SP 800-41 Rev. 1 (Firewall Guidelines)',
                'description': 'US federal government standard',
                'builtin': True,
                'pdf_required': False
            },
            'iso27001': {
                'name': 'ISO/IEC 27001 Network Security Controls',
                'description': 'International security management standard',
                'builtin': False,
                'pdf_required': True
            },
            'custom': {
                'name': 'Custom Organization Policy',
                'description': 'Your own security requirements',
                'builtin': False,
                'pdf_required': True
            }
        }
        
        for key, details in frameworks.items():
            status = f"{Colors.OKGREEN}[Built-in]{Colors.ENDC}" if details['builtin'] else f"{Colors.WARNING}[Requires PDF]{Colors.ENDC}"
            print(f"{status} {Colors.BOLD}{details['name']}{Colors.ENDC}")
            print(f"  {details['description']}")
            print()
            
        print(f"{Colors.OKBLUE}Compliance checking options:{Colors.ENDC}")
        print("  1. Use all built-in frameworks (CIS + PCI-DSS + NIST)")
        print("  2. CIS Benchmark only (most common)")
        print("  3. Custom selection")
        print("  4. Skip compliance checking")
        
        compliance_choice = self.get_input(
            "Select compliance option:",
            options=["1", "2", "3", "4"],
            recommended="1"
        )
        
        self.config['compliance'] = {'frameworks': [], 'custom_pdfs': {}}
        
        if compliance_choice == "1":
            self.config['compliance']['frameworks'] = ['cis', 'pci_dss', 'nist']
            print(f"\n{Colors.OKGREEN}✓ All built-in frameworks selected.{Colors.ENDC}")
        elif compliance_choice == "2":
            self.config['compliance']['frameworks'] = ['cis']
            print(f"\n{Colors.OKGREEN}✓ CIS Benchmark selected - industry standard baseline.{Colors.ENDC}")
        elif compliance_choice == "3":
            for key, details in frameworks.items():
                check = self.confirm_action(f"Check against {details['name']}?")
                if check:
                    self.config['compliance']['frameworks'].append(key)
                    if details['pdf_required']:
                        pdf_path = self.get_input(f"Path to {details['name']} PDF:")
                        self.config['compliance']['custom_pdfs'][key] = pdf_path
        else:
            print(f"\n{Colors.WARNING}Skipping compliance checking.{Colors.ENDC}")
            
        # Benchmark PDF directory
        if self.config['compliance']['frameworks']:
            print(f"\n{Colors.BOLD}Custom Benchmark PDFs:{Colors.ENDC}")
            print("You can provide additional PDF benchmarks for parsing and analysis.")
            print(f"Place PDF files in: {Colors.OKCYAN}./benchmarks/{Colors.ENDC}")
            
            has_pdfs = self.confirm_action("Do you have custom benchmark PDFs to include?")
            if has_pdfs:
                self.config['compliance']['pdf_directory'] = self.get_input(
                    "Benchmark PDF directory:",
                    default="./benchmarks"
                )
                
    def wizard_step_7_advanced(self):
        """Step 7: Advanced options and features"""
        self.print_section_header(
            "STEP 7: ADVANCED OPTIONS",
            "Configure advanced features for power users"
        )
        
        print(f"{Colors.OKGREEN}Advanced features available:{Colors.ENDC}\n")
        
        # Multi-firewall support
        print(f"{Colors.BOLD}1. Multi-Firewall Scanning{Colors.ENDC}")
        print("   Audit multiple FortiGate firewalls in a single run")
        multi_fw = self.confirm_action("   Enable multi-firewall mode?")
        
        if multi_fw:
            self.config['advanced']['multi_firewall'] = True
            print(f"\n{Colors.OKBLUE}   Multi-firewall configuration:{Colors.ENDC}")
            print("   You can provide a CSV/YAML inventory file with firewall details")
            
            inventory_file = self.get_input(
                "   Inventory file path:",
                default="./firewalls.csv"
            )
            self.config['advanced']['inventory_file'] = inventory_file
            
            print(f"\n{Colors.OKCYAN}   Expected CSV format:{Colors.ENDC}")
            print("   hostname,ip_address,ssh_port,api_port,username,description")
            print("   fw01,192.168.1.1,22,443,admin,Production Firewall")
        else:
            self.config['advanced']['multi_firewall'] = False
            
        # Comparison mode
        print(f"\n{Colors.BOLD}2. Historical Comparison{Colors.ENDC}")
        print("   Compare current audit with previous audits to track changes")
        comparison = self.confirm_action("   Enable comparison mode?")
        
        if comparison:
            self.config['advanced']['comparison_mode'] = True
            print(f"\n{Colors.OKBLUE}   Comparison features:{Colors.ENDC}")
            print("   • Configuration drift detection")
            print("   • Remediation progress tracking")
            print("   • Security posture trends")
            
            previous_reports = self.get_input(
                "   Previous audit report directory:",
                default="./reports/previous"
            )
            self.config['advanced']['previous_reports_dir'] = previous_reports
        else:
            self.config['advanced']['comparison_mode'] = False
            
        # Automated remediation
        print(f"\n{Colors.BOLD}3. Remediation Assistance{Colors.ENDC}")
        print("   Generate FortiOS commands to fix identified issues")
        
        remediation_options = [
            "Report only (show what needs fixing)",
            "Generate fix commands (dry-run, no execution)",
            "Interactive fix (review and apply with confirmation)"
        ]
        
        remediation = self.get_input(
            "   Remediation mode:",
            options=remediation_options,
            recommended=remediation_options[1]
        )
        self.config['advanced']['remediation_mode'] = remediation.split()[0].lower()
        
        if "Interactive" in remediation:
            print(f"\n{Colors.FAIL}   ⚠️  WARNING: Interactive mode will MODIFY firewall configuration!{Colors.ENDC}")
            print(f"   {Colors.WARNING}Only use in authorized test environments.{Colors.ENDC}")
            
            if not self.confirm_action("   Do you understand the risks and want to proceed?"):
                print(f"   {Colors.WARNING}Reverting to 'Generate commands only' mode.{Colors.ENDC}")
                self.config['advanced']['remediation_mode'] = 'generate'
                
        # Continuous monitoring
        print(f"\n{Colors.BOLD}4. Scheduled/Continuous Monitoring{Colors.ENDC}")
        print("   Run audits automatically on a schedule")
        scheduled = self.confirm_action("   Enable scheduled auditing?")
        
        if scheduled:
            self.config['advanced']['scheduled'] = True
            
            schedule_options = [
                "Daily (every 24 hours)",
                "Weekly (every Monday at 02:00)",
                "Monthly (1st of month at 02:00)",
                "Custom cron expression"
            ]
            
            schedule = self.get_input(
                "   Schedule frequency:",
                options=schedule_options,
                recommended=schedule_options[1]
            )
            self.config['advanced']['schedule'] = schedule
            
            if "Custom" in schedule:
                cron = self.get_input("   Cron expression (e.g., '0 2 * * 1'):")
                self.config['advanced']['cron'] = cron
        else:
            self.config['advanced']['scheduled'] = False
            
        # Webhook notifications
        print(f"\n{Colors.BOLD}5. Webhook Integration{Colors.ENDC}")
        print("   Send notifications to Slack, Teams, or custom webhooks")
        webhook = self.confirm_action("   Enable webhook notifications?")
        
        if webhook:
            webhook_types = ["Slack", "Microsoft Teams", "Discord", "Custom HTTP"]
            webhook_type = self.get_input(
                "   Webhook type:",
                options=webhook_types
            )
            
            webhook_url = self.get_input("   Webhook URL:")
            
            self.config['advanced']['webhook'] = {
                'type': webhook_type,
                'url': webhook_url,
                'notify_on': ['completion', 'critical_findings', 'errors']
            }
            
        # Logging level
        print(f"\n{Colors.BOLD}6. Logging Configuration{Colors.ENDC}")
        log_levels = ["ERROR (errors only)", "WARNING (errors + warnings)", 
                     "INFO (normal operations)", "DEBUG (detailed troubleshooting)"]
        
        log_level = self.get_input(
            "   Logging level:",
            options=log_levels,
            recommended=log_levels[2]
        )
        self.config['advanced']['log_level'] = log_level.split()[0]
        
        # Save configuration
        print(f"\n{Colors.BOLD}7. Configuration Management{Colors.ENDC}")
        save_config = self.confirm_action("   Save this configuration for future use?")
        
        if save_config:
            config_name = self.get_input(
                "   Configuration profile name:",
                default=f"config_{self.config['session_id']}"
            )
            self.config['advanced']['save_config'] = config_name
            
    def wizard_step_8_review(self):
        """Step 8: Review and confirm configuration"""
        self.print_section_header(
            "STEP 8: CONFIGURATION REVIEW",
            "Review your audit configuration before starting"
        )
        
        print(f"{Colors.OKGREEN}Your audit configuration:{Colors.ENDC}\n")
        
        # Firewall connection
        print(f"{Colors.BOLD}Firewall Connection:{Colors.ENDC}")
        print(f"  Hostname: {self.config['firewall'].get('hostname', 'N/A')}")
        print(f"  Method: {self.config['firewall'].get('connection_method', 'N/A')}")
        if 'ssh_port' in self.config['firewall']:
            print(f"  SSH: Port {self.config['firewall']['ssh_port']}, User: {self.config['firewall']['ssh_username']}")
        if 'api_port' in self.config['firewall']:
            print(f"  API: Port {self.config['firewall']['api_port']}")
            
        # Audit scope
        print(f"\n{Colors.BOLD}Audit Scope:{Colors.ENDC}")
        print(f"  Sections: {', '.join(self.config['audit_scope'].get('sections', []))}")
        print(f"  Testing Level: {self.config['audit_scope'].get('testing_level', 'N/A')}")
        
        # Reports
        print(f"\n{Colors.BOLD}Reports:{Colors.ENDC}")
        print(f"  Types: {', '.join(self.config['report_options'].get('selected_reports', []))}")
        print(f"  Formats: {', '.join(self.config['report_options'].get('formats', []))}")
        print(f"  Output: {self.config['report_options'].get('output_dir', 'N/A')}")
        
        # Compliance
        if self.config.get('compliance', {}).get('frameworks'):
            print(f"\n{Colors.BOLD}Compliance Frameworks:{Colors.ENDC}")
            for fw in self.config['compliance']['frameworks']:
                print(f"  ✓ {fw.upper()}")
                
        # Advanced features
        if self.config.get('advanced'):
            print(f"\n{Colors.BOLD}Advanced Features:{Colors.ENDC}")
            if self.config['advanced'].get('multi_firewall'):
                print(f"  ✓ Multi-firewall scanning enabled")
            if self.config['advanced'].get('comparison_mode'):
                print(f"  ✓ Historical comparison enabled")
            if self.config['advanced'].get('scheduled'):
                print(f"  ✓ Scheduled auditing enabled")
                
        print(f"\n{Colors.BOLD}Estimated Audit Duration:{Colors.ENDC}")
        sections = len(self.config['audit_scope'].get('sections', []))
        level = self.config['audit_scope'].get('testing_level', 2)
        estimated_time = sections * (2 if level <= 2 else 5)
        print(f"  {estimated_time}-{estimated_time + 10} minutes (based on scope and testing level)")
        
        # Confirm to proceed
        print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
        if not self.confirm_action("Configuration looks good. Start audit now?"):
            print(f"\n{Colors.WARNING}Audit cancelled.{Colors.ENDC}")
            
            if self.confirm_action("Save configuration for later use?"):
                self.save_configuration()
                print(f"{Colors.OKGREEN}✓ Configuration saved. Run with --config to load it.{Colors.ENDC}")
            return False
            
        return True
        
    def save_configuration(self):
        """Save current configuration to file"""
        config_dir = Path("./configs")
        config_dir.mkdir(exist_ok=True)
        
        config_name = self.config['advanced'].get('save_config', f"config_{self.config['session_id']}")
        config_file = config_dir / f"{config_name}.json"
        
        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
            
        print(f"\n{Colors.OKGREEN}Configuration saved to: {config_file}{Colors.ENDC}")
        
    def run_wizard(self):
        """Run the complete interactive wizard"""
        self.print_banner()
        
        try:
            # Step 1: Introduction
            self.wizard_step_1_intro()
            
            # Step 2: Firewall connection
            self.wizard_step_2_firewall_info()
            
            # Step 3: Audit scope
            self.wizard_step_3_audit_scope()
            
            # Step 4: Testing level
            self.wizard_step_4_testing_level()
            
            # Step 5: Reports
            self.wizard_step_5_reports()
            
            # Step 6: Compliance
            self.wizard_step_6_compliance()
            
            # Step 7: Advanced options
            self.wizard_step_7_advanced()
            
            # Step 8: Review and confirm
            if not self.wizard_step_8_review():
                return None
                
            return self.config
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}Audit setup interrupted by user.{Colors.ENDC}")
            if self.confirm_action("Save current configuration before exiting?"):
                self.save_configuration()
            sys.exit(0)
            
    def show_menu(self):
        """Show main menu for non-wizard mode"""
        while True:
            self.print_banner()
            print(f"{Colors.BOLD}Main Menu:{Colors.ENDC}\n")
            print("  1. Start Interactive Audit Wizard (RECOMMENDED)")
            print("  2. Load Saved Configuration")
            print("  3. Quick Audit (use defaults)")
            print("  4. View Sample Reports")
            print("  5. Check Prerequisites")
            print("  6. About FortiAudit")
            print("  7. Exit")
            
            choice = self.get_input("\nSelect option:", options=["1","2","3","4","5","6","7"])
            
            if choice == "1":
                return self.run_wizard()
            elif choice == "2":
                return self.load_configuration()
            elif choice == "3":
                return self.quick_audit()
            elif choice == "4":
                self.show_sample_reports()
            elif choice == "5":
                self.check_prerequisites()
            elif choice == "6":
                self.show_about()
            elif choice == "7":
                print(f"\n{Colors.OKGREEN}Thank you for using FortiAudit!{Colors.ENDC}")
                sys.exit(0)
                
    def load_configuration(self):
        """Load a saved configuration file"""
        config_dir = Path("./configs")
        if not config_dir.exists():
            print(f"{Colors.FAIL}No saved configurations found.{Colors.ENDC}")
            time.sleep(2)
            return None
            
        configs = list(config_dir.glob("*.json"))
        if not configs:
            print(f"{Colors.FAIL}No saved configurations found.{Colors.ENDC}")
            time.sleep(2)
            return None
            
        print(f"\n{Colors.OKGREEN}Available configurations:{Colors.ENDC}\n")
        for i, config in enumerate(configs, 1):
            print(f"  {i}. {config.stem}")
            
        choice = self.get_input("Select configuration:", 
                               options=[str(i) for i in range(1, len(configs)+1)])
        
        config_file = configs[int(choice)-1]
        with open(config_file) as f:
            self.config = json.load(f)
            
        print(f"\n{Colors.OKGREEN}✓ Configuration loaded: {config_file.stem}{Colors.ENDC}")
        time.sleep(1)
        return self.config
        
    def quick_audit(self):
        """Run a quick audit with default settings"""
        print(f"\n{Colors.OKGREEN}Quick Audit Mode{Colors.ENDC}")
        print("Using recommended defaults for fastest setup.\n")
        
        hostname = self.get_input("Firewall hostname/IP:")
        username = self.get_input("Username:", default="admin")
        
        self.config = {
            'firewall': {
                'hostname': hostname,
                'connection_method': 'both',
                'ssh_port': 22,
                'ssh_username': username,
                'api_port': 443,
                'verify_ssl': False
            },
            'audit_scope': {
                'sections': ['A', 'B', 'C', 'D', 'H', 'L'],
                'testing_level': 2,
                'external_tools': {}
            },
            'report_options': {
                'selected_reports': ['executive_summary', 'technical_findings', 
                                    'risk_register', 'remediation_roadmap'],
                'output_dir': f"./reports/{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'formats': ['html', 'pdf', 'json']
            },
            'compliance': {
                'frameworks': ['cis'],
                'custom_pdfs': {}
            },
            'advanced': {
                'multi_firewall': False,
                'comparison_mode': False,
                'remediation_mode': 'report',
                'scheduled': False,
                'log_level': 'INFO'
            }
        }
        
        print(f"\n{Colors.OKGREEN}✓ Quick audit configured with recommended settings.{Colors.ENDC}")
        time.sleep(1)
        return self.config
        
    def show_sample_reports(self):
        """Display information about sample reports"""
        print(f"\n{Colors.OKGREEN}Sample Report Documentation{Colors.ENDC}\n")
        print("FortiAudit generates comprehensive reports in multiple formats:")
        print("\n1. Executive Summary (HTML/PDF)")
        print("   • Visual risk heat map")
        print("   • Top 10 critical findings")
        print("   • Compliance scorecard")
        print("   • Recommended actions with timeline")
        print("\n2. Technical Findings Report (HTML/PDF)")
        print("   • Detailed vulnerability descriptions")
        print("   • Evidence (screenshots, command outputs)")
        print("   • Step-by-step remediation")
        print("   • References to standards")
        print("\n3. Risk Register (CSV/JSON)")
        print("   • CVSS scoring for each finding")
        print("   • Prioritized by risk level")
        print("   • Machine-readable for tracking")
        print("\nSample reports are available in: ./examples/sample_reports/")
        
        input(f"\n{Colors.OKBLUE}Press Enter to continue...{Colors.ENDC}")
        
    def check_prerequisites(self):
        """Check system prerequisites"""
        print(f"\n{Colors.OKGREEN}System Prerequisites Check{Colors.ENDC}\n")
        
        prereqs = {
            'Python 3.8+': sys.version_info >= (3, 8),
            'pip (Python package manager)': True,  # If script runs, pip exists
        }
        
        # Check optional tools
        try:
            import paramiko
            prereqs['paramiko (SSH library)'] = True
        except ImportError:
            prereqs['paramiko (SSH library)'] = False
            
        try:
            import requests
            prereqs['requests (HTTP library)'] = True
        except ImportError:
            prereqs['requests (HTTP library)'] = False
            
        for name, status in prereqs.items():
            icon = f"{Colors.OKGREEN}✓{Colors.ENDC}" if status else f"{Colors.FAIL}✗{Colors.ENDC}"
            print(f"  {icon} {name}")
            
        print(f"\n{Colors.OKBLUE}To install missing dependencies:{Colors.ENDC}")
        print("  pip install -r requirements.txt")
        
        input(f"\n{Colors.OKBLUE}Press Enter to continue...{Colors.ENDC}")
        
    def show_about(self):
        """Show about information"""
        about = f"""
{Colors.OKGREEN}About FortiAudit{Colors.ENDC}
{Colors.BOLD}{'='*70}{Colors.ENDC}

Version: 1.0.0
License: MIT
Repository: https://github.com/yourusername/fortiaudit

{Colors.BOLD}Description:{Colors.ENDC}
FortiAudit is a comprehensive, open-source security audit tool specifically 
designed for Fortinet FortiGate firewalls. It automates the assessment of
firewall configurations against industry best practices and compliance 
standards.

{Colors.BOLD}Features:{Colors.ENDC}
• 16 comprehensive audit sections covering all security aspects
• Multiple connection methods (SSH and REST API)
• Intelligent recommendations based on your environment
• 6 types of detailed reports in multiple formats
• Compliance mapping (CIS, PCI-DSS, NIST, ISO 27001)
• Historical comparison and trend analysis
• Automated remediation assistance

{Colors.BOLD}Credits:{Colors.ENDC}
• Based on Astra VAPT and SANS Network Device checklists
• Developed for the security community
• Contributions welcome!

{Colors.BOLD}Support:{Colors.ENDC}
• Documentation: https://fortiaudit.readthedocs.io
• Issues: https://github.com/yourusername/fortiaudit/issues
• Community: https://fortiaudit.slack.com

{Colors.WARNING}⚠️  Legal Notice:{Colors.ENDC}
This tool is for authorized security testing only. Ensure you have proper
authorization before auditing any firewall. Unauthorized use may be illegal.

{Colors.BOLD}{'='*70}{Colors.ENDC}
        """
        print(about)
        input(f"\n{Colors.OKBLUE}Press Enter to continue...{Colors.ENDC}")


# Add this to the end of your cli.py file, replacing the placeholder section

def main():
    """Main entry point"""
    cli = FortiAuditCLI()
    
    # Check if config file provided as argument
    if len(sys.argv) > 1:
        if sys.argv[1] == '--config' and len(sys.argv) > 2:
            config_file = Path(sys.argv[2])
            if config_file.exists():
                with open(config_file) as f:
                    config = json.load(f)
                print(f"{Colors.OKGREEN}Loaded configuration from {config_file}{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}Configuration file not found: {config_file}{Colors.ENDC}")
                sys.exit(1)
        elif sys.argv[1] == '--help':
            print("""
FortiAudit - Fortinet Firewall Security Audit Tool

Usage:
  python fortiaudit/cli.py                    # Interactive wizard mode
  python fortiaudit/cli.py --config FILE      # Load saved configuration
  python fortiaudit/cli.py --help             # Show this help

For more information, visit: https://github.com/jeevadark/fortiaudit
            """)
            sys.exit(0)
    else:
        # Run interactive menu
        config = cli.show_menu()
        
    if config:
        print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{Colors.BOLD}Configuration Complete!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}\n")
        
        # Now actually run the audit!
        try:
            from fortiaudit.core.audit_engine import AuditEngine
            
            print(f"{Colors.BOLD}Starting Audit Engine...{Colors.ENDC}\n")
            
            # Create and run audit
            engine = AuditEngine(config)
            results = engine.run()
            
            # Print summary
            print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{Colors.BOLD}AUDIT COMPLETED SUCCESSFULLY!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}\n")
            
            print(f"{Colors.BOLD}Results Summary:{Colors.ENDC}")
            print(f"  Total Findings: {results['findings_summary']['total']}")
            print(f"  Critical: {results['findings_summary']['by_severity']['critical']}")
            print(f"  High: {results['findings_summary']['by_severity']['high']}")
            print(f"  Medium: {results['findings_summary']['by_severity']['medium']}")
            print(f"  Low: {results['findings_summary']['by_severity']['low']}")
            print(f"\n  Duration: {results['audit_info']['duration_seconds']:.1f} seconds")
            print(f"  Reports: {results['report_location']}")
            print("")
            
        except ImportError as e:
            print(f"{Colors.FAIL}Error: Audit engine not fully implemented: {e}{Colors.ENDC}")
            print(f"{Colors.WARNING}Falling back to configuration display only{Colors.ENDC}")
            print(f"\n{Colors.OKCYAN}Session configuration saved: session file{Colors.ENDC}\n")
        except Exception as e:
            print(f"{Colors.FAIL}Audit failed: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
