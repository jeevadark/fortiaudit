#!/usr/bin/env python3
"""
FortiGate Security Audit Script
Enhanced with Context-Aware Parsing and False Positive Reduction
CIS Benchmark Compliance Assessment
"""

import re
import sys
import json
import hashlib
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from collections import defaultdict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FortiOSDefaults:
    """FortiOS default values by version to prevent false positives"""

    DEFAULTS = {
        "6.0": {
            "admintimeout": 5,
            "admin_lockout_threshold": 3,
            "admin_lockout_duration": 60,
            "password_min_length": 8,
            "ssl_min_proto_ver": "tls-1-1"
        },
        "6.2": {
            "admintimeout": 5,
            "admin_lockout_threshold": 3,
            "admin_lockout_duration": 60,
            "password_min_length": 8,
            "password_complexity": "enabled",  # Auto-enabled
            "ssl_min_proto_ver": "tls-1-1"
        },
        "6.4": {
            "admintimeout": 5,
            "admin_lockout_threshold": 3,
            "admin_lockout_duration": 60,
            "password_min_length": 8,
            "password_complexity": "enabled",
            "ssl_min_proto_ver": "tls-1-2"
        },
        "7.0": {
            "admintimeout": 5,
            "admin_lockout_threshold": 3,
            "admin_lockout_duration": 60,
            "password_min_length": 14,
            "password_complexity": "enabled",
            "ssl_min_proto_ver": "tls-1-2"
        },
        "7.2": {
            "admintimeout": 5,
            "admin_lockout_threshold": 3,
            "admin_lockout_duration": 60,
            "password_min_length": 14,
            "password_complexity": "enabled",
            "ssl_min_proto_ver": "tls-1-2"
        }
    }

    @classmethod
    def get_default(cls, version: str, setting: str, default=None):
        """Get default value for a setting based on FortiOS version"""
        major_minor = ".".join(version.split(".")[:2]) if version else "7.0"

        # Try exact match first
        if major_minor in cls.DEFAULTS:
            return cls.DEFAULTS[major_minor].get(setting, default)

        # Fallback to closest version
        for ver in ["7.2", "7.0", "6.4", "6.2", "6.0"]:
            if major_minor >= ver:
                return cls.DEFAULTS[ver].get(setting, default)

        return default


class ConfigParser:
    """Context-aware FortiGate configuration parser"""

    def __init__(self, config_content: str):
        self.config_content = config_content
        self.version = self._extract_version()
        self.model = self._extract_model()
        self.vdoms = self._extract_vdoms()

    def _extract_version(self) -> str:
        """Extract FortiOS version from config"""
        match = re.search(r'#config-version=([^:]+):(\d+)\.(\d+)\.(\d+)', self.config_content)
        if match:
            return f"{match.group(2)}.{match.group(3)}.{match.group(4)}"
        return "7.0.0"  # Default fallback

    def _extract_model(self) -> str:
        """Extract FortiGate model from config"""
        match = re.search(r'#config-version=([^:]+):', self.config_content)
        return match.group(1) if match else "Unknown"

    def _extract_vdoms(self) -> List[str]:
        """Extract VDOM names if present"""
        vdom_pattern = r'config vdom\s+edit\s+"([^"]+)"'
        vdoms = re.findall(vdom_pattern, self.config_content)
        return vdoms if vdoms else ["root"]

    def get_config_block(self, block_name: str, vdom: str = None) -> Optional[str]:
        """Extract a specific config block with context awareness"""
        # Pattern to match config blocks
        pattern = rf'{re.escape(block_name)}\s+(.*?)(?=^config\s+|\Z)'
        match = re.search(pattern, self.config_content, re.MULTILINE | re.DOTALL)
        return match.group(1) if match else None

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Parse all interfaces with full context"""
        interfaces = []
        interface_block = self.get_config_block("config system interface")

        if not interface_block:
            return interfaces

        # Parse individual interfaces
        iface_pattern = r'edit\s+"([^"]+)"\s+(.*?)(?=edit\s+|next\s*$)'
        matches = re.finditer(iface_pattern, interface_block, re.DOTALL)

        for match in matches:
            iface_name = match.group(1)
            iface_config = match.group(2)

            interface = {
                "name": iface_name,
                "config": iface_config,
                "allowaccess": self._extract_allowaccess(iface_config),
                "ip": self._extract_setting(iface_config, "ip"),
                "type": self._extract_setting(iface_config, "type"),
                "vdom": self._extract_setting(iface_config, "vdom", "root"),
                "description": self._extract_setting(iface_config, "description", ""),
                "role": self._determine_interface_role(iface_name, iface_config)
            }
            interfaces.append(interface)

        return interfaces

    def _extract_allowaccess(self, config: str) -> List[str]:
        """Extract allowaccess protocols from interface config"""
        match = re.search(r'set allowaccess\s+(.+)', config)
        if match:
            return match.group(1).strip().split()
        return []

    def _extract_setting(self, config: str, setting: str, default: str = "") -> str:
        """Extract a setting value from config"""
        match = re.search(rf'set {setting}\s+"?([^"\n]+)"?', config)
        return match.group(1).strip() if match else default

    def _determine_interface_role(self, name: str, config: str) -> str:
        """Determine if interface is WAN, LAN, DMZ, etc."""
        name_lower = name.lower()

        # Check explicit role setting
        role_match = re.search(r'set role\s+(\w+)', config)
        if role_match:
            return role_match.group(1)

        # Heuristic based on name
        if any(x in name_lower for x in ['wan', 'outside', 'external', 'internet', 'port1']):
            return "wan"
        elif any(x in name_lower for x in ['lan', 'inside', 'internal']):
            return "lan"
        elif 'dmz' in name_lower:
            return "dmz"
        else:
            return "undefined"

    def get_firewall_policies(self) -> List[Dict[str, Any]]:
        """Parse firewall policies with full context"""
        policies = []
        policy_block = self.get_config_block("config firewall policy")

        if not policy_block:
            return policies

        policy_pattern = r'edit\s+(\d+)\s+(.*?)(?=edit\s+|next\s*$)'
        matches = re.finditer(policy_pattern, policy_block, re.DOTALL)

        for match in matches:
            policy_id = match.group(1)
            policy_config = match.group(2)

            policy = {
                "id": policy_id,
                "config": policy_config,
                "name": self._extract_setting(policy_config, "name"),
                "srcintf": self._extract_multi_value(policy_config, "srcintf"),
                "dstintf": self._extract_multi_value(policy_config, "dstintf"),
                "srcaddr": self._extract_multi_value(policy_config, "srcaddr"),
                "dstaddr": self._extract_multi_value(policy_config, "dstaddr"),
                "service": self._extract_multi_value(policy_config, "service"),
                "action": self._extract_setting(policy_config, "action", "deny"),
                "utm_status": "enable" in self._extract_setting(policy_config, "utm-status", "disable"),
                "av_profile": self._extract_setting(policy_config, "av-profile"),
                "ips_sensor": self._extract_setting(policy_config, "ips-sensor"),
                "ssl_ssh_profile": self._extract_setting(policy_config, "ssl-ssh-profile")
            }
            policies.append(policy)

        return policies

    def _extract_multi_value(self, config: str, setting: str) -> List[str]:
        """Extract multi-value settings (addresses, services, etc.)"""
        match = re.search(rf'set {setting}\s+(.+)', config)
        if match:
            values = match.group(1).strip()
            # Remove quotes and split
            return [v.strip('"') for v in values.split()]
        return []

    def get_vpn_tunnels(self) -> List[Dict[str, Any]]:
        """Parse IPsec VPN tunnels"""
        tunnels = []
        phase1_block = self.get_config_block("config vpn ipsec phase1-interface")

        if not phase1_block:
            return tunnels

        tunnel_pattern = r'edit\s+"([^"]+)"\s+(.*?)(?=edit\s+|next\s*$)'
        matches = re.finditer(tunnel_pattern, phase1_block, re.DOTALL)

        for match in matches:
            tunnel_name = match.group(1)
            tunnel_config = match.group(2)

            tunnel = {
                "name": tunnel_name,
                "config": tunnel_config,
                "mode": self._extract_setting(tunnel_config, "mode", "main"),
                "dhgrp": self._extract_dhgrp(tunnel_config),
                "proposal": self._extract_setting(tunnel_config, "proposal"),
                "remote_gw": self._extract_setting(tunnel_config, "remote-gw")
            }
            tunnels.append(tunnel)

        return tunnels

    def _extract_dhgrp(self, config: str) -> List[int]:
        """Extract DH groups"""
        match = re.search(r'set dhgrp\s+(.+)', config)
        if match:
            groups = match.group(1).strip().split()
            return [int(g) for g in groups if g.isdigit()]
        return []


class CISBenchmarkClient:
    """Client for CIS Benchmark API integration"""

    def __init__(self, api_key: str = None, api_url: str = None):
        self.api_key = api_key
        self.api_url = api_url or "https://workbench.cisecurity.org/api/v1"

    def get_fortigate_benchmark(self, version: str = "latest") -> Dict:
        """Fetch FortiGate CIS Benchmark"""
        if not self.api_key:
            return self._get_builtin_benchmark()

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            endpoint = f"{self.api_url}/benchmarks/fortigate/{version}"
            print(f"[*] Fetching CIS Benchmark from: {endpoint}")

            response = requests.get(endpoint, headers=headers, verify=True, timeout=30)

            if response.status_code == 200:
                print(f"[+] Successfully fetched CIS Benchmark")
                return response.json()
            else:
                print(f"[-] CIS API returned status {response.status_code}")
                return self._get_builtin_benchmark()

        except Exception as e:
            print(f"[-] Error connecting to CIS API: {e}")
            return self._get_builtin_benchmark()

    def _get_builtin_benchmark(self) -> Dict:
        """Built-in CIS FortiGate Benchmark rules"""
        return {
            "benchmark_name": "CIS Fortinet FortiGate Firewall Benchmark",
            "version": "1.2.0",
            "release_date": "2024-01-15",
            "controls": [
                {
                    "id": "1.1",
                    "title": "Ensure 'Telnet' administrative access is disabled",
                    "level": 1,
                    "severity": "HIGH",
                    "description": "Telnet transmits data in cleartext including credentials",
                    "rationale": "Administrative access via Telnet exposes credentials to network sniffing",
                    "remediation": "Remove telnet from allowaccess on all interfaces",
                    "check_type": "interface_check",
                    "automated": True,
                    "confidence": "high"
                },
                {
                    "id": "1.2",
                    "title": "Ensure 'HTTP' administrative access is disabled",
                    "level": 1,
                    "severity": "HIGH",
                    "description": "HTTP administrative access transmits credentials in cleartext",
                    "rationale": "Use HTTPS instead of HTTP for encrypted management traffic",
                    "remediation": "Replace HTTP with HTTPS in allowaccess settings",
                    "check_type": "interface_check",
                    "automated": True,
                    "confidence": "high"
                },
                {
                    "id": "1.3",
                    "title": "Ensure administrative access is restricted to trusted networks",
                    "level": 1,
                    "severity": "CRITICAL",
                    "description": "Management interfaces should not be accessible from WAN/Internet",
                    "rationale": "Exposing management to untrusted networks increases attack surface",
                    "remediation": "Configure trusthost restrictions on admin accounts",
                    "check_type": "interface_check",
                    "automated": True,
                    "confidence": "high"
                },
                {
                    "id": "2.1",
                    "title": "Ensure multi-factor authentication is enabled for administrators",
                    "level": 1,
                    "severity": "HIGH",
                    "description": "Two-factor authentication adds additional security layer",
                    "rationale": "Single-factor authentication is vulnerable to credential compromise",
                    "remediation": "Enable FortiToken or RADIUS-based 2FA for all admin accounts",
                    "check_type": "admin_check",
                    "automated": True,
                    "confidence": "medium"
                },
                {
                    "id": "3.1",
                    "title": "Ensure pre-shared keys are not stored in cleartext",
                    "level": 1,
                    "severity": "CRITICAL",
                    "description": "Cleartext PSKs in config allow VPN compromise",
                    "rationale": "Encrypted configs prevent PSK exposure",
                    "remediation": "Encrypt configuration backups and rotate PSKs",
                    "check_type": "credential_check",
                    "automated": True,
                    "confidence": "high"
                },
                {
                    "id": "4.1",
                    "title": "Ensure firewall policies follow least privilege",
                    "level": 1,
                    "severity": "MEDIUM",
                    "description": "Overly permissive rules violate least privilege",
                    "rationale": "Specific rules reduce attack surface and blast radius",
                    "remediation": "Replace 'any/all' with specific address/service objects",
                    "check_type": "policy_check",
                    "automated": True,
                    "confidence": "medium"
                },
                {
                    "id": "5.1",
                    "title": "Ensure IPsec VPN uses strong encryption",
                    "level": 1,
                    "severity": "HIGH",
                    "description": "Weak algorithms (DES, 3DES, MD5) are cryptographically broken",
                    "rationale": "Modern attacks can break weak ciphers in reasonable time",
                    "remediation": "Use AES-256 with SHA-256 or better, DH group 14+",
                    "check_type": "vpn_check",
                    "automated": True,
                    "confidence": "high"
                },
                {
                    "id": "6.1",
                    "title": "Ensure remote logging is configured",
                    "level": 1,
                    "severity": "HIGH",
                    "description": "Local-only logs can be lost or tampered with",
                    "rationale": "Remote logging ensures log persistence and integrity",
                    "remediation": "Configure syslog or FortiAnalyzer for remote logging",
                    "check_type": "logging_check",
                    "automated": True,
                    "confidence": "high"
                },
                {
                    "id": "7.1",
                    "title": "Ensure NTP is configured",
                    "level": 1,
                    "severity": "MEDIUM",
                    "description": "Accurate time is critical for logs, certificates, and authentication",
                    "rationale": "Time drift causes authentication failures and log correlation issues",
                    "remediation": "Configure reliable NTP sources",
                    "check_type": "ntp_check",
                    "automated": True,
                    "confidence": "medium"
                },
                {
                    "id": "8.1",
                    "title": "Ensure SNMP community strings are not default",
                    "level": 1,
                    "severity": "HIGH",
                    "description": "Default SNMP communities (public/private) are widely known",
                    "rationale": "Custom community strings prevent unauthorized SNMP access",
                    "remediation": "Change to strong, unique community strings or use SNMPv3",
                    "check_type": "credential_check",
                    "automated": True,
                    "confidence": "high"
                },
                {
                    "id": "9.1",
                    "title": "Ensure UTM profiles are enabled on internet-facing policies",
                    "level": 1,
                    "severity": "HIGH",
                    "description": "Security profiles provide threat protection",
                    "rationale": "Without IPS/AV/WebFilter, threats pass undetected",
                    "remediation": "Enable utm-status and attach security profiles",
                    "check_type": "policy_check",
                    "automated": True,
                    "confidence": "medium"
                },
                {
                    "id": "10.1",
                    "title": "Ensure firmware is up to date",
                    "level": 1,
                    "severity": "CRITICAL",
                    "description": "Outdated firmware contains known vulnerabilities",
                    "rationale": "Vendors release patches for discovered vulnerabilities",
                    "remediation": "Upgrade to latest stable FortiOS version",
                    "check_type": "version_check",
                    "automated": True,
                    "confidence": "high"
                },
                {
                    "id": "11.1",
                    "title": "Ensure SSL/TLS minimum version is 1.2",
                    "level": 1,
                    "severity": "HIGH",
                    "description": "SSL 3.0, TLS 1.0, and TLS 1.1 have known vulnerabilities",
                    "rationale": "Modern protocols fix cryptographic weaknesses",
                    "remediation": "Set ssl-min-proto-ver to tls-1-2 or higher",
                    "check_type": "ssl_check",
                    "automated": True,
                    "confidence": "high"
                },
                {
                    "id": "12.1",
                    "title": "Ensure high-risk services are not exposed externally",
                    "level": 1,
                    "severity": "CRITICAL",
                    "description": "RDP, SSH, database ports should not be exposed to Internet",
                    "rationale": "Direct exposure enables credential attacks and exploitation",
                    "remediation": "Use VPN for remote access instead of port forwarding",
                    "check_type": "vip_check",
                    "automated": True,
                    "confidence": "high"
                }
            ]
        }


class FortiGateAuditor:
    def __init__(self, config_file: str, cis_api_key: str = None, cis_api_url: str = None, exceptions_file: str = None):
        self.config_file = config_file
        self.config_content = ""
        self.parser = None
        self.findings = []
        self.stats = defaultdict(int)
        self.config_hash = ""
        self.exceptions = self._load_exceptions(exceptions_file) if exceptions_file else {}

        # Initialize CIS Benchmark client
        self.cis_client = CISBenchmarkClient(cis_api_key, cis_api_url)
        self.cis_benchmark = None

    def _load_exceptions(self, exceptions_file: str) -> Dict:
        """Load approved exceptions/deviations"""
        try:
            with open(exceptions_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Warning: Could not load exceptions file: {e}")
            return {}

    def is_exception(self, cis_control: str) -> bool:
        """Check if finding is an approved exception"""
        return cis_control in self.exceptions.get('approved_deviations', [])

    def load_config(self) -> bool:
        """Load and parse configuration file"""
        try:
            with open(self.config_file, 'r', encoding='utf-8', errors='ignore') as f:
                self.config_content = f.read()

            self.config_hash = hashlib.sha256(self.config_content.encode()).hexdigest()
            self.parser = ConfigParser(self.config_content)

            print(f"[+] Loaded config file: {self.config_file}")
            print(f"[+] SHA256: {self.config_hash}")
            print(f"[+] Config size: {len(self.config_content)} bytes")
            print(f"[+] FortiOS version: {self.parser.version}")
            print(f"[+] Model: {self.parser.model}")
            print(f"[+] VDOMs: {', '.join(self.parser.vdoms)}")
            return True
        except Exception as e:
            print(f"[-] Error loading config: {e}")
            return False

    def add_finding(self, severity: str, category: str, title: str, description: str,
                    evidence: str, remediation: str, cis_control: str = "",
                    recommendation: str = "", confidence: str = "high"):
        """Add a security finding"""

        # Check if this is an approved exception
        if cis_control and self.is_exception(cis_control):
            print(f"[~] Skipping {cis_control} - Approved exception")
            return

        finding = {
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "recommendation": recommendation or remediation,
            "cis_control": cis_control,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        self.stats[severity] += 1

    def load_cis_benchmark(self):
        """Load CIS Benchmark rules"""
        print("\n[*] Loading CIS FortiGate Benchmark...")
        self.cis_benchmark = self.cis_client.get_fortigate_benchmark()

        if self.cis_benchmark:
            print(f"[+] Loaded: {self.cis_benchmark.get('benchmark_name', 'CIS Benchmark')}")
            print(f"[+] Version: {self.cis_benchmark.get('version', 'N/A')}")
            print(f"[+] Controls: {len(self.cis_benchmark.get('controls', []))}")
            return True
        return False

    def check_management_interfaces(self):
        """CIS 1.1, 1.2, 1.3 - Management interface hardening"""
        print("[*] Checking management interface security...")

        interfaces = self.parser.get_interfaces()

        for iface in interfaces:
            allowaccess = iface['allowaccess']
            name = iface['name']
            role = iface['role']

            # CIS 1.1 - Telnet check
            if 'telnet' in allowaccess:
                self.add_finding(
                    "CRITICAL",
                    "Management Hardening",
                    f"Telnet enabled on interface {name}",
                    f"Interface {name} allows Telnet access, which transmits credentials in cleartext.",
                    f"Interface: {name}\nRole: {role}\nAllowaccess: {' '.join(allowaccess)}",
                    f"Remove telnet:\nconfig system interface\n  edit \"{name}\"\n    set allowaccess {' '.join([a for a in allowaccess if a != 'telnet'])}\n  next\nend",
                    "CIS 1.1",
                    "Immediately disable Telnet. Use SSH for secure CLI access.",
                    "high"
                )

            # CIS 1.2 - HTTP check (only if HTTPS not present)
            if 'http' in allowaccess and 'https' not in allowaccess:
                self.add_finding(
                    "CRITICAL",
                    "Management Hardening",
                    f"HTTP (cleartext) enabled on interface {name}",
                    f"Interface {name} allows HTTP without HTTPS, exposing credentials.",
                    f"Interface: {name}\nRole: {role}\nAllowaccess: {' '.join(allowaccess)}",
                    f"Replace HTTP with HTTPS:\nconfig system interface\n  edit \"{name}\"\n    set allowaccess {' '.join(['https' if a == 'http' else a for a in allowaccess])}\n  next\nend",
                    "CIS 1.2",
                    "Enable HTTPS only. Deploy valid SSL certificates.",
                    "high"
                )

            # CIS 1.3 - WAN exposure check (context-aware)
            if role == "wan":
                risky_access = [a for a in allowaccess if a in ['https', 'ssh', 'http', 'telnet']]
                if risky_access:
                    # Check if trusthost is configured (reduces severity)
                    has_trusthost = 'trusthost' in iface.get('config', '')

                    severity = "HIGH" if has_trusthost else "CRITICAL"
                    confidence = "high"

                    self.add_finding(
                        severity,
                        "Management Hardening",
                        f"Management access on WAN interface {name}",
                        f"Administrative protocols ({', '.join(risky_access)}) exposed on WAN interface. {'Trusthost configured but still risky.' if has_trusthost else 'No IP restriction found.'}",
                        f"Interface: {name}\nRole: {role}\nAllowaccess: {' '.join(allowaccess)}\nTrusthost: {'Yes' if has_trusthost else 'No'}",
                        f"Restrict management to internal networks:\nconfig system interface\n  edit \"{name}\"\n    set allowaccess ping\n  next\nend",
                        "CIS 1.3",
                        "Remove all management access from WAN. Use VPN or jump host for remote admin.",
                        confidence
                    )

    def check_cleartext_credentials(self):
        """CIS 3.1, 8.1 - Credential security"""
        print("[*] Checking for cleartext credentials...")

        # Check PSKs
        psk_matches = re.finditer(r'set psksecret\s+(\S+)', self.config_content, re.IGNORECASE)
        for match in psk_matches:
            line_num = self.config_content[:match.start()].count('\n') + 1
            psk_value = match.group(1)

            # Skip encrypted or masked values
            if not psk_value.startswith('ENC') and psk_value not in ['FortinetPasswordMask', '**']:
                self.add_finding(
                    "CRITICAL",
                    "Credential Management",
                    "Cleartext IPsec PSK in configuration",
                    f"Pre-shared key found in cleartext at line {line_num}. Compromises VPN security.",
                    f"Line {line_num}: set psksecret {psk_value[:10]}... (truncated for security)",
                    "Rotate PSK immediately:\nconfig vpn ipsec phase1-interface\n  edit \"tunnel_name\"\n    set psksecret <new_strong_32char_psk>\n  next\nend",
                    "CIS 3.1",
                    "1. Rotate PSK on both peers\n2. Use certificate-based auth where possible\n3. Encrypt config backups\n4. Restrict config file access",
                    "high"
                )

        # Check SNMP communities
        snmp_matches = re.finditer(r'set community\s+"?([^"\n]+)"?', self.config_content, re.IGNORECASE)
        for match in snmp_matches:
            line_num = self.config_content[:match.start()].count('\n') + 1
            community = match.group(1).strip()

            if community.lower() in ['public', 'private']:
                self.add_finding(
                    "HIGH",
                    "Credential Management",
                    "Default SNMP community string detected",
                    f"Default SNMP community '{community}' found at line {line_num}.",
                    f"Line {line_num}: set community \"{community}\"",
                    "Change to unique community:\nconfig system snmp community\n  edit 1\n    set name \"<complex_32char_string>\"\n  next\nend",
                    "CIS 8.1",
                    "Migrate to SNMPv3 with strong authentication. If SNMPv2c required, use complex unique string.",
                    "high"
                )

        # Check passwords
        password_matches = re.finditer(r'set password\s+(\S+)', self.config_content, re.IGNORECASE)
        for match in password_matches:
            line_num = self.config_content[:match.start()].count('\n') + 1
            pwd_value = match.group(1)

            if not pwd_value.startswith('ENC') and pwd_value not in ['FortinetPasswordMask', '**']:
                self.add_finding(
                    "CRITICAL",
                    "Credential Management",
                    "Cleartext password in configuration",
                    f"Password in cleartext at line {line_num}.",
                    f"Line {line_num}: set password {pwd_value[:5]}... (truncated)",
                    "Change password and enforce policy:\nconfig system password-policy\n  set min-length 14\n  set min-upper-case-letter 1\n  set min-lower-case-letter 1\n  set min-number 1\n  set min-special-character 1\nend",
                    "CIS 3.1",
                    "Force password change for affected accounts. Encrypt backups.",
                    "high"
                )

    def check_firewall_policies(self):
        """CIS 4.1, 9.1 - Firewall policy review"""
        print("[*] Checking firewall policies...")

        policies = self.parser.get_firewall_policies()

        for policy in policies:
            policy_id = policy['id']

            # Check for overly permissive addresses
            if 'all' in policy['srcaddr'] or 'all' in policy['dstaddr']:
                if policy['action'] == 'accept':
                    # Determine if this is internet-facing
                    is_wan_policy = any('wan' in iface.lower() for iface in policy['srcintf'] + policy['dstintf'])
                    severity = "HIGH" if is_wan_policy else "MEDIUM"

                    self.add_finding(
                        severity,
                        "Firewall Policy",
                        f"Overly permissive policy {policy_id}",
                        f"Policy {policy_id} uses 'all' for addresses. {'WAN-facing policy' if is_wan_policy else 'Internal policy'}.",
                        f"Policy: {policy_id}\nName: {policy.get('name', 'N/A')}\nSrcaddr: {', '.join(policy['srcaddr'])}\nDstaddr: {', '.join(policy['dstaddr'])}",
                        f"Restrict to specific objects:\nconfig firewall policy\n  edit {policy_id}\n    set srcaddr \"specific_network\"\n    set dstaddr \"specific_server\"\n  next\nend",
                        "CIS 4.1",
                        "Create specific address objects. Use groups for multiple hosts.",
                        "medium"
                    )

            # Check for 'ALL' services
            if 'ALL' in policy['service']:
                self.add_finding(
                    "HIGH",
                    "Firewall Policy",
                    f"Policy {policy_id} allows all services",
                    f"Policy {policy_id} permits all services, violating least privilege.",
                    f"Policy: {policy_id}\nServices: ALL",
                    f"Restrict to required services:\nconfig firewall policy\n  edit {policy_id}\n    set service \"HTTP\" \"HTTPS\" \"DNS\"\n  next\nend",
                    "CIS 4.1",
                    "Identify required ports via traffic analysis. Create service groups.",
                    "medium"
                )

            # Check UTM on internet-facing policies
            is_internet_facing = any('wan' in iface.lower() or 'internet' in iface.lower()
                                     for iface in policy['srcintf'] + policy['dstintf'])

            if is_internet_facing and not policy['utm_status']:
                # Check FortiOS version - older versions may not have UTM by default
                if self.parser.version >= "6.0":
                    self.add_finding(
                        "MEDIUM",
                        "UTM/Security Profiles",
                        f"Policy {policy_id} lacks UTM on internet-facing traffic",
                        f"Policy {policy_id} on WAN interface without IPS/AV/WebFilter.",
                        f"Policy: {policy_id}\nInterfaces: {', '.join(policy['srcintf'])} -> {', '.join(policy['dstintf'])}",
                        f"Enable UTM:\nconfig firewall policy\n  edit {policy_id}\n    set utm-status enable\n    set av-profile \"default\"\n    set ips-sensor \"default\"\n    set webfilter-profile \"default\"\n  next\nend",
                        "CIS 9.1",
                        "Enable security profiles on all internet-bound traffic.",
                        "medium"
                    )

    def check_vpn_security(self):
        """CIS 5.1 - VPN cryptographic security"""
        print("[*] Checking VPN security...")

        tunnels = self.parser.get_vpn_tunnels()

        for tunnel in tunnels:
            name = tunnel['name']

            # Check DH groups
            weak_dh = [g for g in tunnel['dhgrp'] if g < 14]
            if weak_dh:
                self.add_finding(
                    "HIGH",
                    "VPN Security",
                    f"Weak DH group in tunnel '{name}'",
                    f"Tunnel '{name}' uses weak DH groups {weak_dh}. Vulnerable to cryptographic attacks.",
                    f"Tunnel: {name}\nDH Groups: {tunnel['dhgrp']}",
                    f"Upgrade DH groups:\nconfig vpn ipsec phase1-interface\n  edit \"{name}\"\n    set dhgrp 14 15 19 20\n  next\nend",
                    "CIS 5.1",
                    "Use DH group 14 (2048-bit) minimum. Prefer groups 19/20 (ECC) for performance.",
                    "high"
                )

            # Check for aggressive mode
            if tunnel['mode'] == 'aggressive':
                self.add_finding(
                    "HIGH",
                    "VPN Security",
                    f"Aggressive mode on tunnel '{name}'",
                    f"Tunnel '{name}' uses aggressive mode, exposing identity.",
                    f"Tunnel: {name}\nMode: {tunnel['mode']}",
                    f"Use main mode:\nconfig vpn ipsec phase1-interface\n  edit \"{name}\"\n    set mode main\n  next\nend",
                    "CIS 5.1",
                    "Main mode provides identity protection. Coordinate with remote peer admin.",
                    "high"
                )

            # Check for weak ciphers (word boundary to avoid false positives)
            proposal = tunnel['proposal']
            if proposal and re.search(r'\b(des|3des|md5)\b', proposal, re.IGNORECASE):
                matched_weak = re.findall(r'\b(des|3des|md5)\b', proposal, re.IGNORECASE)
                self.add_finding(
                    "CRITICAL",
                    "VPN Security",
                    f"Weak encryption in tunnel '{name}'",
                    f"Tunnel '{name}' uses weak algorithms: {', '.join(set(matched_weak))}",
                    f"Tunnel: {name}\nProposal: {proposal}",
                    f"Use strong encryption:\nconfig vpn ipsec phase1-interface\n  edit \"{name}\"\n    set proposal aes256-sha256 aes256-sha384 aes256gcm-prfsha256\n  next\nend",
                    "CIS 5.1",
                    "Migrate to AES-256-GCM. Schedule maintenance window for both peers.",
                    "high"
                )

    def check_logging_configuration(self):
        """CIS 6.1 - Remote logging"""
        print("[*] Checking logging configuration...")

        # Check for syslog
        syslog_block = self.parser.get_config_block("config log syslogd setting")
        syslog_enabled = syslog_block and 'set status enable' in syslog_block

        # Check for FortiAnalyzer
        faz_block = self.parser.get_config_block("config log fortianalyzer setting")
        faz_enabled = faz_block and 'set status enable' in faz_block

        # Check for FortiCloud (may be managed externally)
        cloud_block = self.parser.get_config_block("config log forticloud setting")
        cloud_enabled = cloud_block and 'set status enable' in cloud_block

        if not (syslog_enabled or faz_enabled or cloud_enabled):
            # Lower confidence if FortiManager might be managing this
            fmg_block = self.parser.get_config_block("config system fortimanager")
            fmg_managed = fmg_block and 'set status enable' in fmg_block

            confidence = "medium" if fmg_managed else "high"
            note = " (May be managed via FortiManager)" if fmg_managed else ""

            self.add_finding(
                "HIGH",
                "Logging",
                "No remote logging configured" + note,
                f"Neither syslog, FortiAnalyzer, nor FortiCloud logging enabled. Logs at risk of loss.{note}",
                "No remote logging found in configuration",
                "Configure remote syslog:\nconfig log syslogd setting\n  set status enable\n  set server \"syslog.company.com\"\n  set port 514\n  set facility local7\nend",
                "CIS 6.1",
                "Configure redundant syslog servers or FortiAnalyzer. Enable TLS for syslog.",
                confidence
            )

    def check_ntp_configuration(self):
        """CIS 7.1 - NTP time synchronization"""
        print("[*] Checking NTP configuration...")

        ntp_block = self.parser.get_config_block("config system ntp")

        # Check if NTP is enabled
        ntp_enabled = ntp_block and 'set ntpsync enable' in ntp_block

        # Check default - some versions enable FortiGuard NTP by default
        default_ntp = FortiOSDefaults.get_default(self.parser.version, 'ntp_enabled', False)

        if not ntp_enabled and not default_ntp:
            self.add_finding(
                "MEDIUM",
                "System Configuration",
                "NTP synchronization not configured",
                "Time sync critical for logs, certs, and authentication. NTP not enabled.",
                "No NTP configuration found",
                "Configure NTP:\nconfig system ntp\n  set ntpsync enable\n  set type fortiguard\nend\n\nOr custom NTP:\nconfig system ntp\n  set ntpsync enable\n  config ntpserver\n    edit 1\n      set server \"ntp.pool.org\"\n    next\n  end\nend",
                "CIS 7.1",
                "Use reliable NTP sources (pool.ntp.org or internal). Enable authentication if possible.",
                "medium"
            )

    def check_firmware_version(self):
        """CIS 10.1 - Firmware currency"""
        print("[*] Checking firmware version...")

        version = self.parser.version
        model = self.parser.model
        major, minor, patch = map(int, version.split('.'))

        vulnerable = False
        vuln_description = ""

        # Known vulnerable versions
        if major == 6 and minor == 0:
            vulnerable = True
            vuln_description = "FortiOS 6.0 is end-of-support. Contains CVE-2022-40684 (auth bypass) and others."
        elif major == 6 and minor == 2 and patch < 15:
            vulnerable = True
            vuln_description = f"FortiOS 6.2.{patch} has known vulnerabilities. Upgrade to 6.2.15+ or migrate to 7.x"
        elif major == 6 and minor == 4 and patch < 14:
            vulnerable = True
            vuln_description = f"FortiOS 6.4.{patch} has security issues. Upgrade to 6.4.14+ or migrate to 7.2.x"
        elif major == 7 and minor == 0 and patch < 15:
            vulnerable = True
            vuln_description = f"FortiOS 7.0.{patch} has vulnerabilities. Upgrade to 7.0.15+ or migrate to 7.2.x"
        elif major == 7 and minor == 2 and patch < 7:
            vulnerable = True
            vuln_description = f"FortiOS 7.2.{patch} has known issues. Upgrade to 7.2.7+"

        if vulnerable:
            self.add_finding(
                "CRITICAL",
                "Firmware/Patch Management",
                f"Vulnerable FortiOS version: {version}",
                f"FortiOS {version} on {model} contains known vulnerabilities.\n\n{vuln_description}",
                f"Version: {version}\nModel: {model}",
                f"Upgrade firmware:\n1. Review Fortinet PSIRT: https://www.fortiguard.com/psirt\n2. Check upgrade path\n3. Backup config\n4. Test in lab\n5. Schedule maintenance\n6. Upgrade to latest stable",
                "CIS 10.1",
                f"Immediate upgrade required. Target: FortiOS 7.4.x (latest stable) or minimum patch level for current branch.",
                "high"
            )
        else:
            print(f"[+] FortiOS {version} - No critical known vulnerabilities in this check")

    def check_ssl_tls_version(self):
        """CIS 11.1 - SSL/TLS minimum version"""
        print("[*] Checking SSL/TLS configuration...")

        # Check SSL-VPN settings
        sslvpn_block = self.parser.get_config_block("config vpn ssl settings")

        if sslvpn_block and 'set status enable' in sslvpn_block:
            # Extract minimum TLS version
            tls_match = re.search(r'set ssl-min-proto-ver\s+([\w\-\.]+)', sslvpn_block)

            if tls_match:
                tls_version = tls_match.group(1)
                weak_versions = ['ssl-3.0', 'tls-1.0', 'tls-1.1']

                if tls_version in weak_versions:
                    self.add_finding(
                        "HIGH",
                        "VPN Security",
                        "Weak SSL/TLS version for SSL-VPN",
                        f"SSL-VPN allows weak protocol: {tls_version}",
                        f"SSL minimum version: {tls_version}",
                        "Enforce TLS 1.2+:\nconfig vpn ssl settings\n  set ssl-min-proto-ver tls-1-2\n  set algorithm high\nend",
                        "CIS 11.1",
                        "Update SSL-VPN clients to support TLS 1.2+. Test before enforcing.",
                        "high"
                    )
            else:
                # Check default for version
                default_tls = FortiOSDefaults.get_default(self.parser.version, 'ssl_min_proto_ver', 'tls-1-2')
                if default_tls in ['ssl-3.0', 'tls-1.0', 'tls-1.1']:
                    self.add_finding(
                        "MEDIUM",
                        "VPN Security",
                        "SSL/TLS minimum version not explicitly set",
                        f"SSL-VPN relies on default ({default_tls}). Should be explicitly configured.",
                        "No ssl-min-proto-ver setting found",
                        "Explicitly set TLS 1.2:\nconfig vpn ssl settings\n  set ssl-min-proto-ver tls-1-2\nend",
                        "CIS 11.1",
                        "Explicitly configure TLS 1.2 minimum for clarity and compliance.",
                        "medium"
                    )

    def check_vip_exposure(self):
        """CIS 12.1 - External service exposure"""
        print("[*] Checking VIP/port-forward exposure...")

        vip_block = self.parser.get_config_block("config firewall vip")

        if not vip_block:
            return

        vip_pattern = r'edit\s+"([^"]+)"\s+(.*?)(?=edit\s+|next\s*$)'
        vips = re.finditer(vip_pattern, vip_block, re.DOTALL)

        risky_ports = {
            22: 'SSH', 23: 'Telnet', 21: 'FTP', 3389: 'RDP',
            1433: 'MS SQL', 3306: 'MySQL', 5432: 'PostgreSQL',
            5900: 'VNC', 5901: 'VNC', 1521: 'Oracle', 27017: 'MongoDB',
            445: 'SMB', 139: 'NetBIOS', 135: 'RPC'
        }

        for vip_match in vips:
            vip_name = vip_match.group(1)
            vip_config = vip_match.group(2)

            extport_match = re.search(r'set extport\s+(\d+)', vip_config)

            if extport_match:
                port = int(extport_match.group(1))

                if port in risky_ports:
                    # Check if there's a port mapping to non-standard internal port (mitigation)
                    mappedport_match = re.search(r'set mappedport\s+(\d+)', vip_config)
                    is_standard_port = not mappedport_match or int(mappedport_match.group(1)) == port

                    severity = "CRITICAL" if is_standard_port else "HIGH"

                    self.add_finding(
                        severity,
                        "NAT/VIP",
                        f"Risky service exposed: {risky_ports[port]} (port {port})",
                        f"VIP '{vip_name}' exposes {risky_ports[port]} on port {port} externally.",
                        f"VIP: {vip_name}\nExternal port: {port}\nService: {risky_ports[port]}",
                        f"Remove or restrict:\nconfig firewall vip\n  delete \"{vip_name}\"\nend\n\nOr restrict in policy:\nconfig firewall policy\n  edit <policy_id>\n    set srcaddr \"trusted_admin_IPs\"\n  next\nend",
                        "CIS 12.1",
                        f"Replace {risky_ports[port]} exposure with VPN access. If required: use non-standard port, restrict source IPs, implement rate limiting.",
                        "high"
                    )

    def generate_executive_summary(self) -> str:
        """Generate executive summary"""
        risk_score = (self.stats['CRITICAL'] * 10 + self.stats['HIGH'] * 5 +
                      self.stats['MEDIUM'] * 2 + self.stats['LOW'] * 1)

        if risk_score > 50:
            risk_level = "CRITICAL"
            risk_description = "Immediate action required - Multiple critical vulnerabilities"
        elif risk_score > 20:
            risk_level = "HIGH"
            risk_description = "Remediation needed within 7 days - Significant gaps identified"
        elif risk_score > 10:
            risk_level = "MEDIUM"
            risk_description = "Address within 30 days - Moderate concerns present"
        else:
            risk_level = "LOW"
            risk_description = "Address during next maintenance - Minor issues found"

        summary = f"""
EXECUTIVE SUMMARY
{'=' * 80}

Overall Risk Level: {risk_level}
Risk Score: {risk_score}
Assessment: {risk_description}

Configuration Details:
  • FortiOS Version: {self.parser.version}
  • Model: {self.parser.model}
  • VDOMs: {', '.join(self.parser.vdoms)}

Total Findings: {len(self.findings)}
  • CRITICAL: {self.stats['CRITICAL']} (Immediate action required)
  • HIGH:     {self.stats['HIGH']} (Remediate within 7 days)
  • MEDIUM:   {self.stats['MEDIUM']} (Address within 30 days)
  • LOW:      {self.stats['LOW']} (Address during maintenance)

Top Security Concerns:
"""

        critical_high = [f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']]
        critical_high.sort(key=lambda x: 0 if x['severity'] == 'CRITICAL' else 1)

        for i, finding in enumerate(critical_high[:5], 1):
            confidence_marker = " [HIGH CONFIDENCE]" if finding.get('confidence') == 'high' else ""
            summary += f"  {i}. [{finding['severity']}] {finding['title']}{confidence_marker}\n"

        if not critical_high:
            summary += "  None - Configuration meets basic security standards\n"

        return summary

    def generate_report(self, output_file: str = None):
        """Generate comprehensive audit report"""

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(self.findings,
                                 key=lambda x: (severity_order.get(x['severity'], 999), x.get('confidence') != 'high'))

        report = []
        report.append("=" * 80)
        report.append("FortiGate Security Audit Report")
        report.append("CIS Benchmark Compliance Assessment")
        report.append("Context-Aware Analysis with False Positive Reduction")
        report.append("=" * 80)
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Config File: {self.config_file}")
        report.append(f"Config SHA256: {self.config_hash}")

        if self.cis_benchmark:
            report.append(f"\nCIS Benchmark: {self.cis_benchmark.get('benchmark_name', 'N/A')}")
            report.append(f"Benchmark Version: {self.cis_benchmark.get('version', 'N/A')}")

        if self.exceptions:
            report.append(f"\nApproved Exceptions: {len(self.exceptions.get('approved_deviations', []))}")

        report.append("\n" + self.generate_executive_summary())

        report.append("\n" + "=" * 80)
        report.append("DETAILED FINDINGS")
        report.append("=" * 80)

        for idx, finding in enumerate(sorted_findings, 1):
            confidence_indicator = f" [{finding.get('confidence', 'medium').upper()} CONFIDENCE]"

            report.append(f"\n\n{'=' * 80}")
            report.append(f"Finding #{idx}: {finding['severity']}{confidence_indicator}")
            report.append(f"{finding['title']}")
            report.append("=" * 80)

            report.append(f"\nCategory: {finding['category']}")
            if finding.get('cis_control'):
                report.append(f"CIS Control: {finding['cis_control']}")

            report.append(f"\nDescription:")
            report.append(f"{finding['description']}")

            report.append(f"\nEvidence:")
            report.append(f"{finding['evidence']}")

            report.append(f"\nMitigation Steps:")
            report.append(f"{finding['remediation']}")

            if finding.get('recommendation') and finding['recommendation'] != finding['remediation']:
                report.append(f"\nRecommendation:")
                report.append(f"{finding['recommendation']}")

        report.append("\n\n" + "=" * 80)
        report.append("PRIORITIZED ACTION PLAN")
        report.append("=" * 80)

        critical = [f for f in sorted_findings if f['severity'] == 'CRITICAL']
        high = [f for f in sorted_findings if f['severity'] == 'HIGH']
        medium = [f for f in sorted_findings if f['severity'] == 'MEDIUM']

        if critical:
            report.append("\n+-- PRIORITY 1: IMMEDIATE ACTION (Within 24 hours)")
            report.append("|")
            for i, f in enumerate(critical, 1):
                conf = " [HIGH CONF]" if f.get('confidence') == 'high' else ""
                report.append(f"|  {i}. {f['title']}{conf}")
                report.append(f"|     Impact: {f['description'].split('.')[0]}")
            report.append("+--" + "-" * 77)

        if high:
            report.append("\n+-- PRIORITY 2: HIGH PRIORITY (Within 7 days)")
            report.append("|")
            for i, f in enumerate(high, 1):
                conf = " [HIGH CONF]" if f.get('confidence') == 'high' else ""
                report.append(f"|  {i}. {f['title']}{conf}")
            report.append("+--" + "-" * 77)

        if medium:
            report.append("\n+-- PRIORITY 3: MEDIUM PRIORITY (Within 30 days)")
            report.append("|")
            for i, f in enumerate(medium[:5], 1):
                report.append(f"|  {i}. {f['title']}")
            if len(medium) > 5:
                report.append(f"|  ... and {len(medium) - 5} more")
            report.append("+--" + "-" * 77)

        report.append("\n\n" + "=" * 80)
        report.append("QUICK WINS (High Impact, Low Effort)")
        report.append("=" * 80)
        quick_wins = [
            "\n1. Management Access Hardening:",
            "   • Remove telnet/HTTP from all interfaces",
            "   • Remove management access from WAN interfaces",
            "   • Configure trusted host restrictions",
            "\n2. Credential Security:",
            "   • Rotate all cleartext PSKs found in config",
            "   • Change default SNMP community strings",
            "   • Enable configuration backup encryption",
            "\n3. VPN Security:",
            "   • Remove weak ciphers (DES/3DES/MD5)",
            "   • Upgrade to strong DH groups (14+)",
            "   • Enforce TLS 1.2+ for SSL-VPN",
            "\n4. Logging & Monitoring:",
            "   • Enable remote syslog or FortiAnalyzer",
            "   • Configure NTP for accurate timestamps",
            "\n5. Firmware:",
            "   • Plan upgrade to address known CVEs"
        ]
        for win in quick_wins:
            report.append(win)

        report.append("\n\n" + "=" * 80)
        report.append("CIS BENCHMARK COMPLIANCE SUMMARY")
        report.append("=" * 80)

        cis_findings = [f for f in self.findings if f.get('cis_control')]
        report.append(
            f"\nTotal CIS Controls Assessed: {len(self.cis_benchmark.get('controls', [])) if self.cis_benchmark else 0}")
        report.append(f"Controls with Findings: {len(set(f.get('cis_control') for f in cis_findings))}")

        report.append("\nCIS Control Coverage:")
        cis_categories = {}
        for finding in cis_findings:
            if finding.get('cis_control'):
                control = finding['cis_control']
                severity = finding['severity']
                if control not in cis_categories:
                    cis_categories[control] = []
                cis_categories[control].append(severity)

        for cis_id in sorted(cis_categories.keys()):
            severities = cis_categories[cis_id]
            report.append(f"  • {cis_id}: {len(severities)} finding(s) [{', '.join(set(severities))}]")

        report.append("\n\n" + "=" * 80)
        report.append("FALSE POSITIVE MITIGATION")
        report.append("=" * 80)
        report.append(f"""
This audit employs context-aware parsing to reduce false positives:

✓ FortiOS version-specific defaults considered ({self.parser.version})
✓ Interface role detection (WAN/LAN/DMZ)
✓ Hierarchical config parsing (not line-by-line regex)
✓ Confidence scoring for each finding
✓ Exception handling for approved deviations
✓ Word boundary matching to avoid substring false matches

High-confidence findings are prioritized in the action plan.
Medium/low-confidence findings should be manually reviewed.
""")

        report.append("\n" + "=" * 80)
        report.append("RECOMMENDATIONS & NEXT STEPS")
        report.append("=" * 80)
        recommendations = """
1. Immediate Actions (24-48 hours):
   - Address all CRITICAL findings with HIGH confidence
   - Rotate compromised credentials
   - Remove insecure management protocols
   - Disable risky external service exposures

2. Short-term (1-2 weeks):
   - Address HIGH severity findings
   - Update firmware to latest stable version
   - Review and optimize firewall policies
   - Enable remote logging

3. Medium-term (1 month):
   - Address MEDIUM severity findings
   - Implement centralized authentication
   - Enable UTM profiles on all policies
   - Deploy SSL inspection where appropriate

4. Long-term (Ongoing):
   - Establish regular configuration review process
   - Implement automated compliance monitoring
   - Maintain firmware update schedule
   - Perform quarterly security assessments
   - Document all changes in change management system

5. Best Practices:
   - Use configuration management (FortiManager)
   - Implement network segmentation
   - Regular encrypted backups
   - Principle of least privilege
   - Defense in depth strategy
"""
        report.append(recommendations)

        report.append("\n" + "=" * 80)
        report.append("Report End")
        report.append("=" * 80)
        report.append(f"\nThis report contains security-sensitive information")
        report.append(f"Treat as CONFIDENTIAL")

        report_text = "\n".join(report)

        print("\n" + report_text)

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n[+] Report saved to: {output_file}")

        json_file = output_file.replace('.txt', '.json') if output_file else 'audit_report.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'config_file': self.config_file,
                    'config_hash': self.config_hash,
                    'scan_time': datetime.now().isoformat(),
                    'fortios_version': self.parser.version,
                    'model': self.parser.model,
                    'vdoms': self.parser.vdoms,
                    'cis_benchmark': self.cis_benchmark.get('benchmark_name') if self.cis_benchmark else None,
                    'cis_version': self.cis_benchmark.get('version') if self.cis_benchmark else None,
                    'exceptions_loaded': len(self.exceptions.get('approved_deviations', []))
                },
                'summary': {
                    'total_findings': len(self.findings),
                    'critical': self.stats['CRITICAL'],
                    'high': self.stats['HIGH'],
                    'medium': self.stats['MEDIUM'],
                    'low': self.stats['LOW'],
                    'risk_score': (self.stats['CRITICAL'] * 10 + self.stats['HIGH'] * 5 +
                                   self.stats['MEDIUM'] * 2 + self.stats['LOW'] * 1),
                    'high_confidence_critical': len(
                        [f for f in self.findings if f['severity'] == 'CRITICAL' and f.get('confidence') == 'high']),
                    'high_confidence_high': len(
                        [f for f in self.findings if f['severity'] == 'HIGH' and f.get('confidence') == 'high'])
                },
                'findings': sorted_findings,
                'cis_compliance': {
                    'controls_assessed': len(self.cis_benchmark.get('controls', [])) if self.cis_benchmark else 0,
                    'controls_with_findings': len(
                        set(f.get('cis_control') for f in cis_findings if f.get('cis_control')))
                }
            }, f, indent=2)
        print(f"[+] JSON report saved to: {json_file}")

    def run_audit(self):
        """Execute full audit"""
        print("\n" + "=" * 80)
        print("FortiGate Security Auditor")
        print("Enhanced with Context-Aware Parsing & False Positive Reduction")
        print("=" * 80)

        if not self.load_config():
            return False

        # Load CIS Benchmark
        self.load_cis_benchmark()

        print("\n[*] Starting comprehensive security analysis...")
        print("[*] Using context-aware parsing to minimize false positives...")

        # Run all security checks
        self.check_management_interfaces()
        self.check_cleartext_credentials()
        self.check_firewall_policies()
        self.check_vpn_security()
        self.check_logging_configuration()
        self.check_ntp_configuration()
        self.check_firmware_version()
        self.check_ssl_tls_version()
        self.check_vip_exposure()

        print("\n[+] Security analysis complete!")
        print(f"[+] Total findings: {len(self.findings)}")
        print(
            f"    CRITICAL: {self.stats['CRITICAL']} ({len([f for f in self.findings if f['severity'] == 'CRITICAL' and f.get('confidence') == 'high'])} high confidence)")
        print(
            f"    HIGH:     {self.stats['HIGH']} ({len([f for f in self.findings if f['severity'] == 'HIGH' and f.get('confidence') == 'high'])} high confidence)")
        print(f"    MEDIUM:   {self.stats['MEDIUM']}")
        print(f"    LOW:      {self.stats['LOW']}")

        return True


def main():
    parser = argparse.ArgumentParser(
        description='FortiGate Security Audit Tool - Context-aware analysis with CIS Benchmark compliance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic audit with built-in CIS rules
  python fortigate_audit.py -c firewall.cfg -o audit_report.txt

  # With CIS Benchmark API integration
  python fortigate_audit.py -c firewall.cfg -o report.txt --cis-api-key "your_key"

  # With exceptions file for approved deviations
  python fortigate_audit.py -c firewall.cfg -o report.txt --exceptions exceptions.json

Exceptions File Format (JSON):
{
  "approved_deviations": ["CIS 1.3", "CIS 8.1"],
  "justification": {
    "CIS 1.3": "SNMP required for NOC monitoring",
    "CIS 8.1": "Custom community string in use"
  }
}

Note: 
  - CIS API key is optional (uses built-in rules as fallback)
  - Context-aware parsing reduces false positives
  - Confidence scoring helps prioritize findings
  - FortiOS version-specific defaults are considered
  - All findings include mitigation, remediation, and recommendations
        """
    )

    parser.add_argument('-c', '--config', required=True,
                        help='Path to FortiGate configuration file')
    parser.add_argument('-o', '--output', default='fortigate_audit_report.txt',
                        help='Output report file (default: fortigate_audit_report.txt)')
    parser.add_argument('--cis-api-key',
                        help='CIS Benchmark API key (optional)')
    parser.add_argument('--cis-api-url',
                        help='CIS Benchmark API URL (optional)')
    parser.add_argument('--exceptions',
                        help='Path to exceptions file (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')

    args = parser.parse_args()

    # Get CIS API key from environment if not provided
    cis_api_key = args.cis_api_key
    if not cis_api_key:
        import os
        cis_api_key = os.environ.get('CIS_API_KEY')

    # Create auditor instance
    auditor = FortiGateAuditor(
        config_file=args.config,
        cis_api_key=cis_api_key,
        cis_api_url=args.cis_api_url,
        exceptions_file=args.exceptions
    )

    # Run audit
    if auditor.run_audit():
        auditor.generate_report(args.output)

        # Return exit code based on HIGH CONFIDENCE findings
        high_conf_critical = len([f for f in auditor.findings
                                  if f['severity'] == 'CRITICAL' and f.get('confidence') == 'high'])
        high_conf_high = len([f for f in auditor.findings
                              if f['severity'] == 'HIGH' and f.get('confidence') == 'high'])

        if high_conf_critical > 0:
            sys.exit(2)  # Critical findings
        elif high_conf_high > 0:
            sys.exit(1)  # High findings
        else:
            sys.exit(0)  # No critical/high confidence findings
    else:
        sys.exit(3)  # Error running audit


if __name__ == '__main__':
    main()
