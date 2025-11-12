"""
FortiOS Configuration Parser

Parses FortiGate configuration into structured data.
"""

import re
from typing import Dict, List, Any, Optional
from collections import defaultdict

from fortiaudit.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigParser:
    """Parse and analyze FortiOS configuration"""

    def __init__(self, config_text: str):
        """
        Initialize parser with configuration text

        Args:
            config_text: Raw FortiOS configuration
        """
        self.raw_config = config_text
        self.parsed_config: Dict[str, Any] = {}
        self.policies: List[Dict[str, Any]] = []
        self.admin_users: List[Dict[str, Any]] = []
        self.interfaces: List[Dict[str, Any]] = []
        
        logger.info("ConfigParser initialized")

    def parse(self) -> Dict[str, Any]:
        """
        Parse complete configuration

        Returns:
            dict: Parsed configuration structure
        """
        logger.info("Parsing configuration...")

        self._parse_system_global()
        self._parse_admin_users()
        self._parse_interfaces()
        self._parse_firewall_policies()
        self._parse_zones()
        self._parse_vpn_config()
        self._parse_logging_config()

        logger.info("Configuration parsing complete")
        return self.parsed_config

    def _parse_system_global(self):
        """Parse system global configuration"""
        section = self._extract_config_section('config system global')
        
        settings = {}
        for line in section:
            match = re.match(r'\s*set\s+(\S+)\s+(.*)', line)
            if match:
                key, value = match.groups()
                settings[key] = value.strip('"')

        self.parsed_config['system_global'] = settings
        logger.debug(f"Parsed {len(settings)} system global settings")

    def _parse_admin_users(self):
        """Parse administrator accounts"""
        section = self._extract_config_section('config system admin')
        
        current_user = None
        for line in section:
            edit_match = re.match(r'\s*edit\s+"?([^"]+)"?', line)
            if edit_match:
                current_user = {'name': edit_match.group(1)}
                self.admin_users.append(current_user)
                continue
            
            if current_user:
                set_match = re.match(r'\s*set\s+(\S+)\s+(.*)', line)
                if set_match:
                    key, value = set_match.groups()
                    current_user[key] = value.strip('"')

        self.parsed_config['admin_users'] = self.admin_users
        logger.debug(f"Parsed {len(self.admin_users)} admin users")

    def _parse_interfaces(self):
        """Parse network interfaces"""
        section = self._extract_config_section('config system interface')
        
        current_interface = None
        for line in section:
            edit_match = re.match(r'\s*edit\s+"?([^"]+)"?', line)
            if edit_match:
                current_interface = {'name': edit_match.group(1)}
                self.interfaces.append(current_interface)
                continue
            
            if current_interface:
                set_match = re.match(r'\s*set\s+(\S+)\s+(.*)', line)
                if set_match:
                    key, value = set_match.groups()
                    current_interface[key] = value.strip('"')

        self.parsed_config['interfaces'] = self.interfaces
        logger.debug(f"Parsed {len(self.interfaces)} interfaces")

    def _parse_firewall_policies(self):
        """Parse firewall policies"""
        section = self._extract_config_section('config firewall policy')
        
        current_policy = None
        for line in section:
            edit_match = re.match(r'\s*edit\s+(\d+)', line)
            if edit_match:
                current_policy = {'id': int(edit_match.group(1))}
                self.policies.append(current_policy)
                continue
            
            if current_policy:
                set_match = re.match(r'\s*set\s+(\S+)\s+(.*)', line)
                if set_match:
                    key, value = set_match.groups()
                    # Handle multi-value fields
                    if value.startswith('"'):
                        current_policy[key] = [v.strip('"') for v in value.split('"') if v.strip()]
                    else:
                        current_policy[key] = value.strip()

        self.parsed_config['firewall_policies'] = self.policies
        logger.debug(f"Parsed {len(self.policies)} firewall policies")

    def _parse_zones(self):
        """Parse security zones"""
        section = self._extract_config_section('config system zone')
        
        zones = []
        current_zone = None
        for line in section:
            edit_match = re.match(r'\s*edit\s+"?([^"]+)"?', line)
            if edit_match:
                current_zone = {'name': edit_match.group(1), 'members': []}
                zones.append(current_zone)
                continue
            
            if current_zone:
                set_match = re.match(r'\s*set\s+interface\s+(.*)', line)
                if set_match:
                    interfaces = [i.strip('"') for i in set_match.group(1).split() if i.strip('"')]
                    current_zone['members'] = interfaces

        self.parsed_config['zones'] = zones
        logger.debug(f"Parsed {len(zones)} zones")

    def _parse_vpn_config(self):
        """Parse VPN configuration"""
        vpn_config = {
            'ipsec_phase1': [],
            'ipsec_phase2': [],
            'ssl_settings': {}
        }

        # Parse IPsec Phase 1
        section = self._extract_config_section('config vpn ipsec phase1-interface')
        current_phase1 = None
        for line in section:
            edit_match = re.match(r'\s*edit\s+"?([^"]+)"?', line)
            if edit_match:
                current_phase1 = {'name': edit_match.group(1)}
                vpn_config['ipsec_phase1'].append(current_phase1)
                continue
            
            if current_phase1:
                set_match = re.match(r'\s*set\s+(\S+)\s+(.*)', line)
                if set_match:
                    key, value = set_match.groups()
                    current_phase1[key] = value.strip('"')

        self.parsed_config['vpn'] = vpn_config
        logger.debug(f"Parsed VPN configuration")

    def _parse_logging_config(self):
        """Parse logging configuration"""
        logging_config = {}

        # Parse syslog settings
        section = self._extract_config_section('config log syslogd setting')
        for line in section:
            set_match = re.match(r'\s*set\s+(\S+)\s+(.*)', line)
            if set_match:
                key, value = set_match.groups()
                logging_config[key] = value.strip('"')

        self.parsed_config['logging'] = logging_config
        logger.debug("Parsed logging configuration")

    def _extract_config_section(self, section_start: str) -> List[str]:
        """
        Extract a configuration section

        Args:
            section_start: Section identifier (e.g., 'config system global')

        Returns:
            list: Lines belonging to the section
        """
        lines = []
        in_section = False
        depth = 0

        for line in self.raw_config.split('\n'):
            stripped = line.strip()
            
            if stripped.startswith(section_start):
                in_section = True
                depth = 1
                continue
            
            if in_section:
                if stripped.startswith('config'):
                    depth += 1
                elif stripped == 'end':
                    depth -= 1
                    if depth == 0:
                        break
                
                lines.append(line)

        return lines

    def get_policy_by_id(self, policy_id: int) -> Optional[Dict[str, Any]]:
        """Get specific policy by ID"""
        for policy in self.policies:
            if policy.get('id') == policy_id:
                return policy
        return None

    def get_unused_policies(self, hit_counts: Dict[int, int]) -> List[Dict[str, Any]]:
        """
        Identify policies with zero hits

        Args:
            hit_counts: Dictionary of {policy_id: hit_count}

        Returns:
            list: Unused policies
        """
        unused = []
        for policy in self.policies:
            policy_id = policy.get('id')
            if policy_id and hit_counts.get(policy_id, 0) == 0:
                unused.append(policy)
        return unused

    def find_any_any_policies(self) -> List[Dict[str, Any]]:
        """Find overly permissive ANY/ANY policies"""
        any_any = []
        for policy in self.policies:
            if (policy.get('srcaddr') == ['all'] and 
                policy.get('dstaddr') == ['all'] and
                policy.get('service') == ['ALL']):
                any_any.append(policy)
        return any_any

    def to_dict(self) -> Dict[str, Any]:
        """Export parsed configuration as dictionary"""
        return self.parsed_config
