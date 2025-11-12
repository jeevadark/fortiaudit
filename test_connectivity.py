#!/usr/bin/env python3
"""
Quick connectivity test for FortiAudit

Usage:
    python test_connectivity.py
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from fortiaudit.utils.logger import get_logger
from fortiaudit.utils.exceptions import ConnectionError, AuthenticationError

logger = get_logger(__name__)


def test_logger():
    """Test logging functionality"""
    print("=" * 60)
    print("Testing Logger")
    print("=" * 60)
    
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message")
    logger.debug("Debug message")
    
    print("✓ Logger working\n")


def test_imports():
    """Test all imports"""
    print("=" * 60)
    print("Testing Imports")
    print("=" * 60)
    
    try:
        from fortiaudit.core.ssh_connector import SSHConnector
        print("✓ SSH Connector imported")
    except Exception as e:
        print(f"✗ SSH Connector import failed: {e}")
    
    try:
        from fortiaudit.core.api_connector import APIConnector
        print("✓ API Connector imported")
    except Exception as e:
        print(f"✗ API Connector import failed: {e}")
    
    try:
        from fortiaudit.core.config_parser import ConfigParser
        print("✓ Config Parser imported")
    except Exception as e:
        print(f"✗ Config Parser import failed: {e}")
    
    print()


def test_ssh_connector_init():
    """Test SSH connector initialization"""
    print("=" * 60)
    print("Testing SSH Connector Initialization")
    print("=" * 60)
    
    try:
        from fortiaudit.core.ssh_connector import SSHConnector
        
        # Test initialization (don't connect)
        connector = SSHConnector(
            hostname="192.168.1.1",
            username="admin",
            password="test123"
        )
        
        print(f"✓ SSH Connector initialized")
        print(f"  Hostname: {connector.hostname}")
        print(f"  Username: {connector.username}")
        print(f"  Port: {connector.port}")
        print(f"  Connected: {connector.is_connected()}")
        
    except Exception as e:
        print(f"✗ SSH Connector test failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()


def test_cli_import():
    """Test CLI import"""
    print("=" * 60)
    print("Testing CLI Import")
    print("=" * 60)
    
    try:
        from fortiaudit.cli import FortiAuditCLI
        print("✓ CLI imported successfully")
        
        # Try to instantiate
        cli = FortiAuditCLI()
        print("✓ CLI instantiated")
        
    except Exception as e:
        print(f"✗ CLI test failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 10 + "FortiAudit - Connectivity Tests" + " " * 16 + "║")
    print("╚" + "═" * 58 + "╝")
    print("\n")
    
    test_logger()
    test_imports()
    test_ssh_connector_init()
    test_cli_import()
    
    print("=" * 60)
    print("All tests completed!")
    print("=" * 60)
    print("\n")
    print("Next steps:")
    print("1. Copy complete implementations to core files")
    print("2. Test with actual FortiGate device")
    print("3. Implement check modules")
    print("\n")


if __name__ == "__main__":
    main()
