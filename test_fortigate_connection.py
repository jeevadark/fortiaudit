#!/usr/bin/env python3
"""
Test connection to actual FortiGate device

Usage:
    python test_fortigate_connection.py
"""

import sys
import getpass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fortiaudit.core.ssh_connector import SSHConnector
from fortiaudit.core.api_connector import APIConnector
from fortiaudit.utils.logger import get_logger
from fortiaudit.utils.exceptions import ConnectionError, AuthenticationError

logger = get_logger(__name__)


def test_ssh_connection():
    """Test SSH connection to FortiGate"""
    print("\n" + "=" * 60)
    print("SSH Connection Test")
    print("=" * 60)
    
    # Get connection details from user
    hostname = input("FortiGate hostname/IP: ").strip()
    username = input("Username [admin]: ").strip() or "admin"
    
    print("\nAuthentication method:")
    print("1. Password")
    print("2. SSH Key")
    auth_choice = input("Select (1/2) [1]: ").strip() or "1"
    
    if auth_choice == "2":
        key_path = input("SSH key path [~/.ssh/id_rsa]: ").strip() or "~/.ssh/id_rsa"
        password = None
    else:
        password = getpass.getpass("Password: ")
        key_path = None
    
    print("\nAttempting to connect...")
    
    try:
        # Create connector
        connector = SSHConnector(
            hostname=hostname,
            username=username,
            password=password,
            key_file=key_path,
            timeout=30
        )
        
        # Connect
        connector.connect()
        print("✓ Connected successfully!\n")
        
        # Test: Get system status
        print("-" * 60)
        print("Testing: Get System Status")
        print("-" * 60)
        
        status = connector.get_system_status()
        
        print(f"Version: {status.get('Version', 'Unknown')}")
        print(f"Serial: {status.get('Serial Number', 'Unknown')}")
        print(f"Hostname: {status.get('Hostname', 'Unknown')}")
        print(f"System time: {status.get('System time', 'Unknown')}")
        
        # Test: Get partial config (small sample)
        print("\n" + "-" * 60)
        print("Testing: Get Configuration (first 20 lines)")
        print("-" * 60)
        
        result = connector.execute_command('show system global')
        if result['success']:
            lines = result['output'].split('\n')[:20]
            print('\n'.join(lines))
            print(f"\n... (showing first 20 lines)")
        
        # Disconnect
        connector.disconnect()
        print("\n✓ All tests passed!")
        print("✓ SSH connector is working correctly")
        
        return True
        
    except AuthenticationError as e:
        print(f"\n✗ Authentication failed: {e}")
        print("Check your username and password/key")
        return False
        
    except ConnectionError as e:
        print(f"\n✗ Connection failed: {e}")
        print("Check hostname/IP and network connectivity")
        return False
        
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_connection():
    """Test API connection to FortiGate"""
    print("\n" + "=" * 60)
    print("REST API Connection Test")
    print("=" * 60)
    
    hostname = input("FortiGate hostname/IP: ").strip()
    
    print("\nAuthentication method:")
    print("1. API Token (recommended)")
    print("2. Username/Password")
    auth_choice = input("Select (1/2) [1]: ").strip() or "1"
    
    if auth_choice == "1":
        api_token = getpass.getpass("API Token: ")
        username = None
        password = None
    else:
        username = input("Username [admin]: ").strip() or "admin"
        password = getpass.getpass("Password: ")
        api_token = None
    
    verify_ssl = input("Verify SSL certificate? (y/n) [n]: ").strip().lower() != 'y'
    
    print("\nAttempting to connect...")
    
    try:
        # Create connector
        connector = APIConnector(
            hostname=hostname,
            api_token=api_token,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=30
        )
        
        # Connect
        connector.connect()
        print("✓ Connected successfully!\n")
        
        # Test: Get system status
        print("-" * 60)
        print("Testing: Get System Status")
        print("-" * 60)
        
        status = connector.get_system_status()
        
        print(f"Version: {status.get('version', 'Unknown')}")
        print(f"Serial: {status.get('serial', 'Unknown')}")
        print(f"Hostname: {status.get('hostname', 'Unknown')}")
        
        # Test: Get interfaces
        print("\n" + "-" * 60)
        print("Testing: Get Interfaces")
        print("-" * 60)
        
        interfaces = connector.get_interfaces()
        print(f"Found {len(interfaces)} interfaces")
        
        for iface in interfaces[:5]:  # Show first 5
            print(f"  - {iface.get('name')}: {iface.get('ip', 'N/A')}")
        
        if len(interfaces) > 5:
            print(f"  ... and {len(interfaces) - 5} more")
        
        # Disconnect
        connector.disconnect()
        print("\n✓ All tests passed!")
        print("✓ API connector is working correctly")
        
        return True
        
    except AuthenticationError as e:
        print(f"\n✗ Authentication failed: {e}")
        print("Check your API token or credentials")
        return False
        
    except ConnectionError as e:
        print(f"\n✗ Connection failed: {e}")
        print("Check hostname/IP and network connectivity")
        return False
        
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main test menu"""
    print("\n╔" + "═" * 58 + "╗")
    print("║" + " " * 8 + "FortiGate Connection Test" + " " * 25 + "║")
    print("╚" + "═" * 58 + "╝")
    
    print("\nSelect test:")
    print("1. SSH Connection")
    print("2. REST API Connection")
    print("3. Both")
    print("4. Exit")
    
    choice = input("\nSelect (1-4): ").strip()
    
    if choice == "1":
        test_ssh_connection()
    elif choice == "2":
        test_api_connection()
    elif choice == "3":
        test_ssh_connection()
        test_api_connection()
    else:
        print("Exiting...")
        return
    
    print("\n" + "=" * 60)
    print("Testing complete!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(0)
