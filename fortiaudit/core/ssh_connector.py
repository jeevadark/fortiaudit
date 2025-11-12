"""
SSH Connector for FortiGate Firewalls

Handles SSH connections using Paramiko library.
"""

import time
import socket
from typing import Optional, Dict, Any
from pathlib import Path

try:
    import paramiko
except ImportError:
    paramiko = None

from fortiaudit.utils.logger import get_logger
from fortiaudit.utils.exceptions import ConnectionError, AuthenticationError, CommandError

logger = get_logger(__name__)


class SSHConnector:
    """SSH connection handler for FortiGate devices"""

    def __init__(
        self,
        hostname: str,
        username: str,
        password: Optional[str] = None,
        key_file: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
    ):
        """
        Initialize SSH connector

        Args:
            hostname: Firewall hostname or IP
            username: SSH username
            password: SSH password (optional if using key)
            key_file: Path to SSH private key (optional if using password)
            port: SSH port (default: 22)
            timeout: Connection timeout in seconds
        """
        if paramiko is None:
            raise ImportError("paramiko library is required. Install: pip install paramiko")

        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.timeout = timeout

        self.client: Optional[paramiko.SSHClient] = None
        self.shell: Optional[paramiko.Channel] = None
        self._connected = False

        logger.info(f"SSH Connector initialized for {hostname}:{port}")

    def connect(self) -> bool:
        """
        Establish SSH connection

        Returns:
            bool: True if connection successful

        Raises:
            ConnectionError: If connection fails
            AuthenticationError: If authentication fails
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Prepare authentication
            connect_kwargs = {
                'hostname': self.hostname,
                'port': self.port,
                'username': self.username,
                'timeout': self.timeout,
                'look_for_keys': False,
                'allow_agent': False,
            }

            # Add authentication method
            if self.key_file:
                key_path = Path(self.key_file).expanduser()
                if not key_path.exists():
                    raise FileNotFoundError(f"SSH key file not found: {key_path}")
                connect_kwargs['key_filename'] = str(key_path)
                logger.info(f"Using SSH key authentication: {key_path}")
            elif self.password:
                connect_kwargs['password'] = self.password
                logger.info("Using password authentication")
            else:
                raise ValueError("Either password or key_file must be provided")

            # Attempt connection
            logger.info(f"Connecting to {self.hostname}:{self.port}...")
            self.client.connect(**connect_kwargs)

            # Test connection with simple command
            stdin, stdout, stderr = self.client.exec_command('get system status', timeout=10)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')

            if error and 'Command fail' in error:
                raise CommandError(f"Test command failed: {error}")

            self._connected = True
            logger.info(f"✓ Successfully connected to {self.hostname}")
            return True

        except paramiko.AuthenticationException as e:
            logger.error(f"Authentication failed: {e}")
            raise AuthenticationError(f"SSH authentication failed: {e}")
        except paramiko.SSHException as e:
            logger.error(f"SSH error: {e}")
            raise ConnectionError(f"SSH connection error: {e}")
        except socket.timeout:
            logger.error(f"Connection timeout after {self.timeout}s")
            raise ConnectionError(f"Connection timeout: {self.hostname}:{self.port}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise ConnectionError(f"Failed to connect: {e}")

    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute command on FortiGate

        Args:
            command: FortiOS command to execute
            timeout: Command timeout in seconds

        Returns:
            dict: {
                'command': str,
                'output': str,
                'error': str,
                'exit_code': int,
                'success': bool
            }

        Raises:
            ConnectionError: If not connected
            CommandError: If command execution fails
        """
        if not self._connected or not self.client:
            raise ConnectionError("Not connected. Call connect() first.")

        try:
            logger.debug(f"Executing command: {command}")

            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()

            logger.debug(f"Command completed with exit code: {exit_code}")

            return {
                'command': command,
                'output': output,
                'error': error,
                'exit_code': exit_code,
                'success': exit_code == 0 and 'Command fail' not in error
            }

        except socket.timeout:
            logger.error(f"Command timeout after {timeout}s: {command}")
            raise CommandError(f"Command timeout: {command}")
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            raise CommandError(f"Failed to execute command: {e}")

    def get_config(self, config_type: str = 'full') -> str:
        """
        Get firewall configuration

        Args:
            config_type: 'full' or 'partial'

        Returns:
            str: Configuration output
        """
        if config_type == 'full':
            command = 'show full-configuration'
        else:
            command = 'show'

        result = self.execute_command(command, timeout=60)
        
        if not result['success']:
            raise CommandError(f"Failed to get config: {result['error']}")

        return result['output']

    def get_system_status(self) -> Dict[str, str]:
        """
        Get system status information

        Returns:
            dict: Parsed system status
        """
        result = self.execute_command('get system status')
        
        if not result['success']:
            raise CommandError("Failed to get system status")

        # Parse output into dictionary
        status = {}
        for line in result['output'].split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                status[key.strip()] = value.strip()

        return status

    def disconnect(self):
        """Close SSH connection"""
        if self.client:
            try:
                self.client.close()
                logger.info(f"Disconnected from {self.hostname}")
            except Exception as e:
                logger.warning(f"Error during disconnect: {e}")
            finally:
                self._connected = False
                self.client = None

    def is_connected(self) -> bool:
        """Check if connected"""
        return self._connected and self.client is not None

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

    def __del__(self):
        """Cleanup on deletion"""
        self.disconnect()
