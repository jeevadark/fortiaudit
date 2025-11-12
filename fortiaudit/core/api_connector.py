"""
REST API Connector for FortiGate Firewalls

Handles API connections using requests library.
"""

import time
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin
import json

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None

from fortiaudit.utils.logger import get_logger
from fortiaudit.utils.exceptions import ConnectionError, AuthenticationError, APIError

logger = get_logger(__name__)


class APIConnector:
    """REST API connection handler for FortiGate devices"""

    def __init__(
        self,
        hostname: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        """
        Initialize API connector

        Args:
            hostname: Firewall hostname or IP
            api_token: API access token (preferred method)
            username: Username for session-based auth
            password: Password for session-based auth
            port: HTTPS port (default: 443)
            verify_ssl: Verify SSL certificates
            timeout: Request timeout in seconds
        """
        if requests is None:
            raise ImportError("requests library is required for API connections")

        self.hostname = hostname
        self.api_token = api_token
        self.username = username
        self.password = password
        self.port = port
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        self.base_url = f"https://{hostname}:{port}/api/v2"
        self.session: Optional[requests.Session] = None
        self._connected = False

        # Disable SSL warnings if verify_ssl is False
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL verification disabled")

        logger.info(f"API Connector initialized for {hostname}:{port}")

    def connect(self) -> bool:
        """
        Establish API connection

        Returns:
            bool: True if connection successful

        Raises:
            ConnectionError: If connection fails
            AuthenticationError: If authentication fails
        """
        try:
            self.session = requests.Session()

            # Configure retries
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("https://", adapter)

            # Set authentication header
            if self.api_token:
                self.session.headers.update({
                    'Authorization': f'Bearer {self.api_token}'
                })
                logger.info("Using API token authentication")
            elif self.username and self.password:
                # Session-based login
                login_url = urljoin(self.base_url, '/logincheck')
                login_data = {
                    'username': self.username,
                    'secretkey': self.password
                }
                response = self.session.post(
                    login_url,
                    data=login_data,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                if response.status_code != 200:
                    raise AuthenticationError("Login failed")
                logger.info("Using session-based authentication")
            else:
                raise ValueError("Either api_token or username/password must be provided")

            # Test connection
            test_url = urljoin(self.base_url, '/monitor/system/status')
            response = self.session.get(
                test_url,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 401:
                raise AuthenticationError("Invalid credentials or token")
            elif response.status_code != 200:
                raise ConnectionError(f"API test failed: HTTP {response.status_code}")

            self._connected = True
            logger.info(f"✓ Successfully connected to {self.hostname} API")
            return True

        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error: {e}")
            raise ConnectionError(f"SSL certificate verification failed: {e}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            raise ConnectionError(f"Cannot connect to {self.hostname}:{self.port}")
        except requests.exceptions.Timeout:
            logger.error(f"Connection timeout after {self.timeout}s")
            raise ConnectionError(f"Connection timeout: {self.hostname}:{self.port}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise ConnectionError(f"Failed to connect: {e}")

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Send GET request to API

        Args:
            endpoint: API endpoint (e.g., '/cmdb/firewall/policy')
            params: Query parameters

        Returns:
            dict: API response data

        Raises:
            APIError: If request fails
        """
        if not self._connected or not self.session:
            raise ConnectionError("Not connected. Call connect() first.")

        try:
            url = urljoin(self.base_url, endpoint)
            logger.debug(f"GET {url}")

            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            response.raise_for_status()
            data = response.json()

            if data.get('status') == 'error':
                raise APIError(f"API error: {data.get('error')}")

            return data

        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            raise APIError(f"HTTP {e.response.status_code}: {e}")
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout: {endpoint}")
            raise APIError(f"Request timeout: {endpoint}")
        except Exception as e:
            logger.error(f"API request error: {e}")
            raise APIError(f"API request failed: {e}")

    def get_system_status(self) -> Dict[str, Any]:
        """Get system status via API"""
        return self.get('/monitor/system/status')

    def get_firewall_policies(self, vdom: str = 'root') -> List[Dict[str, Any]]:
        """Get firewall policies"""
        response = self.get(f'/cmdb/firewall/policy', params={'vdom': vdom})
        return response.get('results', [])

    def get_interfaces(self, vdom: str = 'root') -> List[Dict[str, Any]]:
        """Get network interfaces"""
        response = self.get(f'/cmdb/system/interface', params={'vdom': vdom})
        return response.get('results', [])

    def get_admin_users(self) -> List[Dict[str, Any]]:
        """Get administrator accounts"""
        response = self.get('/cmdb/system/admin')
        return response.get('results', [])

    def disconnect(self):
        """Close API connection"""
        if self.session:
            try:
                # Logout if session-based
                if self.username:
                    logout_url = urljoin(self.base_url, '/logout')
                    self.session.post(logout_url, verify=self.verify_ssl, timeout=5)
                
                self.session.close()
                logger.info(f"Disconnected from {self.hostname} API")
            except Exception as e:
                logger.warning(f"Error during disconnect: {e}")
            finally:
                self._connected = False
                self.session = None

    def is_connected(self) -> bool:
        """Check if connected"""
        return self._connected and self.session is not None

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
