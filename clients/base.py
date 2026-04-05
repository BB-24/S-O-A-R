"""
Base sandbox client with abstract interface.

All sandbox API clients inherit from this base class.
Ensures consistent behavior and contract across all implementations.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class BaseSandboxClient(ABC):
    """Abstract base class for sandbox API clients."""

    def __init__(self, api_key: str, timeout: int = 30):
        """
        Initialize sandbox client.

        Args:
            api_key: API key/token for authentication
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout

    @abstractmethod
    def submit_file(self, file_path: str) -> Dict[str, Any]:
        """
        Submit a file for analysis.

        Args:
            file_path: Path to the file to analyze

        Returns:
            Response containing submission_id and metadata
        """
        pass

    @abstractmethod
    def get_report(self, submission_id: str) -> Dict[str, Any]:
        """
        Retrieve analysis report for a submitted file.

        Args:
            submission_id: Identifier returned by submit_file()

        Returns:
            Complete analysis report in sandbox-native format
        """
        pass

    @abstractmethod
    def check_status(self, submission_id: str) -> Dict[str, Any]:
        """
        Check analysis status without retrieving full report.

        Args:
            submission_id: Identifier returned by submit_file()

        Returns:
            Status dict with keys: is_complete, status_code, message
        """
        pass

    @abstractmethod
    def validate_response(self, response: Dict[str, Any]) -> bool:
        """
        Validate that API response is valid and complete.

        Args:
            response: Raw API response

        Returns:
            True if response is valid, False otherwise
        """
        pass

    def _log_request(self, method: str, endpoint: str, **kwargs):
        """Log API request for debugging."""
        logger.debug(f"{self.__class__.__name__} → {method} {endpoint}")

    def _log_response(self, status_code: int, response_size: int):
        """Log API response for debugging."""
        logger.debug(f"Response: {status_code} ({response_size} bytes)")
