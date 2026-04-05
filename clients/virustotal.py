"""
VirusTotal API client.

Integrates with VirusTotal v3 API.
https://www.virustotal.com/
"""

import requests
from typing import Dict, Any, Optional
import logging
import time
import os
import hashlib

from .base import BaseSandboxClient

logger = logging.getLogger(__name__)


class VirusTotalClient(BaseSandboxClient):
    """Client for VirusTotal API."""

    BASE_URL = "https://www.virustotal.com/api/v3"
    MAX_RETRIES = 3
    RETRY_DELAY = 3  # seconds

    def __init__(self, api_key: str, timeout: int = 30):
        super().__init__(api_key, timeout)
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "User-Agent": "SOAR-Analyzer/1.0",
        })

    def submit_file(self, file_path: str) -> Dict[str, Any]:
        """
        Submit file to VirusTotal for analysis.

        Args:
            file_path: Path to the file

        Returns:
            {
                "submission_id": "...",
                "status": "queued",
                "sha256": "..."
            }
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Compute file hash first to check if already analyzed
        sha256 = self._compute_file_hash(file_path)
        
        # Check if file is already in VT
        existing_report = self._get_file_by_hash(sha256)
        if existing_report:
            logger.info(f"File already in VirusTotal: {sha256}")
            return {
                "submission_id": sha256,
                "status": "completed",
                "sha256": sha256,
                "raw": existing_report
            }

        # Submit new file
        endpoint = f"{self.BASE_URL}/files"
        self._log_request("POST", endpoint)

        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = self.session.post(
                    endpoint,
                    files=files,
                    timeout=self.timeout
                )

            response.raise_for_status()
            result = response.json()
            self._log_response(response.status_code, len(response.content))

            submission_id = result.get("data", {}).get("id")
            if submission_id:
                return {
                    "submission_id": submission_id,
                    "status": "queued",
                    "sha256": sha256,
                    "raw": result
                }
            else:
                raise Exception("No submission ID in response")

        except requests.RequestException as e:
            logger.error(f"VirusTotal submission failed: {e}")
            raise

    def get_report(self, submission_id: str) -> Dict[str, Any]:
        """
        Retrieve analysis report from VirusTotal.

        Args:
            submission_id: File SHA256 or analysis ID

        Returns:
            Complete report from VirusTotal
        """
        endpoint = f"{self.BASE_URL}/files/{submission_id}"
        self._log_request("GET", endpoint)

        try:
            response = self.session.get(
                endpoint,
                timeout=self.timeout
            )

            if response.status_code == 404:
                raise Exception(f"File not found: {submission_id}")

            response.raise_for_status()
            result = response.json()
            self._log_response(response.status_code, len(response.content))
            return result

        except requests.RequestException as e:
            logger.error(f"Failed to retrieve report: {e}")
            raise

    def check_status(self, submission_id: str) -> Dict[str, Any]:
        """
        Check if analysis is complete.

        Args:
            submission_id: File SHA256 or analysis ID

        Returns:
            {"is_complete": bool, "status_code": int, "message": str}
        """
        endpoint = f"{self.BASE_URL}/files/{submission_id}"
        self._log_request("GET", endpoint)

        try:
            response = self.session.get(
                endpoint,
                timeout=self.timeout
            )

            if response.status_code == 404:
                return {
                    "is_complete": False,
                    "status_code": 404,
                    "message": "File not found or still queued"
                }

            response.raise_for_status()
            self._log_response(response.status_code, len(response.content))

            return {
                "is_complete": True,
                "status_code": 200,
                "message": "Report ready"
            }

        except requests.RequestException as e:
            logger.error(f"Status check failed: {e}")
            return {
                "is_complete": False,
                "status_code": 500,
                "message": str(e)
            }

    def validate_response(self, response: Dict[str, Any]) -> bool:
        """Validate VirusTotal API response."""
        return "data" in response or "attributes" in response

    def _compute_file_hash(self, file_path: str) -> str:
        """Compute SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _get_file_by_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Try to get existing file analysis.

        Args:
            file_hash: SHA256, SHA1, or MD5 hash

        Returns:
            File data if found, None otherwise
        """
        try:
            endpoint = f"{self.BASE_URL}/files/{file_hash}"
            response = self.session.get(
                endpoint,
                timeout=self.timeout
            )

            if response.status_code == 200:
                return response.json().get("data")
            return None

        except requests.RequestException:
            return None

    def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get VirusTotal report for a domain."""
        try:
            endpoint = f"{self.BASE_URL}/domains/{domain}"
            response = self.session.get(
                endpoint,
                timeout=self.timeout
            )

            if response.status_code == 200:
                return response.json().get("data")
            return None

        except requests.RequestException as e:
            logger.warning(f"Failed to get domain report: {e}")
            return None

    def get_ip_report(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get VirusTotal report for an IP address."""
        try:
            endpoint = f"{self.BASE_URL}/ip_addresses/{ip_address}"
            response = self.session.get(
                endpoint,
                timeout=self.timeout
            )

            if response.status_code == 200:
                return response.json().get("data")
            return None

        except requests.RequestException as e:
            logger.warning(f"Failed to get IP report: {e}")
            return None
