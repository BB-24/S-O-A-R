"""
Triage API client (optional).

Integrates with Triage.com sandbox API.
https://triage.com/
"""

import requests
from typing import Dict, Any, Optional
import logging
import time
import os

from .base import BaseSandboxClient

logger = logging.getLogger(__name__)


class TriageClient(BaseSandboxClient):
    """Client for Triage sandbox API."""

    BASE_URL = "https://api.triage.com"
    MAX_RETRIES = 3
    RETRY_DELAY = 5

    def __init__(self, api_key: str, timeout: int = 30):
        super().__init__(api_key, timeout)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "SOAR-Analyzer/1.0",
        })

    def submit_file(self, file_path: str) -> Dict[str, Any]:
        """Submit file to Triage."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        endpoint = f"{self.BASE_URL}/v0/samples"
        self._log_request("POST", endpoint)

        try:
            with open(file_path, "rb") as f:
                files = {"file": f}
                response = self.session.post(
                    endpoint,
                    files=files,
                    timeout=self.timeout
                )

            response.raise_for_status()
            result = response.json()
            self._log_response(response.status_code, len(response.content))

            sample_id = result.get("id")
            if sample_id:
                return {
                    "submission_id": sample_id,
                    "status": "queued",
                    "sha256": result.get("sha256"),
                    "raw": result
                }
            else:
                raise Exception("No sample ID in response")

        except requests.RequestException as e:
            logger.error(f"Triage submission failed: {e}")
            raise

    def get_report(self, submission_id: str) -> Dict[str, Any]:
        """Retrieve analysis report from Triage."""
        endpoint = f"{self.BASE_URL}/v0/samples/{submission_id}"
        self._log_request("GET", endpoint)

        try:
            response = self.session.get(
                endpoint,
                timeout=self.timeout
            )

            response.raise_for_status()
            result = response.json()
            self._log_response(response.status_code, len(response.content))
            return result

        except requests.RequestException as e:
            logger.error(f"Failed to retrieve report: {e}")
            raise

    def check_status(self, submission_id: str) -> Dict[str, Any]:
        """Check if analysis is complete."""
        endpoint = f"{self.BASE_URL}/v0/samples/{submission_id}/reports"
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
                    "message": "Report not ready"
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
        """Validate Triage API response."""
        return "id" in response or "sample_id" in response
