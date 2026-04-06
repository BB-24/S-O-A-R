"""
Hybrid Analysis API client.

Integrates with Hybrid Analysis (AnyRun) sandbox API.
https://hybrid-analysis.com/
"""

import requests
from typing import Dict, Any, Optional
import logging
import time
import os

from .base import BaseSandboxClient

logger = logging.getLogger(__name__)


class HybridAnalysisClient(BaseSandboxClient):
    """Client for Hybrid Analysis (AnyRun) sandbox."""

    BASE_URL = "https://www.hybrid-analysis.com/api/v2"
    MAX_RETRIES = 3
    RETRY_DELAY = 5  # seconds

    def __init__(self, api_key: str, timeout: int = 30):
        super().__init__(api_key, timeout)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SOAR-Analyzer/1.0",
            "accept": "application/json",
        })

    def submit_file(self, file_path: str) -> Dict[str, Any]:
        """
        Submit file to Hybrid Analysis for analysis.

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

        endpoints = [
            f"{self.BASE_URL}/submit/file",
            f"{self.BASE_URL}/quick-scan/file",
        ]

        headers = {
            "api-key": self.api_key,
            "user-agent": "SOAR-Analyzer/1.0",
            "accept": "application/json",
        }

        last_error = None
        for endpoint in endpoints:
            self._log_request("POST", endpoint)
            try:
                with open(file_path, "rb") as f:
                    files = {"file": f}
                    response = self.session.post(
                        endpoint,
                        files=files,
                        data={
                            "scan_type": "all",
                            "environment_id": "120",
                            "allow_community_access": "false",
                            "no_share_third_party": "true",
                        },
                        headers=headers,
                        timeout=self.timeout
                    )

                if response.status_code in (404, 405):
                    last_error = requests.HTTPError(
                        f"{response.status_code} for endpoint {endpoint}"
                    )
                    continue

                response.raise_for_status()
                result = response.json()
                self._log_response(response.status_code, len(response.content))

                if result.get("response_code") == 0 or result.get("sha256"):
                    return {
                        "submission_id": result.get("sha256") or result.get("job_id"),
                        "status": "queued",
                        "sha256": result.get("sha256"),
                        "raw": result
                    }
                raise Exception(f"API error: {result.get('response_code')}")

            except requests.RequestException as e:
                last_error = e
                continue

        logger.error(f"Hybrid Analysis submission failed: {last_error}")
        raise last_error if last_error else RuntimeError("Hybrid Analysis submission failed")

    def get_report(self, submission_id: str) -> Dict[str, Any]:
        """
        Retrieve analysis report from Hybrid Analysis.

        Args:
            submission_id: SHA256 hash of the file

        Returns:
            Complete report from Hybrid Analysis
        """
        headers = {
            "api-key": self.api_key,
            "user-agent": "SOAR-Analyzer/1.0",
            "accept": "application/json",
        }
        candidate_endpoints = [
            f"{self.BASE_URL}/report/{submission_id}/summary",
            f"{self.BASE_URL}/overview/{submission_id}",
            f"{self.BASE_URL}/search/hash?hash={submission_id}",
        ]

        last_error = None
        for attempt in range(self.MAX_RETRIES):
            for endpoint in candidate_endpoints:
                self._log_request("GET", endpoint)
                try:
                    response = self.session.get(
                        endpoint,
                        headers=headers,
                        timeout=self.timeout
                    )

                    if response.status_code in (404, 400):
                        continue

                    response.raise_for_status()
                    result = response.json()
                    self._log_response(response.status_code, len(response.content))

                    if isinstance(result, list):
                        if not result:
                            continue
                        return {"results": result}

                    return result

                except requests.RequestException as e:
                    last_error = e
                    continue

            if attempt < self.MAX_RETRIES - 1:
                logger.debug(
                    f"Retry {attempt + 1}/{self.MAX_RETRIES}: Hybrid report not ready"
                )
                time.sleep(self.RETRY_DELAY)

        if last_error:
            logger.error(f"Failed to retrieve report: {last_error}")
            raise last_error
        raise RuntimeError("Hybrid Analysis report not available after retries")

    def check_status(self, submission_id: str) -> Dict[str, Any]:
        """
        Check if analysis is complete.

        Args:
            submission_id: SHA256 hash

        Returns:
            {"is_complete": bool, "status_code": int, "message": str}
        """
        endpoint = f"{self.BASE_URL}/report/{submission_id}"
        self._log_request("GET", endpoint)

        try:
            headers = {
                "api-key": self.api_key,
                "user-agent": "SOAR-Analyzer/1.0"
            }
            
            response = self.session.get(
                endpoint,
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code == 404:
                return {
                    "is_complete": False,
                    "status_code": 404,
                    "message": "Analysis in progress"
                }

            response.raise_for_status()
            result = response.json()
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
        """Validate Hybrid Analysis API response."""
        required_fields = ["sha256", "status"]
        return all(field in response for field in required_fields)

    def get_detailed_report(self, submission_id: str) -> Dict[str, Any]:
        """
        Retrieve detailed analysis report with full behavioral data.

        Args:
            submission_id: SHA256 hash

        Returns:
            Detailed report
        """
        endpoint = f"{self.BASE_URL}/report/{submission_id}/details"
        self._log_request("GET", endpoint)

        try:
            headers = {
                "api-key": self.api_key,
                "user-agent": "SOAR-Analyzer/1.0"
            }
            
            response = self.session.get(
                endpoint,
                headers=headers,
                timeout=self.timeout
            )

            response.raise_for_status()
            result = response.json()
            self._log_response(response.status_code, len(response.content))
            return result

        except requests.RequestException as e:
            logger.error(f"Failed to retrieve detailed report: {e}")
            raise