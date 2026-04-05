"""
Sandbox Guard - Optional Safety Checks

Performs basic validation and safety checks before submitting files to sandboxes.
"""

import logging
from pathlib import Path
from typing import Tuple, Optional
import os

logger = logging.getLogger(__name__)


class SandboxGuard:
    """Safety checks before sandbox submission."""

    # Define known dangerous file patterns (can be extended)
    DANGEROUS_EXTENSIONS = {
        ".ps1", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".js",
        ".jar", ".class", ".deb", ".rpm", ".sh", ".exe", ".dll",
        ".sys", ".drv", ".msi", ".zip", ".rar", ".7z"
    }

    # Maximum file size for analysis (500MB)
    MAX_FILE_SIZE = 500 * 1024 * 1024

    @staticmethod
    def validate_file(file_path: str) -> Tuple[bool, Optional[str]]:
        """
        Validate file before submission.

        Args:
            file_path: Path to file to validate

        Returns:
            Tuple of (is_safe, warning_message)
        """
        file_path = Path(file_path)

        # Check file exists
        if not file_path.exists():
            return False, f"File not found: {file_path}"

        # Check file is readable
        if not os.access(file_path, os.R_OK):
            return False, f"File is not readable: {file_path}"

        # Check file size
        file_size = file_path.stat().st_size
        if file_size == 0:
            return False, "File is empty"

        if file_size > SandboxGuard.MAX_FILE_SIZE:
            return False, f"File exceeds max size: {file_size} > {SandboxGuard.MAX_FILE_SIZE}"

        # Warnings (not failures)
        warnings = []

        # Check for dangerous extensions
        if file_path.suffix.lower() in SandboxGuard.DANGEROUS_EXTENSIONS:
            # This is expected for malware analysis
            pass

        # Check for filesystem restrictions
        if file_path.name.startswith("."):
            warnings.append("File name starts with dot")

        if " " in str(file_path):
            warnings.append("File path contains spaces")

        warning_msg = "; ".join(warnings) if warnings else None
        return True, warning_msg

    @staticmethod
    def validate_api_key(api_key: Optional[str]) -> bool:
        """
        Basic validation of API key format.

        Args:
            api_key: API key to validate

        Returns:
            True if key looks valid
        """
        if not api_key:
            return False

        # Remove whitespace
        api_key = str(api_key).strip()

        # Key should be at least 10 characters
        if len(api_key) < 10:
            return False

        # Key should not contain obvious placeholders
        if any(x in api_key.lower() for x in ["your_", "xxx", "yyy", "zzz", "example"]):
            return False

        return True

    @staticmethod
    def pre_submission_check(file_path: str, api_key: Optional[str]) -> Tuple[bool, list]:
        """
        Comprehensive pre-submission check.

        Args:
            file_path: File to analyze
            api_key: Sandbox API key

        Returns:
            Tuple of (can_proceed, issues_list)
        """
        issues = []

        # Check file
        file_ok, file_warning = SandboxGuard.validate_file(file_path)
        if not file_ok:
            issues.append(f"File check failed: {file_warning}")
        elif file_warning:
            logger.warning(f"File warning: {file_warning}")

        # Check API key
        if not SandboxGuard.validate_api_key(api_key):
            issues.append("Invalid API key format")

        can_proceed = len(issues) == 0

        if can_proceed:
            logger.info(f"✓ Pre-submission checks passed for {Path(file_path).name}")
        else:
            logger.warning(f"✗ Pre-submission checks failed:")
            for issue in issues:
                logger.warning(f"  - {issue}")

        return can_proceed, issues
