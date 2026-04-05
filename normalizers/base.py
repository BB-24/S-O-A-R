"""
Base normalizer for converting raw API responses to unified schema.

All normalizers inherit from this base class.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from schema import UnifiedReport


class BaseNormalizer(ABC):
    """Abstract base class for API response normalizers."""

    @abstractmethod
    def normalize(self, raw_response: Dict[str, Any]) -> UnifiedReport:
        """
        Convert raw API response to unified schema.

        Args:
            raw_response: Raw response from sandbox API

        Returns:
            UnifiedReport with normalized data
        """
        pass

    @abstractmethod
    def validate_response(self, raw_response: Dict[str, Any]) -> bool:
        """
        Validate that raw response is suitable for normalization.

        Args:
            raw_response: Raw API response

        Returns:
            True if normalizable, False otherwise
        """
        pass

    def _extract_string(self, data: Dict, key: str, default: str = "") -> str:
        """Safely extract string value."""
        value = data.get(key)
        return str(value) if value is not None else default

    def _extract_int(self, data: Dict, key: str, default: int = 0) -> int:
        """Safely extract integer value."""
        value = data.get(key)
        if isinstance(value, int):
            return value
        try:
            return int(value) if value is not None else default
        except (ValueError, TypeError):
            return default

    def _extract_float(self, data: Dict, key: str, default: float = 0.0) -> float:
        """Safely extract float value."""
        value = data.get(key)
        if isinstance(value, float):
            return value
        try:
            return float(value) if value is not None else default
        except (ValueError, TypeError):
            return default

    def _extract_list(self, data: Dict, key: str, default: list = None) -> list:
        """Safely extract list value."""
        if default is None:
            default = []
        value = data.get(key)
        if isinstance(value, list):
            return value
        return default

    def _extract_nested(self, data: Dict, keys: str, default: Any = None) -> Any:
        """
        Safely extract nested dictionary value.

        Args:
            data: Dictionary to extract from
            keys: Dot-separated key path (e.g., "analysis.verdict")
            default: Default value if not found

        Returns:
            Value at nested path or default
        """
        current = data
        for key in keys.split("."):
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return default
        return current if current is not None else default
