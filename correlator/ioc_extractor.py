"""
IOC extraction engine using ioc-finder.

Extracts indicators of compromise from unstructured text and data.
"""

import json
import re
import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# Try to import ioc-finder, graceful fallback if not available
try:
    from ioc_finder import find_iocs
    HAS_IOC_FINDER = True
except ImportError:
    logger.warning("ioc-finder not installed, using basic regex extraction")
    HAS_IOC_FINDER = False


class IOCExtractor:
    """Extract indicators of compromise from various sources."""

    # Regex patterns for basic IOC detection
    IPV4_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    DOMAIN_REGEX = r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}'
    URL_REGEX = r'https?://[^\s\]}"\'<>]+'
    MD5_REGEX = r'\b[a-fA-F0-9]{32}\b'
    SHA1_REGEX = r'\b[a-fA-F0-9]{40}\b'
    SHA256_REGEX = r'\b[a-fA-F0-9]{64}\b'
    EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

    def extract(self, data: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from text.

        Args:
            data: Text to extract IOCs from

        Returns:
            Dict with keys: ips, domains, urls, md5, sha1, sha256, emails
        """
        if HAS_IOC_FINDER:
            return self._extract_with_ioc_finder(data)
        else:
            return self._extract_with_regex(data)

    def _extract_with_ioc_finder(self, data: str) -> Dict[str, List[str]]:
        """Use ioc-finder library for extraction."""
        try:
            iocs = find_iocs(data)

            return {
                "ips": self._deduplicate(iocs.get("ip", [])),
                "domains": self._deduplicate(iocs.get("domain", [])),
                "urls": self._deduplicate(iocs.get("url", [])),
                "md5": self._deduplicate(iocs.get("hash", [])),
                "sha1": [],
                "sha256": [],
                "emails": self._deduplicate(iocs.get("email", [])),
            }
        except Exception as e:
            logger.error(f"ioc-finder extraction failed: {e}, falling back to regex")
            return self._extract_with_regex(data)

    def _extract_with_regex(self, data: str) -> Dict[str, List[str]]:
        """Use regex patterns for extraction."""
        results = {
            "ips": self._find_all(data, self.IPV4_REGEX),
            "domains": self._find_all(data, self.DOMAIN_REGEX),
            "urls": self._find_all(data, self.URL_REGEX),
            "md5": self._find_all(data, self.MD5_REGEX),
            "sha1": self._find_all(data, self.SHA1_REGEX),
            "sha256": self._find_all(data, self.SHA256_REGEX),
            "emails": self._find_all(data, self.EMAIL_REGEX),
        }

        # Filter and validate
        results["ips"] = self._filter_ips(results["ips"])
        results["domains"] = self._filter_domains(results["domains"])

        return results

    def _find_all(self, text: str, pattern: str) -> List[str]:
        """Find all matches of pattern in text."""
        try:
            matches = re.findall(pattern, text, re.IGNORECASE)
            return self._deduplicate(matches)
        except Exception as e:
            logger.warning(f"Regex extraction failed for pattern {pattern}: {e}")
            return []

    def _deduplicate(self, items: List[str]) -> List[str]:
        """Remove duplicates while preserving order."""
        seen = set()
        result = []
        for item in items:
            lower_item = item.lower()
            if lower_item not in seen:
                seen.add(lower_item)
                result.append(item)
        return result

    def _filter_ips(self, ips: List[str]) -> List[str]:
        """Filter out invalid or private IPs."""
        private_ranges = [
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
        ]

        filtered = []
        for ip in ips:
            if ip not in private_ranges:
                # Check if private range
                octets = ip.split(".")
                if len(octets) == 4:
                    try:
                        first = int(octets[0])
                        if not (first == 10 or first == 172 or first == 192):
                            filtered.append(ip)
                    except ValueError:
                        pass

        return filtered

    def _filter_domains(self, domains: List[str]) -> List[str]:
        """Filter out invalid domains."""
        filtered = []
        common_tlds = [
            ".com", ".org", ".net", ".edu", ".gov",
            ".co.uk", ".de", ".fr", ".ru", ".cn",
        ]

        for domain in domains:
            # Skip if contains suspicious patterns
            if any(x in domain.lower() for x in ["<", ">", "[", "]", "{", "}"]):
                continue
            # Must be at least 3 chars
            if len(domain) >= 3:
                filtered.append(domain)

        return filtered

    def extract_from_report(self, report_json: Dict) -> Dict[str, List[str]]:
        """Extract IOCs from JSON report."""
        text = json.dumps(report_json)
        return self.extract(text)