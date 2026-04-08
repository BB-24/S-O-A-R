"""
YARA scanner for malware detection and pattern-based IOC extraction.

Scans files and behavior logs against YARA rules to detect malware families,
extract indicators, and enrich IOC analysis.
"""

import yara
import logging
import os
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from schema import IOC, IOCType, IOCSource

logger = logging.getLogger(__name__)


@dataclass
class YARAMatch:
    """YARA match result."""
    rule_name: str
    matches: List[Dict[str, any]]  # List of dicts with identifier, matched_data, offset
    tags: List[str]
    metadata: Dict[str, any]
    strings_matched: List[str]


class YARAScanner:
    """Scanner for YARA-based detection and IOC extraction."""

    def __init__(self, rules_path: str = None):
        """
        Initialize YARA scanner.

        Args:
            rules_path: Path to YARA rules directory or file.
                       If None, uses default locations.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.rules_path = self._resolve_rules_path(rules_path)
        self.rules = self._load_rules()

    def _resolve_rules_path(self, rules_path: Optional[str]) -> Optional[str]:
        """Resolve the YARA rules path."""
        if rules_path and os.path.exists(rules_path):
            return rules_path

        # Try common locations
        common_paths = [
            os.path.join(os.path.dirname(__file__), '..', 'yara_rules'),
            os.path.expanduser('~/yara-rules'),
            'C:\\yara-rules',
            '/opt/yara-rules',
        ]

        for path in common_paths:
            if os.path.exists(path):
                self.logger.info(f"Found YARA rules at {path}")
                return path

        self.logger.warning("No YARA rules path found. Set YARA_RULES_PATH environment variable")
        return None

    def _load_rules(self) -> Optional[yara.Rules]:
        """
        Load YARA rules from directory or file.

        Returns:
            Compiled YARA rules object or None if rules not found
        """
        if not self.rules_path:
            self.logger.info("YARA rules not configured, analyzer disabled")
            return None

        try:
            if os.path.isfile(self.rules_path):
                # Single rule file
                rules = yara.compile(filepath=self.rules_path)
                self.logger.info(f"Loaded YARA rules from {self.rules_path}")
                return rules
            elif os.path.isdir(self.rules_path):
                # Directory of rules
                rules_dict = {}
                yar_count = 0
                
                for root, dirs, files in os.walk(self.rules_path):
                    for file in files:
                        if file.endswith('.yar') or file.endswith('.yara'):
                            rule_path = os.path.join(root, file)
                            try:
                                rule_name = file.replace('.yar', '').replace('.yara', '')
                                rules_dict[rule_name] = rule_path
                                yar_count += 1
                            except Exception as e:
                                self.logger.warning(f"Failed to load rule {rule_path}: {e}")

                if rules_dict:
                    rules = yara.compile(filepaths=rules_dict)
                    self.logger.info(f"Loaded {yar_count} YARA rules from {self.rules_path}")
                    return rules
                else:
                    self.logger.warning(f"No .yar/.yara files found in {self.rules_path}")
                    return None
        except yara.Error as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
            return None

    def scan_file(self, file_path: str) -> List[YARAMatch]:
        """
        Scan a file with YARA rules.

        Args:
            file_path: Path to file to scan

        Returns:
            List of YARA matches
        """
        if not self.rules:
            return []

        if not os.path.exists(file_path):
            self.logger.warning(f"File not found: {file_path}")
            return []

        try:
            matches = self.rules.match(file_path)
            results = []

            for match in matches:
                # Extract strings with their matched instances
                match_details = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        match_details.append({
                            'identifier': string_match.identifier,
                            'matched_data': instance.matched_data,
                            'offset': instance.offset
                        })
                
                yara_match = YARAMatch(
                    rule_name=match.rule,
                    matches=match_details,  # Store as list of dicts instead of tuples
                    tags=match.tags,
                    metadata=match.meta,
                    strings_matched=[m.get('matched_data', b'') if isinstance(m.get('matched_data'), bytes) else str(m.get('matched_data', '')) for m in match_details]
                )
                results.append(yara_match)

            if results:
                self.logger.info(f"Found {len(results)} YARA matches in {file_path}")
            return results

        except yara.Error as e:
            self.logger.error(f"YARA scan error for {file_path}: {e}")
            return []

    def scan_string(self, data: bytes) -> List[YARAMatch]:
        """
        Scan raw data with YARA rules.

        Args:
            data: Bytes to scan

        Returns:
            List of YARA matches
        """
        if not self.rules:
            return []

        try:
            matches = self.rules.match(data=data)
            results = []

            for match in matches:
                # Extract strings with their matched instances
                match_details = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        match_details.append({
                            'identifier': string_match.identifier,
                            'matched_data': instance.matched_data,
                            'offset': instance.offset
                        })
                
                yara_match = YARAMatch(
                    rule_name=match.rule,
                    matches=match_details,  # Store as list of dicts instead of tuples
                    tags=match.tags,
                    metadata=match.meta,
                    strings_matched=[m.get('matched_data', b'') if isinstance(m.get('matched_data'), bytes) else str(m.get('matched_data', '')) for m in match_details]
                )
                results.append(yara_match)

            return results

        except yara.Error as e:
            self.logger.error(f"YARA scan error: {e}")
            return []

    def extract_iocs_from_matches(self, matches: List[YARAMatch]) -> List[IOC]:
        """
        Extract IOCs from YARA matches.

        Args:
            matches: List of YARA matches

        Returns:
            List of extracted IOCs
        """
        iocs = []
        seen = set()

        for match in matches:
            # Create rule match IOC
            ioc_value = f"{match.rule_name}"
            ioc_key = (IOCType.PROCESS_BEHAVIOR, ioc_value)

            if ioc_key not in seen:
                ioc = IOC(
                    ioc_type=IOCType.PROCESS_BEHAVIOR,
                    value=ioc_value,
                    source=[IOCSource.BEHAVIORAL],
                    confidence=0.95,
                    metadata={
                        'yara_match': True,
                        'yara_rule': match.rule_name,
                        'yara_tags': match.tags,
                        'yara_meta': match.metadata,
                        'match_type': 'malware_family'
                    }
                )
                iocs.append(ioc)
                seen.add(ioc_key)

            # Extract strings from matches that look like IOCs
            for match_detail in match.matches:
                identifier = match_detail.get('identifier', '')
                matched_data = match_detail.get('matched_data', b'')
                
                iocs.extend(self._extract_iocs_from_yara_string(
                    identifier, matched_data, match.rule_name, match.tags
                ))

        return iocs

    def _extract_iocs_from_yara_string(
        self,
        identifier: str,
        matched_data: bytes,
        rule_name: str,
        tags: List[str]
    ) -> List[IOC]:
        """
        Extract IOCs from individual YARA string matches.

        Args:
            identifier: String identifier (e.g., "$url", "$ip")
            matched_data: Matched data (bytes)
            rule_name: YARA rule name
            tags: YARA rule tags

        Returns:
            List of extracted IOCs
        """
        iocs = []
        seen = set()

        try:
            # Try to decode matched data
            if isinstance(matched_data, bytes):
                value = matched_data.decode('utf-8', errors='ignore')
            else:
                value = str(matched_data)

            # Determine IOC type based on identifier or content
            ioc_type = self._classify_yara_string(identifier, value)

            if ioc_type is None:
                return iocs

            ioc_key = (ioc_type, value)
            if ioc_key not in seen:
                ioc = IOC(
                    ioc_type=ioc_type,
                    value=value,
                    source=[IOCSource.BEHAVIORAL],
                    confidence=0.85,
                    metadata={
                        'yara_rule': rule_name,
                        'yara_identifier': identifier,
                        'yara_tags': tags,
                        'extraction_method': 'yara_string'
                    }
                )
                iocs.append(ioc)
                seen.add(ioc_key)

        except Exception as e:
            self.logger.debug(f"Error processing YARA string {identifier}: {e}")

        return iocs

    def _classify_yara_string(self, identifier: str, value: str) -> Optional[IOCType]:
        """
        Classify a YARA matched string as an IOC type.

        Args:
            identifier: String identifier (e.g., "$url", "$ip")
            value: Matched value

        Returns:
            IOCType or None if not classifiable
        """
        # Check identifier hints
        identifier_lower = identifier.lower()

        if any(x in identifier_lower for x in ['url', 'uri']):
            if value.startswith('http'):
                return IOCType.URL
        elif any(x in identifier_lower for x in ['ip', 'ipv4', 'address']):
            if self._is_valid_ip(value):
                return IOCType.IP_ADDRESS
        elif any(x in identifier_lower for x in ['domain', 'host', 'dns']):
            if self._is_valid_domain(value):
                return IOCType.DOMAIN
        elif any(x in identifier_lower for x in ['hash', 'md5', 'sha', 'sha256', 'sha1']):
            return self._classify_hash(value)
        elif any(x in identifier_lower for x in ['file', 'path', 'registry']):
            return IOCType.FILE_PATH

        # Fallback content-based classification
        if value.startswith('http'):
            return IOCType.URL
        elif self._is_valid_ip(value):
            return IOCType.IP_ADDRESS
        elif self._is_valid_domain(value):
            return IOCType.DOMAIN
        elif len(value) == 32 and all(c in '0123456789abcdefABCDEF' for c in value):
            return IOCType.MD5
        elif len(value) == 40 and all(c in '0123456789abcdefABCDEF' for c in value):
            return IOCType.SHA1
        elif len(value) == 64 and all(c in '0123456789abcdefABCDEF' for c in value):
            return IOCType.SHA256

        return None

    def _is_valid_ip(self, value: str) -> bool:
        """Check if value is a valid IPv4 address."""
        import re
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ipv4_pattern, value))

    def _is_valid_domain(self, value: str) -> bool:
        """Check if value is a valid domain."""
        import re
        domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$'
        return bool(re.match(domain_pattern, value.lower()))

    def _classify_hash(self, value: str) -> Optional[IOCType]:
        """Classify hash based on length."""
        value_clean = value.strip()
        if not all(c in '0123456789abcdefABCDEF' for c in value_clean):
            return None

        length = len(value_clean)
        if length == 32:
            return IOCType.MD5
        elif length == 40:
            return IOCType.SHA1
        elif length == 64:
            return IOCType.SHA256
        return None
