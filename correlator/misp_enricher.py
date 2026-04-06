"""
MISP-powered IOC enricher for behavioral IOC extraction and threat intelligence.

Extracts IOCs from sandbox behavioral data and enriches them with MISP intelligence.
Covers DNS queries, registry modifications, file drops, and process behavior.
"""

import logging
from typing import List, Dict, Optional, Set
from datetime import datetime

from schema import IOC, IOCType, MergedReport, NetworkActivity, FileOperation, Process
from clients.misp_client import MISPClient

logger = logging.getLogger(__name__)


class MISPEnricher:
    """Enrich IOCs with MISP threat intelligence."""
    
    def __init__(self, misp_client: Optional[MISPClient] = None):
        """
        Initialize MISP enricher.
        
        Args:
            misp_client: MISPClient instance (optional, degrade gracefully if not available)
        """
        self.misp_client = misp_client
        self.misp_available = misp_client is not None and self._test_misp_connection()
    
    def _test_misp_connection(self) -> bool:
        """Test MISP connection."""
        if not self.misp_client:
            return False
        
        try:
            return self.misp_client.check_health()
        except Exception as e:
            logger.warning(f"MISP connection test failed: {e}")
            return False
    
    def enrich_iocs(self, report: MergedReport) -> MergedReport:
        """
        Enrich all IOCs in report with MISP intelligence.
        
        Args:
            report: MergedReport with IOCs to enrich
            
        Returns:
            Report with enriched IOCs
        """
        if not self.misp_available:
            logger.warning("MISP not available, skipping enrichment")
            return report
        
        try:
            logger.info(f"Enriching {len(report.iocs)} IOCs with MISP intelligence")
            
            for ioc in report.iocs:
                self._enrich_single_ioc(ioc)
            
            logger.info(f"Enrichment complete; found {self._count_malicious_iocs(report.iocs)} malicious IOCs")
        except Exception as e:
            logger.error(f"Error enriching IOCs: {e}")
        
        return report
    
    def _enrich_single_ioc(self, ioc: IOC) -> None:
        """Enrich a single IOC with MISP data."""
        if ioc.ioc_type == IOCType.IP_ADDRESS:
            self._enrich_ip(ioc)
        elif ioc.ioc_type == IOCType.DOMAIN:
            self._enrich_domain(ioc)
        elif ioc.ioc_type in [IOCType.MD5, IOCType.SHA1, IOCType.SHA256]:
            self._enrich_hash(ioc)
    
    def _enrich_ip(self, ioc: IOC) -> None:
        """Enrich IP address with MISP data."""
        if not self.misp_client:
            return
        
        try:
            reputation = self.misp_client.get_ip_reputation(ioc.value)
            
            ioc.misp_events = reputation.get("events", [])
            ioc.misp_tags = reputation.get("tags", [])
            ioc.misp_threat_level = reputation.get("threat_level", "medium")
            ioc.is_known_malicious = reputation.get("is_malicious", False)
            ioc.misp_last_checked = datetime.utcnow()
            
            # Boost confidence if known malicious
            if ioc.is_known_malicious:
                ioc.confidence = min(1.0, ioc.confidence + 0.2)
            
            logger.debug(f"Enriched IP {ioc.value}: malicious={ioc.is_known_malicious}, events={len(ioc.misp_events)}")
        except Exception as e:
            logger.warning(f"Error enriching IP {ioc.value}: {e}")
    
    def _enrich_domain(self, ioc: IOC) -> None:
        """Enrich domain with MISP data."""
        if not self.misp_client:
            return
        
        try:
            reputation = self.misp_client.get_domain_reputation(ioc.value)
            
            ioc.misp_events = reputation.get("events", [])
            ioc.misp_tags = reputation.get("tags", [])
            ioc.misp_threat_level = reputation.get("threat_level", "medium")
            ioc.is_known_malicious = reputation.get("is_malicious", False)
            ioc.misp_last_checked = datetime.utcnow()
            
            # Boost confidence if known malicious
            if ioc.is_known_malicious:
                ioc.confidence = min(1.0, ioc.confidence + 0.2)
            
            logger.debug(f"Enriched domain {ioc.value}: malicious={ioc.is_known_malicious}, events={len(ioc.misp_events)}")
        except Exception as e:
            logger.warning(f"Error enriching domain {ioc.value}: {e}")
    
    def _enrich_hash(self, ioc: IOC) -> None:
        """Enrich file hash with MISP data."""
        if not self.misp_client:
            return
        
        try:
            reputation = self.misp_client.get_hash_reputation(ioc.value)
            
            ioc.misp_events = reputation.get("events", [])
            ioc.misp_tags = reputation.get("tags", [])
            ioc.misp_threat_level = reputation.get("threat_level", "medium")
            ioc.is_known_malicious = reputation.get("is_malicious", False)
            ioc.misp_last_checked = datetime.utcnow()
            
            # Store malware types in metadata
            if reputation.get("malware_types"):
                ioc.metadata["malware_types"] = reputation["malware_types"]
            
            # Boost confidence if known malicious
            if ioc.is_known_malicious:
                ioc.confidence = min(1.0, ioc.confidence + 0.3)
            
            logger.debug(f"Enriched hash {ioc.value[:16]}...: malicious={ioc.is_known_malicious}")
        except Exception as e:
            logger.warning(f"Error enriching hash {ioc.value}: {e}")
    
    def extract_behavioral_iocs(self, report: MergedReport) -> None:
        """
        Extract IOCs from behavioral data including:
        - DNS queries (from network activity)
        - Registry modifications
        - Files dropped
        - Live IP connections
        - Process behavior
        """
        logger.info("Extracting behavioral IOCs from network, file, and process activity")
        
        # Track existing IOC values to avoid duplicates
        existing_values = {(ioc.ioc_type, ioc.value.lower()) for ioc in report.iocs}
        
        # Extract DNS queries
        self._extract_dns_queries(report, existing_values)
        
        # Extract dropped files
        self._extract_dropped_files(report, existing_values)
        
        # Extract registry modifications
        self._extract_registry_modifications(report, existing_values)
        
        # Extract IP connections
        self._extract_ip_connections(report, existing_values)
        
        # Extract process behavior IOCs
        self._extract_process_behavior_iocs(report, existing_values)
        
        logger.info(f"Behavioral extraction complete: {len(report.iocs)} total IOCs")
    
    def _extract_dns_queries(self, report: MergedReport, existing: Set) -> None:
        """Extract DNS queries as IOCs."""
        dns_queries = set()
        
        for activity in report.network_activities:
            # DNS activity detection
            if activity.protocol.lower() == 'dns' and activity.domain:
                domain_key = (IOCType.DNS_QUERY, activity.domain.lower())
                
                if domain_key not in existing:
                    ioc = IOC(
                        ioc_type=IOCType.DNS_QUERY,
                        value=activity.domain,
                        source=[],
                        confidence=0.75,
                        metadata={"protocol": "dns", "context": "network_activity"},
                        operation_context="query"
                    )
                    report.iocs.append(ioc)
                    dns_queries.add(activity.domain)
                    existing.add(domain_key)
        
        if dns_queries:
            logger.debug(f"Extracted {len(dns_queries)} DNS queries")
    
    def _extract_dropped_files(self, report: MergedReport, existing: Set) -> None:
        """Extract dropped/created files as IOCs."""
        dropped_files = set()
        
        for op in report.file_operations:
            # Identify dropped files (writes to temp, unusual paths, or files created in system dirs)
            if op.operation_type in ['create', 'write'] and op.file_path:
                file_key = (IOCType.FILE_DROPPED, op.file_path.lower())
                
                # Check if it's a suspicious location
                suspicious_paths = ['temp', 'appdata', 'system32', 'windows', '%temp%', '$temp']
                is_suspicious = any(path in op.file_path.lower() for path in suspicious_paths)
                
                if is_suspicious and file_key not in existing:
                    ioc = IOC(
                        ioc_type=IOCType.FILE_DROPPED,
                        value=op.file_path,
                        source=[],
                        confidence=0.8,
                        metadata={"operation": op.operation_type},
                        operation_context=op.operation_type,
                        process_name=op.details.get("process_name")
                    )
                    report.iocs.append(ioc)
                    dropped_files.add(op.file_path)
                    existing.add(file_key)
        
        if dropped_files:
            logger.debug(f"Extracted {len(dropped_files)} dropped files")
    
    def _extract_registry_modifications(self, report: MergedReport, existing: Set) -> None:
        """Extract registry modifications as IOCs."""
        registry_mods = set()
        
        for op in report.file_operations:
            # Registry operations have special handling
            # Look for registry-like paths (Windows registry operations)
            if 'registry' in op.file_path.lower() or 'hkey' in op.file_path.lower():
                if op.operation_type in ['create', 'write', 'modify']:
                    reg_key = (IOCType.REGISTRY, op.file_path.lower())
                    
                    if reg_key not in existing:
                        ioc = IOC(
                            ioc_type=IOCType.REGISTRY,
                            value=op.file_path,
                            source=[],
                            confidence=0.8,
                            metadata={"operation": op.operation_type},
                            operation_context=op.operation_type,
                            process_name=op.details.get("process_name")
                        )
                        report.iocs.append(ioc)
                        registry_mods.add(op.file_path)
                        existing.add(reg_key)
        
        # Also look for direct registry modifications in network or process context
        # Search using heuristics from detections
        suspicious_registry_patterns = [
            'run', 'runonce', 'winlogon', 'shell', 'cmd', 'powershell',
            'wmi', 'wmiserver', 'services'
        ]
        
        for detection in report.all_detections.values():
            for d in detection if isinstance(detection, list) else [detection]:
                detection_str = str(d).lower()
                if any(pattern in detection_str for pattern in suspicious_registry_patterns):
                    if 'registry' in detection_str or 'hkey' in detection_str:
                        reg_key = (IOCType.REGISTRY, detection_str)
                        if reg_key not in existing:
                            registry_mods.add(detection_str)
        
        if registry_mods:
            logger.debug(f"Extracted {len(registry_mods)} registry modifications")
    
    def _extract_ip_connections(self, report: MergedReport, existing: Set) -> None:
        """Extract live IP connections as IOCs."""
        ip_connections = set()
        
        for activity in report.network_activities:
            # TCP/UDP outbound connections (likely C2 or data exfiltration)
            if activity.destination_ip and activity.protocol.lower() in ['tcp', 'udp']:
                ip_key = (IOCType.IP_ADDRESS, activity.destination_ip.lower())
                
                if ip_key not in existing:
                    # Higher confidence for specific ports (C2 indicators)
                    suspicious_ports = [443, 8080, 8443, 4444, 5555, 6666, 9999, 10000]
                    is_suspicious_port = activity.destination_port in suspicious_ports
                    
                    confidence = 0.85 if is_suspicious_port else 0.7
                    
                    ioc = IOC(
                        ioc_type=IOCType.IP_ADDRESS,
                        value=activity.destination_ip,
                        source=[],
                        confidence=confidence,
                        metadata={
                            "protocol": activity.protocol,
                            "port": activity.destination_port
                        },
                        operation_context=f"{activity.protocol.upper()}:{activity.destination_port}"
                    )
                    report.iocs.append(ioc)
                    ip_connections.add(activity.destination_ip)
                    existing.add(ip_key)
        
        if ip_connections:
            logger.debug(f"Extracted {len(ip_connections)} IP connections")
    
    def _extract_process_behavior_iocs(self, report: MergedReport, existing: Set) -> None:
        """Extract suspicious process behavior as IOCs."""
        suspicious_behaviors = set()
        
        for process in report.processes:
            # Detect process behavior patterns
            if process.command_line:
                # Suspicious command execution patterns
                suspicious_patterns = [
                    'powershell', 'cmd /c', 'wmic', 'rundll32', 'regsvr32',
                    'certutil', 'bitsadmin', 'mshta', 'cscript', 'wscript',
                    '|', '&', '&&', '||', '`', '$env:', 'iex', 'invoke-'
                ]
                
                cmd_lower = process.command_line.lower()
                if any(pattern in cmd_lower for pattern in suspicious_patterns):
                    behavior_key = (IOCType.PROCESS_BEHAVIOR, cmd_lower[:100])
                    
                    if behavior_key not in existing:
                        ioc = IOC(
                            ioc_type=IOCType.PROCESS_BEHAVIOR,
                            value=process.command_line[:255],  # Limit length
                            source=[],
                            confidence=0.75,
                            metadata={"type": "suspicious_command", "process": process.name},
                            process_name=process.name,
                            operation_context="command_execution"
                        )
                        report.iocs.append(ioc)
                        suspicious_behaviors.add(process.name)
                        existing.add(behavior_key)
        
        if suspicious_behaviors:
            logger.debug(f"Extracted {len(suspicious_behaviors)} suspicious process behaviors")
    
    def _count_malicious_iocs(self, iocs: List[IOC]) -> int:
        """Count IOCs marked as known malicious."""
        return sum(1 for ioc in iocs if ioc.is_known_malicious)
