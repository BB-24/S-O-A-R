"""
MISP (Malware Information Sharing Platform) API client.

For open-source threat intelligence enrichment of IOCs.
Note: Requires MISP instance (self-hosted or cloud).
"""

import requests
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class MISPClient:
    """Client for MISP threat intelligence platform."""
    
    def __init__(self, misp_url: str, api_key: str, verify_ssl: bool = True, timeout: int = 30):
        """
        Initialize MISP client.
        
        Args:
            misp_url: Base URL of MISP instance (e.g., https://misp.example.com)
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        self.misp_url = misp_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make authenticated request to MISP API."""
        url = urljoin(self.misp_url, endpoint)
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.warning(f"MISP request failed: {e}")
            return None
    
    def search_attribute(self, ioc_value: str, ioc_type: str) -> List[Dict[str, Any]]:
        """
        Search for an attribute/IOC in MISP.
        
        Args:
            ioc_value: IOC value (IP, domain, hash, etc.)
            ioc_type: MISP attribute type
            
        Returns:
            List of matching events/attributes
        """
        try:
            payload = {
                "value": ioc_value,
                "type": ioc_type,
                "return_format": "json"
            }
            
            result = self._request('POST', '/attributes/search', json=payload)
            
            if result and 'Attribute' in result:
                return result['Attribute']
            return []
        except Exception as e:
            logger.error(f"Error searching MISP for {ioc_value}: {e}")
            return []
    
    def get_event_tags(self, event_id: int) -> List[str]:
        """Get MISP event tags."""
        try:
            result = self._request('GET', f'/events/view/{event_id}')
            
            if result and 'Event' in result:
                tags = result['Event'].get('Tag', [])
                return [tag.get('name', '') for tag in tags if 'name' in tag]
            return []
        except Exception as e:
            logger.error(f"Error fetching MISP event {event_id}: {e}")
            return []
    
    def get_event_threat_level(self, event_id: int) -> Optional[str]:
        """Get MISP event threat level."""
        try:
            result = self._request('GET', f'/events/view/{event_id}')
            
            if result and 'Event' in result:
                threat_level_id = result['Event'].get('threat_level_id')
                
                # Map MISP threat level IDs to text
                threat_levels = {
                    '1': 'high',
                    '2': 'medium',
                    '3': 'low',
                    '4': 'informational'
                }
                
                return threat_levels.get(str(threat_level_id), 'medium')
            return None
        except Exception as e:
            logger.error(f"Error fetching MISP threat level for {event_id}: {e}")
            return None
    
    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Get comprehensive IP reputation from MISP.
        
        Returns dict with tags, threat_level, events, etc.
        """
        attributes = self.search_attribute(ip, 'ip-dst')
        
        reputation = {
            "value": ip,
            "events": [],
            "tags": set(),
            "threat_level": "medium",
            "is_malicious": False,
            "sources": []
        }
        
        if attributes:
            for attr in attributes:
                event_id = attr.get('event_id')
                if event_id:
                    reputation["events"].append(int(event_id))
                    tags = self.get_event_tags(int(event_id))
                    reputation["tags"].update(tags)
                    
                    threat_level = self.get_event_threat_level(int(event_id))
                    if threat_level == 'high':
                        reputation["threat_level"] = 'high'
            
            reputation["sources"].append("MISP")
            
            # Check if known malicious based on tags
            malicious_indicators = {'trojan', 'malware', 'botnet', 'exploit', 'ransomware', 'worm'}
            if any(ind in str(reputation["tags"]).lower() for ind in malicious_indicators):
                reputation["is_malicious"] = True
        
        reputation["tags"] = list(reputation["tags"])
        return reputation
    
    def get_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Get domain reputation from MISP."""
        attributes = self.search_attribute(domain, 'domain')
        
        reputation = {
            "value": domain,
            "events": [],
            "tags": set(),
            "threat_level": "medium",
            "is_malicious": False,
            "sources": []
        }
        
        if attributes:
            for attr in attributes:
                event_id = attr.get('event_id')
                if event_id:
                    reputation["events"].append(int(event_id))
                    tags = self.get_event_tags(int(event_id))
                    reputation["tags"].update(tags)
                    
                    threat_level = self.get_event_threat_level(int(event_id))
                    if threat_level == 'high':
                        reputation["threat_level"] = 'high'
            
            reputation["sources"].append("MISP")
            
            # Check for phishing, malicious, suspicious tags
            malicious_indicators = {'phishing', 'c2', 'c&c', 'malware', 'botnet', 'exploit'}
            if any(ind in str(reputation["tags"]).lower() for ind in malicious_indicators):
                reputation["is_malicious"] = True
        
        reputation["tags"] = list(reputation["tags"])
        return reputation
    
    def get_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """
        Get file hash reputation from MISP.
        Supports MD5, SHA1, SHA256.
        """
        # Determine hash type
        hash_length = len(file_hash)
        if hash_length == 32:
            hash_type = 'md5'
        elif hash_length == 40:
            hash_type = 'sha1'
        elif hash_length == 64:
            hash_type = 'sha256'
        else:
            logger.warning(f"Unknown hash type for {file_hash}")
            return {}
        
        attributes = self.search_attribute(file_hash, hash_type)
        
        reputation = {
            "value": file_hash,
            "hash_type": hash_type,
            "events": [],
            "tags": set(),
            "threat_level": "medium",
            "is_malicious": False,
            "malware_types": set(),
            "sources": []
        }
        
        if attributes:
            for attr in attributes:
                event_id = attr.get('event_id')
                if event_id:
                    reputation["events"].append(int(event_id))
                    tags = self.get_event_tags(int(event_id))
                    reputation["tags"].update(tags)
                    
                    threat_level = self.get_event_threat_level(int(event_id))
                    if threat_level == 'high':
                        reputation["threat_level"] = 'high'
                    
                    # Extract malware family if present in tags
                    for tag in tags:
                        if ':' in tag:
                            category, value = tag.split(':', 1)
                            if category.lower() in ['malware', 'family']:
                                reputation["malware_types"].add(value)
            
            reputation["sources"].append("MISP")
            
            malicious_indicators = {'trojan', 'malware', 'ransomware', 'worm', 'exploit', 'backdoor'}
            if any(ind in str(reputation["tags"]).lower() for ind in malicious_indicators):
                reputation["is_malicious"] = True
        
        reputation["tags"] = list(reputation["tags"])
        reputation["malware_types"] = list(reputation["malware_types"])
        return reputation
    
    def check_health(self) -> bool:
        """Check if MISP instance is accessible."""
        try:
            result = self._request('GET', '/servers/getPyMISPVersion')
            return result is not None and 'version' in str(result).lower()
        except Exception as e:
            logger.error(f"MISP health check failed: {e}")
            return False
