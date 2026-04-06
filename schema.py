"""
Unified schema for malware analysis reports.

This module defines the canonical data structures used throughout the pipeline.
All API responses are normalized into these dataclasses.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime


class IOCType(str, Enum):
    """Supported IOC types."""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILE_PATH = "file_path"
    REGISTRY = "registry"


class ThreatLevel(str, Enum):
    """Risk/threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class SandboxSource(str, Enum):
    """Supported sandbox platforms."""
    HYBRID_ANALYSIS = "hybrid_analysis"
    VIRUSTOTAL = "virustotal"


@dataclass
class IOC:
    """Indicator of Compromise."""
    ioc_type: IOCType
    value: str
    source: List[SandboxSource] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence: float = 0.0  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash((self.ioc_type, self.value))

    def __eq__(self, other):
        if not isinstance(other, IOC):
            return False
        return self.ioc_type == other.ioc_type and self.value == other.value


@dataclass
class Process:
    """Process information from sandboxed execution."""
    name: str
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    children: List["Process"] = field(default_factory=list)


@dataclass
class NetworkActivity:
    """Network connection attempt."""
    direction: str  # inbound, outbound
    protocol: str  # tcp, udp, dns, http, https
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class FileOperation:
    """File system operation during execution."""
    operation_type: str  # create, read, write, delete, modify
    file_path: str
    timestamp: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MitreAttackTechnique:
    """MITRE ATT&CK technique mapping."""
    technique_id: str  # e.g., "T1566.002"
    technique_name: str
    tactic: str
    confidence: float  # 0.0 to 1.0
    description: Optional[str] = None


@dataclass
class RiskAssessment:
    """Risk scoring and assessment."""
    overall_score: float  # 0-100
    threat_level: ThreatLevel
    confidence: float  # 0-1.0
    reasoning: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)


@dataclass
class UnifiedReport:
    """
    Canonical unified report generated from normalizing sandbox responses.
    """
    # File metadata
    file_name: str
    file_hash_md5: Optional[str] = None
    file_hash_sha1: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size: Optional[int] = None
    file_type: Optional[str] = None

    # Sandbox execution data
    execution_successful: bool = False
    analysis_duration: Optional[float] = None  # in seconds
    submission_timestamp: Optional[datetime] = None
    analysis_timestamp: Optional[datetime] = None

    # Behavioral data
    processes: List[Process] = field(default_factory=list)
    network_activities: List[NetworkActivity] = field(default_factory=list)
    file_operations: List[FileOperation] = field(default_factory=list)

    # Intelligence
    iocs: List[IOC] = field(default_factory=list)
    mitre_techniques: List[MitreAttackTechnique] = field(default_factory=list)
    
    # Analysis results
    verdict: Optional[str] = None  # malicious, suspicious, clean, unknown
    detections: List[str] = field(default_factory=list)  # AV detections
    
    # Risk assessment
    risk: Optional[RiskAssessment] = None
    
    # Source tracking
    source: SandboxSource = SandboxSource.HYBRID_ANALYSIS
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def get_all_hashes(self) -> Dict[str, str]:
        """Return all available hashes."""
        hashes = {}
        if self.file_hash_md5:
            hashes["md5"] = self.file_hash_md5
        if self.file_hash_sha1:
            hashes["sha1"] = self.file_hash_sha1
        if self.file_hash_sha256:
            hashes["sha256"] = self.file_hash_sha256
        return hashes

    def unique_iocs(self) -> List[IOC]:
        """Get deduplicated IOCs."""
        seen = {}
        for ioc in self.iocs:
            key = (ioc.ioc_type, ioc.value)
            if key not in seen:
                seen[key] = ioc
            else:
                # Merge sources
                seen[key].source.extend(ioc.source)
                seen[key].source = list(set(seen[key].source))
        return list(seen.values())


@dataclass
class MergedReport:
    """
    Result of merging multiple UnifiedReports from different sandboxes.
    Deduplicates and resolves conflicts.
    """
    file_name: str
    primary_hash: str  # SHA256 preferred
    all_hashes: Dict[str, str]
    
    # Merged behavioral data
    processes: List[Process] = field(default_factory=list)
    network_activities: List[NetworkActivity] = field(default_factory=list)
    file_operations: List[FileOperation] = field(default_factory=list)
    
    # Consolidated intelligence
    iocs: List[IOC] = field(default_factory=list)
    mitre_techniques: List[MitreAttackTechnique] = field(default_factory=list)
    
    # Aggregated verdicts
    verdicts: Dict[SandboxSource, str] = field(default_factory=dict)
    consensus_verdict: Optional[str] = None
    
    # Detections across all sources
    all_detections: Dict[SandboxSource, List[str]] = field(default_factory=dict)
    
    # Risk scoring
    risk: Optional[RiskAssessment] = None
    
    # Source reports
    source_reports: List[UnifiedReport] = field(default_factory=list)
    merge_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        """Generate summary for quick viewing."""
        return {
            "file_name": self.file_name,
            "hashes": self.all_hashes,
            "consensus_verdict": self.consensus_verdict,
            "threat_level": self.risk.threat_level.value if self.risk else None,
            "risk_score": self.risk.overall_score if self.risk else None,
            "sources_count": len(self.source_reports),
            "ioc_count": len(self.iocs),
            "network_activity_count": len(self.network_activities),
            "process_count": len(self.processes),
            "mitre_techniques_count": len(self.mitre_techniques),
        }
