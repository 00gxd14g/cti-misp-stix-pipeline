#!/usr/bin/env python3
"""
Enhanced MISP to STIX/TAXII Threat Intelligence Pipeline
Author: SOC Team
Version: 3.0.0
Features:
- Dual STIX support (1.x and 2.1)
- Native MISP warninglist enforcement with intelligent override
- Context preservation and graph-based IOC relationships  
- Metrics collection and feedback loop
- Legitimate service abuse detection
- Redis caching for state management
"""

import os
import sys
import time
import json
import hashlib
import logging
import argparse
import datetime
import configparser
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import ipaddress

# External imports
import networkx as nx
import redis
import requests
from pymisp import PyMISP, MISPEvent, MISPAttribute
from ratelimit import limits, sleep_and_retry

# STIX 1.x imports
from stix.core import STIXPackage
from stix.indicator import Indicator as STIX1Indicator
from stix.ttp import TTP
from stix.threat_actor import ThreatActor as STIX1ThreatActor
from stix.campaign import Campaign as STIX1Campaign
from stix.common import Confidence
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.uri_object import URI
from cybox.objects.file_object import File as CybOXFile
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox.objects.mutex_object import Mutex

# STIX 2.1 imports
from stix2 import (
    Bundle, Indicator as STIX2Indicator, ThreatActor as STIX2ThreatActor, 
    Campaign as STIX2Campaign, AttackPattern, Malware, Tool, Identity, 
    Relationship, Sighting, Note, ObservedData, IPv4Address,
    DomainName as STIX2DomainName, URL, File as STIX2File, 
    EmailMessage as STIX2EmailMessage, WindowsRegistryKey, Process, Software
)

# TAXII imports
from cabby import create_client  # TAXII 1.x
from taxii2client.v21 import Server, ApiRoot, Collection  # TAXII 2.1

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('threat_intel_pipeline.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

class Config:
    """Centralized configuration management"""
    def __init__(self, config_file='config.ini'):
        self.config = configparser.ConfigParser()
        
        # Default configuration with environment variable fallbacks
        self.config['MISP'] = {
            'url': os.getenv('MISP_URL', ''),
            'key': os.getenv('MISP_KEY', ''),
            'verify_ssl': os.getenv('MISP_VERIFY_SSL', 'true'),
            'timeout': '30'
        }
        
        self.config['TAXII'] = {
            'version': os.getenv('TAXII_VERSION', 'both'),  # '1.x', '2.1', or 'both'
            'taxii1_server': os.getenv('TAXII1_SERVER', ''),
            'taxii1_discovery': os.getenv('TAXII1_DISCOVERY', '/services/discovery'),
            'taxii1_inbox': os.getenv('TAXII1_INBOX', '/services/inbox'),
            'taxii2_server': os.getenv('TAXII2_SERVER', ''),
            'taxii2_api_root': os.getenv('TAXII2_API_ROOT', '/api/v21/'),
            'taxii2_collection': os.getenv('TAXII2_COLLECTION', ''),
            'username': os.getenv('TAXII_USER', ''),
            'password': os.getenv('TAXII_PASS', ''),
            'verify_ssl': 'true'
        }
        
        self.config['REDIS'] = {
            'host': os.getenv('REDIS_HOST', 'localhost'),
            'port': os.getenv('REDIS_PORT', '6379'),
            'db': os.getenv('REDIS_DB', '0'),
            'password': os.getenv('REDIS_PASSWORD', ''),
            'ttl_days': '7'
        }
        
        self.config['PROCESSING'] = {
            'window_days': '90',
            'historical_days': '365',
            'batch_size': '100',
            'rate_limit_calls': '10',
            'rate_limit_period': '60',
            'confidence_threshold': '50',
            'warninglist_check': 'true',
            'warninglist_override_threshold': '50',
            'stix_version': 'both'  # '1.x', '2.1', or 'both'
        }
        
        self.config['OUTPUT'] = {
            'save_stix1_file': 'true',
            'stix1_filename': 'stix1_package.xml',
            'save_stix2_file': 'true',
            'stix2_filename': 'stix2_bundle.json'
        }
        
        # Load from file if exists
        if os.path.exists(config_file):
            self.config.read(config_file)
    
    def get(self, section, key, fallback=None):
        try:
            return self.config.get(section, key)
        except:
            return fallback

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class ThreatContext:
    """Enhanced threat context information"""
    event_id: str
    event_uuid: str
    threat_level: int
    info: str
    date: str
    org: str = ""
    orgc: str = ""
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    attack_patterns: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    sectors: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    galaxy_clusters: List[Dict] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)
    confidence: float = 0.0
    false_positive_rate: float = 0.0

@dataclass
class EnrichedIOC:
    """IOC with full context and metadata"""
    value: str
    type: str
    attribute_id: str
    attribute_uuid: str
    context: ThreatContext
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    sighting_count: int = 0
    relationships: List[Tuple[str, str]] = field(default_factory=list)
    confidence_score: float = 0.0
    is_blocked: bool = False
    warninglist_hits: List[str] = field(default_factory=list)
    override_reason: Optional[str] = None
    ttl: Optional[int] = None
    to_ids: bool = True
    comment: str = ""

class IOCType(Enum):
    """Extended IOC type enumeration"""
    # Network indicators
    IP_DST = "ip-dst"
    IP_SRC = "ip-src"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    URI = "uri"
    USER_AGENT = "user-agent"
    JA3 = "ja3-fingerprint-md5"
    JA3S = "ja3s-fingerprint-md5"
    PORT = "port"
    
    # File indicators
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SSDEEP = "ssdeep"
    IMPHASH = "imphash"
    PEHASH = "pehash"
    FILENAME = "filename"
    FILEPATH = "filepath"
    
    # Email indicators
    EMAIL_SRC = "email-src"
    EMAIL_DST = "email-dst"
    EMAIL_SUBJECT = "email-subject"
    EMAIL_ATTACHMENT = "email-attachment"
    EMAIL_HEADER = "email-header"
    
    # Registry/System
    REGKEY = "regkey"
    REGKEY_VALUE = "regkey|value"
    MUTEX = "mutex"
    PDB = "pdb"
    PROCESS = "process-name"
    
    # Detection rules
    YARA = "yara"
    SIGMA = "sigma"
    SNORT = "snort"

# ============================================================================
# METRICS AND MONITORING
# ============================================================================

class ThreatMetrics:
    """Comprehensive metrics collection"""
    def __init__(self, redis_client):
        self.redis = redis_client
        self.metrics = {
            'iocs_processed': 0,
            'iocs_blocked': 0,
            'iocs_filtered': 0,
            'iocs_overridden': 0,
            'unique_campaigns': set(),
            'unique_threat_actors': set(),
            'attack_patterns_coverage': defaultdict(int),
            'ioc_types_distribution': defaultdict(int),
            'processing_times': [],
            'true_positives': 0,
            'false_positives': 0,
            'errors': 0,
            'legitimate_service_abuse': 0,
            'stix1_packages': 0,
            'stix2_bundles': 0
        }
    
    def update(self, metric_name: str, value: Any):
        """Update metric value"""
        if isinstance(value, set):
            self.metrics[metric_name].update(value)
        elif isinstance(value, (int, float)):
            self.metrics[metric_name] += value
        elif isinstance(value, list):
            self.metrics[metric_name].extend(value)
        else:
            self.metrics[metric_name] = value
    
    def calculate_detection_coverage(self) -> Dict[str, float]:
        """Calculate MITRE ATT&CK coverage percentage"""
        total_techniques = 500  # Approximate number
        covered = len(self.metrics['attack_patterns_coverage'])
        return {
            'coverage_percentage': (covered / total_techniques) * 100,
            'covered_techniques': covered,
            'total_techniques': total_techniques
        }
    
    def get_summary(self) -> Dict:
        """Get comprehensive metrics summary"""
        total_blocked = self.metrics['iocs_blocked']
        total_filtered = self.metrics['iocs_filtered']
        total_overridden = self.metrics['iocs_overridden']
        
        return {
            'iocs_processed': self.metrics['iocs_processed'],
            'warninglist_stats': {
                'total_blocked': total_blocked,
                'filtered_out': total_filtered,
                'overridden': total_overridden,
                'override_rate': (total_overridden / total_blocked * 100) if total_blocked > 0 else 0
            },
            'unique_campaigns': len(self.metrics['unique_campaigns']),
            'unique_actors': len(self.metrics['unique_threat_actors']),
            'detection_coverage': self.calculate_detection_coverage(),
            'false_positive_rate': self._calculate_fp_rate(),
            'legitimate_service_abuse': self.metrics.get('legitimate_service_abuse', 0),
            'output_stats': {
                'stix1_packages': self.metrics['stix1_packages'],
                'stix2_bundles': self.metrics['stix2_bundles']
            }
        }
    
    def _calculate_fp_rate(self) -> float:
        """Calculate false positive rate"""
        total = self.metrics['true_positives'] + self.metrics['false_positives']
        if total == 0:
            return 0.0
        return (self.metrics['false_positives'] / total) * 100

# ============================================================================
# IOC GRAPH MANAGEMENT
# ============================================================================

class IOCGraph:
    """Graph-based IOC relationship management"""
    def __init__(self):
        self.graph = nx.DiGraph()
        self.ioc_metadata = {}
    
    def add_ioc(self, ioc: EnrichedIOC):
        """Add IOC node with metadata"""
        self.graph.add_node(
            ioc.value,
            type=ioc.type,
            confidence=ioc.confidence_score,
            blocked=ioc.is_blocked,
            context=ioc.context
        )
        self.ioc_metadata[ioc.value] = ioc
    
    def add_relationship(self, source: str, target: str, 
                        relationship_type: str, confidence: float = 0.5):
        """Add weighted relationship between IOCs"""
        self.graph.add_edge(
            source, target,
            type=relationship_type,
            weight=confidence
        )
    
    def find_threat_clusters(self, min_size: int = 3) -> List[Set[str]]:
        """Find related threat activity clusters"""
        clusters = []
        for component in nx.weakly_connected_components(self.graph):
            if len(component) >= min_size:
                clusters.append(component)
        return clusters
    
    def calculate_ioc_importance(self, ioc: str) -> float:
        """Calculate IOC importance using PageRank"""
        try:
            pagerank = nx.pagerank(self.graph, weight='weight')
            return pagerank.get(ioc, 0.0)
        except:
            return 0.0
    
    def get_kill_chain_path(self, start_ioc: str, end_ioc: str) -> List[str]:
        """Find attack path between IOCs"""
        try:
            return nx.shortest_path(self.graph, start_ioc, end_ioc)
        except nx.NetworkXNoPath:
            return []

# ============================================================================
# MISP PROCESSOR
# ============================================================================

class MISPProcessor:
    """Enhanced MISP event processor with warninglist handling"""
    def __init__(self, config: Config):
        self.config = config
        self.misp = self._init_misp_client()
        self.redis = self._init_redis()
        self.ioc_graph = IOCGraph()
        self.metrics = ThreatMetrics(self.redis)
        
        # Legitimate service abuse patterns
        self.abuse_patterns = {
            'domains': [
                'github.com', 'githubusercontent.com', 'gitlab.com',
                'pastebin.com', 'paste.ee', 'hastebin.com',
                'discord.com', 'discord.gg', 'telegram.org', 't.me',
                'twitter.com', 'x.com', 'facebook.com',
                'drive.google.com', 'docs.google.com',
                'dropbox.com', 'wetransfer.com'
            ],
            'ips': [
                '8.8.8.8', '8.8.4.4',  # Google DNS
                '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
                '9.9.9.9',  # Quad9
                '208.67.222.222'  # OpenDNS
            ],
            'abuse_tags': [
                'c2', 'c&c', 'command-and-control', 'cnc',
                'exfiltration', 'data-theft', 'stealer',
                'dns-tunnel', 'dns-over-https', 'doh', 'dot',
                'dga', 'fast-flux', 'domain-flux'
            ]
        }
    
    def _init_misp_client(self) -> PyMISP:
        """Initialize MISP client with SSL verification"""
        return PyMISP(
            self.config.get('MISP', 'url'),
            self.config.get('MISP', 'key'),
            ssl=self.config.get('MISP', 'verify_ssl').lower() == 'true',
            timeout=int(self.config.get('MISP', 'timeout', 30))
        )
    
    def _init_redis(self) -> redis.Redis:
        """Initialize Redis client for state management"""
        return redis.Redis(
            host=self.config.get('REDIS', 'host'),
            port=int(self.config.get('REDIS', 'port')),
            db=int(self.config.get('REDIS', 'db')),
            password=self.config.get('REDIS', 'password') or None,
            decode_responses=True
        )
    
    def get_events(self, tag: str, last_timestamp: int = 0) -> List[MISPEvent]:
        """Fetch events with warninglist enforcement"""
        try:
            window = int(self.config.get('PROCESSING', 'window_days'))
            
            events = self.misp.search(
                tags=tag,
                timestamp=last_timestamp,
                date_from=datetime.datetime.now() - datetime.timedelta(days=window),
                with_attachments=False,
                pythonify=True,
                include_event_uuid=True,
                include_event_tags=True,
                include_correlations=True,
                include_galaxy=True,
                enforceWarninglist=True  # Native warninglist enforcement
            )
            
            logger.info(f"Fetched {len(events)} events from MISP")
            return events
        except Exception as e:
            logger.error(f"Failed to fetch events: {e}")
            return []
    
    def extract_context(self, event: MISPEvent) -> ThreatContext:
        """Extract comprehensive threat context from event"""
        context = ThreatContext(
            event_id=str(event.id),
            event_uuid=event.uuid,
            threat_level=event.threat_level_id,
            info=event.info,
            date=str(event.date),
            org=event.Org.name if hasattr(event, 'Org') else "",
            orgc=event.Orgc.name if hasattr(event, 'Orgc') else ""
        )
        
        # Extract tags
        if hasattr(event, 'tags'):
            context.tags = [tag.name for tag in event.tags]
        
        # Extract galaxy clusters
        if hasattr(event, 'galaxies'):
            for galaxy in event.galaxies:
                for cluster in galaxy.clusters:
                    # Categorize by galaxy type
                    if galaxy.type == 'threat-actor':
                        context.threat_actors.append(cluster.value)
                    elif galaxy.type == 'campaign':
                        context.campaigns.append(cluster.value)
                    elif galaxy.type == 'malware':
                        context.malware_families.append(cluster.value)
                    elif 'mitre' in galaxy.type.lower():
                        context.attack_patterns.append(cluster.value)
                    elif galaxy.type == 'sector':
                        context.sectors.append(cluster.value)
                    
                    # Store complete cluster data
                    context.galaxy_clusters.append({
                        'type': galaxy.type,
                        'name': galaxy.name,
                        'value': cluster.value,
                        'description': cluster.description if hasattr(cluster, 'description') else '',
                        'meta': cluster.meta if hasattr(cluster, 'meta') else {}
                    })
        
        # Extract kill chain phases from MITRE techniques
        for attack in context.attack_patterns:
            phase = self._get_kill_chain_phase(attack)
            if phase:
                context.kill_chain_phases.append(phase)
        
        # Calculate context confidence
        context.confidence = self._calculate_context_confidence(context)
        
        return context
    
    def _get_kill_chain_phase(self, technique: str) -> Optional[str]:
        """Map MITRE technique to kill chain phase"""
        # Simplified mapping - extend for production
        phase_mapping = {
            'T1595': 'reconnaissance', 'T1592': 'reconnaissance',
            'T1190': 'initial-access', 'T1566': 'initial-access',
            'T1059': 'execution', 'T1203': 'execution',
            'T1055': 'persistence', 'T1547': 'persistence',
            'T1548': 'privilege-escalation', 'T1068': 'privilege-escalation',
            'T1550': 'defense-evasion', 'T1070': 'defense-evasion',
            'T1003': 'credential-access', 'T1555': 'credential-access',
            'T1018': 'discovery', 'T1057': 'discovery',
            'T1021': 'lateral-movement', 'T1072': 'lateral-movement',
            'T1074': 'collection', 'T1005': 'collection',
            'T1571': 'command-and-control', 'T1071': 'command-and-control',
            'T1041': 'exfiltration', 'T1048': 'exfiltration',
            'T1486': 'impact', 'T1489': 'impact'
        }
        
        for t_id, phase in phase_mapping.items():
            if t_id in technique:
                return phase
        return None
    
    def _calculate_context_confidence(self, context: ThreatContext) -> float:
        """Calculate confidence score based on context richness"""
        score = 50.0  # Base score
        
        # Attribution boosts
        if context.threat_actors:
            score += 15
            # Extra boost for known APTs
            for actor in context.threat_actors:
                if any(apt in actor.upper() for apt in ['APT', 'LAZARUS', 'EMOTET', 'COBALT', 'FIN']):
                    score += 5
                    break
        
        if context.campaigns:
            score += 10
        
        # TTP mapping boosts
        if context.attack_patterns:
            score += min(15, len(context.attack_patterns) * 3)
        
        # Kill chain coverage
        unique_phases = len(set(context.kill_chain_phases))
        score += min(10, unique_phases * 2)
        
        # Threat level adjustment
        threat_level_scores = {1: 20, 2: 10, 3: 0, 4: -10}
        score += threat_level_scores.get(context.threat_level, 0)
        
        # Sector targeting indicates focused campaign
        if context.sectors:
            score += 5
        
        return max(0, min(100, score))
    
    def process_attribute(self, attr: MISPAttribute, context: ThreatContext) -> Optional[EnrichedIOC]:
        """Process attribute with warninglist handling and override logic"""
        try:
            # Deduplication check
            attr_hash = hashlib.sha256(
                f"{attr.uuid}{attr.timestamp}{attr.value}".encode()
            ).hexdigest()
            
            if self.redis.exists(f"processed:{attr_hash}"):
                return None
            
            # Check blocked status from MISP API
            is_blocked = hasattr(attr, 'blocked') and attr.blocked
            warninglist_hits = []
            override_reason = None
            
            if is_blocked:
                # Extract warninglist information
                if hasattr(attr, 'warninglist_hits'):
                    warninglist_hits = attr.warninglist_hits
                logger.info(f"IOC {attr.value} blocked by: {warninglist_hits}")
                self.metrics.update('iocs_blocked', 1)
                
                # Determine if override is warranted
                should_override, reason = self._should_override_warninglist(attr, context)
                
                if not should_override:
                    logger.info(f"Filtered blocked IOC {attr.value} - {warninglist_hits}")
                    self.metrics.update('iocs_filtered', 1)
                    return None
                else:
                    override_reason = reason
                    logger.warning(f"Overriding warninglist for {attr.value} - Reason: {reason}")
                    self.metrics.update('iocs_overridden', 1)
            
            # Create enriched IOC
            enriched = EnrichedIOC(
                value=attr.value,
                type=attr.type,
                attribute_id=str(attr.id),
                attribute_uuid=attr.uuid,
                context=context,
                first_seen=attr.first_seen if hasattr(attr, 'first_seen') else datetime.datetime.now(),
                last_seen=attr.last_seen if hasattr(attr, 'last_seen') else datetime.datetime.now(),
                sighting_count=attr.sighting_count if hasattr(attr, 'sighting_count') else 0,
                confidence_score=self._calculate_ioc_confidence(attr, context, is_blocked),
                is_blocked=is_blocked,
                warninglist_hits=warninglist_hits,
                override_reason=override_reason,
                ttl=self._calculate_ttl(attr, context),
                to_ids=attr.to_ids if hasattr(attr, 'to_ids') else True,
                comment=attr.comment if hasattr(attr, 'comment') else ""
            )
            
            # Extract relationships
            if hasattr(attr, 'object_relation'):
                enriched.relationships.append((attr.object_relation, attr.value))
            
            # Cache processed state
            self.redis.setex(
                f"processed:{attr_hash}",
                86400 * int(self.config.get('REDIS', 'ttl_days', 7)),
                json.dumps({
                    'timestamp': int(time.time()),
                    'blocked': is_blocked,
                    'overridden': override_reason is not None
                })
            )
            
            # Add to graph
            self.ioc_graph.add_ioc(enriched)
            
            # Update metrics
            self.metrics.update('iocs_processed', 1)
            self.metrics.update('ioc_types_distribution', {attr.type: 1})
            
            return enriched
            
        except Exception as e:
            logger.error(f"Failed to process attribute {attr.id}: {e}")
            self.metrics.update('errors', 1)
            return None
    
    def _should_override_warninglist(self, attr: MISPAttribute, context: ThreatContext) -> Tuple[bool, Optional[str]]:
        """Determine if warninglist should be overridden with reason"""
        override_score = 0
        reasons = []
        
        # Check for high-value threat actors
        if context.threat_actors:
            for actor in context.threat_actors:
                if any(apt in actor.upper() for apt in ['APT', 'LAZARUS', 'EMOTET', 'COBALT', 'FIN', 'BEAR', 'PANDA', 'KITTEN']):
                    override_score += 30
                    reasons.append(f"High-value threat actor: {actor}")
                    break
        
        # Critical campaigns
        if context.campaigns:
            override_score += 10
            reasons.append(f"Active campaign: {', '.join(context.campaigns[:2])}")
        
        # High threat level
        if context.threat_level == 1:  # Critical
            override_score += 25
            reasons.append("Critical threat level")
        elif context.threat_level == 2:  # High
            override_score += 15
            reasons.append("High threat level")
        
        # Multiple correlations
        if hasattr(attr, 'correlation_count') and attr.correlation_count > 5:
            override_score += 20
            reasons.append(f"High correlation count: {attr.correlation_count}")
        
        # Recent sightings
        if hasattr(attr, 'sighting_count') and attr.sighting_count > 3:
            override_score += 15
            reasons.append(f"Multiple sightings: {attr.sighting_count}")
        
        # Check for legitimate service abuse
        abuse_detected = self._check_legitimate_service_abuse(attr, context)
        if abuse_detected:
            override_score += 30
            reasons.append("Legitimate service abuse detected")
            self.metrics.update('legitimate_service_abuse', 1)
        
        # Check threshold
        threshold = int(self.config.get('PROCESSING', 'warninglist_override_threshold', 50))
        if override_score >= threshold:
            reason_str = f"Score {override_score}/{threshold}: " + "; ".join(reasons)
            return True, reason_str
        
        return False, None
    
    def _check_legitimate_service_abuse(self, attr: MISPAttribute, context: ThreatContext) -> bool:
        """Detect abuse of legitimate services for malicious purposes"""
        # Check domains
        if attr.type in ['domain', 'hostname', 'url']:
            value_lower = attr.value.lower()
            for domain in self.abuse_patterns['domains']:
                if domain in value_lower:
                    # Check for abuse indicators in tags/context
                    for tag in context.tags:
                        if any(abuse in tag.lower() for abuse in self.abuse_patterns['abuse_tags']):
                            logger.warning(f"Legitimate service abuse: {attr.value} with tag {tag}")
                            return True
        
        # Check IPs (DNS servers for tunneling)
        if attr.type in ['ip-dst', 'ip-src']:
            if attr.value in self.abuse_patterns['ips']:
                # Check for DNS tunneling indicators
                dns_abuse_tags = ['dns-tunnel', 'doh', 'dot', 'dns-over-https']
                for tag in context.tags:
                    if any(abuse in tag.lower() for abuse in dns_abuse_tags):
                        logger.warning(f"DNS service abuse: {attr.value} with tag {tag}")
                        return True
        
        return False
    
    def _calculate_ioc_confidence(self, attr: MISPAttribute, context: ThreatContext, is_blocked: bool = False) -> float:
        """Calculate IOC-specific confidence with warninglist consideration"""
        base_confidence = context.confidence
        
        # Penalty for blocked IOCs
        if is_blocked:
            base_confidence -= 20
            logger.debug(f"Reduced confidence for blocked IOC {attr.value}: -20 points")
        
        # IDS flag boost
        if hasattr(attr, 'to_ids') and attr.to_ids:
            base_confidence += 10
        
        # Sighting boost
        if hasattr(attr, 'sighting_count'):
            base_confidence += min(10, attr.sighting_count * 2)
        
        # Correlation boost
        if hasattr(attr, 'correlation_count'):
            base_confidence += min(15, attr.correlation_count * 3)
        
        # Verified IOC boost
        if not is_blocked and hasattr(attr, 'verified') and attr.verified:
            base_confidence += 15
        
        return min(100, max(0, base_confidence))
    
    def _calculate_ttl(self, attr: MISPAttribute, context: ThreatContext) -> int:
        """Calculate Time To Live for IOC in days"""
        # Base TTL by IOC type
        ttl_by_type = {
            'ip-dst': 30, 'ip-src': 30,
            'domain': 90, 'hostname': 90,
            'url': 60, 'uri': 60,
            'md5': 365, 'sha1': 365, 'sha256': 365,
            'email-src': 180, 'email-dst': 180,
            'regkey': 365, 'mutex': 365
        }
        
        base_ttl = ttl_by_type.get(attr.type, 60)
        
        # Adjust for APT persistence
        if context.threat_actors:
            if any('APT' in actor for actor in context.threat_actors):
                base_ttl *= 2
        
        # Adjust based on confidence
        if context.confidence > 80:
            base_ttl = int(base_ttl * 1.5)
        elif context.confidence < 30:
            base_ttl = int(base_ttl * 0.5)
        
        return base_ttl
    
    def build_relationships(self, iocs: List[EnrichedIOC]):
        """Build comprehensive IOC relationship graph"""
        for i, ioc1 in enumerate(iocs):
            for ioc2 in iocs[i+1:]:
                # Same event relationship
                if ioc1.context.event_id == ioc2.context.event_id:
                    self.ioc_graph.add_relationship(
                        ioc1.value, ioc2.value,
                        'same-event',
                        confidence=0.8
                    )
                
                # Same campaign
                common_campaigns = set(ioc1.context.campaigns) & set(ioc2.context.campaigns)
                if common_campaigns:
                    self.ioc_graph.add_relationship(
                        ioc1.value, ioc2.value,
                        'same-campaign',
                        confidence=0.9
                    )
                
                # Same threat actor
                common_actors = set(ioc1.context.threat_actors) & set(ioc2.context.threat_actors)
                if common_actors:
                    self.ioc_graph.add_relationship(
                        ioc1.value, ioc2.value,
                        'same-actor',
                        confidence=0.95
                    )

# ============================================================================
# STIX 1.x BUILDER
# ============================================================================

class STIX1Builder:
    """STIX 1.x package builder for legacy SIEM compatibility"""
    def __init__(self):
        self.package = STIXPackage()
        self.package.stix_header.title = "MISP Threat Intelligence Feed"
        self.package.stix_header.description = "Automated MISP to STIX 1.x conversion"
        
    def add_ioc(self, ioc: EnrichedIOC):
        """Convert enriched IOC to STIX 1.x indicator"""
        indicator = STIX1Indicator()
        indicator.title = f"{ioc.type}: {ioc.value}"
        indicator.description = f"Context: {ioc.context.info}"
        
        # Add confidence
        confidence = Confidence()
        confidence.value = ioc.confidence_score / 100.0  # Normalize to 0-1
        indicator.confidence = confidence
        
        # Create observable based on type
        observable = self._create_observable(ioc.type, ioc.value)
        if observable:
            indicator.add_observable(observable)
            
            # Add warninglist notation if overridden
            if ioc.is_blocked and ioc.override_reason:
                indicator.description += f"\n[WARNINGLIST OVERRIDE] {ioc.override_reason}"
            
            self.package.add_indicator(indicator)
        
        # Add threat actors
        for actor_name in ioc.context.threat_actors:
            actor = STIX1ThreatActor()
            actor.title = actor_name
            actor.description = f"Associated with: {ioc.context.info}"
            self.package.add_threat_actor(actor)
            indicator.add_indicated_threat_actor(actor)
        
        # Add campaigns
        for campaign_name in ioc.context.campaigns:
            campaign = STIX1Campaign()
            campaign.title = campaign_name
            campaign.description = f"Campaign: {ioc.context.info}"
            self.package.add_campaign(campaign)
            indicator.add_indicated_campaign(campaign)
        
        # Add TTPs for attack patterns
        for technique in ioc.context.attack_patterns:
            ttp = TTP()
            ttp.title = technique
            self.package.add_ttp(ttp)
            indicator.add_indicated_ttp(ttp)
    
    def _create_observable(self, ioc_type: str, value: str):
        """Create CybOX observable for STIX 1.x"""
        try:
            if ioc_type in ['ip-dst', 'ip-src']:
                return Address(address_value=value, category=Address.CAT_IPV4)
            elif ioc_type in ['domain', 'hostname']:
                return DomainName(value=value)
            elif ioc_type in ['url', 'uri']:
                return URI(value=value, type_=URI.TYPE_URL)
            elif ioc_type == 'md5':
                f = CybOXFile()
                f.md5 = value
                return f
            elif ioc_type == 'sha1':
                f = CybOXFile()
                f.sha1 = value
                return f
            elif ioc_type == 'sha256':
                f = CybOXFile()
                f.sha256 = value
                return f
            elif ioc_type == 'sha512':
                f = CybOXFile()
                f.sha512 = value
                return f
            elif ioc_type == 'filename':
                f = CybOXFile()
                f.file_name = value
                return f
            elif ioc_type in ['email-src', 'email-dst']:
                e = EmailMessage()
                if ioc_type == 'email-src':
                    e.from_ = value
                else:
                    e.to = value
                return e
            elif ioc_type == 'regkey':
                return WinRegistryKey(key=value)
            elif ioc_type == 'mutex':
                return Mutex(name=value)
        except Exception as e:
            logger.error(f"Failed to create observable for {ioc_type}: {e}")
            return None
    
    def get_package(self) -> STIXPackage:
        """Get the complete STIX 1.x package"""
        return self.package
    
    def save_to_file(self, filepath: str):
        """Save STIX 1.x package to XML file"""
        try:
            with open(filepath, 'wb') as f:
                f.write(self.package.to_xml())
            logger.info(f"STIX 1.x package saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save STIX 1.x package: {e}")

# ============================================================================
# STIX 2.1 BUILDER
# ============================================================================

class STIX21Builder:
    """STIX 2.1 bundle builder with enhanced features"""
    def __init__(self):
        self.objects = []
        self.relationships = []
        self.sightings = []
        self.notes = []
        self.object_refs = {}
    
    def add_ioc(self, ioc: EnrichedIOC) -> str:
        """Convert enriched IOC to STIX 2.1 indicator"""
        pattern = self._create_pattern(ioc.type, ioc.value)
        if not pattern:
            return None
        
        # Prepare labels
        labels = ["malicious-activity"]
        if ioc.is_blocked:
            labels.append("warninglist-override")
            if "service abuse" in (ioc.override_reason or "").lower():
                labels.append("legitimate-service-abuse")
        
        # Prepare description
        description = f"Context: {ioc.context.info}"
        if ioc.comment:
            description += f"\nComment: {ioc.comment}"
        if ioc.is_blocked and ioc.override_reason:
            description += f"\n⚠️ WARNINGLIST: {', '.join(ioc.warninglist_hits)}"
            description += f"\n🔍 Override: {ioc.override_reason}"
        
        # Create indicator
        indicator = STIX2Indicator(
            name=f"{ioc.type}: {ioc.value}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=ioc.first_seen.isoformat() if isinstance(ioc.first_seen, datetime.datetime) else ioc.first_seen,
            confidence=int(ioc.confidence_score),
            labels=labels,
            description=description,
            external_references=self._create_external_refs(ioc)
        )
        
        self.objects.append(indicator)
        self.object_refs[ioc.value] = indicator.id
        
        # Add warninglist override note
        if ioc.is_blocked and ioc.override_reason:
            note = Note(
                content=f"Warninglist Override Justification: {ioc.override_reason}\n"
                       f"Threat Context: Actors={', '.join(ioc.context.threat_actors) or 'N/A'}, "
                       f"Campaigns={', '.join(ioc.context.campaigns) or 'N/A'}, "
                       f"Threat Level={ioc.context.threat_level}",
                object_refs=[indicator.id],
                labels=["warninglist-override-justification"]
            )
            self.notes.append(note)
        
        # Add threat actors
        for actor_name in ioc.context.threat_actors:
            actor = STIX2ThreatActor(
                name=actor_name,
                labels=["threat-actor"],
                description=f"Associated with: {ioc.context.info}"
            )
            self.objects.append(actor)
            
            rel = Relationship(
                source_ref=indicator.id,
                target_ref=actor.id,
                relationship_type="indicates"
            )
            self.relationships.append(rel)
        
        # Add campaigns
        for campaign_name in ioc.context.campaigns:
            campaign = STIX2Campaign(
                name=campaign_name,
                description=f"Campaign: {ioc.context.info}"
            )
            self.objects.append(campaign)
            
            rel = Relationship(
                source_ref=indicator.id,
                target_ref=campaign.id,
                relationship_type="indicates"
            )
            self.relationships.append(rel)
        
        # Add attack patterns
        for technique in ioc.context.attack_patterns:
            attack_pattern = AttackPattern(
                name=technique,
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": technique.split(' ')[0] if ' ' in technique else technique
                }]
            )
            self.objects.append(attack_pattern)
            
            rel = Relationship(
                source_ref=indicator.id,
                target_ref=attack_pattern.id,
                relationship_type="indicates"
            )
            self.relationships.append(rel)
        
        # Add sighting if present
        if ioc.sighting_count > 0:
            sighting = Sighting(
                sighting_of_ref=indicator.id,
                count=ioc.sighting_count,
                confidence=int(ioc.confidence_score)
            )
            self.sightings.append(sighting)
        
        return indicator.id
    
    def _create_pattern(self, ioc_type: str, value: str) -> Optional[str]:
        """Create STIX 2.1 pattern from IOC"""
        # Escape special characters in value
        value = value.replace("\\", "\\\\").replace("'", "\\'")
        
        pattern_templates = {
            'ip-dst': "[ipv4-addr:value = '{}']",
            'ip-src': "[ipv4-addr:value = '{}']",
            'domain': "[domain-name:value = '{}']",
            'hostname': "[domain-name:value = '{}']",
            'url': "[url:value = '{}']",
            'uri': "[url:value = '{}']",
            'md5': "[file:hashes.MD5 = '{}']",
            'sha1': "[file:hashes.SHA1 = '{}']",
            'sha256': "[file:hashes.SHA256 = '{}']",
            'sha512': "[file:hashes.SHA512 = '{}']",
            'email-src': "[email-addr:value = '{}']",
            'email-dst': "[email-addr:value = '{}']",
            'email-subject': "[email-message:subject = '{}']",
            'filename': "[file:name = '{}']",
            'filepath': "[file:parent_directory_ref.path = '{}']",
            'mutex': "[mutex:name = '{}']",
            'regkey': "[windows-registry-key:key = '{}']",
            'user-agent': "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{}']",
            'ja3-fingerprint-md5': "[network-traffic:extensions.'tls-ext'.ja3 = '{}']",
            'ja3s-fingerprint-md5': "[network-traffic:extensions.'tls-ext'.ja3s = '{}']"
        }
        
        template = pattern_templates.get(ioc_type)
        if template:
            return template.format(value)
        return None
    
    def _create_external_refs(self, ioc: EnrichedIOC) -> List[Dict]:
        """Create external references for IOC"""
        refs = [{
            "source_name": "MISP",
            "external_id": ioc.attribute_uuid,
            "description": f"MISP Event: {ioc.context.event_uuid}"
        }]
        
        # Add MITRE references
        for technique in ioc.context.attack_patterns:
            if 'T' in technique:
                refs.append({
                    "source_name": "mitre-attack",
                    "external_id": technique.split(' ')[0],
                    "description": technique
                })
        
        return refs
    
    def add_graph_relationships(self, graph: IOCGraph):
        """Add graph-based relationships to STIX bundle"""
        for edge in graph.graph.edges(data=True):
            source_id = self.object_refs.get(edge[0])
            target_id = self.object_refs.get(edge[1])
            
            if source_id and target_id:
                rel = Relationship(
                    source_ref=source_id,
                    target_ref=target_id,
                    relationship_type=edge[2].get('type', 'related-to'),
                    confidence=int(edge[2].get('weight', 0.5) * 100)
                )
                self.relationships.append(rel)
    
    def build_bundle(self) -> Bundle:
        """Build final STIX 2.1 bundle"""
        all_objects = self.objects + self.relationships + self.sightings + self.notes
        return Bundle(objects=all_objects)
    
    def save_to_file(self, filepath: str):
        """Save STIX 2.1 bundle to JSON file"""
        try:
            bundle = self.build_bundle()
            with open(filepath, 'w') as f:
                f.write(bundle.serialize(pretty=True))
            logger.info(f"STIX 2.1 bundle saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save STIX 2.1 bundle: {e}")

# ============================================================================
# TAXII PUBLISHERS
# ============================================================================

class TAXII1Publisher:
    """TAXII 1.x publisher for legacy systems"""
    def __init__(self, config: Config):
        self.config = config
        
    @sleep_and_retry
    @limits(calls=10, period=60)
    def publish(self, stix_package: STIXPackage) -> bool:
        """Publish STIX 1.x package to TAXII 1.x server"""
        try:
            server_url = self.config.get('TAXII', 'taxii1_server')
            discovery_path = self.config.get('TAXII', 'taxii1_discovery')
            inbox_path = self.config.get('TAXII', 'taxii1_inbox')
            username = self.config.get('TAXII', 'username')
            password = self.config.get('TAXII', 'password')
            
            # Create TAXII client
            client = create_client(
                discovery_path=server_url + discovery_path,
                use_https='https' in server_url
            )
            client.set_auth(username=username, password=password)
            
            # Push to TAXII
            content = stix_package.to_xml()
            result = client.push(
                content=content,
                content_binding="urn:stix.mitre.org:xml:1.1.1",
                collection_names=["misp-feed"],
                uri=server_url + inbox_path
            )
            
            if result.status == 200:
                logger.info("Successfully published to TAXII 1.x server")
                return True
            else:
                logger.error(f"TAXII 1.x push failed with status: {result.status}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to publish to TAXII 1.x: {e}")
            return False

class TAXII2Publisher:
    """TAXII 2.1 publisher"""
    def __init__(self, config: Config):
        self.config = config
        self.server = None
        self.api_root = None
        self.collection = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize TAXII 2.1 client"""
        try:
            server_url = self.config.get('TAXII', 'taxii2_server')
            username = self.config.get('TAXII', 'username')
            password = self.config.get('TAXII', 'password')
            
            self.server = Server(
                server_url,
                user=username,
                password=password,
                verify=self.config.get('TAXII', 'verify_ssl').lower() == 'true'
            )
            
            # Get API root
            api_root_path = self.config.get('TAXII', 'taxii2_api_root')
            for root in self.server.api_roots:
                if api_root_path in root.url:
                    self.api_root = root
                    break
            
            if not self.api_root and self.server.api_roots:
                self.api_root = self.server.api_roots[0]
            
            # Get collection
            collection_id = self.config.get('TAXII', 'taxii2_collection')
            if self.api_root:
                for col in self.api_root.collections:
                    if col.id == collection_id or col.title == collection_id:
                        self.collection = col
                        break
                
                if not self.collection and self.api_root.collections:
                    self.collection = self.api_root.collections[0]
            
            if self.collection:
                logger.info(f"TAXII 2.1 client initialized: {self.collection.title}")
            
        except Exception as e:
            logger.error(f"Failed to initialize TAXII 2.1 client: {e}")
    
    @sleep_and_retry
    @limits(calls=10, period=60)
    def publish(self, bundle: Bundle) -> bool:
        """Publish STIX 2.1 bundle to TAXII 2.1 server"""
        try:
            if not self.collection:
                logger.error("TAXII 2.1 collection not initialized")
                return False
            
            # Add objects to collection
            response = self.collection.add_objects(bundle)
            
            if response.get('success'):
                logger.info(f"Successfully published {len(bundle.objects)} objects to TAXII 2.1")
                return True
            else:
                logger.error(f"TAXII 2.1 publish failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to publish to TAXII 2.1: {e}")
            return False

# ============================================================================
# FEEDBACK LOOP
# ============================================================================

class FeedbackLoop:
    """Sighting feedback mechanism for continuous improvement"""
    def __init__(self, misp_client: PyMISP, redis_client: redis.Redis):
        self.misp = misp_client
        self.redis = redis_client
    
    def update_sighting(self, ioc_value: str, sighting_type: str = 'true_positive'):
        """Update IOC sighting in MISP and cache"""
        try:
            # Update Redis cache
            key = f"sighting:{ioc_value}"
            self.redis.hincrby(key, sighting_type, 1)
            
            # Update MISP sighting
            if sighting_type == 'true_positive':
                result = self.misp.add_sighting({
                    'value': ioc_value,
                    'type': '0'  # Positive sighting
                })
            else:
                result = self.misp.add_sighting({
                    'value': ioc_value,
                    'type': '1'  # False positive
                })
            
            logger.info(f"Updated sighting for {ioc_value}: {sighting_type}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to update sighting: {e}")
            return None
    
    def get_ioc_reputation(self, ioc_value: str) -> Dict[str, int]:
        """Get IOC reputation from feedback history"""
        key = f"sighting:{ioc_value}"
        return {
            'true_positives': int(self.redis.hget(key, 'true_positive') or 0),
            'false_positives': int(self.redis.hget(key, 'false_positive') or 0)
        }

# ============================================================================
# MAIN PIPELINE
# ============================================================================

class ThreatIntelPipeline:
    """Main orchestration pipeline with dual STIX support"""
    def __init__(self, config_file: str = 'config.ini'):
        self.config = Config(config_file)
        self.processor = MISPProcessor(self.config)
        self.stix1_builder = None
        self.stix2_builder = None
        self.taxii1_publisher = None
        self.taxii2_publisher = None
        
        # Initialize based on configuration
        stix_version = self.config.get('PROCESSING', 'stix_version', 'both').lower()
        taxii_version = self.config.get('TAXII', 'version', 'both').lower()
        
        if stix_version in ['1.x', 'both']:
            self.stix1_builder = STIX1Builder()
        if stix_version in ['2.1', 'both']:
            self.stix2_builder = STIX21Builder()
        
        if taxii_version in ['1.x', 'both'] and self.config.get('TAXII', 'taxii1_server'):
            self.taxii1_publisher = TAXII1Publisher(self.config)
        if taxii_version in ['2.1', 'both'] and self.config.get('TAXII', 'taxii2_server'):
            self.taxii2_publisher = TAXII2Publisher(self.config)
        
        self.feedback_loop = FeedbackLoop(
            self.processor.misp,
            self.processor.redis
        )
        
        # State management
        self.state_file = 'pipeline_state.json'
        self.state = self._load_state()
    
    def _load_state(self) -> Dict:
        """Load pipeline state from file"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            'last_timestamp': 0,
            'processed_events': [],
            'last_run': None
        }
    
    def _save_state(self):
        """Save pipeline state to file"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def run(self, tag: str, once: bool = False):
        """Main execution loop"""
        while True:
            try:
                start_time = time.time()
                logger.info(f"Starting threat intelligence pipeline - Tag: {tag}")
                
                # Fetch events from MISP
                events = self.processor.get_events(tag, self.state['last_timestamp'])
                
                if not events:
                    logger.info("No new events to process")
                    if once:
                        break
                    time.sleep(3600)
                    continue
                
                # Process events and extract IOCs
                all_iocs = []
                max_timestamp = self.state['last_timestamp']
                
                for event in events:
                    # Extract context
                    context = self.processor.extract_context(event)
                    
                    # Update metrics
                    self.processor.metrics.update('unique_campaigns', set(context.campaigns))
                    self.processor.metrics.update('unique_threat_actors', set(context.threat_actors))
                    
                    # Process attributes
                    for attr in event.attributes:
                        ioc = self.processor.process_attribute(attr, context)
                        if ioc:
                            all_iocs.append(ioc)
                    
                    # Update timestamp
                    event_ts = int(event.timestamp)
                    if event_ts > max_timestamp:
                        max_timestamp = event_ts
                
                if not all_iocs:
                    logger.info("No valid IOCs after filtering")
                    self.state['last_timestamp'] = max_timestamp
                    self._save_state()
                    if once:
                        break
                    time.sleep(3600)
                    continue
                
                logger.info(f"Processed {len(all_iocs)} IOCs")
                
                # Build relationships
                self.processor.build_relationships(all_iocs)
                
                # Find threat clusters
                clusters = self.processor.ioc_graph.find_threat_clusters()
                logger.info(f"Found {len(clusters)} threat clusters")
                
                # Build STIX 1.x if enabled
                if self.stix1_builder:
                    logger.info("Building STIX 1.x package")
                    for ioc in all_iocs:
                        self.stix1_builder.add_ioc(ioc)
                    
                    # Save to file if configured
                    if self.config.get('OUTPUT', 'save_stix1_file', 'false').lower() == 'true':
                        filename = self.config.get('OUTPUT', 'stix1_filename')
                        self.stix1_builder.save_to_file(filename)
                    
                    # Publish to TAXII 1.x
                    if self.taxii1_publisher:
                        package = self.stix1_builder.get_package()
                        if self.taxii1_publisher.publish(package):
                            self.processor.metrics.update('stix1_packages', 1)
                
                # Build STIX 2.1 if enabled
                if self.stix2_builder:
                    logger.info("Building STIX 2.1 bundle")
                    for ioc in all_iocs:
                        self.stix2_builder.add_ioc(ioc)
                    
                    # Add graph relationships
                    self.stix2_builder.add_graph_relationships(self.processor.ioc_graph)
                    
                    # Save to file if configured
                    if self.config.get('OUTPUT', 'save_stix2_file', 'false').lower() == 'true':
                        filename = self.config.get('OUTPUT', 'stix2_filename')
                        self.stix2_builder.save_to_file(filename)
                    
                    # Publish to TAXII 2.1
                    if self.taxii2_publisher:
                        bundle = self.stix2_builder.build_bundle()
                        if self.taxii2_publisher.publish(bundle):
                            self.processor.metrics.update('stix2_bundles', 1)
                
                # Update state
                self.state['last_timestamp'] = max_timestamp
                self.state['last_run'] = datetime.datetime.now().isoformat()
                self._save_state()
                
                # Log metrics
                metrics_summary = self.processor.metrics.get_summary()
                logger.info(f"Pipeline metrics:\n{json.dumps(metrics_summary, indent=2)}")
                
                # Calculate processing time
                processing_time = time.time() - start_time
                logger.info(f"Pipeline completed in {processing_time:.2f} seconds")
                
                if once:
                    break
                
                # Wait before next iteration
                time.sleep(3600)
                
            except Exception as e:
                logger.error(f"Pipeline error: {e}", exc_info=True)
                self.processor.metrics.update('errors', 1)
                if once:
                    break
                time.sleep(3600)

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Enhanced MISP to STIX/TAXII Pipeline with dual version support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --tag APT                     # Process APT-tagged events continuously
  %(prog)s --tag ransomware --once       # Single run for ransomware events
  %(prog)s --feedback malicious.com:false_positive  # Update sighting feedback
  %(prog)s --config custom.ini --tag all # Use custom config file
        """
    )
    
    parser.add_argument('--config', default='config.ini', help='Configuration file path')
    parser.add_argument('--tag', required=True, help='MISP tag to filter events')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    parser.add_argument('--feedback', help='Update sighting (format: ioc_value:type)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Handle feedback update
    if args.feedback:
        try:
            ioc_value, sighting_type = args.feedback.split(':')
            if sighting_type not in ['true_positive', 'false_positive']:
                print("Error: Sighting type must be 'true_positive' or 'false_positive'")
                sys.exit(1)
            
            config = Config(args.config)
            misp = PyMISP(
                config.get('MISP', 'url'),
                config.get('MISP', 'key'),
                ssl=config.get('MISP', 'verify_ssl').lower() == 'true'
            )
            redis_client = redis.Redis(
                host=config.get('REDIS', 'host'),
                port=int(config.get('REDIS', 'port')),
                db=int(config.get('REDIS', 'db')),
                password=config.get('REDIS', 'password') or None
            )
            
            feedback = FeedbackLoop(misp, redis_client)
            result = feedback.update_sighting(ioc_value, sighting_type)
            
            if result:
                print(f"✓ Successfully updated sighting for {ioc_value}: {sighting_type}")
                reputation = feedback.get_ioc_reputation(ioc_value)
                print(f"  Current reputation: {reputation}")
            else:
                print(f"✗ Failed to update sighting for {ioc_value}")
                
        except ValueError:
            print("Error: Invalid feedback format. Use: ioc_value:type")
            sys.exit(1)
        except Exception as e:
            print(f"Error updating feedback: {e}")
            sys.exit(1)
    else:
        # Run the main pipeline
        print(f"""
╔══════════════════════════════════════════════════════════╗
║  MISP to STIX/TAXII Threat Intelligence Pipeline v3.0.0  ║
║  -------------------------------------------------------  ║
║  Features:                                                ║
║  • Dual STIX support (1.x and 2.1)                      ║
║  • Native warninglist enforcement with override          ║
║  • Graph-based IOC relationships                        ║
║  • Legitimate service abuse detection                   ║
║  • Comprehensive metrics and feedback loop              ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        pipeline = ThreatIntelPipeline(args.config)
        pipeline.run(args.tag, args.once)

if __name__ == "__main__":
    main()
