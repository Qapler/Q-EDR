"""
Command and Control (C2) detection rules.

Covers MITRE ATT&CK Tactic: Command and Control (TA0011).
Each rule queries the Neo4j behavioural graph for evidence of C2 activity,
such as periodic beaconing, DNS tunneling, proxy abuse, and protocol anomalies.

Graph node types used: Host, Process, NetworkConnection, DNSQuery, Domain
Relationships used   : CONNECTED_TO, TRIGGERED, RESOLVED_TO, HAS_PROCESS
"""

import logging
from typing import Any, Dict, List

from .base import (
    MITRETechnique,
    Rule,
    RuleCategory,
    RuleMatch,
    Severity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Periodic Beaconing Detection (T1071.001)
# ---------------------------------------------------------------------------

class BeaconingDetectionRule(Rule):
    """
    Detects highly regular outbound network connections indicative of C2 beaconing.

    Adversaries often configure beacons to phone home at fixed intervals.
    This rule flags internal hosts connecting to the same external destination
    repeatedly within the look-back window.
    """

    rule_id = "C2-001"
    rule_name = "C2 Periodic Beaconing Detected"
    description = (
        "Internal host established repeated periodic connections to an external "
        "endpoint at uniform intervals, indicating automated C2 beaconing."
    )
    severity = Severity.HIGH
    category = RuleCategory.COMMAND_CONTROL
    mitre = MITRETechnique(
        tactic="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        sub_technique_id="001",
    )
    time_window_seconds = 1800
    min_match_count = 1
    tags = ["c2", "beaconing", "network"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:CONNECTED_TO]->(nc:NetworkConnection)-[:CONNECTED_TO]->(ext:Host)
        WHERE ext.is_external = true
          AND nc.timestamp > datetime() - duration({seconds: $time_window})
        WITH h, ext, nc.dst_port AS dst_port,
             count(nc) AS conn_count,
             collect(id(nc)) AS conn_ids,
             collect(nc.timestamp) AS timestamps
        WHERE conn_count >= 10
        RETURN h.ip AS source_ip,
               h.hostname AS source_host,
               ext.ip AS external_ip,
               ext.hostname AS external_host,
               dst_port,
               conn_count,
               conn_ids AS ids
        ORDER BY conn_count DESC
        """


# ---------------------------------------------------------------------------
# 2. Domain Fronting (T1090.004)
# ---------------------------------------------------------------------------

class DomainFrontingRule(Rule):
    """
    Detects domain fronting where TLS SNI disagrees with the application-layer
    Host header or certificate Subject Name.
    """

    rule_id = "C2-002"
    rule_name = "Domain Fronting Detected"
    description = (
        "Network connection observed with mismatched TLS SNI and HTTP Host header, "
        "a technique commonly used to bypass censorship or egress filtering."
    )
    severity = Severity.HIGH
    category = RuleCategory.COMMAND_CONTROL
    mitre = MITRETechnique(
        tactic="Command and Control",
        technique_id="T1090",
        technique_name="Proxy",
        sub_technique_id="004",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["c2", "domain_fronting", "tls"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE nc.tls_sni IS NOT NULL
          AND nc.http_host IS NOT NULL
          AND nc.tls_sni <> nc.http_host
          AND nc.timestamp > datetime() - duration({seconds: $time_window})
        RETURN h.ip AS source_ip,
               h.hostname AS source_host,
               nc.dst_ip AS destination_ip,
               nc.dst_port AS dst_port,
               nc.tls_sni AS tls_sni,
               nc.http_host AS http_host,
               nc.timestamp AS timestamp,
               [id(h), id(nc)] AS ids
        """


# ---------------------------------------------------------------------------
# 3. C2 Over DNS (T1071.004)
# ---------------------------------------------------------------------------

class C2OverDNSRule(Rule):
    """
    Detects high volume or anomalous DNS queries targeting a single suspicious domain,
    characteristic of DNS-based command and control channels.
    """

    rule_id = "C2-003"
    rule_name = "C2 Communication over DNS"
    description = (
        "Abnormal frequency of DNS queries (TXT/NULL/CNAME) issued to a specific root domain, "
        "indicating a DNS-based C2 or staging channel."
    )
    severity = Severity.HIGH
    category = RuleCategory.COMMAND_CONTROL
    mitre = MITRETechnique(
        tactic="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        sub_technique_id="004",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["c2", "dns", "tunneling"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:TRIGGERED]->(dns:DNSQuery)
        WHERE dns.query_type IN ['TXT', 'NULL', 'CNAME']
          AND dns.timestamp > datetime() - duration({seconds: $time_window})
        WITH h,
             split(dns.query_name, '.')[-2] + '.' + split(dns.query_name, '.')[-1] AS base_domain,
             count(dns) AS query_count,
             collect(id(dns))[..10] AS sample_dns_ids
        WHERE query_count >= 20
        RETURN h.ip AS host_ip,
               h.hostname AS hostname,
               base_domain,
               query_count,
               sample_dns_ids AS ids
        ORDER BY query_count DESC
        """


# ---------------------------------------------------------------------------
# 4. Proxy Tunneling (T1090.001)
# ---------------------------------------------------------------------------

class ProxyTunnelingRule(Rule):
    """
    Detects HTTP CONNECT or SOCKS proxy tunneling from endpoints towards non-standard external targets.
    """

    rule_id = "C2-004"
    rule_name = "Suspicious Proxy Tunneling"
    description = (
        "An internal process established a tunnel through a local or external proxy "
        "to arbitrary ports, bypassing firewall restrictions."
    )
    severity = Severity.MEDIUM
    category = RuleCategory.COMMAND_CONTROL
    mitre = MITRETechnique(
        tactic="Command and Control",
        technique_id="T1090",
        technique_name="Proxy",
        sub_technique_id="001",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["c2", "proxy", "tunnel"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE (nc.method = 'CONNECT' OR nc.protocol = 'SOCKS5')
          AND NOT nc.dst_port IN [80, 443]
          AND nc.timestamp > datetime() - duration({seconds: $time_window})
        RETURN h.ip AS host_ip,
               p.name AS process_name,
               p.pid AS pid,
               nc.dst_ip AS destination_ip,
               nc.dst_port AS destination_port,
               nc.protocol AS protocol,
               [id(p), id(nc)] AS ids
        """


# ---------------------------------------------------------------------------
# 5. Non-Standard Port Communications (T1571)
# ---------------------------------------------------------------------------

class NonStandardPortCommsRule(Rule):
    """
    Detects standard protocols (HTTP/HTTPS/SSH) operating over unusual, non-standard ports.
    """

    rule_id = "C2-005"
    rule_name = "Protocol on Non-Standard Port"
    description = (
        "Observed traffic using standard network protocols over non-standard destination ports, "
        "often used to conceal C2 communications."
    )
    severity = Severity.MEDIUM
    category = RuleCategory.COMMAND_CONTROL
    mitre = MITRETechnique(
        tactic="Command and Control",
        technique_id="T1571",
        technique_name="Non-Standard Port",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["c2", "protocol_anomaly", "ports"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE ((nc.protocol = 'HTTP' AND NOT nc.dst_port IN [80, 8080, 8000])
           OR  (nc.protocol = 'HTTPS' AND NOT nc.dst_port IN [443, 8443])
           OR  (nc.protocol = 'SSH' AND NOT nc.dst_port IN [22, 2222]))
          AND nc.direction = 'outbound'
          AND nc.timestamp > datetime() - duration({seconds: $time_window})
        RETURN h.ip AS host_ip,
               nc.dst_ip AS destination_ip,
               nc.dst_port AS dst_port,
               nc.protocol AS protocol,
               nc.bytes_sent AS bytes_sent,
               [id(h), id(nc)] AS ids
        """


# ---------------------------------------------------------------------------
# 6. Encrypted Channel to New/Untrusted Domain (T1573)
# ---------------------------------------------------------------------------

class EncryptedChannelNewDomainRule(Rule):
    """
    Detects outbound encrypted sessions (TLS/SSH) towards newly registered domains
    or domains with low reputation scores.
    """

    rule_id = "C2-006"
    rule_name = "Encrypted Connection to Untrusted Domain"
    description = (
        "An internal host connected over an encrypted channel to a recently registered "
        "or flagged external domain."
    )
    severity = Severity.HIGH
    category = RuleCategory.COMMAND_CONTROL
    mitre = MITRETechnique(
        tactic="Command and Control",
        technique_id="T1573",
        technique_name="Encrypted Channel",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["c2", "tls", "reputation"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:CONNECTED_TO]->(nc:NetworkConnection)-[:RESOLVED_TO]->(d:Domain)
        WHERE (d.is_new = true OR d.reputation_score < 30)
          AND nc.protocol IN ['HTTPS', 'TLS', 'SSH']
          AND nc.timestamp > datetime() - duration({seconds: $time_window})
        RETURN h.ip AS host_ip,
               d.name AS domain_name,
               d.reputation_score AS reputation_score,
               nc.dst_ip AS destination_ip,
               nc.dst_port AS dst_port,
               [id(h), id(nc), id(d)] AS ids
        """
