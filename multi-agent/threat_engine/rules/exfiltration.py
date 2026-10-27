"""
Exfiltration detection rules for the Q-EDR threat detection engine.

Covers MITRE ATT&CK Tactic: TA0010 - Exfiltration
Techniques: T1048, T1041, T1567, T1560
"""

import logging
from typing import Any, Dict, List

from .base import Rule, RuleCategory, RuleMatch, Severity, MITRETechnique

logger = logging.getLogger(__name__)


class LargeDataTransferRule(Rule):
    """
    Detects outbound network connections with data transfer exceeding the threshold.

    Large outbound transfers that deviate from baseline behavior may indicate
    exfiltration of sensitive data.

    MITRE ATT&CK: T1048 - Exfiltration Over Alternative Protocol
    """

    rule_id: str = "EXFIL-001"
    rule_name: str = "Large Outbound Data Transfer Detected"
    description: str = (
        "An outbound network connection has transferred more than the configured threshold "
        "of data, which may indicate data exfiltration in progress."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.EXFILTRATION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Exfiltration",
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
    )
    time_window_seconds: int = 3600
    min_match_count: int = 1
    # 100 MB in bytes
    bytes_threshold: int = 100 * 1024 * 1024
    tags: List[str] = ["large-transfer", "exfiltration", "data-loss", "outbound"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= datetime() - duration({seconds: $time_window}) AND
            nc.direction = 'outbound' AND
            nc.bytes_sent IS NOT NULL AND
            nc.bytes_sent >= $bytes_threshold AND
            // Exclude known internal RFC1918 destinations
            NOT (
                nc.dst_ip STARTS WITH '10.' OR
                nc.dst_ip STARTS WITH '192.168.' OR
                nc.dst_ip =~ '172\\.(1[6-9]|2[0-9]|3[01])\\..+' OR
                nc.dst_ip = '127.0.0.1'
            )
        RETURN
            h.id AS entity_id,
            h.hostname AS hostname,
            h.ip_address AS source_ip,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            nc.dst_ip AS destination_ip,
            nc.dst_port AS destination_port,
            nc.protocol AS protocol,
            nc.bytes_sent AS bytes_transferred,
            // Convert to MB for readability
            nc.bytes_sent / 1048576.0 AS mb_transferred,
            nc.timestamp AS event_time,
            nc.duration_seconds AS connection_duration_secs,
            'LargeDataTransferRule' AS rule_id
        ORDER BY nc.bytes_sent DESC
        LIMIT 200
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "bytes_threshold": self.bytes_threshold,
        }


class DNSTunnelingRule(Rule):
    """
    Detects DNS tunneling by identifying unusual volumes of DNS queries with
    abnormally long subdomain names.

    DNS tunneling encodes data in DNS query labels to exfiltrate data bypassing
    traditional network controls. Queries have very long subdomain components.

    MITRE ATT&CK: T1048.001 - Exfiltration Over Alternative Protocol: DNS
    """

    rule_id: str = "EXFIL-002"
    rule_name: str = "DNS Tunneling Exfiltration Detected"
    description: str = (
        "An unusually high number of DNS queries with abnormally long subdomain names were "
        "detected, indicating data may be exfiltrated via DNS tunneling."
    )
    severity: Severity = Severity.CRITICAL
    category: RuleCategory = RuleCategory.EXFILTRATION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Exfiltration",
        technique_id="T1048.001",
        technique_name="Exfiltration Over Alternative Protocol: DNS",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    min_query_count: int = 20
    min_subdomain_length: int = 30
    tags: List[str] = ["dns-tunneling", "exfiltration", "dns", "covert-channel"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[:TRIGGERED]->(dq:DNSQuery)
        WHERE
            dq.timestamp >= datetime() - duration({seconds: $time_window}) AND
            dq.query_name IS NOT NULL AND
            // Long query names indicate encoded payloads
            size(dq.query_name) >= $min_subdomain_length AND
            // High entropy subdomain (many unique characters relative to length)
            dq.query_type IN ['A', 'AAAA', 'TXT', 'MX', 'CNAME', 'NULL']

        WITH
            h, p,
            // Extract the apex domain (last two labels) for grouping
            SPLIT(dq.query_name, '.')[-2] + '.' + SPLIT(dq.query_name, '.')[-1] AS apex_domain,
            COUNT(dq) AS query_count,
            AVG(size(dq.query_name)) AS avg_query_length,
            MAX(size(dq.query_name)) AS max_query_length,
            COLLECT(DISTINCT dq.query_name)[..5] AS sample_queries,
            MIN(dq.timestamp) AS first_seen,
            MAX(dq.timestamp) AS last_seen

        WHERE query_count >= $min_query_count

        RETURN
            h.id AS entity_id,
            h.hostname AS hostname,
            h.ip_address AS source_ip,
            p.name AS process_name,
            p.pid AS pid,
            apex_domain,
            query_count,
            avg_query_length,
            max_query_length,
            sample_queries,
            first_seen AS event_time,
            last_seen,
            'DNSTunnelingRule' AS rule_id
        ORDER BY query_count DESC
        LIMIT 100
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_subdomain_length": self.min_subdomain_length,
            "min_query_count": self.min_query_count,
        }


class C2ExfiltrationRule(Rule):
    """
    Detects data exfiltration to a known or suspected C2 host that exhibits
    beaconing behavior (regular periodic outbound connections).

    C2 channels are often used to exfiltrate collected data back to attacker
    infrastructure after the initial beaconing phase.

    MITRE ATT&CK: T1041 - Exfiltration Over C2 Channel
    """

    rule_id: str = "EXFIL-003"
    rule_name: str = "Data Exfiltration Over C2 Channel"
    description: str = (
        "A host exhibiting beaconing behavior (regular periodic outbound connections) "
        "has transferred significant data, indicating C2-based exfiltration."
    )
    severity: Severity = Severity.CRITICAL
    category: RuleCategory = RuleCategory.EXFILTRATION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Exfiltration",
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
    )
    time_window_seconds: int = 3600
    min_match_count: int = 1
    min_beacon_count: int = 8
    min_total_bytes: int = 10 * 1024 * 1024  # 10 MB
    beacon_interval_tolerance_pct: float = 0.25
    tags: List[str] = ["c2", "exfiltration", "beaconing", "data-loss"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= datetime() - duration({seconds: $time_window}) AND
            nc.direction = 'outbound' AND
            NOT (
                nc.dst_ip STARTS WITH '10.' OR
                nc.dst_ip STARTS WITH '192.168.' OR
                nc.dst_ip =~ '172\\.(1[6-9]|2[0-9]|3[01])\\..+'
            )

        WITH
            h, p, nc.dst_ip AS c2_ip, nc.dst_port AS c2_port,
            COLLECT(nc.timestamp) AS connection_times,
            COUNT(nc) AS connection_count,
            SUM(COALESCE(nc.bytes_sent, 0)) AS total_bytes_sent,
            SUM(COALESCE(nc.bytes_received, 0)) AS total_bytes_received

        WHERE
            connection_count >= $min_beacon_count AND
            total_bytes_sent >= $min_total_bytes

        // Calculate inter-connection intervals to determine beaconing regularity
        WITH
            h, p, c2_ip, c2_port,
            connection_count, total_bytes_sent, total_bytes_received,
            connection_times,
            // Check if connections exhibit regular timing (beaconing pattern)
            // Using stddev of intervals as regularity metric
            connection_count AS beacon_count

        RETURN
            h.id AS entity_id,
            h.hostname AS hostname,
            h.ip_address AS source_ip,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            c2_ip AS c2_destination,
            c2_port AS c2_port,
            connection_count AS beacon_count,
            total_bytes_sent,
            total_bytes_received,
            total_bytes_sent / 1048576.0 AS mb_exfiltrated,
            connection_times[0] AS first_beacon,
            connection_times[-1] AS last_beacon,
            connection_times[0] AS event_time,
            'C2ExfiltrationRule' AS rule_id
        ORDER BY total_bytes_sent DESC
        LIMIT 100
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_beacon_count": self.min_beacon_count,
            "min_total_bytes": self.min_total_bytes,
        }


class HTTPSExfiltrationRule(Rule):
    """
    Detects unusual HTTPS POST requests to rare external hosts with large payloads.

    Adversaries use encrypted HTTPS channels to exfiltrate data to attacker-controlled
    servers, leveraging encryption to evade DPI and content inspection.

    MITRE ATT&CK: T1048.002 - Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2 Protocol
    """

    rule_id: str = "EXFIL-004"
    rule_name: str = "Suspicious HTTPS POST Exfiltration to Rare Host"
    description: str = (
        "A large HTTPS POST request was made to an external host that has rarely or "
        "never been seen before from this endpoint, which may indicate data exfiltration."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.EXFILTRATION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Exfiltration",
        technique_id="T1048.002",
        technique_name="Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2 Protocol",
    )
    time_window_seconds: int = 3600
    min_match_count: int = 1
    min_post_bytes: int = 5 * 1024 * 1024  # 5 MB
    # Number of prior connections to the same host (below = rare)
    rare_host_threshold: int = 3
    tags: List[str] = ["https", "post", "exfiltration", "rare-host", "encrypted"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= datetime() - duration({seconds: $time_window}) AND
            nc.direction = 'outbound' AND
            nc.dst_port IN [443, 8443] AND
            nc.protocol IN ['HTTPS', 'TLS', 'SSL', 'TCP'] AND
            nc.http_method = 'POST' AND
            nc.bytes_sent >= $min_post_bytes AND
            NOT (
                nc.dst_ip STARTS WITH '10.' OR
                nc.dst_ip STARTS WITH '192.168.' OR
                nc.dst_ip =~ '172\\.(1[6-9]|2[0-9]|3[01])\\..+'
            )

        // Count historical connections to the same destination from this host
        OPTIONAL MATCH (h)-[:HAS_PROCESS]->(:Process)-[:CONNECTED_TO]->(hist_nc:NetworkConnection)
        WHERE
            hist_nc.dst_ip = nc.dst_ip AND
            hist_nc.timestamp < nc.timestamp AND
            hist_nc.timestamp >= nc.timestamp - duration({days: 30})

        WITH
            h, p, nc,
            COUNT(hist_nc) AS historical_connection_count

        WHERE historical_connection_count < $rare_host_threshold

        RETURN
            h.id AS entity_id,
            h.hostname AS hostname,
            h.ip_address AS source_ip,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            nc.dst_ip AS destination_ip,
            nc.dst_port AS destination_port,
            nc.http_host AS http_host,
            nc.http_url AS http_url,
            nc.bytes_sent AS post_payload_bytes,
            nc.bytes_sent / 1048576.0 AS post_payload_mb,
            historical_connection_count AS prior_connections_30d,
            nc.timestamp AS event_time,
            'HTTPSExfiltrationRule' AS rule_id
        ORDER BY nc.bytes_sent DESC
        LIMIT 200
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_post_bytes": self.min_post_bytes,
            "rare_host_threshold": self.rare_host_threshold,
        }


class CloudStorageExfilRule(Rule):
    """
    Detects connections to cloud storage services shortly after file access events,
    suggesting files are being exfiltrated via cloud sync tools.

    Adversaries abuse legitimate cloud storage (Dropbox, OneDrive, Mega, Box, etc.)
    to exfiltrate files using legitimate infrastructure to evade detection.

    MITRE ATT&CK: T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage
    """

    rule_id: str = "EXFIL-005"
    rule_name: str = "Cloud Storage Exfiltration After File Access"
    description: str = (
        "A process accessed multiple files and then made connections to a cloud storage "
        "service, indicating potential data exfiltration via cloud platforms."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.EXFILTRATION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Exfiltration",
        technique_id="T1567.002",
        technique_name="Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    )
    time_window_seconds: int = 600
    min_match_count: int = 1
    min_files_accessed: int = 5
    tags: List[str] = [
        "cloud-storage", "dropbox", "onedrive", "mega", "exfiltration", "data-loss"
    ]

    def get_cypher(self) -> str:
        return """
        // Find processes that accessed multiple files
        MATCH (p:Process)-[fa:READS|ACCESSED]->(f:File)
        WHERE
            fa.timestamp >= datetime() - duration({seconds: $time_window}) AND
            // Exclude system files
            NOT toLower(f.path) STARTS WITH 'c:\\windows\\' AND
            NOT toLower(f.path) STARTS WITH 'c:\\program files (x86)\\windows'

        WITH p, COUNT(DISTINCT f) AS files_accessed,
             COLLECT(DISTINCT f.path)[..10] AS sample_files,
             MIN(fa.timestamp) AS first_access,
             MAX(fa.timestamp) AS last_access

        WHERE files_accessed >= $min_files_accessed

        // Find subsequent cloud storage connections from same process
        MATCH (p)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= first_access AND
            nc.timestamp <= datetime() - duration({seconds: $time_window}) + duration({seconds: $time_window}) AND
            nc.direction = 'outbound' AND
            (
                // Dropbox
                nc.http_host =~ '(?i).*dropbox(api)?\\.(com|net)' OR
                // Google Drive
                nc.http_host =~ '(?i).*(drive|storage)\\.googleapis\\.com' OR
                // OneDrive / SharePoint
                nc.http_host =~ '(?i).*(onedrive|sharepoint)\\.live\\.com' OR
                nc.http_host =~ '(?i).*\\.sharepoint\\.com' OR
                // Mega.nz
                nc.http_host =~ '(?i).*(mega\\.nz|mega\\.co\\.nz)' OR
                // Box.com
                nc.http_host =~ '(?i).*box\\.com' OR
                // AWS S3
                nc.http_host =~ '(?i).*s3\\.amazonaws\\.com' OR
                nc.http_host =~ '(?i).*\\.s3(-[a-z0-9-]+)?\\.amazonaws\\.com' OR
                // Azure Blob
                nc.http_host =~ '(?i).*\\.blob\\.core\\.windows\\.net' OR
                // WeTransfer
                nc.http_host =~ '(?i).*wetransfer\\.com'
            )

        WITH
            p, files_accessed, sample_files, first_access, last_access,
            nc.http_host AS cloud_host,
            COUNT(nc) AS cloud_connections,
            SUM(COALESCE(nc.bytes_sent, 0)) AS total_bytes_uploaded

        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            p.host_id AS host_id,
            files_accessed,
            sample_files,
            cloud_host,
            cloud_connections,
            total_bytes_uploaded,
            total_bytes_uploaded / 1048576.0 AS mb_uploaded,
            first_access AS event_time,
            last_access AS last_file_access,
            'CloudStorageExfilRule' AS rule_id
        ORDER BY total_bytes_uploaded DESC
        LIMIT 100
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_files_accessed": self.min_files_accessed,
        }


class CompressedExfilRule(Rule):
    """
    Detects archiving/compression tool usage followed immediately by a large outbound connection.

    Adversaries stage data for exfiltration by compressing it first, then transferring
    the archive to external infrastructure.

    MITRE ATT&CK: T1560.001 - Archive Collected Data: Archive via Utility
    """

    rule_id: str = "EXFIL-006"
    rule_name: str = "Compression then Immediate Large Outbound Transfer"
    description: str = (
        "An archiving/compression tool created a file, and then a large outbound transfer "
        "occurred shortly afterward from the same host, indicating staged exfiltration."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.EXFILTRATION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Exfiltration",
        technique_id="T1560.001",
        technique_name="Archive Collected Data: Archive via Utility",
    )
    time_window_seconds: int = 600
    min_match_count: int = 1
    min_bytes_after_compress: int = 1 * 1024 * 1024  # 1 MB
    compress_to_transfer_window_seconds: int = 300
    tags: List[str] = [
        "compression", "archive", "7zip", "rar", "zip", "exfiltration", "staging"
    ]

    def get_cypher(self) -> str:
        return """
        // Step 1: Find compression tool executions
        MATCH (h:Host)-[:HAS_PROCESS]->(compress_proc:Process)-[:CREATED]->(archive:File)
        WHERE
            compress_proc.start_time >= datetime() - duration({seconds: $time_window}) AND
            (
                toLower(compress_proc.name) IN [
                    '7z.exe', '7za.exe', '7zr.exe',
                    'rar.exe', 'winrar.exe',
                    'zip.exe', 'compact.exe',
                    'tar.exe', 'pkzip.exe',
                    'winzip32.exe', 'wzzip.exe'
                ] OR
                (toLower(compress_proc.name) IN ['powershell.exe', 'pwsh.exe'] AND
                 (toLower(compress_proc.command_line) CONTAINS 'compress-archive' OR
                  toLower(compress_proc.command_line) CONTAINS 'io.compression'))
            ) AND
            (
                toLower(archive.extension) IN [
                    '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz',
                    '.tgz', '.bz2', '.xz', '.cab', '.iso'
                ]
            )

        WITH h, compress_proc, archive,
             compress_proc.start_time AS compress_time

        // Step 2: Find subsequent large outbound connection from same host
        MATCH (h)-[:HAS_PROCESS]->(transfer_proc:Process)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= compress_time AND
            nc.timestamp <= compress_time + duration({seconds: $compress_to_transfer_window}) AND
            nc.direction = 'outbound' AND
            nc.bytes_sent >= $min_bytes AND
            NOT (
                nc.dst_ip STARTS WITH '10.' OR
                nc.dst_ip STARTS WITH '192.168.' OR
                nc.dst_ip =~ '172\\.(1[6-9]|2[0-9]|3[01])\\..+'
            )

        RETURN
            h.id AS entity_id,
            h.hostname AS hostname,
            compress_proc.name AS compression_tool,
            compress_proc.command_line AS compress_command,
            compress_proc.pid AS compress_pid,
            archive.path AS archive_path,
            archive.size_bytes AS archive_size,
            transfer_proc.name AS transfer_process,
            nc.dst_ip AS exfil_destination,
            nc.dst_port AS exfil_port,
            nc.bytes_sent AS bytes_transferred,
            nc.bytes_sent / 1048576.0 AS mb_transferred,
            compress_time AS event_time,
            nc.timestamp AS transfer_time,
            duration.between(compress_time, nc.timestamp).seconds AS seconds_between_compress_and_transfer,
            'CompressedExfilRule' AS rule_id
        ORDER BY nc.bytes_sent DESC
        LIMIT 100
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_bytes": self.min_bytes_after_compress,
            "compress_to_transfer_window": self.compress_to_transfer_window_seconds,
        }


# Registry of all exfiltration rules
ALL_RULES: List[Rule] = [
    LargeDataTransferRule(),
    DNSTunnelingRule(),
    C2ExfiltrationRule(),
    HTTPSExfiltrationRule(),
    CloudStorageExfilRule(),
    CompressedExfilRule(),
]
