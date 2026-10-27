"""
Discovery detection rules for the Q-EDR threat detection engine.

Covers MITRE ATT&CK Tactic: TA0007 - Discovery
Techniques: T1046, T1087, T1082, T1135, T1018
"""

import logging
from typing import Any, Dict, List

from .base import Rule, RuleCategory, RuleMatch, Severity, MITRETechnique

logger = logging.getLogger(__name__)


class NetworkScanningRule(Rule):
    """
    Detects a host rapidly connecting to many different ports across many different hosts.

    Broad horizontal + vertical port scanning is a strong indicator of an attacker
    performing network reconnaissance after initial access.

    MITRE ATT&CK: T1046 - Network Service Discovery
    """

    rule_id: str = "DISC-001"
    rule_name: str = "Broad Network Port Scanning Detected"
    description: str = (
        "A host is rapidly initiating connections to many different destination IP addresses "
        "across multiple ports, indicating network scanning or reconnaissance activity."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.DISCOVERY
    mitre: MITRETechnique = MITRETechnique(
        tactic="Discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
    )
    time_window_seconds: int = 120
    min_match_count: int = 1
    min_unique_dst_ips: int = 10
    min_unique_dst_ports: int = 5
    tags: List[str] = ["network-scan", "port-scan", "reconnaissance", "lateral-movement"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= datetime() - duration({seconds: $time_window}) AND
            nc.direction = 'outbound'
        WITH
            h,
            p,
            COUNT(DISTINCT nc.dst_ip) AS unique_dst_ips,
            COUNT(DISTINCT nc.dst_port) AS unique_dst_ports,
            COUNT(nc) AS total_connections,
            COLLECT(DISTINCT nc.dst_ip)[..20] AS sample_ips,
            COLLECT(DISTINCT nc.dst_port)[..20] AS sample_ports,
            MIN(nc.timestamp) AS first_seen,
            MAX(nc.timestamp) AS last_seen
        WHERE
            unique_dst_ips >= $min_unique_dst_ips AND
            unique_dst_ports >= $min_unique_dst_ports
        RETURN
            h.id AS entity_id,
            h.hostname AS hostname,
            h.ip_address AS source_ip,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            unique_dst_ips,
            unique_dst_ports,
            total_connections,
            sample_ips,
            sample_ports,
            first_seen AS event_time,
            last_seen,
            'NetworkScanningRule' AS rule_id
        ORDER BY unique_dst_ips DESC
        LIMIT 100
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_unique_dst_ips": self.min_unique_dst_ips,
            "min_unique_dst_ports": self.min_unique_dst_ports,
        }


class AccountDiscoveryRule(Rule):
    """
    Detects use of net.exe / net1.exe or LDAP queries to enumerate domain users and groups.

    Adversaries enumerate accounts to understand the target environment, identify
    privileged accounts, and plan lateral movement or privilege escalation.

    MITRE ATT&CK: T1087.002 - Account Discovery: Domain Account
    """

    rule_id: str = "DISC-002"
    rule_name: str = "Domain Account Discovery via net.exe or LDAP"
    description: str = (
        "net.exe or LDAP-based enumeration of domain user accounts and groups was detected, "
        "indicating an adversary is mapping out privileged accounts in the domain."
    )
    severity: Severity = Severity.MEDIUM
    category: RuleCategory = RuleCategory.DISCOVERY
    mitre: MITRETechnique = MITRETechnique(
        tactic="Discovery",
        technique_id="T1087.002",
        technique_name="Account Discovery: Domain Account",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["account-discovery", "net-exe", "ldap", "enumeration", "domain"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)
        WHERE
            p.start_time >= datetime() - duration({seconds: $time_window}) AND
            (
                // net.exe / net1.exe user/group enumeration
                (toLower(p.name) IN ['net.exe', 'net1.exe'] AND
                 (
                     toLower(p.command_line) =~ '(?i).*net\\s+(user|group|localgroup).*(/domain|/dom).*' OR
                     toLower(p.command_line) =~ '(?i).*net\\s+user\\s+/domain.*' OR
                     toLower(p.command_line) =~ '(?i).*net\\s+group\\s+.*(domain admins|enterprise admins|administrators).*'
                 )
                ) OR

                // ADSI / LDAP enumeration via PowerShell
                (toLower(p.name) IN ['powershell.exe', 'pwsh.exe'] AND
                 (
                     toLower(p.command_line) CONTAINS 'get-aduser' OR
                     toLower(p.command_line) CONTAINS 'get-adgroup' OR
                     toLower(p.command_line) CONTAINS 'get-adgroupmember' OR
                     toLower(p.command_line) CONTAINS '[adsisearcher]' OR
                     toLower(p.command_line) CONTAINS 'directoryservices' OR
                     toLower(p.command_line) CONTAINS 'ldap://'
                 )
                ) OR

                // dsquery / dsget for account enumeration
                (toLower(p.name) IN ['dsquery.exe', 'dsget.exe'] AND
                 toLower(p.command_line) =~ '(?i).*(user|group|computer).*')
            )
        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            p.host_id AS host_id,
            p.parent_name AS parent_process,
            p.username AS executing_user,
            p.start_time AS event_time,
            'AccountDiscoveryRule' AS rule_id
        ORDER BY p.start_time DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class SystemInfoDiscoveryRule(Rule):
    """
    Detects a chain of system information discovery commands executed in rapid succession.

    Adversaries run systeminfo, whoami, hostname, ipconfig etc. in quick succession
    during initial access to understand the target system environment.

    MITRE ATT&CK: T1082 - System Information Discovery
    """

    rule_id: str = "DISC-003"
    rule_name: str = "System Information Discovery Command Chain"
    description: str = (
        "Multiple system information discovery commands (systeminfo, whoami, hostname, "
        "ipconfig) were executed in rapid succession from the same parent process."
    )
    severity: Severity = Severity.MEDIUM
    category: RuleCategory = RuleCategory.DISCOVERY
    mitre: MITRETechnique = MITRETechnique(
        tactic="Discovery",
        technique_id="T1082",
        technique_name="System Information Discovery",
    )
    time_window_seconds: int = 180
    min_match_count: int = 3
    tags: List[str] = ["sysinfo", "discovery", "whoami", "hostname", "enumeration"]

    def get_cypher(self) -> str:
        return """
        MATCH (parent:Process)-[:SPAWNED]->(child:Process)
        WHERE
            child.start_time >= datetime() - duration({seconds: $time_window}) AND
            toLower(child.name) IN [
                'systeminfo.exe', 'whoami.exe', 'hostname.exe',
                'ipconfig.exe', 'route.exe', 'arp.exe', 'netstat.exe',
                'qwinsta.exe', 'query.exe', 'tasklist.exe', 'ver.exe',
                'set.exe', 'wmic.exe', 'reg.exe', 'chcp.exe'
            ]
        WITH
            parent,
            COUNT(DISTINCT child.name) AS unique_discovery_cmds,
            COUNT(child) AS total_discovery_invocations,
            COLLECT(DISTINCT child.name) AS commands_run,
            MIN(child.start_time) AS first_seen,
            MAX(child.start_time) AS last_seen
        WHERE unique_discovery_cmds >= $min_count
        RETURN
            parent.id AS entity_id,
            parent.name AS process_name,
            parent.pid AS pid,
            parent.command_line AS command_line,
            parent.host_id AS host_id,
            unique_discovery_cmds,
            total_discovery_invocations,
            commands_run,
            first_seen AS event_time,
            last_seen,
            'SystemInfoDiscoveryRule' AS rule_id
        ORDER BY unique_discovery_cmds DESC
        LIMIT 100
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_count": self.min_match_count,
        }


class ShareEnumerationRule(Rule):
    """
    Detects network share enumeration via net view, SMB, or PowerShell.

    Adversaries enumerate network shares to identify file repositories,
    backup locations, and lateral movement opportunities.

    MITRE ATT&CK: T1135 - Network Share Discovery
    """

    rule_id: str = "DISC-004"
    rule_name: str = "Network Share Enumeration Detected"
    description: str = (
        "Network share enumeration was detected via net view, SMB connections, or "
        "PowerShell cmdlets, indicating an adversary mapping accessible file shares."
    )
    severity: Severity = Severity.MEDIUM
    category: RuleCategory = RuleCategory.DISCOVERY
    mitre: MITRETechnique = MITRETechnique(
        tactic="Discovery",
        technique_id="T1135",
        technique_name="Network Share Discovery",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["share-enum", "smb", "net-view", "network-share", "lateral-movement"]

    def get_cypher(self) -> str:
        return """
        // Pattern 1: net view / net share commands
        OPTIONAL MATCH (p1:Process)
        WHERE
            p1.start_time >= datetime() - duration({seconds: $time_window}) AND
            toLower(p1.name) IN ['net.exe', 'net1.exe'] AND
            (
                toLower(p1.command_line) =~ '(?i).*net\\s+view.*' OR
                toLower(p1.command_line) =~ '(?i).*net\\s+share.*'
            )

        // Pattern 2: PowerShell share enumeration
        OPTIONAL MATCH (p2:Process)
        WHERE
            p2.start_time >= datetime() - duration({seconds: $time_window}) AND
            toLower(p2.name) IN ['powershell.exe', 'pwsh.exe'] AND
            (
                toLower(p2.command_line) CONTAINS 'get-smbshare' OR
                toLower(p2.command_line) CONTAINS 'get-wmiobject win32_share' OR
                toLower(p2.command_line) CONTAINS 'gwmi win32_share' OR
                toLower(p2.command_line) CONTAINS 'invoke-sharefinder' OR
                toLower(p2.command_line) CONTAINS 'find-domainshare'
            )

        // Pattern 3: SMB connections to many different hosts (share access pattern)
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(p3:Process)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= datetime() - duration({seconds: $time_window}) AND
            nc.dst_port = 445 AND
            nc.direction = 'outbound'
        WITH
            p1, p2, p3, h,
            COUNT(DISTINCT nc.dst_ip) AS smb_targets
        WHERE smb_targets >= 5

        WITH
            COLLECT(DISTINCT {
                entity_id: p1.id, process_name: p1.name, pid: p1.pid,
                command_line: p1.command_line, host_id: p1.host_id,
                event_time: p1.start_time, pattern: 'net_view', smb_targets: null
            }) +
            COLLECT(DISTINCT {
                entity_id: p2.id, process_name: p2.name, pid: p2.pid,
                command_line: p2.command_line, host_id: p2.host_id,
                event_time: p2.start_time, pattern: 'powershell_share_enum', smb_targets: null
            }) +
            COLLECT(DISTINCT {
                entity_id: p3.id, process_name: p3.name, pid: p3.pid,
                command_line: p3.command_line, host_id: h.id,
                event_time: p3.start_time, pattern: 'smb_mass_connect', smb_targets: smb_targets
            }) AS all_matches

        UNWIND [m IN all_matches WHERE m.entity_id IS NOT NULL] AS match
        RETURN
            match.entity_id AS entity_id,
            match.process_name AS process_name,
            match.pid AS pid,
            match.command_line AS command_line,
            match.host_id AS host_id,
            match.pattern AS detection_pattern,
            match.smb_targets AS smb_target_count,
            match.event_time AS event_time,
            'ShareEnumerationRule' AS rule_id
        ORDER BY match.event_time DESC
        LIMIT 200
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class ActiveDirectoryReconRule(Rule):
    """
    Detects a large number of LDAP queries originating from a single host,
    indicating Active Directory reconnaissance.

    Adversaries query LDAP to enumerate domain structure, users, computers,
    group policy objects, and trust relationships.

    MITRE ATT&CK: T1018 - Remote System Discovery
    """

    rule_id: str = "DISC-005"
    rule_name: str = "Active Directory Reconnaissance via LDAP"
    description: str = (
        "An unusually high volume of LDAP queries was detected from a single host, "
        "indicating Active Directory reconnaissance or credential harvesting preparation."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.DISCOVERY
    mitre: MITRETechnique = MITRETechnique(
        tactic="Discovery",
        technique_id="T1018",
        technique_name="Remote System Discovery",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    min_ldap_queries: int = 50
    tags: List[str] = ["ldap", "active-directory", "recon", "domain", "enumeration"]

    def get_cypher(self) -> str:
        return """
        // LDAP connections to port 389 or 636 (LDAPS)
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= datetime() - duration({seconds: $time_window}) AND
            nc.direction = 'outbound' AND
            nc.dst_port IN [389, 636, 3268, 3269]

        WITH
            h, p,
            COUNT(nc) AS ldap_query_count,
            COLLECT(DISTINCT nc.dst_ip) AS ldap_targets,
            MIN(nc.timestamp) AS first_query,
            MAX(nc.timestamp) AS last_query
        WHERE ldap_query_count >= $min_ldap_queries

        // Also check for well-known LDAP enumeration tools
        OPTIONAL MATCH (h)-[:HAS_PROCESS]->(enum_proc:Process)
        WHERE
            enum_proc.start_time >= datetime() - duration({seconds: $time_window}) AND
            (
                toLower(enum_proc.name) IN ['bloodhound.exe', 'sharphound.exe', 'adfind.exe', 'ldapdomaindump.exe'] OR
                toLower(enum_proc.command_line) CONTAINS 'invoke-bloodhound' OR
                toLower(enum_proc.command_line) CONTAINS 'get-domainsearcher' OR
                toLower(enum_proc.command_line) CONTAINS 'invoke-adrecon'
            )

        RETURN
            h.id AS entity_id,
            h.hostname AS hostname,
            h.ip_address AS source_ip,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            ldap_query_count,
            ldap_targets,
            enum_proc.name AS known_recon_tool,
            first_query AS event_time,
            last_query,
            'ActiveDirectoryReconRule' AS rule_id
        ORDER BY ldap_query_count DESC
        LIMIT 100
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_ldap_queries": self.min_ldap_queries,
        }


class PortScanInternalRule(Rule):
    """
    Detects internal-to-internal port scanning patterns where one internal host
    connects to many ports on other internal hosts.

    This pattern is characteristic of post-compromise lateral movement scanning
    on RFC1918 private address space.

    MITRE ATT&CK: T1046 - Network Service Discovery
    """

    rule_id: str = "DISC-006"
    rule_name: str = "Internal Port Scan Detected (Lateral Movement Recon)"
    description: str = (
        "An internal host is scanning multiple ports on other internal hosts, which is "
        "characteristic of post-compromise reconnaissance for lateral movement."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.DISCOVERY
    mitre: MITRETechnique = MITRETechnique(
        tactic="Discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
    )
    time_window_seconds: int = 60
    min_match_count: int = 1
    min_unique_ports: int = 10
    min_unique_internal_ips: int = 3
    tags: List[str] = ["port-scan", "internal-scan", "lateral-movement", "recon"]

    def get_cypher(self) -> str:
        return """
        MATCH (src_host:Host)-[:HAS_PROCESS]->(p:Process)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= datetime() - duration({seconds: $time_window}) AND
            nc.direction = 'outbound' AND
            // Destination must be in RFC1918 private ranges
            (
                nc.dst_ip STARTS WITH '10.' OR
                nc.dst_ip STARTS WITH '192.168.' OR
                nc.dst_ip =~ '172\\.(1[6-9]|2[0-9]|3[01])\\..+'
            ) AND
            // Source must also be internal (exclude external to internal)
            (
                src_host.ip_address STARTS WITH '10.' OR
                src_host.ip_address STARTS WITH '192.168.' OR
                src_host.ip_address =~ '172\\.(1[6-9]|2[0-9]|3[01])\\..+'
            ) AND
            // Not connecting to itself
            nc.dst_ip <> src_host.ip_address

        WITH
            src_host,
            p,
            COUNT(DISTINCT nc.dst_port) AS unique_ports_scanned,
            COUNT(DISTINCT nc.dst_ip) AS unique_internal_targets,
            COUNT(nc) AS total_attempts,
            COLLECT(DISTINCT nc.dst_port)[..30] AS sample_ports,
            COLLECT(DISTINCT nc.dst_ip)[..20] AS sample_targets,
            MIN(nc.timestamp) AS first_seen,
            MAX(nc.timestamp) AS last_seen
        WHERE
            unique_ports_scanned >= $min_unique_ports AND
            unique_internal_targets >= $min_unique_internal_ips

        RETURN
            src_host.id AS entity_id,
            src_host.hostname AS source_hostname,
            src_host.ip_address AS source_ip,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            unique_ports_scanned,
            unique_internal_targets,
            total_attempts,
            sample_ports,
            sample_targets,
            first_seen AS event_time,
            last_seen,
            'PortScanInternalRule' AS rule_id
        ORDER BY unique_ports_scanned DESC
        LIMIT 100
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_unique_ports": self.min_unique_ports,
            "min_unique_internal_ips": self.min_unique_internal_ips,
        }


# Registry of all discovery rules
ALL_RULES: List[Rule] = [
    NetworkScanningRule(),
    AccountDiscoveryRule(),
    SystemInfoDiscoveryRule(),
    ShareEnumerationRule(),
    ActiveDirectoryReconRule(),
    PortScanInternalRule(),
]
