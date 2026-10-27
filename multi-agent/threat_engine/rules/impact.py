"""
Impact detection rules.

Covers MITRE ATT&CK Tactic: Impact (TA0040).
Each rule queries the Neo4j behavioural graph for evidence of destructive or
disruptive adversary activity, such as ransomware encryption, shadow copy deletion,
service shutdown, or disk wiping.

Graph node types used: Host, Process, File, Service
Relationships used   : HAS_PROCESS, MODIFIED, DELETED, OWNS, SPAWNED
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
# 1. Ransomware Encryption Activity (T1486)
# ---------------------------------------------------------------------------

class RansomwareEncryptionRule(Rule):
    """
    Detects rapid modification of files by a single process, particularly where
    files are renamed with known ransomware extensions or modified in bulk.
    """

    rule_id = "IMP-001"
    rule_name = "Ransomware File Encryption Detected"
    description = (
        "A process modified a high volume of files within a short time window, "
        "often renaming them with encrypted file extensions, characteristic of ransomware."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.IMPACT
    mitre = MITRETechnique(
        tactic="Impact",
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["impact", "ransomware", "encryption"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[m:MODIFIED]->(f:File)
        WHERE (f.extension IN ['.locked', '.crypto', '.enc', '.crypted', '.wnry', '.locky']
           OR m.action = 'encrypt'
           OR f.name ENDS WITH '.locked')
          AND m.timestamp > datetime() - duration({seconds: $time_window})
        WITH h, p, count(f) AS files_modified, collect(id(f))[..10] AS sample_file_ids
        WHERE files_modified >= 10
        RETURN h.ip AS host_ip,
               p.name AS process_name,
               p.pid AS pid,
               p.command_line AS command_line,
               files_modified,
               [id(p)] + sample_file_ids AS ids
        ORDER BY files_modified DESC
        """


# ---------------------------------------------------------------------------
# 2. Inhibit System Recovery (T1490)
# ---------------------------------------------------------------------------

class InhibitSystemRecoveryRule(Rule):
    """
    Detects execution of commands that delete volume shadow copies or backup catalogs
    (vssadmin, wbadmin, bcdedit) to prevent system recovery after an attack.
    """

    rule_id = "IMP-002"
    rule_name = "System Recovery Inhibition (Shadow Copies Deleted)"
    description = (
        "Command executed to delete volume shadow copies, disable safe boot, "
        "or destroy backup catalogs, a standard precursor to ransomware encryption."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.IMPACT
    mitre = MITRETechnique(
        tactic="Impact",
        technique_id="T1490",
        technique_name="Inhibit System Recovery",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["impact", "recovery_inhibition", "vssadmin", "ransomware"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)
        WHERE (
            (toLower(p.name) = 'vssadmin.exe' AND toLower(p.command_line) CONTAINS 'delete' AND toLower(p.command_line) CONTAINS 'shadows')
            OR (toLower(p.name) = 'wbadmin.exe' AND toLower(p.command_line) CONTAINS 'delete' AND toLower(p.command_line) CONTAINS 'catalog')
            OR (toLower(p.name) = 'bcdedit.exe' AND toLower(p.command_line) CONTAINS 'recoveryenabled' AND toLower(p.command_line) CONTAINS 'no')
            OR (toLower(p.name) = 'wmic.exe' AND toLower(p.command_line) CONTAINS 'shadowcopy' AND toLower(p.command_line) CONTAINS 'delete')
        )
        AND p.timestamp > datetime() - duration({seconds: $time_window})
        RETURN h.ip AS host_ip,
               h.hostname AS hostname,
               p.name AS process_name,
               p.pid AS pid,
               p.command_line AS command_line,
               p.timestamp AS timestamp,
               [id(h), id(p)] AS ids
        """


# ---------------------------------------------------------------------------
# 3. Service Stop / Termination (T1489)
# ---------------------------------------------------------------------------

class ServiceStopRule(Rule):
    """
    Detects multiple critical services being stopped in rapid succession,
    typically to disable security agents, databases, or backups.
    """

    rule_id = "IMP-003"
    rule_name = "Mass Critical Service Termination"
    description = (
        "Multiple critical system, database, or security services were stopped "
        "within a brief window, indicative of impact preparation."
    )
    severity = Severity.HIGH
    category = RuleCategory.IMPACT
    mitre = MITRETechnique(
        tactic="Impact",
        technique_id="T1489",
        technique_name="Service Stop",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["impact", "service_stop", "defense_disruption"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:OWNS]->(s:Service)
        WHERE s.state = 'stopped'
          AND s.timestamp > datetime() - duration({seconds: $time_window})
        WITH h, count(s) AS stopped_count, collect(s.name) AS service_names, collect(id(s)) AS service_ids
        WHERE stopped_count >= 3
        RETURN h.ip AS host_ip,
               h.hostname AS hostname,
               stopped_count,
               service_names,
               service_ids AS ids
        ORDER BY stopped_count DESC
        """


# ---------------------------------------------------------------------------
# 4. Data Destruction / Mass File Deletion (T1485)
# ---------------------------------------------------------------------------

class DataDestructionRule(Rule):
    """
    Detects abnormal bulk deletion of files across critical system or user directories.
    """

    rule_id = "IMP-004"
    rule_name = "Mass File Deletion / Data Destruction"
    description = (
        "A process deleted a large number of files in a short time frame, "
        "indicating intentional data destruction or wiper activity."
    )
    severity = Severity.HIGH
    category = RuleCategory.IMPACT
    mitre = MITRETechnique(
        tactic="Impact",
        technique_id="T1485",
        technique_name="Data Destruction",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["impact", "wiper", "deletion"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[d:DELETED]->(f:File)
        WHERE d.timestamp > datetime() - duration({seconds: $time_window})
        WITH h, p, count(f) AS files_deleted, collect(id(f))[..10] AS sample_file_ids
        WHERE files_deleted >= 20
        RETURN h.ip AS host_ip,
               p.name AS process_name,
               p.pid AS pid,
               files_deleted,
               [id(p)] + sample_file_ids AS ids
        ORDER BY files_deleted DESC
        """


# ---------------------------------------------------------------------------
# 5. Disk Wipe / Master Boot Record Overwrite (T1561.001)
# ---------------------------------------------------------------------------

class DiskWipeRule(Rule):
    """
    Detects attempts to write directly to physical drive devices (e.g. \\\\.\\PhysicalDrive0
    or /dev/sda) bypassing standard filesystem abstractions.
    """

    rule_id = "IMP-005"
    rule_name = "Low-Level Disk Wipe Attempt"
    description = (
        "Process opened a raw physical drive or boot record device with write access, "
        "a signature characteristic of HermeticWiper, CaddyWiper, and similar destructive malware."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.IMPACT
    mitre = MITRETechnique(
        tactic="Impact",
        technique_id="T1561",
        technique_name="Disk Wipe",
        sub_technique_id="001",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["impact", "wiper", "mbr", "raw_disk"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)
        WHERE (toLower(p.command_line) CONTAINS 'physicaldrive'
           OR toLower(p.command_line) CONTAINS '/dev/sd'
           OR toLower(p.command_line) CONTAINS '/dev/nvme'
           OR toLower(p.command_line) CONTAINS 'dd if=/dev/zero'
           OR toLower(p.command_line) CONTAINS 'format ')
          AND p.timestamp > datetime() - duration({seconds: $time_window})
        RETURN h.ip AS host_ip,
               p.name AS process_name,
               p.pid AS pid,
               p.command_line AS command_line,
               p.timestamp AS timestamp,
               [id(h), id(p)] AS ids
        """


# ---------------------------------------------------------------------------
# 6. Web Defacement / Content Overwrite (T1491.001)
# ---------------------------------------------------------------------------

class DefacementRule(Rule):
    """
    Detects unauthorized bulk modification of web server document root files
    by non-standard or untrusted processes.
    """

    rule_id = "IMP-006"
    rule_name = "Web Server Document Defacement"
    description = (
        "Files inside a web document root (/var/www or C:\\inetpub\\wwwroot) were modified "
        "or overwritten by an untrusted or newly spawned process."
    )
    severity = Severity.MEDIUM
    category = RuleCategory.IMPACT
    mitre = MITRETechnique(
        tactic="Impact",
        technique_id="T1491",
        technique_name="Defacement",
        sub_technique_id="001",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["impact", "defacement", "web"]

    def get_cypher(self) -> str:
        return """
        MATCH (h:Host)-[:HAS_PROCESS]->(p:Process)-[m:MODIFIED]->(f:File)
        WHERE (toLower(f.path) CONTAINS '/var/www' OR toLower(f.path) CONTAINS 'wwwroot')
          AND NOT toLower(p.name) IN ['git', 'deploy.sh', 'rsync', 'ansible']
          AND m.timestamp > datetime() - duration({seconds: $time_window})
        WITH h, p, count(f) AS files_changed, collect(id(f))[..5] AS file_ids
        WHERE files_changed >= 3
        RETURN h.ip AS host_ip,
               p.name AS process_name,
               p.pid AS pid,
               files_changed,
               [id(p)] + file_ids AS ids
        """
