"""
Defense Evasion detection rules for the Q-EDR threat detection engine.

Covers MITRE ATT&CK Tactic: TA0005 - Defense Evasion
Techniques: T1070, T1036, T1562, T1027
"""

import logging
from typing import Any, Dict, List

from .base import Rule, RuleCategory, RuleMatch, Severity, MITRETechnique

logger = logging.getLogger(__name__)


class LogClearingRule(Rule):
    """
    Detects processes clearing Windows Event Logs or deleting log files.

    Adversaries clear event logs to remove evidence of their activity.
    This rule monitors for processes invoking wevtutil, Clear-EventLog,
    or directly deleting .evtx files.

    MITRE ATT&CK: T1070.001 - Indicator Removal: Clear Windows Event Logs
    """

    rule_id: str = "DEF-EVA-001"
    rule_name: str = "Windows Event Log Clearing Detected"
    description: str = (
        "A process has cleared or deleted Windows Event Logs, which is a common "
        "indicator of an attacker attempting to remove forensic evidence."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.DEFENSE_EVASION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Defense Evasion",
        technique_id="T1070.001",
        technique_name="Indicator Removal: Clear Windows Event Logs",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["log-clearing", "anti-forensics", "event-log", "wevtutil"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)-[r:DELETED|MODIFIED]->(f:File)
        WHERE (
            // wevtutil cl / wevtutil cl Security / wevtutil cl System
            toLower(p.name) IN ['wevtutil.exe', 'wevtutil'] OR
            toLower(p.command_line) CONTAINS 'clear-eventlog' OR
            toLower(p.command_line) CONTAINS 'wevtutil' OR
            toLower(p.command_line) CONTAINS 'clearev' OR
            // Deleting .evtx log files directly
            (toLower(f.extension) = '.evtx' AND type(r) = 'DELETED') OR
            // PowerShell Clear-EventLog cmdlet
            (toLower(p.name) IN ['powershell.exe', 'pwsh.exe'] AND
             toLower(p.command_line) CONTAINS 'clear-eventlog')
        )
        AND p.start_time >= datetime() - duration({seconds: $time_window})
        WITH p, r, f,
             p.host_id AS host_id,
             p.pid AS pid,
             p.name AS process_name,
             p.command_line AS cmd_line,
             f.path AS file_path
        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            p.host_id AS host_id,
            f.path AS target_file,
            type(r) AS action,
            p.start_time AS event_time,
            'LogClearingRule' AS rule_id
        ORDER BY p.start_time DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class TimestompingRule(Rule):
    """
    Detects file timestomping where modification time is altered significantly
    relative to creation time.

    Adversaries modify file timestamps to blend into the filesystem timeline
    and avoid detection by time-based forensic analysis.

    MITRE ATT&CK: T1070.006 - Indicator Removal: Timestomp
    """

    rule_id: str = "DEF-EVA-002"
    rule_name: str = "File Timestomping Detected"
    description: str = (
        "A file's modification time has been altered to differ significantly from "
        "its creation time, which is a strong indicator of anti-forensic timestomping."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.DEFENSE_EVASION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Defense Evasion",
        technique_id="T1070.006",
        technique_name="Indicator Removal: Timestomp",
    )
    time_window_seconds: int = 3600
    min_match_count: int = 1
    # Minimum hours difference between creation and modified time to flag
    time_diff_threshold_hours: int = 24 * 30  # 30 days
    tags: List[str] = ["timestomp", "anti-forensics", "file-metadata", "timestamp"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)-[r:MODIFIED]->(f:File)
        WHERE
            f.created_time IS NOT NULL AND
            f.modified_time IS NOT NULL AND
            // Modified time is MORE than threshold hours before created time
            // (impossible situation = timestomped to appear older)
            duration.between(f.modified_time, f.created_time).hours > $time_diff_hours
        AND p.start_time >= datetime() - duration({seconds: $time_window})
        WITH p, f,
             duration.between(f.modified_time, f.created_time).hours AS hours_diff
        RETURN
            f.id AS entity_id,
            f.path AS file_path,
            f.created_time AS created_time,
            f.modified_time AS modified_time,
            hours_diff,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            p.host_id AS host_id,
            p.start_time AS event_time,
            'TimestompingRule' AS rule_id
        ORDER BY hours_diff DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "time_diff_hours": self.time_diff_threshold_hours,
        }


class ProcessMasqueradingRule(Rule):
    """
    Detects processes running from non-standard paths to impersonate legitimate binaries.

    Adversaries rename malicious executables or run them from unexpected locations
    to evade process-based detection (e.g., cmd.exe running from %AppData%).

    MITRE ATT&CK: T1036.005 - Masquerading: Match Legitimate Name or Location
    """

    rule_id: str = "DEF-EVA-003"
    rule_name: str = "Process Masquerading from Non-Standard Path"
    description: str = (
        "A known Windows system process is running from a non-standard or suspicious "
        "file path, which may indicate process masquerading by an attacker."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.DEFENSE_EVASION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Defense Evasion",
        technique_id="T1036.005",
        technique_name="Masquerading: Match Legitimate Name or Location",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["masquerading", "process-spoofing", "lolbin", "evasion"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)
        WHERE
            p.start_time >= datetime() - duration({seconds: $time_window})
        AND (
            // System32 binaries running from non-System32 paths
            (toLower(p.name) = 'cmd.exe' AND
             NOT toLower(p.path) CONTAINS 'windows\\system32' AND
             NOT toLower(p.path) CONTAINS 'windows\\syswow64' AND
             NOT toLower(p.path) CONTAINS 'windows\\sysnative') OR

            (toLower(p.name) = 'powershell.exe' AND
             NOT toLower(p.path) CONTAINS 'windows\\system32\\windowspowershell' AND
             NOT toLower(p.path) CONTAINS 'windows\\syswow64\\windowspowershell' AND
             NOT toLower(p.path) CONTAINS 'program files\\powershell') OR

            (toLower(p.name) = 'svchost.exe' AND
             NOT toLower(p.path) CONTAINS 'windows\\system32') OR

            (toLower(p.name) = 'lsass.exe' AND
             NOT toLower(p.path) CONTAINS 'windows\\system32') OR

            (toLower(p.name) = 'explorer.exe' AND
             NOT toLower(p.path) CONTAINS 'windows') OR

            // Running from suspicious user-writable locations
            (toLower(p.name) IN ['cmd.exe','powershell.exe','mshta.exe','wscript.exe','cscript.exe'] AND (
                toLower(p.path) CONTAINS 'appdata\\local\\temp' OR
                toLower(p.path) CONTAINS 'appdata\\roaming' OR
                toLower(p.path) CONTAINS '\\temp\\' OR
                toLower(p.path) CONTAINS '\\tmp\\'
            ))
        )
        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.path AS process_path,
            p.pid AS pid,
            p.command_line AS command_line,
            p.host_id AS host_id,
            p.parent_name AS parent_process,
            p.start_time AS event_time,
            'ProcessMasqueradingRule' AS rule_id
        ORDER BY p.start_time DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class AMSIBypassRule(Rule):
    """
    Detects attempts to bypass the Antimalware Scan Interface (AMSI).

    Adversaries bypass AMSI by patching amsi.dll in memory, disabling it via
    registry keys, or using known PowerShell bypass strings.

    MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
    """

    rule_id: str = "DEF-EVA-004"
    rule_name: str = "AMSI Bypass Attempt Detected"
    description: str = (
        "A process has attempted to bypass the Windows Antimalware Scan Interface (AMSI) "
        "via registry modification, known bypass strings, or amsi.dll patching."
    )
    severity: Severity = Severity.CRITICAL
    category: RuleCategory = RuleCategory.DEFENSE_EVASION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Defense Evasion",
        technique_id="T1562.001",
        technique_name="Impair Defenses: Disable or Modify Tools",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["amsi", "bypass", "powershell", "registry", "defense-impair"]

    def get_cypher(self) -> str:
        return """
        // Pattern 1: Registry-based AMSI disable
        OPTIONAL MATCH (p1:Process)-[r1:MODIFIED|WRITES]->(rk:RegistryKey)
        WHERE
            p1.start_time >= datetime() - duration({seconds: $time_window}) AND
            (
                toLower(rk.key_path) CONTAINS 'amsi' OR
                (toLower(rk.key_path) CONTAINS 'policies\\microsoft\\windows defender' AND
                 rk.value_name IN ['DisableAntiSpyware', 'DisableRealtimeMonitoring']) OR
                toLower(rk.key_path) CONTAINS 'featurethrottlerate'
            )

        // Pattern 2: PowerShell with known AMSI bypass strings
        OPTIONAL MATCH (p2:Process)
        WHERE
            p2.start_time >= datetime() - duration({seconds: $time_window}) AND
            toLower(p2.name) IN ['powershell.exe', 'pwsh.exe'] AND
            (
                toLower(p2.command_line) CONTAINS 'amsiutils' OR
                toLower(p2.command_line) CONTAINS '[ref].assembly.gettype' OR
                toLower(p2.command_line) CONTAINS 'system.management.automation.amsi' OR
                toLower(p2.command_line) CONTAINS 'amsiinitfailed' OR
                toLower(p2.command_line) CONTAINS 'amsi.dll' OR
                toLower(p2.command_line) CONTAINS 'amsicontext' OR
                // Matt Graeber's bypass
                p2.command_line =~ '(?i).*\\.getfield.*nonpublic.*static.*'
            )

        WITH
            COLLECT(DISTINCT {
                entity_id: p1.id, process_name: p1.name, pid: p1.pid,
                command_line: p1.command_line, host_id: p1.host_id,
                registry_key: rk.key_path, event_time: p1.start_time,
                pattern: 'registry_amsi_disable'
            }) +
            COLLECT(DISTINCT {
                entity_id: p2.id, process_name: p2.name, pid: p2.pid,
                command_line: p2.command_line, host_id: p2.host_id,
                registry_key: null, event_time: p2.start_time,
                pattern: 'powershell_bypass_string'
            }) AS all_matches

        UNWIND [m IN all_matches WHERE m.entity_id IS NOT NULL] AS match
        RETURN
            match.entity_id AS entity_id,
            match.process_name AS process_name,
            match.pid AS pid,
            match.command_line AS command_line,
            match.host_id AS host_id,
            match.registry_key AS registry_key,
            match.pattern AS bypass_pattern,
            match.event_time AS event_time,
            'AMSIBypassRule' AS rule_id
        ORDER BY match.event_time DESC
        LIMIT 200
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class IndicatorRemovalRule(Rule):
    """
    Detects rapid deletion of multiple forensic artifacts (files, registry keys, logs).

    Adversaries clean up after themselves by deleting tools, logs, prefetch files,
    and other forensic artifacts to hinder incident response.

    MITRE ATT&CK: T1070 - Indicator Removal
    """

    rule_id: str = "DEF-EVA-005"
    rule_name: str = "Mass Forensic Artifact Deletion Detected"
    description: str = (
        "A process has deleted multiple forensic artifacts (prefetch files, shadow copies, "
        "log files, registry keys) in rapid succession, indicating anti-forensic activity."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.DEFENSE_EVASION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Defense Evasion",
        technique_id="T1070",
        technique_name="Indicator Removal",
    )
    time_window_seconds: int = 120
    min_match_count: int = 5
    tags: List[str] = ["artifact-removal", "anti-forensics", "prefetch", "cleanup"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)-[r:DELETED]->(f:File)
        WHERE
            p.start_time >= datetime() - duration({seconds: $time_window}) AND
            (
                // Prefetch files
                toLower(f.path) CONTAINS '\\windows\\prefetch\\' OR
                toLower(f.extension) = '.pf' OR
                // Temp/staging directories
                toLower(f.path) CONTAINS '\\temp\\' OR
                toLower(f.path) CONTAINS '\\tmp\\' OR
                // Shellbag/MRU related
                toLower(f.path) CONTAINS 'shellbags' OR
                // Recycle bin cleanup
                toLower(f.path) CONTAINS '\\$recycle.bin\\' OR
                // Shimcache / AppCompat
                toLower(f.name) CONTAINS 'appcompat' OR
                // Browser/tool artifacts
                toLower(f.extension) IN ['.lnk', '.tmp', '.log', '.evtx']
            )
        WITH p, COUNT(DISTINCT f) AS artifact_count,
             COLLECT(DISTINCT f.path)[..10] AS sample_paths
        WHERE artifact_count >= $min_count
        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            p.host_id AS host_id,
            artifact_count,
            sample_paths,
            p.start_time AS event_time,
            'IndicatorRemovalRule' AS rule_id
        ORDER BY artifact_count DESC
        LIMIT 100
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_count": self.min_match_count,
        }


class ObfuscatedCommandRule(Rule):
    """
    Detects processes launched with heavily obfuscated or base64-encoded command lines.

    Adversaries obfuscate commands to evade signature-based detection. Common patterns
    include base64 encoded PowerShell payloads, character substitution, and string concat.

    MITRE ATT&CK: T1027 - Obfuscated Files or Information
    """

    rule_id: str = "DEF-EVA-006"
    rule_name: str = "Obfuscated Command Line Execution Detected"
    description: str = (
        "A process was launched with a heavily obfuscated or base64-encoded command line "
        "argument, which is a common technique to bypass security monitoring."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.DEFENSE_EVASION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Defense Evasion",
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["obfuscation", "base64", "powershell", "command-line", "evasion"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)
        WHERE
            p.start_time >= datetime() - duration({seconds: $time_window}) AND
            p.command_line IS NOT NULL AND
            (
                // PowerShell -EncodedCommand / -enc / -ec flags with base64 payload
                (toLower(p.command_line) =~ '(?i).*-(encodedcommand|enc|ec|en)\\s+[A-Za-z0-9+/]{50,}={0,2}.*') OR

                // Long base64-like strings in any command (50+ chars of base64 alphabet)
                (p.command_line =~ '.*[A-Za-z0-9+/]{100,}={0,2}.*') OR

                // Invoke-Expression / IEX with string manipulation
                (toLower(p.command_line) =~ '(?i).*(iex|invoke-expression).*(\\.replace|\\.join|\\[char\\]|\\$env).*') OR

                // chr() character substitution obfuscation
                (toLower(p.command_line) =~ '(?i).*(chr\\([0-9]+\\)\\+){3,}.*') OR

                // String.Format or -join obfuscation
                (toLower(p.command_line) CONTAINS '-join' AND
                 toLower(p.command_line) CONTAINS '[char]') OR

                // FromBase64String
                (toLower(p.command_line) CONTAINS 'frombase64string') OR

                // Tick-mark obfuscation in PowerShell (backtick insertion)
                (toLower(p.name) IN ['powershell.exe','pwsh.exe'] AND
                 p.command_line =~ '.*`[a-zA-Z]{1,3}`[a-zA-Z]{1,3}.*') OR

                // Hex-encoded execution
                (toLower(p.command_line) =~ '(?i).*0x([0-9a-f]{2}){10,}.*')
            )
        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.pid AS pid,
            // Truncate long command lines in output
            CASE WHEN size(p.command_line) > 500
                 THEN left(p.command_line, 500) + '...[TRUNCATED]'
                 ELSE p.command_line
            END AS command_line,
            p.host_id AS host_id,
            p.parent_name AS parent_process,
            p.start_time AS event_time,
            'ObfuscatedCommandRule' AS rule_id
        ORDER BY p.start_time DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class DisableFirewallRule(Rule):
    """
    Detects attempts to disable the Windows Firewall via netsh or service manipulation.

    Adversaries disable host-based firewalls to enable outbound C2 communication
    or lateral movement without firewall interference.

    MITRE ATT&CK: T1562.004 - Impair Defenses: Disable or Modify System Firewall
    """

    rule_id: str = "DEF-EVA-007"
    rule_name: str = "Windows Firewall Disable Attempt Detected"
    description: str = (
        "A process has attempted to disable or modify the Windows Firewall via netsh "
        "commands, service control, or registry modification."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.DEFENSE_EVASION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Defense Evasion",
        technique_id="T1562.004",
        technique_name="Impair Defenses: Disable or Modify System Firewall",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["firewall", "netsh", "disable", "defense-impair", "network"]

    def get_cypher(self) -> str:
        return """
        // Pattern 1: netsh firewall disable commands
        OPTIONAL MATCH (p1:Process)
        WHERE
            p1.start_time >= datetime() - duration({seconds: $time_window}) AND
            toLower(p1.name) = 'netsh.exe' AND
            (
                toLower(p1.command_line) CONTAINS 'firewall set opmode disable' OR
                toLower(p1.command_line) CONTAINS 'advfirewall set allprofiles state off' OR
                toLower(p1.command_line) CONTAINS 'advfirewall set currentprofile state off' OR
                toLower(p1.command_line) CONTAINS 'advfirewall set privateprofile state off' OR
                toLower(p1.command_line) CONTAINS 'advfirewall set publicprofile state off' OR
                toLower(p1.command_line) CONTAINS 'advfirewall set domainprofile state off'
            )

        // Pattern 2: sc.exe stopping MpsSvc (Windows Firewall service)
        OPTIONAL MATCH (p2:Process)
        WHERE
            p2.start_time >= datetime() - duration({seconds: $time_window}) AND
            toLower(p2.name) IN ['sc.exe', 'sc'] AND
            (
                (toLower(p2.command_line) CONTAINS 'mpssvc' AND
                 (toLower(p2.command_line) CONTAINS ' stop ' OR
                  toLower(p2.command_line) CONTAINS 'disabled')) OR
                (toLower(p2.command_line) CONTAINS 'mpsdrv' AND
                 toLower(p2.command_line) CONTAINS 'disabled')
            )

        // Pattern 3: PowerShell disabling firewall profiles
        OPTIONAL MATCH (p3:Process)
        WHERE
            p3.start_time >= datetime() - duration({seconds: $time_window}) AND
            toLower(p3.name) IN ['powershell.exe', 'pwsh.exe'] AND
            (
                toLower(p3.command_line) CONTAINS 'set-netfirewallprofile' AND
                toLower(p3.command_line) CONTAINS '-enabled false'
            )

        WITH
            COLLECT(DISTINCT {
                entity_id: p1.id, process_name: p1.name, pid: p1.pid,
                command_line: p1.command_line, host_id: p1.host_id,
                event_time: p1.start_time, pattern: 'netsh_firewall_off'
            }) +
            COLLECT(DISTINCT {
                entity_id: p2.id, process_name: p2.name, pid: p2.pid,
                command_line: p2.command_line, host_id: p2.host_id,
                event_time: p2.start_time, pattern: 'sc_stop_mpssvc'
            }) +
            COLLECT(DISTINCT {
                entity_id: p3.id, process_name: p3.name, pid: p3.pid,
                command_line: p3.command_line, host_id: p3.host_id,
                event_time: p3.start_time, pattern: 'powershell_disable_profile'
            }) AS all_matches

        UNWIND [m IN all_matches WHERE m.entity_id IS NOT NULL] AS match
        RETURN
            match.entity_id AS entity_id,
            match.process_name AS process_name,
            match.pid AS pid,
            match.command_line AS command_line,
            match.host_id AS host_id,
            match.pattern AS disable_pattern,
            match.event_time AS event_time,
            'DisableFirewallRule' AS rule_id
        ORDER BY match.event_time DESC
        LIMIT 200
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


# Registry of all defense evasion rules
ALL_RULES: List[Rule] = [
    LogClearingRule(),
    TimestompingRule(),
    ProcessMasqueradingRule(),
    AMSIBypassRule(),
    IndicatorRemovalRule(),
    ObfuscatedCommandRule(),
    DisableFirewallRule(),
]
