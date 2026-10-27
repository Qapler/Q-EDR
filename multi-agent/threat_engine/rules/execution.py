"""
Execution detection rules for the Q-EDR threat detection engine.

Covers MITRE ATT&CK Tactic: TA0002 - Execution
Techniques: T1059, T1218, T1047, T1204, T1620
"""

import logging
from typing import Any, Dict, List

from .base import Rule, RuleCategory, RuleMatch, Severity, MITRETechnique

logger = logging.getLogger(__name__)


class PowerShellEncoded(Rule):
    """
    Detects PowerShell processes launched with the -EncodedCommand flag.

    The -EncodedCommand (or -enc / -ec) flag accepts a Base64-encoded command
    and is commonly abused by attackers to evade command-line logging and AV.

    MITRE ATT&CK: T1059.001 - Command and Scripting Interpreter: PowerShell
    """

    rule_id: str = "EXEC-001"
    rule_name: str = "PowerShell Encoded Command Execution"
    description: str = (
        "PowerShell was launched with the -EncodedCommand flag, which is commonly used "
        "by attackers to obfuscate malicious commands and evade detection."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.EXECUTION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Execution",
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["powershell", "encoded-command", "base64", "obfuscation"]

    def get_cypher(self) -> str:
        return r"""
        MATCH (p:Process)
        WHERE
            p.start_time >= datetime() - duration({seconds: $time_window}) AND
            toLower(p.name) IN ['powershell.exe', 'pwsh.exe'] AND
            (
                // Standard encoded command flags (case insensitive)
                toLower(p.command_line) =~ '(?i).*(\\s|^)(-(encodedcommand|enc|ec|en|e))(\\s|$).*' AND
                // Must have a base64-like payload after the flag
                p.command_line =~ '.*(\\s)[A-Za-z0-9+/]{20,}={0,2}(\\s|$).*'
            )
        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.pid AS pid,
            CASE WHEN size(p.command_line) > 500
                 THEN left(p.command_line, 500) + '...[TRUNCATED]'
                 ELSE p.command_line
            END AS command_line,
            p.host_id AS host_id,
            p.parent_name AS parent_process,
            p.parent_pid AS parent_pid,
            p.username AS executing_user,
            p.start_time AS event_time,
            'PowerShellEncoded' AS rule_id
        ORDER BY p.start_time DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class LOLBinExecutionRule(Rule):
    """
    Detects suspicious execution of Living-Off-the-Land Binaries (LOLBins).

    LOLBins are legitimate Windows binaries abused by adversaries to execute
    arbitrary code, download payloads, or bypass security controls.

    MITRE ATT&CK: T1218 - System Binary Proxy Execution
    """

    rule_id: str = "EXEC-002"
    rule_name: str = "Living-off-the-Land Binary (LOLBin) Abuse Detected"
    description: str = (
        "A known Windows LOLBin binary (regsvr32, mshta, certutil, wmic, etc.) was "
        "executed with parameters consistent with malicious abuse."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.EXECUTION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Execution",
        technique_id="T1218",
        technique_name="System Binary Proxy Execution",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["lolbin", "certutil", "mshta", "regsvr32", "proxy-execution"]

    def get_cypher(self) -> str:
        return r"""
        MATCH (p:Process)
        WHERE
            p.start_time >= datetime() - duration({seconds: $time_window}) AND
            (
                // certutil: decode, download, or encode operations
                (toLower(p.name) = 'certutil.exe' AND
                 toLower(p.command_line) =~ '(?i).*(-(urlcache|decode|encode|decodehex|f|split)\\s).*') OR

                // mshta: executing remote or local HTA files / JavaScript / VBScript
                (toLower(p.name) = 'mshta.exe' AND
                 (toLower(p.command_line) CONTAINS 'http' OR
                  toLower(p.command_line) CONTAINS 'vbscript:' OR
                  toLower(p.command_line) CONTAINS 'javascript:' OR
                  toLower(p.command_line) =~ '(?i).*\\.hta.*')) OR

                // regsvr32: squiblydoo - executing arbitrary DLL/SCT from URL
                (toLower(p.name) = 'regsvr32.exe' AND
                 (toLower(p.command_line) CONTAINS '/i:http' OR
                  toLower(p.command_line) CONTAINS '/i:ftp' OR
                  (toLower(p.command_line) CONTAINS '/s' AND
                   toLower(p.command_line) CONTAINS '/u' AND
                   toLower(p.command_line) CONTAINS '/i:'))) OR

                // wmic: executing from URL or spawning processes
                (toLower(p.name) = 'wmic.exe' AND
                 (toLower(p.command_line) CONTAINS 'process call create' OR
                  toLower(p.command_line) CONTAINS '/node:')) OR

                // bitsadmin: downloading files
                (toLower(p.name) = 'bitsadmin.exe' AND
                 (toLower(p.command_line) CONTAINS '/transfer' OR
                  toLower(p.command_line) CONTAINS '/download')) OR

                // InstallUtil: executing arbitrary .NET code
                (toLower(p.name) = 'installutil.exe' AND
                 NOT toLower(p.parent_name) IN ['msiexec.exe', 'setup.exe', 'installer.exe']) OR

                // msiexec: remote MSI installation
                (toLower(p.name) = 'msiexec.exe' AND
                 toLower(p.command_line) =~ '(?i).*/(i|q)\\s+https?://.*') OR

                // odbcconf: executing DLL
                (toLower(p.name) = 'odbcconf.exe' AND
                 toLower(p.command_line) =~ '(?i).*(regsvr|/a).*') OR

                // Forfiles: arbitrary command execution
                (toLower(p.name) = 'forfiles.exe' AND
                 toLower(p.command_line) CONTAINS '/c') OR

                // pcalua / pcwrun: execution proxy
                (toLower(p.name) IN ['pcalua.exe', 'pcwrun.exe'] AND
                 toLower(p.command_line) =~ '(?i).*-a\\s+.*')
            )
        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            p.host_id AS host_id,
            p.parent_name AS parent_process,
            p.parent_pid AS parent_pid,
            p.path AS process_path,
            p.username AS executing_user,
            p.start_time AS event_time,
            'LOLBinExecutionRule' AS rule_id
        ORDER BY p.start_time DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class WMIScriptExecRule(Rule):
    """
    Detects WMI (Windows Management Instrumentation) spawning cmd.exe or PowerShell.

    WMI is commonly used by attackers for lateral movement, persistence, and remote
    execution. WMI spawning shell interpreters is a strong attacker indicator.

    MITRE ATT&CK: T1047 - Windows Management Instrumentation
    """

    rule_id: str = "EXEC-003"
    rule_name: str = "WMI Spawning Shell Interpreter"
    description: str = (
        "WMI processes (wmiprvse.exe, wmic.exe) spawned a command interpreter "
        "(cmd.exe, powershell.exe), which is strongly associated with malicious WMI execution."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.EXECUTION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Execution",
        technique_id="T1047",
        technique_name="Windows Management Instrumentation",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["wmi", "wmiprvse", "lateral-movement", "remote-execution"]

    def get_cypher(self) -> str:
        return """
        MATCH (parent:Process)-[:SPAWNED]->(child:Process)
        WHERE
            child.start_time >= datetime() - duration({seconds: $time_window}) AND
            // WMI parent processes
            toLower(parent.name) IN [
                'wmiprvse.exe', 'wmic.exe', 'wmiapsrv.exe', 'scrcons.exe'
            ] AND
            // Shell interpreters as children
            toLower(child.name) IN [
                'cmd.exe', 'powershell.exe', 'pwsh.exe',
                'wscript.exe', 'cscript.exe', 'mshta.exe',
                'rundll32.exe', 'regsvr32.exe'
            ]
        RETURN
            parent.id AS entity_id,
            parent.name AS wmi_process,
            parent.pid AS wmi_pid,
            child.name AS spawned_process,
            child.pid AS spawned_pid,
            child.command_line AS spawned_command,
            child.host_id AS host_id,
            child.username AS executing_user,
            parent.start_time AS wmi_start_time,
            child.start_time AS event_time,
            'WMIScriptExecRule' AS rule_id
        ORDER BY child.start_time DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class MaliciousMacroRule(Rule):
    """
    Detects Office applications spawning shell interpreters, a classic macro attack pattern.

    Malicious macros in Office documents spawn cmd.exe, PowerShell, or script hosts
    to download and execute second-stage payloads.

    MITRE ATT&CK: T1204.002 - User Execution: Malicious File
    """

    rule_id: str = "EXEC-004"
    rule_name: str = "Office Application Spawning Shell Interpreter (Macro Attack)"
    description: str = (
        "A Microsoft Office application spawned a command interpreter or script host, "
        "which is the hallmark of a malicious macro executing a payload."
    )
    severity: Severity = Severity.CRITICAL
    category: RuleCategory = RuleCategory.EXECUTION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Execution",
        technique_id="T1204.002",
        technique_name="User Execution: Malicious File",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["macro", "office", "vba", "spearphishing", "initial-access"]

    def get_cypher(self) -> str:
        return """
        MATCH (parent:Process)-[:SPAWNED]->(child:Process)
        WHERE
            child.start_time >= datetime() - duration({seconds: $time_window}) AND
            // Office application parents
            toLower(parent.name) IN [
                'winword.exe', 'excel.exe', 'powerpnt.exe',
                'outlook.exe', 'onenote.exe', 'msaccess.exe',
                'mspub.exe', 'wordpad.exe', 'eqnedt32.exe',
                'acrord32.exe', 'acrobat.exe', 'foxit reader.exe'
            ] AND
            // Suspicious child processes
            toLower(child.name) IN [
                'cmd.exe', 'powershell.exe', 'pwsh.exe',
                'wscript.exe', 'cscript.exe', 'mshta.exe',
                'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
                'bitsadmin.exe', 'wmic.exe', 'msiexec.exe',
                'schtasks.exe', 'at.exe', 'curl.exe', 'wget.exe'
            ]
        RETURN
            parent.id AS entity_id,
            parent.name AS office_application,
            parent.pid AS office_pid,
            parent.command_line AS office_command,
            child.name AS spawned_interpreter,
            child.pid AS spawned_pid,
            child.command_line AS spawned_command,
            child.host_id AS host_id,
            child.username AS executing_user,
            parent.start_time AS office_start_time,
            child.start_time AS event_time,
            'MaliciousMacroRule' AS rule_id
        ORDER BY child.start_time DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class ScriptInterpreterChainRule(Rule):
    """
    Detects multi-stage script interpreter chains: cmd -> powershell -> wscript -> download.

    Multi-hop interpreter chaining is used by adversaries to obfuscate their attack
    chain and evade detection systems that only inspect single process relationships.

    MITRE ATT&CK: T1059.005 - Command and Scripting Interpreter: Visual Basic
    """

    rule_id: str = "EXEC-005"
    rule_name: str = "Multi-Stage Script Interpreter Chain Detected"
    description: str = (
        "A chain of script interpreters was spawned in sequence (e.g., cmd → PowerShell → "
        "wscript), followed by download activity, indicating a multi-stage attack."
    )
    severity: Severity = Severity.CRITICAL
    category: RuleCategory = RuleCategory.EXECUTION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Execution",
        technique_id="T1059.005",
        technique_name="Command and Scripting Interpreter: Visual Basic",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = [
        "script-chain", "powershell", "wscript", "cscript", "download", "multi-stage"
    ]

    def get_cypher(self) -> str:
        return """
        // Detect 3-level or deeper interpreter chains
        MATCH (stage1:Process)-[:SPAWNED]->(stage2:Process)-[:SPAWNED]->(stage3:Process)
        WHERE
            stage3.start_time >= datetime() - duration({seconds: $time_window}) AND

            // Stage 1: cmd or initial interpreter
            toLower(stage1.name) IN [
                'cmd.exe', 'explorer.exe', 'winword.exe', 'excel.exe',
                'powerpnt.exe', 'outlook.exe', 'wmiprvse.exe'
            ] AND

            // Stage 2: scripting engine
            toLower(stage2.name) IN [
                'powershell.exe', 'pwsh.exe', 'wscript.exe',
                'cscript.exe', 'mshta.exe', 'cmd.exe'
            ] AND

            // Stage 3: another script engine or download tool (deeper chain)
            toLower(stage3.name) IN [
                'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
                'mshta.exe', 'certutil.exe', 'bitsadmin.exe',
                'curl.exe', 'wget.exe', 'regsvr32.exe', 'rundll32.exe'
            ] AND

            // Stage 1 and Stage 2 should not be the same process name (actual chain)
            stage1.name <> stage2.name

        // Optionally check for network activity from stage 3 (download indicator)
        OPTIONAL MATCH (stage3)-[:CONNECTED_TO]->(nc:NetworkConnection)
        WHERE
            nc.timestamp >= stage3.start_time AND
            nc.direction = 'outbound'

        WITH
            stage1, stage2, stage3, nc,
            COUNT(nc) > 0 AS has_network_activity

        RETURN
            stage1.id AS entity_id,
            stage1.name AS stage1_process,
            stage1.pid AS stage1_pid,
            stage2.name AS stage2_process,
            stage2.pid AS stage2_pid,
            stage2.command_line AS stage2_command,
            stage3.name AS stage3_process,
            stage3.pid AS stage3_pid,
            stage3.command_line AS stage3_command,
            stage3.host_id AS host_id,
            stage3.username AS executing_user,
            has_network_activity,
            stage3.start_time AS event_time,
            'ScriptInterpreterChainRule' AS rule_id
        ORDER BY stage3.start_time DESC
        LIMIT 200
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class DotNetAssemblyLoadRule(Rule):
    """
    Detects processes loading .NET assemblies from unusual paths or network locations.

    Adversaries use reflection to load .NET assemblies in memory from unusual paths
    to execute malicious code without writing to disk (fileless execution).

    MITRE ATT&CK: T1620 - Reflective Code Loading
    """

    rule_id: str = "EXEC-006"
    rule_name: str = "Suspicious .NET Assembly Loading from Non-Standard Path"
    description: str = (
        "A process loaded a .NET assembly from an unusual path (temp directory, network "
        "share, or user-writable location), indicating potential reflective code loading."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.EXECUTION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Execution",
        technique_id="T1620",
        technique_name="Reflective Code Loading",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = [
        "dotnet", "assembly", "reflection", "fileless", "clr", "powershell"
    ]

    def get_cypher(self) -> str:
        return r"""
        MATCH (p:Process)-[r:READS|ACCESSED]->(f:File)
        WHERE
            r.timestamp >= datetime() - duration({seconds: $time_window}) AND
            // DLL / EXE / assembly files
            toLower(f.extension) IN ['.dll', '.exe', '.ni.dll', '.nupkg'] AND
            (
                // From temp/user-writable paths (suspicious for assemblies)
                toLower(f.path) CONTAINS 'appdata\\local\\temp' OR
                toLower(f.path) CONTAINS '\\temp\\' OR
                toLower(f.path) CONTAINS '\\tmp\\' OR
                toLower(f.path) CONTAINS '\\downloads\\' OR
                // From network shares
                f.path STARTS WITH '\\\\' OR
                // From recycle bin
                toLower(f.path) CONTAINS '$recycle.bin' OR
                // From public user directories
                toLower(f.path) CONTAINS '\\users\\public\\' OR
                // From ProgramData (sometimes abused)
                (toLower(f.path) CONTAINS '\\programdata\\' AND
                 NOT toLower(f.path) CONTAINS 'microsoft')
            ) AND
            // Loader processes
            toLower(p.name) IN [
                'powershell.exe', 'pwsh.exe', 'dotnet.exe',
                'csc.exe', 'msbuild.exe', 'installutil.exe',
                'regasm.exe', 'regsvcs.exe', 'vbc.exe'
            ]

        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            p.host_id AS host_id,
            f.path AS assembly_path,
            f.name AS assembly_name,
            f.size_bytes AS assembly_size,
            f.md5_hash AS assembly_hash,
            r.timestamp AS event_time,
            'DotNetAssemblyLoadRule' AS rule_id
        ORDER BY r.timestamp DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


class RunDLL32AbuseRule(Rule):
    """
    Detects rundll32.exe executing non-standard or suspicious DLL entrypoints.

    rundll32.exe is frequently abused to execute malicious DLLs by specifying
    a non-standard export function, bypassing application whitelisting.

    MITRE ATT&CK: T1218.011 - System Binary Proxy Execution: Rundll32
    """

    rule_id: str = "EXEC-007"
    rule_name: str = "Suspicious rundll32.exe DLL Execution"
    description: str = (
        "rundll32.exe was invoked with a non-standard or suspicious DLL and/or entry point, "
        "indicating potential abuse for code execution or defense evasion."
    )
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.EXECUTION
    mitre: MITRETechnique = MITRETechnique(
        tactic="Execution",
        technique_id="T1218.011",
        technique_name="System Binary Proxy Execution: Rundll32",
    )
    time_window_seconds: int = 300
    min_match_count: int = 1
    tags: List[str] = ["rundll32", "dll-execution", "proxy-execution", "lolbin"]

    def get_cypher(self) -> str:
        return r"""
        MATCH (p:Process)
        WHERE
            p.start_time >= datetime() - duration({seconds: $time_window}) AND
            toLower(p.name) = 'rundll32.exe' AND
            (
                // DLL loaded from suspicious paths
                toLower(p.command_line) =~ '(?i).*rundll32(\.exe)?\\s+("|\')?[^"\']*appdata[^"\']*\.dll.*' OR
                toLower(p.command_line) =~ '(?i).*rundll32(\.exe)?\\s+("|\')?[^"\']*temp[^"\']*\.dll.*' OR
                toLower(p.command_line) =~ '(?i).*rundll32(\.exe)?\\s+("|\')?\\\\\\\\[^"\']+\.dll.*' OR

                // JavaScript/VBScript execution via shimgvw
                toLower(p.command_line) CONTAINS 'javascript:' OR
                toLower(p.command_line) CONTAINS 'vbscript:' OR

                // Known malicious entrypoints
                toLower(p.command_line) =~ '(?i).*(shell32\.dll|shdocvw\.dll|syssetup\.dll|advpack\.dll|ieadvpack\.dll),.*' OR

                // Running without proper DLL argument (empty or script)
                (toLower(p.command_line) =~ '(?i).*rundll32(\.exe)?\\s*$') OR

                // Executing .com, .txt, .jpg or other non-DLL as DLL
                toLower(p.command_line) =~ '(?i).*rundll32(\.exe)?\\s+[^\\s]+\\.(com|txt|jpg|png|dat).*' OR

                // Executing from temp or user-writable path
                (toLower(p.command_line) CONTAINS 'rundll32' AND
                 (toLower(p.path) CONTAINS 'temp' OR
                  toLower(p.path) CONTAINS 'appdata') AND
                 NOT toLower(p.path) CONTAINS 'system32')
            )
        RETURN
            p.id AS entity_id,
            p.name AS process_name,
            p.pid AS pid,
            p.command_line AS command_line,
            p.path AS process_path,
            p.host_id AS host_id,
            p.parent_name AS parent_process,
            p.parent_pid AS parent_pid,
            p.username AS executing_user,
            p.start_time AS event_time,
            'RunDLL32AbuseRule' AS rule_id
        ORDER BY p.start_time DESC
        LIMIT 500
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {"time_window": self.time_window_seconds}


# Registry of all execution rules
ALL_RULES: List[Rule] = [
    PowerShellEncoded(),
    LOLBinExecutionRule(),
    WMIScriptExecRule(),
    MaliciousMacroRule(),
    ScriptInterpreterChainRule(),
    DotNetAssemblyLoadRule(),
    RunDLL32AbuseRule(),
]
