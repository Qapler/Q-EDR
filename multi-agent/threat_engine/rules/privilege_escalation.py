"""
Privilege Escalation detection rules.

Covers MITRE ATT&CK Tactic: Privilege Escalation (TA0004).
Each rule queries the Neo4j behavioural graph for evidence of a process or
user gaining elevated privileges through abuse of system mechanisms.

Graph node types used: Process, Host, File, User, Service, RegistryKey
Relationships used   : SPAWNED, ACCESSED, CREATED, MODIFIED, WRITES,
                       HAS_PROCESS, OWNS
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
# 1. Sudo Abuse (T1548.003)
# ---------------------------------------------------------------------------

class SudoAbuseRule(Rule):
    """
    Detects processes executing with sudo from unexpected or non-standard paths.

    Legitimate sudo usage is typically limited to known administrative paths
    (/usr/bin, /usr/sbin, /bin, /sbin).  Processes running with sudo from
    temporary directories, home directories, or world-writable paths are
    strong indicators of privilege escalation.
    """

    rule_id = "PE-001"
    rule_name = "Sudo Abuse from Non-Standard Path"
    description = (
        "A process executed with sudo privileges from a path that is not a "
        "standard administrative directory, indicating potential sudo abuse "
        "for privilege escalation."
    )
    severity = Severity.HIGH
    category = RuleCategory.PRIVILEGE_ESCALATION
    mitre = MITRETechnique(
        tactic="Privilege Escalation",
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        sub_technique_id="003",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["sudo", "linux", "elevation"]

    # Paths considered safe for sudo execution
    SAFE_SUDO_PATHS = [
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        "/usr/local/bin/", "/usr/local/sbin/", "/opt/",
    ]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)
        WHERE p.effective_uid = 0
          AND p.sudo = true
          AND p.start_time > datetime() - duration({seconds: $time_window})
          AND NOT (
              p.path STARTS WITH '/usr/bin/'
              OR p.path STARTS WITH '/usr/sbin/'
              OR p.path STARTS WITH '/bin/'
              OR p.path STARTS WITH '/sbin/'
              OR p.path STARTS WITH '/usr/local/bin/'
              OR p.path STARTS WITH '/usr/local/sbin/'
              OR p.path STARTS WITH '/opt/'
          )
        OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p)
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(p)
        RETURN p.pid         AS pid,
               p.name        AS process_name,
               p.path        AS binary_path,
               p.cmdline     AS command_line,
               p.user        AS original_user,
               p.start_time  AS start_time,
               parent.name   AS parent_process,
               h.hostname    AS hostname,
               [id(p)]       AS ids
        ORDER BY p.start_time DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 2. Token Impersonation (T1134.001)
# ---------------------------------------------------------------------------

class TokenImpersonationRule(Rule):
    """
    Detects processes that use impersonation tokens to spawn privileged children.

    Windows token impersonation allows a process to assume the security context
    of another user.  Attackers abuse this to run child processes under higher-
    privileged accounts (e.g., SYSTEM) after stealing a token from a running
    service or process.
    """

    rule_id = "PE-002"
    rule_name = "Token Impersonation Child Process Spawned"
    description = (
        "A process with an impersonation token (token_type=Impersonation, "
        "impersonation_level >= Impersonation) spawned a child process, "
        "indicating potential token theft and privilege escalation."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.PRIVILEGE_ESCALATION
    mitre = MITRETechnique(
        tactic="Privilege Escalation",
        technique_id="T1134",
        technique_name="Access Token Manipulation",
        sub_technique_id="001",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["token-impersonation", "windows", "access-token"]

    def get_cypher(self) -> str:
        return """
        MATCH (parent:Process)-[:SPAWNED]->(child:Process)
        WHERE parent.token_type = 'Impersonation'
          AND parent.impersonation_level IN ['Impersonation', 'Delegation']
          AND parent.token_integrity_level IN ['System', 'High']
          AND child.start_time > datetime() - duration({seconds: $time_window})
          AND parent.name NOT IN ['services.exe', 'lsass.exe', 'winlogon.exe']
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(parent)
        RETURN parent.pid         AS parent_pid,
               parent.name        AS parent_process,
               parent.token_user  AS impersonated_user,
               parent.token_integrity_level AS integrity_level,
               child.pid          AS child_pid,
               child.name         AS child_process,
               child.cmdline      AS child_cmdline,
               child.start_time   AS spawn_time,
               h.hostname         AS hostname,
               [id(parent), id(child)] AS ids
        ORDER BY child.start_time DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 3. Process Injection (T1055)
# ---------------------------------------------------------------------------

class ProcessInjectionRule(Rule):
    """
    Detects a process writing to the memory of another (cross-process write).

    The graph records memory write operations as WRITES relationships between
    Process nodes.  A cross-process memory write from a non-parent process
    to a high-value target (lsass, winlogon, explorer, etc.) is a strong
    indicator of process injection (DLL injection, process hollowing, etc.).
    """

    rule_id = "PE-003"
    rule_name = "Cross-Process Memory Injection"
    description = (
        "A process was observed writing to the virtual memory of another "
        "process via APIs consistent with process injection techniques such "
        "as DLL injection, process hollowing, or shellcode injection."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.PRIVILEGE_ESCALATION
    mitre = MITRETechnique(
        tactic="Privilege Escalation",
        technique_id="T1055",
        technique_name="Process Injection",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["process-injection", "memory-write", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (attacker:Process)-[w:WRITES]->(victim:Process)
        WHERE w.type = 'remote_memory'
          AND w.api IN ['WriteProcessMemory', 'NtWriteVirtualMemory',
                        'ZwWriteVirtualMemory', 'VirtualAllocEx']
          AND w.timestamp > datetime() - duration({seconds: $time_window})
          AND attacker.pid <> victim.pid
          AND NOT (attacker)-[:SPAWNED]->(victim)
          AND NOT (victim)-[:SPAWNED]->(attacker)
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(attacker)
        RETURN attacker.pid    AS attacker_pid,
               attacker.name   AS attacker_process,
               attacker.path   AS attacker_path,
               victim.pid      AS victim_pid,
               victim.name     AS victim_process,
               victim.user     AS victim_user,
               w.api           AS injection_api,
               w.timestamp     AS event_time,
               h.hostname      AS hostname,
               [id(attacker), id(victim)] AS ids
        ORDER BY w.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 4. SETUID Binary Exploitation (T1548.001)
# ---------------------------------------------------------------------------

class SETUIDExploitRule(Rule):
    """
    Detects exploitation of SETUID binaries to escalate privileges.

    A SETUID binary runs with the file owner's privileges regardless of who
    invoked it.  This rule flags execution of SETUID binaries from unexpected
    parent processes or where the resulting process has a UID that does not
    match the invoking user, indicating privilege escalation.
    """

    rule_id = "PE-004"
    rule_name = "SETUID Binary Execution for Privilege Escalation"
    description = (
        "A SETUID binary was executed and resulted in a process running with "
        "elevated (root) privileges, potentially indicating exploitation of "
        "a vulnerable SETUID program."
    )
    severity = Severity.HIGH
    category = RuleCategory.PRIVILEGE_ESCALATION
    mitre = MITRETechnique(
        tactic="Privilege Escalation",
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        sub_technique_id="001",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["setuid", "linux", "suid", "elevation"]

    def get_cypher(self) -> str:
        return """
        MATCH (parent:Process)-[:SPAWNED]->(child:Process)-[:ACCESSED]->(bin:File)
        WHERE bin.setuid = true
          AND child.effective_uid = 0
          AND child.real_uid <> 0
          AND child.start_time > datetime() - duration({seconds: $time_window})
          AND NOT parent.name IN ['cron', 'su', 'sudo', 'login', 'sshd']
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(child)
        RETURN parent.pid    AS parent_pid,
               parent.name   AS parent_process,
               parent.user   AS invoking_user,
               child.pid     AS child_pid,
               child.name    AS child_process,
               child.real_uid   AS real_uid,
               child.effective_uid AS effective_uid,
               bin.path      AS setuid_binary,
               bin.owner     AS binary_owner,
               h.hostname    AS hostname,
               [id(parent), id(child), id(bin)] AS ids
        ORDER BY child.start_time DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 5. Service Binary Hijacking (T1574.010)
# ---------------------------------------------------------------------------

class ServicePrivEscRule(Rule):
    """
    Detects privilege escalation via service binary replacement or hijacking.

    Attackers replace or modify the executable of a privileged service.  The
    next time the service starts, the attacker's binary runs with SYSTEM or
    elevated privileges.  This rule looks for modifications to service
    binaries followed by service restarts within the time window.
    """

    rule_id = "PE-005"
    rule_name = "Service Binary Replaced or Hijacked"
    description = (
        "A service binary was modified or replaced, and the service was "
        "subsequently restarted, indicating a potential service binary "
        "hijacking attack for privilege escalation."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.PRIVILEGE_ESCALATION
    mitre = MITRETechnique(
        tactic="Privilege Escalation",
        technique_id="T1574",
        technique_name="Hijack Execution Flow",
        sub_technique_id="010",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["service-hijack", "binary-replacement", "windows", "linux"]

    def get_cypher(self) -> str:
        return """
        MATCH (svc:Service)-[:ACCESSED]->(bin:File)
        WHERE bin.is_service_binary = true
        MATCH (modifier:Process)-[mod:MODIFIED]->(bin)
        WHERE mod.timestamp > datetime() - duration({seconds: $time_window})
          AND NOT modifier.name IN ['MsiExec.exe', 'TrustedInstaller.exe',
                                     'msiexec.exe', 'WindowsUpdateAgent']
          AND modifier.integrity_level NOT IN ['System']
        MATCH (svc)-[restart:TRIGGERED]->(new_proc:Process)
        WHERE new_proc.start_time > mod.timestamp
          AND new_proc.start_time <= mod.timestamp + duration({seconds: 120})
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(modifier)
        RETURN svc.name       AS service_name,
               bin.path       AS binary_path,
               modifier.name  AS modifier_process,
               modifier.user  AS modifier_user,
               mod.timestamp  AS modification_time,
               new_proc.name  AS spawned_service_binary,
               new_proc.user  AS service_run_as,
               h.hostname     AS hostname,
               [id(svc), id(bin), id(modifier), id(new_proc)] AS ids
        ORDER BY mod.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 6. Unquoted Service Path (T1574.009)
# ---------------------------------------------------------------------------

class UnquotedServicePathRule(Rule):
    """
    Detects services with unquoted paths that contain spaces and are exploitable.

    When a service's ImagePath is unquoted and contains spaces, Windows tries
    each prefix as a potential executable.  Placing a binary at any of those
    locations causes it to execute with the service's privileges.  This rule
    detects files created in exploit-candidate locations correlated with
    an unquoted service being started.
    """

    rule_id = "PE-006"
    rule_name = "Unquoted Service Path Exploitation"
    description = (
        "A file was created in a path that matches an unquoted service path "
        "segment, and the affected service was subsequently started, "
        "indicating potential unquoted service path exploitation."
    )
    severity = Severity.HIGH
    category = RuleCategory.PRIVILEGE_ESCALATION
    mitre = MITRETechnique(
        tactic="Privilege Escalation",
        technique_id="T1574",
        technique_name="Hijack Execution Flow",
        sub_technique_id="009",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["unquoted-path", "service", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (svc:Service)
        WHERE svc.image_path IS NOT NULL
          AND svc.image_path CONTAINS ' '
          AND NOT (svc.image_path STARTS WITH '"')
        WITH svc,
             split(svc.image_path, ' ')[0] AS first_segment,
             svc.image_path AS unquoted_path
        MATCH (dropper:Process)-[cr:CREATED]->(planted:File)
        WHERE cr.timestamp > datetime() - duration({seconds: $time_window})
          AND (planted.path ENDS WITH '.exe'
               OR planted.path ENDS WITH '.EXE')
          AND planted.path CONTAINS split(unquoted_path, '\\')[1]
        MATCH (svc)-[t:TRIGGERED]->(svc_proc:Process)
        WHERE svc_proc.start_time > cr.timestamp
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(dropper)
        RETURN svc.name        AS service_name,
               unquoted_path  AS unquoted_service_path,
               planted.path   AS planted_binary,
               dropper.name   AS dropper_process,
               dropper.user   AS dropper_user,
               svc_proc.name  AS service_spawned_binary,
               svc_proc.user  AS service_user,
               h.hostname     AS hostname,
               [id(svc), id(planted), id(dropper), id(svc_proc)] AS ids
        ORDER BY cr.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 7. PrintSpooler / Print Nightmare Exploitation (T1068)
# ---------------------------------------------------------------------------

class PrintSpoolerEscRule(Rule):
    """
    Detects exploitation of the Windows Print Spooler service (PrintNightmare
    and similar vulnerabilities) for local privilege escalation.

    The attack pattern is: spoolsv.exe spawns an unexpected child process or
    loads a DLL from a non-standard path, frequently resulting in a SYSTEM-
    level shell.  This rule detects both the process-spawn and DLL-load variants.
    """

    rule_id = "PE-007"
    rule_name = "PrintSpooler Privilege Escalation (PrintNightmare)"
    description = (
        "The Windows Print Spooler service (spoolsv.exe) spawned an unexpected "
        "child process or loaded a DLL from a user-writable path, consistent "
        "with PrintNightmare (CVE-2021-1675 / CVE-2021-34527) exploitation."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.PRIVILEGE_ESCALATION
    mitre = MITRETechnique(
        tactic="Privilege Escalation",
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["printnightmare", "spooler", "windows", "cve-2021-1675"]

    def get_cypher(self) -> str:
        return """
        MATCH (spooler:Process)
        WHERE spooler.name IN ['spoolsv.exe', 'spoolss.exe']
          AND spooler.start_time > datetime() - duration({seconds: $time_window})
        // Variant 1: spoolsv spawns unexpected child
        OPTIONAL MATCH (spooler)-[:SPAWNED]->(child:Process)
        WHERE child.name NOT IN ['conhost.exe', 'splwow64.exe', 'WerFault.exe']
          AND child.start_time > datetime() - duration({seconds: $time_window})
        // Variant 2: spoolsv loads DLL from non-standard path
        OPTIONAL MATCH (spooler)-[:ACCESSED]->(dll:File)
        WHERE dll.extension = 'dll'
          AND dll.start_time > datetime() - duration({seconds: $time_window})
          AND NOT (
              dll.path STARTS WITH 'C:\\Windows\\System32\\'
              OR dll.path STARTS WITH 'C:\\Windows\\SysWOW64\\'
              OR dll.path STARTS WITH 'C:\\Windows\\WinSxS\\'
          )
        WITH spooler, child, dll
        WHERE child IS NOT NULL OR dll IS NOT NULL
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(spooler)
        RETURN spooler.pid       AS spooler_pid,
               spooler.user      AS spooler_user,
               child.pid         AS child_pid,
               child.name        AS child_process,
               child.cmdline     AS child_cmdline,
               child.user        AS child_user,
               dll.path          AS suspicious_dll,
               h.hostname        AS hostname,
               [id(spooler)] + CASE WHEN child IS NOT NULL THEN [id(child)] ELSE [] END +
               CASE WHEN dll IS NOT NULL THEN [id(dll)] ELSE [] END AS ids
        ORDER BY spooler.start_time DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count
