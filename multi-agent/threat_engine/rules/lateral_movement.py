"""
Lateral Movement detection rules.

Covers MITRE ATT&CK Tactic: Lateral Movement (TA0008).
Each rule queries the Neo4j behavioural graph for evidence of an attacker
moving from one host to another using various techniques.

Graph node types used: Host, Process, NetworkConnection, User, Service, File
Relationships used   : CONNECTED_TO, AUTHENTICATED_TO, SPAWNED, CREATED,
                       HAS_PROCESS, OWNS, ACCESSED
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
# 1. Pass-the-Hash (T1550.002)
# ---------------------------------------------------------------------------

class PassTheHashRule(Rule):
    """
    Detects credential reuse via NTLM hash across multiple distinct hosts.

    A pass-the-hash attack is indicated when the same NTLM hash value appears
    in successful authentication events targeting three or more different hosts
    within the look-back window.  The graph stores authentication edges
    (AUTHENTICATED_TO) with a `ntlm_hash` property set when NTLM was used.
    """

    rule_id = "LM-001"
    rule_name = "Pass-the-Hash Detected"
    description = (
        "The same NTLM credential hash was used to authenticate to multiple "
        "hosts within the time window, indicating a pass-the-hash attack."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.LATERAL_MOVEMENT
    mitre = MITRETechnique(
        tactic="Lateral Movement",
        technique_id="T1550",
        technique_name="Use Alternate Authentication Material",
        sub_technique_id="002",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["credential-reuse", "ntlm", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (u:User)-[auth:AUTHENTICATED_TO]->(dst:Host)
        WHERE auth.protocol = 'NTLM'
          AND auth.ntlm_hash IS NOT NULL
          AND auth.timestamp > datetime() - duration({seconds: $time_window})
        WITH u, auth.ntlm_hash AS hash, collect(DISTINCT dst.ip) AS target_ips,
             collect(DISTINCT id(dst)) AS dst_ids, collect(DISTINCT id(u)) AS u_ids
        WHERE size(target_ips) >= 3
        RETURN u.name        AS username,
               hash          AS ntlm_hash,
               target_ips    AS target_hosts,
               size(target_ips) AS hop_count,
               u_ids + dst_ids AS ids
        ORDER BY hop_count DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return any(r.get("hop_count", 0) >= 3 for r in records)


# ---------------------------------------------------------------------------
# 2. RDP Lateral Movement (T1021.001)
# ---------------------------------------------------------------------------

class RDPLateralMovementRule(Rule):
    """
    Detects RDP connections between internal hosts (east-west traffic).

    Legitimate RDP from a management jump-box is expected; this rule flags
    RDP connections that originate from non-designated sources, particularly
    those that chain: workstation → server → domain controller.
    """

    rule_id = "LM-002"
    rule_name = "RDP Lateral Movement"
    description = (
        "An internal host initiated an RDP session to another internal host. "
        "Chained RDP hops may indicate lateral movement by a threat actor."
    )
    severity = Severity.HIGH
    category = RuleCategory.LATERAL_MOVEMENT
    mitre = MITRETechnique(
        tactic="Lateral Movement",
        technique_id="T1021",
        technique_name="Remote Services",
        sub_technique_id="001",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["rdp", "windows", "remote-services"]

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[conn:CONNECTED_TO]->(dst:Host)
        WHERE conn.port = 3389
          AND conn.protocol IN ['TCP', 'RDP']
          AND src.ip <> dst.ip
          AND src.is_internal = true
          AND dst.is_internal = true
          AND conn.timestamp > datetime() - duration({seconds: $time_window})
        OPTIONAL MATCH (u:User)-[:AUTHENTICATED_TO {session_id: conn.session_id}]->(dst)
        RETURN src.ip        AS source_ip,
               src.hostname  AS source_hostname,
               dst.ip        AS target_ip,
               dst.hostname  AS target_hostname,
               conn.timestamp AS event_time,
               u.name         AS authenticated_user,
               [id(src), id(dst)] AS ids
        ORDER BY conn.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 3. SMB Admin Share Access (T1021.002)
# ---------------------------------------------------------------------------

class SMBAdminShareRule(Rule):
    """
    Detects SMB connections to administrative shares (ADMIN$, C$, IPC$).

    Attackers routinely use admin shares for file staging, tool deployment,
    and lateral movement (e.g., PsExec, Impacket's smbexec).  Connections
    from non-administrative hosts to these shares within the window are flagged.
    """

    rule_id = "LM-003"
    rule_name = "SMB Admin Share Access"
    description = (
        "A host connected to an administrative SMB share (ADMIN$, C$, IPC$) "
        "on a remote host, a common lateral movement and staging technique."
    )
    severity = Severity.HIGH
    category = RuleCategory.LATERAL_MOVEMENT
    mitre = MITRETechnique(
        tactic="Lateral Movement",
        technique_id="T1021",
        technique_name="Remote Services",
        sub_technique_id="002",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["smb", "admin-shares", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[conn:CONNECTED_TO]->(dst:Host)
        WHERE conn.port = 445
          AND conn.protocol = 'SMB'
          AND conn.share IN ['ADMIN$', 'C$', 'IPC$']
          AND src.ip <> dst.ip
          AND conn.timestamp > datetime() - duration({seconds: $time_window})
        OPTIONAL MATCH (u:User)-[:AUTHENTICATED_TO {session_id: conn.session_id}]->(dst)
        RETURN src.ip        AS source_ip,
               dst.ip        AS target_ip,
               conn.share    AS share_name,
               u.name        AS authenticated_user,
               conn.timestamp AS event_time,
               [id(src), id(dst)] AS ids
        ORDER BY conn.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 4. WMI Lateral Movement (T1047)
# ---------------------------------------------------------------------------

class WMILateralMovementRule(Rule):
    """
    Detects WMI used to spawn a process on a remote host.

    The pattern is: a WMI provider host (WmiPrvSE.exe or WmiApSrv.exe) on the
    destination spawns a child process shortly after a network connection
    arrives from the source on WMI's default port (135 / dynamic RPC).
    """

    rule_id = "LM-004"
    rule_name = "WMI Remote Process Execution"
    description = (
        "Windows Management Instrumentation (WMI) was used to spawn a process "
        "on a remote host, a technique widely used for lateral movement."
    )
    severity = Severity.HIGH
    category = RuleCategory.LATERAL_MOVEMENT
    mitre = MITRETechnique(
        tactic="Lateral Movement",
        technique_id="T1047",
        technique_name="Windows Management Instrumentation",
    )
    time_window_seconds = 180
    min_match_count = 1
    tags = ["wmi", "remote-execution", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[conn:CONNECTED_TO]->(dst:Host)
        WHERE conn.port IN [135, 49152, 49153, 49154, 49155]
          AND conn.protocol = 'TCP'
          AND src.ip <> dst.ip
          AND conn.timestamp > datetime() - duration({seconds: $time_window})
        MATCH (dst)-[:HAS_PROCESS]->(wmi:Process)
        WHERE wmi.name IN ['WmiPrvSE.exe', 'wmiprvse.exe', 'WmiApSrv.exe']
        MATCH (wmi)-[:SPAWNED]->(child:Process)
        WHERE child.start_time > conn.timestamp
          AND child.start_time <= conn.timestamp + duration({seconds: 30})
          AND NOT child.name IN ['WmiPrvSE.exe', 'wmiprvse.exe', 'conhost.exe']
        RETURN src.ip          AS source_ip,
               dst.ip          AS target_ip,
               dst.hostname    AS target_hostname,
               wmi.pid         AS wmi_pid,
               child.name      AS spawned_process,
               child.cmdline   AS command_line,
               child.start_time AS spawn_time,
               [id(src), id(dst), id(wmi), id(child)] AS ids
        ORDER BY child.start_time DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 5. SSH Key Hopping (T1021.004)
# ---------------------------------------------------------------------------

class SSHKeyHoppingRule(Rule):
    """
    Detects SSH hop chains of three or more consecutive hops.

    An attacker who has compromised a host may use SSH agent forwarding or
    stored keys to pivot through successive systems.  This rule looks for
    at least three chained SSH connections: A → B → C → D within the window.
    """

    rule_id = "LM-005"
    rule_name = "SSH Key Hopping (Multi-Hop)"
    description = (
        "A chain of three or more SSH connections was detected between internal "
        "hosts, indicating potential SSH lateral movement via key hopping or "
        "agent forwarding."
    )
    severity = Severity.HIGH
    category = RuleCategory.LATERAL_MOVEMENT
    mitre = MITRETechnique(
        tactic="Lateral Movement",
        technique_id="T1021",
        technique_name="Remote Services",
        sub_technique_id="004",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["ssh", "linux", "key-hopping"]

    def get_cypher(self) -> str:
        return """
        MATCH path = (h1:Host)-[:CONNECTED_TO {port: 22, protocol: 'SSH'}]->
                     (h2:Host)-[:CONNECTED_TO {port: 22, protocol: 'SSH'}]->
                     (h3:Host)-[:CONNECTED_TO {port: 22, protocol: 'SSH'}]->
                     (h4:Host)
        WHERE h1.ip <> h2.ip
          AND h2.ip <> h3.ip
          AND h3.ip <> h4.ip
          AND h1.is_internal = true
          AND all(rel IN relationships(path)
                  WHERE rel.timestamp > datetime() - duration({seconds: $time_window}))
        RETURN h1.ip AS hop1_ip,
               h2.ip AS hop2_ip,
               h3.ip AS hop3_ip,
               h4.ip AS hop4_ip,
               length(path) AS hop_count,
               [id(h1), id(h2), id(h3), id(h4)] AS ids
        ORDER BY hop_count DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return any(r.get("hop_count", 0) >= 3 for r in records)


# ---------------------------------------------------------------------------
# 6. PsExec / Remote Service Creation (T1569.002)
# ---------------------------------------------------------------------------

class PSExecLateralMovementRule(Rule):
    """
    Detects PsExec-style remote service creation on a target host.

    The signature pattern is: SMB connection to ADMIN$ share followed by
    Service Control Manager (services.exe) creating a short-lived service
    with a suspicious executable name within a short time on the target host.
    """

    rule_id = "LM-006"
    rule_name = "PsExec-Style Remote Service Creation"
    description = (
        "A remote host connected over SMB to the ADMIN$ share and a new "
        "transient service was subsequently created by services.exe, "
        "consistent with PsExec or similar remote execution tools."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.LATERAL_MOVEMENT
    mitre = MITRETechnique(
        tactic="Lateral Movement",
        technique_id="T1569",
        technique_name="System Services",
        sub_technique_id="002",
    )
    time_window_seconds = 120
    min_match_count = 1
    tags = ["psexec", "smb", "service-creation", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[conn:CONNECTED_TO]->(dst:Host)
        WHERE conn.port = 445
          AND conn.protocol = 'SMB'
          AND conn.share = 'ADMIN$'
          AND src.ip <> dst.ip
          AND conn.timestamp > datetime() - duration({seconds: $time_window})
        MATCH (dst)-[:HAS_PROCESS]->(scm:Process)
        WHERE scm.name IN ['services.exe', 'Services.exe']
        MATCH (scm)-[:SPAWNED]->(svc_proc:Process)
        WHERE svc_proc.start_time > conn.timestamp
          AND svc_proc.start_time <= conn.timestamp + duration({seconds: 60})
          AND (svc_proc.name =~ '(?i).*psexe.*'
               OR svc_proc.path STARTS WITH 'C:\\Windows\\Temp\\'
               OR svc_proc.path STARTS WITH 'C:\\Users\\')
        RETURN src.ip           AS source_ip,
               dst.ip           AS target_ip,
               dst.hostname     AS target_hostname,
               svc_proc.name    AS service_binary,
               svc_proc.cmdline AS command_line,
               svc_proc.path    AS binary_path,
               conn.timestamp   AS smb_connect_time,
               [id(src), id(dst), id(scm), id(svc_proc)] AS ids
        ORDER BY conn.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 7. DCOM Remote Execution (T1021.003)
# ---------------------------------------------------------------------------

class DCOMRemoteExecutionRule(Rule):
    """
    Detects DCOM-based remote code execution.

    Attackers use DCOM interfaces such as MMC20.Application, ShellWindows, and
    ShellBrowserWindow to execute commands on remote hosts without touching disk
    in the traditional PsExec way.  The graph captures outbound connections on
    port 135 (RPC endpoint mapper) followed by a child process spawned by
    svchost or dllhost on the destination.
    """

    rule_id = "LM-007"
    rule_name = "DCOM Remote Code Execution"
    description = (
        "A host initiated a DCOM connection (port 135 + dynamic RPC) to a "
        "remote host where dllhost.exe or svchost.exe subsequently spawned an "
        "unexpected child process, consistent with DCOM lateral movement."
    )
    severity = Severity.HIGH
    category = RuleCategory.LATERAL_MOVEMENT
    mitre = MITRETechnique(
        tactic="Lateral Movement",
        technique_id="T1021",
        technique_name="Remote Services",
        sub_technique_id="003",
    )
    time_window_seconds = 180
    min_match_count = 1
    tags = ["dcom", "rpc", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[conn:CONNECTED_TO]->(dst:Host)
        WHERE conn.port = 135
          AND conn.protocol = 'TCP'
          AND src.ip <> dst.ip
          AND conn.timestamp > datetime() - duration({seconds: $time_window})
        MATCH (dst)-[:HAS_PROCESS]->(host_proc:Process)
        WHERE host_proc.name IN ['dllhost.exe', 'svchost.exe', 'mmc.exe']
        MATCH (host_proc)-[:SPAWNED]->(child:Process)
        WHERE child.start_time > conn.timestamp
          AND child.start_time <= conn.timestamp + duration({seconds: 60})
          AND NOT child.name IN ['conhost.exe', 'WerFault.exe']
        RETURN src.ip           AS source_ip,
               dst.ip           AS target_ip,
               host_proc.name   AS dcom_host_process,
               child.name       AS spawned_process,
               child.cmdline    AS command_line,
               child.start_time AS spawn_time,
               [id(src), id(dst), id(host_proc), id(child)] AS ids
        ORDER BY child.start_time DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 8. Remote Scheduled Task Creation (T1053.005)
# ---------------------------------------------------------------------------

class RemoteScheduledTaskRule(Rule):
    """
    Detects scheduled tasks created remotely over the network.

    When schtasks.exe or the Task Scheduler service creates a new task and
    the creation event is preceded by a network connection from a remote host
    (via RPC/SMB on the Task Scheduler named pipe), this indicates that an
    attacker is using scheduled tasks for remote execution or persistence.
    """

    rule_id = "LM-008"
    rule_name = "Remote Scheduled Task Creation"
    description = (
        "A new scheduled task was created on a host via a remote network "
        "connection, a technique used to achieve execution and persistence "
        "on lateral movement targets."
    )
    severity = Severity.HIGH
    category = RuleCategory.LATERAL_MOVEMENT
    mitre = MITRETechnique(
        tactic="Lateral Movement",
        technique_id="T1053",
        technique_name="Scheduled Task/Job",
        sub_technique_id="005",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["scheduled-task", "windows", "remote-execution"]

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[conn:CONNECTED_TO]->(dst:Host)
        WHERE conn.port IN [135, 445]
          AND src.ip <> dst.ip
          AND conn.timestamp > datetime() - duration({seconds: $time_window})
        MATCH (dst)-[:HAS_PROCESS]->(sched:Process)
        WHERE sched.name IN ['schtasks.exe', 'taskeng.exe', 'taskhost.exe',
                              'taskhostw.exe', 'SCHTASKS.EXE']
        WHERE sched.start_time > conn.timestamp
          AND sched.start_time <= conn.timestamp + duration({seconds: 90})
          AND (sched.cmdline CONTAINS '/create' OR sched.cmdline CONTAINS '-create')
        RETURN src.ip        AS source_ip,
               dst.ip        AS target_ip,
               dst.hostname  AS target_hostname,
               sched.cmdline AS task_command,
               sched.user    AS running_as_user,
               conn.timestamp AS connection_time,
               [id(src), id(dst), id(sched)] AS ids
        ORDER BY conn.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count
