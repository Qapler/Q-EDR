"""
Persistence detection rules.

Covers MITRE ATT&CK Tactic: Persistence (TA0003).
Each rule queries the Neo4j behavioural graph for evidence of an attacker
establishing mechanisms that survive system reboots, user logouts, or
credential changes.

Graph node types used: Process, Host, File, User, Service, RegistryKey
Relationships used   : SPAWNED, CREATED, MODIFIED, WRITES, HAS_PROCESS,
                       OWNS, ACCESSED, READS
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
# 1. Scheduled Task Persistence (T1053.005)
# ---------------------------------------------------------------------------

class ScheduledTaskPersistenceRule(Rule):
    """
    Detects new scheduled tasks with suspicious command patterns.

    Legitimate scheduled tasks are typically created by installers or system
    processes from standard paths.  This rule flags tasks created by user-land
    processes with commands pointing to temp directories, encoded PowerShell,
    or known LOLBin patterns.
    """

    rule_id = "PERS-001"
    rule_name = "Suspicious Scheduled Task Created"
    description = (
        "A new scheduled task was created with a command line that references "
        "a suspicious path, encoded payload, or known living-off-the-land "
        "binary, indicating persistence via the Task Scheduler."
    )
    severity = Severity.HIGH
    category = RuleCategory.PERSISTENCE
    mitre = MITRETechnique(
        tactic="Persistence",
        technique_id="T1053",
        technique_name="Scheduled Task/Job",
        sub_technique_id="005",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["scheduled-task", "windows", "lolbin"]

    def get_cypher(self) -> str:
        return """
        MATCH (creator:Process)-[cr:CREATED]->(task:File)
        WHERE task.type = 'scheduled_task'
          AND cr.timestamp > datetime() - duration({seconds: $time_window})
          AND (
              task.command CONTAINS '%TEMP%'
              OR task.command CONTAINS '%APPDATA%'
              OR task.command CONTAINS 'Temp\\'
              OR task.command CONTAINS '-EncodedCommand'
              OR task.command CONTAINS '-enc '
              OR task.command CONTAINS 'powershell -w hidden'
              OR task.command CONTAINS 'cmd /c'
              OR task.command =~ '(?i).*\\\\Users\\\\.*\\\\AppData\\\\.*'
              OR task.command =~ '(?i).*wscript.*\\.vbs.*'
              OR task.command =~ '(?i).*mshta.*'
              OR task.command =~ '(?i).*regsvr32.*'
          )
          AND NOT creator.name IN ['MsiExec.exe', 'msiexec.exe',
                                    'TrustedInstaller.exe', 'svchost.exe']
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(creator)
        RETURN creator.name    AS creator_process,
               creator.user    AS creator_user,
               task.name       AS task_name,
               task.command    AS task_command,
               task.trigger    AS task_trigger,
               task.run_as     AS run_as_user,
               cr.timestamp    AS creation_time,
               h.hostname      AS hostname,
               [id(creator), id(task)] AS ids
        ORDER BY cr.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 2. Registry Run Key (T1547.001)
# ---------------------------------------------------------------------------

class RegistryRunKeyRule(Rule):
    """
    Detects new registry run key entries pointing to non-standard paths.

    Attackers add entries under HKLM/HKCU Run keys to ensure their payload
    executes on every user logon.  This rule flags new entries where the
    target executable is outside standard system directories.
    """

    rule_id = "PERS-002"
    rule_name = "Suspicious Registry Run Key Created"
    description = (
        "A new registry run key entry was created pointing to a non-standard "
        "executable path, a classic persistence mechanism for malware survival "
        "across reboots and logons."
    )
    severity = Severity.HIGH
    category = RuleCategory.PERSISTENCE
    mitre = MITRETechnique(
        tactic="Persistence",
        technique_id="T1547",
        technique_name="Boot or Logon Autostart Execution",
        sub_technique_id="001",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["registry", "run-key", "autostart", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)-[mod:MODIFIED]->(reg:RegistryKey)
        WHERE reg.key_path IN [
            'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
            'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce',
            'HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
            'HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce',
            'HKLM\\\\SOFTWARE\\\\WOW6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'
        ]
          AND mod.operation IN ['SetValue', 'CreateKey']
          AND mod.timestamp > datetime() - duration({seconds: $time_window})
          AND NOT (
              reg.value_data STARTS WITH 'C:\\\\Windows\\\\System32\\\\'
              OR reg.value_data STARTS WITH 'C:\\\\Windows\\\\SysWOW64\\\\'
              OR reg.value_data STARTS WITH 'C:\\\\Program Files\\\\'
              OR reg.value_data STARTS WITH 'C:\\\\Program Files (x86)\\\\'
          )
          AND NOT p.name IN ['MsiExec.exe', 'msiexec.exe', 'TrustedInstaller.exe']
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(p)
        RETURN p.name          AS modifier_process,
               p.user          AS modifier_user,
               reg.key_path    AS registry_key,
               reg.value_name  AS value_name,
               reg.value_data  AS value_data,
               mod.timestamp   AS modification_time,
               h.hostname      AS hostname,
               [id(p), id(reg)] AS ids
        ORDER BY mod.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 3. Web Shell Creation (T1505.003)
# ---------------------------------------------------------------------------

class WebShellCreationRule(Rule):
    """
    Detects web server processes creating script files inside the web root.

    A web shell is a script uploaded by an attacker to a web server that
    provides command execution via HTTP.  The indicator is a web server process
    (Apache, nginx, IIS, Tomcat) creating .php, .asp, .aspx, .jsp, or .py
    files in a web-accessible directory.
    """

    rule_id = "PERS-003"
    rule_name = "Web Shell Created by Web Server Process"
    description = (
        "A web server process created a new script file in the web root "
        "directory, strongly indicating web shell installation for persistent "
        "remote access."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.PERSISTENCE
    mitre = MITRETechnique(
        tactic="Persistence",
        technique_id="T1505",
        technique_name="Server Software Component",
        sub_technique_id="003",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["webshell", "web-server", "script-file"]

    def get_cypher(self) -> str:
        return """
        MATCH (web:Process)-[cr:CREATED]->(f:File)
        WHERE web.name IN [
            'httpd', 'apache2', 'nginx', 'w3wp.exe', 'tomcat',
            'php-fpm', 'python', 'node', 'ruby', 'java'
        ]
          AND cr.timestamp > datetime() - duration({seconds: $time_window})
          AND (
              f.extension IN ['php', 'asp', 'aspx', 'jsp', 'jspx', 'cfm', 'py', 'rb']
              OR f.name =~ '(?i).*(shell|cmd|exec|eval|backdoor|c99|r57).*'
          )
          AND (
              f.path CONTAINS '/var/www/'
              OR f.path CONTAINS '/srv/www/'
              OR f.path CONTAINS '/htdocs/'
              OR f.path CONTAINS '\\\\inetpub\\\\wwwroot\\\\'
              OR f.path CONTAINS '\\\\WebRoot\\\\'
          )
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(web)
        RETURN web.pid       AS web_server_pid,
               web.name      AS web_server_process,
               f.path        AS webshell_path,
               f.name        AS webshell_filename,
               f.size_bytes  AS file_size,
               cr.timestamp  AS creation_time,
               h.hostname    AS hostname,
               h.ip          AS host_ip,
               [id(web), id(f)] AS ids
        ORDER BY cr.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 4. Startup Folder Item Drop (T1547.001)
# ---------------------------------------------------------------------------

class StartupFolderItemRule(Rule):
    """
    Detects files dropped into Windows or Linux startup/autostart directories.

    The Windows Startup folder causes files to be executed at user logon.
    On Linux, /etc/profile.d, ~/.config/autostart, or XDG autostart paths
    are monitored.  Files created in these locations by non-standard processes
    are flagged.
    """

    rule_id = "PERS-004"
    rule_name = "File Dropped in Startup Folder"
    description = (
        "A file was created in a user or system startup folder by an "
        "unexpected process, indicating persistence via autostart execution "
        "on user logon or system boot."
    )
    severity = Severity.HIGH
    category = RuleCategory.PERSISTENCE
    mitre = MITRETechnique(
        tactic="Persistence",
        technique_id="T1547",
        technique_name="Boot or Logon Autostart Execution",
        sub_technique_id="001",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["startup-folder", "autostart", "windows", "linux"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)-[cr:CREATED]->(f:File)
        WHERE cr.timestamp > datetime() - duration({seconds: $time_window})
          AND (
              f.path CONTAINS '\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\'
              OR f.path CONTAINS '\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp\\\\'
              OR f.path CONTAINS '/etc/profile.d/'
              OR f.path CONTAINS '/etc/init.d/'
              OR f.path CONTAINS '/etc/rc.local'
              OR f.path CONTAINS '/.config/autostart/'
              OR f.path CONTAINS '/Library/LaunchAgents/'
              OR f.path CONTAINS '/Library/LaunchDaemons/'
          )
          AND NOT p.name IN ['explorer.exe', 'MsiExec.exe', 'msiexec.exe',
                              'TrustedInstaller.exe', 'wusa.exe', 'dpkg', 'apt', 'rpm']
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(p)
        RETURN p.name        AS creator_process,
               p.user        AS creator_user,
               p.cmdline     AS creator_cmdline,
               f.path        AS startup_item_path,
               f.name        AS filename,
               f.hash_sha256 AS file_hash,
               cr.timestamp  AS drop_time,
               h.hostname    AS hostname,
               [id(p), id(f)] AS ids
        ORDER BY cr.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 5. Account Manipulation (T1098)
# ---------------------------------------------------------------------------

class AccountManipulationRule(Rule):
    """
    Detects a new privileged account created and then immediately used.

    Attackers create backdoor admin accounts for persistent access.  The
    indicator is account creation (net user /add + net localgroup) followed
    by an authentication event from that account within the time window.
    """

    rule_id = "PERS-005"
    rule_name = "Backdoor Admin Account Created and Used"
    description = (
        "A new local administrator account was created and subsequently "
        "authenticated within the detection window, indicating a backdoor "
        "account planted for persistent privileged access."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.PERSISTENCE
    mitre = MITRETechnique(
        tactic="Persistence",
        technique_id="T1098",
        technique_name="Account Manipulation",
    )
    time_window_seconds = 3600
    min_match_count = 1
    tags = ["account-creation", "backdoor-user", "windows", "linux"]

    def get_cypher(self) -> str:
        return """
        MATCH (creator:Process)-[cr:CREATED]->(u:User)
        WHERE u.is_admin = true
          AND cr.timestamp > datetime() - duration({seconds: $time_window})
          AND creator.name IN ['net.exe', 'net1.exe', 'useradd', 'adduser',
                                'New-LocalUser', 'powershell.exe']
        MATCH (u)-[auth:AUTHENTICATED_TO]->(h:Host)
        WHERE auth.timestamp > cr.timestamp
          AND auth.timestamp <= cr.timestamp + duration({seconds: $time_window})
        OPTIONAL MATCH (src:Host)-[:CONNECTED_TO {session_id: auth.session_id}]->(h)
        RETURN u.name          AS new_account,
               creator.name   AS creation_process,
               creator.user   AS created_by,
               cr.timestamp   AS account_created_at,
               auth.timestamp AS first_auth_at,
               h.hostname     AS auth_target_host,
               src.ip         AS auth_source_ip,
               [id(creator), id(u), id(h)] AS ids
        ORDER BY cr.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 6. Cron Job Persistence (T1053.003)
# ---------------------------------------------------------------------------

class CronJobPersistenceRule(Rule):
    """
    Detects suspicious cron job additions used for persistence.

    Attackers add cron jobs that download and execute payloads periodically.
    This rule flags cron entries written by non-root/non-installer processes
    that contain URLs, curl/wget, base64 decode, or pipe-to-bash patterns.
    """

    rule_id = "PERS-006"
    rule_name = "Suspicious Cron Job Added"
    description = (
        "A cron job entry was added containing suspicious commands such as "
        "curl/wget with piped execution, base64 decode, or reverse shell "
        "patterns, indicating persistence via scheduled job."
    )
    severity = Severity.HIGH
    category = RuleCategory.PERSISTENCE
    mitre = MITRETechnique(
        tactic="Persistence",
        technique_id="T1053",
        technique_name="Scheduled Task/Job",
        sub_technique_id="003",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["cron", "linux", "scheduled-job"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)-[w:WRITES]->(f:File)
        WHERE f.path IN ['/etc/crontab', '/var/spool/cron/crontabs/root']
           OR f.path STARTS WITH '/etc/cron.d/'
           OR f.path STARTS WITH '/etc/cron.hourly/'
           OR f.path STARTS WITH '/etc/cron.daily/'
           OR f.path STARTS WITH '/var/spool/cron/'
          AND w.timestamp > datetime() - duration({seconds: $time_window})
          AND (
              w.content CONTAINS 'curl '
              OR w.content CONTAINS 'wget '
              OR w.content CONTAINS 'bash -i'
              OR w.content CONTAINS '/dev/tcp/'
              OR w.content CONTAINS 'base64 -d'
              OR w.content CONTAINS 'base64 --decode'
              OR w.content CONTAINS 'python -c'
              OR w.content CONTAINS 'perl -e'
              OR w.content CONTAINS 'nc -e'
              OR w.content =~ '.*\\| *bash.*'
              OR w.content =~ '.*\\| *sh.*'
          )
          AND NOT p.name IN ['cron', 'crond', 'anacron', 'fcron']
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(p)
        RETURN p.name        AS writer_process,
               p.user        AS writer_user,
               f.path        AS cron_file,
               w.content     AS cron_entry,
               w.timestamp   AS write_time,
               h.hostname    AS hostname,
               [id(p), id(f)] AS ids
        ORDER BY w.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 7. BITS Job Persistence (T1197)
# ---------------------------------------------------------------------------

class BITSJobPersistenceRule(Rule):
    """
    Detects BITS (Background Intelligent Transfer Service) jobs used for
    download-and-execute persistence.

    Attackers use bitsadmin.exe or PowerShell's BITS module to create jobs
    that download a payload and execute a program when complete.  The graph
    captures bitsadmin process creation and subsequent file drops or
    process spawns triggered by the BITS service.
    """

    rule_id = "PERS-007"
    rule_name = "BITS Job Download-and-Execute Persistence"
    description = (
        "A BITS job was created to download a remote file and trigger "
        "execution upon completion, a technique used to achieve download-and-"
        "execute persistence that bypasses many security controls."
    )
    severity = Severity.HIGH
    category = RuleCategory.PERSISTENCE
    mitre = MITRETechnique(
        tactic="Persistence",
        technique_id="T1197",
        technique_name="BITS Jobs",
    )
    time_window_seconds = 1800
    min_match_count = 1
    tags = ["bits", "windows", "download-execute"]

    def get_cypher(self) -> str:
        return """
        MATCH (bits_creator:Process)-[cr:CREATED]->(bits_job:File)
        WHERE bits_job.type = 'bits_job'
          AND cr.timestamp > datetime() - duration({seconds: $time_window})
          AND (
              bits_creator.name IN ['bitsadmin.exe', 'powershell.exe', 'pwsh.exe']
              AND (
                  bits_creator.cmdline CONTAINS 'AddFile'
                  OR bits_creator.cmdline CONTAINS '/AddFile'
                  OR bits_creator.cmdline CONTAINS 'SetNotifyCmdLine'
                  OR bits_creator.cmdline CONTAINS 'Start-BitsTransfer'
              )
          )
          AND bits_job.remote_url IS NOT NULL
          AND bits_job.notify_cmdline IS NOT NULL
        OPTIONAL MATCH (bits_svc:Process {name: 'svchost.exe'})-[:SPAWNED]->(payload:Process)
        WHERE payload.start_time > cr.timestamp
          AND payload.start_time <= cr.timestamp + duration({seconds: $time_window})
          AND payload.cmdline CONTAINS bits_job.local_path
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(bits_creator)
        RETURN bits_creator.name     AS creator_process,
               bits_creator.user     AS creator_user,
               bits_job.remote_url   AS download_url,
               bits_job.local_path   AS local_destination,
               bits_job.notify_cmdline AS execute_on_complete,
               cr.timestamp          AS job_creation_time,
               payload.name          AS executed_payload,
               h.hostname            AS hostname,
               [id(bits_creator), id(bits_job)] +
               CASE WHEN payload IS NOT NULL THEN [id(payload)] ELSE [] END AS ids
        ORDER BY cr.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 8. DLL Side-Loading (T1574.002)
# ---------------------------------------------------------------------------

class DLLSideloadingRule(Rule):
    """
    Detects DLL side-loading: a malicious DLL placed in the same directory
    as a legitimate executable, causing Windows to load it instead of the
    intended system DLL.

    The pattern: a non-standard process drops a .dll file into the directory
    of a signed/trusted executable (e.g., AV software, Microsoft tools) within
    the time window, followed by that executable loading the DLL.
    """

    rule_id = "PERS-008"
    rule_name = "DLL Side-Loading Detected"
    description = (
        "A DLL was placed in the same directory as a legitimate executable "
        "by an unexpected process, and the executable subsequently loaded "
        "that DLL, indicating a DLL side-loading persistence or execution "
        "technique."
    )
    severity = Severity.HIGH
    category = RuleCategory.PERSISTENCE
    mitre = MITRETechnique(
        tactic="Persistence",
        technique_id="T1574",
        technique_name="Hijack Execution Flow",
        sub_technique_id="002",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["dll-sideload", "dll-hijack", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (dropper:Process)-[cr:CREATED]->(dll:File)
        WHERE dll.extension = 'dll'
          AND cr.timestamp > datetime() - duration({seconds: $time_window})
          AND NOT dropper.name IN ['MsiExec.exe', 'msiexec.exe',
                                    'TrustedInstaller.exe', 'wusa.exe',
                                    'setup.exe', 'install.exe']
          AND NOT dll.path STARTS WITH 'C:\\Windows\\'
          AND NOT dll.path STARTS WITH 'C:\\Program Files\\'
        MATCH (legit:Process)-[load:ACCESSED]->(dll)
        WHERE load.access_type = 'LoadLibrary'
          AND load.timestamp > cr.timestamp
          AND load.timestamp <= cr.timestamp + duration({seconds: $time_window})
          AND legit.is_signed = true
          AND legit.name <> dropper.name
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(dropper)
        RETURN dropper.name   AS dropper_process,
               dropper.user   AS dropper_user,
               dll.path       AS dll_path,
               dll.hash_sha256 AS dll_hash,
               legit.name     AS loading_process,
               legit.path     AS loading_process_path,
               load.timestamp AS load_time,
               h.hostname     AS hostname,
               [id(dropper), id(dll), id(legit)] AS ids
        ORDER BY load.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count
