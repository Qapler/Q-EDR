"""
Credential Access detection rules.

Covers MITRE ATT&CK Tactic: Credential Access (TA0006).
Each rule queries the Neo4j behavioural graph for evidence of credential
theft, dumping, brute-force, or harvesting activities.

Graph node types used: Process, Host, File, User, NetworkConnection
Relationships used   : SPAWNED, ACCESSED, AUTHENTICATED_TO, HAS_PROCESS,
                       CONNECTED_TO, READS, WRITES
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
# 1. LSASS Memory Dump (T1003.001)
# ---------------------------------------------------------------------------

class LSASSDumpRule(Rule):
    """
    Detects processes accessing the LSASS process memory for credential dumping.

    Tools such as Mimikatz, ProcDump, Task Manager (as SYSTEM), and custom
    dumpers open lsass.exe with PROCESS_VM_READ access to extract plaintext
    credentials, NTLM hashes, and Kerberos tickets from memory.
    """

    rule_id = "CA-001"
    rule_name = "LSASS Memory Access (Credential Dump)"
    description = (
        "A process opened lsass.exe with memory-read access, strongly "
        "indicating an attempt to dump credentials from the Local Security "
        "Authority Subsystem Service."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.CREDENTIAL_ACCESS
    mitre = MITRETechnique(
        tactic="Credential Access",
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        sub_technique_id="001",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["lsass", "mimikatz", "credential-dump", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (attacker:Process)-[acc:ACCESSED]->(lsass:Process)
        WHERE lsass.name IN ['lsass.exe', 'LSASS.exe']
          AND acc.access_rights IN [
              'PROCESS_VM_READ', 'PROCESS_ALL_ACCESS',
              'PROCESS_DUP_HANDLE', 'PROCESS_QUERY_INFORMATION'
          ]
          AND acc.timestamp > datetime() - duration({seconds: $time_window})
          AND NOT attacker.name IN [
              'MsMpEng.exe', 'SenseCncProxy.exe', 'csrss.exe',
              'wininit.exe', 'lsm.exe', 'svchost.exe', 'SecurityHealthService.exe'
          ]
          AND NOT attacker.is_signed = true
          AND NOT (attacker.publisher CONTAINS 'Microsoft' AND attacker.is_signed = true)
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(attacker)
        RETURN attacker.pid         AS attacker_pid,
               attacker.name        AS attacker_process,
               attacker.path        AS attacker_path,
               attacker.cmdline     AS command_line,
               attacker.user        AS user,
               attacker.is_signed   AS is_signed,
               lsass.pid            AS lsass_pid,
               acc.access_rights    AS access_rights,
               acc.timestamp        AS event_time,
               h.hostname           AS hostname,
               [id(attacker), id(lsass)] AS ids
        ORDER BY acc.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 2. Kerberoasting (T1558.003)
# ---------------------------------------------------------------------------

class KerberoastingRule(Rule):
    """
    Detects Kerberoasting: bulk Kerberos TGS-REQ for service accounts.

    Kerberoasting requests TGS tickets for service accounts whose SPNs are
    registered in Active Directory.  The tickets are encrypted with the
    service account's password hash, which can then be cracked offline.
    The pattern is many TGS requests from a single source within a short window.
    """

    rule_id = "CA-002"
    rule_name = "Kerberoasting – Bulk TGS Requests"
    description = (
        "A single source made an unusually high number of Kerberos TGS "
        "requests for service principal names within a short window, "
        "indicating a Kerberoasting attack to harvest crackable ticket hashes."
    )
    severity = Severity.HIGH
    category = RuleCategory.CREDENTIAL_ACCESS
    mitre = MITRETechnique(
        tactic="Credential Access",
        technique_id="T1558",
        technique_name="Steal or Forge Kerberos Tickets",
        sub_technique_id="003",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["kerberos", "kerberoasting", "active-directory"]

    # Threshold: requests per window to constitute Kerberoasting
    TGS_THRESHOLD = 10

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[auth:AUTHENTICATED_TO]->(dc:Host)
        WHERE auth.protocol = 'Kerberos'
          AND auth.ticket_type = 'TGS'
          AND auth.spn IS NOT NULL
          AND auth.timestamp > datetime() - duration({seconds: $time_window})
        WITH src, dc,
             collect(DISTINCT auth.spn) AS requested_spns,
             count(auth) AS tgs_count,
             collect(DISTINCT id(src)) AS src_ids,
             collect(DISTINCT id(dc)) AS dc_ids
        WHERE tgs_count >= $tgs_threshold
        RETURN src.ip            AS source_ip,
               src.hostname      AS source_hostname,
               dc.ip             AS dc_ip,
               dc.hostname       AS dc_hostname,
               tgs_count         AS total_tgs_requests,
               size(requested_spns) AS unique_spns,
               requested_spns[0..10] AS sample_spns,
               src_ids + dc_ids  AS ids
        ORDER BY tgs_count DESC
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "tgs_threshold": self.TGS_THRESHOLD,
        }

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return any(r.get("total_tgs_requests", 0) >= self.TGS_THRESHOLD for r in records)


# ---------------------------------------------------------------------------
# 3. Password Spraying (T1110.003)
# ---------------------------------------------------------------------------

class PasswordSprayingRule(Rule):
    """
    Detects password spraying: many failed auth attempts from one source
    targeting many distinct accounts or hosts.

    Unlike brute-force (many attempts on one account), spraying tries one
    or few passwords against many accounts to avoid lockout policies.
    """

    rule_id = "CA-003"
    rule_name = "Password Spraying Detected"
    description = (
        "A single source IP made failed authentication attempts against "
        "multiple distinct user accounts within the detection window, "
        "consistent with a password spraying attack to avoid lockouts."
    )
    severity = Severity.HIGH
    category = RuleCategory.CREDENTIAL_ACCESS
    mitre = MITRETechnique(
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        sub_technique_id="003",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["password-spray", "brute-force", "authentication"]

    DISTINCT_ACCOUNT_THRESHOLD = 10
    FAILED_AUTH_THRESHOLD = 20

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[auth:AUTHENTICATED_TO]->(dst:Host)
        WHERE auth.success = false
          AND auth.timestamp > datetime() - duration({seconds: $time_window})
        WITH src, dst,
             collect(DISTINCT auth.username) AS targeted_accounts,
             count(auth) AS fail_count,
             collect(DISTINCT id(src)) AS src_ids,
             collect(DISTINCT id(dst)) AS dst_ids
        WHERE size(targeted_accounts) >= $account_threshold
          AND fail_count >= $fail_threshold
        RETURN src.ip                  AS source_ip,
               src.hostname            AS source_hostname,
               fail_count              AS total_failures,
               size(targeted_accounts) AS distinct_accounts,
               targeted_accounts[0..20] AS sample_accounts,
               dst.ip                  AS target_ip,
               src_ids + dst_ids       AS ids
        ORDER BY fail_count DESC
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "account_threshold": self.DISTINCT_ACCOUNT_THRESHOLD,
            "fail_threshold": self.FAILED_AUTH_THRESHOLD,
        }

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return any(
            r.get("distinct_accounts", 0) >= self.DISTINCT_ACCOUNT_THRESHOLD
            for r in records
        )


# ---------------------------------------------------------------------------
# 4. Brute Force (T1110.001)
# ---------------------------------------------------------------------------

class BruteForceRule(Rule):
    """
    Detects brute-force attacks: many failed auth attempts from one source
    against a single target account or host.

    A high volume of sequential failed authentications against the same
    account or system within a short time window is the primary indicator.
    """

    rule_id = "CA-004"
    rule_name = "Brute-Force Authentication Attack"
    description = (
        "A source IP made an excessive number of failed authentication "
        "attempts against a single target or account, indicating a brute-"
        "force attack against system credentials."
    )
    severity = Severity.HIGH
    category = RuleCategory.CREDENTIAL_ACCESS
    mitre = MITRETechnique(
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        sub_technique_id="001",
    )
    time_window_seconds = 120
    min_match_count = 1
    tags = ["brute-force", "authentication", "lockout"]

    FAIL_THRESHOLD = 50

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[auth:AUTHENTICATED_TO]->(dst:Host)
        WHERE auth.success = false
          AND auth.timestamp > datetime() - duration({seconds: $time_window})
        WITH src, dst, auth.username AS target_user,
             count(auth) AS fail_count,
             min(auth.timestamp) AS first_attempt,
             max(auth.timestamp) AS last_attempt,
             collect(DISTINCT id(src)) AS src_ids,
             collect(DISTINCT id(dst)) AS dst_ids
        WHERE fail_count >= $fail_threshold
        // Check whether the final attempt succeeded (account compromise)
        OPTIONAL MATCH (src)-[succ:AUTHENTICATED_TO]->(dst)
        WHERE succ.success = true
          AND succ.username = target_user
          AND succ.timestamp >= last_attempt
          AND succ.timestamp <= last_attempt + duration({seconds: 60})
        RETURN src.ip              AS source_ip,
               dst.ip              AS target_ip,
               dst.hostname        AS target_hostname,
               target_user         AS targeted_account,
               fail_count          AS failure_count,
               first_attempt       AS attack_start,
               last_attempt        AS last_failure,
               succ IS NOT NULL    AS eventual_success,
               src_ids + dst_ids   AS ids
        ORDER BY fail_count DESC
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "fail_threshold": self.FAIL_THRESHOLD,
        }

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return any(r.get("failure_count", 0) >= self.FAIL_THRESHOLD for r in records)


# ---------------------------------------------------------------------------
# 5. Credential Stuffing (T1110.004)
# ---------------------------------------------------------------------------

class CredentialStuffingRule(Rule):
    """
    Detects credential stuffing: authentication attempts matching the pattern
    of known-breached credential lists (low volume, high success rate across
    many distinct accounts, originating from non-interactive sources).

    Unlike password spraying, stuffing uses unique username:password pairs
    from breach databases.  The signature is a moderate number of auth attempts
    from one source with an abnormally high success rate across many accounts.
    """

    rule_id = "CA-005"
    rule_name = "Credential Stuffing Attack Pattern"
    description = (
        "A single source made authentication attempts against multiple accounts "
        "with a success rate atypical of legitimate usage, consistent with "
        "credential stuffing using breached username/password pairs."
    )
    severity = Severity.HIGH
    category = RuleCategory.CREDENTIAL_ACCESS
    mitre = MITRETechnique(
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        sub_technique_id="004",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["credential-stuffing", "breached-credentials"]

    MIN_ATTEMPTS = 20
    MIN_SUCCESS_RATE = 0.15   # 15% success rate is suspicious for bulk attempts

    def get_cypher(self) -> str:
        return """
        MATCH (src:Host)-[auth:AUTHENTICATED_TO]->(dst:Host)
        WHERE auth.timestamp > datetime() - duration({seconds: $time_window})
          AND auth.is_interactive = false
        WITH src, dst,
             count(auth) AS total_attempts,
             sum(CASE WHEN auth.success THEN 1 ELSE 0 END) AS successes,
             collect(DISTINCT auth.username) AS usernames,
             collect(DISTINCT id(src)) AS src_ids,
             collect(DISTINCT id(dst)) AS dst_ids
        WHERE total_attempts >= $min_attempts
          AND (toFloat(successes) / toFloat(total_attempts)) >= $min_success_rate
          AND size(usernames) >= 5
        RETURN src.ip                      AS source_ip,
               dst.ip                      AS target_ip,
               total_attempts              AS total_attempts,
               successes                   AS successful_logins,
               size(usernames)             AS distinct_accounts_tried,
               round(toFloat(successes) / toFloat(total_attempts) * 100, 1) AS success_rate_pct,
               usernames[0..10]            AS sample_usernames,
               src_ids + dst_ids           AS ids
        ORDER BY success_rate_pct DESC
        """

    def get_cypher_params(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window_seconds,
            "min_attempts": self.MIN_ATTEMPTS,
            "min_success_rate": self.MIN_SUCCESS_RATE,
        }

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return any(
            r.get("success_rate_pct", 0) / 100.0 >= self.MIN_SUCCESS_RATE
            and r.get("total_attempts", 0) >= self.MIN_ATTEMPTS
            for r in records
        )


# ---------------------------------------------------------------------------
# 6. SAM Database Access (T1003.002)
# ---------------------------------------------------------------------------

class SAMDatabaseAccessRule(Rule):
    """
    Detects direct access to the SAM database file for offline credential extraction.

    The Windows SAM database stores hashed credentials for local accounts.
    Direct file access to SAM (outside of SYSTEM/registry processes) or
    copying it via reg.exe or vssadmin is a strong indicator of credential dumping.
    """

    rule_id = "CA-006"
    rule_name = "SAM Database File Accessed"
    description = (
        "A process accessed or copied the Windows SAM database file, which "
        "stores local account credential hashes, indicating an attempt to "
        "extract local account password hashes offline."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.CREDENTIAL_ACCESS
    mitre = MITRETechnique(
        tactic="Credential Access",
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        sub_technique_id="002",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["sam-database", "credential-dump", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)-[acc:ACCESSED]->(f:File)
        WHERE (
            f.path IN [
                'C:\\Windows\\System32\\config\\SAM',
                'C:\\Windows\\System32\\config\\SYSTEM',
                'C:\\Windows\\System32\\config\\SECURITY'
            ]
            OR f.path =~ '(?i).*\\\\SAM$'
        )
          AND acc.timestamp > datetime() - duration({seconds: $time_window})
          AND NOT p.name IN ['smss.exe', 'csrss.exe', 'wininit.exe',
                              'lsass.exe', 'services.exe', 'svchost.exe']
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(p)
        RETURN p.pid         AS pid,
               p.name        AS process_name,
               p.path        AS process_path,
               p.cmdline     AS command_line,
               p.user        AS user,
               f.path        AS accessed_file,
               acc.access_type AS access_type,
               acc.timestamp AS event_time,
               h.hostname    AS hostname,
               [id(p), id(f)] AS ids
        ORDER BY acc.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 7. Keylogging (T1056.001)
# ---------------------------------------------------------------------------

class KeyloggingRule(Rule):
    """
    Detects processes hooking keyboard input APIs for keylogging.

    Keyloggers use Windows API hooks (SetWindowsHookEx with WH_KEYBOARD_LL /
    WH_KEYBOARD), raw input (RegisterRawInputDevices), or GetAsyncKeyState in
    polling loops to capture keystrokes.  The graph captures API call sequences
    that match these patterns.
    """

    rule_id = "CA-007"
    rule_name = "Keyboard Hook / Keylogging API Usage"
    description = (
        "A process invoked keyboard hook APIs (SetWindowsHookEx, "
        "RegisterRawInputDevices, GetAsyncKeyState) in patterns consistent "
        "with keylogging to capture user credentials and sensitive input."
    )
    severity = Severity.HIGH
    category = RuleCategory.CREDENTIAL_ACCESS
    mitre = MITRETechnique(
        tactic="Credential Access",
        technique_id="T1056",
        technique_name="Input Capture",
        sub_technique_id="001",
    )
    time_window_seconds = 300
    min_match_count = 1
    tags = ["keylogger", "input-capture", "api-hook", "windows"]

    def get_cypher(self) -> str:
        return """
        MATCH (p:Process)-[api:ACCESSED]->(hook:File)
        WHERE hook.type = 'api_call'
          AND hook.api_name IN [
              'SetWindowsHookExA', 'SetWindowsHookExW',
              'RegisterRawInputDevices', 'GetRawInputData',
              'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState'
          ]
          AND api.hook_type IN ['WH_KEYBOARD', 'WH_KEYBOARD_LL', 'RAW_INPUT', 'POLLING']
          AND api.timestamp > datetime() - duration({seconds: $time_window})
          AND NOT p.name IN [
              'explorer.exe', 'SearchHost.exe', 'TextInputHost.exe',
              'osk.exe', 'tabtip.exe', 'ctfmon.exe', 'RawInput.exe'
          ]
          AND NOT p.is_signed = true
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(p)
        RETURN p.pid         AS pid,
               p.name        AS process_name,
               p.path        AS process_path,
               p.user        AS user,
               hook.api_name AS hooked_api,
               api.hook_type AS hook_type,
               api.timestamp AS event_time,
               h.hostname    AS hostname,
               [id(p)] AS ids
        ORDER BY api.timestamp DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count


# ---------------------------------------------------------------------------
# 8. NTDS.dit Dump (T1003.003)
# ---------------------------------------------------------------------------

class NTDSDumpRule(Rule):
    """
    Detects access to the NTDS.dit Active Directory database for credential extraction.

    NTDS.dit contains all domain user credentials.  Attackers access it via:
    1. Direct file copy (requires VSS or special privileges).
    2. Volume Shadow Copy creation followed by ntds.dit access from the shadow.
    3. ntdsutil.exe snapshot commands.
    4. vssadmin / wbadmin with paths containing 'ntds'.
    """

    rule_id = "CA-008"
    rule_name = "NTDS.dit Active Directory Database Dump"
    description = (
        "The Active Directory NTDS.dit database was accessed or copied, "
        "either directly or through a Volume Shadow Copy, indicating an "
        "attempt to extract all domain credential hashes."
    )
    severity = Severity.CRITICAL
    category = RuleCategory.CREDENTIAL_ACCESS
    mitre = MITRETechnique(
        tactic="Credential Access",
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        sub_technique_id="003",
    )
    time_window_seconds = 600
    min_match_count = 1
    tags = ["ntds", "active-directory", "domain-credentials", "vss"]

    def get_cypher(self) -> str:
        return """
        // Pattern 1: Direct or VSS-based NTDS.dit file access
        MATCH (p:Process)-[acc:ACCESSED]->(f:File)
        WHERE (
            f.path =~ '(?i).*ntds\\.dit$'
            OR f.path =~ '(?i).*HarddiskVolumeShadowCopy.*ntds.*'
        )
          AND acc.timestamp > datetime() - duration({seconds: $time_window})
          AND NOT p.name IN ['ntds.exe', 'lsass.exe', 'svchost.exe',
                              'dsamain.exe', 'dfsr.exe']
        OPTIONAL MATCH (h:Host)-[:HAS_PROCESS]->(p)

        RETURN 'direct_access'   AS detection_type,
               p.pid             AS pid,
               p.name            AS process_name,
               p.cmdline         AS command_line,
               p.user            AS user,
               f.path            AS ntds_path,
               acc.timestamp     AS event_time,
               h.hostname        AS hostname,
               [id(p), id(f)]    AS ids

        UNION ALL

        // Pattern 2: ntdsutil / vssadmin / wbadmin with ntds-related args
        MATCH (p2:Process)
        WHERE p2.name IN ['ntdsutil.exe', 'vssadmin.exe', 'wbadmin.exe',
                           'diskshadow.exe', 'esentutl.exe']
          AND (
              p2.cmdline =~ '(?i).*ntds.*'
              OR p2.cmdline =~ '(?i).*snapshot.*'
              OR p2.cmdline CONTAINS 'ifm'
          )
          AND p2.start_time > datetime() - duration({seconds: $time_window})
        OPTIONAL MATCH (h2:Host)-[:HAS_PROCESS]->(p2)

        RETURN 'tool_invocation' AS detection_type,
               p2.pid            AS pid,
               p2.name           AS process_name,
               p2.cmdline        AS command_line,
               p2.user           AS user,
               null              AS ntds_path,
               p2.start_time     AS event_time,
               h2.hostname       AS hostname,
               [id(p2)]          AS ids
        ORDER BY event_time DESC
        """

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        return len(records) >= self.min_match_count
