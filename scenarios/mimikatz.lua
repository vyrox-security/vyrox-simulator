--[[
    Mimikatz Credential Dumping Attack Simulation

    This scenario simulates a Mimikatz credential dumping attack, which is one of
    the most common techniques used by adversaries to extract credentials from
    compromised Windows systems.

    MITRE ATT&CK Mapping:
    - Tactic: Credential Access
    - Technique: T1003 - OS Credential Dumping
    - Sub-technique: T1003.001 - LSASS Memory

    Scenario Details:
    - Target: Windows desktop endpoint (win-desktop-01)
    - User context: CORP\jsmith (regular domain user)
    - Process: mimikatz.exe with common dump commands
    - Severity: CRITICAL (requires immediate attention)

    Detection Context:
    - Mimikatz is a well-known hacking tool
    - The command line "sekurlsa::logonpasswords" is highly indicative
    - Should trigger heuristic rules with high confidence
    - LLM triage should confirm based on process name and cmdline

    Payload Format:
    This Lua script returns a table compatible with the Vyrox ingestion service.
    The payload mimics the CrowdStrike Falcon event format for realistic testing.

    Usage:
        python simulate.py mimikatz --url http://localhost:8001
--]]

--[[
    Scenario Definition Table

    This table contains all the information needed to generate a test alert.
    It defines the attack scenario metadata and the actual alert payload.
--]]
local scenario = {
    -- Human-readable scenario name (used in logs and display)
    name = "mimikatz",

    -- EDR vendor format (crowdstrike or sentinelone)
    -- Determines which webhook endpoint and authentication method to use
    source = "crowdstrike",

    -- Initial severity assessment (may be overridden by triage)
    -- CRITICAL indicates this is a high-priority security event
    severity = "CRITICAL",

    -- MITRE ATT&CK tactic (high-level attack category)
    tactic = "Credential Access",

    -- MITRE ATT&CK technique ID
    technique = "T1003",

    -- The actual alert payload that will be sent to the ingestion service
    -- This mimics the CrowdStrike Falcon sensor event format
    payload = {
        -- Unique detection identifier (timestamp-based for uniqueness)
        detect_id = "cs-" .. os.time(),

        -- Tenant identifier for multi-tenancy testing
        -- "default-tenant" maps to the default tenant in Vyrox
        customer_id = "default-tenant",

        -- Event timestamp (Unix time)
        timestamp = os.time(),

        -- Endpoint information where the event was detected
        sensor = {
            hostname = "win-desktop-01"
        },

        -- Process that triggered the detection
        -- Includes user context, file name, command line, and hash
        process = {
            -- User account that was running the process
            -- "CORP\jsmith" indicates a domain user context
            user_name = "CORP\\jsmith",

            -- Executable name (mimikatz.exe is a well-known tool)
            file_name = "mimikatz.exe",

            -- Full command line that was executed
            -- This specific command dumps credentials from LSASS
            command_line = "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",

            -- SHA256 hash of the executable
            -- In production, this would be the actual file hash
            sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        },

        -- MITRE ATT&CK mapping (repeated for payload completeness)
        tactic = "Credential Access",
        technique = "T1003",

        -- Vendor severity assessment
        severity = "CRITICAL"
    }
}

-- Return the scenario table to the Python script
-- The simulate.py script will serialize this and send to Vyrox
return scenario