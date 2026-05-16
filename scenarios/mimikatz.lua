-- Mimikatz Attack Simulation Scenario
-- Version: 1.0

local scenario = {
    name = "mimikatz",
    source = "crowdstrike",
    severity = "CRITICAL",
    tactic = "Credential Access",
    technique = "T1003",
    payload = {
        detect_id = "cs-" .. os.time(),
        customer_id = "default-tenant",
        timestamp = os.time(),
        sensor = {
            hostname = "win-desktop-01"
        },
        process = {
            user_name = "CORP\\jsmith",
            file_name = "mimikatz.exe",
            command_line = "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
            sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        },
        tactic = "Credential Access",
        technique = "T1003",
        severity = "CRITICAL"
    }
}

return scenario
