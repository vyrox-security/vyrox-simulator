-- SentinelOne Lateral Movement Simulation Scenario
-- Version: 1.0

local scenario = {
    name = "lateral_movement",
    source = "sentinelone",
    severity = "HIGH",
    tactic = "Lateral Movement",
    technique = "T1021",
    payload = {
        id = "s1-" .. os.time(),
        accountId = "default-tenant",
        createdAt = os.time(),
        agentRealtimeInfo = {
            computerName = "mac-laptop-02"
        },
        fileFullName = "admin",
        processName = "ssh",
        commandLine = "ssh -i id_rsa root@10.0.0.5 'cat /etc/shadow'",
        fileContentHash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        mitreTactic = "Lateral Movement",
        mitreTechnique = "T1021",
        severity = "HIGH"
    }
}

return scenario
