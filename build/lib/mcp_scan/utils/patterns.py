# Risk Patterns Configuration

RISK_PATTERNS = {
    "CRITICAL": [
        r"exec", r"shell", r"bash", r"cmd", r"system", r"run_command",  # RCE
        r"eval", r"python_code", r"script",                             # Code Execution
        r"delete", r"remove", r"drop", r"truncate",                     # Destructive
        r"sudo", r"chmod", r"chown"                                     # Privilege Escalation
    ],
    "HIGH": [
        r"curl", r"wget", r"fetch", r"request", r"http_client",         # SSRF
        r"write", r"upload", r"modify", r"update",                      # Data Tampering
        r"api_key", r"token", r"secret", r"password"                    # Credential Leakage
    ],
    "MEDIUM": [
        r"file_system", r"fs", r"read_file", r"read",                   # File System
        r"sql", r"query", r"database",                                  # Database
        r"scrape", r"crawl", r"browse", r"summarize_url"                # Indirect Injection
    ],
    "LOW": [
        r"get", r"search", r"list"                                      # Info Leakage
    ],
    "POISON": [
        r"ignore previous instructions", r"system override",            # Jailbreak
        r"system prompt", r"priority command", r"debugging requirement",
        r"always call this tool", r"forward all data",                  # Forced Action
        r"you must", r"override safety",
        r"do not mention", r"don't mention", r"implementation detail",  # Secrecy
        r"side effect", r"application will crash", r"data will be lost" # Coercion
    ]
}

MOLTBOT_SIGNATURES = [
    "<title>Moltbot", 
    "<title>ClawdBot", 
    "content=\"Moltbot\"",
    "Moltbot Dashboard"
]

MOLTBOT_PORTS = [8080, 18789, 3000]

MOLTBOT_MDNS_SIGNATURES = [
    "clawdbot",
    "moltbot"
]

