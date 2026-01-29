# MCP Security Scanner 🛡️

A comprehensive security auditing framework for the **Model Context Protocol (MCP)** ecosystem. 
It protects against two main vectors: **Application Vulnerabilities** (in MCP Servers) and **Infrastructure Exposure** (in AI Agents like Moltbot/ClawdBot).

## 🚀 Key Features

### 1. MCP Server Auditing (`check` mode)
- **🔎 Static Analysis**: Scans tool definitions, resources, and prompts for dangerous capabilities.
  - Detects RCE keywords (`exec`, `system`), dangerous file ops, and sensitive resource exposure.
- **🧠 Tool Poisoning Attack (TPA) Detection**: Identifies malicious instructions embedded in tool descriptions aimed at hijacking the LLM.
  - Flags prompt injection phrases (`Ignore previous instructions`), coercive language (`You must`), and cross-tool manipulation.
- **💥 Active Fuzzing**: Goes beyond heuristics to **confirm** vulnerabilities (requires `--fuzz`).
  - **RCE Verification**: Safely tests command injection (e.g., `; echo $((...))`).
  - **LFI Probing**: Checks for path traversal (`../../etc/passwd`).
  - **SSRF Testing**: Simulates metadata service access attempts (`http://169.254.169.254`).

### 2. Infrastructure Scanning (`moltbot` mode)
- **🤖 Moltbot/ClawdBot Discovery**: Detects exposed personal AI agent instances.
  - **TCP Port Audit**: Scans for default Gateway (18789) and Admin Console (8080).
  - **UDP mDNS Probing**: Identifies hidden services via unicast mDNS queries on port 5353 (leaking `_clawdbot-gw._tcp`).
  - **Auth Bypass Verification**: Checks if the dashboard is accessible without authentication.

## 📦 Installation

```bash
git clone https://github.com/your-username/mcp-security-scanner.git
cd mcp-security-scanner
pip install .
```

*Note: Requires Python 3.8+*

## 🛠️ Usage

The tool provides a unified CLI `mcp-scan` with two subcommands:

### Mode 1: Audit an MCP Server (`check`)

Scans a local MCP server by running its command.

**Basic Static Scan (Safe):**
```bash
mcp-scan check npx -y @modelcontextprotocol/server-filesystem /Users/demo
```

**Active Fuzzing (Vulnerability Verification):**
⚠️ *WARNING: Sends actual attack payloads. Only use in test environments.*
```bash
mcp-scan check --fuzz python labs/vulnerable_server.py
```

### Mode 2: Scan Infrastructure (`moltbot`)

Scans a target IP for exposed AI Agent services (Moltbot/ClawdBot).

```bash
mcp-scan moltbot <TARGET_IP>
```

**Example:**
```bash
mcp-scan moltbot 192.168.1.10
```
*Detects: Unauthenticated Admin Panels, Open API Gateways, and mDNS leaks.*

## 🧪 Vulnerability Labs

The project includes vulnerable servers in the `labs/` directory for testing:

1.  **Infrastructure Vulnerabilities (RCE/LFI/SSRF)**:
    ```bash
    mcp-scan check --fuzz python labs/vulnerable_server.py
    ```
2.  **Tool Poisoning Attacks (TPA)**:
    ```bash
    mcp-scan check python labs/tpa_server.py
    ```

## 📜 Disclaimer

This tool is for educational and defensive purposes only. Do not use this tool against systems you do not own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this tool.

---
Created by Arron (AI + CyberSecurity Advocate)