# MCP Security Scanner 🛡️

A comprehensive security auditing and fuzzing tool for **Model Context Protocol (MCP)** servers. 
Unlike passive scanners, this tool can **actively verify** vulnerabilities like RCE, LFI, and SSRF by sending safe proof-of-concept payloads.

## Key Features

- **🔎 Static Metadata Analysis**: Scans tool definitions, resources, and prompts for dangerous capabilities using heuristic patterns.
  - Detects RCE keywords (`exec`, `system`)
  - Identifies dangerous file operations (`write`, `delete`)
  - Flags sensitive resource exposure (`file:///`, `.env`)
  
- **💥 Active Fuzzing (New!)**: Goes beyond heuristics to **confirm** vulnerabilities.
  - **RCE Verification**: Safely tests command injection vectors (e.g., `; echo VULN`).
  - **LFI Probing**: Checks for path traversal in file reading tools (`../../etc/passwd`).
  - **SSRF Testing**: Simulates metadata service access attempts (`http://169.254.169.254`).

- **🛡️ Human-in-the-Loop (HITL) Check**: Verifies if high-risk tools have `isUserApprovalRequired` enabled.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### 1. Basic Scan (Static Analysis)
Connects to the server and audits its metadata. Safe to run anywhere.

```bash
python scanner.py <command> [args...]
```

**Example:**
```bash
python scanner.py npx -y @modelcontextprotocol/server-filesystem /Users/yourname/documents
```

### 2. Active Fuzzing (Vulnerability Verification)
⚠️ **WARNING**: This mode sends actual attack payloads to the server. Use only in test environments.

Add the `--fuzz` flag:

```bash
python scanner.py --fuzz python vulnerable_server.py
```

## Vulnerability Lab

Includes a `vulnerable_server.py` to demonstrate detection capabilities.

1. **Start the Vulnerable Server:**
   ```bash
   python scanner.py --fuzz python vulnerable_server.py
   ```

2. **Expect Findings:**
   - **RCE**: Command Injection in `execute_shell_command`
   - **LFI**: Path Traversal in `read_system_file`
   - **SSRF**: Cloud Metadata access in `fetch_url`

## Disclaimer

This tool is for educational and defensive purposes only. Do not use this tool against systems you do not own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this tool.

---
Created by Arron (AI + CyberSecurity Advocate)