# MCP Security Scanner 🛡️

A heuristic-based security scanning tool for **Model Context Protocol (MCP)** servers. It helps developers and security researchers identify over-privileged tools, sensitive resource exposure, and potential attack surfaces in MCP implementations.

## Key Features

- **Dynamic Capability Enumeration**: Connects to any MCP server via Stdio and lists all tools, resources, and prompts.
- **Risk Heuristics**: 
  - 🔴 **RCE Detection**: Identifies keywords like `exec`, `shell`, `system`.
  - 🟠 **Data Modification**: Flags tools that can `delete`, `write`, or `modify` data.
  - 🔴 **Sensitive Exposure**: Detects root directory (`file:///`) and sensitive path (`/etc`, `.env`) exposure.
- **Automated Reporting**: Generates a clean security posture report with risk levels.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Scan a local MCP server by passing its startup command:

```bash
python scanner.py <command> [args...]
```

### Example: Scan a Filesystem Server
```bash
python scanner.py npx -y @modelcontextprotocol/server-filesystem /Users/yourname/documents
```

## Why it matters?
As AI Agents gain more autonomy through the MCP protocol, the security of MCP servers becomes the last line of defense. This tool aims to bring "Security Validation" to the burgeoning AI Agent ecosystem.

---
Created by Arron (AI + CyberSecurity Advocate)
