import re
import json
from typing import Any, List, Dict
from mcp_scan.utils.patterns import RISK_PATTERNS

class StaticAnalyzer:
    def __init__(self):
        self.findings = []
        self.tools_to_fuzz = [] # List of (tool_name, tool_schema, risk_category)

    def add_finding(self, level: str, title: str, description: str, raw_data: Any = None):
        self.findings.append({
            "level": level,
            "title": title,
            "description": description,
            "raw": raw_data
        })

    def scan_tool(self, tool: Any):
        """Scans a single tool definition for security risks."""
        name = tool.name
        desc = tool.description or ""
        input_schema = tool.inputSchema
        
        requires_approval = getattr(tool, "isUserApprovalRequired", False)
        if not requires_approval and hasattr(tool, "model_dump"):
             requires_approval = tool.model_dump().get("isUserApprovalRequired", False)

        combined_text = f"{name} {desc}".lower()
        
        found_risk = False
        
        # 0. Tool Poisoning Detection (TPA)
        for pattern in RISK_PATTERNS["POISON"]:
             if re.search(pattern, combined_text):
                self.add_finding(
                    "HIGH",
                    "Tool Poisoning Attack Detected (TPA)",
                    f"Tool '{name}' contains manipulative instructions in its description: '{pattern}'. This may hijack the Agent's behavior.",
                    {"pattern": pattern, "snippet": desc[:100]}
                )
                found_risk = True
                break

        # Check for unusually long descriptions (Obfuscation)
        if len(desc) > 500:
             self.add_finding(
                "MEDIUM",
                "Suspiciously Long Description",
                f"Tool '{name}' has a description length of {len(desc)} chars. Malicious instructions are often hidden in long texts.",
                {"length": len(desc)}
            )

        for level, patterns in RISK_PATTERNS.items():
            if level == "POISON": continue # Handled above
            for pattern in patterns:
                if re.search(pattern, combined_text):
                    risk_title = f"Detected Risky Capability: {pattern}"
                    risk_desc = f"Tool '{name}' implies dangerous operations."
                    risk_category = "General"
                    
                    if level == "CRITICAL" and pattern in [r"exec", r"shell", r"cmd", r"system", r"bash", r"run_command"]:
                        risk_category = "RCE"
                        if "read" in name or "file" in name:
                            risk_category = "LFI"
                    elif level == "HIGH" and pattern in [r"curl", r"wget", r"fetch", r"request"]:
                        risk_title = "Potential SSRF Vector (OWASP LLM06)"
                        risk_desc = f"Tool '{name}' can access network resources."
                        risk_category = "SSRF"
                    elif level == "MEDIUM" and pattern in [r"file_system", r"fs", r"read", r"read_file"]:
                        risk_category = "LFI" # Local File Inclusion / Path Traversal

                    # HITL Check
                    if requires_approval:
                        final_level = "LOW"
                        risk_title = f"[MITIGATED] {risk_title}"
                        risk_desc += " ✅ Mitigation: 'isUserApprovalRequired' is enabled."
                    else:
                        final_level = level
                        if level in ["CRITICAL", "HIGH", "MEDIUM"]:
                            risk_title += " (HITL Bypass)"
                            risk_desc += " ❌ WARNING: 'isUserApprovalRequired' is MISSING/FALSE."
                            
                            # Add to Fuzzing Queue if eligible
                            if risk_category in ["RCE", "SSRF", "LFI"]:
                                self.tools_to_fuzz.append((name, input_schema, risk_category))

                    self.add_finding(final_level, risk_title, risk_desc, {"tool_name": name})
                    found_risk = True
                    break 
            if found_risk: break

        if "properties" in input_schema and not input_schema["properties"]:
            self.add_finding("LOW", "Opaque Input Schema", f"Tool '{name}' has undefined input properties.", input_schema)

    def scan_resource(self, resource: Any):
        uri = resource.uri
        name = resource.name
        if uri.startswith("file:///"):
            if len(uri) <= 8:
                self.add_finding("CRITICAL", "Root Directory Exposure", f"Resource '{name}' exposes filesystem root.", {"uri": uri})
            elif any(s in uri for s in ["/etc/", ".env", ".ssh"]):
                self.add_finding("CRITICAL", "Sensitive File Exposure", f"Resource '{name}' exposes sensitive config.", {"uri": uri})

    def scan_prompt(self, prompt: Any):
        name = prompt.name
        desc = prompt.description or ""
        combined_text = f"{name} {desc}".lower()
        if any(s in combined_text for s in ["key", "secret", "password", "token"]):
            self.add_finding("HIGH", "Potential Hardcoded Secret", f"Prompt '{name}' suggests hardcoded secrets.", {"prompt": name})

    def generate_report(self):
        print("\n" + "="*60)
        print("🛡️  MCP Security Scan Report (Static Analysis)")
        print("="*60)
        
        if self.findings:
            priority_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            self.findings.sort(key=lambda x: priority_map.get(x["level"], 4))

            for finding in self.findings:
                icon_map = {"CRITICAL": "☠️", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🔵"}
                icon = icon_map.get(finding["level"], "⚪")
                print(f"\n{icon} [{finding['level']}] {finding['title']}")
                print(f"   Description: {finding['description']}")
        else:
            print("✅ No static security risks detected.")
