import asyncio
import sys
import json
import re
import argparse
from typing import List, Dict, Any, Optional
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# ================= 配置区 =================

RISK_PATTERNS = {
    "CRITICAL": [
        r"exec", r"shell", r"bash", r"cmd", r"system", r"run_command",  # RCE
        r"eval", r"python_code", r"script",                             # 代码执行
        r"delete", r"remove", r"drop", r"truncate",                     # 破坏性操作
        r"sudo", r"chmod", r"chown"                                     # 提权
    ],
    "HIGH": [
        r"curl", r"wget", r"fetch", r"request", r"http_client",         # SSRF
        r"write", r"upload", r"modify", r"update",                      # 数据篡改
        r"api_key", r"token", r"secret", r"password"                    # 敏感凭证泄露
    ],
    "MEDIUM": [
        r"file_system", r"fs", r"read_file", r"read",                   # 文件系统访问
        r"sql", r"query", r"database",                                  # 数据库操作
        r"scrape", r"crawl", r"browse", r"summarize_url"                # 间接提示词注入
    ],
    "LOW": [
        r"get", r"search", r"list"                                      # 信息泄露风险
    ]
}

# ================= 扫描逻辑 =================

class FuzzingEngine:
    def __init__(self, session: ClientSession):
        self.session = session
        self.results = []

    async def fuzz_tool(self, tool_name: str, input_schema: Dict[str, Any], risk_category: str):
        """对特定工具执行主动 Fuzzing 测试"""
        print(f"    [Fuzzing] Targeting '{tool_name}' ({risk_category})...")
        
        # 1. 确定注入点 (参数名)
        target_param = self._identify_target_param(input_schema)
        if not target_param:
            print(f"      [!] Skipped: Could not identify a suitable parameter to fuzz.")
            return

        # 2. 选择 Payloads
        payloads = self._get_payloads(risk_category)
        
        # 3. 执行攻击
        for payload_name, payload_val in payloads.items():
            try:
                # 构造参数
                args = {target_param: payload_val}
                
                # 调用工具
                # 注意: MCP call_tool 返回的是 CallToolResult，包含 content 列表
                result = await self.session.call_tool(tool_name, arguments=args)
                
                # 检查回显
                output_text = ""
                if result.content:
                    for item in result.content:
                        if hasattr(item, "text"):
                            output_text += item.text
                
                if self._check_success(risk_category, output_text):
                    print(f"      [!] 💥 VULNERABILITY CONFIRMED: {payload_name}")
                    print(f"          Payload: {payload_val}")
                    print(f"          Snippet: {output_text[:100].replace(chr(10), ' ')}...")
                    self.results.append({
                        "tool": tool_name,
                        "vulnerability": payload_name,
                        "payload": payload_val,
                        "evidence": output_text[:200]
                    })
                else:
                    print(f"      [-] {payload_name} failed (Safe response).")

            except Exception as e:
                print(f"      [-] Error executing {payload_name}: {e}")

    def _identify_target_param(self, schema: Dict[str, Any]) -> Optional[str]:
        """简单的启发式参数选择"""
        if not schema or "properties" not in schema:
            return None
        
        props = schema["properties"]
        if not props:
            return None
        
        # 优先找名字像 payload 的参数
        priority_names = ["path", "file", "filename", "url", "command", "cmd", "query", "sql"]
        for name in priority_names:
            if name in props:
                return name
        
        # 否则取第一个字符串类型的参数
        for name, detail in props.items():
            if detail.get("type") == "string":
                return name
        
        # 实在不行取第一个
        return list(props.keys())[0]

    def _get_payloads(self, category: str) -> Dict[str, str]:
        if category in ["RCE", "Command Injection"]:
            return {
                "Command Injection (Simple)": "; echo 'VULN_CHECK_SUCCESS'",
                "Command Injection (Pipe)": "| echo 'VULN_CHECK_SUCCESS'"
            }
        elif category in ["File System", "LFI"]:
            return {
                "LFI (Linux /etc/passwd)": "../../../../etc/passwd",
                "LFI (Windows win.ini)": "..\\..\\..\\..\\Windows\\win.ini"
            }
        elif category in ["SSRF"]:
            return {
                "SSRF (AWS Metadata)": "http://169.254.169.254/latest/meta-data/",
                "SSRF (Localhost)": "http://127.0.0.1:22"
            }
        return {}

    def _check_success(self, category: str, output: str) -> bool:
        if not output: return False
        
        if category in ["RCE", "Command Injection"]:
            return "VULN_CHECK_SUCCESS" in output or "uid=" in output or "Command Injection successful" in output
        
        elif category in ["File System", "LFI"]:
            return "root:x:0:0" in output or "[fonts]" in output.lower()
        
        elif category in ["SSRF"]:
            return "ami-id" in output or "AWS_ACCESS_KEY" in output or "SSH" in output
            
        return False


class SecurityScanner:
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
        """扫描单个工具定义的安全风险"""
        name = tool.name
        desc = tool.description or ""
        input_schema = tool.inputSchema
        
        requires_approval = getattr(tool, "isUserApprovalRequired", False)
        if not requires_approval and hasattr(tool, "model_dump"):
             requires_approval = tool.model_dump().get("isUserApprovalRequired", False)

        combined_text = f"{name} {desc}".lower()
        
        found_risk = False
        for level, patterns in RISK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_text):
                    risk_title = f"Detected Risky Capability: {pattern}"
                    risk_desc = f"Tool '{name}' implies dangerous operations."
                    risk_category = "General"
                    
                    if level == "CRITICAL" and pattern in [r"exec", r"shell", r"cmd", r"system", r"bash", r"run_command"]:
                        risk_category = "RCE"
                        # Heuristic refinement: "read_system_file" matches "system" but is likely LFI
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

    def generate_report(self, fuzz_results: List[Dict] = None):
        print("\n" + "="*60)
        print("🛡️  MCP Security Scan Report")
        print("="*60)
        
        # 1. Static Findings
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

        # 2. Dynamic Fuzzing Results
        if fuzz_results:
            print("\n" + "="*60)
            print("💥 ACTIVE FUZZING RESULTS (Confirmed Vulnerabilities)")
            print("="*60)
            for res in fuzz_results:
                print(f"\n☠️  [VULNERABLE] Tool: {res['tool']}")
                print(f"    Type: {res['vulnerability']}")
                print(f"    Payload: {res['payload']}")
                print(f"    Evidence: {res['evidence']}")
        elif fuzz_results is not None:
            print("\n✨ Active Fuzzing completed. No verified vulnerabilities found (this is good!).")


async def run_scanner(command: str, args: List[str], enable_fuzz: bool):
    server_params = StdioServerParameters(command=command, args=args, env=None)
    scanner = SecurityScanner()

    print(f"[*] Connecting to MCP Server: {command} {' '.join(args)}...")
    
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("[+] Connection established.")

                print("[*] Scanning Tools...")
                result = await session.list_tools()
                for tool in result.tools:
                    scanner.scan_tool(tool)
                
                print("[*] Scanning Resources...")
                result = await session.list_resources()
                for resource in result.resources:
                    scanner.scan_resource(resource)
                
                print("[*] Scanning Prompts...")
                result = await session.list_prompts()
                for prompt in result.prompts:
                    scanner.scan_prompt(prompt)

                fuzz_results = None
                if enable_fuzz and scanner.tools_to_fuzz:
                    print(f"\n[*] Starting Active Fuzzing on {len(scanner.tools_to_fuzz)} targets...")
                    print("    ⚠️  WARNING: This executes REAL commands on the server.")
                    fuzzer = FuzzingEngine(session)
                    for tool_name, schema, category in scanner.tools_to_fuzz:
                        await fuzzer.fuzz_tool(tool_name, schema, category)
                    fuzz_results = fuzzer.results
                elif enable_fuzz:
                    print("\n[*] Fuzzing enabled but no eligible high-risk tools found.")
                    fuzz_results = []

                scanner.generate_report(fuzz_results)

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP Security Scanner")
    parser.add_argument("command", help="Server command (e.g., npx, python)")
    parser.add_argument("args", nargs="*", help="Server arguments")
    parser.add_argument("--fuzz", action="store_true", help="Enable active fuzzing (executes payloads)")
    
    # 手动处理 args，因为 argparse 会混淆 server 的参数
    # 这里做一个简单的 trick：--fuzz 必须放在 command 之前，或者我们需要手动解析
    
    if "--fuzz" in sys.argv:
        enable_fuzz = True
        sys.argv.remove("--fuzz")
    else:
        enable_fuzz = False
        
    if len(sys.argv) < 2:
        print("Usage: python scanner.py [--fuzz] <command> [args...]")
        sys.exit(1)
        
    asyncio.run(run_scanner(sys.argv[1], sys.argv[2:], enable_fuzz))