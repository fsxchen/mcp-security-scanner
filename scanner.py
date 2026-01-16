import asyncio
import sys
import json
import re
from typing import List, Dict, Any
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# ================= 配置区 =================

# 扩充风险关键词库 (对应 OWASP LLM Top 10)
RISK_PATTERNS = {
    "CRITICAL": [
        r"exec", r"shell", r"bash", r"cmd", r"system", r"run_command",  # RCE
        r"eval", r"python_code", r"script",                             # 代码执行
        r"delete", r"remove", r"drop", r"truncate",                     # 破坏性操作
        r"sudo", r"chmod", r"chown"                                     # 提权
    ],
    "HIGH": [
        r"curl", r"wget", r"fetch", r"request", r"http_client",         # SSRF (服务端请求伪造) 风险
        r"write", r"upload", r"modify", r"update",                      # 数据篡改
        r"api_key", r"token", r"secret", r"password"                    # 敏感凭证泄露 (在 Prompt 或 output 中)
    ],
    "MEDIUM": [
        r"file_system", r"fs", r"read_file",                            # 文件系统访问
        r"sql", r"query", r"database",                                  # 数据库操作
        r"scrape", r"crawl", r"browse", r"summarize_url"                # 间接提示词注入 (读取不可信外部来源)
    ],
    "LOW": [
        r"get", r"search", r"list"                                      # 信息泄露风险
    ]
}

# ================= 扫描逻辑 =================

class SecurityScanner:
    def __init__(self):
        self.findings = []

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
        
        # 获取 MCP 协议特有的安全标志: isUserApprovalRequired
        # 兼容性处理：检查对象属性或字典
        requires_approval = getattr(tool, "isUserApprovalRequired", False)
        if not requires_approval and hasattr(tool, "model_dump"):
             # 尝试从 pydantic 模型转储中获取
             requires_approval = tool.model_dump().get("isUserApprovalRequired", False)

        combined_text = f"{name} {desc}".lower()
        
        # 1. 关键词启发式扫描
        found_risk = False
        for level, patterns in RISK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_text):
                    # 默认风险信息
                    risk_title = f"Detected Risky Capability: {pattern}"
                    risk_desc = f"Tool '{name}' implies dangerous operations."
                    
                    # 针对特定场景的增强描述
                    if level == "HIGH" and pattern in [r"curl", r"wget", r"fetch"]:
                        risk_title = "Potential SSRF Vector (OWASP LLM06)"
                        risk_desc = f"Tool '{name}' can access network resources. Ensure it cannot access internal IPs or cloud metadata."
                    
                    if level == "MEDIUM" and pattern in [r"scrape", r"crawl"]:
                        risk_title = "Indirect Prompt Injection Vector (OWASP LLM01)"
                        risk_desc = f"Tool '{name}' processes untrusted external content. Malicious web pages could hijack the Agent."

                    # === HITL (Human-in-the-loop) 检查逻辑 ===
                    if requires_approval:
                        # 如果开启了用户确认，风险降级
                        final_level = "LOW"
                        risk_title = f"[MITIGATED] {risk_title}"
                        risk_desc += " ✅ Mitigation: 'isUserApprovalRequired' is enabled. User confirmation protects against autonomous misuse."
                    else:
                        # 如果没有确认，且原本就是高危，则标记为 HITL Bypass
                        final_level = level
                        if level in ["CRITICAL", "HIGH"]:
                            risk_title += " (HITL Bypass)"
                            risk_desc += " ❌ WARNING: 'isUserApprovalRequired' is MISSING/FALSE. AI can execute this autonomously!"

                    self.add_finding(final_level, risk_title, risk_desc, {"tool_name": name, "requires_approval": requires_approval})
                    found_risk = True
                    break 
            if found_risk: break

        # 2. Schema 检查
        if "properties" in input_schema and not input_schema["properties"]:
            self.add_finding(
                "LOW",
                "Opaque Input Schema",
                f"Tool '{name}' has undefined input properties. This complicates validation and increases injection risks.",
                input_schema
            )

    def scan_resource(self, resource: Any):
        """扫描资源定义"""
        uri = resource.uri
        name = resource.name
        
        if uri.startswith("file:///"):
            if len(uri) <= 8: # file:///
                self.add_finding(
                    "CRITICAL",
                    "Root Directory Exposure",
                    f"Resource '{name}' exposes the entire filesystem root. This is a catastrophic misconfiguration.",
                    {"uri": uri}
                )
            elif any(s in uri for s in ["/etc/", ".env", ".ssh", "id_rsa", ".aws"]):
                self.add_finding(
                    "CRITICAL",
                    "Sensitive File Exposure",
                    f"Resource '{name}' exposes sensitive system configuration or credentials.",
                    {"uri": uri}
                )

    def scan_prompt(self, prompt: Any):
        """扫描 Prompt 模板 (检查硬编码密钥)"""
        name = prompt.name
        desc = prompt.description or ""
        
        # 检查 Prompt 定义中是否包含敏感词
        combined_text = f"{name} {desc}".lower()
        if any(s in combined_text for s in ["key", "secret", "password", "token"]):
            self.add_finding(
                "HIGH",
                "Potential Hardcoded Secret in Prompts",
                f"Prompt '{name}' metadata contains keywords suggesting hardcoded secrets.",
                {"prompt": name, "description": desc}
            )

    def generate_report(self):
        """生成文本报告"""
        print("\n" + "="*60)
        print("🛡️  MCP Security Scan Report")
        print("="*60)
        
        if not self.findings:
            print("✅ No obvious security risks detected (based on heuristics).")
            return

        priority_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.findings.sort(key=lambda x: priority_map.get(x["level"], 4))

        for finding in self.findings:
            icon_map = {"CRITICAL": "☠️", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🔵"}
            icon = icon_map.get(finding["level"], "⚪")
            
            print(f"\n{icon} [{finding['level']}] {finding['title']}")
            print(f"   Description: {finding['description']}")
            if finding['raw']:
                # 简化 raw 输出
                raw_str = json.dumps(finding['raw'])
                if len(raw_str) > 100: raw_str = raw_str[:100] + "..."
                print(f"   Context: {raw_str}")

async def run_scanner(command: str, args: List[str]):
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

                scanner.generate_report()

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <command> [args...]")
        sys.exit(1)
    asyncio.run(run_scanner(sys.argv[1], sys.argv[2:]))
