import asyncio
import sys
import json
import re
from typing import List, Dict, Any
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# ================= 配置区 =================

# 高危关键词库 (Regex)
RISK_PATTERNS = {
    "HIGH": [
        r"exec", r"shell", r"bash", r"cmd", r"system", r"run_command",  # RCE 风险
        r"eval", r"python_code", r"script",                             # 代码执行
        r"delete", r"remove", r"drop", r"truncate"                      # 破坏性操作
    ],
    "MEDIUM": [
        r"write", r"upload", r"modify", r"update",                      # 数据篡改
        r"file_system", r"fs",                                          # 文件系统访问
        r"sql", r"query", r"database"                                   # 数据库注入风险
    ],
    "LOW": [
        r"read", r"get", r"fetch", r"search"                            # 信息泄露风险
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

        # 1. 检查名称和描述中的危险关键词
        combined_text = f"{name} {desc}".lower()
        
        for level, patterns in RISK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_text):
                    self.add_finding(
                        level, 
                        f"Detected Risky Capability: {pattern}",
                        f"Tool '{name}' contains keywords implying dangerous operations. Ensure strict authorization.",
                        {"tool_name": name, "description": desc}
                    )
                    break # 同一级别的风险只报一次

        # 2. 检查参数Schema (简单的启发式检查)
        # 如果参数没有任何描述，或者允许任意属性，可能存在 Prompt Injection 风险
        if "properties" in input_schema and not input_schema["properties"]:
            self.add_finding(
                "LOW",
                "Opaque Input Schema",
                f"Tool '{name}' takes input but has no specific properties defined. This increases hallucination and injection risks.",
                input_schema
            )

    def scan_resource(self, resource: Any):
        """扫描资源定义"""
        uri = resource.uri
        name = resource.name
        
        # 检查是否暴露了根目录或敏感文件
        if uri.startswith("file:///"):
            if len(uri) <= 8: # file:///
                self.add_finding(
                    "CRITICAL",
                    "Root Directory Exposure",
                    f"Resource '{name}' seems to expose the entire file system root via '{uri}'.",
                    {"uri": uri}
                )
            elif "/etc/" in uri or ".env" in uri or ".ssh" in uri:
                self.add_finding(
                    "HIGH",
                    "Sensitive File Exposure",
                    f"Resource '{name}' exposes sensitive system paths.",
                    {"uri": uri}
                )

    def generate_report(self):
        """生成文本报告"""
        print("\n" + "="*60)
        print("🛡️  MCP Security Scan Report")
        print("="*60)
        
        if not self.findings:
            print("✅ No obvious security risks detected (based on heuristics).")
            return

        # 按风险等级排序
        priority_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.findings.sort(key=lambda x: priority_map.get(x["level"], 4))

        for finding in self.findings:
            icon = "🔴" if finding["level"] in ["CRITICAL", "HIGH"] else "Dg" if finding["level"] == "MEDIUM" else "🔵"
            print(f"\n{icon} [{finding['level']}] {finding['title']}")
            print(f"   Description: {finding['description']}")
            if finding['raw']:
                print(f"   Context: {json.dumps(finding['raw'], indent=2)}")

async def run_scanner(command: str, args: List[str]):
    # 配置 Server 参数
    server_params = StdioServerParameters(
        command=command,
        args=args,
        env=None
    )

    scanner = SecurityScanner()

    print(f"[*] Connecting to MCP Server: {command} {' '.join(args)}...")
    
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # 初始化连接
                await session.initialize()
                print("[+] Connection established.")

                # 1. 获取并扫描 Tools
                print("[*] Fetching Tools...")
                result = await session.list_tools()
                for tool in result.tools:
                    scanner.scan_tool(tool)
                
                # 2. 获取并扫描 Resources
                print("[*] Fetching Resources...")
                result = await session.list_resources()
                for resource in result.resources:
                    scanner.scan_resource(resource)
                
                # 3. 获取并扫描 Prompts
                print("[*] Fetching Prompts...")
                result = await session.list_prompts()
                # (此处可以添加针对 Prompt 的扫描逻辑，例如检测是否包含 system prompt 泄露)

                # 生成报告
                scanner.generate_report()

    except Exception as e:
        print(f"❌ Error connecting to server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mcp_scanner.py <command_to_run_server> [args...]")
        print("Example: python mcp_scanner.py npx -y @modelcontextprotocol/server-filesystem /Users/xcyang")
        sys.exit(1)

    command = sys.argv[1]
    args = sys.argv[2:]
    
    asyncio.run(run_scanner(command, args))