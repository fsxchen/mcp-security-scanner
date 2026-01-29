from typing import Dict, Any, Optional
from mcp import ClientSession

class FuzzingEngine:
    def __init__(self, session: ClientSession):
        self.session = session
        self.results = []

    async def fuzz_tool(self, tool_name: str, input_schema: Dict[str, Any], risk_category: str):
        """Executes active fuzzing tests on a specific tool."""
        print(f"    [Fuzzing] Targeting '{tool_name}' ({risk_category})...")
        
        target_param = self._identify_target_param(input_schema)
        if not target_param:
            print(f"      [!] Skipped: Could not identify a suitable parameter to fuzz.")
            return

        payloads = self._get_payloads(risk_category)
        
        for payload_name, payload_val in payloads.items():
            try:
                args = {target_param: payload_val}
                result = await self.session.call_tool(tool_name, arguments=args)
                
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
        if not schema or "properties" not in schema:
            return None
        
        props = schema["properties"]
        if not props:
            return None
        
        priority_names = ["path", "file", "filename", "url", "command", "cmd", "query", "sql"]
        for name in priority_names:
            if name in props:
                return name
        
        for name, detail in props.items():
            if detail.get("type") == "string":
                return name
        
        return list(props.keys())[0]

    def _get_payloads(self, category: str) -> Dict[str, str]:
        if category in ["RCE", "Command Injection"]:
            return {
                "Command Injection (Math)": "; echo $((414141+414141))",
                "Command Injection (Pipe Math)": "| echo $((414141+414141))"
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
            # Math check: 414141 + 414141 = 828282
            # Also keep checking for uid/gid for other types of RCE behavior
            return "828282" in output or "uid=" in output or "gid=" in output
        
        elif category in ["File System", "LFI"]:
            return "root:x:0:0" in output or "[fonts]" in output.lower()
        
        elif category in ["SSRF"]:
            return "ami-id" in output or "AWS_ACCESS_KEY" in output or "SSH" in output
            
        return False
