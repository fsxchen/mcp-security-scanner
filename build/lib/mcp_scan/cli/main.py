import sys
import argparse
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_scan.core.static import StaticAnalyzer
from mcp_scan.core.fuzzer import FuzzingEngine
from mcp_scan.core.moltbot import MoltbotScanner

async def run_mcp_scan(command: str, args: list, enable_fuzz: bool):
    server_params = StdioServerParameters(command=command, args=args, env=None)
    scanner = StaticAnalyzer()

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

                scanner.generate_report()
                
                if fuzz_results:
                    print("\n" + "="*60)
                    print("💥 ACTIVE FUZZING RESULTS (Confirmed Vulnerabilities)")
                    print("="*60)
                    for res in fuzz_results:
                        print(f"\n☠️  [VULNERABLE] Tool: {res['tool']}")
                        print(f"    Type: {res['vulnerability']}")
                        print(f"    Payload: {res['payload']}")
                        print(f"    Evidence: {res['evidence']}")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

async def run_moltbot_scan(target: str):
    scanner = MoltbotScanner(target)
    await scanner.run()

def main():
    parser = argparse.ArgumentParser(description="MCP Security Scanner Suite")
    subparsers = parser.add_subparsers(dest="mode", help="Scan mode")

    # Mode 1: Check (Static MCP Scan)
    check_parser = subparsers.add_parser("check", help="Static analysis of MCP server")
    check_parser.add_argument("command", help="Server command (e.g., npx, python)")
    check_parser.add_argument("args", nargs="*", help="Server arguments")
    check_parser.add_argument("--fuzz", action="store_true", help="Enable active fuzzing")

    # Mode 2: Moltbot (Infrastructure Scan)
    moltbot_parser = subparsers.add_parser("moltbot", help="Scan for exposed Moltbot/ClawdBot instances")
    moltbot_parser.add_argument("target", help="Target IP or Hostname")

    args = parser.parse_args()

    if args.mode == "check":
        # Handle the args specifically for the command
        # argparse eats the args, so we might need to be careful if server args have flags
        # For simplicity, we assume server command and its args are passed correctly.
        asyncio.run(run_mcp_scan(args.command, args.args, args.fuzz))
    elif args.mode == "moltbot":
        asyncio.run(run_moltbot_scan(args.target))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
