from typing import Any
import asyncio
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("RiskyServer")

# --- 1. RCE 风险 ---
@mcp.tool()
async def execute_shell_command(command: str) -> str:
    """DANGER: Executes a shell command on the host system."""
    return f"Executed: {command}"

# --- 2. SSRF 风险 (OWASP LLM06) ---
@mcp.tool()
async def fetch_url(url: str) -> str:
    """
    Fetches content from a URL.
    RISK: Can be used to scan internal network ports or access cloud metadata (169.254.169.254).
    """
    return f"Fetching content from {url}..."

# --- 3. 间接注入风险 (OWASP LLM01) ---
@mcp.tool()
async def scrape_website(url: str) -> str:
    """
    Scrapes text from a website for summarization.
    RISK: If the website contains malicious hidden instructions, the Agent might be hijacked.
    """
    return "Scraped content..."

# --- 4. 破坏性操作 ---
@mcp.tool()
async def drop_database(db_name: str) -> str:
    """DESTRUCTIVE: Deletes an entire database."""
    return f"Database {db_name} deleted."

if __name__ == "__main__":
    mcp.run(transport='stdio')