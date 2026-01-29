import asyncio
import aiohttp
import argparse
import sys
from urllib.parse import urlparse

# ================= Configuration =================
TARGET_PORTS = [8080, 18789, 3000] # Common ports for Moltbot/ClawdBot
SIGNATURES = [
    "<title>Moltbot", 
    "<title>ClawdBot", 
    "content=\"Moltbot\"",
    "Moltbot Dashboard"
]

class MoltbotScanner:
    def __init__(self, target: str, timeout: int = 5):
        self.target = target
        self.timeout = timeout
        self.results = []

    def _normalize_target(self, target: str) -> str:
        """Ensures target is a hostname or IP, stripping scheme if present."""
        if "://" in target:
            return urlparse(target).hostname
        return target

    async def scan_port(self, session: aiohttp.ClientSession, port: int):
        host = self._normalize_target(self.target)
        url = f"http://{host}:{port}"
        
        try:
            print(f"[*] Probing {url}...")
            async with session.get(url, timeout=self.timeout) as response:
                text = await response.text()
                status = response.status
                
                # 1. Fingerprint Detection
                is_moltbot = False
                for sig in SIGNATURES:
                    if sig.lower() in text.lower():
                        is_moltbot = True
                        break
                
                if is_moltbot:
                    print(f"  [!] 🚨 FOUND MOLTBOT INSTANCE ON PORT {port}!")
                    self.results.append({
                        "port": port,
                        "url": url,
                        "type": "Exposed Web Interface",
                        "severity": "CRITICAL",
                        "details": "Web interface is accessible. Check for authentication bypass."
                    })
                    
                    # 2. Check for Auth Bypass (Weak Check)
                    # If we can see the dashboard HTML without a redirect to /login, it might be exposed.
                    if "login" not in response.url.path and status == 200:
                         print(f"  [!] 💀 POTENTIAL AUTH BYPASS: Direct access to dashboard allowed.")
                         self.results.append({
                            "port": port,
                            "url": url,
                            "type": "Unauthenticated Access",
                            "severity": "CRITICAL",
                            "details": "Dashboard appears accessible without login redirect."
                        })

                # 3. Gateway Port Check (18789)
                if port == 18789 and status == 200:
                     print(f"  [!] ⚠️  Gateway Port 18789 is OPEN. Potential API exposure.")
                     self.results.append({
                        "port": port,
                        "url": url,
                        "type": "Exposed Gateway",
                        "severity": "HIGH",
                        "details": "Port 18789 is the default Gateway port. If unauthenticated, it allows remote control."
                    })

        except (aiohttp.ClientConnectorError, asyncio.TimeoutError):
            # Port closed or filtered
            pass
        except Exception as e:
            print(f"  [-] Error checking port {port}: {e}")

    async def run(self):
        print(f"[*] Starting Moltbot/ClawdBot Scan for: {self.target}")
        async with aiohttp.ClientSession() as session:
            tasks = [self.scan_port(session, p) for p in TARGET_PORTS]
            await asyncio.gather(*tasks)
        
        self.generate_report()

    def generate_report(self):
        print("\n" + "="*60)
        print("🔍 Moltbot/ClawdBot Scan Report")
        print("="*60)
        
        if not self.results:
            print("✅ No obvious Moltbot instances found on common ports.")
            return

        for res in self.results:
            icon = "☠️" if res["severity"] == "CRITICAL" else "🔴"
            print(f"\n{icon} [{res['severity']}] {res['type']}")
            print(f"   URL: {res['url']}")
            print(f"   Details: {res['details']}")
            
        print("\n⚠️  Recommendation: If this is your server, assume it is compromised.")
        print("    1. Firewall ports 8080 and 18789 immediately.")
        print("    2. Rotate all API keys stored in the bot.")
        print("    3. Reinstall behind a secure VPN (e.g., Tailscale).")

async def main():
    parser = argparse.ArgumentParser(description="Moltbot/ClawdBot Exposure Scanner")
    parser.add_argument("target", help="Target IP address or Hostname (e.g., 192.168.1.10)")
    args = parser.parse_args()
    
    scanner = MoltbotScanner(args.target)
    await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())
