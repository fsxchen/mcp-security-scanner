import asyncio
import aiohttp
from urllib.parse import urlparse
from mcp_scan.utils.patterns import MOLTBOT_SIGNATURES, MOLTBOT_PORTS

class MoltbotScanner:
    def __init__(self, target: str, timeout: int = 5):
        self.target = target
        self.timeout = timeout
        self.results = []

    def _normalize_target(self, target: str) -> str:
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
                
                is_moltbot = False
                for sig in MOLTBOT_SIGNATURES:
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
                    
                    if "login" not in response.url.path and status == 200:
                         print(f"  [!] 💀 POTENTIAL AUTH BYPASS: Direct access to dashboard allowed.")
                         self.results.append({
                            "port": port,
                            "url": url,
                            "type": "Unauthenticated Access",
                            "severity": "CRITICAL",
                            "details": "Dashboard appears accessible without login redirect."
                        })

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
            pass
        except Exception as e:
            print(f"  [-] Error checking port {port}: {e}")

    async def run(self):
        print(f"[*] Starting Moltbot/ClawdBot Scan for: {self.target}")
        async with aiohttp.ClientSession() as session:
            tasks = [self.scan_port(session, p) for p in MOLTBOT_PORTS]
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
