import asyncio
import aiohttp
import socket
import struct
from urllib.parse import urlparse
from mcp_scan.utils.patterns import MOLTBOT_SIGNATURES, MOLTBOT_PORTS, MOLTBOT_MDNS_SIGNATURES

class MoltbotScanner:
    def __init__(self, target: str, timeout: int = 5):
        self.target = target
        self.timeout = timeout
        self.results = []

    def _normalize_target(self, target: str) -> str:
        if "://" in target:
            return urlparse(target).hostname
        return target

    def _create_dns_query(self, name, qtype):
        header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        qname = b""
        for part in name.split("."):
            qname += struct.pack("B", len(part)) + part.encode("utf-8")
        qname += b"\x00"
        question = qname + struct.pack("!HH", qtype, 1)
        return header + question

    async def probe_mdns(self):
        """Probes UDP 5353 for mDNS leaks."""
        host = self._normalize_target(self.target)
        port = 5353
        print(f"[*] Probing {host}:{port} via Unicast mDNS...")
        
        loop = asyncio.get_event_loop()
        query = self._create_dns_query("_services._dns-sd._udp.local", 12)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Use run_in_executor for blocking socket calls if necessary, 
            # but for a single send/recv with timeout, a simple implementation is fine.
            # However, to be fully async-friendly:
            sock.setblocking(False)
            
            await loop.sock_sendto(sock, query, (host, port))
            
            # Second query for common HTTP services
            query_http = self._create_dns_query("_http._tcp.local", 12)
            await loop.sock_sendto(sock, query_http, (host, port))

            # Buffer for response
            data = bytearray(1024)
            # Wait for response with timeout
            try:
                # We use a simple loop and wait_for to simulate timeout for recvfrom
                # since sock_recvfrom doesn't take a timeout.
                resp_data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout=self.timeout)
                printable = "".join([chr(b) if 32 <= b <= 126 else "." for b in resp_data])
                
                is_match = False
                for sig in MOLTBOT_MDNS_SIGNATURES:
                    if sig.lower() in printable.lower():
                        is_match = True
                        break
                
                if is_match:
                    print(f"  [!] 🚨 LEAK DETECTED: Found ClawdBot/Moltbot via mDNS on {host}:{port}!")
                    self.results.append({
                        "port": port,
                        "url": f"udp://{host}:{port}",
                        "type": "mDNS Information Leak",
                        "severity": "HIGH",
                        "details": f"Target is responding to mDNS queries with service signature: {printable[:50]}..."
                    })
            except asyncio.TimeoutError:
                pass # No mDNS response
                
        except Exception as e:
            # print(f"  [-] mDNS probe error: {e}")
            pass
        finally:
            sock.close()

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
            pass

    async def run(self):
        print(f"[*] Starting Moltbot/ClawdBot Scan for: {self.target}")
        
        # Run mDNS probe and port scan in parallel
        async with aiohttp.ClientSession() as session:
            tasks = [self.scan_port(session, p) for p in MOLTBOT_PORTS]
            tasks.append(self.probe_mdns())
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
        print("    1. Firewall ports 8080, 18789 and UDP 5353 immediately.")
        print("    2. Rotate all API keys stored in the bot.")