import asyncio
import aiohttp
import socket
import struct
from urllib.parse import urlparse
from mcp_scan.utils.patterns import MOLTBOT_SIGNATURES, MOLTBOT_PORTS, MOLTBOT_MDNS_SIGNATURES

class DNSParser:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def parse_name(self):
        labels = []
        loop_detection = 0
        tmp_offset = self.offset
        jumped = False
        
        while True:
            if tmp_offset >= len(self.data): break
            length = self.data[tmp_offset]
            
            if length == 0:
                if not jumped: self.offset = tmp_offset + 1
                break
            
            if (length & 0xC0) == 0xC0: # Pointer
                if tmp_offset + 2 > len(self.data): break
                pointer = struct.unpack("!H", self.data[tmp_offset:tmp_offset+2])[0] & 0x3FFF
                if not jumped: self.offset = tmp_offset + 2
                tmp_offset = pointer
                jumped = True
                loop_detection += 1
                if loop_detection > 10: break # Prevent loops
                continue
                
            tmp_offset += 1
            if tmp_offset + length > len(self.data): break
            labels.append(self.data[tmp_offset:tmp_offset+length])
            tmp_offset += length
            if not jumped: self.offset = tmp_offset
            
        try:
            return b".".join(labels).decode('utf-8', errors='ignore')
        except:
            return "<invalid-name>"

    def skip_header(self):
        self.offset = 12 # Header is 12 bytes

    def skip_questions(self, q_count):
        for _ in range(q_count):
            self.parse_name()
            self.offset += 4 # Type(2) + Class(2)

    def parse_records(self, count):
        records = []
        for _ in range(count):
            if self.offset >= len(self.data): break
            name = self.parse_name()
            # Type(2), Class(2), TTL(4), RDLENGTH(2)
            if self.offset + 10 > len(self.data): break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", self.data[self.offset:self.offset+10])
            self.offset += 10
            
            rdata_start = self.offset
            rdata_val = None
            
            try:
                if rtype == 12: # PTR
                    parser_sub = DNSParser(self.data)
                    parser_sub.offset = self.offset
                    rdata_val = parser_sub.parse_name()
                elif rtype == 33: # SRV
                    # Priority(2), Weight(2), Port(2), Target(Name)
                    # We need to be careful with offset calculation inside rdata
                    if rdlen >= 6:
                        parser_sub = DNSParser(self.data)
                        parser_sub.offset = self.offset + 6
                        target = parser_sub.parse_name()
                        port = struct.unpack("!H", self.data[self.offset+4:self.offset+6])[0]
                        rdata_val = {"target": target, "port": port}
                elif rtype == 16: # TXT
                    # TXT records are sequence of <len><text>
                    txt_parts = []
                    curr = self.offset
                    end = self.offset + rdlen
                    while curr < end:
                        tlen = self.data[curr]
                        curr += 1
                        if curr + tlen > end: break
                        txt_parts.append(self.data[curr:curr+tlen].decode('utf-8', errors='ignore'))
                        curr += tlen
                    rdata_val = txt_parts
            except Exception:
                rdata_val = "<parse-error>"

            self.offset = rdata_start + rdlen
            records.append({"name": name, "type": rtype, "data": rdata_val})
        return records

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
            sock.setblocking(False)
            
            await loop.sock_sendto(sock, query, (host, port))
            
            # Second query for common HTTP services (likely to return SRV/TXT in additionals)
            query_http = self._create_dns_query("_http._tcp.local", 12)
            await loop.sock_sendto(sock, query_http, (host, port))

            # Also try querying specific known services if we suspect Moltbot
            query_molt = self._create_dns_query("_clawdbot-gw._tcp.local", 12)
            await loop.sock_sendto(sock, query_molt, (host, port))

            # Buffer for response
            try:
                # Allow receiving multiple packets
                end_time = loop.time() + self.timeout
                while True:
                    remaining = end_time - loop.time()
                    if remaining <= 0: break
                    
                    try:
                        resp_data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=remaining)
                    except asyncio.TimeoutError:
                        break

                    # Quick ASCII check for signatures
                    printable = "".join([chr(b) if 32 <= b <= 126 else "." for b in resp_data])
                    is_match = False
                    for sig in MOLTBOT_MDNS_SIGNATURES:
                        if sig.lower() in printable.lower():
                            is_match = True
                            break
                    
                    if is_match:
                        # Full Parse
                        parser = DNSParser(resp_data)
                        try:
                            # Header
                            if len(resp_data) < 12: continue
                            header = struct.unpack("!HHHHHH", resp_data[:12])
                            qdcount, ancount, nscount, arcount = header[2], header[3], header[4], header[5]
                            
                            parser.skip_header()
                            parser.skip_questions(qdcount)
                            records = parser.parse_records(ancount + nscount + arcount)
                            
                            details_lines = []
                            for rec in records:
                                if rec['type'] == 12: # PTR
                                    details_lines.append(f"Service Instance: {rec['data']}")
                                elif rec['type'] == 33: # SRV
                                    data = rec['data']
                                    if isinstance(data, dict):
                                        details_lines.append(f"Target Host: {data['target']} (Port {data['port']})")
                                elif rec['type'] == 16: # TXT
                                    if isinstance(rec['data'], list):
                                        txt_str = ", ".join(rec['data'])
                                        details_lines.append(f"Metadata: {txt_str}")

                            details_str = "\n   ".join(details_lines) if details_lines else f"Raw: {printable[:50]}..."
                            
                            print(f"  [!] 🚨 LEAK DETECTED: Found ClawdBot/Moltbot via mDNS on {host}:{port}!")
                            self.results.append({
                                "port": port,
                                "url": f"udp://{host}:{port}",
                                "type": "mDNS Information Leak",
                                "severity": "HIGH",
                                "details": f"Target leaking internal network info:\n   {details_str}"
                            })
                            # If we found a match, we can stop or keep looking for more packets
                            break 
                        except Exception as e:
                            # Fallback
                            print(f"  [!] Parse error but signature found: {e}")
            except Exception:
                pass
                
        except Exception as e:
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
