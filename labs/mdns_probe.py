import socket
import struct
import sys
import argparse

def create_dns_query(name, qtype):
    # Header
    # ID: 0x0000, Flags: 0x0100 (Standard Query), Questions: 1, Others: 0
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    
    # Question Name
    qname = b""
    for part in name.split("."):
        qname += struct.pack("B", len(part)) + part.encode("utf-8")
    qname += b"\x00"
    
    # QType (PTR=12), QClass (IN=1)
    # Note: For unicast mDNS query, some implementations might require QClass |= 0x8000 (Unicast Response)
    # but strictly speaking standard DNS query is enough for misconfigured servers.
    question = qname + struct.pack("!HH", qtype, 1)
    
    return header + question

def parse_dns_response(data):
    # Simple parser to extract strings, very basic
    print(f"[*] Received {len(data)} bytes")
    try:
        # Try to find readable strings which might contain service names
        # Filter for printable ascii
        printable = "".join([chr(b) if 32 <= b <= 126 else "." for b in data])
        print(f"[*] Raw Content (ASCII):\n{printable}")
        
        # Check for specific signatures
        if "Moltbot" in printable or "ClawdBot" in printable:
            print("\n[!] 🚨 FOUND CLAWDBOT/MOLTBOT SIGNATURE IN MDNS RESPONSE!")
            return True
    except Exception as e:
        print(f"[-] Parse error: {e}")
    return False

def probe_mdns(target_ip, port=5353):
    print(f"[*] Probing {target_ip}:{port} via Unicast mDNS...")
    
    # Query for _services._dns-sd._udp.local (PTR)
    query = create_dns_query("_services._dns-sd._udp.local", 12)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    
    try:
        sock.sendto(query, (target_ip, port))
        
        # Also try _http._tcp.local
        query_http = create_dns_query("_http._tcp.local", 12)
        sock.sendto(query_http, (target_ip, port))

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                print(f"\n[+] Response from {addr}:")
                if parse_dns_response(data):
                    print("[+] Confirmed: Target is leaking mDNS info.")
                    break
            except socket.timeout:
                print("[-] Timeout waiting for response.")
                break
                
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mdns_probe.py <ip>")
        sys.exit(1)
    probe_mdns(sys.argv[1])
