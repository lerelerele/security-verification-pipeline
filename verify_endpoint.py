"""
Verification Endpoint — Pipeline Connectivity Logger
Escucha en puerto 80 y registra cada peticion con IP, headers, timestamp.
Diseñado para verificar conectividad del pipeline de seguridad.

Uso: python verify_endpoint.py [--port 80]
"""

import json
import os
import sys
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

LOG_FILE = "C:\\verification\\requests.jsonl"
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# GitHub Actions IP ranges (will be fetched at startup)
GITHUB_IP_RANGES = []

def fetch_github_ranges():
    """Fetch GitHub Actions IP ranges from GitHub Meta API."""
    global GITHUB_IP_RANGES
    try:
        import urllib.request
        url = "https://api.github.com/meta"
        req = urllib.request.Request(url, headers={"User-Agent": "verification-endpoint"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            GITHUB_IP_RANGES = data.get("actions", [])
            GITHUB_IP_RANGES.extend(data.get("git", []))
            print(f"[+] Loaded {len(GITHUB_IP_RANGES)} GitHub IP ranges")
    except Exception as e:
        print(f"[-] Could not fetch GitHub IP ranges: {e}")
        GITHUB_IP_RANGES = []

def is_github_ip(ip):
    """Check if IP is in GitHub Actions range."""
    if not GITHUB_IP_RANGES:
        return None
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in GITHUB_IP_RANGES:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except:
        pass
    return False

class VerificationHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logging

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        
        # Extract client info
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        user_agent = self.headers.get("User-Agent", "unknown")
        accept = self.headers.get("Accept", "")
        x_forwarded_for = self.headers.get("X-Forwarded-For", "")
        x_real_ip = self.headers.get("X-Real-IP", "")
        
        # Check if from GitHub
        from_github = is_github_ip(client_ip)
        source_label = "GITHUB" if from_github else "UNKNOWN" if from_github is None else "EXTERNAL"
        
        # Build request record
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "client_ip": client_ip,
            "client_port": client_port,
            "method": "GET",
            "path": parsed.path,
            "query": qs,
            "user_agent": user_agent,
            "accept": accept,
            "x_forwarded_for": x_forwarded_for,
            "x_real_ip": x_real_ip,
            "from_github": from_github,
            "source_label": source_label,
            "headers": {k: v for k, v in self.headers.items()},
        }
        
        # Log to file
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        
        # Print to console
        print(f"[{record['timestamp']}] {source_label} {client_ip}:{client_port} {parsed.path} UA={user_agent}")
        
        # Respond with something plausible
        if parsed.path == "/api/verify":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            response = {
                "status": "ok",
                "verified": True,
                "timestamp": record["timestamp"],
                "source": qs.get("source", ["unknown"])[0],
                "service": "security-verification-pipeline",
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""
        
        client_ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "unknown")
        from_github = is_github_ip(client_ip)
        source_label = "GITHUB" if from_github else "UNKNOWN" if from_github is None else "EXTERNAL"
        
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "client_ip": client_ip,
            "client_port": self.client_address[1],
            "method": "POST",
            "path": parsed.path,
            "query": parse_qs(parsed.query),
            "body": body[:5000],
            "user_agent": user_agent,
            "from_github": from_github,
            "source_label": source_label,
            "headers": {k: v for k, v in self.headers.items()},
        }
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        
        print(f"[{record['timestamp']}] {source_label} {client_ip} POST {parsed.path} body={len(body)}b")
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok", "received": True}).encode())


def main():
    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 80
    
    print(f"[+] Verification endpoint starting on port {port}")
    print(f"[+] Log file: {LOG_FILE}")
    fetch_github_ranges()
    
    server = HTTPServer(("0.0.0.0", port), VerificationHandler)
    print(f"[+] Listening on 0.0.0.0:{port}")
    print(f"[+] Endpoints: GET /api/verify?source=agent, POST /api/verify")
    print(f"[+] Waiting for requests...")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down")
        server.server_close()

if __name__ == "__main__":
    main()