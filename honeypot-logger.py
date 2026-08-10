#!/usr/bin/env python3
"""
honeypot-logger.py — HTTP logger para el honeypot.
Responde 200 a CUALQUIER path. Logea todo en JSONL.
No necesita rutas especificas - responde a /api/status/check, /api/verify, lo que sea.

Uso:
  python honeypot-logger.py --port 80 --log-file C:\\honeypot.jsonl
"""

import argparse
import json
import os
import sys
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

LOG_FILE = None
REQUEST_COUNTER = 0


def iso_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def log_request(handler, body=b""):
    global REQUEST_COUNTER
    REQUEST_COUNTER += 1

    client_ip = handler.client_address[0]
    client_port = handler.client_address[1]

    parsed = urlparse(handler.path)
    path = parsed.path
    query = parse_qs(parsed.query)

    headers = {}
    for key in handler.headers:
        val = handler.headers[key]
        if len(val) < 5000:
            headers[key] = val
        else:
            headers[key] = val[:200] + "...[TRUNCATED]"

    body_decoded = None
    if body:
        try:
            body_decoded = body.decode("utf-8", errors="replace")
            if len(body_decoded) > 10000:
                body_decoded = body_decoded[:10000] + "...[TRUNCATED]"
        except Exception:
            body_decoded = "[binary %d bytes]" % len(body)

    ua = headers.get("User-Agent", "").lower()
    path_lower = path.lower()
    classifications = []

    if "/api/status/check" in path_lower or "/api/verify" in path_lower:
        classifications.append("honeypot_verify")
    if "/mcp" in path_lower or "/sse" in path_lower:
        classifications.append("mcp_probe")
    if "/v1/models" in path_lower or "/v1/completions" in path_lower or "/v1/embeddings" in path_lower:
        classifications.append("llm_api_probe")
    if "libredtail" in ua:
        classifications.append("libredtail_scanner")
    if "zgrab" in ua:
        classifications.append("zgrab_scanner")
    if "censys" in ua:
        classifications.append("censys_scanner")
    if "masscan" in ua:
        classifications.append("masscan")
    if "palo alto" in ua:
        classifications.append("palo_alto_expanse")
    if "powershell" in ua:
        classifications.append("powershell_agent")
    if "python-requests" in ua or "python-httpx" in ua:
        classifications.append("python_bot")
    if "winrm" in ua:
        classifications.append("winrm_brute")
    if "wget" in ua:
        classifications.append("wget_scanner")
    if "phpunit" in path_lower:
        classifications.append("phpunit_rce")
    if "think" in path_lower and "invokefunction" in path_lower:
        classifications.append("thinkphp_rce")
    if "/.env" in path_lower or "/.aws" in path_lower or "/.git" in path_lower:
        classifications.append("cred_harvest")
    if "/.ssh" in path_lower:
        classifications.append("ssh_key_harvest")
    if "/wsman" in path_lower:
        classifications.append("winrm_probe")
    if "/sdk/weblanguage" in path_lower:
        classifications.append("cctv_recon")
    if "/actuator" in path_lower:
        classifications.append("spring_actuator")
    if "/geoserver" in path_lower:
        classifications.append("geoserver_recon")
    if "/_layouts" in path_lower or "/_vti" in path_lower:
        classifications.append("sharepoint_recon")
    if not classifications:
        classifications.append("unknown")

    entry = {
        "id": REQUEST_COUNTER,
        "timestamp": iso_now(),
        "client_ip": client_ip,
        "client_port": client_port,
        "method": handler.command,
        "path": path,
        "raw_path": handler.path,
        "query_params": query,
        "headers": headers,
        "user_agent": headers.get("User-Agent", ""),
        "body": body_decoded,
        "body_size": len(body),
        "classifications": classifications,
    }

    if LOG_FILE:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    else:
        print(json.dumps(entry, ensure_ascii=False))

    return entry


class HoneypotHandler(BaseHTTPRequestHandler):
    def _handle(self, method):
        body = b""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)

        log_request(self, body=body)

        response = b'{"status":"ok"}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("X-Powered-By", "PHP/8.2.0")
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_OPTIONS(self):
        self._handle("OPTIONS")

    def do_HEAD(self):
        self._handle("HEAD")

    def log_message(self, format, *args):
        pass


def main():
    global LOG_FILE
    parser = argparse.ArgumentParser(description="Honeypot HTTP Logger")
    parser.add_argument("--port", type=int, default=80, help="Port to listen on")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--log-file", default="./honeypot.jsonl", help="JSONL log file")
    args = parser.parse_args()

    LOG_FILE = args.log_file

    log_dir = os.path.dirname(args.log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    server = HTTPServer((args.host, args.port), HoneypotHandler)

    print("Honeypot logger listening on %s:%d" % (args.host, args.port))
    print("Logging to %s" % args.log_file)
    print("PID: %d" % os.getpid())
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()