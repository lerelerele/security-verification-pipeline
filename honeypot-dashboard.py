#!/usr/bin/env python3
"""
honeypot-dashboard.py — Dashboard web en tiempo real con mapa mundial y feed animado.
Lee C:\\honeypot-ai.jsonl y sirve un dashboard con mapa, metricas y feed de IPs.

Uso:
  python honeypot-dashboard.py --port 3000 --log-file C:\\honeypot-ai.jsonl
"""

import argparse
import json
import os
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import Counter, defaultdict
import requests

LOG_FILE = None

# IP geolocation cache
GEO_CACHE = {}


def load_logs():
    entries = []
    if not os.path.exists(LOG_FILE):
        return entries
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except:
                continue
    return entries


def geolocate_ip(ip):
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,lat,lon,query", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            GEO_CACHE[ip] = data
            return data
    except:
        pass
    GEO_CACHE[ip] = None
    return None


def get_stats(entries):
    stats = {
        "total_requests": 0,
        "total_conversations": 0,
        "captcha_passed": 0,
        "captcha_failed": 0,
        "human_blocked": 0,
        "sanitizer_blocked": 0,
        "llm_errors": 0,
        "unique_ips": set(),
        "sessions": set(),
        "ip_counter": Counter(),
        "ua_counter": Counter(),
        "conversations": [],
        "data_extracted": [],
        "agents_fell": 0,
        "recent_connections": [],
        "geo_data": [],
    }
    seen_sessions_fell = set()
    for e in entries:
        event = e.get("event", "")
        if event == "request":
            stats["total_requests"] += 1
            ip = e.get("client_ip", "?")
            stats["unique_ips"].add(ip)
            stats["ip_counter"][ip] += 1
            ua = e.get("user_agent", "")[:60]
            if ua:
                stats["ua_counter"][ua] += 1
            sid = e.get("session_id", "")
            if sid:
                stats["sessions"].add(sid)
            stats["recent_connections"].append({
                "ip": ip,
                "timestamp": e.get("timestamp", ""),
                "path": e.get("path", ""),
                "ua": ua,
                "method": e.get("method", ""),
            })
        elif event == "captcha_passed":
            stats["captcha_passed"] += 1
        elif event == "captcha_failed":
            stats["captcha_failed"] += 1
        elif event == "human_blocked":
            stats["human_blocked"] += 1
        elif event == "conversation":
            stats["total_conversations"] += 1
            stats["conversations"].append(e)
            sid = e.get("session_id", "")
            if sid and sid not in seen_sessions_fell and e.get("data_extracted_so_far"):
                stats["agents_fell"] += 1
                seen_sessions_fell.add(sid)
        elif event == "llm_error":
            stats["llm_errors"] += 1
        elif event == "data_extracted":
            stats["data_extracted"].append(e)

    # Geolocate unique IPs
    for ip in stats["unique_ips"]:
        geo = geolocate_ip(ip)
        if geo:
            stats["geo_data"].append({
                "ip": ip,
                "country": geo.get("country", "?"),
                "countryCode": geo.get("countryCode", ""),
                "city": geo.get("city", "?"),
                "lat": geo.get("lat", 0),
                "lon": geo.get("lon", 0),
                "count": stats["ip_counter"][ip],
            })

    stats["unique_ips"] = len(stats["unique_ips"])
    stats["sessions"] = len(stats["sessions"])
    stats["recent_connections"] = stats["recent_connections"][-20:]
    return stats


def generate_html(stats):
    import html as html_mod
    geo_json = json.dumps(stats["geo_data"], ensure_ascii=False)
    recent_json = json.dumps(stats["recent_connections"][-15:], ensure_ascii=False)
    conversations_json = json.dumps(stats["conversations"][-5:], ensure_ascii=False)
    data_extracted_json = json.dumps(stats["data_extracted"][-10:], ensure_ascii=False)

    top_ips = ""
    for ip, count in stats["ip_counter"].most_common(10):
        top_ips += f"<tr><td>{html_mod.escape(ip)}</td><td>{count}</td></tr>"

    top_uas = ""
    for ua, count in stats["ua_counter"].most_common(5):
        top_uas += f"<tr><td>{html_mod.escape(ua)}</td><td>{count}</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<title>Honeypot Dashboard</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0a0e14; color:#c9d1d9; overflow-x:hidden; }}
.header {{ display:flex; justify-content:space-between; align-items:center; padding:15px 25px; background:#0d1117; border-bottom:1px solid #30363d; }}
.header h1 {{ color:#58a6ff; font-size:1.4em; }}
.badges {{ display:flex; gap:8px; flex-wrap:wrap; }}
.badge {{ padding:3px 10px; border-radius:12px; font-size:0.75em; font-weight:bold; }}
.b-g {{ background:#0d2818; color:#3fb950; border:1px solid #238636; }}
.b-b {{ background:#0d1a33; color:#58a6ff; border:1px solid #1f6feb; }}
.b-p {{ background:#1a0d2e; color:#bc8cff; border:1px solid #8957e5; }}
.b-y {{ background:#2e2a05; color:#d29922; border:1px solid #9e6a03; }}

.main {{ display:grid; grid-template-columns:1fr 1fr; gap:15px; padding:15px 25px; }}

.metrics {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; padding:15px 25px; }}
.metric {{ background:#0d1117; border:1px solid #30363d; border-radius:10px; padding:18px; text-align:center; transition:transform 0.2s; }}
.metric:hover {{ transform:scale(1.05); border-color:#58a6ff; }}
.metric .num {{ font-size:2em; font-weight:bold; }}
.metric .lbl {{ color:#8b949e; font-size:0.8em; margin-top:4px; }}
.g {{ color:#3fb950; }} .r {{ color:#f85149; }} .y {{ color:#d29922; }} .b {{ color:#58a6ff; }} .p {{ color:#bc8cff; }}

.map-section {{ background:#0d1117; border:1px solid #30363d; border-radius:10px; padding:20px; }}
.map-section h2 {{ color:#58a6ff; margin-bottom:15px; font-size:1.1em; }}
#map {{ width:100%; height:280px; background:#0a0e14; border-radius:8px; position:relative; overflow:hidden; }}

.feed-section {{ background:#0d1117; border:1px solid #30363d; border-radius:10px; padding:20px; max-height:340px; overflow:hidden; }}
.feed-section h2 {{ color:#58a6ff; margin-bottom:15px; font-size:1.1em; }}
#feed {{ max-height:280px; overflow:hidden; position:relative; }}
.feed-item {{ padding:8px 12px; margin:4px 0; background:#161b22; border-radius:6px; border-left:3px solid #58a6ff; animation:slideIn 0.5s ease; display:flex; justify-content:space-between; }}
.feed-item .ip {{ color:#58a6ff; font-weight:bold; }}
.feed-item .path {{ color:#8b949e; font-size:0.85em; }}
.feed-item .time {{ color:#6e7681; font-size:0.8em; }}
@keyframes slideIn {{ from{{opacity:0;transform:translateY(20px);}} to{{opacity:1;transform:translateY(0);}} }}

.convs {{ background:#0d1117; border:1px solid #30363d; border-radius:10px; padding:20px; margin:15px 25px; }}
.convs h2 {{ color:#58a6ff; margin-bottom:15px; font-size:1.1em; }}
.conv {{ background:#161b22; border:1px solid #30363d; border-radius:6px; padding:12px; margin:8px 0; }}
.conv-h {{ color:#58a6ff; font-weight:bold; margin-bottom:6px; }}
.conv-a {{ color:#f85149; margin:3px 0; word-break:break-word; font-size:0.9em; }}
.conv-s {{ color:#3fb950; margin:3px 0; word-break:break-word; font-size:0.9em; }}
.conv-d {{ color:#d29922; margin:3px 0; font-size:0.8em; word-break:break-word; }}

.data-ext {{ background:#0d1117; border:1px solid #30363d; border-radius:10px; padding:20px; margin:15px 25px; }}
.data-ext h2 {{ color:#d29922; margin-bottom:15px; font-size:1.1em; }}
.data-row {{ padding:6px 10px; margin:4px 0; background:#161b22; border-radius:4px; border-left:3px solid #d29922; }}
.data-row .ip {{ color:#58a6ff; }}
.data-row .val {{ color:#d29922; }}

.tables {{ display:grid; grid-template-columns:1fr 1fr; gap:15px; padding:15px 25px; }}
.table-section {{ background:#0d1117; border:1px solid #30363d; border-radius:10px; padding:20px; }}
.table-section h2 {{ color:#58a6ff; margin-bottom:10px; font-size:1.1em; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ padding:6px 10px; text-align:left; border-bottom:1px solid #21262d; font-size:0.9em; }}
th {{ color:#58a6ff; }}
.updated {{ color:#6e7681; font-size:0.75em; text-align:right; padding:5px 25px 15px; }}

.pulse {{ position:absolute; width:12px; height:12px; border-radius:50%; background:#f85149; animation:pulse 2s infinite; }}
@keyframes pulse {{ 0%{{box-shadow:0 0 0 0 rgba(248,81,73,0.7);}} 70%{{box-shadow:0 0 0 15px rgba(248,81,73,0);}} 100%{{box-shadow:0 0 0 0 rgba(248,81,73,0);}} }}
</style>
</head>
<body>
<div class="header">
  <h1>🔧 Honeypot AI Dashboard</h1>
  <div class="badges">
    <span class="badge b-g">MiniMax-m3 Sanitizer</span>
    <span class="badge b-b">DeepSeek-v4-flash</span>
    <span class="badge b-p">CAPTCHA Active</span>
    <span class="badge b-y">Ollama Local</span>
  </div>
</div>

<div class="metrics">
  <div class="metric"><div class="num b">{stats['total_requests']}</div><div class="lbl">Total Requests</div></div>
  <div class="metric"><div class="num p">{stats['captcha_passed']}</div><div class="lbl">CAPTCHA Passed</div></div>
  <div class="metric"><div class="num g">{stats['total_conversations']}</div><div class="lbl">Conversations</div></div>
  <div class="metric"><div class="num y">{stats['agents_fell']}</div><div class="lbl">Agents Fell 🎣</div></div>
  <div class="metric"><div class="num r">{stats['human_blocked']}</div><div class="lbl">Humans Blocked</div></div>
</div>

<div class="main">
  <div class="map-section">
    <h2>🌍 World Map — Connection Origins</h2>
    <div id="map"></div>
    <div id="geo-list" style="margin-top:10px;font-size:0.8em;color:#8b949e;"></div>
  </div>
  <div class="feed-section">
    <h2>📡 Live Connection Feed</h2>
    <div id="feed"></div>
  </div>
</div>

<div class="convs">
  <h2>💬 Last Conversations</h2>
  <div id="convs-container"></div>
</div>

<div class="data-ext">
  <h2>🎣 Data Extracted from Agents</h2>
  <div id="data-container"></div>
</div>

<div class="tables">
  <div class="table-section">
    <h2>🌐 Top IPs</h2>
    <table><tr><th>IP</th><th>Hits</th></tr>{top_ips or '<tr><td colspan=2>No data</td></tr>'}</table>
  </div>
  <div class="table-section">
    <h2>🤖 Top User-Agents</h2>
    <table><tr><th>UA</th><th>Count</th></tr>{top_uas or '<tr><td colspan=2>No data</td></tr>'}</table>
  </div>
</div>

<div class="updated">Last updated: {datetime.datetime.now().strftime('%H:%M:%S')} | Auto-refresh: 10s</div>

<script>
const geoData = {geo_json};
const recentConnections = {recent_json};
const conversations = {conversations_json};
const dataExtracted = {data_extracted_json};

// Simple world map projection (equirectangular)
const mapEl = document.getElementById('map');
const mapW = mapEl.clientWidth || 500;
const mapH = 280;
mapEl.style.width = mapW + 'px';

// Draw simplified continents as background using SVG
const svg = `<svg width="${mapW}" height="${mapH}" style="position:absolute;top:0;left:0;">
  <rect width="${mapW}" height="${mapH}" fill="#0a0e14"/>
  <!-- Grid lines -->
  <line x1="0" y1="${mapH/2}" x2="${mapW}" y2="${mapH/2}" stroke="#1a2333" stroke-width="0.5"/>
  <line x1="${mapW/2}" y1="0" x2="${mapW/2}" y2="${mapH}" stroke="#1a2333" stroke-width="0.5"/>
  <!-- Continents (simplified blobs) -->
  <g fill="#161b22" stroke="#30363d" stroke-width="0.5">
    <!-- North America -->
    <path d="M 80 60 Q 120 50 160 55 L 170 90 Q 150 110 120 115 L 90 110 Q 70 90 80 60 Z"/>
    <!-- South America -->
    <path d="M 140 130 Q 160 140 155 170 L 140 200 Q 120 195 125 170 L 135 135 Z"/>
    <!-- Europe -->
    <path d="M 230 55 Q 260 50 280 55 L 275 80 Q 250 85 230 80 Z"/>
    <!-- Africa -->
    <path d="M 245 90 Q 280 95 275 130 L 260 170 Q 240 165 235 140 L 240 95 Z"/>
    <!-- Asia -->
    <path d="M 280 50 Q 350 45 420 60 L 410 100 Q 350 110 300 95 L 285 70 Z"/>
    <!-- Australia -->
    <path d="M 390 165 Q 430 160 440 180 L 425 195 Q 395 190 390 175 Z"/>
  </g>
</svg>`;
mapEl.innerHTML = svg;

// Plot geo points
const geoList = document.getElementById('geo-list');
let geoHtml = '';
geoData.forEach(g => {{
  const x = ((g.lon + 180) / 360) * mapW;
  const y = ((90 - g.lat) / 180) * mapH;
  if (x >= 0 && x <= mapW && y >= 0 && y <= mapH) {{
    const dot = document.createElement('div');
    dot.className = 'pulse';
    dot.style.left = (x - 6) + 'px';
    dot.style.top = (y - 6) + 'px';
    dot.title = g.ip + ' - ' + g.city + ', ' + g.country;
    mapEl.appendChild(dot);
  }}
  geoHtml += `<div>${{g.city}}, ${{g.country}} (${{g.ip}}) - ${{g.count}} hits</div>`;
}});
geoList.innerHTML = geoHtml || '<div>No geo data yet</div>';

// Feed
const feedEl = document.getElementById('feed');
let feedHtml = '';
recentConnections.reverse().forEach(c => {{
  const t = c.timestamp ? c.timestamp.substring(11,19) : '';
  feedHtml += `<div class="feed-item"><span><span class="ip">${{c.ip}}</span> <span class="path">${{c.method}} ${{c.path}}</span></span><span class="time">${{t}}</span></div>`;
}});
feedEl.innerHTML = feedHtml || '<div style="color:#6e7681;">No connections yet</div>';

// Conversations
const convsEl = document.getElementById('convs-container');
let convsHtml = '';
conversations.forEach(c => {{
  const dataStr = c.data_extracted_so_far ? JSON.stringify(c.data_extracted_so_far.slice(-2)).substring(0,200) : 'none';
  convsHtml += `<div class="conv">
    <div class="conv-h">IP: ${{c.client_ip}} | Messages: ${{c.messages_exchanged}}</div>
    <div class="conv-a">Agent: ${{(c.agent_input||'').substring(0,150)}}</div>
    <div class="conv-s">Server: ${{(c.our_response||'').substring(0,150)}}</div>
    <div class="conv-d">Extracted: ${{dataStr}}</div>
  </div>`;
}});
convsEl.innerHTML = convsHtml || '<div style="color:#6e7681;">No conversations yet</div>';

// Data extracted
const dataEl = document.getElementById('data-container');
let dataHtml = '';
dataExtracted.forEach(d => {{
  dataHtml += `<div class="data-row"><span class="ip">${{d.client_ip}}</span> → <span class="val">${{JSON.stringify(d.data)}}</span></div>`;
}});
dataEl.innerHTML = dataHtml || '<div style="color:#6e7681;">No data extracted yet</div>';
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        entries = load_logs()
        stats = get_stats(entries)
        html = generate_html(stats)
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main():
    global LOG_FILE
    parser = argparse.ArgumentParser(description="Honeypot Dashboard")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--log-file", default="./honeypot-ai.jsonl")
    args = parser.parse_args()
    LOG_FILE = args.log_file
    print("Dashboard: http://0.0.0.0:" + str(args.port))
    print("Log: " + args.log_file)
    print("PID: " + str(os.getpid()))
    server = HTTPServer((args.host, args.port), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStop")
        server.shutdown()


if __name__ == "__main__":
    main()