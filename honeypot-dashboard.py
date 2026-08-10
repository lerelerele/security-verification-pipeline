#!/usr/bin/env python3
"""honeypot-dashboard.py — Dashboard simple que funciona sin f-string collisions."""
import argparse, json, os, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import Counter
import requests

LOG_FILE = None
GEO_CACHE = {}

def load_logs():
    entries = []
    if not os.path.exists(LOG_FILE): return entries
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try: entries.append(json.loads(line.strip()))
            except: pass
    return entries

def geolocate(ip):
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    try:
        r = requests.get("http://ip-api.com/json/" + ip + "?fields=status,country,countryCode,city,lat,lon", timeout=5)
        d = r.json()
        if d.get("status") == "success": GEO_CACHE[ip] = d; return d
    except: pass
    GEO_CACHE[ip] = None
    return None

def get_stats(entries):
    s = {"reqs":0,"convs":0,"captcha":0,"human":0,"errors":0,"fell":0,"ips":set(),"ip_c":Counter(),"ua_c":Counter(),"convs_list":[],"data_list":[],"recent":[],"geo":[]}
    fell_sids = set()
    for e in entries:
        ev = e.get("event","")
        if ev == "request":
            s["reqs"] += 1
            ip = e.get("client_ip","?")
            s["ips"].add(ip); s["ip_c"][ip] += 1
            ua = e.get("user_agent","")[:60]
            if ua: s["ua_c"][ua] += 1
            s["recent"].append({"ip":ip,"ts":e.get("timestamp","")[:19],"path":e.get("path",""),"method":e.get("method",""),"ua":ua})
        elif ev == "captcha_passed": s["captcha"] += 1
        elif ev == "human_blocked": s["human"] += 1
        elif ev == "conversation":
            s["convs"] += 1; s["convs_list"].append(e)
            sid = e.get("session_id","")
            if sid not in fell_sids and e.get("data_extracted_so_far"):
                s["fell"] += 1; fell_sids.add(sid)
        elif ev == "llm_error": s["errors"] += 1
        elif ev == "data_extracted": s["data_list"].append(e)
    for ip in s["ips"]:
        g = geolocate(ip)
        if g: s["geo"].append({"ip":ip,"country":g.get("country","?"),"city":g.get("city","?"),"lat":g.get("lat",0),"lon":g.get("lon",0),"count":s["ip_c"][ip],"cc":g.get("countryCode","")})
    s["ips"] = len(s["ips"])
    s["recent"] = s["recent"][-15:]
    return s

HTML_TEMPLATE = '''<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="10">
<title>Honeypot Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0a0e14;color:#c9d1d9}
.h{display:flex;justify-content:space-between;align-items:center;padding:12px 20px;background:#0d1117;border-bottom:1px solid #30363d}
.h h1{color:#58a6ff;font-size:1.3em}
.badges{display:flex;gap:6px;flex-wrap:wrap}
.badge{padding:2px 8px;border-radius:10px;font-size:0.7em;font-weight:bold}
.bg{background:#0d2818;color:#3fb950;border:1px solid #238636}
.bb{background:#0d1a33;color:#58a6ff;border:1px solid #1f6feb}
.bp{background:#1a0d2e;color:#bc8cff;border:1px solid #8957e5}
.by{background:#2e2a05;color:#d29922;border:1px solid #9e6a03}
.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;padding:15px 20px}
.m{background:#0d1117;border:1px solid #30363d;border-radius:10px;padding:15px;text-align:center}
.m .n{font-size:1.8em;font-weight:bold}
.m .l{color:#8b949e;font-size:0.75em;margin-top:3px}
.g{color:#3fb950}.r{color:#f85149}.y{color:#d29922}.b{color:#58a6ff}.p{color:#bc8cff}
.main{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:12px 20px}
.section{background:#0d1117;border:1px solid #30363d;border-radius:10px;padding:15px}
.section h2{color:#58a6ff;margin-bottom:10px;font-size:1em}
#map{width:100%;height:250px;background:#0a0e14;border-radius:6px;position:relative;overflow:hidden}
#feed{max-height:220px;overflow:hidden}
.fi{padding:6px 10px;margin:3px 0;background:#161b22;border-radius:4px;border-left:3px solid #58a6ff;animation:si 0.5s}
.fi .ip{color:#58a6ff;font-weight:bold}.fi .p{color:#8b949e;font-size:0.8em}.fi .t{color:#6e7681;font-size:0.75em}
@keyframes si{from{opacity:0;transform:translateY(15px)}to{opacity:1;transform:translateY(0)}}
.conv{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px;margin:6px 0}
.ch{color:#58a6ff;font-weight:bold;margin-bottom:4px}
.ca{color:#f85149;margin:2px 0;word-break:break-word;font-size:0.85em}
.cs{color:#3fb950;margin:2px 0;word-break:break-word;font-size:0.85em}
.cd{color:#d29922;margin:2px 0;font-size:0.8em;word-break:break-word}
.dr{padding:5px 8px;margin:3px 0;background:#161b22;border-radius:4px;border-left:3px solid #d29922;font-size:0.85em}
.dr .ip{color:#58a6ff}.dr .v{color:#d29922}
table{width:100%;border-collapse:collapse}
th,td{padding:5px 8px;text-align:left;border-bottom:1px solid #21262d;font-size:0.85em}
th{color:#58a6ff}
.updated{color:#6e7681;font-size:0.7em;text-align:right;padding:5px 20px 10px}
.dot{position:absolute;width:10px;height:10px;border-radius:50%;background:#f85149;animation:pl 2s infinite}
@keyframes pl{0%{box-shadow:0 0 0 0 rgba(248,81,73,0.7)}70%{box-shadow:0 0 0 12px rgba(248,81,73,0)}100%{box-shadow:0 0 0 0 rgba(248,81,73,0)}}
</style></head><body>
<div class="h"><h1>Honeypot AI Dashboard</h1>
<div class="badges"><span class="badge bg">MiniMax-m3</span><span class="badge bb">DeepSeek-v4-flash</span><span class="badge bp">CAPTCHA</span><span class="badge by">Ollama Local</span></div></div>

<div class="metrics">
<div class="m"><div class="n b">__REQS__</div><div class="l">Requests</div></div>
<div class="m"><div class="n p">__CAPTCHA__</div><div class="l">CAPTCHA Passed</div></div>
<div class="m"><div class="n g">__CONVS__</div><div class="l">Conversations</div></div>
<div class="m"><div class="n y">__FELL__</div><div class="l">Agents Fell</div></div>
<div class="m"><div class="n r">__HUMAN__</div><div class="l">Humans Blocked</div></div>
</div>

<div class="main">
<div class="section"><h2>World Map</h2><div id="map"></div><div id="geolist" style="margin-top:8px;font-size:0.75em;color:#8b949e"></div></div>
<div class="section"><h2>Live Connection Feed</h2><div id="feed"></div></div>
</div>

<div class="section" style="margin:12px 20px"><h2>Last Conversations</h2><div id="convs"></div></div>
<div class="section" style="margin:12px 20px"><h2>Data Extracted</h2><div id="dext"></div></div>

<div class="main">
<div class="section"><h2>Top IPs</h2><table><tr><th>IP</th><th>Hits</th></tr>__TIPS__</table></div>
<div class="section"><h2>Top User-Agents</h2><table><tr><th>UA</th><th>Count</th></tr>__TUAS__</table></div>
</div>

<div class="updated">Updated: __TIME__ | Auto-refresh 10s</div>

<script>
var geoData = __GEO__;
var recent = __RECENT__;
var convs = __CONVS_LIST__;
var dext = __DATA_LIST__;

var mapEl = document.getElementById('map');
var mapW = mapEl.clientWidth || 400;
var mapH = 250;
mapEl.innerHTML = '<svg width="'+mapW+'" height="'+mapH+'" style="position:absolute;top:0;left:0"><rect width="'+mapW+'" height="'+mapH+'" fill="#0a0e14"/><line x1="0" y1="'+mapH/2+'" x2="'+mapW+'" y2="'+mapH/2+'" stroke="#1a2333" stroke-width="0.5"/><line x1="'+mapW/2+'" y1="0" x2="'+mapW/2+'" y2="'+mapH+'" stroke="#1a2333" stroke-width="0.5"/><g fill="#161b22" stroke="#30363d" stroke-width="0.5"><path d="M 60 50 Q 100 40 140 45 L 150 80 Q 130 100 100 105 L 70 100 Q 50 80 60 50 Z"/><path d="M 120 120 Q 140 130 135 160 L 120 190 Q 100 185 105 160 L 115 125 Z"/><path d="M 210 50 Q 240 45 260 50 L 255 75 Q 230 80 210 75 Z"/><path d="M 225 85 Q 260 90 255 125 L 240 165 Q 220 160 215 135 L 220 90 Z"/><path d="M 260 45 Q 330 40 400 55 L 390 95 Q 330 105 280 90 L 265 65 Z"/><path d="M 370 155 Q 410 150 420 170 L 405 185 Q 375 180 370 165 Z"/></g></svg>';

var geoList = document.getElementById('geolist');
var gh = '';
geoData.forEach(function(g){
  var x = ((g.lon + 180) / 360) * mapW;
  var y = ((90 - g.lat) / 180) * mapH;
  if(x>=0&&x<=mapW&&y>=0&&y<=mapH){
    var d = document.createElement('div');
    d.className = 'dot';
    d.style.left = (x-5)+'px';
    d.style.top = (y-5)+'px';
    d.title = g.ip+' - '+g.city+', '+g.country;
    mapEl.appendChild(d);
  }
  gh += '<div>'+g.city+', '+g.country+' ('+g.ip+') - '+g.count+' hits</div>';
});
geoList.innerHTML = gh || '<div>No geo data</div>';

var feedEl = document.getElementById('feed');
var fh = '';
recent.reverse().forEach(function(c){
  fh += '<div class="fi"><span class="ip">'+c.ip+'</span> <span class="p">'+c.method+' '+c.path+'</span> <span class="t">'+c.ts.substring(11,19)+'</span></div>';
});
feedEl.innerHTML = fh || '<div style="color:#6e7681">No connections</div>';

var convsEl = document.getElementById('convs');
var ch = '';
convs.forEach(function(c){
  var ds = c.data_extracted_so_far ? JSON.stringify(c.data_extracted_so_far.slice(-2)).substring(0,200) : 'none';
  ch += '<div class="conv"><div class="ch">IP: '+c.client_ip+' | Msgs: '+c.messages_exchanged+'</div><div class="ca">Agent: '+(c.agent_input||'').substring(0,150)+'</div><div class="cs">Server: '+(c.our_response||'').substring(0,150)+'</div><div class="cd">Extracted: '+ds+'</div></div>';
});
convsEl.innerHTML = ch || '<div style="color:#6e7681">No conversations</div>';

var dextEl = document.getElementById('dext');
var dh = '';
dext.forEach(function(d){
  dh += '<div class="dr"><span class="ip">'+d.client_ip+'</span> -> <span class="v">'+JSON.stringify(d.data)+'</span></div>';
});
dextEl.innerHTML = dh || '<div style="color:#6e7681">No data extracted</div>';
</script></body></html>'''

class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        entries = load_logs()
        s = get_stats(entries)
        tips = "".join("<tr><td>{}</td><td>{}</td></tr>".format(ip,c) for ip,c in s["ip_c"].most_common(10))
        tuas = "".join("<tr><td>{}</td><td>{}</td></tr>".format(ua,c) for ua,c in s["ua_c"].most_common(5))
        html = HTML_TEMPLATE
        html = html.replace("__REQS__", str(s["reqs"]))
        html = html.replace("__CAPTCHA__", str(s["captcha"]))
        html = html.replace("__CONVS__", str(s["convs"]))
        html = html.replace("__FELL__", str(s["fell"]))
        html = html.replace("__HUMAN__", str(s["human"]))
        html = html.replace("__TIME__", datetime.datetime.now().strftime("%H:%M:%S"))
        html = html.replace("__GEO__", json.dumps(s["geo"], ensure_ascii=False))
        html = html.replace("__RECENT__", json.dumps(s["recent"], ensure_ascii=False))
        html = html.replace("__CONVS_LIST__", json.dumps(s["convs_list"][-5:], ensure_ascii=False))
        html = html.replace("__DATA_LIST__", json.dumps(s["data_list"][-10:], ensure_ascii=False))
        html = html.replace("__TIPS__", tips or '<tr><td colspan=2>No data</td></tr>')
        html = html.replace("__TUAS__", tuas or '<tr><td colspan=2>No data</td></tr>')
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

def main():
    global LOG_FILE
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=3000)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--log-file", default="./honeypot-ai.jsonl")
    a = p.parse_args()
    LOG_FILE = a.log_file
    print("Dashboard: http://0.0.0.0:" + str(a.port))
    print("Log: " + a.log_file)
    print("PID: " + str(os.getpid()))
    server = HTTPServer((a.host, a.port), DashboardHandler)
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nStop"); server.shutdown()

if __name__ == "__main__": main()