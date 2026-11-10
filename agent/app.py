from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timezone
from pathlib import Path
import subprocess, socket, re, json, os, ipaddress

BASE = Path(__file__).resolve().parent
LOG = BASE / "events.jsonl"
DNS_LOG = Path(os.getenv("DNSMASQ_LOG", str(BASE / "dnsmasq.log")))
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

def read_events():
    rows=[]
    if LOG.exists():
        for line in LOG.read_text(errors="replace").splitlines()[-2000:]:
            try: rows.append(json.loads(line))
            except json.JSONDecodeError: pass
    # Include dnsmasq query log lines as separate DNS telemetry.
    if DNS_LOG.exists():
        for line in DNS_LOG.read_text(errors="replace").splitlines()[-1000:]:
            if "query[" in line:
                rows.append({"timestamp":datetime.now(timezone.utc).isoformat(),"source":"dnsmasq","domain":line.split()[-1],"method":"DNS","category":"DNS query","severity":"low","path":line.strip()})
    return rows

def write_event(data):
    data["timestamp"] = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    with LOG.open("a", encoding="utf-8") as f: f.write(json.dumps(data, ensure_ascii=False)+"\n")

@app.get("/api/status")
def status():
    events=read_events()
    ips={e.get("ip") for e in events if e.get("ip")}
    return jsonify(total_events=len(events), unique_ips=len(ips),
                   dns_queries=sum(1 for e in events if e.get("source")=="dnsmasq"),
                   high_signal=sum(1 for e in events if e.get("severity")=="high"),
                   service="online", honeypot_port=8080)

@app.get("/api/events")
def events():
    return jsonify(events=read_events()[-500:])

@app.post("/api/events")
def ingest():
    data=request.get_json(silent=True) or {}
    allowed={"timestamp","hostname","path","method","type","tabId","source","severity","ip","domain","category","agent"}
    clean={k:v for k,v in data.items() if k in allowed and isinstance(v,(str,int,float))}
    if not clean: return jsonify(error="No valid event fields"),400
    write_event(clean)
    return jsonify(ok=True),201

@app.post("/api/diagnostics")
def diagnostics():
    data=request.get_json(silent=True) or {}
    domain=str(data.get("domain","")).strip().lower()
    domain=domain.removeprefix("https://").removeprefix("http://").split("/")[0].split(":")[0]
    if len(domain)>253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+",domain):
        return jsonify(message="Enter a valid public domain name.",output="Input validation failed."),400
    results=[]
    for cmd,label in [(["nslookup",domain],"NSLOOKUP"),(["curl","-I","-L","--max-time","6","--max-redirs","3","-sS",f"https://{domain}"],"CURL HEAD")]:
        try:
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=9,check=False)
            results.append(f"$ {' '.join(cmd)}\n{(p.stdout+p.stderr).strip()[:3000] or '(no output)'}")
        except FileNotFoundError: results.append(f"{label}: tool not installed.")
        except subprocess.TimeoutExpired: results.append(f"{label}: timed out.")
    write_event({"source":"diagnostics","domain":domain,"method":"DNS/HTTP","path":"diagnostic run","severity":"low","category":"Operator diagnostic"})
    return jsonify(message="Diagnostics completed. Results are informational.",output="\n\n".join(results))

@app.get("/api/health")
def health(): return jsonify(ok=True,service="dns-sentinel-agent")

if __name__=="__main__":
    app.run(host="127.0.0.1",port=8765,debug=False)
