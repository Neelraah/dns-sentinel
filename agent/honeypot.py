from flask import Flask, request, Response
from datetime import datetime, timezone
from pathlib import Path
import json, re

app=Flask(__name__)
LOG=Path(__file__).resolve().parent/"events.jsonl"
SUSPICIOUS=[(re.compile(p,re.I),name,sev) for p,name,sev in [
 (r"/(?:wp-admin|wp-login)", "Credential probing","medium"),
 (r"/(?:\.env|\.git|phpmyadmin)", "Sensitive file discovery","high"),
 (r"\.(?:exe|dll|ps1|bat)(?:$|\?)", "Malware path probe","high"),
 (r"(?:\.\./){2,}", "Path traversal probe","high"),
 (r"/(?:admin|backup|config)(?:/|$)", "Administrative endpoint probe","medium")
]]
@app.route("/",defaults={"path":""},methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
@app.route("/<path:path>",methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
def catch_all(path):
    # Never execute, save, or reflect request bodies.
    route="/"+path
    category,severity="Honeypot interaction","low"
    for pattern,label,level in SUSPICIOUS:
        if pattern.search(route): category,severity=label,level; break
    event={"timestamp":datetime.now(timezone.utc).isoformat(),"ip":request.remote_addr,
           "method":request.method,"path":route[:500],"agent":request.headers.get("User-Agent","")[:300],
           "source":"honeypot","category":category,"severity":severity}
    with LOG.open("a",encoding="utf-8") as f: f.write(json.dumps(event)+"\n")
    return Response("DNS Sentinel decoy service active\n",status=200,mimetype="text/plain")
if __name__=="__main__": app.run(host="0.0.0.0",port=8080,debug=False)
