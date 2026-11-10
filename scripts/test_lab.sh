#!/usr/bin/env bash
set -euo pipefail
echo "[1/3] Checking local agent"
curl --fail --silent http://127.0.0.1:8765/api/health
echo
echo "[2/3] Sending harmless request to local honeypot"
curl --silent -A "DNS-Sentinel-Lab-Test" http://127.0.0.1:8080/wp-login.php
echo
echo "[3/3] Querying local dnsmasq on port 5353 (if configured)"
if command -v nslookup >/dev/null 2>&1; then nslookup example.com 127.0.0.1#5353 || true; else echo "nslookup not installed"; fi
echo "Done. Open the extension dashboard to inspect the event."
