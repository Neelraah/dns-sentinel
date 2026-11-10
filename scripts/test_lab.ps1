$ErrorActionPreference = "Stop"
Write-Host "[1/3] Checking local agent"
Invoke-RestMethod http://127.0.0.1:8765/api/health
Write-Host "[2/3] Sending harmless request to local honeypot"
curl.exe -A "DNS-Sentinel-Lab-Test" http://127.0.0.1:8080/wp-login.php
Write-Host "[3/3] DNS lookup"
nslookup.exe example.com 127.0.0.1
Write-Host "Done. Open the extension dashboard."
