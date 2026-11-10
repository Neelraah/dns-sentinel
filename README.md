# DNS Sentinel — Browser Extension + DNS Honeypot

A local-first defensive research project combining a Chromium extension, a Python telemetry agent, a Flask honeypot and optional `dnsmasq` sinkhole integration.

## What it does

- Observes browser requests for a small set of suspicious URL patterns (e.g. exposed `.env`, `/wp-login`, traversal patterns).
- Sends matching metadata to a local-only API at `127.0.0.1:8765`.
- Runs `nslookup` and bounded `curl -I` diagnostics for a domain entered by the operator.
- Hosts a harmless HTTP decoy on `127.0.0.1:8080`; it records method, source IP, path, user-agent and timestamp. It never executes request bodies or downloaded files.
- Displays events, classifications and a timeline in a lavender/yellow dashboard.
- Can ingest dnsmasq query logs when the operator configures a lab resolver.

## Architecture

```text
Chromium browser
  └─ DNS Sentinel MV3 extension
       ├─ webRequest observer
       └─ localhost API client ─────────────┐
                                            v
                                  Python Flask API :8765
                                    ├─ events.jsonl
                                    ├─ nslookup
                                    └─ curl -I (bounded)
                                            ^
dnsmasq (optional lab resolver) ── query log

curl / lab client ─────────────> Flask honeypot :8080
```

## Requirements

- Chrome or Microsoft Edge
- Python 3.10+ and pip
- `curl`
- `nslookup` (usually supplied by `dnsutils` on Debian/Ubuntu or `bind-tools` on Arch)
- `dnsmasq` only if you want to test DNS sinkholing
- Docker Compose is optional

## 1. Start the local agent

From the repository root:

```bash
cd agent
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

In a second terminal:

```bash
cd agent
python honeypot.py
```

The API binds to loopback only (`127.0.0.1`). The decoy listener binds to all interfaces by default in this starter build; for a personal machine, change it to `127.0.0.1` unless you intentionally need a separate isolated lab client.

Check:
```bash
curl http://127.0.0.1:8765/api/health
curl http://127.0.0.1:8080/wp-login.php
```

## 2. Load the extension

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the `extension/` folder.
5. Pin DNS Sentinel. Open its popup, then launch the dashboard.

The extension uses broad host permissions because its purpose is to observe requests across sites. Browser permissions are visible during installation. It does not read form fields, cookies, passwords or page text.

## 3. Run a safe lab test

With both Python processes running:

```bash
# macOS/Linux
bash scripts/test_lab.sh

# Windows PowerShell
.\scripts\test_lab.ps1
```

Then refresh the dashboard. A request to `/wp-login.php` should appear as a credential-probing event.

## 4. Optional dnsmasq lab configuration

`dnsmasq/dnsmasq.conf.example` is a **reference configuration**, not an auto-installer. It listens on loopback port `5353`, logs queries, and demonstrates how explicit lab test domains can be mapped to a sinkhole address.

On Debian/Ubuntu, install tools with:
```bash
sudo apt update
sudo apt install dnsmasq dnsutils curl
```

Review the example and run dnsmasq in the foreground for a controlled lab:
```bash
sudo dnsmasq --no-daemon --conf-file=dnsmasq/dnsmasq.conf.example
```

In another terminal, test:
```bash
nslookup example.com 127.0.0.1
```

To test a sinkhole mapping, add a domain you own or a reserved lab name such as `bad-domain.test`:
```ini
address=/bad-domain.test/127.0.0.1
```
Then query it explicitly:
```bash
nslookup bad-domain.test 127.0.0.1
```

**Important:** The example uses port 5353 to avoid taking over the machine's normal DNS service. Most operating systems and browsers will not automatically use this resolver. Explicitly query it for the lab test. Do not replace system DNS or redirect third-party domains without authorization. Do not expose dnsmasq as an open resolver. The honeypot is an HTTP decoy; DNS sinkholing alone does not automatically redirect HTTPS traffic to a working TLS decoy.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/status` | Event counters |
| GET | `/api/events` | Recent events |
| POST | `/api/events` | Ingest extension metadata |
| POST | `/api/diagnostics` | Validated `nslookup` + bounded `curl` |

## Security notes / limitations

- This is a **monitoring and research prototype**, not a production DNS firewall, EDR or malware sandbox.
- Browser URL-pattern detections are heuristic signals, not proof of compromise.
- The extension cannot install or control `dnsmasq`; privileged DNS configuration is a separate, deliberate operator action.
- Diagnostics accept domain names only, reject shell metacharacters and invoke subprocesses using argument arrays (no shell).
- Keep the agent bound to localhost. Do not port-forward it or expose it to the public internet.
- Use only on devices, networks and websites you own or are authorized to test.
- No geolocation is fabricated. The dashboard reports source IPs only when the honeypot can observe them.
- Browser requests are not equivalent to raw DNS queries. DNS telemetry comes from the configured resolver log.

## Project structure

```text
dns-sentinel-extension/
├── extension/       # Manifest V3 extension and UI
├── agent/           # Flask API + honeypot service
├── dnsmasq/         # Optional lab resolver configuration
├── scripts/         # Harmless smoke tests
└── README.md
```

## Suggested GitHub repository description

DNS Sentinel is a local-first DNS honeypot and browser threat-observation extension built with Manifest V3, Python/Flask, dnsmasq, nslookup and curl. It captures suspicious request metadata, supports controlled DNS sinkhole experiments and visualizes activity in a lavender-and-yellow security dashboard.
