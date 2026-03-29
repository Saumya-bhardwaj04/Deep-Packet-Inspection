# Python DPI Engine

## What this service does

- Reads packets from a PCAP file.
- Parses IPv4/TCP/UDP traffic.
- Extracts TLS SNI, HTTP Host, and DNS query domains.
- Classifies each connection to an app category.
- Applies blocking rules (IP, app, domain wildcard, port).
- Writes only allowed packets to output PCAP.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_api.py
```

## API endpoints

- GET /api/health
- GET /api/apps
- GET /api/rules
- POST /api/rules
- POST /api/process

## CLI usage

```powershell
python cli.py --input ..\test_dpi.pcap --output ..\output_python.pcap --rules sample_rules.json
```
