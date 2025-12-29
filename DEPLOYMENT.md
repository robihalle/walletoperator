# Deployment guide (safe template)

This file explains how the app is typically run.
It contains NO real domains, NO IPs, NO secrets.

## Run locally
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 5000
