# walletoperator (FastAPI + Uvicorn)

This repo contains the FastAPI app (`app.py`) and static assets used to run the
wallet operator lookup website.

## What is NOT included (by design)

To avoid leaking private data, this repo does **NOT** include:
- keys/certs
- domains/IPs
- databases (e.g. `operator_profiles.db`)
- uploads directory
- GeoIP or map files

## Quickstart (local)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 5000
