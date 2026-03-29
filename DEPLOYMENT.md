# Deployment Guide

## Architecture

- Frontend: Vercel (Vite React app in `frontend`)
- Backend: Render (Node API in `node_backend`)
- Data: Supabase Postgres (`supabase/schema.sql`)
- Worker: Python CLI (`python_engine/cli.py`) invoked by Node

## 1) Supabase Setup

1. Create a new Supabase project.
2. Open SQL Editor and run `supabase/schema.sql`.
3. Copy:
   - Project URL -> `SUPABASE_URL`
   - Service role key -> `SUPABASE_SERVICE_ROLE_KEY`

## 2) Render Backend Deployment

1. Push repository to GitHub.
2. In Render, create a new Web Service from repo.
3. Render auto-detects `render.yaml`.
4. Set environment variables:
   - `JWT_SECRET` (strong random secret)
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - Optional: `PYTHON_BIN` and `PYTHON_SCRIPT_PATH`
5. Deploy and verify `https://<render-app>/api/health`.

## 3) Vercel Frontend Deployment

1. Import the same repository into Vercel.
2. Keep root config from `vercel.json`.
3. Add env var:
   - `VITE_API_URL=https://<render-app>`
4. Deploy and open the frontend URL.

## 4) Post-deploy Smoke Test

1. Register a user in UI.
2. Login and verify token-authenticated actions work.
3. Save rules.
4. Run a PCAP process with a valid input path on backend host.
5. Check history entries appear.

## Notes

- Supabase is required for persistence (`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`).
- Uploaded/output runtime files are ignored in git and should be attached to persistent disk if required.

## Live Streaming Mode

- New endpoints:
   - `POST /api/dpi/stream/start`
   - `GET /api/dpi/stream/status`
   - `POST /api/dpi/stream/stop`
- Frontend includes a `Streaming` dashboard tab for start/stop and live telemetry.
- Python dependency: `scapy` (included in `python_engine/requirements.txt`).
- Windows requirement: install Npcap for interface capture support. Without Npcap/libpcap, live capture cannot sniff packets.
- If needed, set `PYTHON_BIN` to your `python_engine` venv interpreter; backend now auto-detects `python_engine/.venv` when available.
