# Packet Analyzer

## What Is DPI?

DPI (Deep Packet Inspection) means inspecting packet content and metadata beyond basic IP routing headers.

In this project, DPI is used to:

- classify traffic by app/domain (for example YouTube, Google, Facebook)
- apply blocking policies (IP, app, domain wildcard, port)
- track processing stats (total, forwarded, dropped, drop rate)
- generate reports from processed traffic runs

## Project Stack

- Frontend: React + Vite in `frontend`
- Backend API: Node + Express in `node_backend`
- DPI engine: Python in `python_engine`
- Database: Supabase (required)

## Folder Purpose

- `node_backend/uploads`:
  - runtime upload directory for `.pcap` files sent from UI/API
  - needed by upload/analyze routes
- `node_backend/outputs`:
  - runtime output directory for generated `.pcap` and streaming output
  - needed for result downloads and live stream output

These folders are required at runtime. Keep them in repo with `.gitkeep`, but do not commit generated `.pcap` artifacts.

## Prerequisites

- Windows 10/11
- Node.js 20+
- Python 3.10+
- Supabase project (with schema applied)
- Optional for live capture on Windows: Npcap

## One-Time Setup

### 1) Supabase setup

1. Create a Supabase project.
2. Open SQL Editor.
3. Run `supabase/schema.sql`.
4. Copy:
   - project URL -> `SUPABASE_URL`
   - service role key -> `SUPABASE_SERVICE_ROLE_KEY`

### 2) Backend setup

```powershell
cd node_backend
copy .env.example .env
npm install
```

Edit `node_backend/.env` and set at least:

- `JWT_SECRET`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

### 3) Frontend setup

```powershell
cd frontend
copy .env.example .env
npm install
```

Set `VITE_API_URL` in `frontend/.env` (for local use `http://localhost:8000`).

### 4) Python setup

```powershell
cd python_engine
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run Locally

Open separate terminals.

### 1) Start backend

```powershell
cd node_backend
npm start
```

Backend health: `http://localhost:8000/api/health`

### 2) Start frontend

```powershell
cd frontend
npm run dev
```

Frontend: `http://localhost:5173`

## Quick Smoke Test

1. Open frontend.
2. Register a user.
3. Login.
4. Upload `test_dpi.pcap` in analysis/testing flow.
5. Confirm run appears in report/history.
6. Confirm records in Supabase tables (`users`, `dpi_runs`).

## Auth and Roles

- login/register via JWT auth
- viewer: analysis/report access
- admin: rules, DPI run, streaming, user management

## Deployment

Use:

- `render.yaml` for backend deployment
- `vercel.json` for frontend deployment
- `DEPLOYMENT.md` for end-to-end production steps
