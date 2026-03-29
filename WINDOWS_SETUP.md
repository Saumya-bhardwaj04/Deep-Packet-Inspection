# Windows Setup Guide

This project runs as a React + Node + Python stack.

You do not need C++ compiler setup for normal usage.

For full setup and run steps, use [README.md](README.md).

## Quick Windows Checklist

1. Install Node.js 20+
2. Install Python 3.10+
3. Create Supabase project and apply `supabase/schema.sql`
4. Configure `node_backend/.env` from `node_backend/.env.example`
5. Configure `frontend/.env` from `frontend/.env.example`
6. Install dependencies and run:

```powershell
cd node_backend
npm install
npm start
```

```powershell
cd frontend
npm install
npm run dev
```

```powershell
cd python_engine
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Live Capture on Windows

If you want live interface sniffing, install Npcap and restart backend.

- Download: https://npcap.com/
- Install with WinPcap compatibility mode enabled.

Without Npcap, file-based `.pcap` processing still works.
