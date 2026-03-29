from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from dpi_engine import DPIEngine, RuleManager
from dpi_engine.types import AppType


class RulePayload(BaseModel):
    blocked_ips: list[str] = Field(default_factory=list)
    blocked_apps: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    blocked_ports: list[int] = Field(default_factory=list)


class ProcessPayload(BaseModel):
    input_file: str
    output_file: str


app = FastAPI(title="DPI Python Engine", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

rule_manager = RuleManager()
engine = DPIEngine(rule_manager=rule_manager)


@app.get("/api/health")
def health() -> dict:
    return {"ok": True}


@app.get("/api/apps")
def apps() -> dict:
    return {"apps": [a.value for a in AppType]}


@app.get("/api/rules")
def get_rules() -> dict:
    return rule_manager.to_dict()


@app.post("/api/rules")
def set_rules(payload: RulePayload) -> dict:
    rule_manager.update_from_payload(payload.model_dump())
    return {"ok": True, "rules": rule_manager.to_dict()}


@app.post("/api/rules/load")
def load_rules(file_path: str) -> dict:
    path = Path(file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Rules file not found")
    rule_manager.load_from_file(path)
    return {"ok": True, "rules": rule_manager.to_dict()}


@app.post("/api/rules/save")
def save_rules(file_path: str) -> dict:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rule_manager.save_to_file(path)
    return {"ok": True, "file": str(path)}


@app.post("/api/process")
def process_pcap(payload: ProcessPayload) -> dict:
    in_path = Path(payload.input_file)
    if not in_path.exists():
        raise HTTPException(status_code=404, detail="Input PCAP file not found")

    out_path = Path(payload.output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        result = engine.process_file(in_path, out_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Processing failed: {exc}") from exc

    return {
        "ok": True,
        "input_file": result.input_file,
        "output_file": result.output_file,
        "stats": result.stats,
    }
