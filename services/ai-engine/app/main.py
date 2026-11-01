"""CodeGate AI engine — FastAPI service for explanation and triage (cahier §9.4).

Deterministic analysis happens upstream (TypeScript/Rust). This service only
makes risks understandable; it never decides allow/block.
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from .explain import Finding, explain

app = FastAPI(title="CodeGate AI Engine", version="0.1.0")


class ExplainRequest(BaseModel):
    type: str
    severity: str
    title: str
    description: str
    file_path: str | None = None
    line: int | None = None
    rule_id: str | None = None
    remediation: str | None = None


class ExplainResponse(BaseModel):
    explanation: str
    source: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/explain", response_model=ExplainResponse)
def explain_endpoint(req: ExplainRequest) -> ExplainResponse:
    finding = Finding(**req.model_dump())
    result = explain(finding)
    return ExplainResponse(**result)
