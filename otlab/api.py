"""Local evidence analysis API. Run bound to 127.0.0.1 only.

This endpoint accepts instrumented evidence, not PCAP uploads. No LLM or Kafka yet.
"""
import json
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal
from .policy import validate
from .storage import Store, EvidenceConflict


class Evidence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    event_id: str = Field(min_length=1, max_length=128)
    source: str = Field(max_length=15)
    request_hex: str = Field(min_length=16, max_length=520)
    response_hex: str | None = Field(default=None, max_length=520)
    evidence_kind: Literal['application_instrumented', 'packet_capture']


def create_app(database=None, policy_path=None):
    root = Path(__file__).resolve().parents[1]
    policy_path = policy_path or root / 'config/conveyor-policy.json'
    policy = validate(json.loads(Path(policy_path).read_text()))
    store = Store(database or os.environ.get('OTLAB_DB', str(root / 'runtime/findings.sqlite3')), policy)
    app = FastAPI(title='OT Lab — Modbus policy evidence', version='0.2.0')

    @app.get('/health')
    def health():
        return {'status': 'ready', 'detection': 'policy_rules', 'ai': 'not_implemented',
                'transport': 'direct_http', 'storage': 'sqlite'}

    @app.post('/events')
    def ingest(evidence: Evidence):
        try:
            result, created = store.ingest(evidence.model_dump())
        except EvidenceConflict as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except (ValueError, KeyError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return {'created': created, 'result': result}

    @app.get('/findings')
    def findings(limit: int = Query(default=100, ge=1, le=1000)):
        return {'items': store.list(limit)}

    return app
