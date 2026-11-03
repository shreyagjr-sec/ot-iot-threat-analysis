"""SQLite-backed analysis, idempotent per evidence ID and exact content."""
import hashlib
import ipaddress
import json
from pathlib import Path
import sqlite3
from contextlib import contextmanager
from .protocol import decode, response_status
from .policy import evaluate


class EvidenceConflict(ValueError):
    pass


class Store:
    def __init__(self, path, policy):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        with self.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS findings (
                event_id TEXT PRIMARY KEY, evidence_hash TEXT NOT NULL,
                policy_hash TEXT NOT NULL, result TEXT NOT NULL,
                created_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))''')

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def ingest(self, evidence):
        event_id = evidence['event_id']
        if not isinstance(event_id, str) or not 1 <= len(event_id) <= 128:
            raise ValueError('event_id must have 1..128 characters')
        source = str(ipaddress.IPv4Address(evidence['source']))
        request_hex, response_hex = evidence['request_hex'], evidence.get('response_hex')
        if not isinstance(request_hex, str) or len(request_hex) > 520:
            raise ValueError('Invalid request hex length')
        if response_hex is not None and (not isinstance(response_hex, str) or len(response_hex) > 520):
            raise ValueError('Invalid response hex length')
        raw = bytes.fromhex(request_hex)
        request = decode(raw)
        response = bytes.fromhex(response_hex) if response_hex is not None else None
        normalized = {'source': source, 'request_hex': raw.hex(),
                      'response_hex': response.hex() if response is not None else None,
                      'evidence_kind': evidence['evidence_kind']}
        if normalized['evidence_kind'] not in ('application_instrumented', 'packet_capture'):
            raise ValueError('Unknown evidence kind')
        digest = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
        policy_hash = hashlib.sha256(json.dumps(self.policy, sort_keys=True).encode()).hexdigest()
        result = {'event_id': event_id, **normalized,
                  'transaction': request.transaction, 'unit': request.unit,
                  'function': request.function, 'address': request.address,
                  'quantity': request.quantity, 'values': list(request.values),
                  'finding': evaluate(request, source, self.policy),
                  'response_status': response_status(request, response) if response is not None else 'not_observed',
                  'policy_sha256': policy_hash}
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT evidence_hash, policy_hash, result FROM findings WHERE event_id=?', (event_id,)).fetchone()
            if existing:
                if existing[:2] != (digest, policy_hash):
                    raise EvidenceConflict('Event ID already exists with different evidence or policy')
                return json.loads(existing[2]), False
            db.execute('INSERT INTO findings(event_id,evidence_hash,policy_hash,result) VALUES(?,?,?,?)',
                       (event_id, digest, policy_hash, json.dumps(result)))
        return result, True

    def list(self, limit=100):
        if not 1 <= limit <= 1000:
            raise ValueError('limit must be within 1..1000')
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute(
                'SELECT result FROM findings ORDER BY rowid DESC LIMIT ?', (limit,))]
