"""Bounded real HTTP + SQLite persistence check. Requires baseline dependencies."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from otlab.demo import run


def verify():
    root = Path(__file__).resolve().parent
    output = root / 'runtime' / ('api-check-' + uuid.uuid4().hex[:12])
    run(output / 'demo')
    events = [json.loads(line) for line in (output / 'demo/events.jsonl').read_text().splitlines()]
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    env = dict(os.environ, OTLAB_DB=str(output / 'findings.sqlite3'))
    log = (output / 'api.log').open('w')
    process = None

    def request(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url + path, data=data, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    def start():
        child = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'otlab.api:create_app',
                                  '--factory', '--host', '127.0.0.1', '--port', str(port)],
                                 cwd=root, env=env, stdout=log, stderr=log,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for _ in range(50):
            if child.poll() is not None:
                raise RuntimeError('API exited; inspect api.log')
            try:
                if request('/health')[0] == 200:
                    return child
            except (OSError, ValueError):
                time.sleep(.1)
        child.terminate()
        child.wait(timeout=5)
        raise RuntimeError('API startup timed out')

    try:
        process = start()
        bodies = []
        for event in events:
            body = {key: event[key] for key in ('event_id', 'source', 'request_hex', 'response_hex', 'evidence_kind')}
            bodies.append(body)
            status, response = request('/events', body)
            assert status == 200 and response['created']
            assert response['result']['finding'] == event['finding']
            assert response['result']['response_status'] == event['response_status']
        status, retry = request('/events', bodies[0])
        assert status == 200 and retry['created'] is False
        conflict_status, _ = request('/events', {**bodies[0], 'source': '127.0.0.3'})
        assert conflict_status == 409
        invalid_status, _ = request('/events', {**bodies[0], 'event_id': 'invalid', 'request_hex': 'zz' * 12})
        assert invalid_status == 422
        process.terminate()
        process.wait(timeout=5)
        process = start()
        status, saved = request('/findings')
        assert status == 200 and len(saved['items']) == len(events)
        report = {'events_analyzed': len(events), 'policy_results_match_live_demo': True,
                  'duplicate_created': False, 'conflicting_event_status': conflict_status,
                  'invalid_evidence_status': invalid_status,
                  'persisted_after_restart': len(saved['items']),
                  'transport': 'actual HTTP on IPv4 loopback', 'ai': 'not implemented',
                  'capture': 'application evidence only; Npcap capture needs elevation'}
        (output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        print('Evidence folder:', output)
    finally:
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        log.close()


if __name__ == '__main__':
    verify()
