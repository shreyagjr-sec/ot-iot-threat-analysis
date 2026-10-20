"""Bounded loopback-only integration check; no production traffic required."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import requests
import struct


def synthetic_pcapng():
    """One generated Ethernet/IPv4/UDP frame using documentation-only IPs."""
    def block(kind, body):
        length = len(body) + 12
        return struct.pack('<II', kind, length) + body + struct.pack('<I', length)
    payload = b'OT-IOT-SYNTHETIC-TEST'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28+len(payload), 1, 0, 64, 17, 0,
                     bytes([192,0,2,1]), bytes([192,0,2,2]))
    total = sum(struct.unpack('!10H', ip))
    total = (total & 65535) + (total >> 16)
    checksum = (~total) & 65535
    ip = ip[:10] + struct.pack('!H', checksum) + ip[12:]
    packet = bytes.fromhex('0200000000020200000000010800') + ip + struct.pack('!HHHH', 12000, 12001, 8+len(payload), 0) + payload
    padded = packet + b'\0' * ((-len(packet)) % 4)
    return (block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)) +
            block(1, struct.pack('<HHI', 1, 0, 65535)) +
            block(6, struct.pack('<IIIII', 0, 0, 0, len(packet), len(packet)) + padded))


def verify():
    root = Path(__file__).resolve().parent
    run = root / 'runtime' / time.strftime('%Y%m%d-%H%M%S')
    buffer = run / 'buffer'
    received = run / 'received'
    run.mkdir(parents=True)
    env = dict(os.environ, RECEIVED_DIR=str(received), WATCH_DIR=str(buffer),
               CAPTURE_INTERFACE='1', CAPTURE_WINDOW_SECONDS='3',
               CAPTURE_DURATION_SECONDS='12', CAPTURE_FILTER='tcp port 18765',
               AI_API_URL='http://127.0.0.1:18765/analyze', PYTHONUNBUFFERED='1')
    children = []
    logs = []
    def start(args, name):
        log = (run / (name + '.log')).open('w')
        logs.append(log)
        p = subprocess.Popen(args, cwd=root, env=env, stdout=log, stderr=log,
                             creationflags=subprocess.CREATE_NO_WINDOW)
        children.append(p)
        return p
    try:
        start([sys.executable, '-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', '18765'], 'receiver')
        url = 'http://127.0.0.1:18765'
        for _ in range(50):
            try:
                assert requests.get(url, timeout=1).json()['status'] == 'receiver ready'
                break
            except (requests.RequestException, AssertionError):
                time.sleep(.2)
        else:
            raise RuntimeError('Receiver failed to start')
        if '--live' in sys.argv:
            capture = start([sys.executable, 'capture_agent.py'], 'capture')
            while capture.poll() is None:
                requests.get(url, timeout=2)
                time.sleep(.25)
            assert capture.returncode == 0, 'Capture failed; see capture.log'
        else:
            buffer.mkdir(parents=True)
            for i in range(4):
                path = buffer / f'synthetic-{i}.pcapng'
                path.write_bytes(synthetic_pcapng())
                os.utime(path, (time.time()+i, time.time()+i))
        files = sorted(buffer.glob('*.pcapng'), key=lambda p: p.stat().st_mtime)
        assert len(files) >= 2, 'Expected multiple rotated capture files'
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        sender = start([sys.executable, 'pipeline_sender.py'], 'sender')
        for _ in range(100):
            if len(list(received.glob('*.pcapng'))) == len(files)-1:
                break
            time.sleep(.2)
        sender.terminate()
        sender.wait(timeout=5)
        delivered = list(received.glob('*.pcapng'))
        assert len(delivered) == len(files)-1
        assert len(list(buffer.glob('*.pcapng'))) == 1
        assert all(hashlib.sha256(p.read_bytes()).hexdigest() == hashes[p.name] for p in delivered)
        with delivered[0].open('rb') as handle:
            duplicate = requests.post(url+'/analyze', files={'file': (delivered[0].name, handle)}, timeout=5)
        assert duplicate.status_code == 409
        invalid = requests.post(url+'/analyze', files={'file': ('invalid.txt', b'example')}, timeout=5)
        assert invalid.status_code == 400
        with delivered[0].open('rb') as handle:
            upload = requests.post(url+'/analyze', files={'file': ('verification-copy.pcapng', handle)}, timeout=5)
        assert upload.status_code == 200
        assert upload.json()['verdict'] == 'NOT_ANALYZED'
        report = dict(date=time.strftime('%Y-%m-%d'), traffic='Loopback capture' if '--live' in sys.argv else 'Generated PCAPNG fixtures; no live traffic captured',
                      input_chunks=len(files), forwarded_chunks=len(delivered),
                      byte_integrity='PASS: SHA-256 matches for every forwarded chunk',
                      acknowledged_sources_removed=True, newest_chunk_retained=True,
                      duplicate_upload_status=duplicate.status_code, invalid_extension_status=invalid.status_code,
                      receiver_response=upload.json(), analysis='Not implemented: NOT_ANALYZED is a placeholder')
        out = root / 'docs'
        out.mkdir(exist_ok=True)
        (out/'verification.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
    finally:
        for p in reversed(children):
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=10)
        for log in logs:
            log.close()


if __name__ == '__main__':
    verify()
