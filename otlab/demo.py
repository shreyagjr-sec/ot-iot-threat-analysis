"""Run a bounded live-TCP experiment: python -m otlab.demo."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import socket
import subprocess
import struct
import threading
import time
import uuid
from .protocol import Stream, decode, frame, response_status
from .policy import evaluate, validate
from .simulator import Server


# Ground truth is authored independently of the policy evaluator.
CASES = [
    ('normal_start', '127.0.0.2', 1, '0600000001', False),
    ('normal_speed', '127.0.0.2', 1, '0600010032', False),
    ('lower_boundary', '127.0.0.2', 1, '0600010000', False),
    ('upper_boundary', '127.0.0.2', 1, '0600010064', False),
    ('unapproved_source', '127.0.0.3', 1, '0600010032', True),
    ('excess_speed', '127.0.0.2', 1, '0600010065', True),
    ('invalid_run_command', '127.0.0.2', 1, '0600000002', True),
    ('combined_violation', '127.0.0.3', 1, '06000100c8', True),
    ('valid_multiple', '127.0.0.2', 1, '10000000020400010032', False),
    ('invalid_multiple', '127.0.0.2', 1, '100000000204000100c8', True),
    ('read_only_register_write', '127.0.0.2', 1, '0600020001', True),
    ('normal_read', '127.0.0.2', 1, '0300000003', None),
    ('unconfigured_unit', '127.0.0.2', 2, '0600010032', None),
    ('normal_stop', '127.0.0.2', 1, '0600000000', False),
]


def run(output, repeats=1, capture_tool=None):
    root = Path(__file__).resolve().parents[1]
    policy_path = root / 'config/conveyor-policy.json'
    policy_bytes = policy_path.read_bytes()
    policy = validate(json.loads(policy_bytes))
    server = Server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    events = []
    run_id = uuid.uuid4().hex
    capture = None
    capture_log = None
    try:
        if capture_tool:
            output.mkdir(parents=True, exist_ok=True)
            capture_log = (output / 'capture.log').open('w', encoding='utf-8')
            capture = subprocess.Popen([
                str(capture_tool), '-i', r'\Device\NPF_Loopback',
                '-f', f'tcp port {server.server_address[1]}',
                '-a', 'duration:6', '-w', str(output / 'traffic.pcapng')],
                stdout=capture_log, stderr=capture_log,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            time.sleep(1)
            if capture.poll() is not None:
                raise RuntimeError('Capture could not start; inspect capture.log')
        for repeat in range(repeats):
            for index, (name, source, unit, hex_pdu, expected) in enumerate(CASES):
                transaction = index + 1
                raw = frame(transaction, unit, bytes.fromhex(hex_pdu))
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.settimeout(3)
                    client.bind((source, 0))
                    client.connect(server.server_address)
                    observed_source = client.getsockname()[0]
                    start = time.perf_counter_ns()
                    # Two application sends exercise fragmented input safely;
                    # TCP may merge them, so unit tests also force every split.
                    client.sendall(raw[:4])
                    client.sendall(raw[4:])
                    stream, replies = Stream(), []
                    while not replies:
                        data = client.recv(4096)
                        if not data:
                            raise RuntimeError('Server closed without response')
                        replies.extend(stream.feed(data))
                    response = replies[0]
                    request = decode(raw)
                    rule_start = time.perf_counter_ns()
                    finding = evaluate(request, observed_source, policy)
                    rule_us = (time.perf_counter_ns() - rule_start) / 1000
                    outcome = response_status(request, response)
                    roundtrip_us = (time.perf_counter_ns() - start) / 1000
                events.append(dict(event_id=f'{run_id}:{repeat}:{name}',
                                   evidence_kind='application_instrumented',
                                   case=name, repeat=repeat, source=observed_source,
                                   request_hex=raw.hex(), response_hex=response.hex(),
                                   expected_violation=expected, response_status=outcome,
                                   finding=finding, rule_processing_us=rule_us,
                                   request_response_and_rule_us=roundtrip_us))
        scored = [e for e in events if e['expected_violation'] is not None]
        tp = sum(e['expected_violation'] and e['finding']['verdict'] == 'policy_violation' for e in scored)
        fp = sum(not e['expected_violation'] and e['finding']['verdict'] == 'policy_violation' for e in scored)
        fn = sum(e['expected_violation'] and e['finding']['verdict'] != 'policy_violation' for e in scored)
        tn = len(scored) - tp - fp - fn
        def percentiles(key):
            values = sorted(e[key] for e in events)
            return {'p50': values[(len(values) - 1) // 2],
                    'p95': values[min(len(values) - 1, int(len(values) * .95))]}
        summary = dict(created_utc=datetime.now(timezone.utc).isoformat(),
                       python=platform.python_version(), platform=platform.platform(),
                       policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
                       events=len(events), scored_events=len(scored),
                       excluded_events=len(events)-len(scored),
                       confusion_matrix={'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn},
                       precision=tp/(tp+fp) if tp+fp else None,
                       recall=tp/(tp+fn) if tp+fn else None,
                       false_positive_rate=fp/(fp+tn) if fp+tn else None,
                       rule_processing_us=percentiles('rule_processing_us'),
                       request_response_and_rule_us=percentiles('request_response_and_rule_us'),
                       traffic='Actual loopback TCP; application-instrumented, not packet-captured',
                       limitations=['Hand-authored lab cases, not independent public-dataset validation',
                                    'No Kafka, PCAP parser, LLM, or production latency measurement',
                                    'Acknowledgement proves protocol acceptance, not physical actuation',
                                    'Source IP allowlist is not authentication'])
        if capture:
            if capture.wait(timeout=10) != 0:
                raise RuntimeError('Capture failed; inspect capture.log')
            summary['capture_file'] = 'traffic.pcapng'
            summary['capture_port'] = server.server_address[1]
            summary['traffic'] = 'Actual loopback TCP with dumpcap PCAPNG and application evidence'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'events.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(summary, indent=2))
        if fp or fn:
            raise AssertionError('Unexpected policy result; inspect event evidence')
        return summary
    finally:
        if capture and capture.poll() is None:
            capture.terminate()
            capture.wait(timeout=5)
        if capture_log:
            capture_log.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path('runtime/conveyor-demo'))
    parser.add_argument('--repeats', type=int, default=1)
    parser.add_argument('--capture-tool', type=Path, help='Optional path to Windows dumpcap.exe; loopback only')
    args = parser.parse_args()
    if not 1 <= args.repeats <= 100:
        parser.error('repeats must be within 1..100')
    run(args.output, args.repeats, args.capture_tool)
