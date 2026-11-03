"""Validate the bounded demo PCAP using tshark TCP stream reconstruction.

Supports the demo's one-transaction-per-connection layout only. Not a general
PCAP ingestion worker. No administrator access needed to read an existing PCAP.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from otlab.policy import evaluate, validate
from otlab.protocol import Stream, decode, response_status


def command(tool, *args):
    result = subprocess.run([str(tool), *args], capture_output=True, text=True,
                            timeout=30, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout


def verify(folder, tshark):
    capture = folder / 'traffic.pcapng'
    summary = json.loads((folder / 'summary.json').read_text())
    expected = [json.loads(line) for line in (folder / 'events.jsonl').read_text().splitlines()]
    policy = validate(json.loads((Path(__file__).parent / 'config/conveyor-policy.json').read_text()))
    port = summary['capture_port']
    streams = command(tshark, '-r', str(capture), '-Y', f'tcp.port == {port}',
                      '-T', 'fields', '-e', 'tcp.stream')
    ids = sorted({int(line.strip()) for line in streams.splitlines() if line.strip()})
    if len(ids) != len(expected):
        raise AssertionError(f'Expected {len(expected)} connections, captured {len(ids)}')
    remaining = {e['request_hex']: e for e in expected}
    if len(remaining) != len(expected):
        raise ValueError('Verifier requires unique request ADUs (single demo run)')
    checks = []
    captured_events = []
    capture_hash = hashlib.sha256(capture.read_bytes()).hexdigest()
    for stream_id in ids:
        output = command(tshark, '-r', str(capture), '-q', '-z', f'follow,tcp,raw,{stream_id}')
        nodes, data = {}, [bytearray(), bytearray()]
        for line in output.splitlines():
            match = re.fullmatch(r'Node ([01]): ([0-9.]+):(\d+)', line)
            if match:
                nodes[int(match[1])] = (match[2], int(match[3]))
            elif re.fullmatch(r'\t?[0-9a-fA-F]+', line):
                node = 1 if line.startswith('\t') else 0
                data[node].extend(bytes.fromhex(line.strip()))
        if len(nodes) != 2:
            raise AssertionError('Could not parse tshark stream endpoints')
        servers = [node for node, endpoint in nodes.items() if endpoint == ('127.0.0.1', port)]
        if len(servers) != 1:
            raise AssertionError('Unexpected server endpoint')
        server = servers[0]
        source = nodes[1 - server][0]
        frames = []
        for node_data in (data[1 - server], data[server]):
            framing = Stream()
            decoded = framing.feed(node_data)
            framing.finish()
            if len(decoded) != 1:
                raise AssertionError('Verifier supports exactly one request and one response per connection')
            frames.append(decoded[0])
        request_raw, response_raw = frames
        event = remaining.pop(request_raw.hex(), None)
        if event is None:
            raise AssertionError('Captured request does not match a unique expected event')
        if source != event['source'] or response_raw.hex() != event['response_hex']:
            raise AssertionError(f"Captured source or response differs for {event['case']}")
        request = decode(request_raw)
        finding = evaluate(request, source, policy)
        status = response_status(request, response_raw)
        if finding != event['finding'] or status != event['response_status']:
            raise AssertionError(f"Policy or response classification differs for {event['case']}")
        checks.append({'case': event['case'], 'tcp_stream': stream_id,
                       'source': source, 'request_bytes_match': True,
                       'response_bytes_match': True, 'finding': finding,
                       'response_status': status})
        captured_events.append({'event_id': f'pcap:{capture_hash}:{stream_id}',
                                'source': source, 'request_hex': request_raw.hex(),
                                'response_hex': response_raw.hex(),
                                'evidence_kind': 'packet_capture'})
    if remaining:
        raise AssertionError('Some expected transactions are absent from capture')
    packet_rows = command(tshark, '-r', str(capture), '-T', 'fields', '-e', 'frame.number')
    report = {'capture_sha256': capture_hash,
              'packets': len([line for line in packet_rows.splitlines() if line.strip()]),
              'connections_checked': len(checks), 'all_expected_bytes_match': True,
              'policy_results_match': True,
              'reassembly': 'Wireshark tshark follow,tcp,raw; ordered directional stream bytes',
              'tshark_version': command(tshark, '--version').splitlines()[0],
              'limitations': ['Bounded demo verifier, not general PCAP ingestion',
                              'One transaction per TCP connection',
                              'Policy classification uses the same detector; ground truth remains authored lab cases',
                              'Not a public-dataset or production performance evaluation'],
              'checks': checks}
    (folder / 'capture-verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (folder / 'captured-events.jsonl').write_text(
        ''.join(json.dumps(event) + '\n' for event in captured_events), encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'checks'}, indent=2))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--folder', type=Path, default=Path('runtime/capture-validation'))
    parser.add_argument('--tshark', type=Path, default=Path(r'E:\Wireshark\tshark.exe'))
    args = parser.parse_args()
    verify(args.folder, args.tshark)
