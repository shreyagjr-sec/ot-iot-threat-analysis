"""Bounded real broker + live Modbus + consumer recovery + SQLite + API check."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import uuid
from kafka import KafkaConsumer, TopicPartition
from otlab.broker import Broker, ROOT, available_port
from otlab.demo import run
from otlab.storage import Store
from otlab.streaming import INPUT, RESULTS, REJECTED, ensure_topics, producer, publish, consume


def collect(bootstrap, topic, count):
    reader = KafkaConsumer(bootstrap_servers=bootstrap, enable_auto_commit=False,
                           auto_offset_reset='earliest')
    try:
        reader.assign([TopicPartition(topic, 0)])
        reader.seek_to_beginning()
        values = []
        deadline = time.monotonic() + 15
        while len(values) < count and time.monotonic() < deadline:
            for messages in reader.poll(timeout_ms=500).values():
                values.extend(json.loads(message.value) for message in messages)
        assert len(values) == count, (topic, len(values), count)
        return values
    finally:
        reader.close()


def verify():
    output = ROOT / 'runtime' / ('kafka-check-' + uuid.uuid4().hex[:12])
    broker = Broker(output / 'broker', available_port(), available_port())
    bootstrap = f'127.0.0.1:{broker.port}'
    database = output / 'findings.sqlite3'
    group = 'recovery-check'
    sender = None
    api = None
    api_log = None
    try:
        broker.start()
        ensure_topics(bootstrap)
        sender = producer(bootstrap)
        run(output / 'demo', on_event=lambda event: publish(sender, event))
        events = [json.loads(line) for line in (output / 'demo/events.jsonl').read_text().splitlines()]
        publish(sender, events[0])
        publish(sender, {**events[0], 'source': '127.0.0.3'})
        sender.send(INPUT, value=b'{invalid json').get(timeout=20)
        sender.close(timeout=10)
        sender = None
        # Deliberately stop after first database commit and before Kafka offset commit.
        try:
            consume(bootstrap, database, group, 1, crash_after_store=True)
        except RuntimeError as error:
            if str(error) != 'INJECTED_FAILURE_AFTER_SQLITE_COMMIT':
                raise
        else:
            raise AssertionError('Fault injection did not run')
        policy = json.loads((ROOT / 'config/conveyor-policy.json').read_text())
        assert len(Store(database, policy).list()) == 1
        processed = consume(bootstrap, database, group, 17)
        assert processed == {'processed': 17, 'created': 13, 'duplicates': 2, 'rejected': 2}, processed
        findings = Store(database, policy).list()
        assert len(findings) == 14
        expected = {e['event_id']: e for e in events}
        assert all(item['finding'] == expected[item['event_id']]['finding'] for item in findings)
        results = collect(bootstrap, RESULTS, 15)
        rejected = collect(bootstrap, REJECTED, 2)
        assert len({item['event_id'] for item in results}) == 14
        reader = KafkaConsumer(bootstrap_servers=bootstrap, group_id=group, enable_auto_commit=False)
        try:
            committed = reader.committed(TopicPartition(INPUT, 0))
            assert committed == 17
        finally:
            reader.close()
        captured_count = 0
        final_committed = committed
        capture_folder = ROOT / 'runtime/capture-validation'
        if (capture_folder / 'traffic.pcapng').exists():
            from verify_capture import verify as verify_capture
            verify_capture(capture_folder, Path(r'E:\Wireshark\tshark.exe'))
            captured = [json.loads(line) for line in (capture_folder / 'captured-events.jsonl').read_text().splitlines()]
            sender = producer(bootstrap)
            for event in captured:
                publish(sender, event)
            sender.close(timeout=10)
            sender = None
            capture_result = consume(bootstrap, database, group, len(captured))
            assert capture_result['created'] == len(captured) and capture_result['rejected'] == 0
            captured_count = len(captured)
            saved_capture = [item for item in Store(database, policy).list() if item['evidence_kind'] == 'packet_capture']
            assert len(saved_capture) == captured_count
            assert sum(item['finding']['verdict'] == 'policy_violation' for item in saved_capture) == 6
            collect(bootstrap, RESULTS, 15 + captured_count)
            checkpoint = KafkaConsumer(bootstrap_servers=bootstrap, group_id=group, enable_auto_commit=False)
            try:
                final_committed = checkpoint.committed(TopicPartition(INPUT, 0))
                assert final_committed == 17 + captured_count
            finally:
                checkpoint.close()
        port = available_port()
        api_log = (output / 'api.log').open('w')
        api = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'otlab.api:create_app',
                                '--factory', '--host', '127.0.0.1', '--port', str(port)],
                               cwd=ROOT, env=dict(os.environ, OTLAB_DB=str(database)),
                               stdout=api_log, stderr=api_log,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for _ in range(50):
            if api.poll() is not None:
                raise RuntimeError('API exited; inspect api.log')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/findings', timeout=2) as response:
                    fetched = json.load(response)['items']
                break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('API startup timed out')
        assert len(fetched) == 14 + captured_count
        report = {'broker': 'Apache Kafka 4.1.2, single-node KRaft, IPv4 loopback',
                  'client': 'kafka-python 3.0.12', 'live_modbus_events_published': 14,
                  'recovery_test_input_records': 17, 'total_input_records': 17 + captured_count,
                  'consumer_recovery': processed,
                  'fault_injection': 'stopped after SQLite commit before result publication and offset commit',
                  'recovery_preserved_unique_findings': 14, 'kafka_result_records': 15 + captured_count,
                  'rejected_records': len(rejected), 'committed_input_offset': final_committed,
                  'api_findings_returned': len(fetched), 'policy_matches_demo': True,
                  'captured_transactions_published_and_saved': captured_count,
                  'delivery': 'at-least-once; SQLite deduplicates, Kafka results may repeat',
                  'limitations': ['Capture reconstruction supports bounded demo only, not arbitrary PCAP ingestion',
                                  'Single local broker, no high availability',
                                  'Controlled worker failure, not power-loss durability validation',
                                  'No LLM, public dataset, or throughput benchmark yet']}
        (output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
        print('Evidence folder:', output)
        return output
    finally:
        if sender:
            sender.close(timeout=10)
        if api and api.poll() is None:
            api.terminate()
            api.wait(timeout=5)
        if api_log:
            api_log.close()
        broker.stop()


if __name__ == '__main__':
    verify()
