"""Kafka evidence transport, durable detection, results, and rejected messages.

At-least-once processing. SQLite deduplicates by event ID; Kafka results may repeat.
"""
import argparse
import json
from pathlib import Path
import time
from kafka import KafkaProducer, KafkaConsumer, TopicPartition
from kafka.admin import KafkaAdminClient, NewTopic
from kafka.errors import TopicAlreadyExistsError
from kafka.structs import OffsetAndMetadata
from .policy import validate
from .storage import Store

INPUT = 'ot.evidence'
RESULTS = 'ot.analysis.results'
REJECTED = 'ot.evidence.rejected'
EVIDENCE_KEYS = ('event_id', 'source', 'request_hex', 'response_hex', 'evidence_kind')


def ensure_topics(bootstrap):
    admin = KafkaAdminClient(bootstrap_servers=bootstrap, request_timeout_ms=10000)
    try:
        for name in (INPUT, RESULTS, REJECTED):
            try:
                admin.create_topics([NewTopic(name, 1, 1)])
            except TopicAlreadyExistsError:
                pass
    finally:
        admin.close()


def producer(bootstrap):
    return KafkaProducer(bootstrap_servers=bootstrap, acks='all', retries=5,
                         max_in_flight_requests_per_connection=1,
                         request_timeout_ms=10000, max_block_ms=15000)


def publish(client, event):
    evidence = {key: event[key] for key in EVIDENCE_KEYS}
    metadata = client.send(INPUT, key=evidence['event_id'].encode(),
                           value=json.dumps(evidence).encode()).get(timeout=20)
    return metadata


def process_value(raw, store):
    if len(raw) > 16384:
        raise ValueError('Evidence message exceeds 16 KiB')
    evidence = json.loads(raw)
    if not isinstance(evidence, dict) or set(evidence) - set(EVIDENCE_KEYS):
        raise ValueError('Expected an evidence object with known fields')
    return store.ingest(evidence)


def consume(bootstrap, database, group, count, timeout=45, crash_after_store=False):
    root = Path(__file__).resolve().parents[1]
    policy = validate(json.loads((root / 'config/conveyor-policy.json').read_text()))
    store = Store(database, policy)
    consumer = KafkaConsumer(INPUT, bootstrap_servers=bootstrap, group_id=group,
                             auto_offset_reset='earliest', enable_auto_commit=False,
                             max_poll_records=1, request_timeout_ms=30000,
                             session_timeout_ms=10000)
    output = producer(bootstrap)
    report = {'processed': 0, 'created': 0, 'duplicates': 0, 'rejected': 0}
    deadline = time.monotonic() + timeout
    try:
        while report['processed'] < count and time.monotonic() < deadline:
            batches = consumer.poll(timeout_ms=500, max_records=1)
            for partition, messages in batches.items():
                for message in messages:
                    try:
                        result, created = process_value(message.value, store)
                    except (ValueError, KeyError, TypeError) as error:
                        failure = {'source_topic': message.topic, 'partition': message.partition,
                                   'offset': message.offset, 'error': str(error),
                                   'raw_hex': message.value[:16384].hex()}
                        output.send(REJECTED, value=json.dumps(failure).encode()).get(timeout=20)
                        report['rejected'] += 1
                    else:
                        if crash_after_store:
                            # Fault injection: database committed, Kafka offset deliberately uncommitted.
                            raise RuntimeError('INJECTED_FAILURE_AFTER_SQLITE_COMMIT')
                        output.send(RESULTS, key=result['event_id'].encode(),
                                    value=json.dumps(result).encode()).get(timeout=20)
                        report['created' if created else 'duplicates'] += 1
                    # Commit only this message after durable DB + result publication or rejection publication.
                    consumer.commit({partition: OffsetAndMetadata(message.offset + 1, '')})
                    report['processed'] += 1
        if report['processed'] != count:
            raise TimeoutError(f'Expected {count} messages, got {report}')
        return report
    finally:
        consumer.close(autocommit=False)
        output.close(timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bootstrap', default='127.0.0.1:19092')
    parser.add_argument('--database', type=Path, default=Path('runtime/findings.sqlite3'))
    parser.add_argument('--group', default='otlab-detector')
    parser.add_argument('--count', type=int, default=14)
    args = parser.parse_args()
    print(json.dumps(consume(args.bootstrap, args.database, args.group, args.count), indent=2))
