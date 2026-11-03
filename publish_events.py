"""Publish recorded normalized evidence to the local Kafka input topic."""
import argparse
import json
from pathlib import Path
from otlab.streaming import ensure_topics, producer, publish


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=Path, default=Path('runtime/capture-validation/captured-events.jsonl'))
    parser.add_argument('--bootstrap', default='127.0.0.1:19092')
    args = parser.parse_args()
    ensure_topics(args.bootstrap)
    client = producer(args.bootstrap)
    count = 0
    try:
        with args.file.open(encoding='utf-8') as handle:
            for line in handle:
                if line.strip():
                    publish(client, json.loads(line))
                    count += 1
    finally:
        client.close(timeout=10)
    print(f'Kafka acknowledged {count} evidence messages.')
