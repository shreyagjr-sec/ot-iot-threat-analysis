# Connected Kafka milestone

## What works

```text
live Modbus demo -> evidence producer -> ot.evidence
                                        -> detection worker -> SQLite -> API /findings
                                                            -> ot.analysis.results
                                        -> invalid/conflicting evidence -> ot.evidence.rejected

saved demo PCAP -> tshark reconstruction -> normalized captured evidence -> same Kafka path
```

Kafka 4.1.2 is downloaded into runtime/tools/ and checksum-verified against the Apache SHA-512 file. kafka-python 3.0.12 is installed in the existing parent virtual environment. The broker uses a 512 MiB maximum Java heap and loopback-only broker/controller listeners. This machine's Java 26.0.1 successfully ran the integration. Upstream Kafka documents Java 17+ and recommends supported LTS runtimes; the Windows/native Java configuration here is a tested local lab deployment, not a production deployment recommendation. Docker and WSL are not required for this milestone.

## Run the complete verification

From E:\Ot IoT Security Project\repository:

```powershell
& '..\.venv\Scripts\python.exe' verify_kafka.py
```

This starts an isolated real broker on free loopback ports, creates topics, sends actual live Modbus evidence, tests worker recovery and rejection routing, checks saved capture evidence when present, starts the API against the same database, and stops its processes. Evidence is retained in a unique runtime/kafka-check-* folder. The existing capture file must be readable for its optional captured-traffic phase; no new elevated capture is started.

Each demo run has unique event IDs. Captured evidence IDs include the PCAP hash and TCP stream ID, making retries of the same capture idempotent. A live observation and a later capture-based observation intentionally have different IDs: the verification's 28 findings represent 14 new live transactions and 14 transactions reconstructed from an earlier capture, not 28 independent attack scenarios.

## Keep the components running manually

Terminal 1 — broker:

```powershell
& '..\.venv\Scripts\python.exe' -m otlab.broker
```

Terminal 2 — reconstruct existing capture and publish its 14 events:

```powershell
& '..\.venv\Scripts\python.exe' verify_capture.py
& '..\.venv\Scripts\python.exe' publish_events.py
```

Terminal 3 — consume 14 messages into the default database:

```powershell
& '..\.venv\Scripts\python.exe' -m otlab.streaming --count 14
```

Then expose that database through the API:

```powershell
& '..\.venv\Scripts\python.exe' -m uvicorn otlab.api:create_app --factory --host 127.0.0.1 --port 8001
```

Open http://127.0.0.1:8001/docs and execute GET /findings. Use Ctrl+C to stop the broker and API when finished. The worker is bounded by --count and exits; it is not an unattended service. Reusing the same group resumes committed offsets. A count greater than available messages times out rather than reporting success.

## Delivery behavior

The producer waits for Kafka acknowledgements. The worker saves to SQLite, publishes a result and waits for its acknowledgement, then commits the input offset. Invalid messages and ID conflicts go to the rejection topic before their offsets are committed. Unexpected storage/network failures halt processing without advancing the failed record.

Delivery is at least once. A failure after SQLite save can cause another delivery, which SQLite deduplicates. Kafka result messages can repeat; consumers should deduplicate results by event_id and policy_sha256. There is no atomic transaction spanning SQLite and Kafka and no exactly-once claim. The fault test deliberately raises after a committed SQLite write, before result publication and offset acknowledgement; it validates that specific recovery window, not all failure modes.

## Reproduce installation elsewhere

Use Python 3.13 and a Java 17+ JDK. From a project virtual environment:

```powershell
python -m pip install -r requirements-streaming.txt
python setup_kafka.py
python verify_kafka.py
```

JAVA_HOME can select the JDK. On this laptop the launcher finds the installed JDK directly, avoiding an unresponsive Java PATH shim. The pinned archive is approximately 127 MiB and remains outside Git. Setup requires internet; subsequent local runs do not.

## Limits and next work

One broker and one partition per topic; no high availability, authentication, TLS, or production sizing evaluation. The capture adapter validates the demo's one-transaction-per-connection layout. General multi-transaction PCAP ingestion, live capture streaming, an LLM, dashboard, public-dataset evaluation, and throughput/resource experiments are pending.

References:
- https://kafka.apache.org/41/getting-started/quickstart/
- https://kafka.apache.org/41/operations/kraft/
- https://kafka-python.readthedocs.io/en/master/apidoc/KafkaConsumer.html
