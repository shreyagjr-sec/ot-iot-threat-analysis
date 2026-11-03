# Milestone 1 — Live Modbus conveyor and policy detection

## Run

From the project root in PowerShell (Python 3.13; no new dependencies needed):

```powershell
python -m unittest discover -s tests -v
python -m otlab.demo
```

The demo starts a bounded simulator on a random port on 127.0.0.1, sends 14 transactions, saves JSON evidence under runtime/conveyor-demo/, and stops the simulator. It has no external-target option. Source 127.0.0.2 represents the approved controller; 127.0.0.3 represents the unapproved controller. Both remain inside the laptop's IPv4 loopback network. No administrator access, Docker, or network capture is required for this milestone.

## Understand the files

| File | Purpose |
|---|---|
| config/conveyor-policy.json | Allowed source, unit ID, register addresses, value limits |
| otlab/protocol.py | Strict framing, request decoding, response correlation |
| otlab/policy.py | Source and value policy decisions independent of simulator |
| otlab/simulator.py | Intentionally unprotected register server and illustrative conveyor state |
| otlab/demo.py | Bounded live requests, independently authored expected labels, saved results |
| tests/test_otlab.py | Protocol edge cases and policy verification |
| docs/evidence/milestone1/ | Evidence from the actual recorded run |

The existing capture_agent.py, pipeline_sender.py, and main.py still form a separate baseline. They are not yet connected to this new detector. The old receiver still returns NOT_ANALYZED.

## Experiment

Register 0 holds run/stop (0..1), register 1 speed percentage (0..100), and register 2 an illustrative read-only position. These are lab-defined semantics, not claims about a commercial conveyor. Supported functions: FC03 read holding registers, FC06 write single register, and FC16 write multiple registers. Other functions are unsupported, not silently benign. Coils, FC22/FC23, authentication, and real PLC control are outside this milestone.

The deliberately vulnerable server accepts out-of-policy command values, so we can observe and detect an accepted policy violation. A write to register 2 gets an exception response; it is still classified as a prohibited attempt. An acknowledgement indicates protocol acceptance, not verified physical actuation. Unconfigured unit IDs are explicitly unassessed.

## Recorded results — 2026-11-03

- Baseline fixture delivery: 3/3 forwarded files matched SHA-256; duplicate 409; invalid extension 400.
- Unit tests: 11 passed.
- Actual loopback transactions: 14; scored write cases: 12.
- True positives: 6; true negatives: 6; false positives: 0; false negatives: 0.
- Two excluded cases: a read and a write addressed to an unconfigured unit.
- Rule-processing p50/p95: 25.0 / 61.7 microseconds in this run.
- Request/response plus rule-processing p50/p95: 1117.5 / 2078.2 microseconds in this run.

These timing values are diagnostic measurements from one tiny sequential run. They exclude connection establishment and do not measure passive detection latency, capture delay, Kafka overhead, or performance under load. The roundtrip metric includes TCP exchange, decoding, and rule evaluation. The small constructed dataset does not establish generalization or production accuracy. Precision and recall of 1.0 apply only to these authored cases.

Events are application-instrumented and include request/response hex; they are NOT packet captures. Socket stream framing handles ordered bytes, not PCAP TCP sequence reconstruction. There is no LLM, Kafka, public dataset, or resource benchmark in this milestone. Policy source IP is not authenticated identity.

## Next integration

1. Restore E: write access and integrate this staged milestone into the Git checkout.
2. Add isolated capture and independently validate parsing against captured traffic.
3. Introduce normalized event IDs, Kafka, persisted findings, and API result access.
4. Validate public dataset semantics and labels; then integrate evidence-grounded LLM explanations.

## Reference

Modbus Organization, MODBUS Application Protocol Specification V1.1b3:
https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
