# Progress

## 2026-11-03 — Kafka connected to detection, persistence, and API

- Downloaded Apache Kafka 4.1.2 locally and verified its SHA-512. Installed kafka-python 3.0.12 in the existing virtual environment. No Docker/WSL installation or system Java changes.
- Ran a real loopback-only KRaft broker using installed Java 26.0.1. Broker binary/data stay in ignored runtime/.
- Added acknowledged evidence producer, bounded detector worker, result topic, rejection topic, and explicit post-processing offset commits.
- Connected actual live demo evidence and tshark-reconstructed captured evidence to Kafka, SQLite, and API retrieval.
- Verified worker interruption after SQLite save and before Kafka acknowledgement; replay did not duplicate the database row.
- Verified duplicate evidence handling and rejected malformed JSON/conflicting evidence routing.
- Added repeatable setup, verification, manual run commands, and two streaming validation tests (18 total passing at initial integration).
- Refer to docs/KAFKA.md for commands, exact delivery semantics, limitations, and reproducibility.
- Final end-to-end verification: 14 new live events plus 14 saved-capture transactions produced 28 unique findings visible through the API. Including duplicate/conflict/malformed test inputs, all 31 input offsets were processed; result topic held 29 records (one intentional duplicate), and rejection topic held two records.
- Final run evidence: runtime/kafka-check-9bf75a4e7752/verification.json; publishable copy in docs/evidence/kafka/verification.json. All 18 code tests passed.
- Still pending: general PCAP ingestion/live capture streaming, LLM explanations, dashboard, public datasets, and research benchmarks.

## 2026-11-03 — User-run live capture independently checked

- User successfully ran the elevated dumpcap demo. The previous Npcap privilege blocker is resolved for elevated user-run capture.
- Inspected the actual PCAPNG: 180 packets; dumpcap reports 180 received and zero dropped.
- Added verify_capture.py using tshark TCP stream reconstruction, including requests split over TCP segments.
- Verified all 14 captured connections: source addresses, complete request bytes, and complete response bytes match the application evidence exactly. Recomputed policy classifications also match.
- Capture SHA-256: aa6bde815a201422bf3284124644871d54d0e07ad430e265b6a3cccef567d592.
- All 16 existing tests pass after this addition.
- Local raw evidence: runtime/capture-validation/. Publishable verification report: docs/evidence/capture-validation.json.
- Limitation: this validates a bounded one-transaction-per-connection demo; a general PCAP ingestion worker, Kafka, and AI explanations remain pending.

## 2026-11-03 — E: integration and persistent analysis API

Completed and verified directly in E:\Ot IoT Security Project\repository:
- Folder write access granted for this session; transferred staged milestone and preserved previous documents under ignored runtime/ backup.
- Re-ran live Modbus demo from E:, with six true-positive violations and six true-negative permitted writes; read/unconfigured-unit cases are explicit exclusions.
- Added SQLite findings, strict evidence ingestion, policy-version hashing, retry deduplication, and conflicting-ID rejection.
- Added local FastAPI endpoints /health, /events, /findings and a simple PowerShell launcher.
- All 16 tests passed. Fixed a Windows sandbox temp-path issue by keeping test temporary databases inside project runtime/ and closing database handles explicitly.
- Real HTTP verification analyzed 14 events; duplicate retry created no new record; conflict returned 409; malformed evidence returned 422; all 14 findings survived API restart.
- Runtime evidence: runtime/api-check-ae8e4dd0def5/verification.json and demo/events.jsonl.

Capture blocker:
- dumpcap enumerated the loopback adapter but rejected capture: Npcap administrator-only mode requires elevated access.
- Saved failure log: runtime/capture-validation/capture.log. Capture option is implemented, but successful packet capture and independent PCAP validation remain unverified.
- No Docker, WSL, Npcap, or model installation performed.

Next: independent capture validation, Kafka deployment, and connecting persisted evidence to downstream analysis. Historical staged-work entries below describe earlier state, not the current folder location.

## 2026-11-03 — First live Modbus milestone (staged)

Completed:
- Re-ran the HTTP baseline integration successfully with generated capture fixtures.
- Built strict Modbus TCP stream framing, FC03/FC06/FC16 request decoding, and response correlation.
- Built loopback-only Python conveyor simulator, JSON policy, and separate source/value detector.
- Ran 14 actual TCP transactions: 6 prohibited writes detected, 6 valid writes allowed, 2 explicitly excluded read/unconfigured-unit cases.
- All 11 unit tests passed, including fragmentation, malformed traffic, and exception handling.
- Saved event evidence, summary, run instructions, and explicit evaluation limitations.

Environment limitation:
- E: folder write access was not granted by the permission tool in this turn. Work is staged in this chat workspace, not installed into E:.
- E: files and GitHub have not been changed. No software or services were installed.

Next: integrate staged work once folder access is granted, add independent packet-capture validation, then Kafka and persistent findings.

## 2026-11-02 — Scope and workspace preparation

Completed:
- Confirmed one-month independent study, IEEE-format report, and approximately 5–10 student hours per week.
- Selected a factory conveyor simulation using Python and actual Modbus TCP traffic.
- Selected policy detection of unapproved-source writes and out-of-range values, with LLM evidence explanations.
- Selected evaluation of detection accuracy, false positives, latency, resource use, and explanation quality.
- Reviewed local scripts and preserved them in ../legacy-local/.
- Cloned the existing GitHub repository into this active workspace.

Verified:
- Existing local receiver uses a constant clean verdict, not actual detection.
- Existing sender has an incomplete URL and deletes acknowledged captures.
- Python and VS Code are available; WSL reports not installed; Docker was not found on PATH.

Not completed:
- No simulator, Kafka deployment, policy detector, or LLM evaluation has been implemented in this milestone.
- No new experiments or performance results have been produced.
- No changes from this milestone have been pushed to GitHub.

Next:
1. Verify the GitHub baseline locally and review its implementation.
2. Implement and test a Modbus parser and policy rules with independent labeled scenarios.
3. Add the conveyor simulator, isolated traffic generation, and capture.
4. Add Kafka, persisted results, and API/dashboard.
5. Validate a public dataset subset and add evidence-grounded LLM explanations.
6. Run reproducible experiments and write the report from measured results.

Progress is updated when work occurs; there is no background schedule.
