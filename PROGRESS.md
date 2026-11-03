# Progress

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
