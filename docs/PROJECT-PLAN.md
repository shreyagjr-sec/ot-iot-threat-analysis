# Research and implementation plan

## Research question
How accurately and quickly can a streaming pipeline detect policy-violating Modbus TCP writes, and how faithfully can an LLM explain packet-level evidence?

## Scope
A simulated factory conveyor with a controller, PLC server, and controlled test client. Policies specify permitted source addresses, destinations, unit IDs, register ranges, and allowed values. Source IP is a policy signal, not proof of authenticated identity. Detect attempted writes separately from confirmed successful writes using response evidence.

Rules make detection decisions. The LLM explains structured evidence and does not control detection or equipment. Automated defense is optional future work. This is a research prototype, not a production safety system.

## Target flow
Simulator / public PCAP -> capture and Modbus TCP reassembly -> normalized events -> Kafka -> policy worker -> persisted findings -> API/dashboard -> optional LLM explanation.

Keep PCAPs on disk and send references through Kafka. Explicitly handle duplicate events, capture boundaries, TCP segmentation, Modbus exceptions, retries, and incomplete evidence. Keep detection timing separate from explanation timing.

## Four-week milestones
1. Simulator, capture/parser, policy configuration, reproducible positive and negative cases.
2. Kafka integration, durable findings, API and simple dashboard, delivery failure handling.
3. Public dataset suitability review, LLM integration, controlled evaluation and resource measurements.
4. Repeat experiments, analyze limitations, finalize IEEE report, reproducibility guide and demonstration.

The student has about 20–40 total hours. Prefer one complete tested path; reduce optional enrichment and visualization before sacrificing evaluation or report quality.

## Evaluation
- Event-level confusion matrix, precision, recall, F1, false-positive rate, and sample counts.
- Detection latency p50/p95, throughput, backlog, CPU, RAM, and disk use under stated workloads.
- Separate capture-window delay, queue delay, rule processing, and LLM response time.
- Explanation rubric: factual consistency, evidence traceability, unsupported claims, and useful remediation; document reviewer and sample-selection limits.
- Include benign writes, boundary values, unauthorized in-range writes, authorized out-of-range writes, combined violations, reads, exceptions, and fragmented traffic.
- Compare the same detector with direct transport and Kafka to measure transport overhead; assess explanation value separately from detection correctness.

## Dataset requirements
Inspect licensing, PCAP availability, timestamps, Modbus write function coverage, labels, and attack semantics before selecting a subset. CIC Modbus 2023 and CICAPT-IIoT2024 are candidates, not validated matches. Do not invent controller allowlists or safe register bounds for public data and present them as original ground truth. Where required policy labels are absent, disclose this and use simulator ground truth for those measurements. Keep splits separated by scenario/session where applicable.

## Report and portfolio
Maintain an experiment manifest, configurations, dependency versions, seeds where applicable, raw measurement outputs, and scripts producing tables. IEEE template and page limit remain to be confirmed with the supervisor. Cite external datasets and tools. Keep secrets, raw sensitive captures, environments, and bulk datasets out of Git. No claims of successful analysis until tested.

## Hardware and budget
Windows x64, AMD Ryzen AI 9 365, Radeon 880M integrated graphics, 32 GB RAM; project allocation approximately 130 GB. Prefer free/local AI; cloud fallback budget at most USD 15, with cost estimate and tracking before use.
