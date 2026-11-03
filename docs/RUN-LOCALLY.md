# Run the current research prototype

Active folder: `E:\Ot IoT Security Project\repository`.

Open PowerShell in this folder. The launcher prefers a repository-local virtual environment, then the pre-existing parent environment. Nothing installs automatically.

```powershell
.\Start-Lab.ps1 -Mode demo
.\Start-Lab.ps1 -Mode tests
.\Start-Lab.ps1 -Mode verify
```

- demo: 14 actual loopback Modbus TCP transactions; saves request/response evidence and policy results.
- tests: protocol and storage tests (16 tests at this milestone).
- verify: full demo followed by real HTTP ingestion, duplicate/conflict checks, and API restart/persistence verification. Uses an isolated runtime database.

If PowerShell blocks scripts, invoke Python directly instead of changing global execution policy:

```powershell
& '..\.venv\Scripts\python.exe' -m otlab.demo
& '..\.venv\Scripts\python.exe' verify_api.py
```

## Local API

```powershell
.\Start-Lab.ps1 -Mode api
```

Open `http://127.0.0.1:8001/docs`. Endpoints: GET /health, POST /events, GET /findings. Ctrl+C stops the service. The standalone API starts with an empty database unless evidence has been ingested into it. The verification script uses a separate temporary-run database; its results do not automatically populate the standalone service.

Evidence ingestion recomputes decisions from request bytes and the configured policy. It does not accept caller-provided verdicts. Event IDs make retries idempotent; reusing an ID with changed evidence or changed policy returns 409. Missing response evidence is not treated as a successful write. Evidence provenance is supplied by the client, not independently certified by this local API.

SQLite findings are under runtime/findings.sqlite3 by default. Run folders, logs, captures, and databases remain local and ignored by Git. This API has no authentication; bind only to loopback. It accepts bounded single-transaction hex evidence, not PCAP files. The older main:app receiver is a separate baseline and still returns NOT_ANALYZED.

## Live packet capture (currently blocked)

The capture attempt failed because this machine's Npcap requires administrator privileges. No Npcap configuration was changed. From an elevated PowerShell, the optional loopback-only check is:

```powershell
& '..\.venv\Scripts\python.exe' -m otlab.demo --capture-tool 'E:\Wireshark\dumpcap.exe' --output runtime/capture-validation
```

This starts a six-second capture filtered to the demo's random loopback port. A successful capture still needs independent tshark validation; packet analysis is not implemented yet. Do not describe the current application evidence as packet-capture evidence.

## Still to build

Kafka deployment and consumer delivery; independent PCAP parsing/validation; public-dataset selection; AI explanations; dashboard; resource/load experiments; final IEEE report. Docker and WSL2 are not installed by these scripts.
