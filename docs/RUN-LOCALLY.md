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

## Live packet capture (verified with elevated user run)

Npcap on this machine requires administrator privileges. An elevated user run succeeded and its capture was verified. No Npcap configuration was changed. From an elevated PowerShell, the loopback-only check is:

```powershell
& '..\.venv\Scripts\python.exe' -m otlab.demo --capture-tool 'E:\Wireshark\dumpcap.exe' --output runtime/capture-validation
```

This starts a six-second capture filtered to the demo's random loopback port. Captured packet timestamps span only the active traffic interval, which can be much shorter than six seconds. Then verify the saved capture (administrator access is not needed for this step):

```powershell
& '..\.venv\Scripts\python.exe' verify_capture.py
```

The verifier reconstructs directional TCP streams using tshark and compares source addresses and request/response bytes with the application evidence. It supports exactly one request/response per connection and one demo run. The verified run contained 180 packets and all 14 expected transactions. This is a bounded capture verifier, not a general PCAP ingestion worker.

## Still to build

Kafka deployment and consumer delivery; independent PCAP parsing/validation; public-dataset selection; AI explanations; dashboard; resource/load experiments; final IEEE report. Docker and WSL2 are not installed by these scripts.
