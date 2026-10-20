"""Local FastAPI PCAP receiver; verdict is a placeholder, NOT AI analysis."""
from pathlib import Path
import shutil
import os
from fastapi import FastAPI, UploadFile, File, HTTPException

app = FastAPI(title="OT/IoT Prototype PCAP Receiver")
RECEIVED_DIR = Path(os.environ.get("RECEIVED_DIR", "runtime/received"))
RECEIVED_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/")
def home():
    return {"status": "receiver ready"}


@app.post("/analyze")
def analyze_pcap(file: UploadFile = File(...)):
    filename = Path(file.filename or "").name
    if not filename or not filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Expected a .pcap or .pcapng file")
    save_path = RECEIVED_DIR / filename
    if save_path.exists():
        raise HTTPException(status_code=409, detail="Filename already exists; manual review required")
    with save_path.open("wb") as destination:
        shutil.copyfileobj(file.file, destination)
    return {"status": "success", "filename": filename,
            "verdict": "NOT_ANALYZED", "message": "File received; AI integration pending"}
