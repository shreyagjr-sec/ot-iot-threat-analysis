"""Live Windows capture into rotating PCAPNG files. Requires dumpcap/Npcap."""
from pathlib import Path
import subprocess
import os

INTERFACE_NUMBER = os.environ.get("CAPTURE_INTERFACE", "1")  # Verify with dumpcap -D
OUTPUT_DIR = Path(os.environ.get("WATCH_DIR", "runtime/buffer"))
TIME_WINDOW_SECONDS = int(os.environ.get("CAPTURE_WINDOW_SECONDS", "10"))
DUMPCAP_PATH = Path(os.environ.get("DUMPCAP_PATH", r"E:\Wireshark\dumpcap.exe"))


def start_capture():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if not DUMPCAP_PATH.is_file():
        raise FileNotFoundError(f"dumpcap not found: {DUMPCAP_PATH}")
    cmd = [str(DUMPCAP_PATH), "-i", INTERFACE_NUMBER,
           "-b", f"duration:{TIME_WINDOW_SECONDS}",
           "-w", str(OUTPUT_DIR / "traffic_chunk.pcapng")]
    if os.environ.get("CAPTURE_FILTER"):
        cmd.extend(["-f", os.environ["CAPTURE_FILTER"]])
    if os.environ.get("CAPTURE_DURATION_SECONDS"):
        cmd.extend(["-a", "duration:" + os.environ["CAPTURE_DURATION_SECONDS"]])
    print("Starting capture:", " ".join(cmd))
    process = subprocess.Popen(cmd)
    try:
        return process.wait()
    except KeyboardInterrupt:
        print("Stopping capture...")
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return 0


if __name__ == "__main__":
    raise SystemExit(start_capture())
