"""Send completed capture chunks to the local mock analysis endpoint."""
from pathlib import Path
import time
import requests
import os

WATCH_DIR = Path(os.environ.get("WATCH_DIR", "runtime/buffer"))
AI_API_URL = os.environ.get("AI_API_URL", "http://127.0.0.1:8000/analyze")
POLL_SECONDS = 1


def get_completed_pcaps(directory):
    if not directory.exists():
        return []
    files = sorted(directory.glob("*.pcapng"), key=lambda f: f.stat().st_mtime)
    # Conservative prototype heuristic: assume newest is still being written.
    return files[:-1]


def monitor_and_send():
    WATCH_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Watching {WATCH_DIR}; posting to {AI_API_URL}")
    while True:
        try:
            for path in get_completed_pcaps(WATCH_DIR):
                print(f"Sending {path.name}")
                started = time.monotonic()
                with path.open("rb") as handle:
                    response = requests.post(AI_API_URL,
                        files={"file": (path.name, handle, "application/octet-stream")},
                        timeout=60)
                response.raise_for_status()
                result = response.json()
                if result.get("status") == "success":
                    path.unlink()
                    print(f"Acknowledged and removed {path.name}; {time.monotonic()-started:.2f}s")
                else:
                    print(f"No success acknowledgement for {path.name}: {result}")
        except KeyboardInterrupt:
            print("Sender stopped")
            break
        except (requests.RequestException, OSError, ValueError) as exc:
            print(f"Sender error: {exc}; retrying later")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    monitor_and_send()
