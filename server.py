from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import time
import secrets
from threading import Lock

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8765"))
API_KEY = os.environ.get("MODEV3_API_KEY", "")
DB_FILE = os.environ.get("DB_FILE", "devices.json")
DB_LOCK = Lock()

def load_devices():
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_devices(devices):
    temp = DB_FILE + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(devices, f, ensure_ascii=False)
    os.replace(temp, DB_FILE)

class Handler(BaseHTTPRequestHandler):
    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        return bool(API_KEY) and secrets.compare_digest(
            self.headers.get("X-API-Key", ""), API_KEY
        )

    def do_GET(self):
        if not self.authorized():
            self.send_json(401, {"error": "Unauthorized"})
            return

        if self.path != "/devices":
            self.send_json(404, {"error": "Not found"})
            return

        now = int(time.time())
        with DB_LOCK:
            devices = load_devices()
            result = []

            for device_id, info in list(devices.items()):
                age = now - int(info.get("last_seen", 0))

                if age > 7 * 24 * 60 * 60:
                    del devices[device_id]
                    continue

                result.append({
                    "id": device_id,
                    "name": info.get("name", "Android device"),
                    "online": age <= 120,
                    "last_seen": info.get("last_seen", 0)
                })

            save_devices(devices)

        self.send_json(200, {"devices": result})

    def do_POST(self):
        if not self.authorized():
            self.send_json(401, {"error": "Unauthorized"})
            return

        if self.path != "/register":
            self.send_json(404, {"error": "Not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 4096:
                self.send_json(400, {"error": "Invalid request size"})
                return

            data = json.loads(self.rfile.read(length))
            device_id = str(data.get("id", "")).strip()
            name = str(data.get("name", "Android device")).strip()

            if not device_id or len(device_id) > 100:
                self.send_json(400, {"error": "Invalid device ID"})
                return

            with DB_LOCK:
                devices = load_devices()
                devices[device_id] = {
                    "name": name[:80] or "Android device",
                    "last_seen": int(time.time())
                }
                save_devices(devices)

            self.send_json(200, {"ok": True})

        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON"})

    def log_message(self, fmt, *args):
        print(fmt % args)

if not API_KEY:
    raise SystemExit("MODEV3_API_KEY environment variable is required")

print(f"Mode V3 server listening on port {PORT}")
HTTPServer((HOST, PORT), Handler).serve_forever()
