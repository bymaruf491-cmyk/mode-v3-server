from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
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
MAX_BODY = 8192

def load_devices():
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_devices(devices):
    temp = DB_FILE + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(devices, f, ensure_ascii=False)
    os.replace(temp, DB_FILE)

def new_device(name="Android device"):
    return {
        "name": name,
        "last_seen": int(time.time()),
        "command": "UNLOCK",
        "command_id": 0,
        "ack_id": 0,
        "messages": []
    }

class Handler(BaseHTTPRequestHandler):
    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
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

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > MAX_BODY:
            raise ValueError("Invalid request size")
        data = json.loads(self.rfile.read(length))
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    def do_GET(self):
        if not self.authorized():
            self.send_json(401, {"error": "Unauthorized"})
            return

        parsed = urlparse(self.path)
        route = parsed.path
        params = parse_qs(parsed.query)

        if route == "/health":
            self.send_json(200, {"ok": True, "service": "mode-v3-server"})
            return

        if route == "/devices":
            now = int(time.time())
            with DB_LOCK:
                devices = load_devices()
                result = []
                for device_id, info in devices.items():
                    age = now - int(info.get("last_seen", 0))
                    result.append({
                        "id": device_id,
                        "name": info.get("name", "Android device"),
                        "online": age <= 120,
                        "last_seen": info.get("last_seen", 0)
                    })
            self.send_json(200, {"devices": result})
            return

        if route in ("/command", "/messages"):
            device_id = params.get("device_id", [""])[0].strip()
            if not device_id:
                self.send_json(400, {"error": "device_id required"})
                return
            with DB_LOCK:
                devices = load_devices()
                info = devices.get(device_id)
                if not info:
                    self.send_json(404, {"error": "Device not registered"})
                    return
                if route == "/command":
                    result = {
                        "device_id": device_id,
                        "command": info.get("command", "UNLOCK"),
                        "command_id": info.get("command_id", 0)
                    }
                else:
                    result = {
                        "device_id": device_id,
                        "messages": info.get("messages", [])
                    }
            self.send_json(200, result)
            return

        self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        if not self.authorized():
            self.send_json(401, {"error": "Unauthorized"})
            return

        route = urlparse(self.path).path
        try:
            data = self.read_json()
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON or request size"})
            return

        device_id = str(data.get("device_id", data.get("id", ""))).strip()
        if not device_id or len(device_id) > 100:
            self.send_json(400, {"error": "Invalid device ID"})
            return

        with DB_LOCK:
            devices = load_devices()

            if route == "/register":
                name = str(data.get("name", "Android device")).strip()[:80]
                info = devices.get(device_id, new_device(name))
                info["name"] = name or "Android device"
                info["last_seen"] = int(time.time())
                devices[device_id] = info
                save_devices(devices)
                self.send_json(200, {"ok": True, "device_id": device_id})
                return

            if device_id not in devices:
                self.send_json(404, {"error": "Device not registered"})
                return

            info = devices[device_id]

            if route == "/heartbeat":
                info["last_seen"] = int(time.time())
                save_devices(devices)
                self.send_json(200, {"ok": True})
                return

            if route == "/command":
                command = str(data.get("command", "")).upper()
                if command not in ("LOCK", "UNLOCK"):
                    self.send_json(400, {"error": "Command must be LOCK or UNLOCK"})
                    return
                info["command"] = command
                info["command_id"] = int(info.get("command_id", 0)) + 1
                save_devices(devices)
                self.send_json(200, {
                    "ok": True,
                    "command": command,
                    "command_id": info["command_id"]
                })
                return

            if route == "/urgent":
                message = str(data.get("message", "")).strip()
                if not message:
                    self.send_json(400, {"error": "Message required"})
                    return
                messages = info.setdefault("messages", [])
                messages.append({
                    "id": int(time.time() * 1000),
                    "message": message[:500],
                    "created_at": int(time.time())
                })
                info["messages"] = messages[-100:]
                save_devices(devices)
                self.send_json(200, {"ok": True})
                return

            if route == "/ack":
                try:
                    ack_id = int(data.get("command_id", 0))
                except (TypeError, ValueError):
                    self.send_json(400, {"error": "Invalid command_id"})
                    return
                info["ack_id"] = max(int(info.get("ack_id", 0)), ack_id)
                info["last_seen"] = int(time.time())
                save_devices(devices)
                self.send_json(200, {"ok": True, "ack_id": info["ack_id"]})
                return

        self.send_json(404, {"error": "Not found"})

    def log_message(self, fmt, *args):
        print(fmt % args)

if not API_KEY:
    raise SystemExit("MODEV3_API_KEY environment variable is required")

print(f"Mode V3 server listening on port {PORT}")
HTTPServer((HOST, PORT), Handler).serve_forever()
