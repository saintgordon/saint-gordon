import json
from http.server import BaseHTTPRequestHandler

from scripts.update_soundcloud import build

ALLOWED_ORIGINS = frozenset({
    "https://saintgordon.vercel.app",
    "http://localhost:8000",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
})


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        origin = (self.headers.get("Origin") or "").strip()
        try:
            tracks, _ = build(download_artwork=False)
            payload = json.dumps(tracks, ensure_ascii=False).encode("utf-8")
        except Exception as error:
            self.log_error("SoundCloud update failed: %s", error)
            self.send_response(503)
            self.send_header("Cache-Control", "no-store")
            payload = b'{"error":"SoundCloud releases are temporarily unavailable"}'
        else:
            self.send_response(200)
            self.send_header("Cache-Control", "public, s-maxage=300, stale-while-revalidate=600")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Vary", "Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
