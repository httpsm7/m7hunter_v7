#!/usr/bin/env python3
# web/dashboard.py — compatibility shim → use web/server.py
try:
    from web.server import Dashboard
except ImportError:
    # Minimal fallback
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading

    class Dashboard:
        def __init__(self, log=None, port=8719, **kw):
            self.log = log
            self.port = port

        def start(self, blocking=True):
            class H(BaseHTTPRequestHandler):
                def log_message(self, *a): pass
                def do_GET(self):
                    self.send_response(302)
                    self.send_header("Location", "http://localhost:8719/")
                    self.end_headers()
            srv = HTTPServer(("0.0.0.0", self.port), H)
            if self.log:
                self.log.success(f"Dashboard (basic): http://localhost:{self.port}")
            if blocking:
                srv.serve_forever()
            else:
                threading.Thread(target=srv.serve_forever, daemon=True).start()
