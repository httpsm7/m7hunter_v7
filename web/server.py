#!/usr/bin/env python3
# web/server.py — Live Dashboard with WebSocket Support
# Blueprint Fix: Real-time findings/progress via SocketIO
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import os, json, threading, time
from flask import Flask, jsonify, send_from_directory, request
from core.error_handler import get_handler

app  = Flask(__name__, static_folder="static")
app.config["SECRET_KEY"] = os.urandom(24)
_pipeline_ref = None
_socketio_ref = None

def init_server(pipeline):
    global _pipeline_ref
    _pipeline_ref = pipeline
    try:
        from flask_socketio import SocketIO
        global _socketio_ref
        _socketio_ref = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
        _register_socketio_events()
    except ImportError:
        pass
    return app

def _register_socketio_events():
    sio = _socketio_ref
    @sio.on("connect")
    def on_connect():
        if _pipeline_ref:
            try: sio.emit("status", _get_status())
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("server", _e)
    @sio.on("pause")
    def on_pause():
        if _pipeline_ref and _pipeline_ref.ceo:
            _pipeline_ref.ceo.pause(); sio.emit("status",{"paused":True})
    @sio.on("resume")
    def on_resume():
        if _pipeline_ref and _pipeline_ref.ceo:
            _pipeline_ref.ceo.resume(); sio.emit("status",{"paused":False})

def broadcast_finding(finding: dict):
    if _socketio_ref:
        try: _socketio_ref.emit("new_finding", finding, broadcast=True)
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("server", _e)

def broadcast_progress(step: str, pct: int, msg: str = ""):
    if _socketio_ref:
        try: _socketio_ref.emit("progress",{"step":step,"pct":pct,"msg":msg}, broadcast=True)
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("server", _e)

def _get_status() -> dict:
    p = _pipeline_ref
    if not p: return {}
    try:
        findings = p.findings_engine.get_all() if hasattr(p,"findings_engine") else []
        return {"target":getattr(p,"target",""),"findings":len(findings),
                "uptime":round(time.time()-p._start_time,0) if hasattr(p,"_start_time") else 0}
    except Exception:
        return {}

@app.route("/")
def index():
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    return send_from_directory(static_dir, "index.html")

@app.route("/api/findings")
def api_findings():
    try:
        p = _pipeline_ref
        if not p: return jsonify([])
        findings = p.findings_engine.get_all() if hasattr(p,"findings_engine") else []
        sev = request.args.get("severity","")
        if sev: findings = [f for f in findings if f.get("severity","").lower()==sev.lower()]
        return jsonify(findings)
    except Exception as e:
        get_handler().capture("web/server", e, "api_findings")
        return jsonify([])

@app.route("/api/status")
def api_status(): return jsonify(_get_status())

@app.route("/api/errors")
def api_errors():
    try:
        errors = get_handler().get_errors()[-50:]
        return jsonify(errors)
    except Exception:
        return jsonify([])

@app.route("/api/report")
def api_report():
    try:
        p = _pipeline_ref
        if not p: return jsonify({"error":"not ready"})
        findings = p.findings_engine.get_all() if hasattr(p,"findings_engine") else []
        sev_count = {}
        for f in findings:
            s = f.get("severity","info")
            sev_count[s] = sev_count.get(s,0)+1
        return jsonify({"target":getattr(p,"target",""),"total":len(findings),
                        "severity_breakdown":sev_count,"findings":findings})
    except Exception as e:
        get_handler().capture("web/server", e, "api_report")
        return jsonify({"error":str(e)})

def run_dashboard(pipeline, host="127.0.0.1", port=8719, debug=False):
    init_server(pipeline)
    if _socketio_ref:
        _socketio_ref.run(app, host=host, port=port, debug=debug, use_reloader=False)
    else:
        app.run(host=host, port=port, debug=debug, use_reloader=False)
