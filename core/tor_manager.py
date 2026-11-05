#!/usr/bin/env python3
# core/tor_manager.py — Tor IP Rotation Manager
# MilkyWay Intelligence | Author: Sharlix

import socket, time, subprocess, threading


class TorManager:
    def __init__(self, log, rotate_every: int = 25, socks_port: int = 9050,
                 ctrl_port: int = 9051, password: str = "m7hunter"):
        self.log          = log
        self.rotate_every = rotate_every
        self.socks        = socks_port
        self.ctrl         = ctrl_port
        self.password     = password
        self.count        = 0
        self._lock        = threading.Lock()
        self._running     = False
        self.current_ip   = "unknown"

    def start(self):
        self.log.section("Tor IP Rotation")
        subprocess.run(["pkill", "-f", "tor.*m7hunter"],
                        capture_output=True, timeout=10)
        time.sleep(1)
        self._write_torrc()
        subprocess.Popen(
            ["tor", "-f", "/tmp/torrc.m7hunter", "--runasdaemon", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        for _ in range(20):
            if self._port_open():
                self._running  = True
                self.current_ip = self._get_ip()
                break
            time.sleep(1)
        if self._running:
            self.log.success(
                f"Tor ready | SOCKS5 127.0.0.1:{self.socks} | Exit: {self.current_ip}"
            )
        else:
            self.log.warn("Tor timeout — running without IP rotation")

    def _write_torrc(self):
        h = self._hash_pw()
        with open("/tmp/torrc.m7hunter", "w") as f:
            f.write(
                f"SocksPort {self.socks}\n"
                f"ControlPort {self.ctrl}\n"
                f"HashedControlPassword {h}\n"
                f"DataDirectory /tmp/tor_m7hunter\n"
            )

    def _hash_pw(self) -> str:
        try:
            r = subprocess.run(
                ["tor", "--hash-password", self.password],
                capture_output=True, text=True, timeout=15
            )
            for line in r.stdout.split("\n"):
                if line.startswith("16:"):
                    return line.strip()
        except Exception:
            pass
        return "16:E600ADC90A2E3F9D8F0A4D24BCFF62C8F6C1E9B3D2A1F0E9C8B7A6D5"

    def _port_open(self) -> bool:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect(("127.0.0.1", self.socks))
            s.close()
            return True
        except Exception:
            return False

    def _get_ip(self) -> str:
        try:
            r = subprocess.run(
                ["curl", "-s", "--socks5", f"127.0.0.1:{self.socks}",
                 "--connect-timeout", "10", "https://api.ipify.org"],
                capture_output=True, text=True, timeout=15
            )
            return r.stdout.strip() or "unknown"
        except Exception:
            return "unknown"

    def rotate(self):
        try:
            s = socket.socket()
            s.connect(("127.0.0.1", self.ctrl))
            s.send(f'AUTHENTICATE "{self.password}"\r\n'.encode())
            time.sleep(0.3)
            s.send(b"SIGNAL NEWNYM\r\n")
            time.sleep(2)
            s.close()
            self.current_ip = self._get_ip()
            self.log.success(f"[Tor] New circuit — IP: {self.current_ip}")
        except Exception as e:
            self.log.warn(f"[Tor] Rotation failed: {e}")

    def tick(self):
        with self._lock:
            self.count += 1
            if self.count % self.rotate_every == 0:
                self.rotate()

    def is_running(self) -> bool:
        return self._running

    def proxy_url(self) -> str:
        return f"socks5://127.0.0.1:{self.socks}"

    def stop(self):
        try:
            subprocess.run(
                ["pkill", "-f", "tor.*m7hunter"],
                capture_output=True, timeout=10
            )
        except Exception:
            pass
