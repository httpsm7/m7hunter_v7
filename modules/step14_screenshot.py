#!/usr/bin/env python3
# modules/step14_screenshot.py — Screenshot Live Hosts (gowitness)
# MilkyWay Intelligence | Author: Sharlix

import os
from core.utils import count_lines, safe_read


class Step14Screenshot:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p    = self.p
        live = p.files["live_hosts"]
        ss_dir = p.files["screenshots_dir"]
        os.makedirs(ss_dir, exist_ok=True)

        if not os.path.isfile(live) or count_lines(live) == 0:
            p.log.warn("Screenshot: no live hosts"); return

        p.log.info(f"Screenshots: {count_lines(live)} hosts via gowitness")

        p.shell(
            f"gowitness file -f {live} "
            f"--screenshot-path {ss_dir} "
            f"--delay 1 "
            f"--timeout 10 "
            f"--threads 5 2>/dev/null",
            label="gowitness", tool_name="gowitness",
            timeout=p.tmgr.get("gowitness")
        )

        n = len([f for f in os.listdir(ss_dir) if f.endswith(".png")])
        p.log.success(f"Screenshots: {n} captured → {ss_dir}")
