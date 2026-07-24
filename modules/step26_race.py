import os
#!/usr/bin/env python3
# modules/step26_race.py — Race Condition (V7 async HTTP/2 engine)
# MilkyWay Intelligence | Author: Sharlix
from engines.race_engine_v7 import RaceEngineV7


def _get_live_hosts(p, limit=100):
    """Returns live hosts - ALWAYS includes main target as fallback."""
    tgt = p.target.strip()
    if not tgt.startswith("http"):
        tgt = "https://" + tgt

    hosts = []
    seen  = set()

    for key in ("fmt_url", "live_hosts", "resolved"):
        src = p.files.get(key, "")
        if not src or not os.path.isfile(src):
            continue
        from core.utils import safe_read
        for line in safe_read(src):
            line = line.strip()
            if not line:
                continue
            if not line.startswith("http"):
                line = "https://" + line
            if line not in seen:
                seen.add(line)
                hosts.append(line)
        if hosts:
            break

    # GUARANTEED: always include main target
    if tgt not in seen:
        hosts.insert(0, tgt)

    return hosts[:limit]


class Step26Race:
    def __init__(self, pipeline): self.p = pipeline
    def run(self):
        self.p.log.info("Race Condition: using V7 async HTTP/2 engine")
        RaceEngineV7(self.p).run()
