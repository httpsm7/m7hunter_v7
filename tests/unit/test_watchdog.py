#!/usr/bin/env python3
import sys, os, time, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def test_watchdog_starts_stops():
    from core.watchdog import Watchdog
    wd = Watchdog()
    wd.start()
    time.sleep(0.1)
    assert wd._running
    wd.stop()
    assert not wd._running

def test_heartbeat_register():
    from core.watchdog import Watchdog
    wd = Watchdog()
    wd.register_engine("test_engine")
    wd.heartbeat("test_engine", "running", 0.5)
    with wd._lock:
        hb = wd._beats.get("test_engine")
    assert hb is not None
    assert hb.state == "running"
    assert hb.progress == 0.5

def test_stall_detection():
    from core.watchdog import Watchdog, WatchdogPolicy
    policy = WatchdogPolicy(engine_timeout_s=0.1)
    wd = Watchdog(policy=policy)
    wd.register_engine("slow_engine")
    wd.heartbeat("slow_engine", "running")
    time.sleep(0.3)
    wd._check_heartbeats()
    alerts = wd.get_alerts("stall")
    assert len(alerts) >= 1
    assert alerts[0]["engine"] == "slow_engine"

def test_stall_callback():
    from core.watchdog import Watchdog, WatchdogPolicy
    policy = WatchdogPolicy(engine_timeout_s=0.1)
    wd = Watchdog(policy=policy)
    stalled = []
    wd.on_stall(lambda name, hb: stalled.append(name))
    wd.register_engine("cb_engine")
    wd.heartbeat("cb_engine", "running")
    time.sleep(0.3)
    wd._check_heartbeats()
    assert "cb_engine" in stalled

def test_health_report():
    from core.watchdog import Watchdog
    wd = Watchdog()
    wd.register_engine("e1")
    wd.heartbeat("e1", "done")
    r = wd.health_report()
    assert "engines_tracked" in r
    assert r["engines_tracked"] == 1

def test_unregister_engine():
    from core.watchdog import Watchdog
    wd = Watchdog()
    wd.register_engine("tmp")
    wd.unregister_engine("tmp")
    with wd._lock:
        assert "tmp" not in wd._beats

def test_alerts_accumulate():
    from core.watchdog import Watchdog
    wd = Watchdog()
    wd._raise_alert({"type":"test","msg":"x"})
    wd._raise_alert({"type":"test","msg":"y"})
    assert len(wd.get_alerts("test")) == 2

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
