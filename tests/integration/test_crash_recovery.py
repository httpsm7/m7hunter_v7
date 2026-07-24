#!/usr/bin/env python3
# tests/integration/test_crash_recovery.py
# Buildmap 4: Crash recovery — unfinished tasks continue after restart
import sys, os, time, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def test_resume_after_partial_completion():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d, "crash.db"))
        sm.create_scan("crash_001", "crash.com")
        # Simulate: 3 stages completed before crash
        for stage in ["step01_subdomain", "step02_dns", "step03_probe"]:
            sm.stage_start("crash_001", stage)
            sm.stage_done("crash_001", stage)
        # "Restart" — check pending
        all_stages = ["step01_subdomain","step02_dns","step03_probe",
                      "step05_crawl","step07_xss"]
        pending = sm.get_pending_stages("crash_001", all_stages)
        assert "step01_subdomain" not in pending
        assert "step02_dns"       not in pending
        assert "step03_probe"     not in pending
        assert "step05_crawl"     in pending
        assert "step07_xss"       in pending

def test_findings_survive_restart():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d, "crash2.db"))
        sm.create_scan("crash_002", "crash.com")
        sm.persist_findings_bulk("crash_002", [
            {"vuln_type":"XSS","url":"https://x.com","severity":"high",
             "confidence":0.92,"detail":"reflected"},
            {"vuln_type":"SQLI","url":"https://x.com/api","severity":"critical",
             "confidence":0.98,"detail":"time-based"},
        ])
        # New instance simulates restart
        sm2 = StateManager(db_path=os.path.join(d, "crash2.db"))
        findings = sm2.get_findings("crash_002")
        assert len(findings) == 2
        types = {f["vuln_type"] for f in findings}
        assert "XSS" in types and "SQLI" in types

def test_checkpoint_survives_restart():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d, "crash3.db"))
        sm.create_scan("crash_003", "crash.com")
        sm.save_checkpoint("crash_003", "crawl_progress", {"urls_found": 1500})
        # Simulate restart
        sm2  = StateManager(db_path=os.path.join(d, "crash3.db"))
        data = sm2.load_checkpoint("crash_003", "crawl_progress")
        assert data is not None
        assert data["urls_found"] == 1500

def test_resumable_scan_detected():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d, "crash4.db"))
        sm.create_scan("crash_004", "resume.com")
        # Don't finish it
        existing = sm.find_resumable_scan("resume.com")
        assert existing is not None
        assert existing["scan_id"] == "crash_004"

def test_failed_stage_does_not_block_resume():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d, "crash5.db"))
        sm.create_scan("crash_005", "crash.com")
        sm.stage_start("crash_005", "step01_subdomain")
        sm.stage_done("crash_005", "step01_subdomain")
        sm.stage_start("crash_005", "step07_xss")
        sm.stage_done("crash_005", "step07_xss", error="timeout")
        all_stages = ["step01_subdomain","step07_xss","step08_sqli"]
        pending = sm.get_pending_stages("crash_005", all_stages)
        # step08_sqli should still be pending
        assert "step08_sqli" in pending
        assert "step01_subdomain" not in pending

def test_scan_summary_after_partial():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d, "crash6.db"))
        sm.create_scan("crash_006", "summary.com")
        sm.stage_start("crash_006", "step01_subdomain")
        sm.stage_done("crash_006", "step01_subdomain", findings_n=5)
        sm.persist_findings_bulk("crash_006", [
            {"vuln_type":"CORS","url":"https://x.com","severity":"medium",
             "confidence":0.75,"detail":"wildcard"}
        ])
        summary = sm.scan_summary("crash_006")
        assert summary["total_findings"] == 1
        done_stages = [s for s in summary["stages"] if s["status"]=="done"]
        assert len(done_stages) == 1

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
