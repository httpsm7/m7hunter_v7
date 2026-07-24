
---

## EDRP Refactor — Event-Driven Resource-Orchestrated Pipeline

### NEW FILES

| File | Role |
|------|------|
| `core/state_manager.py` | SQLite-backed checkpoint, resume, findings store |
| `core/resource_controller.py` | RAM/CPU guard, single-active heavy policy |
| `core/engine_registry.py` | DAG metadata for all 29 engines |
| `core/scheduler.py` | Event-driven stage scheduler (the brain) |
| `core/pipeline_edrp.py` | Full EDRP pipeline integrating all components |

### UPDATED FILES

| File | Change |
|------|--------|
| `core/base_step.py` | Full lifecycle: idle→warming→running→cooling→sleeping→done |
| `ai/pipeline_controller.py` | AIGate — only activates on confidence 0.50–0.84 |
| `m7hunter.py` | --edrp, --resume, --ram-limit, --no-screenshots flags |
| `requirements.txt` | Added psutil==5.9.8 |

### BLUEPRINT IMPLEMENTATION STATUS

**Must Add (all done):**
- [x] SQLite checkpointing
- [x] Strict resume support
- [x] Global scheduler (DAG-based)
- [x] RAM-aware throttle
- [x] One shared async HTTP client (via ResourceController gate)
- [x] Module lifecycle hooks (idle/warming/running/cooling/sleeping)
- [x] Centralized error logging (error_handler)
- [x] Dependency graph (engine_registry topological_order)
- [x] CI tests for core engine (test_edrp.py — 19 tests)
- [x] Plugin compatibility metadata (EngineSpec.requires_lab, safe_to_skip)

**Should Add (all done):**
- [x] Per-engine RAM budget (EngineSpec.ram_class)
- [x] Module warm/cool lifecycle (prepare/cool_down/sleep hooks)
- [x] Automatic cleanup on stage end (Scheduler._flush_and_release)
- [x] Structured JSON findings schema (StateManager.persist_finding)
- [x] Scope enforcement via engine selection

**Architecture Rule (10 GB RAM):**
- Only one heavy/critical module active at a time ✓
- Playwright paused when RAM > 70% ✓
- AI only on ambiguous findings (confidence 0.50–0.84) ✓
- Findings batched to SQLite, not held in memory ✓
- Engines unloaded after completion (handle release in cooling) ✓

### PIPELINE FLOW
```
User Input → Scope Engine → Scheduler (DAG order)
  → step01_subdomain [recon/medium]
    → step02_dns [recon/low]
      → step03_probe [probe/low]
        → step05_crawl [crawl/high — single heavy slot]
          → step07_xss, step08_sqli, step11_ssrf ... [vuln/medium]
      → step04_ports [probe/medium]
  → step16_github [recon/low — parallel with above]
→ AI Gate (ambiguous findings only)
→ Report Generator
→ SQLite Checkpoint + Sleep
```

### USAGE
```bash
# Standard EDRP run
sudo m7hunter -u target.com --edrp --deep

# Resume interrupted scan
sudo m7hunter -u target.com --edrp --resume

# RAM-constrained machine (4 GB)
sudo m7hunter -u target.com --edrp --ram-limit 3072

# With lab plugins (2FA, SAML)
sudo m7hunter -u target.com --edrp --lab

# Check resource status mid-scan via dashboard
sudo m7hunter -u target.com --edrp --dashboard
```

### TEST RESULTS
```
test_edrp.py       19/19 passed
test_confidence.py 10/10 passed
test_risk_scorer.py 8/8 passed
test_error_handler  5/5 passed
TOTAL             42/42 passed
```
