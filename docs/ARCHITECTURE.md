# M7Hunter V7 — Architecture Reference
## MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

## Core Design: Event-Driven Resource-Orchestrated Pipeline

```
Input → Scope Engine → Scheduler (DAG) → Engines → AI Gate → Evidence → Report → Checkpoint
```

## Module Lifecycle (Every Engine)
```
IDLE → WARMING → RUNNING → FLUSHING → SLEEPING → DONE
```

## Core Systems

| File | Role |
|------|------|
| `core/scheduler.py` | DAG-based stage orchestrator — the brain |
| `core/resource_controller.py` | RAM/CPU guard, single-heavy-stage policy |
| `core/state_manager.py` | SQLite checkpointing + resume |
| `core/engine_registry.py` | 29-engine DAG metadata registry |
| `core/browser_pool.py` | Shared Playwright pool, demand-only |
| `core/stealth_manager.py` | Single browser + isolated contexts |
| `core/proxy_manager.py` | Rotation, cooldown, failure scoring |
| `core/plugin_registry.py` | Isolated plugin execution |
| `core/scope_engine.py` | Wildcard/regex/CIDR scope enforcement |
| `core/error_handler.py` | Centralized exception capture |
| `core/secure_store.py` | Fernet-encrypted credential vault |

## AI Layer

| File | Role |
|------|------|
| `ai/agent_manager.py` | Coordinator — gates activation, tracks budget |
| `ai/risk_engine.py` | Structured JSON risk evaluation |
| `ai/prompt_router.py` | Role-based prompt dispatch |
| `ai/memory_store.py` | Decision caching, cross-finding context |

## RAM Rules (10 GB Target)

| Condition | Action |
|-----------|--------|
| RAM > 75% | Reduce concurrency |
| RAM > 85% | Pause browser engines |
| CPU > 90% | Throttle crawling |
| browser_count > limit | Suspend JS rendering |

## AI Activation Gates

| Trigger | AI Activates? |
|---------|---------------|
| confidence 0.50–0.84 (ambiguous) | YES |
| High-confidence + correlation needed | YES |
| Normal crawling | NO |
| Low confidence (<0.50) | NO |
| RAM > 75% | NO |

## Usage

```bash
# Standard EDRP scan
sudo m7hunter -u target.com --edrp --deep

# Resume interrupted scan
sudo m7hunter -u target.com --edrp --resume

# RAM-constrained (4 GB)
sudo m7hunter -u target.com --edrp --ram-limit 4096

# With lab plugins (2FA/SAML bypass testing)
sudo m7hunter -u target.com --edrp --lab

# Install
sudo bash install.sh
```

## Engines Directory Map

```
engines/
  recon/    → step01_subdomain, step02_dns, step16_github
  ports/    → step04_ports
  crawl/    → step05_crawl
  vuln/     → step06_nuclei through step27_nosql
  verify/   → double_verify, confidence scoring
```
