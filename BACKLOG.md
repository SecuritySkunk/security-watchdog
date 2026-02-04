# Security Watchdog — Implementation Backlog

**Created:** 2026-02-04  
**Status:** Ready to implement  
**Approach:** Use local Ollama (qwen3-coder) for heavy lifting

---

## Phase 1: Project Setup ⏳

- [ ] **1.1** Create `package.json` with dependencies:
  - `better-sqlite3` (SQLite)
  - `@microsoft/presidio-analyzer` or REST wrapper
  - `fuse.js` (fuzzy matching)
  - `vitest` (testing)
  - TypeScript tooling
- [ ] **1.2** Create `tsconfig.json`
- [ ] **1.3** Set up project structure:
  ```
  src/
  ├── registry/      # Layer 0
  ├── scanner/       # Layer 1  
  ├── agent/         # Layer 2
  ├── auditor/       # Layer 3
  ├── posture/       # Cross-cutting
  ├── escalation/    # Cross-cutting
  ├── gateway/       # Hook integration
  └── dashboard/     # Web UI
  ```
- [ ] **1.4** Initialize SQLite database from `03-schema.sql`
- [ ] **1.5** Verify Ollama is running locally with suitable model

---

## Phase 2: Layer 0 — Registry 🚧

**Spec:** `docs/04-module-registry.docx`  
**Stub:** `code/04-registry-stub.ts`

- [ ] **2.1** Implement CRUD for pattern definitions
- [ ] **2.2** Implement CRUD for user-defined entries
- [ ] **2.3** Implement live inventory table operations
- [ ] **2.4** Build CLI commands (`watchdog registry add/list/remove`)
- [ ] **2.5** Implement caching layer
- [ ] **2.6** Write unit tests

---

## Phase 3: Layer 1 — Pattern Scanner 🚧

**Spec:** `docs/05-module-scanner.docx`  
**Stub:** `code/05-scanner-stub.ts`

- [ ] **3.1** Integrate Presidio for structural PII detection
  - Option A: Run Presidio as Python service, call via REST
  - Option B: Port patterns to pure JS (more work, no Python dep)
- [ ] **3.2** Integrate fuse.js for fuzzy matching against registry
- [ ] **3.3** Implement three-step scan pipeline
- [ ] **3.4** Implement bidirectional scanning (inbound/outbound)
- [ ] **3.5** Build quarantine mechanism for flagged payloads
- [ ] **3.6** Write unit tests against `11-test-corpus.json`

---

## Phase 4: Layer 2 — Security Agent 🚧

**Spec:** `docs/06-module-security-agent.docx`  
**Stub:** `code/06-security-agent-stub.ts`

- [ ] **4.1** Build Ollama client wrapper
- [ ] **4.2** Implement hardened system prompt
- [ ] **4.3** Implement prompt injection defenses (data framing)
- [ ] **4.4** Implement three-decision logic (FALSE_POSITIVE/BLOCK/ESCALATE)
- [ ] **4.5** Wire to quarantine queue from Layer 1
- [ ] **4.6** Write unit tests

---

## Phase 5: Cross-Cutting — Posture & Escalation 🚧

**Specs:** `docs/08-module-posture.docx`, `docs/09-module-escalation.docx`  
**Stubs:** `code/08-posture-stub.ts`, `code/09-escalation-stub.ts`

- [ ] **5.1** Implement posture levels (GREEN/YELLOW/RED/BLACK)
- [ ] **5.2** Implement posture calculation from inventory
- [ ] **5.3** Build escalation message templates
- [ ] **5.4** Implement approval code parsing (APPROVE/DENY/DENY-ADD)
- [ ] **5.5** Implement timeout handling (fail-closed)
- [ ] **5.6** Wire escalation to messaging channels

---

## Phase 6: Layer 3 — Auditor Daemon 🚧

**Spec:** `docs/07-module-auditor.docx`  
**Stub:** `code/07-auditor-stub.ts`

- [ ] **6.1** Build health-check for Security Agent
- [ ] **6.2** Build health-check for Pattern Scanner
- [ ] **6.3** Implement ISOLATION MODE for gateway
- [ ] **6.4** Implement periodic workspace scanner
- [ ] **6.5** Build decision log storage
- [ ] **6.6** Create systemd/launchd service files
- [ ] **6.7** Write integration tests

---

## Phase 7: Gateway Integration 🚧

**Spec:** `docs/14-gateway-integration.docx`  
**Stub:** `code/14-gateway-hook.ts`

- [ ] **7.1** Implement `agent_tool_call` hook handler
- [ ] **7.2** Wire scanner into hook pipeline
- [ ] **7.3** Implement synchronous approval token flow
- [ ] **7.4** Test with OpenClaw gateway
- [ ] **7.5** Write E2E tests against `11-attack-scenarios.json`

---

## Phase 8: Dashboard 🚧

**Spec:** `docs/15-dashboard-spec.docx`  
**Wireframes:** `code/15-dashboard-wireframes.html`

- [ ] **8.1** Build REST API for dashboard data
- [ ] **8.2** Implement dashboard frontend (simple HTML/JS or React)
- [ ] **8.3** Wire posture display
- [ ] **8.4** Wire decision log viewer
- [ ] **8.5** Wire registry management UI

---

## Implementation Notes

### Presidio Decision

Microsoft Presidio is Python-based. Options:
1. **Run as sidecar service** — Python FastAPI wrapper, call from Node
2. **Use presidio-anonymizer npm package** — limited, may not have full analyzer
3. **Port patterns to JavaScript** — use regex directly, lose Presidio's NER

Recommendation: Start with sidecar service for accuracy, optimize later if needed.

### Model for Security Agent

Current Ollama models on thermidor:
- `qwen3-coder` — good for code, may work for classification
- `phi4` — smaller, faster

Test both against attack scenarios to pick best performer.

### Development Workflow

1. Read the stub file
2. Read the corresponding spec
3. Implement one function at a time
4. Test against corpus
5. Commit working increments

---

## Files Quick Reference

| Component | Spec | Stub | Tests |
|-----------|------|------|-------|
| Registry | `04-module-registry.docx` | `04-registry-stub.ts` | TBD |
| Scanner | `05-module-scanner.docx` | `05-scanner-stub.ts` | `11-test-corpus.json` |
| Security Agent | `06-module-security-agent.docx` | `06-security-agent-stub.ts` | `11-attack-scenarios.json` |
| Auditor | `07-module-auditor.docx` | `07-auditor-stub.ts` | TBD |
| Posture | `08-module-posture.docx` | `08-posture-stub.ts` | TBD |
| Escalation | `09-module-escalation.docx` | `09-escalation-stub.ts` | TBD |
| Gateway Hook | `14-gateway-integration.docx` | `14-gateway-hook.ts` | TBD |
| Dashboard | `15-dashboard-spec.docx` | `15-dashboard-wireframes.html` | TBD |
