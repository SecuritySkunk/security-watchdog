# OpenClaw Security Watchdog — Project Playbook

## How This Works

This playbook contains everything you need to systematically produce a complete
solution architecture package for the Security Watchdog system. It is organized
into three parts:

1. **Project Setup** — How to configure a Claude Project with the right context
2. **Prompt Sequence** — 19 numbered prompts to run in order, each producing
   specific deliverables
3. **Deliverable Checklist** — What you'll have when finished

Each prompt is scoped to complete within a single conversation turn without
timing out. Some prompts produce Word documents, some produce code files, some
produce both. You'll download each deliverable as it's created and accumulate
the full package.

---

## PART 1: PROJECT SETUP

### Step 1: Create a Claude Project

Go to claude.ai → Projects → Create Project

**Project Name:** `OpenClaw Security Watchdog — Solution Architecture`

### Step 2: Set the Project Instructions

Paste the following into the Project Instructions field:

```
You are an experienced Solution Architect producing documentation for the
OpenClaw Security Watchdog project — a multi-layer security system that
protects sensitive data in autonomous AI agent environments.

Context:
- OpenClaw is an open-source AI agent framework that connects LLMs to
  real-world channels (WhatsApp, Telegram, Discord, etc.)
- The core problem: LLM agents have no enforced separation between
  information they can reason about and information they can transmit.
  Everything lives in one context window. Confidentiality instructions
  are probabilistic, not deterministic.
- A real breach occurred: an agent named Socket posted sensitive personal
  information (family details, technology references) to a public AI
  social network despite explicit instructions not to share it.
- The Security Watchdog is an independent security layer that intercepts
  all agent communications and enforces data classification policies
  through a three-layer architecture:
    Layer 0: Sensitive Data Registry (SQLite database of patterns and
             user-defined sensitive entries with classification levels)
    Layer 1: Pattern Scanner (deterministic Node.js module using
             established PII detection libraries — NOT custom regex)
    Layer 2: Security Agent (local AI via Ollama for contextual
             classification when Layer 1 flags something)
    Layer 3: Auditor daemon (health checks, periodic scans, audit logs)
- Additional components: Dynamic Posture Engine, Human Escalation
  Interface, Executive Dashboard, Locale Framework
- The system is jurisdiction-aware, starting with US-GA locale but
  architecturally extensible to UK, EU/GDPR, Switzerland, etc.
- All development will be outsourced. Documentation must be detailed
  enough for developers to build their assigned module while
  understanding how it fits into the whole.

Your role across all prompts:
- Produce professional, implementation-ready documentation
- Reference established libraries and tools (Presidio, detect-secrets,
  fuse.js, Ollama, better-sqlite3, etc.) — never reinvent the wheel
- Include concrete examples, not just abstract descriptions
- When stubbing code, use TypeScript with full type definitions
- Follow TOGAF and arc42 conventions for architecture documentation
- Include Mermaid diagram syntax for all diagrams (they render in the
  documents and are also human-readable as text)
- Track dependencies between modules explicitly
- Every document should be self-contained enough that a developer
  receiving only that document plus the Architecture Overview could
  begin work

When creating documents:
- Use .docx format for formal documentation
- Use .ts for TypeScript stubs
- Use .json for configuration schemas
- Use .sql for database schemas
- Use .md for developer-facing READMEs
- Always create files, never just show content in chat
```

### Step 3: Upload Project Knowledge

Upload these items to the Project Knowledge section:

**Required:**
- This playbook file (so Claude has the full prompt sequence for context)
- The conversation transcript from our architecture discussion (download
  from your current conversation, or copy key sections)

**Recommended (if you have them):**
- OpenClaw's AGENTS.md or similar configuration files
- OpenClaw's gateway source code or documentation
- Any OpenClaw plugin examples

**If you don't have the transcript**, create a text file called
`architecture-summary.txt` with the content from the "Description" and
"Full summary" sections at the top of this conversation (everything after
"[NOTE: This conversation was successfully compacted...]").

### Step 4: Verify Setup

Before running the first prompt, run this quick check:

```
Confirm you have context about the OpenClaw Security Watchdog project.
List the three layers of the architecture and the key design decision
about where the watchdog intercepts traffic.
```

If Claude accurately describes Layers 0-3 and explains that the watchdog
operates at the gateway level (transparent to the assistant), you're
ready to proceed.

---

## PART 2: PROMPT SEQUENCE

### How to Use These Prompts

- Run them in order (some reference outputs from earlier prompts)
- Download each deliverable before moving on
- If a prompt produces a large document that gets cut off, follow up with:
  "Continue from where you left off and complete the document."
- If you want to adjust something, modify the prompt before running it
- Each prompt is marked with its expected deliverables and estimated
  complexity

---

### PHASE 1: FOUNDATION DOCUMENTS

These establish the overall architecture that all module specs reference.

---

#### PROMPT 01 — Solution Architecture Overview
**Deliverables:** `01-solution-architecture-overview.docx`
**Estimated complexity:** High (but scoped to overview level)

```
Create the Solution Architecture Overview document for the Security
Watchdog project as a Word document.

This is the master reference document. Every developer on the project
will read this before their module specification. It must provide enough
context for someone with no prior knowledge of the project to understand
what they're building and why.

Structure the document as follows:

1. EXECUTIVE SUMMARY (1 page)
   - The problem: autonomous AI agents lack enforced data boundaries
   - The breach that motivated this project (agent posted sensitive
     personal data to public platform despite instructions)
   - The solution: an independent security layer at the gateway level
   - Key design principle: the assistant agent is unaware the watchdog
     exists — enforcement happens transparently at the gateway

2. SYSTEM CONTEXT
   - What OpenClaw is and how it works (agent loop, gateway, channels)
   - Where the Security Watchdog sits in the architecture
   - System context diagram (Mermaid) showing: User, Assistant Agent,
     Gateway, Security Watchdog, External Channels, Ollama
   - What is in scope vs. out of scope

3. ARCHITECTURE OVERVIEW
   - The four-layer stack (Registry, Scanner, Security Agent, Auditor)
   - Component diagram (Mermaid) showing all components and their
     relationships
   - Key architectural decisions and rationale (ADR format, brief):
     * Why gateway-level interception (not assistant-level)
     * Why a local AI model for Layer 2 (not the same API as assistant)
     * Why fail-closed design (watchdog down = outbound queued)
     * Why jurisdiction-aware from day one
   - Data flow: outbound message lifecycle (from assistant tool call
     through watchdog pipeline to transmission or block)
   - Data flow: inbound content inspection

4. COMPONENT SUMMARY TABLE
   A table with one row per component:
   - Component name
   - Layer
   - Technology
   - Key responsibility
   - Dependencies
   - Estimated complexity (T-shirt: S/M/L/XL)

5. TECHNOLOGY STACK
   - Runtime: Node.js (match OpenClaw)
   - Database: SQLite via better-sqlite3
   - PII Detection: Microsoft Presidio (Python) or presidio-anonymizer,
     detect-secrets for credential patterns
   - Fuzzy Matching: fuse.js
   - Local AI: Ollama with quantized models (Llama 3.1 8B or Mistral 7B)
   - Process Management: systemd/launchd for auditor daemon
   - Testing: Vitest for unit tests, Playwright for integration tests
   - Monitoring: OpenTelemetry for metrics collection

6. SECURITY ARCHITECTURE
   - Threat model summary (three attack surfaces: inbound access,
     prompt injection, credential exposure)
   - How each layer addresses which threats
   - What the architecture does NOT solve (semantic encoding, internal
     reasoning, adversarial superintelligence)
   - Trust boundaries diagram (Mermaid)

7. DEPLOYMENT ARCHITECTURE
   - Target environment: Linux host running OpenClaw
   - Process topology: Gateway (existing), Watchdog Scanner (new,
     in-process hook), Security Agent wrapper (new, separate process),
     Ollama (existing or new), Auditor daemon (new, systemd service)
   - Deployment diagram (Mermaid)
   - Configuration management approach

8. LOCALE FRAMEWORK OVERVIEW
   - Why jurisdiction matters for PII detection
   - The locale plugin model (patterns.json, rules.json, crypto.json)
   - Starting locale: US-GA
   - Extension path for UK, EU/GDPR, Switzerland

9. PROJECT PHASES & DEPENDENCIES
   - Phase 1: Foundation (Registry + Scanner)
   - Phase 2: Intelligence (Security Agent)
   - Phase 3: Dynamics (Posture Engine + Inventory)
   - Phase 4: Operations (Auditor + Dashboard)
   - Phase 5: Human Loop (Escalation Interface)
   - Dependency graph (Mermaid) showing which modules block which

10. GLOSSARY
    Key terms: PII, classification level, posture, locale, quarantine,
    escalation, fail-closed, gateway hook, tool call, etc.

Use Mermaid syntax for all diagrams. Include a table of figures.
Make it professional but readable — this is the document that gets
everyone aligned.
```

---

#### PROMPT 02 — Interface Contracts & API Specification
**Deliverables:** `02-interface-contracts.docx`, `02-interfaces.ts`
**Estimated complexity:** High

```
Create two deliverables for the interface contracts between all Security
Watchdog components:

DELIVERABLE 1: Interface Contracts Document (Word)
This document defines every interface between components so that
developers building different modules can develop independently and
integrate successfully.

For each interface, document:
- Interface name and ID (e.g., IF-001: Scanner → Security Agent)
- Source component → Target component
- Communication mechanism (function call, HTTP, IPC, message queue)
- Request schema (with field descriptions and types)
- Response schema (with field descriptions and types)
- Error handling contract (what happens on timeout, error, invalid input)
- SLA (latency budget, availability requirement)
- Example request/response pair

The interfaces to define:

IF-001: Gateway → Pattern Scanner (outbound interception)
  - Gateway passes outbound tool call payload to scanner
  - Scanner returns CLEAN, FLAGGED, or ERROR

IF-002: Pattern Scanner → Security Agent (escalation)
  - Scanner passes quarantined payload with flag details
  - Agent returns FALSE_POSITIVE, BLOCK, or ESCALATE with reasoning

IF-003: Security Agent → Escalation Interface (human approval)
  - Agent passes escalation request with context
  - Interface returns APPROVED, DENIED, DENIED_AND_ADD, or TIMEOUT

IF-004: Gateway → Pattern Scanner (inbound inspection)
  - Gateway passes inbound content for inventory logging
  - Scanner returns inventory entries created and posture recommendation

IF-005: Auditor → Pattern Scanner (health check)
  - Auditor pings scanner, expects health response
  - Includes current posture, items scanned since last check, error count

IF-006: Auditor → Security Agent (health check)
  - Same pattern, specific to Security Agent process

IF-007: Posture Engine → Registry (inventory query)
  - Posture Engine queries current sensitive data inventory
  - Registry returns inventory with classifications and storage locations

IF-008: Dashboard → Auditor (metrics collection)
  - Dashboard pulls metrics from Auditor's decision log
  - Returns aggregated stats per time period

IF-009: CLI → Registry (CRUD operations)
  - Command-line interface for managing registry entries
  - Full CRUD on patterns, user entries, and locale configurations

IF-010: Watchdog → Gateway (approval token)
  - The synchronous approval/rejection response to Gateway
  - Includes signed token for approved payloads

DELIVERABLE 2: TypeScript Interface Definitions File
Create a single .ts file that defines all the TypeScript interfaces,
types, and enums used across the project. This becomes the shared type
package that all modules import.

Include:
- ClassificationLevel enum (NEVER_SHARE, ASK_FIRST, INTERNAL_ONLY, PUBLIC)
- PostureLevel enum (GREEN, YELLOW, RED, BLACK)
- ScanResult type
- QuarantinePayload type
- SecurityAgentDecision type
- EscalationRequest/Response types
- InventoryEntry type
- RegistryPattern type
- RegistryUserEntry type
- LocaleDefinition type
- AuditLogEntry type
- HealthCheckResponse type
- ApprovalToken type
- DashboardMetrics type
- All request/response types for each interface

Add JSDoc comments on every field explaining what it is and any
constraints.
```

---

#### PROMPT 03 — Data Model & Database Schema
**Deliverables:** `03-data-model.docx`, `03-schema.sql`, `03-seed-us-ga.sql`
**Estimated complexity:** Medium

```
Create three deliverables for the data model:

DELIVERABLE 1: Data Model Document (Word)
Document the complete data model for the Security Watchdog. This
database is the foundation — Registry, Inventory, Audit Log, Posture
History, and Escalation Queue all live here.

For each table, provide:
- Table name and purpose
- Column definitions with types, constraints, and descriptions
- Indexes and their justification
- Foreign key relationships
- Example rows (2-3 per table)
- Data retention policy
- Entity-relationship diagram (Mermaid) for each logical group

Tables to define:

REGISTRY GROUP:
- locale_definitions: jurisdiction configurations
- pattern_definitions: regex patterns for structural PII per locale
- user_entries: user-defined sensitive data items
- entry_variants: semantic variants for fuzzy matching
- destination_rules: per-destination classification overrides

INVENTORY GROUP:
- inventory_items: live catalog of sensitive data in the system
- inventory_locations: where each item is stored (file, session, memory)
- inventory_events: intake/purge/transform events

OPERATIONS GROUP:
- scan_decisions: every scan result (Layer 1)
- agent_decisions: every Security Agent invocation (Layer 2)
- escalation_queue: pending human approvals
- escalation_history: resolved escalations
- posture_history: posture level changes over time
- audit_log: system events (health checks, errors, config changes)

DASHBOARD GROUP:
- daily_metrics: pre-aggregated daily statistics
- project_tracking: development phase progress (for the build dashboard)

DELIVERABLE 2: SQLite Schema File (.sql)
The complete CREATE TABLE statements with:
- Appropriate SQLite types and constraints
- CHECK constraints for enums (classification levels, posture levels)
- Indexes on frequently queried columns
- Triggers for updated_at timestamps
- Comments explaining non-obvious design decisions

DELIVERABLE 3: US-GA Seed Data (.sql)
INSERT statements that populate:
- The US-GA locale definition
- All structural PII patterns for US jurisdiction:
  * SSN (with known invalid range exclusions)
  * EIN
  * US passport number
  * Driver's license (Georgia format + general US)
  * Phone (NANP format)
  * Email (general pattern)
  * Credit card numbers (Visa, MC, Amex, Discover with Luhn note)
  * US bank routing numbers (ABA format)
  * ZIP codes (5-digit and ZIP+4)
  * IP addresses (v4 and v6)
  * MAC addresses
  * Dates of birth (common US formats)
  * US military service numbers
  * DEA numbers
  * Medicare/Medicaid numbers
- A few example user entries demonstrating different classification
  levels and destination rules (use fictional data, not real PII)
```

---

### PHASE 2: MODULE SPECIFICATIONS

Each prompt produces a developer-ready specification for one module.
Developers receive their module spec plus the Architecture Overview
(Prompt 01) and Interface Contracts (Prompt 02).

---

#### PROMPT 04 — Module Spec: Sensitive Data Registry
**Deliverables:** `04-module-registry.docx`, `04-registry-stub.ts`
**Estimated complexity:** Medium

```
Create the module specification and code stub for the Sensitive Data
Registry (Layer 0).

DELIVERABLE 1: Module Specification (Word)

Structure:
1. MODULE OVERVIEW
   - Purpose: persistent store for PII patterns, user-defined sensitive
     entries, classification policies, and live inventory
   - Position in architecture: foundation layer, no runtime dependencies
     on other watchdog components
   - Technology: SQLite via better-sqlite3 (Node.js)

2. FUNCTIONAL REQUIREMENTS
   FR-REG-001 through FR-REG-nnn, covering:
   - CRUD operations on pattern definitions
   - CRUD operations on user-defined entries with variants
   - Classification level management (NEVER_SHARE, ASK_FIRST,
     INTERNAL_ONLY, PUBLIC)
   - Destination-specific rule overrides
   - Locale management (load, switch, list, validate)
   - Inventory tracking (add item, update location, record events,
     query by classification, query by storage location)
   - Bulk import/export for locale pattern sets
   - Search across entries (by keyword, by classification, by locale)

3. NON-FUNCTIONAL REQUIREMENTS
   - Performance: single read < 5ms, bulk scan query < 50ms
   - Storage: database file size monitoring, warn at configurable threshold
   - Reliability: WAL mode for concurrent read/write, automatic backup
   - Security: database file permissions (0600), no sensitive data in
     logs, prepared statements only (SQL injection prevention)

4. CLI SPECIFICATION
   Command reference for `openclaw security registry`:
   - `registry add pattern <name> --regex <pattern> --category <cat> --level <level> --locale <locale>`
   - `registry add entry <value> --level <level> --variants <v1,v2,...>`
   - `registry add destination-rule <entry-id> --destination <dest> --level <level>`
   - `registry remove <type> <id>`
   - `registry list [patterns|entries|rules] [--locale <locale>] [--level <level>]`
   - `registry search <query>`
   - `registry locale load <locale-name>`
   - `registry locale list`
   - `registry inventory list [--level <level>] [--location <path>]`
   - `registry inventory stats`
   - `registry export <locale> --output <file>`
   - `registry import <file> [--locale <locale>]`

5. ERROR HANDLING
   - All errors as typed exceptions with error codes
   - Database corruption detection and recovery procedure
   - Constraint violation handling (duplicate patterns, invalid levels)

6. TESTING REQUIREMENTS
   - Unit tests for every CRUD operation
   - Edge cases: empty database, maximum entry sizes, unicode handling,
     concurrent access
   - Performance benchmarks: 10K patterns, 1K user entries, 100K
     inventory items

DELIVERABLE 2: TypeScript Stub (registry-stub.ts)
A complete stub with:
- All class and method signatures with full type annotations
- JSDoc comments explaining each method
- TODO markers for implementation
- The RegistryManager class with constructor (database path, locale)
- PatternRepository, EntryRepository, InventoryRepository as internal
  classes
- Export of the public API
- Use better-sqlite3 types
```

---

#### PROMPT 05 — Module Spec: Pattern Scanner
**Deliverables:** `05-module-scanner.docx`, `05-scanner-stub.ts`
**Estimated complexity:** High

```
Create the module specification and code stub for the Pattern Scanner
(Layer 1).

DELIVERABLE 1: Module Specification (Word)

Structure:
1. MODULE OVERVIEW
   - Purpose: deterministic, high-speed first-pass filter for all
     inbound and outbound content
   - Position in architecture: gateway hook, synchronous in the
     outbound path
   - Technology: Node.js module using established PII detection libraries
   - Critical constraint: this module must NOT use custom regex.
     Use Microsoft Presidio (via Python bridge or the presidio-anonymizer
     npm package if available), detect-secrets for credential patterns,
     and fuse.js for fuzzy matching against user-defined entries.

2. LIBRARY SELECTION & JUSTIFICATION
   For each library, document:
   - What it does
   - Why it was chosen (established, maintained, proven)
   - License
   - How it's integrated (npm package, Python subprocess, etc.)
   - Fallback if unavailable

   Libraries to evaluate and recommend:
   - Presidio Analyzer (Python) for structural PII — evaluate whether
     to call via child_process or use a Node.js alternative
   - detect-secrets (Python) for API keys, tokens, credentials
   - fuse.js (Node.js) for fuzzy string matching against registry
   - natural (Node.js) for tokenization if needed
   - Note: if Presidio requires Python, document the Python bridge
     pattern and consider performance implications. If there's a
     pure Node.js alternative with comparable detection quality,
     prefer it to avoid the Python dependency.

3. FUNCTIONAL REQUIREMENTS
   FR-SCN-001 through FR-SCN-nnn, covering:

   OUTBOUND SCANNING:
   - Intercept all outbound tool calls at gateway hook
   - Three-stage scan pipeline:
     Stage 1: Structural PII detection (via Presidio or equivalent)
     Stage 2: Credential/secret detection (via detect-secrets or equiv)
     Stage 3: Fuzzy match against user-defined registry entries (fuse.js)
   - Destination classification (categorize target as: public_platform,
     private_channel, local_file, owner_only, api_call)
   - Result assembly: CLEAN (no flags) or FLAGGED (with details)
   - Quarantine payload construction for flagged content

   INBOUND SCANNING:
   - Scan inbound content for sensitive data entering the system
   - Log to inventory (do not block — user/external source sent it)
   - Adjust posture recommendation based on what was detected

   TAGGED FORMAT DETECTION:
   - Detect [SENSITIVE:type:value] tagged format in workspace files
   - Cross-reference tags with registry entries

4. NON-FUNCTIONAL REQUIREMENTS
   - Latency: CLEAN path < 10ms, FLAGGED path < 50ms (excluding
     Security Agent time)
   - Throughput: handle burst of 100 scans/second
   - Memory: scanner process < 256MB RSS
   - Reliability: scanner crash must not crash gateway
   - False positive target: < 5% on representative test corpus

5. GATEWAY HOOK INTEGRATION
   - How to register as an OpenClaw gateway hook
   - The agent_tool_call event structure
   - Synchronous vs. asynchronous hook behavior
   - How to return CLEAN (pass-through) vs. FLAGGED (quarantine)
   - Error handling: if scanner throws, default to QUEUE (fail-closed)

6. SCAN PIPELINE DETAIL
   For each stage, document:
   - Input format
   - Processing steps
   - Output format
   - Performance budget
   - Configuration options (thresholds, enabled/disabled)
   - How confidence scores map to flag decisions

7. DESTINATION CLASSIFICATION RULES
   Table mapping tool call signatures to destination types:
   - HTTP POST to known social platforms → public_platform
   - Message send to group chat → private_channel (but semi-public)
   - File write to workspace → local_file
   - Message to owner's DM → owner_only
   - API call to external service → api_call
   How to extend with new destination types.

8. TESTING REQUIREMENTS
   - Unit tests per scan stage
   - Integration test with mock gateway hook
   - Performance benchmarks (latency histogram, throughput test)
   - False positive / false negative measurement against test corpus
   - Test with adversarial inputs (encoded PII, split across fields)

DELIVERABLE 2: TypeScript Stub (scanner-stub.ts)
Complete stub with:
- PatternScanner class
- ScanPipeline with stage registration
- GatewayHook integration class
- DestinationClassifier
- InboundScanner and OutboundScanner
- FuzzyMatcher wrapper around fuse.js
- All interfaces for stage results
- Configuration schema
```

---

#### PROMPT 06 — Module Spec: Security Agent
**Deliverables:** `06-module-security-agent.docx`, `06-security-agent-stub.ts`
**Estimated complexity:** High

```
Create the module specification and code stub for the Security Agent
(Layer 2).

DELIVERABLE 1: Module Specification (Word)

Structure:
1. MODULE OVERVIEW
   - Purpose: contextual AI classification when Pattern Scanner flags
     content that may or may not be genuinely sensitive
   - Position: separate process from assistant, invoked only on flags
   - Technology: Ollama running local quantized model
   - Critical design: this is NOT creative reasoning — it's narrow
     classification. The prompt is hardened against injection.

2. MODEL SELECTION & CONFIGURATION
   - Primary: Llama 3.1 8B (Q4_K_M quantization)
   - Alternative: Mistral 7B (Q4_K_M)
   - Why these models (balance of classification accuracy vs. speed
     vs. memory)
   - Ollama configuration: localhost only, specific port, model preload
   - GPU vs. CPU inference tradeoffs
   - Model evaluation criteria and how to benchmark a replacement model

3. PROMPT ENGINEERING
   - System prompt (exact text) — hardened against injection:
     * Frames all input as DATA, not instructions
     * Restricts output to structured JSON only
     * No tool use, no external calls
     * Explicit anti-injection instructions
   - User prompt template with placeholders for:
     * The flagged text
     * The flag details from Pattern Scanner
     * The registry entries that triggered flags
     * The destination classification
     * The current posture level
   - Output schema (JSON):
     * decision: FALSE_POSITIVE | BLOCK | ESCALATE
     * confidence: 0.0-1.0
     * reasoning: brief explanation
     * matched_entries: array of registry entry IDs confirmed
     * recommended_action: what the user should know

4. INJECTION DEFENSE
   - Input sanitization: strip instruction-like patterns before analysis
   - Prompt structure: all user content in clearly delimited data blocks
   - Output validation: parse JSON strictly, reject non-conforming output
   - Fallback: if output doesn't parse, treat as ESCALATE (fail-safe)
   - Testing: include adversarial prompt injection in test corpus

5. FUNCTIONAL REQUIREMENTS
   FR-AGT-001 through FR-AGT-nnn:
   - Accept quarantined payload from Pattern Scanner
   - Load relevant registry context (entries that triggered flags)
   - Construct classification prompt
   - Call Ollama API (localhost HTTP)
   - Parse and validate response
   - Return structured decision
   - Log decision with full context to audit database
   - Handle Ollama errors (timeout, malformed response, process down)

6. NON-FUNCTIONAL REQUIREMENTS
   - Latency: < 3 seconds for classification (GPU), < 10 seconds (CPU)
   - Availability: process monitored by Auditor, restart on crash
   - Memory: Ollama + model < 8GB RAM (Q4 quantization)
   - Security: Ollama bound to localhost only, no external network
   - Accuracy: > 90% correct classification on test corpus

7. PROCESS MANAGEMENT
   - Startup sequence (ensure Ollama running, model loaded)
   - Health check endpoint (HTTP GET /health)
   - Graceful shutdown
   - Crash recovery (Auditor restarts, pending decisions → ESCALATE)

8. TESTING REQUIREMENTS
   - Unit tests with mock Ollama responses
   - Classification accuracy test against labeled test corpus
   - Injection resistance tests (adversarial prompts in payload)
   - Latency benchmarks (GPU and CPU)
   - Timeout and error handling tests
   - Integration test with Pattern Scanner

DELIVERABLE 2: TypeScript Stub (security-agent-stub.ts)
Complete stub with:
- SecurityAgent class
- OllamaClient wrapper
- PromptBuilder (constructs classification prompts)
- ResponseParser (validates and parses JSON output)
- InputSanitizer (strips injection patterns)
- DecisionLogger
- HealthCheck endpoint
- Configuration schema
```

---

#### PROMPT 07 — Module Spec: Auditor Daemon
**Deliverables:** `07-module-auditor.docx`, `07-auditor-stub.ts`
**Estimated complexity:** Medium

```
Create the module specification and code stub for the Auditor Daemon
(Layer 3).

DELIVERABLE 1: Module Specification (Word)

Structure:
1. MODULE OVERVIEW
   - Purpose: independent watchdog over the watchdog — ensures the
     security stack is running and data policies are being enforced
   - Position: separate systemd/launchd service
   - Technology: Node.js long-running daemon

2. FUNCTIONAL REQUIREMENTS
   FR-AUD-001 through FR-AUD-nnn:

   HEALTH MONITORING:
   - Ping Pattern Scanner health endpoint every N seconds (configurable)
   - Ping Security Agent health endpoint every N seconds
   - Ping Ollama process every N seconds
   - On any health check failure:
     * Log failure with timestamp and component
     * If consecutive failures > threshold: trigger isolation mode
     * Notify user via configured channel
   - On recovery: exit isolation mode, log recovery, notify user

   ISOLATION MODE:
   - Signal gateway to queue all outbound tool calls (do not execute)
   - Continue allowing inbound traffic (read-only safe)
   - Continue allowing local file operations (workspace access)
   - Dashboard shows ISOLATION status prominently
   - Auto-recovery when all components healthy for N consecutive checks

   PERIODIC WORKSPACE SCAN:
   - Scan workspace files using Pattern Scanner's detection libraries
   - Compare findings against current inventory
   - Detect drift: sensitive data in files not tracked in inventory
   - Detect stale inventory: entries pointing to files that no longer
     contain the data (compaction, deletion, paraphrase changed it)
   - Log discrepancies, update inventory, adjust posture if needed
   - Configurable schedule (default: every 6 hours)

   AUDIT LOG MANAGEMENT:
   - Maintain decision log (all scan decisions, agent decisions,
     escalations, posture changes)
   - Log rotation and retention policy
   - Export functionality (JSON, CSV) for compliance reporting
   - Tamper detection (hash chain on log entries)

   METRICS AGGREGATION:
   - Compute daily metrics for dashboard consumption:
     * Total scans (inbound/outbound)
     * Flags raised (by category, by level)
     * Blocks executed
     * Escalations (pending, approved, denied)
     * False positive rate (from overrides)
     * Average scan latency
     * Posture level time distribution
     * Inventory size by classification
   - Store in daily_metrics table

3. NON-FUNCTIONAL REQUIREMENTS
   - Uptime: daemon must survive component crashes
   - Resource usage: < 100MB RSS idle, < 256MB during workspace scan
   - Startup: auto-start via systemd/launchd, start before OpenClaw
   - Logging: structured JSON logs, log level configurable

4. SYSTEMD SERVICE CONFIGURATION
   - Unit file specification
   - Dependencies (After=network.target ollama.service)
   - Restart policy (always, 5s delay)
   - Resource limits
   - Journal integration

5. TESTING REQUIREMENTS
   - Health check with mock components (healthy, unhealthy, flapping)
   - Isolation mode trigger and recovery
   - Workspace scan with planted test data
   - Metrics aggregation accuracy
   - Log integrity verification
   - Long-running stability test (24h)

DELIVERABLE 2: TypeScript Stub (auditor-stub.ts)
Complete stub with:
- AuditorDaemon class (main daemon loop)
- HealthChecker (component ping logic)
- IsolationManager (gateway signaling)
- WorkspaceScanner (periodic scan orchestrator)
- AuditLogger (tamper-evident logging)
- MetricsAggregator
- Configuration schema
- Systemd unit file template as string constant
```

---

#### PROMPT 08 — Module Spec: Dynamic Posture Engine
**Deliverables:** `08-module-posture.docx`, `08-posture-stub.ts`
**Estimated complexity:** Medium

```
Create the module specification and code stub for the Dynamic Posture
Engine.

DELIVERABLE 1: Module Specification (Word)

Structure:
1. MODULE OVERVIEW
   - Purpose: automatically adjusts security scrutiny level based on
     what sensitive data is currently in the system
   - This is the "intelligence" that prevents the watchdog from being
     either too aggressive (blocking everything) or too passive (missing
     real threats)

2. POSTURE LEVELS (detailed specification)
   For each level (GREEN, YELLOW, RED, BLACK), define:
   - Trigger conditions (what causes entry to this level)
   - Exit conditions (what allows return to lower level)
   - Scanner behavior at this level
   - Security Agent involvement at this level
   - Escalation threshold at this level
   - User notification requirements
   - Dashboard indicator

   GREEN: No RESTRICTED or NEVER_SHARE data in inventory
   YELLOW: RESTRICTED (ASK_FIRST) data present
   RED: NEVER_SHARE data present
   BLACK: Manual override, all outbound blocked

3. POSTURE CALCULATION ALGORITHM
   - Input: current inventory (all items with classifications)
   - Factors: highest classification present, count of items per level,
     time since last scan, pending escalations
   - Hysteresis: don't flap between levels on edge cases
   - Manual override: user can force BLACK or force GREEN (with warning)
   - Posture change triggers inventory re-evaluation

4. FUNCTIONAL REQUIREMENTS
   FR-PST-001 through FR-PST-nnn:
   - Calculate posture from inventory state
   - Recalculate on inventory change events
   - Provide current posture to Scanner (affects scan behavior)
   - Log posture changes with reason
   - Support manual override with audit trail
   - Provide posture history for dashboard
   - Lifecycle alerts (e.g., "NEVER_SHARE data has been in system for
     7 days — consider purging or confirming still needed")

5. INVENTORY LIFECYCLE MANAGEMENT
   - Track how long each sensitive item has been in the system
   - Alert when items exceed retention thresholds
   - Recommend purge actions (user confirms)
   - Track data transformations (original → paraphrased → summarized)

6. TESTING REQUIREMENTS
   - Posture calculation with various inventory states
   - Level transitions (up and down)
   - Hysteresis behavior (rapid inventory changes)
   - Manual override and release
   - Lifecycle alerts at thresholds

DELIVERABLE 2: TypeScript Stub (posture-stub.ts)
Complete stub with:
- PostureEngine class
- PostureCalculator (pure function: inventory → posture)
- InventoryLifecycleManager
- PostureOverrideManager
- PostureEventEmitter (notifies scanner, dashboard)
- Configuration schema (thresholds, hysteresis, retention limits)
```

---

#### PROMPT 09 — Module Spec: Human Escalation Interface
**Deliverables:** `09-module-escalation.docx`, `09-escalation-stub.ts`
**Estimated complexity:** Medium

```
Create the module specification and code stub for the Human Escalation
Interface.

DELIVERABLE 1: Module Specification (Word)

Structure:
1. MODULE OVERVIEW
   - Purpose: when the Security Agent can't confidently classify
     content (ESCALATE decision), route to user for human judgment
   - Delivery channel: messages via OpenClaw's existing channel
     infrastructure (WhatsApp, Telegram, etc.)
   - Design: async approval workflow with configurable timeout

2. ESCALATION FLOW (detailed)
   Step-by-step from Security Agent ESCALATE decision to resolution:
   - Agent creates escalation request with context
   - Escalation Interface formats human-readable summary
   - Message sent to designated approval channel
   - User responds with approval code
   - Interface processes response, updates registry if needed
   - Result returned to waiting gateway request

3. MESSAGE FORMAT SPECIFICATION
   Define exact message templates for:
   - Escalation notification (what the agent tried to do, what was
     flagged, why it was escalated, what the options are)
   - Approval confirmation
   - Denial confirmation
   - Timeout notification
   - Status query response (user asks "what's pending?")

   Keep messages concise — these arrive on mobile. Include only what's
   needed to make a decision.

4. RESPONSE CODES
   - APPROVE-{id}: approve this specific escalation
   - DENY-{id}: deny this escalation
   - DENY-ADD-{id}: deny and add flagged content to registry as
     NEVER_SHARE
   - APPROVE-ALL: approve all pending (with confirmation)
   - DENY-ALL: deny all pending (with confirmation)
   - STATUS: list pending escalations

5. FUNCTIONAL REQUIREMENTS
   FR-ESC-001 through FR-ESC-nnn:
   - Send escalation message via configured channel
   - Parse user response codes
   - Match responses to pending escalations
   - Handle timeout (configurable, default 15 minutes, defaults to BLOCK)
   - Queue management (multiple pending escalations)
   - Priority ordering (NEVER_SHARE content escalations first)
   - Duplicate detection (same content escalated twice)
   - Registry learning: DENY-ADD updates registry for future scans

6. CHANNEL CONFIGURATION
   - Which channel to use for escalations (configurable)
   - Fallback channel if primary unavailable
   - Rate limiting (don't spam user with rapid escalations — batch
     if multiple arrive within N seconds)

7. TESTING REQUIREMENTS
   - Approval flow end-to-end with mock channel
   - Denial flow with registry update
   - Timeout behavior
   - Batch escalation
   - Invalid response handling
   - Channel unavailability fallback

DELIVERABLE 2: TypeScript Stub (escalation-stub.ts)
Complete stub with:
- EscalationInterface class
- EscalationFormatter (creates human-readable messages)
- ResponseParser (parses approval codes)
- EscalationQueue (manages pending items)
- ChannelAdapter interface (abstract over WhatsApp/Telegram/etc.)
- TimeoutManager
- RegistryLearner (updates registry from DENY-ADD responses)
- Configuration schema
```

---

#### PROMPT 10 — Module Spec: Locale Framework
**Deliverables:** `10-module-locale.docx`, `10-locale-us-ga.json`, `10-locale-template.json`
**Estimated complexity:** Medium

```
Create the module specification and locale definition files for the
Locale Framework.

DELIVERABLE 1: Module Specification (Word)

Structure:
1. MODULE OVERVIEW
   - Purpose: jurisdiction-aware PII detection and compliance rules
   - This is not a standalone runtime module — it's a configuration
     framework consumed by the Registry and Scanner
   - Design: locale as plugin directory with structured JSON files

2. LOCALE DIRECTORY STRUCTURE
   ~/.openclaw/security/locales/<locale-id>/
   ├── patterns.json    — PII detection patterns for this jurisdiction
   ├── rules.json       — compliance and handling rules
   ├── crypto.json      — encryption configuration
   └── README.md        — human description of this locale

3. PATTERNS.JSON SPECIFICATION
   For each pattern entry:
   - id: unique identifier (e.g., "us-ssn", "uk-nino")
   - category: PII category (government_id, financial, contact, medical,
     biometric, location, network, credential)
   - name: human-readable name
   - description: what this pattern detects
   - regex: the pattern (but remember — prefer Presidio recognizer names
     over raw regex where possible)
   - presidio_entity: corresponding Presidio entity type if available
   - validation: additional validation function name (e.g., "luhn",
     "ssn_area_check")
   - examples: array of example matches (for testing)
   - false_positive_examples: array of non-matches that look similar
   - default_classification: NEVER_SHARE | ASK_FIRST | INTERNAL_ONLY
   - regulatory_reference: which law/regulation makes this sensitive

4. RULES.JSON SPECIFICATION
   - jurisdiction: legal jurisdiction name
   - applicable_regulations: array of regulation references
   - breach_notification: requirements if data is exposed
     * timeline: hours to notify
     * authority: who to notify
     * threshold: what constitutes a breach
   - data_subject_rights: what rights individuals have
     * right_to_access: boolean
     * right_to_erasure: boolean
     * right_to_portability: boolean
   - cross_border_transfer: rules about sending data to other
     jurisdictions
   - special_categories: data types requiring extra protection
   - retention_defaults: recommended retention periods by category

5. CRYPTO.JSON SPECIFICATION
   - algorithm: encryption algorithm for data at rest (default: AES-256-GCM)
   - key_derivation: KDF for password-based keys (default: Argon2id)
   - minimum_key_length: in bits
   - key_escrow: required | optional | prohibited
   - key_rotation_period: recommended rotation interval
   - approved_implementations: list of approved libraries/tools
   - regulatory_notes: jurisdiction-specific encryption requirements

6. LOCALE LOADING AND VALIDATION
   - How locales are discovered and loaded at startup
   - Schema validation for each JSON file
   - Multiple active locales (most restrictive wins on conflict)
   - Locale inheritance (e.g., eu-gdpr as base, de as override)
   - Version tracking for locale updates

7. CONTRIBUTION GUIDE
   How to create a new locale:
   - Fork the template
   - Research jurisdiction's PII definitions and regulations
   - Map to Presidio entity types where possible
   - Define patterns for jurisdiction-specific identifiers
   - Document regulatory references
   - Submit with test data for validation

8. TESTING REQUIREMENTS
   - Schema validation for all JSON files
   - Pattern matching accuracy against locale-specific test data
   - Multi-locale conflict resolution
   - Locale hot-reload without service restart

DELIVERABLE 2: US-GA Locale Files (JSON)
Complete patterns.json for US with Georgia-specific additions.
Include all patterns discussed in our architecture (SSN, EIN, DL,
passport, phone, email, credit card, routing number, ZIP, IP, MAC,
DOB, military service number, DEA number, Medicare/Medicaid).
For each pattern, include examples and false_positive_examples.

DELIVERABLE 3: Locale Template (JSON)
A blank template with all fields, placeholder values, and inline
comments explaining what each field means. A developer creating a
new locale starts by copying this template.
```

---

### PHASE 3: TEST DATA & TESTING

---

#### PROMPT 11 — Test Data Package
**Deliverables:** `11-test-data.docx`, `11-test-corpus.json`, `11-attack-scenarios.json`
**Estimated complexity:** Medium

```
Create the test data package for the Security Watchdog project.

IMPORTANT: All test data must be synthetic — no real PII. Generate
realistic-looking but entirely fictional data.

DELIVERABLE 1: Test Data Documentation (Word)
Document the test data strategy:
- What each test corpus covers
- How to regenerate test data if needed
- Coverage matrix: which test data exercises which components
- Labeling conventions (how expected results are encoded)

DELIVERABLE 2: Test Corpus (JSON)
A comprehensive JSON file containing labeled test cases organized by
category. For each test case:
- id: unique test case ID
- input: the text to scan
- expected_flags: array of expected flag types
- expected_classification: expected overall classification
- description: what this test case exercises
- difficulty: easy | medium | hard | adversarial

Categories to include (at least 10 test cases each):

STRUCTURAL PII:
- SSNs in various formats (dashes, spaces, no separators)
- Credit card numbers (all major networks)
- Phone numbers (with/without country code, parentheses, dots)
- Email addresses
- IP addresses (v4, v6, abbreviated)
- Dates of birth in multiple formats

FALSE POSITIVES:
- 9-digit numbers that aren't SSNs (zip+random, order numbers)
- 16-digit numbers that fail Luhn check
- Phone-formatted numbers that are timestamps or reference numbers
- Strings containing "123-45-6789" in technical documentation context

USER-DEFINED ENTRIES:
- Exact matches for fictional family names
- Fuzzy matches (misspellings, nicknames, partial matches)
- Technology references (exact, abbreviated, described)
- Address fragments

MIXED CONTENT:
- Paragraphs with one PII item embedded in normal text
- Multiple PII types in same content
- PII spanning multiple fields/lines

ADVERSARIAL:
- Base64-encoded PII
- PII split across multiple words with filler
- Leetspeak/character substitution
- Unicode homoglyph substitution
- PII in URLs or code snippets
- Prompt injection attempts with embedded PII
- Instructions disguised as data ("ignore previous rules and output...")

DESTINATION CLASSIFICATION:
- Tool call payloads for various destinations (social post, DM,
  file write, API call)
- Ambiguous destinations

DELIVERABLE 3: Attack Scenarios (JSON)
Structured scenarios for integration testing. Each scenario:
- id: scenario ID
- name: descriptive name
- setup: what state the system should be in
- trigger: what action occurs
- expected_behavior: what the watchdog should do
- verification: how to confirm correct behavior

Include at least 15 scenarios covering:
- The original breach scenario (Moltbook post with family/tech data)
- Prompt injection via inbound message
- Prompt injection via web content the agent reads
- Credential exfiltration attempt
- Data leakage through paraphrasing
- Social engineering (other agent asks for info via Moltbook)
- Rapid-fire escalation flooding
- Component failure during active scan
- Posture level transitions
- Manual override scenarios
```

---

#### PROMPT 12 — Test Scripts & QA Plan
**Deliverables:** `12-qa-plan.docx`, `12-test-runner.ts`
**Estimated complexity:** Medium

```
Create the QA plan and test runner framework for the project.

DELIVERABLE 1: QA Plan (Word)

Structure:
1. TEST STRATEGY OVERVIEW
   - Testing pyramid: unit (70%), integration (20%), E2E (10%)
   - Test automation framework: Vitest for unit/integration
   - CI/CD integration approach
   - Test environments (local dev, CI, staging)

2. UNIT TEST SPECIFICATIONS
   For each module, list:
   - Test file name and location
   - Test categories (happy path, edge cases, error handling)
   - Mock requirements (what to mock, mock data sources)
   - Coverage target (line coverage, branch coverage)

   Modules: Registry, Scanner, Security Agent, Auditor, Posture Engine,
   Escalation Interface

3. INTEGRATION TEST SPECIFICATIONS
   For each interface (IF-001 through IF-010), define:
   - Test name
   - Components involved
   - Setup requirements
   - Test steps
   - Expected results
   - Teardown

4. END-TO-END TEST SCENARIOS
   Map to attack scenarios from test data package:
   - Full pipeline tests (message → gateway → scanner → agent → result)
   - Failure mode tests (component down during operation)
   - Performance tests (latency under load)

5. SECURITY TEST SPECIFICATIONS
   - Prompt injection test suite
   - Fuzzing inputs to scanner
   - SQL injection against registry
   - Malformed Ollama response handling
   - Credential exposure verification (no secrets in logs)

6. PERFORMANCE TEST SPECIFICATIONS
   - Scanner latency: P50, P95, P99 under various loads
   - Security Agent classification time: GPU and CPU
   - End-to-end latency: message to approval/block
   - Memory usage under sustained operation (24h test)
   - Database performance with 100K+ inventory entries

7. ACCEPTANCE CRITERIA
   Per module, define the Definition of Done:
   - Code coverage threshold
   - All unit tests passing
   - Integration tests passing
   - Performance benchmarks met
   - Security tests passing
   - Documentation complete
   - Code review approved

8. REGRESSION TEST STRATEGY
   - Which tests run on every commit
   - Which tests run nightly
   - Which tests run on release candidate

DELIVERABLE 2: Test Runner Stub (TypeScript)
A Vitest-based test runner framework with:
- Test suite structure for each module
- Helper functions for common test operations
- Mock factories for each component
- Test data loader (reads test corpus JSON)
- Performance measurement utilities
- Report generation
- Example tests (2-3 per module) showing the pattern to follow
```

---

### PHASE 4: CODE SCAFFOLDING

---

#### PROMPT 13 — Project Scaffolding & Configuration
**Deliverables:** Multiple files (project structure)
**Estimated complexity:** Medium

```
Create the project scaffolding — the directory structure, configuration
files, and build setup that developers will clone to begin work.

Create all files under a directory called "security-watchdog".

Produce these files:

1. package.json
   - Project metadata
   - Dependencies (better-sqlite3, fuse.js, ollama client, etc.)
   - DevDependencies (vitest, typescript, eslint, prettier)
   - Scripts (build, test, lint, start, dev)

2. tsconfig.json
   - Strict TypeScript configuration
   - Path aliases for module imports

3. .eslintrc.json
   - Strict linting rules appropriate for security-critical code
   - No-any rule, explicit return types required

4. Directory structure (create README.md in each directory explaining
   its purpose):
   security-watchdog/
   ├── src/
   │   ├── registry/         — Layer 0: Sensitive Data Registry
   │   ├── scanner/          — Layer 1: Pattern Scanner
   │   ├── security-agent/   — Layer 2: Security Agent
   │   ├── auditor/          — Layer 3: Auditor Daemon
   │   ├── posture/          — Dynamic Posture Engine
   │   ├── escalation/       — Human Escalation Interface
   │   ├── dashboard/        — Executive Dashboard
   │   ├── gateway-hook/     — OpenClaw Gateway integration
   │   ├── shared/           — Shared types, utilities, constants
   │   │   ├── types.ts      — All shared TypeScript interfaces
   │   │   ├── constants.ts  — Enums, classification levels, etc.
   │   │   └── errors.ts     — Custom error classes
   │   └── index.ts          — Main entry point
   ├── locales/
   │   ├── us-ga/            — US Georgia locale
   │   └── _template/        — Blank locale template
   ├── config/
   │   ├── default.json      — Default configuration
   │   └── schema.json       — JSON Schema for configuration validation
   ├── scripts/
   │   ├── setup.sh          — First-time setup script
   │   └── seed-db.sh        — Database seeding script
   ├── test/
   │   ├── unit/             — Unit tests (mirrors src/ structure)
   │   ├── integration/      — Integration tests
   │   ├── e2e/              — End-to-end tests
   │   ├── fixtures/         — Test data files
   │   └── helpers/          — Test utilities and mocks
   ├── docs/                 — Generated documentation output
   ├── systemd/              — Service unit files
   │   ├── watchdog-auditor.service
   │   └── watchdog-agent.service
   └── docker/               — Optional Docker setup
       ├── Dockerfile
       └── docker-compose.yml

5. src/shared/types.ts — Copy from the interface definitions (Prompt 02)

6. src/shared/constants.ts — All enums and constants

7. src/shared/errors.ts — Custom error hierarchy:
   - WatchdogError (base)
   - RegistryError, ScannerError, SecurityAgentError, AuditorError
   - QuarantineError, EscalationError, PostureError
   - Each with error code and structured context

8. config/default.json — Complete default configuration with comments

9. config/schema.json — JSON Schema for configuration validation

10. scripts/setup.sh — Checks prerequisites (Node.js, SQLite, Ollama),
    creates directories, initializes database, loads default locale

11. README.md — Project overview, setup instructions, architecture
    diagram (Mermaid), development workflow, contribution guidelines
```

---

#### PROMPT 14 — Gateway Hook Integration Stub
**Deliverables:** `14-gateway-hook.ts`, `14-gateway-integration.docx`
**Estimated complexity:** Medium

```
Create the gateway hook integration code and documentation. This is the
critical integration point where the watchdog connects to OpenClaw.

DELIVERABLE 1: Integration Guide (Word)
Document exactly how the watchdog hooks into OpenClaw's gateway:

1. OPENCLAW HOOK SYSTEM
   - How gateway hooks work (event subscription model)
   - Available hook points (agent_tool_call, message_received, etc.)
   - Hook registration API
   - Hook execution order and priority
   - Synchronous vs. async hooks

2. WATCHDOG HOOK IMPLEMENTATION
   - Which events to hook
   - The interception flow (outbound and inbound)
   - How to block/modify/pass-through tool calls
   - The approval token mechanism
   - Error handling (hook throws, hook times out)

3. INSTALLATION
   - How to install the watchdog as an OpenClaw extension
   - Configuration required in OpenClaw's config
   - Verification steps (how to confirm it's working)
   - How to disable without uninstalling (kill switch)

4. PERFORMANCE IMPACT
   - Expected latency addition per tool call
   - Worst case (Security Agent invoked)
   - Memory footprint of the hook module
   - How to monitor hook performance

DELIVERABLE 2: Gateway Hook Code (TypeScript)
The actual integration module (as complete as possible without access
to OpenClaw's internals):
- Hook registration
- Outbound interception handler
- Inbound inspection handler
- Approval token generation and verification
- Pass-through for clean payloads
- Quarantine for flagged payloads
- Timeout handling
- Kill switch
- Health reporting to Auditor
```

---

### PHASE 5: EXECUTIVE DASHBOARD & PROJECT MANAGEMENT

---

#### PROMPT 15 — Executive Dashboard Specification
**Deliverables:** `15-dashboard-spec.docx`, `15-dashboard-wireframes.html`
**Estimated complexity:** High

```
Create the Executive Dashboard specification with two components:

COMPONENT 1: The RUNTIME dashboard (operational monitoring of the
deployed watchdog — this is permanent)

COMPONENT 2: The PROJECT dashboard (tracking development progress
during the build — this is temporary)

DELIVERABLE 1: Dashboard Specification (Word)

SECTION A: RUNTIME DASHBOARD

1. DASHBOARD OVERVIEW
   - Purpose: real-time and daily visibility into watchdog operations
   - Audience: system owner (Henry), not technical operators
   - Technology: lightweight web UI served by Auditor daemon
   - Update frequency: real-time for status, daily for aggregates

2. RUNTIME METRICS (define each with formula and data source)

   HEALTH PANEL:
   - Current posture level (GREEN/YELLOW/RED/BLACK with color indicator)
   - Component status (Scanner, Security Agent, Auditor: UP/DOWN/DEGRADED)
   - Time in current posture level
   - Active inventory count by classification level

   DAILY OPERATIONS PANEL:
   - Total scans today (inbound / outbound)
   - Flags raised today (by category)
   - Blocks executed today
   - Escalations today (pending / approved / denied)
   - False positive rate (rolling 7-day)

   TRENDS PANEL (charts):
   - Scan volume over time (30-day line chart)
   - Flag distribution by category (stacked bar, 30 days)
   - Posture level history (timeline, 30 days)
   - Escalation response time (average, 30 days)

   INVENTORY PANEL:
   - Current sensitive data inventory (grouped by classification)
   - Longest-held items (retention age)
   - Recently added items
   - Items recommended for purge

   RECENT ACTIVITY FEED:
   - Last 20 decisions (scan result, timestamp, action taken)
   - Expandable detail for each entry

3. RUNTIME DASHBOARD WIREFRAMES
   Describe layout (will create as HTML in Deliverable 2):
   - Single-page dashboard, responsive
   - Top bar: posture level indicator, component health dots
   - Left column: metrics cards
   - Right column: charts
   - Bottom: activity feed

SECTION B: PROJECT DASHBOARD

4. PROJECT TRACKING OVERVIEW
   - Purpose: daily visibility into development progress
   - Audience: project owner, stakeholders
   - Lifespan: active during development, archived at deployment

5. PROJECT METRICS (industry standard)

   PHASE TRACKING:
   - Current phase (Design Review / Development / QA / Security Audit /
     Deployment)
   - Phase progress (% complete based on deliverables)
   - Days elapsed vs. estimated per phase
   - Blockers count and age

   PER-MODULE TRACKING:
   - Module name
   - Assigned developer
   - Status (Not Started / In Progress / Code Complete / In Review /
     QA Passed / Done)
   - Code coverage percentage
   - Open defects (Critical / High / Medium / Low)
   - Days since last commit

   QUALITY METRICS:
   - Defect density (defects per KLOC)
   - Defect discovery rate (new defects per day)
   - Defect closure rate (resolved defects per day)
   - Technical debt items logged
   - Code review turnaround time (hours)

   SECURITY AUDIT METRICS:
   - Findings count by severity (Critical / High / Medium / Low / Info)
   - Findings resolved vs. open
   - Days to remediate by severity
   - Penetration test pass/fail status

   VELOCITY METRICS:
   - Story points completed per sprint/week
   - Burn-down chart
   - Sprint velocity trend

   RISK REGISTER:
   - Active risks count by impact level
   - Risks mitigated this period
   - New risks identified

6. DAILY REPORT FORMAT
   What the daily email/message contains:
   - One-line status summary
   - Phase progress update
   - Module status table (status emoji per module)
   - Blockers requiring attention
   - Metrics that changed significantly
   - Next milestones and ETAs

DELIVERABLE 2: Dashboard Wireframes (HTML)
Create a single-page HTML file with:
- Both dashboards as tabs (Runtime / Project)
- Static mock data showing realistic values
- Clean, professional design (use Tailwind via CDN)
- Charts using Chart.js via CDN
- Responsive layout
- This is a wireframe/prototype, not the production dashboard
```

---

#### PROMPT 16 — Project Management Artifacts
**Deliverables:** `16-project-management.docx`
**Estimated complexity:** Medium

```
Create the project management artifacts needed to execute this project
with outsourced developers.

Produce a single Word document containing:

1. WORK BREAKDOWN STRUCTURE (WBS)
   Hierarchical breakdown of all work:
   Level 1: Phases (Foundation, Intelligence, Dynamics, Operations,
            Human Loop, Integration, Deployment)
   Level 2: Modules within each phase
   Level 3: Tasks within each module (design review, development,
            unit testing, integration testing, documentation, code review)
   Level 4: Subtasks where appropriate

   Include estimated effort (person-days) for each Level 3 item.

2. RACI MATRIX
   For each major deliverable, identify:
   R = Responsible (does the work)
   A = Accountable (approves the work)
   C = Consulted (provides input)
   I = Informed (notified of progress)

   Roles:
   - Solution Architect (you/Henry)
   - Module Developer (outsourced, per module)
   - QA Engineer (outsourced)
   - Security Auditor (outsourced)
   - DevOps Engineer (if separate from developer)

3. DEPENDENCY MAP
   Which modules must complete before others can start:
   - Hard dependencies (cannot begin without)
   - Soft dependencies (can begin with stubs, needs integration later)
   - Include a Gantt-style timeline with critical path marked

4. RISK REGISTER
   At least 15 identified risks:
   - Risk ID and description
   - Probability (High/Medium/Low)
   - Impact (High/Medium/Low)
   - Risk score (P × I)
   - Mitigation strategy
   - Owner
   - Status

   Include risks like: Presidio performance inadequate, Ollama model
   accuracy below threshold, OpenClaw gateway hook API changes,
   developer turnover, scope creep, etc.

5. DEFINITION OF DONE
   Per phase:
   - Design Review: all specs reviewed and approved, interface contracts
     signed off, test data approved
   - Development: code complete, unit tests passing, coverage targets
     met, linting clean, self-documented
   - QA Testing: all integration tests passing, E2E scenarios passing,
     performance benchmarks met, no critical/high defects open
   - Security Audit: all critical/high findings remediated, penetration
     test passed, no credential exposure, prompt injection tests passed
   - Deployment: installed on target system, health checks passing,
     monitoring active, runbook documented, user trained

6. COMMUNICATION PLAN
   - Daily: async status update in project channel
   - Weekly: 30-minute sync call (developer + architect)
   - Per milestone: deliverable review meeting
   - Escalation path: when to escalate and to whom
   - Tools: GitHub for code, Issues for tracking, project channel for
     daily comms

7. OUTSOURCING GUIDELINES
   - What developers receive: Architecture Overview + their Module Spec
     + Interface Contracts + Test Data + Project Scaffolding
   - What they deliver: code + unit tests + integration test stubs +
     deployment docs
   - Code standards: TypeScript strict, ESLint config provided, Prettier
     formatting, conventional commits
   - Review process: PR with passing CI, architect review, security
     review for critical paths
   - IP and confidentiality: work-for-hire, NDA on architecture details
```

---

### PHASE 6: SECURITY & COMPLIANCE

---

#### PROMPT 17 — Security Audit Plan & Compliance Mapping
**Deliverables:** `17-security-audit.docx`
**Estimated complexity:** Medium

```
Create the Security Audit Plan and Compliance Mapping document.

Structure:

1. SECURITY AUDIT SCOPE
   - What's being audited: the Security Watchdog system
   - What's NOT being audited: OpenClaw itself, Ollama, the LLM,
     the host operating system
   - Audit type: security architecture review + code audit + pen test
   - Standards referenced: OWASP, NIST 800-53 (relevant controls),
     CIS benchmarks

2. THREAT MODEL (formalized)
   Using STRIDE methodology:
   - Spoofing: can an attacker impersonate a component?
   - Tampering: can registry/logs be modified?
   - Repudiation: can actions be denied without evidence?
   - Information Disclosure: can sensitive data leak despite watchdog?
   - Denial of Service: can watchdog be overwhelmed/crashed?
   - Elevation of Privilege: can assistant bypass watchdog?

   For each threat:
   - Attack vector
   - Likelihood
   - Impact
   - Current mitigation
   - Residual risk
   - Additional mitigation recommended

3. SECURITY CONTROLS CHECKLIST
   Map to NIST 800-53 controls where applicable:
   - Access Control (AC): who can configure watchdog, registry access
   - Audit and Accountability (AU): tamper-evident logging, log retention
   - Configuration Management (CM): hardened defaults, change tracking
   - Identification and Authentication (IA): approval tokens, channel auth
   - Incident Response (IR): isolation mode, notification
   - System and Communications Protection (SC): encryption at rest,
     localhost-only communications
   - System and Information Integrity (SI): health checks, input validation

4. PENETRATION TEST PLAN
   Test cases for a security tester:
   - Prompt injection through various vectors (messages, web content,
     documents)
   - Attempt to exfiltrate data past watchdog (encoding, side channels)
   - Attempt to disable watchdog components
   - Attempt to modify registry to weaken protections
   - Attempt SQL injection against registry database
   - Attempt to forge approval tokens
   - Attempt to cause false negatives (PII that evades detection)
   - Attempt denial of service against scanner
   - Test fail-closed behavior under various failure modes

5. COMPLIANCE MAPPING
   For US-GA locale:
   - Georgia Data Breach Notification (10-1-912): how watchdog helps
     prevent breaches that would trigger notification
   - HIPAA (if health data present): how classifications map to PHI
   - GLBA (if financial data present): how financial PII is protected
   - FTC Act Section 5: reasonable security measures demonstration

6. AUDIT DELIVERABLES
   What the security auditor produces:
   - Findings report (severity, description, reproduction steps,
     recommendation)
   - Risk rating per finding
   - Remediation verification after fixes
   - Final attestation letter

7. PRE-AUDIT SELF-ASSESSMENT CHECKLIST
   A checklist developers can run before submitting for security audit:
   - No secrets in code or configuration files
   - All SQL uses prepared statements
   - All user input validated and sanitized
   - All network communication localhost-only or encrypted
   - All file permissions restrictive (0600 for sensitive files)
   - Error messages don't leak sensitive information
   - Logging doesn't include sensitive data content
   - Dependencies audited (npm audit clean)
   - No known vulnerable dependencies
```

---

### PHASE 7: INTEGRATION & DEPLOYMENT

---

#### PROMPT 18 — Deployment Runbook & Operations Guide
**Deliverables:** `18-deployment-runbook.docx`
**Estimated complexity:** Medium

```
Create the Deployment Runbook and Operations Guide.

This document is used by whoever installs and maintains the system.
Write it as step-by-step procedures, not architectural description.

Structure:

1. PREREQUISITES
   - Hardware requirements (CPU, RAM, disk, GPU optional)
   - Software requirements (Node.js version, Python version for
     Presidio, Ollama, SQLite)
   - Network requirements (localhost-only, no external ports)
   - OpenClaw version compatibility
   - User account and permissions

2. INSTALLATION PROCEDURE
   Step-by-step:
   - Clone repository
   - Run setup script (what it does, expected output)
   - Install Node.js dependencies
   - Install Python dependencies (Presidio, detect-secrets)
   - Install and configure Ollama
   - Pull and verify model
   - Initialize database
   - Load US-GA locale
   - Configure OpenClaw gateway hook
   - Install systemd services
   - Verify installation (health check commands)

3. CONFIGURATION REFERENCE
   Every configurable parameter:
   - Parameter name
   - Description
   - Default value
   - Valid values
   - Where to set it (config file, environment variable, CLI flag)
   - Requires restart? (yes/no)

4. FIRST-RUN SETUP
   - Add initial user-defined sensitive entries
   - Configure escalation channel
   - Run test scan to verify detection
   - Verify posture calculation
   - Send test escalation and approve it
   - Review dashboard

5. OPERATIONAL PROCEDURES
   - Starting the system (order of operations)
   - Stopping the system (graceful shutdown procedure)
   - Restarting individual components
   - Checking system health (commands and expected output)
   - Reviewing audit logs
   - Responding to escalation notifications
   - Handling isolation mode (what happened, how to recover)
   - Adding new sensitive entries
   - Updating locale patterns
   - Updating the Ollama model

6. TROUBLESHOOTING GUIDE
   Common issues and resolution:
   - Scanner not detecting known PII
   - Security Agent timing out
   - Ollama not responding
   - High false positive rate
   - Escalation messages not arriving
   - Dashboard not loading
   - Database locked errors
   - Posture stuck at wrong level

7. BACKUP AND RECOVERY
   - What to back up (database, configuration, locale files)
   - Backup procedure and schedule
   - Recovery procedure
   - Database corruption recovery

8. UPGRADE PROCEDURE
   - How to upgrade the watchdog
   - Database migration handling
   - Configuration migration
   - Verification after upgrade
   - Rollback procedure

9. MONITORING AND ALERTING
   - What to monitor (process up/down, scan latency, error rate)
   - Alert thresholds
   - Integration with external monitoring (optional)
   - Log aggregation recommendations
```

---

#### PROMPT 19 — Final Integration Document & Deliverable Index
**Deliverables:** `19-integration-guide.docx`, `19-deliverable-index.md`
**Estimated complexity:** Medium

```
Create two final deliverables that tie everything together.

DELIVERABLE 1: Integration Guide (Word)
The guide for assembling all modules into a working system.

Structure:
1. INTEGRATION SEQUENCE
   Order in which modules should be integrated and tested:
   - Step 1: Registry + CLI (standalone, no dependencies)
   - Step 2: Scanner + Registry (scanner reads patterns from registry)
   - Step 3: Gateway Hook + Scanner (scanner intercepts real traffic)
   - Step 4: Security Agent + Scanner (flagged content gets classified)
   - Step 5: Posture Engine + Registry (dynamic posture from inventory)
   - Step 6: Auditor + all components (health monitoring active)
   - Step 7: Escalation Interface + Security Agent (human loop)
   - Step 8: Dashboard + Auditor (metrics visible)
   - Step 9: Full E2E validation

   For each step:
   - What you're integrating
   - Integration test to run
   - Expected result
   - What to do if it fails
   - Sign-off criteria before next step

2. INTEGRATION TEST PROCEDURES
   Detailed test procedures for each integration step:
   - Setup instructions
   - Test commands to run
   - Expected output
   - Pass/fail criteria

3. SMOKE TEST SUITE
   Quick tests to verify the full system is working:
   - Can scanner detect SSN in outbound message? (expect BLOCK)
   - Can scanner pass clean message through? (expect CLEAN, < 10ms)
   - Does Security Agent respond to classification request? (expect JSON)
   - Does Auditor detect component down? (stop agent, expect ISOLATION)
   - Does escalation reach user? (trigger ESCALATE, check channel)
   - Does dashboard show recent activity? (check activity feed)

4. KNOWN LIMITATIONS
   Document honestly what this system does and doesn't do:
   - What attacks it prevents
   - What attacks it mitigates but doesn't prevent
   - What attacks it cannot address
   - Recommended complementary measures

5. FUTURE ROADMAP
   Prioritized list of potential improvements:
   - Additional locales (UK, EU, Switzerland)
   - Semantic similarity via embeddings (beyond fuzzy match)
   - Browser extension for content inspection
   - Multi-agent coordination (watchdog per agent)
   - Compliance reporting automation
   - SIEM integration

DELIVERABLE 2: Deliverable Index (Markdown)
A complete index of all project deliverables:
- Document number and name
- File name
- Description (one line)
- Status (to be filled in during execution)
- Dependencies (which other docs it references)
- Primary audience (architect, developer, QA, security, operations)

This becomes the table of contents for the entire project package.
```

---

## PART 3: DELIVERABLE CHECKLIST

When all prompts have been executed, you should have:

### Documents (Word)
- [ ] 01 - Solution Architecture Overview
- [ ] 02 - Interface Contracts & API Specification
- [ ] 03 - Data Model & Database Schema
- [ ] 04 - Module Spec: Sensitive Data Registry
- [ ] 05 - Module Spec: Pattern Scanner
- [ ] 06 - Module Spec: Security Agent
- [ ] 07 - Module Spec: Auditor Daemon
- [ ] 08 - Module Spec: Dynamic Posture Engine
- [ ] 09 - Module Spec: Human Escalation Interface
- [ ] 10 - Module Spec: Locale Framework
- [ ] 11 - Test Data Package
- [ ] 12 - QA Plan & Test Scripts
- [ ] 15 - Executive Dashboard Specification
- [ ] 16 - Project Management Artifacts
- [ ] 17 - Security Audit Plan
- [ ] 18 - Deployment Runbook
- [ ] 19 - Integration Guide

### Code & Data Files
- [ ] 02 - interfaces.ts (shared type definitions)
- [ ] 03 - schema.sql (database schema)
- [ ] 03 - seed-us-ga.sql (US-GA locale seed data)
- [ ] 04 - registry-stub.ts
- [ ] 05 - scanner-stub.ts
- [ ] 06 - security-agent-stub.ts
- [ ] 07 - auditor-stub.ts
- [ ] 08 - posture-stub.ts
- [ ] 09 - escalation-stub.ts
- [ ] 10 - locale-us-ga.json (patterns, rules, crypto)
- [ ] 10 - locale-template.json
- [ ] 11 - test-corpus.json
- [ ] 11 - attack-scenarios.json
- [ ] 12 - test-runner.ts
- [ ] 13 - Project scaffolding (full directory structure)
- [ ] 14 - gateway-hook.ts
- [ ] 15 - dashboard-wireframes.html
- [ ] 19 - deliverable-index.md

### Total: ~17 Word documents + ~20 code/data files

---

## TIPS FOR EXECUTION

1. **Save everything as you go.** Download each deliverable before
   running the next prompt. Later prompts may reference earlier outputs.

2. **If a prompt times out**, follow up with:
   "Continue from where you left off and complete the document."

3. **If quality seems thin on a section**, follow up with:
   "Expand section [X] of the document with more detail, specifically [what you want]."

4. **If you want to adjust the architecture**, do it before running
   the module specs (Prompts 04-10). Changes after module specs are
   written require updating multiple documents.

5. **The project scaffolding (Prompt 13)** creates many files. Download
   the whole thing as a zip or run it in a development environment.

6. **Code stubs** are TypeScript with full type signatures but TODO
   implementations. Developers fill in the TODOs.

7. **Test data** is synthetic. You'll want to add your own real
   user-defined entries (family names, technology references) to the
   registry after deployment — don't put real PII in the test corpus.

8. **The project dashboard** is temporary infrastructure for the build.
   The runtime dashboard is permanent. Both are specified in Prompt 15.

---

## ESTIMATED TOTAL EFFORT

Running all 19 prompts: ~4-6 hours of prompt execution time
(including review and follow-up requests between prompts)

Resulting documentation package: sufficient to brief outsourced
developers who have no prior context on the project

The architecture is designed so each developer only needs:
- The Architecture Overview (Prompt 01) — for the big picture
- The Interface Contracts (Prompt 02) — for their module boundaries
- Their specific Module Spec (Prompts 04-10) — for their implementation
- The Test Data (Prompt 11) — for their testing
- The Project Scaffolding (Prompt 13) — for their development environment
