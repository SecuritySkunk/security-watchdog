# OpenClaw Source Files — Upload Guide for Security Watchdog Project

> **Instructions:** From your shallow clone at `~/openclaw` (or wherever you cloned it), upload the files below in tier order. Tier 1 is critical — the Watchdog cannot be properly designed without these. Tier 2 fills in important detail. Tier 3 is useful context.
>
> **Quick command to check what exists:** Before uploading, you can verify paths with:
> ```bash
> cd openclaw
> find src/hooks src/gateway src/plugins src/agents src/channels src/tools -maxdepth 2 -type f -name "*.ts" | head -60
> ```
> This will show you the actual file layout, since directory names may have shifted during the Clawdbot → OpenClaw rebrand.

---

## TIER 1 — Critical (Upload These First)

These files define the hook system, gateway internals, and protocol — the exact integration surface where the Security Watchdog will attach.

### 1a. Hook System (Our Primary Integration Point)

The Watchdog registers as a gateway hook. Understanding the `HookHandler` type, event types, and registration API is essential.

| File Path (expected) | Why We Need It |
|---|---|
| `src/hooks/hooks.ts` | **#1 priority.** Defines `HookHandler` type, event types (`command`, `session`, `agent`, `gateway:startup`, etc.), hook registration, and execution model. |
| `src/hooks/hook-runner.ts` (or similar) | Hook execution engine — how hooks are dispatched, priority ordering, sync vs async behavior. |
| `src/hooks/types.ts` (if separate) | Hook-related TypeScript types and interfaces. |
| `src/hooks/index.ts` | Hook module exports — shows public API surface. |

### 1b. Gateway Core

The gateway is where tool calls flow and where our interception happens.

| File Path (expected) | Why We Need It |
|---|---|
| `src/gateway/protocol/schema.ts` | **Gateway protocol schema** — defines all WS request/response types, event definitions, `PROTOCOL_VERSION`. The official docs confirm this file. |
| `src/gateway/server.ts` (or `gateway.ts`) | Main gateway server — how it starts, processes requests, dispatches tool calls. |
| `src/gateway/client.ts` | Gateway client — how internal components talk to the gateway (confirmed at line 382+). |
| `src/gateway/types.ts` (if separate) | Gateway TypeScript types. |
| `src/gateway/index.ts` | Gateway module exports. |

### 1c. Agent Tool Call Flow

Understanding how the agent issues tool calls and how those calls flow through the gateway to external services.

| File Path (expected) | Why We Need It |
|---|---|
| `src/agents/agent.ts` (or main agent file) | Agent runtime — how it assembles tool calls, receives results. |
| `src/agents/types.ts` (if separate) | Agent-related types (session, agent ID, tool call structures). |
| `src/tools/` (any `.ts` files) | Tool definitions — what a "tool call" looks like internally, how arguments are structured, how results are returned. |

### 1d. Plugin / Extension Architecture

The Watchdog will ship as an extension. We need to understand the plugin SDK.

| File Path (expected) | Why We Need It |
|---|---|
| `src/plugins/loader.ts` | **Confirmed file.** Plugin loading, registry, SDK alias resolution. |
| `src/plugin-sdk/index.ts` | Plugin SDK — the public API for extensions (confirmed in `loader.ts`). |
| `src/plugins/types.ts` (if separate) | Plugin types including `PluginRegistry`, `PluginLogger`, `GatewayRequestHandler`. |

---

## TIER 2 — Important (Upload After Tier 1)

These provide channel-level detail and configuration context needed for accurate Watchdog implementation.

### 2a. Channel Adapters (Message Format at Source)

We need to understand the message envelope format as it arrives from each channel, since the Watchdog inspects both inbound and outbound content.

| File Path (expected) | Why We Need It |
|---|---|
| `src/channels/whatsapp/` (main `.ts` files) | WhatsApp adapter — message structure, how outbound messages are sent via Baileys. |
| `src/channels/telegram/` (main `.ts` files) | Telegram adapter — message structure, bot API integration. |
| `src/channels/discord/` (main `.ts` files) | Discord adapter — message structure. |
| `src/channels/types.ts` (if shared) | Shared channel types — common message envelope, delivery context. |

> **Note:** You don't need to upload every channel — WhatsApp + Telegram + Discord covers the main patterns. If there's a shared `channels/types.ts` or `channels/base.ts`, that alone might be enough.

### 2b. Configuration System

The Watchdog config needs to integrate naturally with OpenClaw's existing config system.

| File Path (expected) | Why We Need It |
|---|---|
| `src/config/` (main `.ts` files) | Config loading, validation, hot-reload, JSON Schema generation. |
| `src/config/types.ts` (if separate) | `OpenClawConfig` type definition. |
| `src/config/schema.ts` (if separate) | Config JSON Schema definition. |

### 2c. Session and Message Types

These define the session/message structures referenced in our interfaces.

| File Path (expected) | Why We Need It |
|---|---|
| `src/sessions/` (main `.ts` files) | Session management — session IDs, session keys, transcript handling. |
| `src/messages/` (if exists) | Message processing pipeline, delivery context, outbound send flow. |

---

## TIER 3 — Useful Context (Upload If Convenient)

### 3a. Extensions Directory

Working examples of how extensions are structured.

| File Path (expected) | Why We Need It |
|---|---|
| `extensions/` (any subdirectory) | Real extension examples — package structure, manifest format, how they register with the gateway. |

### 3b. Security and Policy

| File Path (expected) | Why We Need It |
|---|---|
| `SECURITY.md` | Security policy, reporting, existing threat model. |
| `src/security/` (if exists) | Any existing security audit code, DM policy enforcement, `openclaw doctor` checks. |
| `.detect-secrets.cfg` | Existing detect-secrets configuration (we use the same tool in our Scanner). |
| `.secrets.baseline` | Secrets baseline — useful reference for our credential detection. |

### 3c. Root Configuration

| File Path (expected) | Why We Need It |
|---|---|
| `package.json` | Dependencies, scripts, workspace configuration. |
| `tsconfig.json` | TypeScript compiler configuration (we should match). |
| `AGENTS.md` | Development conventions, coding standards, build/test workflow. |

### 3d. Documentation

| File Path (expected) | Why We Need It |
|---|---|
| `docs/gateway/` (any `.md` files) | Gateway documentation — architecture, protocol, runbook. |
| `docs/hooks.md` or `docs/concepts/hooks.md` | Hooks documentation. |
| `docs/plugins.md` or similar | Plugin development guide. |

---

## Quick Upload Script

If you want to gather all the likely files into a single folder for easy upload:

```bash
cd openclaw

# Create a staging directory
mkdir -p /tmp/openclaw-for-watchdog

# Tier 1 — Critical
cp -r src/hooks/ /tmp/openclaw-for-watchdog/src-hooks/ 2>/dev/null
cp -r src/gateway/ /tmp/openclaw-for-watchdog/src-gateway/ 2>/dev/null
cp -r src/plugins/ /tmp/openclaw-for-watchdog/src-plugins/ 2>/dev/null
cp -r src/plugin-sdk/ /tmp/openclaw-for-watchdog/src-plugin-sdk/ 2>/dev/null
cp -r src/agents/ /tmp/openclaw-for-watchdog/src-agents/ 2>/dev/null
cp -r src/tools/ /tmp/openclaw-for-watchdog/src-tools/ 2>/dev/null

# Tier 2 — Important  
cp -r src/channels/ /tmp/openclaw-for-watchdog/src-channels/ 2>/dev/null
cp -r src/config/ /tmp/openclaw-for-watchdog/src-config/ 2>/dev/null
cp -r src/sessions/ /tmp/openclaw-for-watchdog/src-sessions/ 2>/dev/null
cp -r src/messages/ /tmp/openclaw-for-watchdog/src-messages/ 2>/dev/null

# Tier 3 — Context
cp package.json tsconfig.json AGENTS.md SECURITY.md /tmp/openclaw-for-watchdog/ 2>/dev/null
cp .detect-secrets.cfg .secrets.baseline /tmp/openclaw-for-watchdog/ 2>/dev/null
cp -r extensions/ /tmp/openclaw-for-watchdog/extensions/ 2>/dev/null

echo "Staged files:"
find /tmp/openclaw-for-watchdog -type f -name "*.ts" -o -name "*.json" -o -name "*.md" | wc -l
echo "files ready in /tmp/openclaw-for-watchdog/"
```

> **Heads up on upload limits:** If there are too many files, prioritize Tier 1 only. The `src/hooks/` and `src/gateway/protocol/schema.ts` files alone would let me produce the Gateway Hook Integration document (Prompt 14 from the playbook) with high confidence.

---

## What I'll Do With These Files

Once uploaded, I can:

1. **Validate our interface contracts** — Confirm our `OutboundScanRequest`, `AgentToolCallEvent`, and hook registration patterns match actual OpenClaw types.
2. **Write the Gateway Hook Integration module** (Prompt 14) — With real type imports instead of inferred stubs.
3. **Align our extension packaging** — Match the actual `openclaw.hooks` manifest format and plugin SDK patterns.
4. **Correct any assumptions** — Our current architecture docs are based on public documentation and changelog analysis. The source code will reveal any gaps.
