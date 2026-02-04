# Security Watchdog 🐕‍🦺

**A security layer for AI assistants to prevent sensitive data leakage.**

Security Watchdog scans outbound content from AI agents to detect and protect sensitive information before it leaves your system. It provides a comprehensive pipeline for PII detection, quarantine management, and audit logging.

[![Tests](https://img.shields.io/badge/tests-121%20passing-brightgreen)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

## Features

- 🔍 **Pattern Scanning** - Regex-based detection for SSN, phone, email, credit cards, and more
- 🎯 **User Entry Matching** - Protect specific sensitive values and their variants
- 🤖 **Presidio Integration** - NLP-based PII detection via Microsoft Presidio
- 🚦 **Posture Levels** - Configurable security modes (permissive → lockdown)
- 📦 **Quarantine System** - Hold flagged content for human review
- 📋 **Audit Logging** - Complete decision trail for compliance
- 🔐 **Classification System** - NEVER_SHARE, ASK_FIRST, INTERNAL_ONLY, PUBLIC

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Gateway Hook                            │
│                  (OpenClaw Integration Layer)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│   │   Pattern   │  │  Presidio   │  │   Decision Logger   │   │
│   │   Scanner   │  │   Client    │  │    (Audit Trail)    │   │
│   └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘   │
│          │                │                     │              │
│          └────────┬───────┘                     │              │
│                   ▼                             │              │
│          ┌───────────────┐                      │              │
│          │   Registry    │◄─────────────────────┘              │
│          │   Manager     │                                     │
│          └───────────────┘                                     │
│                   │                                            │
│                   ▼                                            │
│          ┌───────────────┐                                     │
│          │   SQLite DB   │                                     │
│          │ (patterns,    │                                     │
│          │  entries,     │                                     │
│          │  inventory)   │                                     │
│          └───────────────┘                                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
npm install @openclaw/security-watchdog
```

Or clone and build from source:

```bash
git clone https://github.com/thermidor-ai/security-watchdog.git
cd security-watchdog
npm install
npm run build
```

## Quick Start

### Basic Scanning

```typescript
import { PatternScanner } from '@openclaw/security-watchdog';

// Initialize scanner
const scanner = new PatternScanner({ 
  databasePath: './security.db' 
});
scanner.initialize();

// Scan content
const result = scanner.scan('My SSN is 123-45-6789');

if (result.verdict === 'flagged') {
  console.log('Sensitive data detected!');
  console.log('Classification:', result.highestClassification);
  console.log('Flags:', result.flags);
}
```

### Gateway Integration

```typescript
import { GatewayHook } from '@openclaw/security-watchdog';

const hook = new GatewayHook({
  databasePath: './security.db',
  hmacKey: 'your-secret-key',
  postureLevel: 'standard',
});
hook.initialize();

// Scan outbound content
const result = hook.scanOutbound({
  content: 'Here is the document...',
  destination: 'email',
  target: 'recipient@example.com',
});

switch (result.action) {
  case 'allow':
    console.log('Content approved:', result.approvalToken);
    break;
  case 'quarantine':
    console.log('Content quarantined:', result.quarantineId);
    break;
  case 'block':
    console.log('Content blocked');
    break;
}
```

### Audit Logging

```typescript
import { DecisionLogger } from '@openclaw/security-watchdog';

const logger = new DecisionLogger({
  databasePath: './audit.db',
  retentionDays: 90,
});

// Log decisions (typically done automatically by GatewayHook)
logger.logOutboundScan(result, contentHash, contentLength);
logger.logQuarantineApproved(quarantineId, requestId, 'admin');

// Query audit trail
const decisions = logger.query({
  type: 'outbound_scan',
  verdict: 'flagged',
  startTime: '2026-01-01',
});

// Get statistics
const stats = logger.getStats();
console.log('Total decisions:', stats.totalDecisions);
console.log('By classification:', stats.byClassification);
```

## Classification Levels

| Level | Description | Default Action |
|-------|-------------|----------------|
| **NEVER_SHARE** | Highly sensitive (SSN, passwords, keys) | Quarantine/Block |
| **ASK_FIRST** | Moderately sensitive (phone, name) | Quarantine |
| **INTERNAL_ONLY** | Internal use (email, org name) | Allow to internal, quarantine external |
| **PUBLIC** | Safe to share | Allow |

## Posture Levels

| Posture | Behavior |
|---------|----------|
| **permissive** | Allow ASK_FIRST, quarantine NEVER_SHARE |
| **standard** | Quarantine both ASK_FIRST and NEVER_SHARE |
| **strict** | Quarantine ASK_FIRST, block NEVER_SHARE |
| **lockdown** | Block all flagged content |

## Registry Management

Define patterns and user entries:

```typescript
import { RegistryManager } from '@openclaw/security-watchdog';

const registry = new RegistryManager('./security.db');

// Add a pattern
registry.createPattern({
  localeId: 'us-ga',
  category: 'financial',
  patternType: 'credit_card',
  displayName: 'Credit Card Number',
  regexPattern: '\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b',
  defaultClassification: 'NEVER_SHARE',
  isActive: true,
});

// Add a user entry with variants
const entry = registry.createEntry({
  label: 'home_address',
  displayName: 'Home Address',
  primaryValue: '123 Main Street',
  classification: 'NEVER_SHARE',
  category: 'address',
});
registry.addVariant(entry.id, '123 Main St');
registry.addVariant(entry.id, '123 Main St.');
```

## Presidio Integration

For NLP-based PII detection:

```typescript
import { PresidioClient } from '@openclaw/security-watchdog';

const presidio = new PresidioClient({
  analyzerUrl: 'http://localhost:5002',
  minScore: 0.5,
});

const result = await presidio.analyze('John Smith lives at 123 Oak Ave');

for (const entity of result.entities) {
  console.log(`Found ${entity.entity_type} at ${entity.start}-${entity.end}`);
  console.log(`Classification: ${presidio.getEntityClassification(entity.entity_type)}`);
}
```

### Running Presidio

```bash
# Docker (recommended)
docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer

# Or via Python
pip install presidio-analyzer
python -m presidio_analyzer.app
```

## API Reference

### PatternScanner

| Method | Description |
|--------|-------------|
| `initialize()` | Load patterns and build indexes |
| `scan(text, localeIds?)` | Scan text for sensitive data |
| `scanMultiple(texts, localeIds?)` | Batch scan |
| `reload()` | Reload patterns from registry |
| `fuzzySearch(query, limit?)` | Search for similar entries |

### GatewayHook

| Method | Description |
|--------|-------------|
| `initialize()` | Initialize the hook |
| `scanOutbound(request)` | Scan outbound content |
| `inspectInbound(request)` | Inspect inbound content |
| `getQuarantine(id)` | Get quarantine entry |
| `approveQuarantine(id, approver)` | Approve quarantined content |
| `rejectQuarantine(id, rejector)` | Reject quarantined content |
| `setPosture(level)` | Change posture level |
| `getHealth()` | Get health metrics |

### DecisionLogger

| Method | Description |
|--------|-------------|
| `logOutboundScan(result, ...)` | Log outbound scan decision |
| `logQuarantineApproved(...)` | Log approval |
| `query(filters)` | Query decision log |
| `getStats(start?, end?)` | Get aggregated statistics |
| `exportToFile(path, filters?)` | Export to JSONL |
| `purgeOldEntries()` | Remove old entries |

### RegistryManager

| Method | Description |
|--------|-------------|
| `createPattern(input)` | Create PII pattern |
| `createEntry(input)` | Create user entry |
| `addVariant(entryId, text)` | Add entry variant |
| `listPatterns(filters?)` | List patterns |
| `listEntries(filters?)` | List entries |
| `recordDetection(...)` | Record inventory detection |

## Testing

```bash
# Run all tests
npm test

# Run specific test file
npm test -- src/__tests__/pattern-scanner.test.ts

# Run with coverage
npm run test:coverage

# Integration tests (requires Presidio)
PRESIDIO_URL=http://localhost:5002 npm test
```

## Project Structure

```
src/
├── registry/          # Database and pattern management
│   ├── registry-manager.ts
│   ├── pattern-repository.ts
│   ├── entry-repository.ts
│   └── inventory-repository.ts
├── scanner/           # Content scanning
│   └── pattern-scanner.ts
├── gateway/           # OpenClaw integration
│   └── gateway-hook.ts
├── audit/             # Decision logging
│   └── decision-logger.ts
├── external/          # Third-party integrations
│   └── presidio-client.ts
├── shared/            # Common types and utilities
│   └── types.ts
└── __tests__/         # Unit tests
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for your changes
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Credits

Built with ❤️ by [thermidor-ai](https://github.com/thermidor-ai)

Powered by:
- [better-sqlite3](https://github.com/WiseLibs/better-sqlite3)
- [Fuse.js](https://fusejs.io/)
- [Microsoft Presidio](https://microsoft.github.io/presidio/)
