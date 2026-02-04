# OpenClaw Security Watchdog

A security layer for OpenClaw to prevent AI data leakage.

## Overview

The Security Watchdog provides a four-layer defense system that intercepts and analyzes all outbound communications from an OpenClaw agent, preventing accidental disclosure of sensitive information.

### Architecture

- **Layer 0: Registry** - SQLite database tracking PII patterns, user-defined sensitive entries, and live data inventory
- **Layer 1: Scanner** - Deterministic pattern matching using Presidio and fuse.js
- **Layer 2: Security Agent** - Local AI (Ollama) for contextual classification
- **Layer 3: Auditor** - Health monitoring and workspace scanning daemon

## Status

🚧 **Work in Progress**

Currently implementing:
- [x] Project scaffolding
- [x] Database schema
- [x] PatternRepository
- [x] EntryRepository  
- [x] InventoryRepository
- [ ] RegistryManager (main API)
- [ ] Pattern Scanner
- [ ] Security Agent
- [ ] Auditor Daemon
- [ ] Gateway Hook

## Requirements

- Node.js 20+
- SQLite 3.x
- Ollama (for Layer 2)

## Installation

```bash
npm install
npm run db:init
```

## Development

```bash
npm run typecheck  # Type checking
npm run lint       # ESLint
npm run test       # Run tests
npm run build      # Build for production
```

## License

MIT

## Author

Built by [thermidor-ai](https://github.com/thermidor-ai) for the OpenClaw ecosystem.
