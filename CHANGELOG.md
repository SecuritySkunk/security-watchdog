# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-04

### Added

#### Registry Module
- `RegistryManager` - Unified API facade for all registry operations
- `PatternRepository` - CRUD for PII regex patterns with locale support
- `EntryRepository` - CRUD for user-defined sensitive entries and variants
- `InventoryRepository` - Track detected sensitive data locations
- SQLite database schema with 18 tables
- Support for multiple locales and classification levels

#### Scanner Module
- `PatternScanner` - Layer 1 content scanning engine
- Regex-based pattern matching for PII types
- Exact and case-insensitive user entry matching
- Variant detection for entry aliases
- Fuse.js fuzzy search index for similarity search
- Context snippet extraction around matches
- Classification prioritization (NEVER_SHARE > ASK_FIRST > INTERNAL_ONLY > PUBLIC)

#### Gateway Module
- `GatewayHook` - Integration layer for OpenClaw
- Outbound scanning with allow/quarantine/block decisions
- Inbound inspection with posture recommendations
- Quarantine management (create, approve, reject, list)
- HMAC-signed approval tokens
- Posture levels: permissive, standard, strict, lockdown
- Health metrics and monitoring

#### Audit Module
- `DecisionLogger` - Comprehensive audit trail
- Logs all security decisions with full context
- Query API with filters (type, action, verdict, time range)
- Aggregated statistics for reporting
- JSONL export for compliance
- Configurable retention with automatic purge
- Batched writes for performance
- Sensitive data sanitization (no matched text in logs)

#### External Module
- `PresidioClient` - Microsoft Presidio integration
- NLP-based PII entity detection
- Configurable entity type mappings
- Health tracking and retry logic
- Support for 18 default entity types

### Testing
- 121 unit tests across all modules
- Mock-based testing for external services
- Integration test support for Presidio

### Documentation
- Comprehensive README with examples
- API reference for all public methods
- Architecture diagram
- Installation and usage guides

## [0.2.0] - 2026-02-04

### Added

#### Dashboard Module
- Web-based dashboard UI with dark theme
- Real-time stats display (scans, blocks, quarantines)
- Quarantine queue management (approve/reject)
- Pattern browser with category filtering
- User entry viewer with variant counts
- Audit log viewer with pagination
- Test scanner for ad-hoc content testing
- Posture control from the UI
- Auto-refresh every 30 seconds

#### Production Hardening
- `/health` endpoint for load balancer health checks
- `/metrics` endpoint with Prometheus-compatible format
- Graceful shutdown handling (SIGINT, SIGTERM, SIGHUP)
- Request counting and metrics tracking
- Environment-based configuration
- Improved error handling and logging
- Server startup/shutdown logging

#### CLI Improvements
- `--help` flag with usage documentation
- Database existence validation on startup
- Default database path (`~/.openclaw/security/registry.db`)
- Environment variable documentation
- Better error messages

### Changed
- Test count updated to 166 (was 121)
- Improved documentation with dashboard and production sections

### Documentation
- Added dashboard usage instructions
- Added production deployment guide
- Added health check and metrics documentation
- Added environment variables reference
- Added PM2 and systemd deployment examples

## [Unreleased]

### Planned
- OpenClaw hook directory integration
- Real-time posture adjustment based on inbound content
- Webhook notifications for flagged content
- Additional language support beyond English
- Custom recognizer support for Presidio
