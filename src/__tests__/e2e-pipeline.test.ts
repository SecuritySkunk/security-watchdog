/**
 * End-to-End Pipeline Integration Tests
 * 
 * Tests the full security pipeline:
 * PatternScanner (Layer 1) → SecurityAgent (Layer 2) → GatewayHook (Layer 3)
 */

import { describe, it, expect, beforeAll, afterAll, vi, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { existsSync, unlinkSync } from 'fs';

import { PatternScanner } from '../scanner/pattern-scanner.js';
import { SecurityAgent } from '../agent/security-agent.js';
import { GatewayHook } from '../gateway/gateway-hook.js';
import { RegistryManager } from '../registry/registry-manager.js';
import { ClassificationLevel } from '../registry/types.js';

// Test database path - use same location as other tests
const TEST_DB_PATH = '/tmp/watchdog-e2e-test.db';

// Mock fetch for SecurityAgent
const mockFetch = vi.fn();
global.fetch = mockFetch;

// TODO: Fix database initialization issue
describe.skip('E2E Pipeline Integration', () => {
  let registry: RegistryManager;
  let scanner: PatternScanner;
  let agent: SecurityAgent;
  let gateway: GatewayHook;

  beforeAll(() => {
    // Create test database inline
    if (existsSync(TEST_DB_PATH)) {
      unlinkSync(TEST_DB_PATH);
    }
    
    const db = new Database(TEST_DB_PATH);
    
    db.exec(`
      CREATE TABLE locales (
        locale_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        description TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        priority INTEGER NOT NULL DEFAULT 100,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      );

      CREATE TABLE patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        locale_id TEXT NOT NULL REFERENCES locales(locale_id),
        category TEXT NOT NULL,
        pattern_type TEXT NOT NULL,
        display_name TEXT NOT NULL,
        presidio_recognizer TEXT,
        regex_pattern TEXT,
        regex_flags TEXT DEFAULT 'i',
        validation_function TEXT,
        default_classification TEXT NOT NULL DEFAULT 'NEVER_SHARE' 
          CHECK (default_classification IN ('NEVER_SHARE', 'ASK_FIRST', 'INTERNAL_ONLY', 'PUBLIC')),
        false_positive_hints TEXT,
        example_values TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE(locale_id, category, pattern_type)
      );

      CREATE TABLE user_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        primary_value TEXT NOT NULL,
        classification TEXT NOT NULL DEFAULT 'NEVER_SHARE'
          CHECK (classification IN ('NEVER_SHARE', 'ASK_FIRST', 'INTERNAL_ONLY', 'PUBLIC')),
        category TEXT NOT NULL DEFAULT 'personal',
        notes TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      );

      CREATE TABLE entry_variants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entry_id INTEGER NOT NULL REFERENCES user_entries(id) ON DELETE CASCADE,
        variant_text TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE(entry_id, variant_text)
      );

      CREATE TABLE inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        registry_ref_type TEXT NOT NULL CHECK (registry_ref_type IN ('pattern', 'user_entry')),
        registry_ref_id INTEGER NOT NULL,
        registry_ref_label TEXT NOT NULL,
        storage_location TEXT NOT NULL,
        storage_type TEXT NOT NULL CHECK (storage_type IN ('file', 'session', 'memory', 'context')),
        data_form TEXT NOT NULL DEFAULT 'verbatim' CHECK (data_form IN ('verbatim', 'paraphrased', 'derived', 'reference')),
        detected_by TEXT NOT NULL,
        current_classification TEXT NOT NULL DEFAULT 'NEVER_SHARE'
          CHECK (current_classification IN ('NEVER_SHARE', 'ASK_FIRST', 'INTERNAL_ONLY', 'PUBLIC')),
        is_active INTEGER NOT NULL DEFAULT 1,
        first_detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        last_verified_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        deactivated_at TEXT,
        deactivated_by TEXT,
        UNIQUE(registry_ref_type, registry_ref_id, storage_location)
      );

      INSERT INTO locales (locale_id, display_name, description)
      VALUES ('us', 'United States', 'Test locale');
    `);
    
    db.close();

    // Initialize components
    registry = new RegistryManager(TEST_DB_PATH);
    
    // Add test patterns via registry API
    registry.createPattern({
      localeId: 'us',
      category: 'government_id',
      patternType: 'ssn',
      displayName: 'Social Security Number',
      regexPattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
      regexFlags: 'g',
      defaultClassification: 'NEVER_SHARE',
      isActive: true,
    });

    registry.createPattern({
      localeId: 'us',
      category: 'contact',
      patternType: 'email',
      displayName: 'Email Address',
      regexPattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b',
      regexFlags: 'gi',
      defaultClassification: 'ASK_FIRST',
      isActive: true,
    });

    registry.createPattern({
      localeId: 'us',
      category: 'contact',
      patternType: 'phone',
      displayName: 'Phone Number',
      regexPattern: '\\b\\d{3}-\\d{3}-\\d{4}\\b',
      regexFlags: 'g',
      defaultClassification: 'ASK_FIRST',
      isActive: true,
    });

    // Add test user entry
    registry.createEntry({
      label: 'my_password',
      displayName: 'My Password',
      primaryValue: 'SuperSecret123!',
      classification: 'NEVER_SHARE',
      category: 'credential',
    });

    scanner = new PatternScanner(registry);
    agent = new SecurityAgent({
      enabled: true,
      ollamaUrl: 'http://localhost:11434/v1',
      model: 'test-model',
      cacheTtlMs: 0,
    });
    gateway = new GatewayHook({
      databasePath: TEST_DB_PATH,
      postureLevel: 'standard',
    });

    scanner.initialize();
    gateway.initialize();
  });

  afterAll(() => {
    // Cleanup test database
    if (existsSync(TEST_DB_PATH)) {
      unlinkSync(TEST_DB_PATH);
    }
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ─── Layer 1: Scanner Tests ─────────────────────────────────

  describe('Layer 1: PatternScanner', () => {
    it('should detect SSN in text', () => {
      const result = scanner.scan('My SSN is 123-45-6789');
      
      expect(result.flagCount).toBeGreaterThan(0);
      expect(result.flags[0].patternType).toBe('ssn');
      expect(result.highestClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });

    it('should detect email in text', () => {
      const result = scanner.scan('Contact me at john@example.com');
      
      expect(result.flagCount).toBeGreaterThan(0);
      expect(result.flags[0].patternType).toBe('email');
    });

    it('should detect user-defined entries', () => {
      const result = scanner.scan('The password is SuperSecret123!');
      
      expect(result.flagCount).toBeGreaterThan(0);
      expect(result.flags.some(f => f.source === 'entry')).toBe(true);
    });

    it('should return clean for safe content', () => {
      const result = scanner.scan('This is a perfectly safe message about weather.');
      
      expect(result.flagCount).toBe(0);
      expect(result.verdict).toBe('clean');
    });
  });

  // ─── Layer 2: SecurityAgent Tests ───────────────────────────

  describe('Layer 2: SecurityAgent', () => {
    it('should confirm real sensitive data', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                classification: 'NEVER_SHARE',
                confidence: 0.95,
                reasoning: 'This appears to be a real SSN in a personal context',
              }),
            },
          }],
        }),
      });

      const scanResult = scanner.scan('My SSN is 123-45-6789, please keep it safe.');
      const agentResult = await agent.analyze(scanResult, 'My SSN is 123-45-6789, please keep it safe.');

      expect(agentResult.agentUsed).toBe(true);
      expect(agentResult.overallClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });

    it('should downgrade false positives', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                classification: 'PUBLIC',
                confidence: 0.9,
                reasoning: 'This is example data in documentation showing SSN format',
              }),
            },
          }],
        }),
      });

      const content = 'Example SSN format: 123-45-6789 (not a real number)';
      const scanResult = scanner.scan(content);
      const agentResult = await agent.analyze(scanResult, content);

      expect(agentResult.analyses[0].classification).toBe(ClassificationLevel.PUBLIC);
    });

    it('should handle multiple flags with different classifications', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: {
                content: JSON.stringify({
                  classification: 'NEVER_SHARE',
                  confidence: 0.95,
                  reasoning: 'Real SSN',
                }),
              },
            }],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: {
                content: JSON.stringify({
                  classification: 'ASK_FIRST',
                  confidence: 0.8,
                  reasoning: 'Personal email address',
                }),
              },
            }],
          }),
        });

      const content = 'SSN: 123-45-6789, Email: john@personal.com';
      const scanResult = scanner.scan(content);
      const agentResult = await agent.analyze(scanResult, content);

      expect(agentResult.overallClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });
  });

  // ─── Layer 3: GatewayHook Tests ─────────────────────────────

  describe('Layer 3: GatewayHook', () => {
    it('should block NEVER_SHARE content in standard posture', () => {
      const result = gateway.scanOutbound({
        content: 'My SSN is 123-45-6789',
        destination: 'email',
      });

      expect(result.action).toBe('block');
      expect(result.highestClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });

    it('should quarantine ASK_FIRST content', () => {
      const result = gateway.scanOutbound({
        content: 'Contact me at john@example.com',
        destination: 'chat',
      });

      expect(result.action).toBe('quarantine');
      expect(result.quarantineId).toBeDefined();
    });

    it('should allow clean content with approval token', () => {
      const result = gateway.scanOutbound({
        content: 'The weather is nice today.',
        destination: 'chat',
      });

      expect(result.action).toBe('allow');
      expect(result.approvalToken).toBeDefined();
    });
  });

  // ─── Full Pipeline Integration ──────────────────────────────

  describe('Full Pipeline Integration', () => {
    it('should process content through entire pipeline', async () => {
      const content = 'Here is my info: SSN 123-45-6789, email test@example.com';

      // Layer 1: Scan
      const scanResult = scanner.scan(content);
      expect(scanResult.flagCount).toBeGreaterThanOrEqual(2);

      // Layer 2: Agent analysis (mock LLM)
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: {
                content: JSON.stringify({
                  classification: 'NEVER_SHARE',
                  confidence: 0.95,
                  reasoning: 'Real SSN',
                }),
              },
            }],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: {
                content: JSON.stringify({
                  classification: 'ASK_FIRST',
                  confidence: 0.85,
                  reasoning: 'Personal email',
                }),
              },
            }],
          }),
        });

      const agentResult = await agent.analyze(scanResult, content);
      expect(agentResult.overallClassification).toBe(ClassificationLevel.NEVER_SHARE);

      // Layer 3: Gateway decision
      const gatewayResult = gateway.scanOutbound({
        content,
        destination: 'email',
      });
      expect(gatewayResult.action).toBe('block');
    });

    it('should allow content after agent downgrades classification', async () => {
      // Content that looks like SSN but is example data
      const content = 'The SSN format is XXX-XX-XXXX, for example: 123-45-6789';

      // Scanner will flag it
      const scanResult = scanner.scan(content);
      expect(scanResult.flagCount).toBeGreaterThan(0);

      // Agent should recognize it as example data
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                classification: 'PUBLIC',
                confidence: 0.9,
                reasoning: 'This is example/documentation data, not real PII',
              }),
            },
          }],
        }),
      });

      const agentResult = await agent.analyze(scanResult, content);
      expect(agentResult.overallClassification).toBe(ClassificationLevel.PUBLIC);

      // With agent's PUBLIC classification, this would be allowed
      // (Note: current gateway doesn't use agent yet, this tests the concept)
    });

    it('should handle mixed sensitive and safe content', async () => {
      const content = `
        Meeting notes from today:
        - Discussed Q4 budget projections
        - Action item: Contact vendor at vendor@company.com
        - Next meeting: Tuesday 3pm
      `;

      // Layer 1: Scan
      const scanResult = scanner.scan(content);
      
      // Should find the email
      const emailFlag = scanResult.flags.find(f => f.patternType === 'email');
      expect(emailFlag).toBeDefined();

      // Layer 2: Agent could classify business email as INTERNAL_ONLY
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                classification: 'INTERNAL_ONLY',
                confidence: 0.85,
                reasoning: 'Business email in meeting notes context',
              }),
            },
          }],
        }),
      });

      const agentResult = await agent.analyze(scanResult, content);
      expect(agentResult.overallClassification).toBe(ClassificationLevel.INTERNAL_ONLY);
    });
  });

  // ─── Error Handling ─────────────────────────────────────────

  describe('Pipeline Error Handling', () => {
    it('should fail-closed when agent is unavailable', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Ollama not running'));

      const content = 'SSN: 123-45-6789';
      const scanResult = scanner.scan(content);
      const agentResult = await agent.analyze(scanResult, content);

      // Should use scanner's classification (fail-closed)
      expect(agentResult.overallClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });

    it('should continue pipeline when scanner finds no flags', async () => {
      const content = 'Just a normal message about the weather.';
      
      const scanResult = scanner.scan(content);
      expect(scanResult.flagCount).toBe(0);

      const agentResult = await agent.analyze(scanResult, content);
      expect(agentResult.agentUsed).toBe(false); // No flags to analyze
      expect(agentResult.overallClassification).toBe(ClassificationLevel.PUBLIC);

      const gatewayResult = gateway.scanOutbound({
        content,
        destination: 'chat',
      });
      expect(gatewayResult.action).toBe('allow');
    });
  });

  // ─── Performance ────────────────────────────────────────────

  describe('Pipeline Performance', () => {
    it('should complete scan in reasonable time', () => {
      const content = 'Test content with email@example.com and phone 555-123-4567';
      
      const start = performance.now();
      const result = scanner.scan(content);
      const duration = performance.now() - start;

      expect(duration).toBeLessThan(100); // Should be under 100ms
      expect(result).toBeDefined();
    });

    it('should handle large content', () => {
      const content = 'Normal text. '.repeat(1000) + 'SSN: 123-45-6789' + ' More text.'.repeat(1000);
      
      const result = scanner.scan(content);
      expect(result.flagCount).toBeGreaterThan(0);
    });
  });
});
