/**
 * Unit tests for GatewayHook
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { GatewayHook, type GatewayHookConfig } from '../gateway/gateway-hook.js';
import { RegistryManager } from '../registry/registry-manager.js';
import { ClassificationLevel } from '../shared/types.js';
import { existsSync, unlinkSync } from 'fs';
import Database from 'better-sqlite3';

const TEST_DB = '/tmp/test-gateway-hook.db';

/** Initialize test database with required schema. */
function initTestDb(): void {
  if (existsSync(TEST_DB)) {
    unlinkSync(TEST_DB);
  }
  
  const db = new Database(TEST_DB);
  
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
      variant_type TEXT NOT NULL DEFAULT 'alias',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      UNIQUE(entry_id, variant_text)
    );

    CREATE TABLE inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      registry_ref_type TEXT NOT NULL CHECK (registry_ref_type IN ('pattern', 'user_entry')),
      registry_ref_id INTEGER NOT NULL,
      registry_ref_label TEXT NOT NULL,
      storage_location TEXT NOT NULL,
      storage_type TEXT NOT NULL,
      data_form TEXT NOT NULL DEFAULT 'verbatim',
      detected_by TEXT NOT NULL,
      current_classification TEXT NOT NULL DEFAULT 'NEVER_SHARE'
        CHECK (current_classification IN ('NEVER_SHARE', 'ASK_FIRST', 'INTERNAL_ONLY', 'PUBLIC')),
      first_detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      last_confirmed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      confirmation_count INTEGER NOT NULL DEFAULT 1,
      is_active INTEGER NOT NULL DEFAULT 1,
      deactivated_at TEXT,
      deactivated_by TEXT,
      UNIQUE(registry_ref_type, registry_ref_id, storage_location)
    );

    INSERT INTO locales (locale_id, display_name, description)
    VALUES ('us-ga', 'United States - Georgia', 'US locale with Georgia state specifics');
  `);
  
  db.close();
}

describe('GatewayHook', () => {
  let hook: GatewayHook;
  let registry: RegistryManager;

  const config: GatewayHookConfig = {
    databasePath: TEST_DB,
    hmacKey: 'test-secret-key',
    postureLevel: 'standard',
  };

  beforeAll(() => {
    initTestDb();
  });

  afterAll(() => {
    if (existsSync(TEST_DB)) {
      unlinkSync(TEST_DB);
    }
  });

  beforeEach(() => {
    // Clear tables
    const db = new Database(TEST_DB);
    db.exec('DELETE FROM entry_variants');
    db.exec('DELETE FROM user_entries');
    db.exec('DELETE FROM patterns');
    db.exec('DELETE FROM inventory');
    db.close();

    // Add test patterns
    registry = new RegistryManager(TEST_DB);
    registry.createPattern({
      localeId: 'us-ga',
      category: 'pii',
      patternType: 'ssn',
      displayName: 'Social Security Number',
      regexPattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
      regexFlags: 'g',
      defaultClassification: 'NEVER_SHARE',
      isActive: true,
    });

    registry.createPattern({
      localeId: 'us-ga',
      category: 'pii',
      patternType: 'phone',
      displayName: 'Phone Number',
      regexPattern: '\\b\\d{3}[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b',
      regexFlags: 'g',
      defaultClassification: 'ASK_FIRST',
      isActive: true,
    });

    registry.createPattern({
      localeId: 'us-ga',
      category: 'pii',
      patternType: 'email',
      displayName: 'Email Address',
      regexPattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b',
      regexFlags: 'gi',
      defaultClassification: 'INTERNAL_ONLY',
      isActive: true,
    });

    // Create hook
    hook = new GatewayHook(config);
    hook.initialize();
  });

  describe('Initialization', () => {
    it('should initialize successfully', () => {
      const health = hook.getHealth();
      expect(health.initialized).toBe(true);
      expect(health.outboundEnabled).toBe(true);
      expect(health.inboundEnabled).toBe(true);
    });

    it('should return error if not initialized', () => {
      const uninitHook = new GatewayHook(config);
      const result = uninitHook.scanOutbound({ content: 'test', destination: 'email' });
      expect(result.verdict).toBe('error');
      expect(result.action).toBe('quarantine'); // Fail-closed
    });
  });

  describe('Outbound Scanning', () => {
    it('should allow clean content', () => {
      const result = hook.scanOutbound({
        content: 'Hello, this is a normal message.',
        destination: 'email',
      });

      expect(result.action).toBe('allow');
      expect(result.verdict).toBe('clean');
      expect(result.approvalToken).toBeTruthy();
      expect(result.flags.length).toBe(0);
    });

    it('should quarantine NEVER_SHARE content', () => {
      const result = hook.scanOutbound({
        content: 'My SSN is 123-45-6789',
        destination: 'email',
      });

      expect(result.action).toBe('quarantine');
      expect(result.verdict).toBe('flagged');
      expect(result.quarantineId).toBeTruthy();
      expect(result.highestClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });

    it('should quarantine ASK_FIRST content in standard posture', () => {
      const result = hook.scanOutbound({
        content: 'Call me at 555-123-4567',
        destination: 'email',
      });

      expect(result.action).toBe('quarantine');
      expect(result.verdict).toBe('flagged');
      expect(result.highestClassification).toBe(ClassificationLevel.ASK_FIRST);
    });

    it('should allow ASK_FIRST content in permissive posture', () => {
      hook.setPosture('permissive');
      const result = hook.scanOutbound({
        content: 'Call me at 555-123-4567',
        destination: 'email',
      });

      expect(result.action).toBe('allow');
      expect(result.highestClassification).toBe(ClassificationLevel.ASK_FIRST);
    });

    it('should block in strict posture for NEVER_SHARE', () => {
      hook.setPosture('strict');
      const result = hook.scanOutbound({
        content: 'My SSN is 123-45-6789',
        destination: 'email',
      });

      expect(result.action).toBe('block');
      expect(result.verdict).toBe('flagged');
    });

    it('should block everything in lockdown posture', () => {
      hook.setPosture('lockdown');
      const result = hook.scanOutbound({
        content: 'Even email test@example.com gets blocked',
        destination: 'email',
      });

      expect(result.action).toBe('block');
    });

    it('should generate unique result IDs', () => {
      const r1 = hook.scanOutbound({ content: 'test 1', destination: 'email' });
      const r2 = hook.scanOutbound({ content: 'test 2', destination: 'email' });
      expect(r1.resultId).not.toBe(r2.resultId);
    });

    it('should track timing', () => {
      const result = hook.scanOutbound({ content: 'some text', destination: 'email' });
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
      expect(result.timestamp).toBeTruthy();
    });
  });

  describe('Inbound Inspection', () => {
    it('should detect sensitive data in inbound content', () => {
      const result = hook.inspectInbound({
        content: 'User shared SSN: 999-88-7777',
        source: 'telegram',
        senderId: 'user123',
      });

      expect(result.sensitiveDataDetected).toBe(true);
      expect(result.highestClassification).toBe(ClassificationLevel.NEVER_SHARE);
      expect(result.postureRecommendation).toBe('strict');
    });

    it('should recommend posture increase for ASK_FIRST', () => {
      const result = hook.inspectInbound({
        content: 'My number is 555-999-1234',
        source: 'telegram',
      });

      expect(result.sensitiveDataDetected).toBe(true);
      expect(result.highestClassification).toBe(ClassificationLevel.ASK_FIRST);
      expect(result.postureRecommendation).toBe('standard');
    });

    it('should not recommend posture change for clean content', () => {
      const result = hook.inspectInbound({
        content: 'Just a normal message',
        source: 'telegram',
      });

      expect(result.sensitiveDataDetected).toBe(false);
      expect(result.postureRecommendation).toBeNull();
    });
  });

  describe('Quarantine Management', () => {
    it('should create and retrieve quarantine', () => {
      const result = hook.scanOutbound({
        content: 'SSN: 111-22-3333',
        destination: 'email',
        target: 'recipient@example.com',
      });

      expect(result.quarantineId).toBeTruthy();
      
      const entry = hook.getQuarantine(result.quarantineId!);
      expect(entry).toBeTruthy();
      expect(entry!.status).toBe('pending');
      expect(entry!.destination).toBe('email');
    });

    it('should approve quarantine and return token', () => {
      const result = hook.scanOutbound({
        content: 'SSN: 222-33-4444',
        destination: 'email',
      });

      const token = hook.approveQuarantine(result.quarantineId!, 'admin');
      expect(token).toBeTruthy();

      const entry = hook.getQuarantine(result.quarantineId!);
      expect(entry!.status).toBe('approved');
      expect(entry!.resolvedBy).toBe('admin');
    });

    it('should reject quarantine', () => {
      const result = hook.scanOutbound({
        content: 'SSN: 333-44-5555',
        destination: 'email',
      });

      const success = hook.rejectQuarantine(result.quarantineId!, 'admin');
      expect(success).toBe(true);

      const entry = hook.getQuarantine(result.quarantineId!);
      expect(entry!.status).toBe('rejected');
    });

    it('should list pending quarantines', () => {
      hook.scanOutbound({ content: 'SSN: 444-55-6666', destination: 'email' });
      hook.scanOutbound({ content: 'SSN: 555-66-7777', destination: 'chat' });
      
      const pending = hook.listPendingQuarantines();
      expect(pending.length).toBe(2);
    });

    it('should not approve already resolved quarantine', () => {
      const result = hook.scanOutbound({
        content: 'SSN: 666-77-8888',
        destination: 'email',
      });

      hook.rejectQuarantine(result.quarantineId!, 'admin');
      const token = hook.approveQuarantine(result.quarantineId!, 'admin2');
      expect(token).toBeNull();
    });
  });

  describe('Posture Control', () => {
    it('should get and set posture', () => {
      expect(hook.getPosture()).toBe('standard');
      
      hook.setPosture('strict');
      expect(hook.getPosture()).toBe('strict');
      
      hook.setPosture('permissive');
      expect(hook.getPosture()).toBe('permissive');
    });
  });

  describe('Health & Metrics', () => {
    it('should track scan count', () => {
      hook.scanOutbound({ content: 'test 1', destination: 'email' });
      hook.scanOutbound({ content: 'test 2', destination: 'email' });
      hook.scanOutbound({ content: 'test 3', destination: 'email' });

      const health = hook.getHealth();
      expect(health.metrics.scansTotal).toBe(3);
    });

    it('should track quarantine count', () => {
      hook.scanOutbound({ content: 'SSN: 777-88-9999', destination: 'email' });
      hook.scanOutbound({ content: 'SSN: 888-99-0000', destination: 'email' });

      const health = hook.getHealth();
      expect(health.metrics.quarantinesTotal).toBe(2);
      expect(health.metrics.quarantinesPending).toBe(2);
    });

    it('should track uptime', () => {
      const health = hook.getHealth();
      // Uptime is calculated from startedAt, may be 0 if test runs instantly
      expect(health.metrics.uptimeMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Disabled Scanning', () => {
    it('should allow everything when outbound disabled', () => {
      const disabledHook = new GatewayHook({
        ...config,
        outboundEnabled: false,
      });
      disabledHook.initialize();

      const result = disabledHook.scanOutbound({
        content: 'SSN: 999-00-1111',
        destination: 'email',
      });

      expect(result.action).toBe('allow');
      expect(result.approvalToken).toBeTruthy();
    });

    it('should not inspect when inbound disabled', () => {
      const disabledHook = new GatewayHook({
        ...config,
        inboundEnabled: false,
      });
      disabledHook.initialize();

      const result = disabledHook.inspectInbound({
        content: 'SSN: 999-00-1111',
        source: 'telegram',
      });

      expect(result.sensitiveDataDetected).toBe(false);
    });
  });

  describe('INTERNAL_ONLY Destinations', () => {
    it('should allow INTERNAL_ONLY to file destination', () => {
      const result = hook.scanOutbound({
        content: 'Email: internal@company.com',
        destination: 'file',
      });

      expect(result.action).toBe('allow');
    });

    it('should allow INTERNAL_ONLY to clipboard', () => {
      const result = hook.scanOutbound({
        content: 'Email: internal@company.com',
        destination: 'clipboard',
      });

      expect(result.action).toBe('allow');
    });

    it('should quarantine INTERNAL_ONLY to external destination', () => {
      const result = hook.scanOutbound({
        content: 'Email: internal@company.com',
        destination: 'email',
      });

      expect(result.action).toBe('quarantine');
    });
  });

  describe('Registry Access', () => {
    it('should expose registry for direct access', () => {
      const reg = hook.getRegistry();
      expect(reg).toBeTruthy();
      
      // Can use registry directly
      const patterns = reg.listPatterns({ isActive: true });
      expect(patterns.length).toBe(3);
    });
  });
});
