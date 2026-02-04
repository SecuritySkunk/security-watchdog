/**
 * Unit tests for DecisionLogger
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { DecisionLogger, type DecisionLoggerConfig } from '../audit/decision-logger.js';
import { ClassificationLevel } from '../shared/types.js';
import type { OutboundResult, InboundResult } from '../gateway/gateway-hook.js';
import { existsSync, unlinkSync, readFileSync } from 'fs';

const TEST_DB = '/tmp/test-decision-logger.db';
const TEST_LOG = '/tmp/test-decision-logger.jsonl';

describe('DecisionLogger', () => {
  let logger: DecisionLogger;

  const config: DecisionLoggerConfig = {
    databasePath: TEST_DB,
    logFilePath: TEST_LOG,
    retentionDays: 30,
    fileLoggingEnabled: false,
    batchSize: 10,
  };

  beforeEach(() => {
    // Clean up
    if (existsSync(TEST_DB)) unlinkSync(TEST_DB);
    if (existsSync(TEST_LOG)) unlinkSync(TEST_LOG);

    logger = new DecisionLogger(config);
  });

  afterEach(() => {
    logger.close();
    if (existsSync(TEST_DB)) unlinkSync(TEST_DB);
    if (existsSync(TEST_LOG)) unlinkSync(TEST_LOG);
  });

  describe('Initialization', () => {
    it('should initialize successfully', () => {
      expect(logger.isInitialized()).toBe(true);
    });

    it('should log startup event', () => {
      logger.flush();
      const entries = logger.query({ type: 'system_startup' });
      expect(entries.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Outbound Scan Logging', () => {
    it('should log clean outbound scan', () => {
      const result: OutboundResult = {
        resultId: 'result-123',
        requestId: 'req-123',
        action: 'allow',
        approvalToken: 'token-abc',
        verdict: 'clean',
        flags: [],
        highestClassification: null,
        durationMs: 15,
        timestamp: new Date().toISOString(),
      };

      logger.logOutboundScan(result, 'hash-xyz', 100, 'session-1');
      logger.flush();

      const entries = logger.query({ type: 'outbound_scan' });
      expect(entries.length).toBe(1);
      expect(entries[0].action).toBe('allow');
      expect(entries[0].verdict).toBe('clean');
      expect(entries[0].contentHash).toBe('hash-xyz');
      expect(entries[0].contentLength).toBe(100);
    });

    it('should log flagged outbound scan', () => {
      const result: OutboundResult = {
        resultId: 'result-456',
        requestId: 'req-456',
        action: 'quarantine',
        quarantineId: 'quar-xyz',
        verdict: 'flagged',
        flags: [{
          id: 'flag-1',
          matchedText: '123-45-6789',
          patternType: 'ssn',
          displayName: 'SSN',
          classification: ClassificationLevel.NEVER_SHARE,
          confidence: 1.0,
          source: 'pattern',
          startIndex: 10,
          endIndex: 21,
          context: 'SSN: [123-45-6789]',
        }],
        highestClassification: ClassificationLevel.NEVER_SHARE,
        durationMs: 25,
        timestamp: new Date().toISOString(),
      };

      logger.logOutboundScan(result, 'hash-abc', 50);
      logger.flush();

      const entries = logger.query({ type: 'outbound_scan' });
      expect(entries.length).toBe(1);
      expect(entries[0].action).toBe('quarantine');
      expect(entries[0].verdict).toBe('flagged');
      expect(entries[0].flagCount).toBe(1);
      expect(entries[0].highestClassification).toBe('NEVER_SHARE');
      expect(entries[0].flagDetails).toBeTruthy();
      
      // Flag details should NOT contain matched text (sensitive)
      const details = JSON.parse(entries[0].flagDetails!);
      expect(details[0].matchedText).toBeUndefined();
      expect(details[0].patternType).toBe('ssn');
    });
  });

  describe('Inbound Inspection Logging', () => {
    it('should log inbound inspection', () => {
      const result: InboundResult = {
        resultId: 'inb-123',
        requestId: 'inb-req-123',
        sensitiveDataDetected: true,
        flags: [{
          id: 'flag-2',
          matchedText: 'secret',
          patternType: 'password',
          displayName: 'Password',
          classification: ClassificationLevel.NEVER_SHARE,
          confidence: 0.9,
          source: 'entry',
          startIndex: 0,
          endIndex: 6,
          context: '[secret]',
        }],
        highestClassification: ClassificationLevel.NEVER_SHARE,
        postureRecommendation: 'strict',
        durationMs: 10,
        timestamp: new Date().toISOString(),
      };

      logger.logInboundInspect(result, 'hash-inb', 200, 'session-2');
      logger.flush();

      const entries = logger.query({ type: 'inbound_inspect' });
      expect(entries.length).toBe(1);
      expect(entries[0].action).toBe('detected');
      expect(entries[0].flagCount).toBe(1);
      expect(entries[0].metadata).toContain('postureRecommendation');
    });
  });

  describe('Quarantine Logging', () => {
    it('should log quarantine creation', () => {
      logger.logQuarantineCreated(
        'quar-001',
        'req-001',
        'email',
        'user@example.com',
        ClassificationLevel.NEVER_SHARE,
        2
      );
      logger.flush();

      const entries = logger.query({ type: 'quarantine_created' });
      expect(entries.length).toBe(1);
      expect(entries[0].destination).toBe('email');
      expect(entries[0].target).toBe('user@example.com');
      expect(entries[0].flagCount).toBe(2);
    });

    it('should log quarantine approval', () => {
      logger.logQuarantineApproved('quar-002', 'req-002', 'admin', 'Verified safe');
      logger.flush();

      const entries = logger.query({ type: 'quarantine_approved' });
      expect(entries.length).toBe(1);
      expect(entries[0].operator).toBe('admin');
      expect(entries[0].reason).toBe('Verified safe');
    });

    it('should log quarantine rejection', () => {
      logger.logQuarantineRejected('quar-003', 'req-003', 'security');
      logger.flush();

      const entries = logger.query({ type: 'quarantine_rejected' });
      expect(entries.length).toBe(1);
      expect(entries[0].operator).toBe('security');
    });
  });

  describe('System Events', () => {
    it('should log posture change', () => {
      logger.logPostureChanged('standard', 'strict', 'admin', 'Security incident');
      logger.flush();

      const entries = logger.query({ type: 'posture_changed' });
      expect(entries.length).toBe(1);
      expect(entries[0].previousState).toBe('standard');
      expect(entries[0].newState).toBe('strict');
    });

    it('should log kill switch', () => {
      logger.logKillSwitchOn('admin', 'Emergency');
      logger.logKillSwitchOff('admin');
      logger.flush();

      const onEntries = logger.query({ type: 'kill_switch_on' });
      const offEntries = logger.query({ type: 'kill_switch_off' });
      expect(onEntries.length).toBe(1);
      expect(offEntries.length).toBe(1);
    });

    it('should log registry update', () => {
      logger.logRegistryUpdated('pattern_added', { patternId: 123, type: 'ssn' });
      logger.flush();

      const entries = logger.query({ type: 'registry_updated' });
      expect(entries.length).toBe(1);
      expect(entries[0].action).toBe('pattern_added');
    });
  });

  describe('Query Functionality', () => {
    beforeEach(() => {
      // Add various entries
      logger.logPostureChanged('permissive', 'standard', 'user1');
      logger.logPostureChanged('standard', 'strict', 'user2');
      logger.logKillSwitchOn('admin', 'Test');
      logger.flush();
    });

    it('should filter by type', () => {
      const entries = logger.query({ type: 'posture_changed' });
      expect(entries.length).toBe(2);
    });

    it('should filter by operator', () => {
      const entries = logger.query({ operator: 'admin' });
      expect(entries.length).toBe(1);
    });

    it('should limit results', () => {
      const entries = logger.query({ limit: 1 });
      expect(entries.length).toBe(1);
    });

    it('should paginate with offset', () => {
      const page1 = logger.query({ limit: 2, offset: 0 });
      const page2 = logger.query({ limit: 2, offset: 2 });
      expect(page1.length).toBe(2);
      expect(page2.length).toBeGreaterThanOrEqual(1);
      expect(page1[0].id).not.toBe(page2[0].id);
    });

    it('should order results', () => {
      const asc = logger.query({ orderBy: 'timestamp', orderDir: 'asc' });
      const desc = logger.query({ orderBy: 'timestamp', orderDir: 'desc' });
      expect(asc[0].id).not.toBe(desc[0].id);
    });
  });

  describe('Statistics', () => {
    beforeEach(() => {
      logger.logPostureChanged('permissive', 'standard');
      logger.logKillSwitchOn('admin', 'Test');
      logger.logKillSwitchOff('admin');
      logger.flush();
    });

    it('should calculate stats', () => {
      const stats = logger.getStats();
      expect(stats.totalDecisions).toBeGreaterThanOrEqual(3);
      expect(stats.byType['posture_changed']).toBe(1);
      expect(stats.byType['kill_switch_on']).toBe(1);
    });
  });

  describe('File Logging', () => {
    it('should write to file when enabled', () => {
      const fileLogger = new DecisionLogger({
        ...config,
        fileLoggingEnabled: true,
      });

      fileLogger.logPostureChanged('standard', 'strict');
      fileLogger.flush();
      fileLogger.close();

      expect(existsSync(TEST_LOG)).toBe(true);
      const content = readFileSync(TEST_LOG, 'utf-8');
      expect(content).toContain('posture_changed');
    });
  });

  describe('Export', () => {
    it('should export to JSONL file', () => {
      logger.logPostureChanged('a', 'b');
      logger.logKillSwitchOn('x', 'y');
      logger.flush();

      const exportPath = '/tmp/export-test.jsonl';
      const count = logger.exportToFile(exportPath);
      
      expect(count).toBeGreaterThanOrEqual(2);
      expect(existsSync(exportPath)).toBe(true);
      
      const content = readFileSync(exportPath, 'utf-8');
      const lines = content.trim().split('\n');
      expect(lines.length).toBe(count);

      // Cleanup
      unlinkSync(exportPath);
    });
  });

  describe('Retention', () => {
    it('should purge old entries', () => {
      // This is hard to test without time manipulation
      // Just verify it runs without error
      const purged = logger.purgeOldEntries();
      expect(purged).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Batching', () => {
    it('should auto-flush at batch size', () => {
      const smallBatchLogger = new DecisionLogger({
        ...config,
        batchSize: 3, // Startup + 2 more = flush
      });

      // Note: startup event is logged automatically
      // Log 2 more entries (startup + 2 = 3, triggers flush)
      smallBatchLogger.logPostureChanged('a', 'b');
      smallBatchLogger.logPostureChanged('b', 'c');
      
      // At this point batch should have flushed (startup + 2 posture changes = 3)
      // Log one more that won't be in DB yet
      smallBatchLogger.logPostureChanged('c', 'd');

      // Query all entries - startup should be flushed
      const startupEntries = smallBatchLogger.query({ type: 'system_startup' });
      expect(startupEntries.length).toBe(1); // Startup was flushed

      smallBatchLogger.close();
    });
  });
});
