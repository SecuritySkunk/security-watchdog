/**
 * RegistryManager Test Suite
 * 
 * Tests the main registry facade and underlying repositories.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { existsSync, unlinkSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import Database from 'better-sqlite3';
import { RegistryManager } from '../registry/registry-manager.js';
import { RegistryError, RegistryErrorCode } from '../registry/types.js';

const TEST_DB_PATH = '/tmp/watchdog-test.db';

// Initialize test database with schema
function initTestDb(): void {
  if (existsSync(TEST_DB_PATH)) {
    unlinkSync(TEST_DB_PATH);
  }
  
  const db = new Database(TEST_DB_PATH);
  
  // Create schema matching the actual schema.sql
  db.exec(`
    -- Locales table
    CREATE TABLE locales (
      locale_id TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      description TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      priority INTEGER NOT NULL DEFAULT 100,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    -- Patterns table
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

    -- User entries table
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

    -- Entry variants table
    CREATE TABLE entry_variants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entry_id INTEGER NOT NULL REFERENCES user_entries(id) ON DELETE CASCADE,
      variant_text TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      UNIQUE(entry_id, variant_text)
    );

    -- Inventory table
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

    -- Posture input view
    CREATE VIEW v_posture_input AS
    SELECT 
      COUNT(CASE WHEN current_classification = 'NEVER_SHARE' AND is_active = 1 THEN 1 END) as never_share_count,
      COUNT(CASE WHEN current_classification = 'ASK_FIRST' AND is_active = 1 THEN 1 END) as ask_first_count,
      COUNT(CASE WHEN current_classification = 'INTERNAL_ONLY' AND is_active = 1 THEN 1 END) as internal_only_count,
      COUNT(CASE WHEN is_active = 1 THEN 1 END) as total_active
    FROM inventory;

    -- Insert test locale
    INSERT INTO locales (locale_id, display_name, description)
    VALUES ('us-ga', 'United States - Georgia', 'Test locale');
  `);
  
  db.close();
}

describe('RegistryManager', () => {
  let manager: RegistryManager;

  beforeAll(() => {
    initTestDb();
  });

  afterAll(() => {
    if (existsSync(TEST_DB_PATH)) {
      unlinkSync(TEST_DB_PATH);
    }
  });

  beforeEach(() => {
    manager = new RegistryManager(TEST_DB_PATH);
  });

  describe('Health Check', () => {
    it('should return healthy status', () => {
      const health = manager.getHealth();
      expect(health.ok).toBe(true);
      expect(typeof health.patternCount).toBe('number');
      expect(typeof health.entryCount).toBe('number');
      expect(typeof health.inventoryActiveCount).toBe('number');
    });

    it('should return database path', () => {
      expect(manager.getDatabasePath()).toBe(TEST_DB_PATH);
    });
  });

  describe('Pattern Management', () => {
    it('should create a pattern', () => {
      const pattern = manager.createPattern({
        localeId: 'us-ga',
        category: 'financial',
        patternType: 'test_ssn',
        displayName: 'Test SSN',
        regexPattern: '\\d{3}-\\d{2}-\\d{4}',
        defaultClassification: 'NEVER_SHARE',
        exampleValues: ['123-45-6789'],
      });

      expect(pattern.id).toBeGreaterThan(0);
      expect(pattern.displayName).toBe('Test SSN');
      expect(pattern.defaultClassification).toBe('NEVER_SHARE');
    });

    it('should retrieve a pattern by ID', () => {
      const created = manager.createPattern({
        localeId: 'us-ga',
        category: 'contact',
        patternType: 'test_phone',
        displayName: 'Test Phone',
        regexPattern: '\\d{3}-\\d{3}-\\d{4}',
        defaultClassification: 'ASK_FIRST',
      });

      const retrieved = manager.getPattern(created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.displayName).toBe('Test Phone');
    });

    it('should return null for non-existent pattern', () => {
      const pattern = manager.getPattern(99999);
      expect(pattern).toBeNull();
    });

    it('should update a pattern', () => {
      const created = manager.createPattern({
        localeId: 'us-ga',
        category: 'test',
        patternType: 'test_update',
        displayName: 'Original Name',
        defaultClassification: 'INTERNAL_ONLY',
      });

      const updated = manager.updatePattern(created.id, {
        displayName: 'Updated Name',
      });

      expect(updated.displayName).toBe('Updated Name');
    });

    it('should list patterns with filter', () => {
      const patterns = manager.listPatterns({ localeId: 'us-ga', isActive: true });
      expect(Array.isArray(patterns)).toBe(true);
    });

    it('should count patterns', () => {
      const count = manager.countPatterns({ isActive: true });
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should deactivate a pattern', () => {
      const created = manager.createPattern({
        localeId: 'us-ga',
        category: 'test',
        patternType: 'test_deactivate',
        displayName: 'To Deactivate',
        defaultClassification: 'PUBLIC',
      });

      manager.deactivatePattern(created.id);
      const retrieved = manager.getPattern(created.id);
      expect(retrieved!.isActive).toBe(false);
    });
  });

  describe('Entry Management', () => {
    it('should create an entry with variants', () => {
      const entry = manager.createEntry({
        label: 'my_ssn',
        displayName: 'My SSN',
        primaryValue: '123-45-6789',
        classification: 'NEVER_SHARE',
        category: 'personal',
        variants: ['123456789', '123 45 6789'],
      });

      expect(entry.id).toBeGreaterThan(0);
      expect(entry.label).toBe('my_ssn');
      expect(entry.variants.length).toBe(2);
    });

    it('should retrieve entry by ID', () => {
      const created = manager.createEntry({
        label: 'test_entry_1',
        displayName: 'Test Entry',
        primaryValue: 'secret value',
        classification: 'ASK_FIRST',
      });

      const retrieved = manager.getEntry(created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.primaryValue).toBe('secret value');
    });

    it('should retrieve entry by label', () => {
      const created = manager.createEntry({
        label: 'unique_label',
        displayName: 'Unique Entry',
        primaryValue: 'unique value',
        classification: 'INTERNAL_ONLY',
      });

      const retrieved = manager.getEntryByLabel('unique_label');
      expect(retrieved).not.toBeNull();
      expect(retrieved!.displayName).toBe('Unique Entry');
    });

    it('should add and remove variants', () => {
      const entry = manager.createEntry({
        label: 'variant_test',
        displayName: 'Variant Test',
        primaryValue: 'primary',
        classification: 'PUBLIC',
      });

      const variant = manager.addVariant(entry.id, 'new variant');
      expect(variant.variantText).toBe('new variant');

      const variants = manager.listVariants(entry.id);
      expect(variants.length).toBe(1);

      manager.removeVariant(variant.id);
      const afterRemove = manager.listVariants(entry.id);
      expect(afterRemove.length).toBe(0);
    });

    it('should throw on duplicate label', () => {
      manager.createEntry({
        label: 'duplicate_test',
        displayName: 'First',
        primaryValue: 'value1',
        classification: 'PUBLIC',
      });

      expect(() => {
        manager.createEntry({
          label: 'duplicate_test',
          displayName: 'Second',
          primaryValue: 'value2',
          classification: 'PUBLIC',
        });
      }).toThrow();
    });
  });

  describe('Inventory Management', () => {
    it('should record a detection', () => {
      const inventory = manager.recordDetection({
        registryRefType: 'pattern',
        registryRefId: 1,
        registryRefLabel: 'ssn_pattern',
        storageLocation: '/test/file.md',
        storageType: 'file',
        detectedBy: 'scanner',
        currentClassification: 'NEVER_SHARE',
      });

      expect(inventory.id).toBeGreaterThan(0);
      expect(inventory.storageLocation).toBe('/test/file.md');
    });

    it('should update existing detection on same location', () => {
      const first = manager.recordDetection({
        registryRefType: 'user_entry',
        registryRefId: 1,
        registryRefLabel: 'my_data',
        storageLocation: '/unique/path.txt',
        storageType: 'file',
        detectedBy: 'scanner',
        currentClassification: 'ASK_FIRST',
      });

      const second = manager.recordDetection({
        registryRefType: 'user_entry',
        registryRefId: 1,
        registryRefLabel: 'my_data',
        storageLocation: '/unique/path.txt',
        storageType: 'file',
        detectedBy: 'scanner',
        currentClassification: 'ASK_FIRST',
      });

      // INSERT OR REPLACE creates new row with new ID, but only one row should exist
      // for this unique (type, id, location) combination
      const all = manager.queryInventory({ storageLocation: '/unique/path.txt' });
      expect(all.length).toBe(1);
      expect(second.storageLocation).toBe(first.storageLocation);
    });

    it('should get inventory stats', () => {
      const stats = manager.getInventoryStats();
      expect(typeof stats.totalActive).toBe('number');
      expect(typeof stats.totalInactive).toBe('number');
      expect(stats.byClassification).toBeDefined();
      expect(stats.byStorageType).toBeDefined();
    });

    it('should get posture input', () => {
      const posture = manager.getPostureInput();
      expect(typeof posture.neverShareCount).toBe('number');
      expect(typeof posture.askFirstCount).toBe('number');
      expect(typeof posture.internalOnlyCount).toBe('number');
      expect(typeof posture.totalActive).toBe('number');
    });

    it('should query inventory', () => {
      const results = manager.queryInventory({ isActive: true });
      expect(Array.isArray(results)).toBe(true);
    });

    it('should deactivate inventory entry', () => {
      // Use unique values to avoid conflicts with other tests
      const uniqueId = Date.now();
      const entry = manager.recordDetection({
        registryRefType: 'pattern',
        registryRefId: uniqueId,
        registryRefLabel: `to_deactivate_${uniqueId}`,
        storageLocation: `/deactivate/test_${uniqueId}.md`,
        storageType: 'file',
        detectedBy: 'test',
        currentClassification: 'INTERNAL_ONLY',
      });

      expect(entry).not.toBeNull();
      manager.deactivateInventoryEntry(entry.id, 'test_user');
      const retrieved = manager.getInventoryEntry(entry.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.isActive).toBe(false);
      expect(retrieved!.deactivatedBy).toBe('test_user');
    });

    it('should clear inventory by location', () => {
      manager.recordDetection({
        registryRefType: 'pattern',
        registryRefId: 100,
        registryRefLabel: 'clear_test',
        storageLocation: '/clear/me.txt',
        storageType: 'file',
        detectedBy: 'test',
        currentClassification: 'PUBLIC',
      });

      const cleared = manager.clearInventoryByLocation('/clear/me.txt', 'cleaner');
      expect(cleared).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Error Handling', () => {
    it('should wrap errors as RegistryError', () => {
      expect(() => {
        manager.createPattern({
          localeId: 'nonexistent-locale',
          category: 'test',
          patternType: 'error_test',
          displayName: 'Error Test',
          defaultClassification: 'PUBLIC',
        });
      }).toThrow(RegistryError);
    });
  });
});
