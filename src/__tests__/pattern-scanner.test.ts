/**
 * Unit tests for PatternScanner
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PatternScanner, type ScannerConfig } from '../scanner/pattern-scanner.js';
import { RegistryManager } from '../registry/registry-manager.js';
import { ClassificationLevel } from '../shared/types.js';
import { existsSync, unlinkSync } from 'fs';
import Database from 'better-sqlite3';

const TEST_DB = '/tmp/test-scanner.db';

/** Initialize test database with required schema. */
function initTestDb(): void {
  if (existsSync(TEST_DB)) {
    unlinkSync(TEST_DB);
  }
  
  const db = new Database(TEST_DB);
  
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

    -- Variants table
    CREATE TABLE entry_variants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entry_id INTEGER NOT NULL REFERENCES user_entries(id) ON DELETE CASCADE,
      variant_text TEXT NOT NULL,
      variant_type TEXT NOT NULL DEFAULT 'alias',
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

    -- Insert default locale
    INSERT INTO locales (locale_id, display_name, description)
    VALUES ('us-ga', 'United States - Georgia', 'US locale with Georgia state specifics');
  `);
  
  db.close();
}

describe('PatternScanner', () => {
  let scanner: PatternScanner;
  let registry: RegistryManager;

  const config: ScannerConfig = {
    databasePath: TEST_DB,
    fuseThreshold: 0.4,
    fuseDistance: 100,
    minMatchLength: 3,
    maxScanTimeMs: 5000,
    contextSize: 20,
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
    // Clear tables between tests
    const db = new Database(TEST_DB);
    db.exec('DELETE FROM entry_variants');
    db.exec('DELETE FROM user_entries');
    db.exec('DELETE FROM patterns');
    db.exec('DELETE FROM inventory');
    db.close();

    // Initialize registry with test data
    registry = new RegistryManager(TEST_DB);
    
    // Add some test patterns
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

    // Add a test user entry
    const entry = registry.createEntry({
      label: 'home_address',
      displayName: 'Home Address',
      primaryValue: '123 Main Street',
      classification: 'NEVER_SHARE',
      category: 'address',
      isActive: true,
    });

    registry.addVariant(entry.id, '123 Main St');
    registry.addVariant(entry.id, '123 Main St.');

    // Create and initialize scanner
    scanner = new PatternScanner(config);
    scanner.initialize();
  });

  describe('Initialization', () => {
    it('should initialize successfully', () => {
      expect(scanner.getLoadedPatternCount()).toBe(3);
      expect(scanner.getLoadedEntryCount()).toBe(1);
    });

    it('should error if scanning before initialize', () => {
      const uninitScanner = new PatternScanner(config);
      // Don't call initialize()
      const result = uninitScanner.scan('test');
      expect(result.verdict).toBe('error');
      expect(result.error).toContain('not initialized');
    });
  });

  describe('Pattern Matching', () => {
    it('should detect SSN pattern', () => {
      const result = scanner.scan('My SSN is 123-45-6789');
      
      expect(result.verdict).toBe('flagged');
      expect(result.flagCount).toBe(1);
      expect(result.flags[0].matchedText).toBe('123-45-6789');
      expect(result.flags[0].patternType).toBe('ssn');
      expect(result.flags[0].classification).toBe(ClassificationLevel.NEVER_SHARE);
      expect(result.flags[0].confidence).toBe(1.0);
      expect(result.flags[0].source).toBe('pattern');
    });

    it('should detect phone number pattern', () => {
      const result = scanner.scan('Call me at 555-123-4567');
      
      expect(result.verdict).toBe('flagged');
      expect(result.flagCount).toBe(1);
      expect(result.flags[0].matchedText).toBe('555-123-4567');
      expect(result.flags[0].patternType).toBe('phone');
      expect(result.flags[0].classification).toBe(ClassificationLevel.ASK_FIRST);
    });

    it('should detect email pattern (case-insensitive)', () => {
      const result = scanner.scan('Email: Test.User@Example.COM');
      
      expect(result.verdict).toBe('flagged');
      expect(result.flagCount).toBe(1);
      expect(result.flags[0].matchedText).toBe('Test.User@Example.COM');
      expect(result.flags[0].patternType).toBe('email');
    });

    it('should detect multiple patterns in same text', () => {
      const result = scanner.scan('SSN: 111-22-3333, Phone: 555-666-7777, Email: test@example.com');
      
      expect(result.verdict).toBe('flagged');
      expect(result.flagCount).toBe(3);
      
      const types = result.flags.map(f => f.patternType).sort();
      expect(types).toEqual(['email', 'phone', 'ssn']);
    });

    it('should return clean for text without matches', () => {
      const result = scanner.scan('This is just a normal sentence.');
      
      expect(result.verdict).toBe('clean');
      expect(result.flagCount).toBe(0);
      expect(result.highestClassification).toBeNull();
    });
  });

  describe('User Entry Matching', () => {
    it('should detect primary value match', () => {
      const result = scanner.scan('I live at 123 Main Street in the city');
      
      expect(result.verdict).toBe('flagged');
      // May match both "123 Main Street" and variant "123 Main St" (substring)
      expect(result.flagCount).toBeGreaterThanOrEqual(1);
      const primaryMatch = result.flags.find(f => f.matchedText === '123 Main Street');
      expect(primaryMatch).toBeTruthy();
      expect(primaryMatch!.patternType).toBe('home_address');
      expect(primaryMatch!.source).toBe('entry');
    });

    it('should detect variant match', () => {
      const result = scanner.scan('Address: 123 Main St, City');
      
      expect(result.verdict).toBe('flagged');
      expect(result.flagCount).toBe(1);
      expect(result.flags[0].matchedText).toBe('123 Main St');
      expect(result.flags[0].confidence).toBe(0.95); // Lower for variants
    });

    it('should match case-insensitively', () => {
      const result = scanner.scan('address is 123 MAIN STREET');
      
      expect(result.verdict).toBe('flagged');
      // May match both primary value and variant substring
      expect(result.flagCount).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Classification', () => {
    it('should report highest classification (NEVER_SHARE > ASK_FIRST)', () => {
      const result = scanner.scan('SSN: 111-22-3333, Phone: 555-666-7777');
      
      expect(result.highestClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });

    it('should report highest classification (ASK_FIRST > INTERNAL_ONLY)', () => {
      const result = scanner.scan('Phone: 555-666-7777, Email: test@example.com');
      
      expect(result.highestClassification).toBe(ClassificationLevel.ASK_FIRST);
    });
  });

  describe('Context Extraction', () => {
    it('should include context around match', () => {
      const result = scanner.scan('Before text 123-45-6789 after text');
      
      expect(result.flags[0].context).toContain('[123-45-6789]');
      expect(result.flags[0].context).toContain('Before text');
      expect(result.flags[0].context).toContain('after text');
    });

    it('should handle match at start of text', () => {
      const result = scanner.scan('123-45-6789 is my number');
      
      expect(result.flags[0].context).toContain('[123-45-6789]');
      expect(result.flags[0].startIndex).toBe(0);
    });

    it('should handle match at end of text', () => {
      const result = scanner.scan('My number is 123-45-6789');
      
      expect(result.flags[0].context).toContain('[123-45-6789]');
    });
  });

  describe('Multiple Scans', () => {
    it('should scan multiple texts', () => {
      const texts = [
        'SSN: 111-22-3333',
        'No sensitive data here',
        'Phone: 555-123-4567',
      ];

      const results = scanner.scanMultiple(texts);
      
      expect(results.length).toBe(3);
      expect(results[0].verdict).toBe('flagged');
      expect(results[1].verdict).toBe('clean');
      expect(results[2].verdict).toBe('flagged');
    });
  });

  describe('Reload', () => {
    it('should reload patterns and entries', () => {
      // Add a new pattern
      registry.createPattern({
        localeId: 'us-ga',
        category: 'financial',
        patternType: 'credit_card',
        displayName: 'Credit Card',
        regexPattern: '\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b',
        regexFlags: 'g',
        defaultClassification: 'NEVER_SHARE',
        isActive: true,
      });

      // Before reload - shouldn't detect
      const before = scanner.scan('Card: 4111-1111-1111-1111');
      expect(before.verdict).toBe('clean');

      // Reload
      scanner.reload();
      expect(scanner.getLoadedPatternCount()).toBe(4);

      // After reload - should detect
      const after = scanner.scan('Card: 4111-1111-1111-1111');
      expect(after.verdict).toBe('flagged');
    });
  });

  describe('Fuzzy Search', () => {
    it('should find similar entries', () => {
      const results = scanner.fuzzySearch('123 Main');
      
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].entry.label).toBe('home_address');
    });

    it('should return empty for no matches', () => {
      const results = scanner.fuzzySearch('completely unrelated');
      
      expect(results.length).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty text', () => {
      const result = scanner.scan('');
      expect(result.verdict).toBe('clean');
      expect(result.inputLength).toBe(0);
    });

    it('should have unique scan IDs', () => {
      const r1 = scanner.scan('text 1');
      const r2 = scanner.scan('text 2');
      expect(r1.scanId).not.toBe(r2.scanId);
    });

    it('should track timing', () => {
      const result = scanner.scan('Some text to scan');
      expect(result.durationMs).toBeGreaterThan(0);
      expect(result.scannedAt).toBeTruthy();
    });

    it('should deduplicate overlapping matches', () => {
      // Add entry that might match same as pattern
      registry.createEntry({
        label: 'test_ssn',
        displayName: 'Test SSN',
        primaryValue: '999-88-7777',
        classification: 'NEVER_SHARE',
        category: 'ssn',
        isActive: true,
      });
      scanner.reload();

      const result = scanner.scan('SSN: 999-88-7777');
      // Should have 2 flags (pattern + entry) as they have different patternTypes
      expect(result.flagCount).toBe(2);
    });
  });
});
