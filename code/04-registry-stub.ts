/**
 * Security Watchdog — Sensitive Data Registry (Layer 0)
 *
 * Module:       Registry
 * Document ID:  SWDOG-MOD-004
 * Version:      1.0 DRAFT
 * Generated:    February 2026
 *
 * This module provides the persistent store for PII patterns,
 * user-defined sensitive entries, classification policies,
 * destination rules, locale management, and live data inventory.
 *
 * It is the foundation layer — no runtime dependencies on other
 * watchdog components.  Every other module reads from the Registry.
 *
 * ────────────────────────────────────────────────────────────────
 * USAGE:
 *   import { RegistryManager } from '@watchdog/registry';
 *   const registry = new RegistryManager({ dbPath, locale: 'us-ga' });
 *   registry.initialize();
 * ────────────────────────────────────────────────────────────────
 */

import Database from "better-sqlite3";
import type {
  ClassificationLevel,
  PatternDefinition,
  UserDefinedEntry,
  EntryVariant,
  DestinationRule,
  InventoryEntry,
  RegistryReference,
  DataForm,
  DestinationType,
  PostureLevel,
} from "@watchdog/types";

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

/** Configuration options for the RegistryManager. */
export interface RegistryConfig {
  /** Path to the SQLite database file. Default: ~/.openclaw/security/registry.db */
  dbPath: string;

  /** Primary locale to load at startup (e.g., "us-ga"). */
  locale: string;

  /** Additional locales to activate (most restrictive wins on conflict). */
  additionalLocales?: string[];

  /** Path to the locales directory. Default: ~/.openclaw/security/locales/ */
  localesDir?: string;

  /** Database file size warning threshold in bytes. Default: 50 MB. */
  sizeWarningThresholdBytes?: number;

  /** Enable WAL mode. Default: true. */
  walMode?: boolean;

  /** Enable automatic backups. Default: true. */
  autoBackup?: boolean;

  /** Backup directory. Default: ~/.openclaw/security/backups/ */
  backupDir?: string;
}

// ═══════════════════════════════════════════════════════════════
// CUSTOM ERRORS
// ═══════════════════════════════════════════════════════════════

/** Base error class for all Registry operations. */
export class RegistryError extends Error {
  public readonly code: RegistryErrorCode;
  public readonly details?: Record<string, unknown>;

  constructor(
    code: RegistryErrorCode,
    message: string,
    details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "RegistryError";
    this.code = code;
    this.details = details;
  }
}

/** All Registry error codes, prefixed with REG_. */
export enum RegistryErrorCode {
  /** Database file cannot be opened or created. */
  CONNECTION_ERROR = "REG_CONNECTION_ERROR",
  /** SQL query failed unexpectedly. */
  QUERY_ERROR = "REG_QUERY_ERROR",
  /** UNIQUE or FK constraint violated (e.g., duplicate pattern). */
  CONSTRAINT_VIOLATION = "REG_CONSTRAINT_VIOLATION",
  /** Requested row not found. */
  NOT_FOUND = "REG_NOT_FOUND",
  /** Invalid classification level value. */
  INVALID_CLASSIFICATION = "REG_INVALID_CLASSIFICATION",
  /** Invalid locale identifier or locale directory missing. */
  INVALID_LOCALE = "REG_INVALID_LOCALE",
  /** Locale JSON file failed schema validation. */
  LOCALE_VALIDATION_ERROR = "REG_LOCALE_VALIDATION_ERROR",
  /** Database file permissions are too permissive. */
  PERMISSION_ERROR = "REG_PERMISSION_ERROR",
  /** Database integrity check failed. */
  CORRUPTION_DETECTED = "REG_CORRUPTION_DETECTED",
  /** Database file exceeds the configured size threshold. */
  SIZE_THRESHOLD_EXCEEDED = "REG_SIZE_THRESHOLD_EXCEEDED",
  /** Import file is malformed or incompatible. */
  IMPORT_ERROR = "REG_IMPORT_ERROR",
  /** Export operation failed (I/O, permissions). */
  EXPORT_ERROR = "REG_EXPORT_ERROR",
  /** Bulk operation partially failed. */
  BULK_OPERATION_ERROR = "REG_BULK_OPERATION_ERROR",
}

// ═══════════════════════════════════════════════════════════════
// DATA TRANSFER OBJECTS
// ═══════════════════════════════════════════════════════════════

/** Input for creating a new pattern definition. */
export interface CreatePatternInput {
  localeId: string;
  category: string;
  patternType: string;
  displayName: string;
  presidioRecognizer?: string;
  regexPattern?: string;
  regexFlags?: string;
  validationFunction?: string;
  defaultClassification: ClassificationLevel;
  falsePositiveHints?: string[];
  exampleValues?: string[];
}

/** Input for updating an existing pattern definition. */
export interface UpdatePatternInput {
  displayName?: string;
  presidioRecognizer?: string;
  regexPattern?: string;
  regexFlags?: string;
  validationFunction?: string;
  defaultClassification?: ClassificationLevel;
  falsePositiveHints?: string[];
  exampleValues?: string[];
  isActive?: boolean;
}

/** Input for creating a new user-defined entry. */
export interface CreateEntryInput {
  label: string;
  displayName: string;
  primaryValue: string;
  classification: ClassificationLevel;
  category?: string;
  notes?: string;
  /** Initial variants to add alongside the entry. */
  variants?: string[];
}

/** Input for updating an existing user-defined entry. */
export interface UpdateEntryInput {
  displayName?: string;
  primaryValue?: string;
  classification?: ClassificationLevel;
  category?: string;
  notes?: string;
  isActive?: boolean;
}

/** Input for creating a destination-specific rule override. */
export interface CreateDestinationRuleInput {
  entryId: number;
  destinationType: DestinationType;
  targetPattern?: string;
  overrideClassification: ClassificationLevel;
}

/** Input for adding an item to the live inventory. */
export interface CreateInventoryInput {
  registryRefType: "pattern" | "user_entry";
  registryRefId: number;
  registryRefLabel: string;
  storageLocation: string;
  storageType: "file" | "session" | "memory" | "context";
  dataForm?: DataForm;
  detectedBy: string;
  currentClassification: ClassificationLevel;
}

/** Input for updating an inventory item. */
export interface UpdateInventoryInput {
  storageLocation?: string;
  storageType?: "file" | "session" | "memory" | "context";
  dataForm?: DataForm;
  currentClassification?: ClassificationLevel;
  isActive?: boolean;
  deactivatedBy?: string;
}

/** Filters for querying inventory items. */
export interface InventoryQueryFilter {
  classification?: ClassificationLevel;
  storageType?: "file" | "session" | "memory" | "context";
  storageLocation?: string;
  isActive?: boolean;
  registryRefType?: "pattern" | "user_entry";
  limit?: number;
  offset?: number;
}

/** Filters for listing patterns. */
export interface PatternQueryFilter {
  localeId?: string;
  category?: string;
  isActive?: boolean;
  classification?: ClassificationLevel;
  limit?: number;
  offset?: number;
}

/** Filters for listing user entries. */
export interface EntryQueryFilter {
  category?: string;
  classification?: ClassificationLevel;
  isActive?: boolean;
  keyword?: string;
  limit?: number;
  offset?: number;
}

/** Inventory statistics returned by getInventoryStats(). */
export interface InventoryStats {
  totalActive: number;
  totalInactive: number;
  byClassification: Record<string, number>;
  byStorageType: Record<string, number>;
  byDataForm: Record<string, number>;
  oldestActiveItem: InventoryEntry | null;
  newestActiveItem: InventoryEntry | null;
}

/** Locale metadata. */
export interface LocaleInfo {
  localeId: string;
  displayName: string;
  description: string | null;
  isActive: boolean;
  priority: number;
  patternCount: number;
  createdAt: string;
  updatedAt: string;
}

/** Export/import envelope for locale data. */
export interface LocaleExportData {
  version: string;
  localeId: string;
  exportedAt: string;
  patterns: CreatePatternInput[];
  metadata: {
    displayName: string;
    description: string | null;
    priority: number;
  };
}

/** Search result wrapper. */
export interface SearchResult {
  type: "pattern" | "user_entry" | "variant";
  id: number;
  label: string;
  displayName: string;
  classification: ClassificationLevel;
  category: string;
  matchField: string;
  matchText: string;
  /** Relevance score (0.0–1.0). Higher is better. */
  score: number;
}

/** Database health/status information. */
export interface DatabaseStatus {
  filePath: string;
  fileSizeBytes: number;
  walSizeBytes: number;
  integrityOk: boolean;
  journalMode: string;
  patternCount: number;
  entryCount: number;
  inventoryActiveCount: number;
  localeCount: number;
  schemaVersion: number;
  createdAt: string;
}

// ═══════════════════════════════════════════════════════════════
// INTERNAL REPOSITORIES
// ═══════════════════════════════════════════════════════════════

/**
 * PatternRepository — CRUD and query operations for PII pattern
 * definitions in the registry. Each pattern belongs to a locale
 * and maps to a Presidio recognizer, a regex, or both.
 *
 * @internal Used only within RegistryManager; not exported directly.
 */
class PatternRepository {
  private db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /**
   * Create a new pattern definition.
   *
   * @param input - Pattern creation parameters.
   * @returns The newly created PatternDefinition with assigned ID.
   * @throws {RegistryError} REG_CONSTRAINT_VIOLATION if locale_id + category + pattern_type already exists.
   * @throws {RegistryError} REG_INVALID_LOCALE if the referenced locale does not exist.
   */
  create(input: CreatePatternInput): PatternDefinition {
    // TODO: Validate locale exists
    // TODO: INSERT with prepared statement
    // TODO: Return the new row with generated ID
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Retrieve a single pattern by ID.
   *
   * @param id - The pattern's auto-incremented ID.
   * @returns The PatternDefinition, or null if not found.
   */
  getById(id: number): PatternDefinition | null {
    // TODO: SELECT by id
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Update fields on an existing pattern.
   *
   * @param id - The pattern ID to update.
   * @param input - Fields to update (only provided fields are changed).
   * @returns The updated PatternDefinition.
   * @throws {RegistryError} REG_NOT_FOUND if the pattern does not exist.
   */
  update(id: number, input: UpdatePatternInput): PatternDefinition {
    // TODO: Build dynamic UPDATE from provided fields
    // TODO: Use prepared statement with bound params
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Soft-delete a pattern by setting is_active = 0.
   * Patterns are never physically deleted (audit trail).
   *
   * @param id - The pattern ID to deactivate.
   * @throws {RegistryError} REG_NOT_FOUND if the pattern does not exist.
   */
  deactivate(id: number): void {
    // TODO: UPDATE is_active = 0
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Permanently delete a pattern. Use with extreme caution —
   * only for removing invalid or test data.
   *
   * @param id - The pattern ID to delete.
   * @throws {RegistryError} REG_NOT_FOUND if the pattern does not exist.
   */
  hardDelete(id: number): void {
    // TODO: DELETE by id
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * List patterns with optional filters. Default: all active patterns.
   *
   * @param filter - Optional query filters (locale, category, classification, etc.).
   * @returns Array of matching PatternDefinition records.
   */
  list(filter?: PatternQueryFilter): PatternDefinition[] {
    // TODO: Build SELECT with optional WHERE clauses
    // TODO: Support pagination via limit/offset
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Load all active patterns for the specified locales into memory.
   * Optimized for the Scanner's startup preload — returns all
   * patterns in a single query ordered by locale priority.
   *
   * @param localeIds - Locale IDs to load (e.g., ["us-ga"]).
   * @returns Array of active PatternDefinition records.
   */
  preloadForScanner(localeIds: string[]): PatternDefinition[] {
    // TODO: SELECT * FROM patterns
    //       WHERE locale_id IN (?) AND is_active = 1
    //       ORDER BY locale priority
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Count patterns matching the given filter.
   *
   * @param filter - Optional query filters.
   * @returns The count of matching patterns.
   */
  count(filter?: PatternQueryFilter): number {
    // TODO: SELECT COUNT(*)
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Bulk insert patterns from a locale import.
   * Runs in a transaction — all succeed or all fail.
   *
   * @param patterns - Array of pattern creation inputs.
   * @returns Number of patterns inserted.
   * @throws {RegistryError} REG_BULK_OPERATION_ERROR on partial failure.
   */
  bulkInsert(patterns: CreatePatternInput[]): number {
    // TODO: Begin transaction
    // TODO: Insert each pattern via prepared statement
    // TODO: Commit or rollback
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Delete all patterns for a specific locale.
   * Used when re-importing a locale's pattern set.
   *
   * @param localeId - The locale whose patterns should be removed.
   * @returns Number of patterns deleted.
   */
  deleteByLocale(localeId: string): number {
    // TODO: DELETE FROM patterns WHERE locale_id = ?
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }
}

/**
 * EntryRepository — CRUD and query operations for user-defined
 * sensitive data entries. Manages variants and destination rules
 * as child records.
 *
 * @internal Used only within RegistryManager; not exported directly.
 */
class EntryRepository {
  private db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /**
   * Create a new user-defined entry with optional initial variants.
   * Runs in a transaction so entry + variants are atomic.
   *
   * @param input - Entry creation parameters (includes optional variants).
   * @returns The newly created UserDefinedEntry with assigned ID.
   * @throws {RegistryError} REG_CONSTRAINT_VIOLATION if label already exists.
   */
  create(input: CreateEntryInput): UserDefinedEntry {
    // TODO: Begin transaction
    // TODO: INSERT into user_entries
    // TODO: INSERT variants (if provided)
    // TODO: Commit
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Retrieve a single entry by ID, including its variants.
   *
   * @param id - The entry's auto-incremented ID.
   * @returns The UserDefinedEntry, or null if not found.
   */
  getById(id: number): (UserDefinedEntry & { variants: EntryVariant[] }) | null {
    // TODO: SELECT entry + JOIN variants
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Retrieve a single entry by its label.
   *
   * @param label - The unique label (e.g., "family_count").
   * @returns The UserDefinedEntry, or null if not found.
   */
  getByLabel(label: string): (UserDefinedEntry & { variants: EntryVariant[] }) | null {
    // TODO: SELECT by label
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Update fields on an existing entry.
   *
   * @param id - The entry ID to update.
   * @param input - Fields to update.
   * @returns The updated UserDefinedEntry.
   * @throws {RegistryError} REG_NOT_FOUND if the entry does not exist.
   */
  update(id: number, input: UpdateEntryInput): UserDefinedEntry {
    // TODO: Build dynamic UPDATE from provided fields
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Soft-delete an entry by setting is_active = 0.
   *
   * @param id - The entry ID to deactivate.
   * @throws {RegistryError} REG_NOT_FOUND if the entry does not exist.
   */
  deactivate(id: number): void {
    // TODO: UPDATE is_active = 0
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Permanently delete an entry and its variants/rules (CASCADE).
   *
   * @param id - The entry ID to delete.
   * @throws {RegistryError} REG_NOT_FOUND if the entry does not exist.
   */
  hardDelete(id: number): void {
    // TODO: DELETE by id (CASCADE handles variants + rules)
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * List entries with optional filters.
   *
   * @param filter - Optional query filters.
   * @returns Array of matching UserDefinedEntry records.
   */
  list(filter?: EntryQueryFilter): UserDefinedEntry[] {
    // TODO: Build SELECT with optional WHERE clauses
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Load all active entries with their variants for Scanner preload.
   * Returns entries with concatenated variant texts for fuse.js indexing.
   *
   * @returns Array of entries with variants (uses v_entries_with_variants view).
   */
  preloadForScanner(): Array<UserDefinedEntry & { variants: string[] }> {
    // TODO: SELECT * FROM v_entries_with_variants
    // TODO: Split variant string on '|||' separator
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Count entries matching the given filter.
   *
   * @param filter - Optional query filters.
   * @returns The count of matching entries.
   */
  count(filter?: EntryQueryFilter): number {
    // TODO: SELECT COUNT(*)
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── VARIANT MANAGEMENT ──────────────────────────────────────

  /**
   * Add a variant phrasing to an existing entry.
   *
   * @param entryId - The parent entry ID.
   * @param variantText - The alternative phrasing.
   * @returns The newly created EntryVariant.
   * @throws {RegistryError} REG_CONSTRAINT_VIOLATION if variant already exists for this entry.
   */
  addVariant(entryId: number, variantText: string): EntryVariant {
    // TODO: INSERT into entry_variants
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Remove a variant by its ID.
   *
   * @param variantId - The variant's auto-incremented ID.
   * @throws {RegistryError} REG_NOT_FOUND if the variant does not exist.
   */
  removeVariant(variantId: number): void {
    // TODO: DELETE by id
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * List all variants for a given entry.
   *
   * @param entryId - The parent entry ID.
   * @returns Array of EntryVariant records.
   */
  listVariants(entryId: number): EntryVariant[] {
    // TODO: SELECT by entry_id
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Bulk-add variants to an entry. Skips duplicates silently.
   *
   * @param entryId - The parent entry ID.
   * @param variants - Array of variant texts.
   * @returns Number of variants inserted (excluding skipped duplicates).
   */
  bulkAddVariants(entryId: number, variants: string[]): number {
    // TODO: INSERT OR IGNORE in transaction
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── DESTINATION RULE MANAGEMENT ─────────────────────────────

  /**
   * Add a destination-specific classification override for an entry.
   *
   * @param input - Rule creation parameters.
   * @returns The newly created DestinationRule.
   * @throws {RegistryError} REG_CONSTRAINT_VIOLATION if rule already exists for this entry + destination + target.
   */
  addDestinationRule(input: CreateDestinationRuleInput): DestinationRule {
    // TODO: INSERT into destination_rules
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Remove a destination rule by its ID.
   *
   * @param ruleId - The rule's auto-incremented ID.
   * @throws {RegistryError} REG_NOT_FOUND if the rule does not exist.
   */
  removeDestinationRule(ruleId: number): void {
    // TODO: DELETE by id
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * List all destination rules for a given entry.
   *
   * @param entryId - The parent entry ID.
   * @returns Array of DestinationRule records.
   */
  listDestinationRules(entryId: number): DestinationRule[] {
    // TODO: SELECT by entry_id
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Load all active destination rules for Scanner preload.
   * Returns rules joined with their parent entry for efficient lookup.
   *
   * @returns Array of DestinationRule records for active entries.
   */
  preloadDestinationRules(): DestinationRule[] {
    // TODO: SELECT dr.* FROM destination_rules dr
    //       JOIN user_entries ue ON ue.id = dr.entry_id
    //       WHERE ue.is_active = 1
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Resolve the effective classification for an entry given a specific
   * destination. Checks destination rules first; falls back to the
   * entry's default classification.
   *
   * @param entryId - The user entry ID.
   * @param destinationType - The destination type enum value.
   * @param destinationTarget - The specific target URL/name (for target_pattern matching).
   * @returns The effective ClassificationLevel.
   */
  resolveClassification(
    entryId: number,
    destinationType: DestinationType,
    destinationTarget: string
  ): ClassificationLevel {
    // TODO: Check destination_rules for matching rule
    // TODO: If no rule matches, return entry's default classification
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }
}

/**
 * InventoryRepository — Tracks sensitive data currently present
 * in the agent's accessible storage (files, sessions, memory).
 *
 * Updated by:
 *   - Inbound inspection (IF-002): new sensitive data entering system
 *   - Workspace scanner (Auditor): periodic verification
 *   - Manual operations via CLI
 *
 * Consumed by:
 *   - Posture Engine: determines security posture from inventory
 *   - Dashboard: displays current inventory state
 *   - Scanner: adjusts scrutiny based on inventory
 *
 * @internal Used only within RegistryManager; not exported directly.
 */
class InventoryRepository {
  private db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /**
   * Add a new item to the live inventory.
   * If an item already exists at the same location with the same
   * registry reference, updates the existing entry instead.
   *
   * @param input - Inventory item creation parameters.
   * @returns The created or updated InventoryEntry.
   */
  addOrUpdate(input: CreateInventoryInput): InventoryEntry {
    // TODO: INSERT OR REPLACE keyed on
    //       (registry_ref_type, registry_ref_id, storage_location, storage_type)
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Retrieve a single inventory item by ID.
   *
   * @param id - The item's auto-incremented ID.
   * @returns The InventoryEntry, or null if not found.
   */
  getById(id: number): InventoryEntry | null {
    // TODO: SELECT by id
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Update an inventory item's fields.
   *
   * @param id - The item ID to update.
   * @param input - Fields to update.
   * @returns The updated InventoryEntry.
   * @throws {RegistryError} REG_NOT_FOUND if the item does not exist.
   */
  update(id: number, input: UpdateInventoryInput): InventoryEntry {
    // TODO: Build dynamic UPDATE
    // TODO: If isActive is set to false, set deactivated_at and deactivated_by
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Mark an inventory item as inactive (data no longer present at location).
   *
   * @param id - The item ID.
   * @param deactivatedBy - The process or scan ID that detected removal.
   */
  deactivate(id: number, deactivatedBy: string): void {
    // TODO: UPDATE is_active = 0, deactivated_at = NOW(), deactivated_by = ?
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Mark the item as still present at its location (verification scan).
   *
   * @param id - The item ID.
   */
  verify(id: number): void {
    // TODO: UPDATE last_verified_at = NOW()
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Query inventory items with filters.
   *
   * @param filter - Optional query filters.
   * @returns Array of matching InventoryEntry records.
   */
  query(filter?: InventoryQueryFilter): InventoryEntry[] {
    // TODO: Build SELECT with optional WHERE clauses
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Get aggregated inventory statistics for dashboard and posture engine.
   *
   * @returns InventoryStats with counts by classification, storage type, etc.
   */
  getStats(): InventoryStats {
    // TODO: Use v_inventory_summary and v_posture_input views
    // TODO: Query oldest and newest active items
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Get posture input data (counts of active items by classification).
   * Used by the Posture Engine for posture calculation.
   *
   * @returns Object with never_share_count, ask_first_count, internal_only_count, total_active.
   */
  getPostureInput(): {
    neverShareCount: number;
    askFirstCount: number;
    internalOnlyCount: number;
    totalActive: number;
  } {
    // TODO: SELECT * FROM v_posture_input
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Bulk deactivate inventory items at a specific storage location.
   * Used when a file is deleted or session is purged.
   *
   * @param storageLocation - The storage path.
   * @param deactivatedBy - The process or scan ID.
   * @returns Number of items deactivated.
   */
  deactivateByLocation(storageLocation: string, deactivatedBy: string): number {
    // TODO: UPDATE WHERE storage_location = ? AND is_active = 1
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Purge inactive inventory items older than the specified days.
   * Called by the Auditor daemon during daily maintenance.
   *
   * @param olderThanDays - Inactive items older than this are deleted.
   * @returns Number of items purged.
   */
  purgeInactive(olderThanDays: number): number {
    // TODO: DELETE WHERE is_active = 0 AND deactivated_at < cutoff
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Find inventory items that may be stale (last verified before cutoff).
   *
   * @param olderThanHours - Items not verified within this window.
   * @returns Array of potentially stale InventoryEntry records.
   */
  findStale(olderThanHours: number): InventoryEntry[] {
    // TODO: SELECT WHERE is_active = 1 AND last_verified_at < cutoff
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// PUBLIC API: REGISTRY MANAGER
// ═══════════════════════════════════════════════════════════════

/**
 * RegistryManager — The public API for all registry operations.
 *
 * This is the main entry point for interacting with the Sensitive
 * Data Registry.  It initializes the database, manages connection
 * lifecycle, and exposes the three internal repositories (patterns,
 * entries, inventory) plus locale management and search.
 *
 * @example
 * ```typescript
 * const registry = new RegistryManager({
 *   dbPath: '~/.openclaw/security/registry.db',
 *   locale: 'us-ga',
 * });
 *
 * registry.initialize();
 *
 * // Add a user-defined entry
 * const entry = registry.entries.create({
 *   label: 'family_count',
 *   displayName: 'Number of Children',
 *   primaryValue: '6 children',
 *   classification: 'ASK_FIRST',
 *   category: 'family',
 *   variants: ['six children', '6 kids', 'six kids'],
 * });
 *
 * // Add destination rule: NEVER_SHARE on public platforms
 * registry.entries.addDestinationRule({
 *   entryId: entry.id,
 *   destinationType: 'PUBLIC_PLATFORM',
 *   overrideClassification: 'NEVER_SHARE',
 * });
 *
 * // Search across all entries
 * const results = registry.search('family');
 *
 * registry.close();
 * ```
 */
export class RegistryManager {
  private db: Database.Database | null = null;
  private config: RegistryConfig;
  private _patterns: PatternRepository | null = null;
  private _entries: EntryRepository | null = null;
  private _inventory: InventoryRepository | null = null;

  /**
   * Construct a RegistryManager.
   * Call initialize() before using any repository methods.
   *
   * @param config - Configuration for database path, locale, etc.
   */
  constructor(config: RegistryConfig) {
    this.config = config;
  }

  /**
   * Access the PatternRepository for CRUD operations on pattern definitions.
   * @throws {RegistryError} if initialize() has not been called.
   */
  get patterns(): PatternRepository {
    if (!this._patterns) {
      throw new RegistryError(
        RegistryErrorCode.CONNECTION_ERROR,
        "Registry not initialized. Call initialize() first."
      );
    }
    return this._patterns;
  }

  /**
   * Access the EntryRepository for CRUD operations on user-defined entries.
   * @throws {RegistryError} if initialize() has not been called.
   */
  get entries(): EntryRepository {
    if (!this._entries) {
      throw new RegistryError(
        RegistryErrorCode.CONNECTION_ERROR,
        "Registry not initialized. Call initialize() first."
      );
    }
    return this._entries;
  }

  /**
   * Access the InventoryRepository for live inventory tracking.
   * @throws {RegistryError} if initialize() has not been called.
   */
  get inventory(): InventoryRepository {
    if (!this._inventory) {
      throw new RegistryError(
        RegistryErrorCode.CONNECTION_ERROR,
        "Registry not initialized. Call initialize() first."
      );
    }
    return this._inventory;
  }

  // ─── LIFECYCLE ───────────────────────────────────────────────

  /**
   * Initialize the registry: open (or create) the database, set
   * pragmas, verify permissions, run migrations, and instantiate
   * the internal repositories.
   *
   * This method is idempotent — calling it multiple times is safe.
   *
   * @throws {RegistryError} REG_CONNECTION_ERROR if the database cannot be opened.
   * @throws {RegistryError} REG_PERMISSION_ERROR if file permissions are too permissive.
   * @throws {RegistryError} REG_CORRUPTION_DETECTED if integrity check fails.
   */
  initialize(): void {
    // TODO: Check/create database directory
    // TODO: Open better-sqlite3 connection
    // TODO: Verify file permissions (must be 0600)
    // TODO: Set pragmas (WAL, foreign_keys, busy_timeout, etc.)
    // TODO: Run migrations if needed
    // TODO: Verify database integrity (PRAGMA integrity_check)
    // TODO: Instantiate PatternRepository, EntryRepository, InventoryRepository
    // TODO: Load configured locale(s)
    throw new RegistryError(
      RegistryErrorCode.CONNECTION_ERROR,
      "Not implemented"
    );
  }

  /**
   * Close the database connection and release resources.
   * After close(), the RegistryManager must be re-initialized
   * before further use.
   */
  close(): void {
    // TODO: Close better-sqlite3 connection
    // TODO: Set repositories to null
    if (this.db) {
      this.db.close();
      this.db = null;
    }
    this._patterns = null;
    this._entries = null;
    this._inventory = null;
  }

  /**
   * Check whether the registry has been initialized and the
   * database connection is open.
   */
  get isInitialized(): boolean {
    return this.db !== null && this.db.open;
  }

  // ─── LOCALE MANAGEMENT ───────────────────────────────────────

  /**
   * Load a locale from its directory on disk. Reads patterns.json,
   * validates the JSON against the locale schema, and inserts/updates
   * the locale and its patterns in the database.
   *
   * If the locale already exists, its patterns are replaced (all
   * existing patterns for the locale are deleted and re-inserted).
   *
   * @param localeId - The locale identifier (must match a directory name under localesDir).
   * @throws {RegistryError} REG_INVALID_LOCALE if the directory does not exist.
   * @throws {RegistryError} REG_LOCALE_VALIDATION_ERROR if JSON files fail schema validation.
   */
  loadLocale(localeId: string): void {
    // TODO: Read patterns.json from localesDir/localeId/
    // TODO: Validate JSON against locale schema
    // TODO: Begin transaction
    // TODO: INSERT or UPDATE locale row
    // TODO: DELETE existing patterns for locale
    // TODO: INSERT new patterns from JSON
    // TODO: Commit
    throw new RegistryError(
      RegistryErrorCode.INVALID_LOCALE,
      "Not implemented"
    );
  }

  /**
   * Activate a locale (set is_active = 1). Patterns from active
   * locales are included in Scanner preloads.
   *
   * @param localeId - The locale to activate.
   * @throws {RegistryError} REG_NOT_FOUND if the locale does not exist in the database.
   */
  activateLocale(localeId: string): void {
    // TODO: UPDATE locales SET is_active = 1 WHERE locale_id = ?
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Deactivate a locale. Its patterns remain in the database but
   * are excluded from Scanner preloads.
   *
   * @param localeId - The locale to deactivate.
   * @throws {RegistryError} REG_NOT_FOUND if the locale does not exist.
   */
  deactivateLocale(localeId: string): void {
    // TODO: UPDATE locales SET is_active = 0 WHERE locale_id = ?
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * List all registered locales with their pattern counts.
   *
   * @returns Array of LocaleInfo records.
   */
  listLocales(): LocaleInfo[] {
    // TODO: SELECT locales with COUNT(patterns)
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Validate a locale's JSON files against the expected schema
   * without loading them into the database.
   *
   * @param localeId - The locale to validate.
   * @returns Object with isValid flag and array of validation errors.
   */
  validateLocale(localeId: string): { isValid: boolean; errors: string[] } {
    // TODO: Read patterns.json, rules.json, crypto.json
    // TODO: Validate each against its JSON schema
    // TODO: Return validation results
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── SEARCH ──────────────────────────────────────────────────

  /**
   * Search across patterns, user entries, and variants for a keyword.
   * Matches against display_name, label, primary_value, variant_text,
   * and pattern_type fields. Uses SQLite LIKE for basic matching.
   *
   * @param query - The search keyword (partial match supported).
   * @param options - Optional: filter by classification, limit results.
   * @returns Array of SearchResult records sorted by relevance score.
   */
  search(
    query: string,
    options?: {
      classification?: ClassificationLevel;
      limit?: number;
    }
  ): SearchResult[] {
    // TODO: UNION across patterns, user_entries, entry_variants
    // TODO: Filter by classification if provided
    // TODO: Score results by match quality (exact > starts_with > contains)
    // TODO: Order by score descending
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── EXPORT / IMPORT ─────────────────────────────────────────

  /**
   * Export a locale's patterns as a JSON file suitable for sharing
   * or backup. Includes locale metadata and all active patterns.
   *
   * @param localeId - The locale to export.
   * @param outputPath - File path to write the JSON export.
   * @throws {RegistryError} REG_NOT_FOUND if the locale does not exist.
   * @throws {RegistryError} REG_EXPORT_ERROR on I/O failure.
   */
  exportLocale(localeId: string, outputPath: string): void {
    // TODO: SELECT locale metadata
    // TODO: SELECT all active patterns for locale
    // TODO: Build LocaleExportData envelope
    // TODO: Write JSON to outputPath
    throw new RegistryError(
      RegistryErrorCode.EXPORT_ERROR,
      "Not implemented"
    );
  }

  /**
   * Import a locale from a JSON export file. Creates or replaces
   * the locale and its patterns.
   *
   * @param inputPath - Path to the JSON export file.
   * @param overrideLocaleId - Optionally override the locale ID from the file.
   * @throws {RegistryError} REG_IMPORT_ERROR if the file is malformed.
   */
  importLocale(inputPath: string, overrideLocaleId?: string): void {
    // TODO: Read and parse JSON file
    // TODO: Validate against LocaleExportData schema
    // TODO: loadLocale() with the parsed data
    throw new RegistryError(
      RegistryErrorCode.IMPORT_ERROR,
      "Not implemented"
    );
  }

  // ─── DATABASE HEALTH ─────────────────────────────────────────

  /**
   * Get database status including file size, integrity, and
   * counts of key entities. Used by the Auditor and Dashboard.
   *
   * @returns DatabaseStatus with file size, integrity check, and entity counts.
   */
  getDatabaseStatus(): DatabaseStatus {
    // TODO: stat() the database file
    // TODO: PRAGMA integrity_check
    // TODO: Count patterns, entries, inventory, locales
    // TODO: Read schema_version from config_meta
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Check the database file size against the configured warning
   * threshold. Returns true if the size exceeds the threshold.
   *
   * @returns true if database size exceeds the threshold.
   */
  checkSizeThreshold(): boolean {
    // TODO: stat() the database file
    // TODO: Compare to config.sizeWarningThresholdBytes
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Create a backup of the database file using SQLite's backup API.
   *
   * @param outputPath - Optional custom backup path. Default: backupDir/registry-{timestamp}.db
   * @returns The path to the backup file.
   */
  backup(outputPath?: string): string {
    // TODO: Use db.backup() from better-sqlite3
    // TODO: or copy file while no writes in progress
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Run PRAGMA integrity_check and return the results.
   * Throws on critical corruption.
   *
   * @returns Object with ok flag and array of issues found.
   * @throws {RegistryError} REG_CORRUPTION_DETECTED on critical corruption.
   */
  integrityCheck(): { ok: boolean; issues: string[] } {
    // TODO: PRAGMA integrity_check
    // TODO: Parse results
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Vacuum the database to reclaim space after large deletions.
   * This operation locks the database briefly.
   */
  vacuum(): void {
    // TODO: VACUUM
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── TRANSACTION HELPERS ─────────────────────────────────────

  /**
   * Execute a function within a database transaction.
   * If the function throws, the transaction is rolled back.
   *
   * @param fn - The function to execute within the transaction.
   * @returns The return value of the function.
   */
  transaction<T>(fn: () => T): T {
    // TODO: Use db.transaction() from better-sqlite3
    if (!this.db) {
      throw new RegistryError(
        RegistryErrorCode.CONNECTION_ERROR,
        "Registry not initialized."
      );
    }
    const txn = this.db.transaction(fn);
    return txn();
  }
}

// ═══════════════════════════════════════════════════════════════
// CLI ADAPTER
// ═══════════════════════════════════════════════════════════════

/**
 * RegistryCLI — Adapter between command-line arguments and
 * RegistryManager methods. Parses argv, invokes the appropriate
 * repository method, and formats output for the terminal.
 *
 * This class does NOT implement the CLI framework (argument parsing,
 * help text, etc.) — it provides the handler functions that a CLI
 * framework (e.g., commander, yargs) would call.
 *
 * @example
 * ```typescript
 * const cli = new RegistryCLI(registry);
 *
 * // Called by the CLI framework when user runs:
 * //   openclaw security registry add entry "6 children" --level ASK_FIRST --variants "six kids,6 kids"
 * cli.addEntry({
 *   primaryValue: '6 children',
 *   classification: 'ASK_FIRST',
 *   variants: ['six kids', '6 kids'],
 * });
 * ```
 */
export class RegistryCLI {
  private registry: RegistryManager;

  constructor(registry: RegistryManager) {
    this.registry = registry;
  }

  // ─── PATTERN COMMANDS ────────────────────────────────────────

  /**
   * Handler for: openclaw security registry add pattern
   *
   * @param options - Parsed CLI options for pattern creation.
   * @returns Formatted output string for the terminal.
   */
  addPattern(options: {
    name: string;
    regex?: string;
    presidioRecognizer?: string;
    category: string;
    level: ClassificationLevel;
    locale: string;
  }): string {
    // TODO: Call patterns.create()
    // TODO: Format success message with created ID
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Handler for: openclaw security registry remove pattern <id>
   */
  removePattern(id: number): string {
    // TODO: Call patterns.deactivate()
    // TODO: Format confirmation message
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── ENTRY COMMANDS ──────────────────────────────────────────

  /**
   * Handler for: openclaw security registry add entry
   *
   * @param options - Parsed CLI options for entry creation.
   * @returns Formatted output string.
   */
  addEntry(options: {
    value: string;
    label?: string;
    displayName?: string;
    level: ClassificationLevel;
    category?: string;
    variants?: string[];
  }): string {
    // TODO: Auto-generate label from value if not provided
    // TODO: Call entries.create()
    // TODO: Format success message
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Handler for: openclaw security registry remove entry <id>
   */
  removeEntry(id: number): string {
    // TODO: Call entries.deactivate()
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Handler for: openclaw security registry add destination-rule
   */
  addDestinationRule(options: {
    entryId: number;
    destination: DestinationType;
    targetPattern?: string;
    level: ClassificationLevel;
  }): string {
    // TODO: Call entries.addDestinationRule()
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── LIST COMMANDS ───────────────────────────────────────────

  /**
   * Handler for: openclaw security registry list patterns|entries|rules
   *
   * @param type - What to list.
   * @param options - Parsed filter options.
   * @returns Formatted table string for the terminal.
   */
  list(
    type: "patterns" | "entries" | "rules",
    options?: {
      locale?: string;
      level?: ClassificationLevel;
      category?: string;
    }
  ): string {
    // TODO: Call appropriate list method
    // TODO: Format as table using column alignment
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Handler for: openclaw security registry search <query>
   *
   * @param query - The search keyword.
   * @returns Formatted search results string.
   */
  searchCommand(query: string): string {
    // TODO: Call registry.search()
    // TODO: Format results with type, label, classification
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── LOCALE COMMANDS ─────────────────────────────────────────

  /**
   * Handler for: openclaw security registry locale load <locale-name>
   */
  localeLoad(localeId: string): string {
    // TODO: Call registry.loadLocale()
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Handler for: openclaw security registry locale list
   */
  localeList(): string {
    // TODO: Call registry.listLocales()
    // TODO: Format as table
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── INVENTORY COMMANDS ──────────────────────────────────────

  /**
   * Handler for: openclaw security registry inventory list
   */
  inventoryList(options?: {
    level?: ClassificationLevel;
    location?: string;
  }): string {
    // TODO: Call inventory.query()
    // TODO: Format as table
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Handler for: openclaw security registry inventory stats
   */
  inventoryStats(): string {
    // TODO: Call inventory.getStats()
    // TODO: Format stats display
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  // ─── EXPORT/IMPORT COMMANDS ──────────────────────────────────

  /**
   * Handler for: openclaw security registry export <locale> --output <file>
   */
  exportCommand(localeId: string, outputPath: string): string {
    // TODO: Call registry.exportLocale()
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }

  /**
   * Handler for: openclaw security registry import <file> [--locale <locale>]
   */
  importCommand(inputPath: string, localeOverride?: string): string {
    // TODO: Call registry.importLocale()
    throw new RegistryError(
      RegistryErrorCode.QUERY_ERROR,
      "Not implemented"
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// MODULE EXPORTS
// ═══════════════════════════════════════════════════════════════

export {
  RegistryManager,
  RegistryCLI,
  // Re-export types that consumers of this module need
  type RegistryConfig,
  type CreatePatternInput,
  type UpdatePatternInput,
  type CreateEntryInput,
  type UpdateEntryInput,
  type CreateDestinationRuleInput,
  type CreateInventoryInput,
  type UpdateInventoryInput,
  type InventoryQueryFilter,
  type PatternQueryFilter,
  type EntryQueryFilter,
  type InventoryStats,
  type LocaleInfo,
  type LocaleExportData,
  type SearchResult,
  type DatabaseStatus,
};
