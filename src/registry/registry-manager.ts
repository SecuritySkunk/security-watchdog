/**
 * RegistryManager - Main public API facade for the Registry module.
 * 
 * Provides a unified interface to Pattern, Entry, and Inventory repositories.
 */

import { PatternRepository } from './pattern-repository.js';
import { EntryRepository } from './entry-repository.js';
import { InventoryRepository } from './inventory-repository.js';
import type {
  PatternDefinition, CreatePatternInput, UpdatePatternInput, PatternQueryFilter,
  UserDefinedEntry, EntryVariant, CreateEntryInput, UpdateEntryInput, EntryQueryFilter,
  InventoryEntry, CreateInventoryInput, UpdateInventoryInput, InventoryQueryFilter, InventoryStats,
} from './types.js';
import { RegistryError, RegistryErrorCode } from './types.js';

export interface RegistryHealth {
  ok: boolean;
  patternCount: number;
  entryCount: number;
  inventoryActiveCount: number;
  error?: string;
}

export interface PostureInput {
  neverShareCount: number;
  askFirstCount: number;
  internalOnlyCount: number;
  totalActive: number;
}

/**
 * Main public API facade for the Registry module.
 */
export class RegistryManager {
  private patterns: PatternRepository;
  private entries: EntryRepository;
  private inventory: InventoryRepository;
  private dbPath: string;

  /**
   * Creates a new RegistryManager instance.
   * @param dbPath - Path to the SQLite database file
   */
  constructor(dbPath: string) {
    this.dbPath = dbPath;
    this.patterns = new PatternRepository(dbPath);
    this.entries = new EntryRepository(dbPath);
    this.inventory = new InventoryRepository(dbPath);
  }

  // ============================================================
  // PATTERN METHODS
  // ============================================================

  /** Creates a new PII pattern definition. */
  createPattern(input: CreatePatternInput): PatternDefinition {
    try {
      return this.patterns.create(input);
    } catch (error) {
      throw this.wrapError(error, 'Failed to create pattern');
    }
  }

  /** Retrieves a pattern by ID. */
  getPattern(id: number): PatternDefinition | null {
    try {
      return this.patterns.getById(id);
    } catch (error) {
      throw this.wrapError(error, 'Failed to get pattern');
    }
  }

  /** Updates an existing pattern. */
  updatePattern(id: number, input: UpdatePatternInput): PatternDefinition {
    try {
      return this.patterns.update(id, input);
    } catch (error) {
      throw this.wrapError(error, 'Failed to update pattern');
    }
  }

  /** Soft-deletes a pattern (sets isActive = false). */
  deactivatePattern(id: number): void {
    try {
      this.patterns.deactivate(id);
    } catch (error) {
      throw this.wrapError(error, 'Failed to deactivate pattern');
    }
  }

  /** Permanently deletes a pattern. Use with caution. */
  deletePattern(id: number): void {
    try {
      this.patterns.hardDelete(id);
    } catch (error) {
      throw this.wrapError(error, 'Failed to delete pattern');
    }
  }

  /** Lists patterns with optional filtering. */
  listPatterns(filter?: PatternQueryFilter): PatternDefinition[] {
    try {
      return this.patterns.list(filter);
    } catch (error) {
      throw this.wrapError(error, 'Failed to list patterns');
    }
  }

  /** Gets all active patterns for specified locales (optimized for scanner). */
  getPatternsForScanner(localeIds: string[]): PatternDefinition[] {
    try {
      return this.patterns.preloadForScanner(localeIds);
    } catch (error) {
      throw this.wrapError(error, 'Failed to preload patterns for scanner');
    }
  }

  /** Counts patterns matching the filter. */
  countPatterns(filter?: PatternQueryFilter): number {
    try {
      return this.patterns.count(filter);
    } catch (error) {
      throw this.wrapError(error, 'Failed to count patterns');
    }
  }

  // ============================================================
  // ENTRY METHODS (User-Defined Sensitive Data)
  // ============================================================

  /** Creates a new user-defined sensitive entry with optional variants. */
  createEntry(input: CreateEntryInput): UserDefinedEntry & { variants: EntryVariant[] } {
    try {
      return this.entries.create(input);
    } catch (error) {
      throw this.wrapError(error, 'Failed to create entry');
    }
  }

  /** Retrieves an entry by ID, including its variants. */
  getEntry(id: number): (UserDefinedEntry & { variants: EntryVariant[] }) | null {
    try {
      return this.entries.getById(id);
    } catch (error) {
      throw this.wrapError(error, 'Failed to get entry');
    }
  }

  /** Retrieves an entry by its unique label. */
  getEntryByLabel(label: string): (UserDefinedEntry & { variants: EntryVariant[] }) | null {
    try {
      return this.entries.getByLabel(label);
    } catch (error) {
      throw this.wrapError(error, 'Failed to get entry by label');
    }
  }

  /** Updates an existing entry. */
  updateEntry(id: number, input: UpdateEntryInput): UserDefinedEntry {
    try {
      return this.entries.update(id, input);
    } catch (error) {
      throw this.wrapError(error, 'Failed to update entry');
    }
  }

  /** Soft-deletes an entry. */
  deactivateEntry(id: number): void {
    try {
      this.entries.deactivate(id);
    } catch (error) {
      throw this.wrapError(error, 'Failed to deactivate entry');
    }
  }

  /** Permanently deletes an entry and its variants. */
  deleteEntry(id: number): void {
    try {
      this.entries.hardDelete(id);
    } catch (error) {
      throw this.wrapError(error, 'Failed to delete entry');
    }
  }

  /** Lists entries with optional filtering. */
  listEntries(filter?: EntryQueryFilter): UserDefinedEntry[] {
    try {
      return this.entries.list(filter);
    } catch (error) {
      throw this.wrapError(error, 'Failed to list entries');
    }
  }

  /** Gets all active entries with variants (optimized for scanner). */
  getEntriesForScanner(): Array<UserDefinedEntry & { variants: string[] }> {
    try {
      return this.entries.preloadForScanner();
    } catch (error) {
      throw this.wrapError(error, 'Failed to preload entries for scanner');
    }
  }

  /** Counts entries matching the filter. */
  countEntries(filter?: EntryQueryFilter): number {
    try {
      return this.entries.count(filter);
    } catch (error) {
      throw this.wrapError(error, 'Failed to count entries');
    }
  }

  /** Adds a variant spelling/format to an entry. */
  addVariant(entryId: number, variantText: string): EntryVariant {
    try {
      return this.entries.addVariant(entryId, variantText);
    } catch (error) {
      throw this.wrapError(error, 'Failed to add variant');
    }
  }

  /** Removes a variant by its ID. */
  removeVariant(variantId: number): void {
    try {
      this.entries.removeVariant(variantId);
    } catch (error) {
      throw this.wrapError(error, 'Failed to remove variant');
    }
  }

  /** Lists all variants for an entry. */
  listVariants(entryId: number): EntryVariant[] {
    try {
      return this.entries.listVariants(entryId);
    } catch (error) {
      throw this.wrapError(error, 'Failed to list variants');
    }
  }

  // ============================================================
  // INVENTORY METHODS (Live Data Tracking)
  // ============================================================

  /** Records a new detection or updates existing inventory entry. */
  recordDetection(input: CreateInventoryInput): InventoryEntry {
    try {
      return this.inventory.addOrUpdate(input);
    } catch (error) {
      throw this.wrapError(error, 'Failed to record detection');
    }
  }

  /** Retrieves an inventory entry by ID. */
  getInventoryEntry(id: number): InventoryEntry | null {
    try {
      return this.inventory.getById(id);
    } catch (error) {
      throw this.wrapError(error, 'Failed to get inventory entry');
    }
  }

  /** Updates an inventory entry. */
  updateInventoryEntry(id: number, input: UpdateInventoryInput): InventoryEntry {
    try {
      return this.inventory.update(id, input);
    } catch (error) {
      throw this.wrapError(error, 'Failed to update inventory entry');
    }
  }

  /** Deactivates an inventory entry (data no longer present). */
  deactivateInventoryEntry(id: number, deactivatedBy: string): void {
    try {
      this.inventory.deactivate(id, deactivatedBy);
    } catch (error) {
      throw this.wrapError(error, 'Failed to deactivate inventory entry');
    }
  }

  /** Marks an inventory entry as verified (still present). */
  verifyInventoryEntry(id: number): void {
    try {
      this.inventory.verify(id);
    } catch (error) {
      throw this.wrapError(error, 'Failed to verify inventory entry');
    }
  }

  /** Queries inventory with optional filtering. */
  queryInventory(filter?: InventoryQueryFilter): InventoryEntry[] {
    try {
      return this.inventory.query(filter);
    } catch (error) {
      throw this.wrapError(error, 'Failed to query inventory');
    }
  }

  /** Gets aggregated inventory statistics. */
  getInventoryStats(): InventoryStats {
    try {
      return this.inventory.getStats();
    } catch (error) {
      throw this.wrapError(error, 'Failed to get inventory stats');
    }
  }

  /** Gets posture calculation inputs. */
  getPostureInput(): PostureInput {
    try {
      return this.inventory.getPostureInput();
    } catch (error) {
      throw this.wrapError(error, 'Failed to get posture input');
    }
  }

  /** Deactivates all inventory entries for a storage location. */
  clearInventoryByLocation(storageLocation: string, clearedBy: string): number {
    try {
      return this.inventory.deactivateByLocation(storageLocation, clearedBy);
    } catch (error) {
      throw this.wrapError(error, 'Failed to clear inventory by location');
    }
  }

  /** Purges inactive inventory entries older than specified days. */
  purgeInactiveInventory(olderThanDays: number): number {
    try {
      return this.inventory.purgeInactive(olderThanDays);
    } catch (error) {
      throw this.wrapError(error, 'Failed to purge inactive inventory');
    }
  }

  /** Finds inventory entries that haven't been verified recently. */
  findStaleInventory(olderThanHours: number): InventoryEntry[] {
    try {
      return this.inventory.findStale(olderThanHours);
    } catch (error) {
      throw this.wrapError(error, 'Failed to find stale inventory');
    }
  }

  // ============================================================
  // HEALTH & UTILITY
  // ============================================================

  /** Gets registry health status and counts. */
  getHealth(): RegistryHealth {
    try {
      const patternCount = this.patterns.count({ isActive: true });
      const entryCount = this.entries.count({ isActive: true });
      const inventoryStats = this.inventory.getStats();
      return {
        ok: true,
        patternCount,
        entryCount,
        inventoryActiveCount: inventoryStats.totalActive,
      };
    } catch (error) {
      return {
        ok: false,
        patternCount: 0,
        entryCount: 0,
        inventoryActiveCount: 0,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /** Gets the database path. */
  getDatabasePath(): string {
    return this.dbPath;
  }

  // ============================================================
  // PRIVATE HELPERS
  // ============================================================

  private wrapError(error: unknown, context: string): RegistryError {
    if (error instanceof RegistryError) {
      return error;
    }
    const message = error instanceof Error ? error.message : 'Unknown error';
    return new RegistryError(
      RegistryErrorCode.INTERNAL_ERROR,
      `${context}: ${message}`,
      { originalError: message }
    );
  }
}

export default RegistryManager;
