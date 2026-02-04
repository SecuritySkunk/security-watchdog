/**
 * Registry Module - Public API
 * 
 * This module provides data management for the Security Watchdog:
 * - Pattern definitions (PII detection rules)
 * - User-defined entries (custom sensitive data)
 * - Live inventory (tracked sensitive data locations)
 */

// Main facade
export { RegistryManager, default } from './registry-manager.js';
export type { RegistryHealth, PostureInput } from './registry-manager.js';

// Types
export type {
  // Pattern types
  PatternDefinition,
  CreatePatternInput,
  UpdatePatternInput,
  PatternQueryFilter,
  // Entry types
  UserDefinedEntry,
  EntryVariant,
  CreateEntryInput,
  UpdateEntryInput,
  EntryQueryFilter,
  // Inventory types
  DataForm,
  InventoryEntry,
  CreateInventoryInput,
  UpdateInventoryInput,
  InventoryQueryFilter,
  InventoryStats,
  // Classification
  ClassificationLevel,
} from './types.js';

// Errors
export { RegistryError, RegistryErrorCode } from './types.js';

// Individual repositories (for advanced use cases)
export { PatternRepository } from './pattern-repository.js';
export { EntryRepository } from './entry-repository.js';
export { InventoryRepository } from './inventory-repository.js';
