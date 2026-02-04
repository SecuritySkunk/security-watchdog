/**
 * Registry Module Types
 * 
 * Re-exports shared types and defines registry-specific types.
 */

import { ClassificationLevel } from '../shared/types.js';

// Re-export
export { ClassificationLevel };

// Registry-specific types

export interface PatternDefinition {
  id: number;
  localeId: string;
  category: string;
  patternType: string;
  displayName: string;
  presidioRecognizer: string | null;
  regexPattern: string | null;
  regexFlags: string;
  validationFunction: string | null;
  defaultClassification: ClassificationLevel;
  falsePositiveHints: string[];
  exampleValues: string[];
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

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

export interface PatternQueryFilter {
  localeId?: string;
  category?: string;
  isActive?: boolean;
  classification?: ClassificationLevel;
  limit?: number;
  offset?: number;
}

// User-defined entry types

export interface UserDefinedEntry {
  id: number;
  label: string;
  displayName: string;
  primaryValue: string;
  classification: ClassificationLevel;
  category: string;
  notes: string | null;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface EntryVariant {
  id: number;
  entryId: number;
  variantText: string;
  createdAt: string;
}

export interface CreateEntryInput {
  label: string;
  displayName: string;
  primaryValue: string;
  classification: ClassificationLevel;
  category?: string;
  notes?: string;
  variants?: string[];
}

export interface UpdateEntryInput {
  displayName?: string;
  primaryValue?: string;
  classification?: ClassificationLevel;
  category?: string;
  notes?: string;
  isActive?: boolean;
}

export interface EntryQueryFilter {
  category?: string;
  classification?: ClassificationLevel;
  isActive?: boolean;
  keyword?: string;
  limit?: number;
  offset?: number;
}

// Inventory types

export type DataForm = 'verbatim' | 'paraphrased' | 'derived' | 'reference';

export interface InventoryEntry {
  id: number;
  registryRefType: 'pattern' | 'user_entry';
  registryRefId: number;
  registryRefLabel: string;
  storageLocation: string;
  storageType: 'file' | 'session' | 'memory' | 'context';
  dataForm: DataForm;
  detectedBy: string;
  currentClassification: ClassificationLevel;
  isActive: boolean;
  firstDetectedAt: string;
  lastVerifiedAt: string;
  deactivatedAt: string | null;
  deactivatedBy: string | null;
}

export interface CreateInventoryInput {
  registryRefType: 'pattern' | 'user_entry';
  registryRefId: number;
  registryRefLabel: string;
  storageLocation: string;
  storageType: 'file' | 'session' | 'memory' | 'context';
  dataForm?: DataForm;
  detectedBy: string;
  currentClassification: ClassificationLevel;
}

export interface UpdateInventoryInput {
  storageLocation?: string;
  storageType?: 'file' | 'session' | 'memory' | 'context';
  dataForm?: DataForm;
  currentClassification?: ClassificationLevel;
  isActive?: boolean;
  deactivatedBy?: string;
}

export interface InventoryQueryFilter {
  classification?: ClassificationLevel;
  storageType?: 'file' | 'session' | 'memory' | 'context';
  storageLocation?: string;
  isActive?: boolean;
  registryRefType?: 'pattern' | 'user_entry';
  limit?: number;
  offset?: number;
}

export interface InventoryStats {
  totalActive: number;
  totalInactive: number;
  byClassification: Record<string, number>;
  byStorageType: Record<string, number>;
  byDataForm: Record<string, number>;
  oldestActiveItem: InventoryEntry | null;
  newestActiveItem: InventoryEntry | null;
}

/** Base error class for all Registry operations. */
export class RegistryError extends Error {
  public readonly code: RegistryErrorCode;
  public readonly details: Record<string, unknown> | undefined;

  constructor(
    code: RegistryErrorCode,
    message: string,
    details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'RegistryError';
    this.code = code;
    this.details = details;
  }
}

export enum RegistryErrorCode {
  CONNECTION_ERROR = 'REG_CONNECTION_ERROR',
  QUERY_ERROR = 'REG_QUERY_ERROR',
  CONSTRAINT_VIOLATION = 'REG_CONSTRAINT_VIOLATION',
  NOT_FOUND = 'REG_NOT_FOUND',
  INVALID_CLASSIFICATION = 'REG_INVALID_CLASSIFICATION',
  INVALID_LOCALE = 'REG_INVALID_LOCALE',
  LOCALE_VALIDATION_ERROR = 'REG_LOCALE_VALIDATION_ERROR',
  PERMISSION_ERROR = 'REG_PERMISSION_ERROR',
  CORRUPTION_DETECTED = 'REG_CORRUPTION_DETECTED',
  SIZE_THRESHOLD_EXCEEDED = 'REG_SIZE_THRESHOLD_EXCEEDED',
  IMPORT_ERROR = 'REG_IMPORT_ERROR',
  EXPORT_ERROR = 'REG_EXPORT_ERROR',
  BULK_OPERATION_ERROR = 'REG_BULK_OPERATION_ERROR',
  INTERNAL_ERROR = 'REG_INTERNAL_ERROR',
  DUPLICATE_LABEL = 'REG_DUPLICATE_LABEL',
  DUPLICATE_VARIANT = 'REG_DUPLICATE_VARIANT',
}
