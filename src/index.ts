/**
 * Security Watchdog - Main Entry Point
 * 
 * Exports all public APIs for integration with OpenClaw and other systems.
 */

// Registry Module
export { RegistryManager } from './registry/registry-manager.js';
export { PatternRepository } from './registry/pattern-repository.js';
export { EntryRepository } from './registry/entry-repository.js';
export { InventoryRepository } from './registry/inventory-repository.js';
export type {
  PatternDefinition,
  CreatePatternInput,
  UpdatePatternInput,
  PatternQueryFilter,
  UserDefinedEntry,
  EntryVariant,
  CreateEntryInput,
  UpdateEntryInput,
  EntryQueryFilter,
  InventoryEntry,
  CreateInventoryInput,
  UpdateInventoryInput,
  InventoryQueryFilter,
  InventoryStats,
  DataForm,
  RegistryErrorCode,
} from './registry/types.js';
export { ClassificationLevel, RegistryError } from './registry/types.js';

// Scanner Module
export { PatternScanner } from './scanner/pattern-scanner.js';
export type {
  ScannerConfig,
  ScanFlag,
  ScanResult,
} from './scanner/pattern-scanner.js';

// Gateway Module
export { GatewayHook } from './gateway/gateway-hook.js';
export type {
  GatewayHookConfig,
  PostureLevel,
  DestinationType,
  OutboundRequest,
  OutboundResult,
  InboundRequest,
  InboundResult,
  QuarantineEntry,
} from './gateway/gateway-hook.js';

// Audit Module
export { DecisionLogger } from './audit/decision-logger.js';
export type {
  DecisionLoggerConfig,
  DecisionType,
  DecisionEntry,
  DecisionQuery,
  DecisionStats,
} from './audit/decision-logger.js';

// External Module
export { PresidioClient, DEFAULT_ENTITY_TYPES } from './external/presidio-client.js';
export type {
  PresidioConfig,
  PresidioAnalyzeRequest,
  PresidioEntity,
  PresidioResult,
  PresidioHealth,
  EntityClassification,
  EntityTypeConfig,
} from './external/presidio-client.js';

// Shared
export {
  getDatabase,
  closeDatabase,
  isDatabaseConnected,
  getDatabaseStatus,
} from './shared/database.js';
export type { DatabaseConfig } from './shared/database.js';

// Shared Types (Enums)
export {
  ClassificationLevel as Classification,
  ScanVerdict,
  AgentDecision,
  EscalationResponse,
  PostureLevel as PostureLevelEnum,
  DestinationType as DestinationTypeEnum,
  HealthStatus,
  SystemMode,
  ScanDirection,
  DataForm as DataFormEnum,
} from './shared/types.js';

// Version
export const VERSION = '0.1.0';
