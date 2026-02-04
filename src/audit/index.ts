/**
 * Audit Module - Public API
 * 
 * Provides audit trail and logging for security decisions.
 */

export { DecisionLogger, default } from './decision-logger.js';
export type {
  DecisionLoggerConfig,
  DecisionType,
  DecisionEntry,
  DecisionQuery,
  DecisionStats,
} from './decision-logger.js';
