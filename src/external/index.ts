/**
 * External Module - Third-party Service Integrations
 * 
 * Provides clients for external services like Presidio.
 */

export { PresidioClient, default } from './presidio-client.js';
export type {
  PresidioConfig,
  PresidioAnalyzeRequest,
  PresidioEntity,
  PresidioResult,
  PresidioHealth,
  EntityClassification,
  EntityTypeConfig,
} from './presidio-client.js';
export { DEFAULT_ENTITY_TYPES } from './presidio-client.js';
