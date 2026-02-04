/**
 * Auditor Module — System Health and Monitoring
 */

export { AuditorDaemon, DEFAULT_CONFIG } from './auditor-daemon.js';
export type {
  AuditorConfig,
  SystemMode,
  ComponentHealth,
  SystemHealth,
  WorkspaceScanResult,
  AuditorMetrics,
  AuditorEvents,
} from './auditor-daemon.js';
