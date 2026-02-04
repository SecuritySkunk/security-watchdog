/**
 * Security Watchdog — Auditor Daemon (Layer 3)
 *
 * Document ID:  SWDOG-MOD-007
 * Version:      1.0 DRAFT
 * Generated:    February 2026
 *
 * This module implements the independent Auditor Daemon that monitors
 * all other Security Watchdog components, performs periodic workspace
 * reconciliation scans, maintains tamper-evident audit logs, and
 * aggregates metrics for the Executive Dashboard.
 *
 * The Auditor is the enforcement mechanism behind the fail-closed
 * design principle: if any security component fails, outbound traffic
 * is queued until the component recovers.
 *
 * ────────────────────────────────────────────────────────────────
 * INSTALLATION:
 *   Runs as a systemd service (see SYSTEMD_UNIT_FILE constant).
 *   Start before the OpenClaw gateway.
 *
 * DEPENDENCIES:
 *   - better-sqlite3 (Registry database access)
 *   - Node.js native fetch (health check HTTP calls)
 *   - Pattern Scanner library (workspace scanning)
 *   - crypto (hash chain, HMAC)
 * ────────────────────────────────────────────────────────────────
 */

import type {
  HealthCheckResponse,
  HealthStatus,
  SystemMode,
  PostureLevel,
  DailyMetrics,
  DashboardSummary,
  SystemHealthReport,
  ComponentHealthSummary,
  ScanDecisionRecord,
  InventorySummary,
  InventoryEntry,
  EscalationStatus,
  WatchdogError,
  WatchdogErrorCode,
  AuditorConfig,
} from "@watchdog/types";

import type Database from "better-sqlite3";

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

/** Complete Auditor configuration with defaults. */
export interface AuditorDaemonConfig {
  /** Database file path. Default: ~/.openclaw/security/registry.db */
  databasePath: string;

  /** Port for the dashboard HTTP API. Default: 5004 */
  dashboardPort: number;

  /** ─── Health Check Settings ─── */

  /** Seconds between health check cycles. Default: 30 */
  healthCheckIntervalSeconds: number;

  /** HTTP timeout per health check in milliseconds. Default: 1000 */
  healthCheckTimeoutMs: number;

  /** Consecutive failures before triggering isolation. Default: 3 */
  isolationThreshold: number;

  /** Consecutive healthy checks required to exit isolation. Default: 5 */
  recoveryThreshold: number;

  /** ─── Component Endpoints ─── */

  /** Health check endpoints per component. */
  components: ComponentEndpoint[];

  /** ─── Workspace Scan Settings ─── */

  /** Seconds between workspace scans. Default: 21600 (6 hours) */
  workspaceScanIntervalSeconds: number;

  /** Files per batch during workspace scan. Default: 50 */
  workspaceScanBatchSize: number;

  /** Pause between batches in milliseconds. Default: 100 */
  workspaceScanPauseMs: number;

  /** Workspace directory paths to scan. */
  workspacePaths: string[];

  /** Session log directory path. */
  sessionLogPath: string;

  /** File extensions to scan (others are skipped). */
  scannableExtensions: string[];

  /** ─── Metrics & Retention ─── */

  /** Seconds between today's metrics refresh. Default: 300 */
  metricsRefreshIntervalSeconds: number;

  /** Days to retain daily_metrics rows. Default: 90 */
  metricsRetentionDays: number;

  /** Days to retain scan_decisions rows. Default: 90 */
  logRetentionDays: number;

  /** Days to retain posture_history rows. Default: 365 */
  postureHistoryRetentionDays: number;

  /** Max health_checks rows per component. Default: 1000 */
  maxHealthCheckEntries: number;

  /** Days to retain resolved quarantine entries. Default: 7 */
  quarantineRetentionDays: number;

  /** ─── Notification Settings ─── */

  /** Channel for isolation/recovery notifications. */
  notificationChannel: string;

  /** Peer ID (phone number, username) for notifications. */
  notificationPeerId: string;

  /** Minutes before sending isolation reminder. Default: 30 */
  isolationReminderMinutes: number;

  /** ─── Flapping Detection ─── */

  /** Window in minutes for flapping detection. Default: 10 */
  flappingWindowMinutes: number;

  /** State changes within window to flag as flapping. Default: 6 */
  flappingThreshold: number;

  /** ─── Logging ─── */

  /** Log level: ERROR, WARN, INFO, DEBUG. Default: INFO */
  logLevel: "ERROR" | "WARN" | "INFO" | "DEBUG";
}

/** Health check endpoint configuration for a single component. */
export interface ComponentEndpoint {
  /** Component name (must match IF-009 component field). */
  name: string;

  /** HTTP health endpoint URL. */
  endpoint: string;

  /** Whether this component is critical (failure triggers isolation). */
  isCritical: boolean;

  /** Optional: specific validation (e.g., verify Ollama model loaded). */
  validationFn?: string;
}

/** Default configuration values. */
export const DEFAULT_CONFIG: AuditorDaemonConfig = {
  databasePath: "~/.openclaw/security/registry.db",
  dashboardPort: 5004,

  healthCheckIntervalSeconds: 30,
  healthCheckTimeoutMs: 1000,
  isolationThreshold: 3,
  recoveryThreshold: 5,

  components: [
    { name: "pattern-scanner", endpoint: "http://127.0.0.1:5001/health", isCritical: true },
    { name: "presidio", endpoint: "http://127.0.0.1:5002/health", isCritical: true },
    { name: "security-agent", endpoint: "http://127.0.0.1:5003/health", isCritical: true },
    { name: "ollama", endpoint: "http://127.0.0.1:11434/api/tags", isCritical: false, validationFn: "validateOllamaModel" },
    { name: "dashboard", endpoint: "http://127.0.0.1:5004/health", isCritical: false },
  ],

  workspaceScanIntervalSeconds: 21600,
  workspaceScanBatchSize: 50,
  workspaceScanPauseMs: 100,
  workspacePaths: ["~/.openclaw/agents/"],
  sessionLogPath: "~/.openclaw/sessions/",
  scannableExtensions: [".txt", ".md", ".json", ".yaml", ".yml", ".log", ".csv", ".tsv", ".xml", ".html"],

  metricsRefreshIntervalSeconds: 300,
  metricsRetentionDays: 90,
  logRetentionDays: 90,
  postureHistoryRetentionDays: 365,
  maxHealthCheckEntries: 1000,
  quarantineRetentionDays: 7,

  notificationChannel: "whatsapp",
  notificationPeerId: "",
  isolationReminderMinutes: 30,

  flappingWindowMinutes: 10,
  flappingThreshold: 6,

  logLevel: "INFO",
};


// ═══════════════════════════════════════════════════════════════
// INTERNAL TYPES
// ═══════════════════════════════════════════════════════════════

/** Tracks the health state of a single component. */
interface ComponentHealthState {
  /** Component name. */
  name: string;

  /** Current status. */
  status: HealthStatus;

  /** Consecutive failure count. */
  consecutiveFailures: number;

  /** Consecutive success count (for recovery). */
  consecutiveSuccesses: number;

  /** Recent check results for flapping detection. */
  recentChecks: Array<{ status: HealthStatus; timestamp: Date }>;

  /** Last successful check timestamp. */
  lastSuccessAt: Date | null;

  /** Last failure timestamp. */
  lastFailureAt: Date | null;

  /** Whether component is currently flagged as flapping. */
  isFlapping: boolean;
}

/** Result of a workspace scan. */
interface WorkspaceScanResult {
  /** Total files scanned. */
  filesScanned: number;

  /** Files skipped (binary, unreadable, etc.). */
  filesSkipped: number;

  /** New inventory items discovered. */
  newItemsFound: number;

  /** Existing inventory items verified as still present. */
  itemsVerified: number;

  /** Stale inventory items deactivated. */
  staleItemsDeactivated: number;

  /** Drift items detected (paraphrased/modified). */
  driftItemsDetected: number;

  /** Scan duration in milliseconds. */
  durationMs: number;

  /** Errors encountered during scan. */
  errors: string[];
}

/** A single entry in the tamper-evident hash chain. */
interface HashChainEntry {
  /** The scan decision request_id. */
  requestId: string;

  /** SHA-256 hash of this entry's data + previous hash. */
  chainHash: string;

  /** The previous entry's chain hash (for verification). */
  previousHash: string;
}

/** Structured log event. */
interface LogEvent {
  /** ISO 8601 timestamp. */
  timestamp: string;

  /** Log level. */
  level: "ERROR" | "WARN" | "INFO" | "DEBUG";

  /** Component name. */
  component: string;

  /** Event type identifier. */
  event: string;

  /** Human-readable message. */
  message: string;

  /** Event-specific context. */
  context?: Record<string, unknown>;
}


// ═══════════════════════════════════════════════════════════════
// AUDITOR DAEMON (Main Class)
// ═══════════════════════════════════════════════════════════════

/**
 * The main Auditor Daemon class. Orchestrates all auditor functions:
 * health checking, isolation management, workspace scanning, audit
 * logging, metrics aggregation, and the dashboard HTTP API.
 *
 * Lifecycle:
 *   1. constructor(config) — initializes sub-components
 *   2. start() — begins the main loop (health checks, scans, metrics)
 *   3. stop() — graceful shutdown (completes current cycle, closes DB)
 *
 * @example
 * ```typescript
 * const auditor = new AuditorDaemon(config);
 * await auditor.start();
 *
 * // Graceful shutdown on SIGTERM
 * process.on("SIGTERM", () => auditor.stop());
 * ```
 */
export class AuditorDaemon {
  private readonly config: AuditorDaemonConfig;
  private readonly healthChecker: HealthChecker;
  private readonly isolationManager: IsolationManager;
  private readonly workspaceScanner: WorkspaceScanner;
  private readonly auditLogger: AuditLogger;
  private readonly metricsAggregator: MetricsAggregator;
  private readonly dashboardServer: DashboardServer;
  private readonly logger: StructuredLogger;

  private db: Database.Database | null = null;
  private healthCheckTimer: NodeJS.Timeout | null = null;
  private workspaceScanTimer: NodeJS.Timeout | null = null;
  private metricsRefreshTimer: NodeJS.Timeout | null = null;
  private isRunning: boolean = false;
  private startedAt: Date | null = null;

  constructor(config: Partial<AuditorDaemonConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logger = new StructuredLogger(this.config.logLevel, "auditor-daemon");

    // TODO: Initialize database connection
    // this.db = new BetterSqlite3(this.config.databasePath);
    // this.db.pragma("journal_mode = WAL");
    // this.db.pragma("busy_timeout = 5000");
    // this.db.pragma("foreign_keys = ON");

    this.healthChecker = new HealthChecker(this.config, this.logger);
    this.isolationManager = new IsolationManager(this.config, this.logger);
    this.workspaceScanner = new WorkspaceScanner(this.config, this.logger);
    this.auditLogger = new AuditLogger(this.config, this.logger);
    this.metricsAggregator = new MetricsAggregator(this.config, this.logger);
    this.dashboardServer = new DashboardServer(this.config, this.logger);
  }

  /**
   * Start the Auditor daemon. Performs an initial health check,
   * then enters the main loop with scheduled health checks,
   * workspace scans, and metrics refreshes.
   *
   * FR-AUD-011: Immediate health check on startup.
   */
  async start(): Promise<void> {
    // TODO: Implement startup sequence
    // 1. Open database connection and set pragmas
    // 2. Read current system_mode from database
    // 3. Perform initial health check of all components
    // 4. If any critical component is down, enter ISOLATION
    // 5. Start the dashboard HTTP server
    // 6. Schedule health check timer
    // 7. Schedule workspace scan timer
    // 8. Schedule metrics refresh timer
    // 9. Log startup event
    // 10. Signal systemd watchdog (sd_notify READY=1)
    throw new Error("TODO: Implement start()");
  }

  /**
   * Gracefully stop the Auditor daemon.
   * Completes current cycle, flushes logs, closes DB, stops HTTP server.
   *
   * NFR-AUD-004: Shutdown < 5 seconds.
   */
  async stop(): Promise<void> {
    // TODO: Implement graceful shutdown
    // 1. Set isRunning = false
    // 2. Clear all timers
    // 3. Wait for current health check cycle to complete (if running)
    // 4. Stop dashboard HTTP server
    // 5. Flush any pending audit log writes
    // 6. Close database connection
    // 7. Log shutdown event
    throw new Error("TODO: Implement stop()");
  }

  /**
   * Main health check cycle. Called on timer.
   * Pings all components, evaluates results, triggers isolation
   * or recovery as needed.
   */
  private async runHealthCheckCycle(): Promise<void> {
    // TODO: Implement health check cycle
    // 1. For each configured component:
    //    a. Call healthChecker.checkComponent(component)
    //    b. Record result in health_checks table
    //    c. Update component state (consecutive failures/successes)
    // 2. Evaluate isolation conditions:
    //    a. If any critical component exceeds failure threshold → isolate
    //    b. If in isolation and all critical healthy for recovery threshold → recover
    // 3. Prune old health_checks entries
    // 4. Signal systemd watchdog (WATCHDOG=1)
    throw new Error("TODO: Implement runHealthCheckCycle()");
  }

  /**
   * Run a workspace scan. Called on timer or on-demand via CLI.
   *
   * FR-AUD-040: Full workspace scan at configured interval.
   */
  async runWorkspaceScan(): Promise<WorkspaceScanResult> {
    // TODO: Implement workspace scan orchestration
    // 1. Log scan start
    // 2. Call workspaceScanner.scan()
    // 3. Update config_meta last_workspace_scan timestamp
    // 4. Trigger posture recalculation if inventory changed
    // 5. Log scan summary
    // 6. Return result
    throw new Error("TODO: Implement runWorkspaceScan()");
  }

  /**
   * Refresh today's metrics. Called on timer.
   *
   * FR-AUD-082: Recompute metrics every N seconds.
   */
  private async refreshMetrics(): Promise<void> {
    // TODO: Implement metrics refresh
    // 1. Call metricsAggregator.computeDaily(today)
    // 2. Run daily pruning if it hasn't run today
    throw new Error("TODO: Implement refreshMetrics()");
  }

  /** Get current uptime in seconds. */
  getUptimeSeconds(): number {
    if (!this.startedAt) return 0;
    return Math.floor((Date.now() - this.startedAt.getTime()) / 1000);
  }
}


// ═══════════════════════════════════════════════════════════════
// HEALTH CHECKER
// ═══════════════════════════════════════════════════════════════

/**
 * Handles health check HTTP requests to individual components.
 * Tracks component state including consecutive failures,
 * flapping detection, and Ollama model verification.
 *
 * Implements: IF-009 (Health Monitoring)
 * Requirements: FR-AUD-001 through FR-AUD-012
 */
export class HealthChecker {
  private readonly config: AuditorDaemonConfig;
  private readonly logger: StructuredLogger;
  private readonly componentStates: Map<string, ComponentHealthState>;

  constructor(config: AuditorDaemonConfig, logger: StructuredLogger) {
    this.config = config;
    this.logger = logger;
    this.componentStates = new Map();

    // Initialize state for each configured component
    for (const comp of config.components) {
      this.componentStates.set(comp.name, {
        name: comp.name,
        status: "UNREACHABLE" as HealthStatus,
        consecutiveFailures: 0,
        consecutiveSuccesses: 0,
        recentChecks: [],
        lastSuccessAt: null,
        lastFailureAt: null,
        isFlapping: false,
      });
    }
  }

  /**
   * Ping a single component's health endpoint.
   * Returns a HealthCheckResponse or a synthetic UNREACHABLE response.
   *
   * FR-AUD-001: Ping with configurable interval.
   * NFR-AUD-014: Timeout of 1000ms per check.
   *
   * @param component - The component endpoint configuration.
   * @returns The health check result.
   */
  async checkComponent(component: ComponentEndpoint): Promise<HealthCheckResponse> {
    // TODO: Implement HTTP health check
    // 1. Send HTTP GET to component.endpoint with AbortController timeout
    // 2. Parse JSON response as HealthCheckResponse
    // 3. If component has validationFn (e.g., Ollama), run additional validation
    // 4. On connection refused / timeout, return synthetic UNREACHABLE response
    // 5. Update component state (consecutive counters, recent checks)
    // 6. Check for flapping
    throw new Error("TODO: Implement checkComponent()");
  }

  /**
   * Update the internal state for a component after a health check.
   *
   * FR-AUD-005: Maintain consecutive failure counter.
   * FR-AUD-009: Detect recovery.
   *
   * @param componentName - Name of the component.
   * @param status - The result status.
   */
  updateComponentState(componentName: string, status: HealthStatus): void {
    // TODO: Implement state update
    // 1. Get current state from map
    // 2. If HEALTHY: reset consecutiveFailures, increment consecutiveSuccesses
    // 3. If non-HEALTHY: reset consecutiveSuccesses, increment consecutiveFailures
    // 4. Update lastSuccessAt / lastFailureAt
    // 5. Add to recentChecks, trim to flapping window
    // 6. Check flapping condition
    throw new Error("TODO: Implement updateComponentState()");
  }

  /**
   * Check whether a component should trigger isolation.
   *
   * FR-AUD-006: Consecutive failures > threshold triggers isolation.
   *
   * @param componentName - Name of the component.
   * @returns True if the component has exceeded the isolation threshold.
   */
  shouldTriggerIsolation(componentName: string): boolean {
    // TODO: Implement isolation threshold check
    // 1. Get component state
    // 2. Find the component config to check isCritical
    // 3. If not critical, return false
    // 4. Return consecutiveFailures > config.isolationThreshold
    throw new Error("TODO: Implement shouldTriggerIsolation()");
  }

  /**
   * Check whether isolation can be safely exited.
   * All critical components must be healthy for N consecutive checks.
   *
   * FR-AUD-025: Auto-recovery when all critical healthy for N checks.
   *
   * @returns True if all critical components have met the recovery threshold.
   */
  canExitIsolation(): boolean {
    // TODO: Implement recovery check
    // 1. For each component in config.components where isCritical = true:
    //    a. Get component state
    //    b. If consecutiveSuccesses < config.recoveryThreshold, return false
    // 2. All critical components are healthy → return true
    throw new Error("TODO: Implement canExitIsolation()");
  }

  /**
   * Detect flapping: rapid alternation between healthy and unhealthy.
   *
   * FR-AUD-012: Flapping detection within configurable window.
   *
   * @param componentName - Name of the component.
   * @returns True if the component is flapping.
   */
  detectFlapping(componentName: string): boolean {
    // TODO: Implement flapping detection
    // 1. Get component state
    // 2. Filter recentChecks to those within flappingWindowMinutes
    // 3. Count status transitions (HEALTHY → non-HEALTHY or vice versa)
    // 4. Return transitions > config.flappingThreshold
    throw new Error("TODO: Implement detectFlapping()");
  }

  /**
   * Validate Ollama response: check that the configured model is loaded.
   *
   * FR-AUD-004: Verify model loaded, report DEGRADED if not.
   *
   * @param response - The raw Ollama /api/tags response.
   * @param expectedModel - The model name that should be loaded.
   * @returns HEALTHY if model found, DEGRADED if not.
   */
  validateOllamaModel(response: unknown, expectedModel: string): HealthStatus {
    // TODO: Implement Ollama model validation
    // 1. Parse the Ollama tags response (contains { models: [...] })
    // 2. Check if any model.name matches expectedModel
    // 3. Return HEALTHY if found, DEGRADED if not
    throw new Error("TODO: Implement validateOllamaModel()");
  }

  /**
   * Get the current health state for all components.
   * Used by the dashboard and for the system health report.
   *
   * @returns Array of component health summaries.
   */
  getComponentSummaries(): ComponentHealthSummary[] {
    // TODO: Implement summary generation
    // 1. Map each component state to a ComponentHealthSummary
    // 2. Include recent check results for trend display
    throw new Error("TODO: Implement getComponentSummaries()");
  }
}


// ═══════════════════════════════════════════════════════════════
// ISOLATION MANAGER
// ═══════════════════════════════════════════════════════════════

/**
 * Manages the system isolation mode lifecycle. Handles entering
 * isolation (updating system_mode in the database), exiting
 * isolation (recovery), processing the isolation queue, and
 * sending user notifications.
 *
 * Requirements: FR-AUD-020 through FR-AUD-029
 */
export class IsolationManager {
  private readonly config: AuditorDaemonConfig;
  private readonly logger: StructuredLogger;
  private db: Database.Database | null = null;
  private isolationEnteredAt: Date | null = null;
  private reminderSent: boolean = false;

  constructor(config: AuditorDaemonConfig, logger: StructuredLogger) {
    this.config = config;
    this.logger = logger;
  }

  /** Inject the database connection (set after daemon startup). */
  setDatabase(db: Database.Database): void {
    this.db = db;
  }

  /**
   * Enter isolation mode. Updates system_mode to ISOLATION,
   * logs the event, and notifies the user.
   *
   * FR-AUD-020: Atomic update to system_mode.
   * FR-AUD-024: Notify user on isolation entry.
   *
   * @param reason - Human-readable reason for isolation.
   * @param triggeredBy - Component name that caused the failure.
   */
  async enterIsolation(reason: string, triggeredBy: string): Promise<void> {
    // TODO: Implement isolation entry
    // 1. Update system_mode SET mode = 'ISOLATION', reason, triggered_by, entered_at
    // 2. Log posture_history entry with trigger_type = 'isolation'
    // 3. Record isolationEnteredAt for reminder timing
    // 4. Send notification to user via configured channel
    // 5. Log structured event
    throw new Error("TODO: Implement enterIsolation()");
  }

  /**
   * Exit isolation mode. Updates system_mode to NORMAL,
   * processes the isolation queue, and notifies the user.
   *
   * FR-AUD-025: Auto-recovery after N consecutive healthy checks.
   * FR-AUD-026: Re-submit isolation queue through scanning pipeline.
   * FR-AUD-027: Recovery notification.
   */
  async exitIsolation(): Promise<void> {
    // TODO: Implement isolation exit
    // 1. Update system_mode SET mode = 'NORMAL', reason = 'auto-recovery'
    // 2. Process isolation queue (re-submit queued payloads)
    // 3. Calculate isolation duration
    // 4. Send recovery notification to user
    // 5. Reset reminderSent flag
    // 6. Log structured event
    throw new Error("TODO: Implement exitIsolation()");
  }

  /**
   * Process the isolation queue: re-submit all payloads with
   * state 'isolation_queued' through the normal scanning pipeline.
   *
   * FR-AUD-026: Re-submit queued payloads on recovery.
   *
   * @returns Number of payloads processed.
   */
  async processIsolationQueue(): Promise<number> {
    // TODO: Implement queue processing
    // 1. SELECT all quarantine_queue entries with state = 'isolation_queued'
    // 2. For each entry:
    //    a. Decrypt tool_args
    //    b. Re-submit through the Scanner (IF-001)
    //    c. Update quarantine state based on scan result
    // 3. Return count of processed entries
    throw new Error("TODO: Implement processIsolationQueue()");
  }

  /**
   * Check whether an isolation reminder should be sent.
   *
   * FR-AUD-028: Reminder after configurable threshold.
   *
   * @returns True if reminder is due.
   */
  isReminderDue(): boolean {
    if (!this.isolationEnteredAt || this.reminderSent) return false;
    const elapsedMinutes = (Date.now() - this.isolationEnteredAt.getTime()) / 60000;
    return elapsedMinutes >= this.config.isolationReminderMinutes;
  }

  /**
   * Send an isolation reminder notification.
   *
   * FR-AUD-028: Reminder with manual recovery instructions.
   */
  async sendReminder(): Promise<void> {
    // TODO: Implement reminder
    // 1. Format reminder message with duration, failed components, instructions
    // 2. Send via notification channel
    // 3. Set reminderSent = true
    throw new Error("TODO: Implement sendReminder()");
  }

  /**
   * Get the current system mode from the database.
   *
   * @returns Current system mode record.
   */
  getCurrentMode(): { mode: SystemMode; enteredAt: string; reason: string | null } {
    // TODO: Implement
    // SELECT * FROM system_mode WHERE id = 1
    throw new Error("TODO: Implement getCurrentMode()");
  }

  /**
   * Manual override: force isolation or force resume.
   *
   * FR-AUD-029: Manual override via CLI.
   *
   * @param action - 'isolate' or 'resume'.
   * @param reason - User-provided reason.
   */
  async manualOverride(action: "isolate" | "resume", reason: string): Promise<void> {
    // TODO: Implement manual override
    // 1. If action = 'isolate': enter isolation with trigger_type = 'manual_override'
    // 2. If action = 'resume': exit isolation (if currently isolated)
    // 3. Log the manual override with user reason
    throw new Error("TODO: Implement manualOverride()");
  }
}


// ═══════════════════════════════════════════════════════════════
// WORKSPACE SCANNER
// ═══════════════════════════════════════════════════════════════

/**
 * Performs periodic reconciliation scans of workspace files,
 * comparing detected sensitive data against the current inventory.
 * Detects new items, stale entries, and drift from modifications.
 *
 * The scanner uses the Pattern Scanner's detection libraries
 * (Presidio, fuse.js) as imported modules, not via HTTP.
 *
 * Requirements: FR-AUD-040 through FR-AUD-051
 */
export class WorkspaceScanner {
  private readonly config: AuditorDaemonConfig;
  private readonly logger: StructuredLogger;
  private db: Database.Database | null = null;

  constructor(config: AuditorDaemonConfig, logger: StructuredLogger) {
    this.config = config;
    this.logger = logger;
  }

  /** Inject the database connection. */
  setDatabase(db: Database.Database): void {
    this.db = db;
  }

  /**
   * Execute a full workspace scan.
   *
   * FR-AUD-040: Full scan at configured interval.
   * FR-AUD-041: Use Pattern Scanner libraries.
   *
   * @returns Scan result summary.
   */
  async scan(): Promise<WorkspaceScanResult> {
    // TODO: Implement full workspace scan
    // 1. Enumerate all files in workspace paths
    // 2. Filter to scannable extensions
    // 3. Process files in batches (config.workspaceScanBatchSize)
    // 4. For each file:
    //    a. Read file content
    //    b. Scan with Presidio + fuse.js
    //    c. Compare detections against inventory
    //    d. Create/update/deactivate inventory entries
    // 5. After all files processed, deactivate stale inventory
    // 6. Compile and return results
    throw new Error("TODO: Implement scan()");
  }

  /**
   * Enumerate all scannable files in configured workspace paths.
   *
   * FR-AUD-050: Skip unreadable files with warning.
   *
   * @returns Array of absolute file paths.
   */
  private async enumerateFiles(): Promise<string[]> {
    // TODO: Implement file enumeration
    // 1. For each path in config.workspacePaths:
    //    a. Recursively list all files
    //    b. Filter by config.scannableExtensions
    //    c. Skip symlinks, binary files, files > size limit
    // 2. Also enumerate files in config.sessionLogPath
    // 3. Return sorted list of absolute paths
    throw new Error("TODO: Implement enumerateFiles()");
  }

  /**
   * Scan a single file for sensitive data.
   *
   * FR-AUD-041: Use Pattern Scanner libraries directly.
   *
   * @param filePath - Absolute path to the file.
   * @returns Array of detected items with registry references.
   */
  private async scanFile(filePath: string): Promise<FileDetection[]> {
    // TODO: Implement single file scan
    // 1. Read file content (handle encoding errors)
    // 2. Call Presidio analyzer with file content
    // 3. Call fuse.js fuzzy matcher against user entries
    // 4. Merge and deduplicate results
    // 5. Return detections with file location metadata
    throw new Error("TODO: Implement scanFile()");
  }

  /**
   * Reconcile scan detections against current inventory.
   *
   * FR-AUD-042: Compare with inventory, update or create entries.
   * FR-AUD-043: Detect and deactivate stale entries.
   * FR-AUD-044: Detect drift (paraphrased content).
   *
   * @param detections - All detections from the current scan.
   */
  private async reconcileInventory(detections: FileDetection[]): Promise<{
    newItems: number;
    verified: number;
    stale: number;
    drift: number;
  }> {
    // TODO: Implement inventory reconciliation
    // 1. Build a set of (registry_ref_type, registry_ref_id, storage_location) from detections
    // 2. For each detection:
    //    a. Query inventory for matching entry
    //    b. If found: update last_verified_at → counted as "verified"
    //    c. If not found: INSERT new inventory entry → counted as "newItems"
    // 3. Query all active file-based inventory entries
    //    a. If entry's storage_location not in detections → mark inactive (stale)
    // 4. Return counts
    throw new Error("TODO: Implement reconcileInventory()");
  }

  /**
   * Process files in batches with throttling to prevent CPU starvation.
   *
   * FR-AUD-051: Batch processing with configurable pause.
   *
   * @param files - Array of file paths.
   * @param batchSize - Files per batch.
   * @param pauseMs - Pause between batches in milliseconds.
   */
  private async processBatched(
    files: string[],
    batchSize: number,
    pauseMs: number,
  ): Promise<FileDetection[]> {
    // TODO: Implement batched processing
    // 1. Chunk files into batches of batchSize
    // 2. For each batch:
    //    a. Process all files in parallel (Promise.all)
    //    b. Collect detections
    //    c. If not last batch, await sleep(pauseMs)
    // 3. Return all detections
    throw new Error("TODO: Implement processBatched()");
  }
}

/** Detection result from scanning a single file. */
interface FileDetection {
  /** Registry reference type ("pattern" or "user_entry"). */
  registryRefType: "pattern" | "user_entry";

  /** Registry reference ID. */
  registryRefId: number;

  /** Label for display. */
  registryRefLabel: string;

  /** Absolute file path where detected. */
  storageLocation: string;

  /** Storage type (always "file" for workspace scan). */
  storageType: "file";

  /** How the data appears. */
  dataForm: "VERBATIM" | "PARAPHRASED" | "DERIVED";

  /** Classification level from registry. */
  classification: string;

  /** Detection confidence. */
  confidence: number;
}


// ═══════════════════════════════════════════════════════════════
// AUDIT LOGGER
// ═══════════════════════════════════════════════════════════════

/**
 * Manages the tamper-evident audit log. Maintains a hash chain
 * on scan_decisions entries, provides log verification, retention
 * pruning, and export to JSON/CSV.
 *
 * Requirements: FR-AUD-060 through FR-AUD-067
 */
export class AuditLogger {
  private readonly config: AuditorDaemonConfig;
  private readonly logger: StructuredLogger;
  private db: Database.Database | null = null;

  /** The hash of the most recent log entry (for chain continuity). */
  private lastChainHash: string = "";

  constructor(config: AuditorDaemonConfig, logger: StructuredLogger) {
    this.config = config;
    this.logger = logger;
  }

  /** Inject the database connection. */
  setDatabase(db: Database.Database): void {
    this.db = db;
  }

  /**
   * Initialize the hash chain by reading the last entry's hash.
   * Called during daemon startup.
   */
  async initializeChain(): Promise<void> {
    // TODO: Implement chain initialization
    // 1. SELECT content_hash FROM scan_decisions ORDER BY id DESC LIMIT 1
    // 2. If no entries, set lastChainHash to a known genesis hash
    // 3. Store as lastChainHash for the next entry
    throw new Error("TODO: Implement initializeChain()");
  }

  /**
   * Compute a tamper-evident hash for a new scan decision entry.
   * The hash includes the previous entry's hash, creating a chain.
   *
   * FR-AUD-060: Hash chain on scan_decisions.
   *
   * @param entryData - Serialized entry data to hash.
   * @returns The chain hash for this entry.
   */
  computeChainHash(entryData: string): string {
    // TODO: Implement hash computation
    // 1. Concatenate: lastChainHash + "|" + entryData
    // 2. Compute SHA-256 of the concatenation
    // 3. Update lastChainHash with the new hash
    // 4. Return the new hash
    throw new Error("TODO: Implement computeChainHash()");
  }

  /**
   * Verify the integrity of the audit log hash chain.
   * Walks from the first entry to the most recent, checking each link.
   *
   * FR-AUD-061: Log integrity verification.
   *
   * @returns Verification result with first broken link if found.
   */
  async verifyChain(): Promise<{
    isValid: boolean;
    entriesChecked: number;
    firstBrokenAt?: string;
    brokenAtIndex?: number;
  }> {
    // TODO: Implement chain verification
    // 1. SELECT all scan_decisions ordered by id ASC
    // 2. Start with genesis hash
    // 3. For each entry:
    //    a. Compute expected hash from entry data + previous hash
    //    b. Compare with stored content_hash
    //    c. If mismatch: record the broken link and stop
    // 4. Return result
    throw new Error("TODO: Implement verifyChain()");
  }

  /**
   * Enforce retention policy: delete old entries.
   *
   * FR-AUD-062: Delete entries older than retention period.
   *
   * @returns Number of entries deleted.
   */
  async pruneOldEntries(): Promise<number> {
    // TODO: Implement retention pruning
    // 1. Calculate cutoff date (now - logRetentionDays)
    // 2. DELETE FROM scan_decisions WHERE completed_at < cutoff
    //    (scan_flags cascade via FK)
    // 3. DELETE resolved quarantine entries older than quarantineRetentionDays
    // 4. DELETE resolved escalations matching deleted decisions
    // 5. DELETE old posture_history entries
    // 6. DELETE old daily_metrics entries
    // 7. Return total deleted count
    throw new Error("TODO: Implement pruneOldEntries()");
  }

  /**
   * Export audit log entries to JSON.
   *
   * FR-AUD-063: JSON export with nested flags.
   *
   * @param fromDate - Start date (ISO 8601).
   * @param toDate - End date (ISO 8601).
   * @returns JSON string of exported entries.
   */
  async exportJSON(fromDate: string, toDate: string): Promise<string> {
    // TODO: Implement JSON export
    // 1. SELECT scan_decisions WHERE timestamp BETWEEN fromDate AND toDate
    // 2. For each decision, SELECT associated scan_flags
    // 3. Build array of decision objects with nested flags
    // 4. Return JSON.stringify with pretty printing
    throw new Error("TODO: Implement exportJSON()");
  }

  /**
   * Export audit log entries to CSV.
   *
   * FR-AUD-064: CSV export (denormalized, one row per flag).
   *
   * @param fromDate - Start date (ISO 8601).
   * @param toDate - End date (ISO 8601).
   * @returns CSV string with header row.
   */
  async exportCSV(fromDate: string, toDate: string): Promise<string> {
    // TODO: Implement CSV export
    // 1. SELECT decisions JOIN flags for date range
    // 2. Build CSV header
    // 3. Build one row per flag (decision fields repeated)
    // 4. Decisions with no flags get one row with empty flag fields
    // 5. Return CSV string
    throw new Error("TODO: Implement exportCSV()");
  }
}


// ═══════════════════════════════════════════════════════════════
// METRICS AGGREGATOR
// ═══════════════════════════════════════════════════════════════

/**
 * Computes aggregated daily metrics from the scan_decisions table
 * and stores them in daily_metrics for efficient dashboard queries.
 *
 * Requirements: FR-AUD-080 through FR-AUD-087
 */
export class MetricsAggregator {
  private readonly config: AuditorDaemonConfig;
  private readonly logger: StructuredLogger;
  private db: Database.Database | null = null;

  constructor(config: AuditorDaemonConfig, logger: StructuredLogger) {
    this.config = config;
    this.logger = logger;
  }

  /** Inject the database connection. */
  setDatabase(db: Database.Database): void {
    this.db = db;
  }

  /**
   * Compute daily metrics for a given date by aggregating scan_decisions.
   *
   * FR-AUD-080: Aggregate scan_decisions per calendar day.
   * FR-AUD-081: All specified metric fields.
   *
   * @param date - Date in YYYY-MM-DD format.
   */
  async computeDaily(date: string): Promise<DailyMetrics> {
    // TODO: Implement daily aggregation
    // 1. SELECT aggregated counts from scan_decisions WHERE date(timestamp) = date
    //    - outbound_scans: COUNT WHERE direction = 'OUTBOUND'
    //    - inbound_inspections: COUNT WHERE direction = 'INBOUND'
    //    - total_flags: SUM(flag_count)
    //    - blocked_count: COUNT WHERE final_outcome = 'blocked'
    //    - approved_by_human: COUNT WHERE final_outcome = 'approved_by_user'
    //    - denied_by_human: COUNT WHERE final_outcome IN ('denied_by_user', 'denied_and_added')
    //    - timeout_count: COUNT WHERE final_outcome = 'denied_by_timeout'
    //    - false_positive_count: COUNT WHERE agent_decision = 'FALSE_POSITIVE'
    //    - clean_pass_count: COUNT WHERE scanner_verdict = 'CLEAN' AND direction = 'OUTBOUND'
    //    - avg_scan_latency_ms: AVG(scanner_duration_ms)
    //    - avg_agent_latency_ms: AVG(agent_duration_ms) WHERE agent_duration_ms IS NOT NULL
    // 2. Compute P95 scan latency
    // 3. Compute inventory metrics (new, verified, expired)
    // 4. INSERT OR REPLACE into daily_metrics
    // 5. Return the computed metrics
    throw new Error("TODO: Implement computeDaily()");
  }

  /**
   * Compute the P95 scan latency for a given date.
   *
   * FR-AUD-083: P95 approximation.
   *
   * @param date - Date in YYYY-MM-DD format.
   * @returns P95 latency in milliseconds.
   */
  computeP95Latency(date: string): number {
    // TODO: Implement P95 calculation
    // 1. SELECT scanner_duration_ms FROM scan_decisions
    //    WHERE date(timestamp) = date AND direction = 'OUTBOUND'
    //    ORDER BY scanner_duration_ms ASC
    // 2. Find the value at index Math.ceil(count * 0.95) - 1
    // 3. Return that value (or 0 if no entries)
    throw new Error("TODO: Implement computeP95Latency()");
  }

  /**
   * Build the DashboardSummary response for IF-010 /api/summary.
   *
   * FR-AUD-087: Combined summary endpoint.
   *
   * @param recentCount - Number of recent decisions to include.
   * @param healthReport - Current system health report.
   * @returns Dashboard summary payload.
   */
  buildDashboardSummary(
    recentCount: number,
    healthReport: SystemHealthReport,
  ): DashboardSummary {
    // TODO: Implement dashboard summary
    // 1. Get today's metrics (or compute if stale)
    // 2. Get recent decisions from v_recent_decisions
    // 3. Get inventory summary from v_inventory_summary
    // 4. Get active escalations from escalations WHERE state = 'pending'
    // 5. Assemble and return DashboardSummary
    throw new Error("TODO: Implement buildDashboardSummary()");
  }

  /**
   * Get inventory summary by classification level.
   *
   * @returns Inventory summary for the dashboard.
   */
  getInventorySummary(): InventorySummary {
    // TODO: Implement
    // SELECT from v_posture_input and v_inventory_summary
    // Also get last_workspace_scan from config_meta
    throw new Error("TODO: Implement getInventorySummary()");
  }
}


// ═══════════════════════════════════════════════════════════════
// DASHBOARD SERVER
// ═══════════════════════════════════════════════════════════════

/**
 * Lightweight HTTP server for dashboard API endpoints.
 * Implements IF-010: Dashboard → Auditor data API.
 * All endpoints are read-only GET, localhost-only.
 *
 * Endpoints:
 *   GET /api/summary    — Combined dashboard payload
 *   GET /api/metrics    — Historical daily metrics
 *   GET /api/decisions  — Paginated decision log
 *   GET /api/inventory  — Filtered inventory items
 *   GET /api/health     — Full system health report
 *   GET /health         — Auditor's own health endpoint (IF-009)
 *
 * Requirements: FR-AUD-086, FR-AUD-087
 */
export class DashboardServer {
  private readonly config: AuditorDaemonConfig;
  private readonly logger: StructuredLogger;
  private server: any = null; // http.Server

  constructor(config: AuditorDaemonConfig, logger: StructuredLogger) {
    this.config = config;
    this.logger = logger;
  }

  /**
   * Start the HTTP server on the configured port (localhost only).
   *
   * FR-AUD-086: Expose HTTP API at localhost:5004.
   */
  async start(
    metricsAggregator: MetricsAggregator,
    healthChecker: HealthChecker,
    getUptimeSeconds: () => number,
  ): Promise<void> {
    // TODO: Implement HTTP server startup
    // 1. Create http.createServer with request handler
    // 2. Bind to 127.0.0.1:config.dashboardPort
    // 3. Route requests to handler functions
    // 4. Log server start
    throw new Error("TODO: Implement start()");
  }

  /**
   * Stop the HTTP server.
   */
  async stop(): Promise<void> {
    // TODO: Implement server shutdown
    // 1. Call server.close()
    // 2. Wait for open connections to drain
    throw new Error("TODO: Implement stop()");
  }

  /**
   * Handle GET /api/summary
   *
   * @returns DashboardSummary JSON response.
   */
  private handleSummary(queryParams: URLSearchParams): DashboardSummary {
    // TODO: Implement
    // 1. Parse recentCount from query params (default 20)
    // 2. Build system health report from HealthChecker
    // 3. Call metricsAggregator.buildDashboardSummary()
    throw new Error("TODO: Implement handleSummary()");
  }

  /**
   * Handle GET /api/metrics
   *
   * @returns Array of DailyMetrics for the requested date range.
   */
  private handleMetrics(queryParams: URLSearchParams): DailyMetrics[] {
    // TODO: Implement
    // 1. Parse from/to dates from query params (default: today)
    // 2. SELECT FROM daily_metrics WHERE date BETWEEN from AND to
    throw new Error("TODO: Implement handleMetrics()");
  }

  /**
   * Handle GET /api/decisions
   *
   * @returns Paginated array of ScanDecisionRecord.
   */
  private handleDecisions(queryParams: URLSearchParams): ScanDecisionRecord[] {
    // TODO: Implement
    // 1. Parse limit, offset, direction, verdict filters
    // 2. SELECT from scan_decisions with filters and pagination
    throw new Error("TODO: Implement handleDecisions()");
  }

  /**
   * Handle GET /api/inventory
   *
   * @returns Filtered array of inventory entries.
   */
  private handleInventory(queryParams: URLSearchParams): InventoryEntry[] {
    // TODO: Implement
    // 1. Parse classification, storageType filters
    // 2. SELECT from inventory WHERE filters AND is_active = 1
    throw new Error("TODO: Implement handleInventory()");
  }

  /**
   * Handle GET /api/health — Full system health report.
   */
  private handleSystemHealth(): SystemHealthReport {
    // TODO: Implement
    // Build complete SystemHealthReport from HealthChecker state
    throw new Error("TODO: Implement handleSystemHealth()");
  }

  /**
   * Handle GET /health — Auditor's own health (IF-009 compliance).
   */
  private handleOwnHealth(getUptimeSeconds: () => number): HealthCheckResponse {
    // TODO: Implement
    // Return HealthCheckResponse for the auditor daemon itself
    // Include: uptime, database accessible, timers running, etc.
    throw new Error("TODO: Implement handleOwnHealth()");
  }
}


// ═══════════════════════════════════════════════════════════════
// STRUCTURED LOGGER
// ═══════════════════════════════════════════════════════════════

/**
 * Structured JSON logger that writes to stdout for systemd journal
 * integration. Each log line is a single JSON object.
 *
 * NFR-AUD-020: Structured JSON log output.
 * NFR-AUD-022: Never log raw sensitive data.
 */
export class StructuredLogger {
  private readonly minLevel: number;
  private readonly component: string;

  private static readonly LEVELS: Record<string, number> = {
    ERROR: 0,
    WARN: 1,
    INFO: 2,
    DEBUG: 3,
  };

  constructor(level: string, component: string) {
    this.minLevel = StructuredLogger.LEVELS[level] ?? 2;
    this.component = component;
  }

  /**
   * Log an event at the specified level.
   *
   * @param level - Log level.
   * @param event - Event type identifier (e.g., "health_check_failed").
   * @param message - Human-readable message.
   * @param context - Additional structured context.
   */
  log(
    level: "ERROR" | "WARN" | "INFO" | "DEBUG",
    event: string,
    message: string,
    context?: Record<string, unknown>,
  ): void {
    if (StructuredLogger.LEVELS[level] > this.minLevel) return;

    const entry: LogEvent = {
      timestamp: new Date().toISOString(),
      level,
      component: this.component,
      event,
      message,
      ...(context ? { context } : {}),
    };

    // Write to stdout as a single JSON line
    process.stdout.write(JSON.stringify(entry) + "\n");
  }

  error(event: string, message: string, context?: Record<string, unknown>): void {
    this.log("ERROR", event, message, context);
  }

  warn(event: string, message: string, context?: Record<string, unknown>): void {
    this.log("WARN", event, message, context);
  }

  info(event: string, message: string, context?: Record<string, unknown>): void {
    this.log("INFO", event, message, context);
  }

  debug(event: string, message: string, context?: Record<string, unknown>): void {
    this.log("DEBUG", event, message, context);
  }
}


// ═══════════════════════════════════════════════════════════════
// SYSTEMD UNIT FILE TEMPLATE
// ═══════════════════════════════════════════════════════════════

/**
 * Systemd unit file for the Auditor Daemon.
 * Install to /etc/systemd/system/watchdog-auditor.service
 *
 * See Section 4 of 07-module-auditor.docx for installation instructions.
 */
export const SYSTEMD_UNIT_FILE = `[Unit]
Description=Security Watchdog Auditor Daemon
Documentation=https://github.com/openclaw/security-watchdog
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=simple
User=openclaw
Group=openclaw
WorkingDirectory=/opt/security-watchdog
ExecStart=/usr/bin/node dist/auditor/index.js
Restart=always
RestartSec=5
WatchdogSec=120

# Resource limits
MemoryMax=512M
MemoryHigh=256M
CPUQuota=80%

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/home/openclaw/.openclaw/security

# Environment
Environment=NODE_ENV=production
Environment=WATCHDOG_LOG_LEVEL=info
EnvironmentFile=-/home/openclaw/.openclaw/security/auditor.env

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=watchdog-auditor

[Install]
WantedBy=multi-user.target
`;


// ═══════════════════════════════════════════════════════════════
// LAUNCHD PLIST TEMPLATE (macOS)
// ═══════════════════════════════════════════════════════════════

/**
 * launchd plist for macOS deployments.
 * Install to ~/Library/LaunchDaemons/com.openclaw.watchdog-auditor.plist
 */
export const LAUNCHD_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.openclaw.watchdog-auditor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/node</string>
    <string>/opt/security-watchdog/dist/auditor/index.js</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>StandardOutPath</key>
  <string>/var/log/watchdog-auditor.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/watchdog-auditor.error.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NODE_ENV</key>
    <string>production</string>
    <key>WATCHDOG_LOG_LEVEL</key>
    <string>info</string>
  </dict>
</dict>
</plist>
`;


// ═══════════════════════════════════════════════════════════════
// ENTRY POINT
// ═══════════════════════════════════════════════════════════════

/**
 * Main entry point for the Auditor Daemon.
 * Loads configuration, creates the daemon, and starts it.
 * Handles SIGTERM/SIGINT for graceful shutdown.
 */
async function main(): Promise<void> {
  // TODO: Implement entry point
  // 1. Load config from ~/.openclaw/security/config.json (auditor section)
  // 2. Override with environment variables (WATCHDOG_AUDITOR_*)
  // 3. Resolve ~ in paths
  // 4. Create AuditorDaemon instance
  // 5. Register signal handlers:
  //    process.on("SIGTERM", () => daemon.stop())
  //    process.on("SIGINT",  () => daemon.stop())
  //    process.on("uncaughtException", (err) => { log error, continue })
  //    process.on("unhandledRejection", (err) => { log error, continue })
  // 6. Start the daemon
  // 7. On clean exit, process.exit(0)

  const config: Partial<AuditorDaemonConfig> = {};
  // TODO: Load from config file and env vars

  const daemon = new AuditorDaemon(config);

  process.on("SIGTERM", async () => {
    await daemon.stop();
    process.exit(0);
  });

  process.on("SIGINT", async () => {
    await daemon.stop();
    process.exit(0);
  });

  await daemon.start();
}

// Run if executed directly
// main().catch(err => { console.error(err); process.exit(1); });

export default AuditorDaemon;
