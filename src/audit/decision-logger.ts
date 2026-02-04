/**
 * Decision Logger - Audit trail for all security decisions
 * 
 * Logs all scan decisions, approvals, rejections, and system events
 * to both SQLite (for querying) and optionally to file (for archival).
 * 
 * Provides:
 * - Structured logging of all security decisions
 * - Query API for audit reports
 * - Export functionality for compliance
 * - Retention management
 */

import { randomUUID } from 'crypto';
import Database from 'better-sqlite3';
import { existsSync, mkdirSync, appendFileSync } from 'fs';
import { dirname } from 'path';
import type { ScanFlag } from '../scanner/pattern-scanner.js';
import type { OutboundResult, InboundResult, PostureLevel } from '../gateway/gateway-hook.js';
import { ClassificationLevel } from '../shared/types.js';

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

/** Decision logger configuration. */
export interface DecisionLoggerConfig {
  /** Path to the SQLite database. */
  databasePath: string;
  /** Optional path for file-based log export. */
  logFilePath?: string;
  /** Retention period in days (default: 90). */
  retentionDays?: number;
  /** Whether to write to file in addition to DB (default: false). */
  fileLoggingEnabled?: boolean;
  /** Batch size for bulk operations (default: 100). */
  batchSize?: number;
}

/** Types of decisions that can be logged. */
export type DecisionType =
  | 'outbound_scan'
  | 'inbound_inspect'
  | 'quarantine_created'
  | 'quarantine_approved'
  | 'quarantine_rejected'
  | 'quarantine_expired'
  | 'posture_changed'
  | 'kill_switch_on'
  | 'kill_switch_off'
  | 'registry_updated'
  | 'system_startup'
  | 'system_shutdown';

/** A logged decision entry. */
export interface DecisionEntry {
  /** Unique decision ID. */
  id: string;
  /** Type of decision. */
  type: DecisionType;
  /** ISO timestamp. */
  timestamp: string;
  /** Request ID (if applicable). */
  requestId?: string;
  /** Session key (if applicable). */
  sessionKey?: string;
  /** Action taken (allow, block, quarantine, etc.). */
  action?: string;
  /** Verdict (clean, flagged, error). */
  verdict?: string;
  /** Destination type. */
  destination?: string;
  /** Destination target. */
  target?: string;
  /** Content hash (never actual content). */
  contentHash?: string;
  /** Content length. */
  contentLength?: number;
  /** Number of flags detected. */
  flagCount?: number;
  /** Highest classification level. */
  highestClassification?: string;
  /** Scan duration in ms. */
  durationMs?: number;
  /** Operator who made the decision (for manual actions). */
  operator?: string;
  /** Reason or notes. */
  reason?: string;
  /** Previous state (for state changes). */
  previousState?: string;
  /** New state (for state changes). */
  newState?: string;
  /** Structured flag details (JSON). */
  flagDetails?: string;
  /** Additional metadata (JSON). */
  metadata?: string;
}

/** Query filters for decision log. */
export interface DecisionQuery {
  /** Filter by decision type. */
  type?: DecisionType;
  /** Filter by types (multiple). */
  types?: DecisionType[];
  /** Filter by action. */
  action?: string;
  /** Filter by verdict. */
  verdict?: string;
  /** Filter by destination. */
  destination?: string;
  /** Filter by classification level. */
  classification?: ClassificationLevel;
  /** Filter by operator. */
  operator?: string;
  /** Start timestamp (inclusive). */
  startTime?: string;
  /** End timestamp (inclusive). */
  endTime?: string;
  /** Filter by session key. */
  sessionKey?: string;
  /** Filter by request ID. */
  requestId?: string;
  /** Maximum results. */
  limit?: number;
  /** Offset for pagination. */
  offset?: number;
  /** Order by field. */
  orderBy?: 'timestamp' | 'type' | 'action';
  /** Order direction. */
  orderDir?: 'asc' | 'desc';
}

/** Aggregated statistics. */
export interface DecisionStats {
  /** Total decisions in period. */
  totalDecisions: number;
  /** Breakdown by type. */
  byType: Record<string, number>;
  /** Breakdown by action. */
  byAction: Record<string, number>;
  /** Breakdown by verdict. */
  byVerdict: Record<string, number>;
  /** Breakdown by classification. */
  byClassification: Record<string, number>;
  /** Average scan duration (ms). */
  avgDurationMs: number;
  /** Time range of data. */
  timeRange: {
    earliest: string;
    latest: string;
  };
}

// ═══════════════════════════════════════════════════════════════
// DECISION LOGGER
// ═══════════════════════════════════════════════════════════════

/**
 * DecisionLogger provides comprehensive audit logging for all
 * security decisions made by the Watchdog system.
 */
export class DecisionLogger {
  private readonly config: Required<DecisionLoggerConfig>;
  private db: Database.Database;
  private initialized = false;
  private pendingWrites: DecisionEntry[] = [];

  constructor(config: DecisionLoggerConfig) {
    this.config = {
      databasePath: config.databasePath,
      logFilePath: config.logFilePath || '',
      retentionDays: config.retentionDays ?? 90,
      fileLoggingEnabled: config.fileLoggingEnabled ?? false,
      batchSize: config.batchSize ?? 100,
    };

    // Ensure directory exists
    const dbDir = dirname(this.config.databasePath);
    if (!existsSync(dbDir)) {
      mkdirSync(dbDir, { recursive: true });
    }

    this.db = new Database(this.config.databasePath);
    this.initSchema();
    this.initialized = true;

    // Log startup
    this.logDecision({
      type: 'system_startup',
      reason: 'Decision logger initialized',
    });
  }

  /**
   * Log an outbound scan decision.
   */
  logOutboundScan(result: OutboundResult, contentHash: string, contentLength: number, sessionKey?: string): void {
    const entry: Partial<DecisionEntry> & { type: DecisionType } = {
      type: 'outbound_scan',
      requestId: result.requestId,
      action: result.action,
      verdict: result.verdict,
      contentHash,
      contentLength,
      flagCount: result.flags.length,
      durationMs: result.durationMs,
    };
    if (sessionKey) entry.sessionKey = sessionKey;
    if (result.highestClassification) entry.highestClassification = result.highestClassification;
    if (result.flags.length > 0) entry.flagDetails = JSON.stringify(this.sanitizeFlags(result.flags));
    this.logDecision(entry);
  }

  /**
   * Log an inbound inspection.
   */
  logInboundInspect(result: InboundResult, _contentHash: string, _contentLength: number, sessionKey?: string): void {
    const entry: Partial<DecisionEntry> & { type: DecisionType } = {
      type: 'inbound_inspect',
      requestId: result.requestId,
      action: result.sensitiveDataDetected ? 'detected' : 'clean',
      flagCount: result.flags.length,
      durationMs: result.durationMs,
    };
    if (sessionKey) entry.sessionKey = sessionKey;
    if (result.highestClassification) entry.highestClassification = result.highestClassification;
    if (result.postureRecommendation) entry.metadata = JSON.stringify({ postureRecommendation: result.postureRecommendation });
    this.logDecision(entry);
  }

  /**
   * Log quarantine creation.
   */
  logQuarantineCreated(
    quarantineId: string,
    requestId: string,
    destination: string,
    target: string | undefined,
    highestClassification: ClassificationLevel,
    flagCount: number
  ): void {
    const entry: Partial<DecisionEntry> & { type: DecisionType } = {
      type: 'quarantine_created',
      requestId,
      action: 'quarantine',
      destination,
      highestClassification,
      flagCount,
      metadata: JSON.stringify({ quarantineId }),
    };
    if (target) entry.target = target;
    this.logDecision(entry);
  }

  /**
   * Log quarantine approval.
   */
  logQuarantineApproved(quarantineId: string, requestId: string, operator: string, reason?: string): void {
    const entry: Partial<DecisionEntry> & { type: DecisionType } = {
      type: 'quarantine_approved',
      requestId,
      action: 'approved',
      operator,
      metadata: JSON.stringify({ quarantineId }),
    };
    if (reason) entry.reason = reason;
    this.logDecision(entry);
  }

  /**
   * Log quarantine rejection.
   */
  logQuarantineRejected(quarantineId: string, requestId: string, operator: string, reason?: string): void {
    const entry: Partial<DecisionEntry> & { type: DecisionType } = {
      type: 'quarantine_rejected',
      requestId,
      action: 'rejected',
      operator,
      metadata: JSON.stringify({ quarantineId }),
    };
    if (reason) entry.reason = reason;
    this.logDecision(entry);
  }

  /**
   * Log posture change.
   */
  logPostureChanged(previousLevel: PostureLevel, newLevel: PostureLevel, operator?: string, reason?: string): void {
    const entry: Partial<DecisionEntry> & { type: DecisionType } = {
      type: 'posture_changed',
      action: 'changed',
      previousState: previousLevel,
      newState: newLevel,
    };
    if (operator) entry.operator = operator;
    if (reason) entry.reason = reason;
    this.logDecision(entry);
  }

  /**
   * Log kill switch activation.
   */
  logKillSwitchOn(operator: string, reason: string): void {
    this.logDecision({
      type: 'kill_switch_on',
      action: 'disabled',
      operator,
      reason,
    });
  }

  /**
   * Log kill switch deactivation.
   */
  logKillSwitchOff(operator: string): void {
    this.logDecision({
      type: 'kill_switch_off',
      action: 'enabled',
      operator,
    });
  }

  /**
   * Log registry update.
   */
  logRegistryUpdated(changeType: string, details: Record<string, unknown>): void {
    this.logDecision({
      type: 'registry_updated',
      action: changeType,
      metadata: JSON.stringify(details),
    });
  }

  /**
   * Log system shutdown.
   */
  logShutdown(): void {
    this.logDecision({
      type: 'system_shutdown',
      reason: 'Decision logger shutting down',
    });
    this.flush();
  }

  /**
   * Query decision log with filters.
   */
  query(filters: DecisionQuery = {}): DecisionEntry[] {
    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (filters.type) {
      conditions.push('type = ?');
      params.push(filters.type);
    }

    if (filters.types && filters.types.length > 0) {
      conditions.push(`type IN (${filters.types.map(() => '?').join(', ')})`);
      params.push(...filters.types);
    }

    if (filters.action) {
      conditions.push('action = ?');
      params.push(filters.action);
    }

    if (filters.verdict) {
      conditions.push('verdict = ?');
      params.push(filters.verdict);
    }

    if (filters.destination) {
      conditions.push('destination = ?');
      params.push(filters.destination);
    }

    if (filters.classification) {
      conditions.push('highest_classification = ?');
      params.push(filters.classification);
    }

    if (filters.operator) {
      conditions.push('operator = ?');
      params.push(filters.operator);
    }

    if (filters.startTime) {
      conditions.push('timestamp >= ?');
      params.push(filters.startTime);
    }

    if (filters.endTime) {
      conditions.push('timestamp <= ?');
      params.push(filters.endTime);
    }

    if (filters.sessionKey) {
      conditions.push('session_key = ?');
      params.push(filters.sessionKey);
    }

    if (filters.requestId) {
      conditions.push('request_id = ?');
      params.push(filters.requestId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const orderBy = filters.orderBy || 'timestamp';
    const orderDir = filters.orderDir || 'desc';
    const limit = filters.limit || 100;
    const offset = filters.offset || 0;

    const sql = `
      SELECT * FROM decision_log
      ${whereClause}
      ORDER BY ${orderBy} ${orderDir}
      LIMIT ? OFFSET ?
    `;

    const rows = this.db.prepare(sql).all(...params, limit, offset) as Record<string, unknown>[];
    return rows.map(this.rowToEntry);
  }

  /**
   * Get aggregated statistics for a time period.
   */
  getStats(startTime?: string, endTime?: string): DecisionStats {
    const conditions: string[] = [];
    const params: string[] = [];

    if (startTime) {
      conditions.push('timestamp >= ?');
      params.push(startTime);
    }
    if (endTime) {
      conditions.push('timestamp <= ?');
      params.push(endTime);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Total count
    const countRow = this.db.prepare(`SELECT COUNT(*) as count FROM decision_log ${whereClause}`).get(...params) as { count: number };

    // Build additional conditions
    const andWhere = whereClause ? `${whereClause} AND` : 'WHERE';

    // By type
    const byTypeRows = this.db.prepare(`
      SELECT type, COUNT(*) as count FROM decision_log ${whereClause} GROUP BY type
    `).all(...params) as { type: string; count: number }[];

    // By action
    const byActionRows = this.db.prepare(`
      SELECT action, COUNT(*) as count FROM decision_log ${andWhere} action IS NOT NULL GROUP BY action
    `).all(...params) as { action: string; count: number }[];

    // By verdict
    const byVerdictRows = this.db.prepare(`
      SELECT verdict, COUNT(*) as count FROM decision_log ${andWhere} verdict IS NOT NULL GROUP BY verdict
    `).all(...params) as { verdict: string; count: number }[];

    // By classification
    const byClassRows = this.db.prepare(`
      SELECT highest_classification, COUNT(*) as count FROM decision_log ${andWhere} highest_classification IS NOT NULL GROUP BY highest_classification
    `).all(...params) as { highest_classification: string; count: number }[];

    // Avg duration
    const avgRow = this.db.prepare(`
      SELECT AVG(duration_ms) as avg FROM decision_log ${andWhere} duration_ms IS NOT NULL
    `).get(...params) as { avg: number | null };

    // Time range
    const rangeRow = this.db.prepare(`
      SELECT MIN(timestamp) as earliest, MAX(timestamp) as latest FROM decision_log ${whereClause}
    `).get(...params) as { earliest: string | null; latest: string | null };

    return {
      totalDecisions: countRow.count,
      byType: Object.fromEntries(byTypeRows.map(r => [r.type, r.count])),
      byAction: Object.fromEntries(byActionRows.map(r => [r.action, r.count])),
      byVerdict: Object.fromEntries(byVerdictRows.map(r => [r.verdict, r.count])),
      byClassification: Object.fromEntries(byClassRows.map(r => [r.highest_classification, r.count])),
      avgDurationMs: avgRow.avg ?? 0,
      timeRange: {
        earliest: rangeRow.earliest || '',
        latest: rangeRow.latest || '',
      },
    };
  }

  /**
   * Export decisions to JSONL file for archival/compliance.
   */
  exportToFile(filePath: string, filters: DecisionQuery = {}): number {
    const entries = this.query({ ...filters, limit: 1000000 }); // Large limit for export
    
    const dir = dirname(filePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    for (const entry of entries) {
      appendFileSync(filePath, JSON.stringify(entry) + '\n');
    }

    return entries.length;
  }

  /**
   * Purge old entries beyond retention period.
   */
  purgeOldEntries(): number {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);
    const cutoffTimestamp = cutoffDate.toISOString();

    const result = this.db.prepare(`
      DELETE FROM decision_log WHERE timestamp < ?
    `).run(cutoffTimestamp);

    return result.changes;
  }

  /**
   * Flush any pending writes.
   */
  flush(): void {
    if (this.pendingWrites.length === 0) return;

    const stmt = this.db.prepare(`
      INSERT INTO decision_log (
        id, type, timestamp, request_id, session_key, action, verdict,
        destination, target, content_hash, content_length, flag_count,
        highest_classification, duration_ms, operator, reason,
        previous_state, new_state, flag_details, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertMany = this.db.transaction((entries: DecisionEntry[]) => {
      for (const entry of entries) {
        stmt.run(
          entry.id,
          entry.type,
          entry.timestamp,
          entry.requestId || null,
          entry.sessionKey || null,
          entry.action || null,
          entry.verdict || null,
          entry.destination || null,
          entry.target || null,
          entry.contentHash || null,
          entry.contentLength || null,
          entry.flagCount || null,
          entry.highestClassification || null,
          entry.durationMs || null,
          entry.operator || null,
          entry.reason || null,
          entry.previousState || null,
          entry.newState || null,
          entry.flagDetails || null,
          entry.metadata || null
        );
      }
    });

    insertMany(this.pendingWrites);
    this.pendingWrites = [];
  }

  /**
   * Get count of logged decisions.
   */
  getCount(): number {
    const row = this.db.prepare('SELECT COUNT(*) as count FROM decision_log').get() as { count: number };
    return row.count;
  }

  /**
   * Close the logger.
   */
  close(): void {
    this.logShutdown();
    this.db.close();
    this.initialized = false;
  }

  // ════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ════════════════════════════════════════════════════════════

  /** Initialize the database schema. */
  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS decision_log (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        request_id TEXT,
        session_key TEXT,
        action TEXT,
        verdict TEXT,
        destination TEXT,
        target TEXT,
        content_hash TEXT,
        content_length INTEGER,
        flag_count INTEGER,
        highest_classification TEXT,
        duration_ms REAL,
        operator TEXT,
        reason TEXT,
        previous_state TEXT,
        new_state TEXT,
        flag_details TEXT,
        metadata TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_decision_log_timestamp ON decision_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_decision_log_type ON decision_log(type);
      CREATE INDEX IF NOT EXISTS idx_decision_log_action ON decision_log(action);
      CREATE INDEX IF NOT EXISTS idx_decision_log_session ON decision_log(session_key);
      CREATE INDEX IF NOT EXISTS idx_decision_log_request ON decision_log(request_id);
    `);
  }

  /** Log a decision (batched). */
  private logDecision(partial: Partial<DecisionEntry> & { type: DecisionType }): void {
    const entry: DecisionEntry = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      ...partial,
    };

    this.pendingWrites.push(entry);

    // Flush if batch size reached
    if (this.pendingWrites.length >= this.config.batchSize) {
      this.flush();
    }

    // Also write to file if enabled
    if (this.config.fileLoggingEnabled && this.config.logFilePath) {
      const dir = dirname(this.config.logFilePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      appendFileSync(this.config.logFilePath, JSON.stringify(entry) + '\n');
    }
  }

  /** Sanitize flags for logging (remove sensitive matched text). */
  private sanitizeFlags(flags: ScanFlag[]): Partial<ScanFlag>[] {
    return flags.map(f => ({
      id: f.id,
      patternType: f.patternType,
      classification: f.classification,
      confidence: f.confidence,
      source: f.source,
      startIndex: f.startIndex,
      endIndex: f.endIndex,
      // Omit: matchedText, context (may contain sensitive data)
    }));
  }

  /** Convert database row to DecisionEntry. */
  private rowToEntry(row: Record<string, unknown>): DecisionEntry {
    const entry: DecisionEntry = {
      id: row['id'] as string,
      type: row['type'] as DecisionType,
      timestamp: row['timestamp'] as string,
    };
    
    if (row['request_id']) entry.requestId = row['request_id'] as string;
    if (row['session_key']) entry.sessionKey = row['session_key'] as string;
    if (row['action']) entry.action = row['action'] as string;
    if (row['verdict']) entry.verdict = row['verdict'] as string;
    if (row['destination']) entry.destination = row['destination'] as string;
    if (row['target']) entry.target = row['target'] as string;
    if (row['content_hash']) entry.contentHash = row['content_hash'] as string;
    if (row['content_length'] != null) entry.contentLength = row['content_length'] as number;
    if (row['flag_count'] != null) entry.flagCount = row['flag_count'] as number;
    if (row['highest_classification']) entry.highestClassification = row['highest_classification'] as string;
    if (row['duration_ms'] != null) entry.durationMs = row['duration_ms'] as number;
    if (row['operator']) entry.operator = row['operator'] as string;
    if (row['reason']) entry.reason = row['reason'] as string;
    if (row['previous_state']) entry.previousState = row['previous_state'] as string;
    if (row['new_state']) entry.newState = row['new_state'] as string;
    if (row['flag_details']) entry.flagDetails = row['flag_details'] as string;
    if (row['metadata']) entry.metadata = row['metadata'] as string;
    
    return entry;
  }

  /** Check if logger is initialized. */
  isInitialized(): boolean {
    return this.initialized;
  }
}

export default DecisionLogger;
