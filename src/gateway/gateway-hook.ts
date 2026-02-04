/**
 * Gateway Hook Integration - Bridges Security Watchdog with OpenClaw
 * 
 * This module provides:
 * 1. Outbound scanning of tool calls before execution
 * 2. Inbound inspection of received messages
 * 3. Approval token generation for clean content
 * 4. Quarantine management for flagged content
 * 
 * Usage:
 *   const hook = new GatewayHook({ databasePath: '...' });
 *   hook.initialize();
 *   
 *   // Scan outbound content
 *   const result = hook.scanOutbound({ content: 'My SSN is 123-45-6789', destination: 'email' });
 *   if (result.action === 'quarantine') {
 *     // Content flagged - requires approval
 *   }
 */

import { randomUUID, createHmac } from 'crypto';
import { PatternScanner, type ScanResult, type ScanFlag } from '../scanner/pattern-scanner.js';
import { RegistryManager } from '../registry/registry-manager.js';
import { ClassificationLevel } from '../shared/types.js';

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

/** Gateway hook configuration. */
export interface GatewayHookConfig {
  /** Path to the SQLite database. */
  databasePath: string;
  /** HMAC key for signing approval tokens. */
  hmacKey?: string;
  /** Whether outbound scanning is enabled. Default: true */
  outboundEnabled?: boolean;
  /** Whether inbound inspection is enabled. Default: true */
  inboundEnabled?: boolean;
  /** Current posture level. Default: 'standard' */
  postureLevel?: PostureLevel;
  /** Scanner configuration overrides. */
  scannerConfig?: {
    fuseThreshold?: number;
    fuseDistance?: number;
    minMatchLength?: number;
  };
}

/** Security posture levels. */
export type PostureLevel = 'permissive' | 'standard' | 'strict' | 'lockdown';

/** Destination types for outbound content. */
export type DestinationType = 
  | 'email'
  | 'chat'
  | 'api'
  | 'file'
  | 'clipboard'
  | 'browser'
  | 'unknown';

/** Outbound scan request. */
export interface OutboundRequest {
  /** Unique request ID for deduplication. */
  requestId?: string;
  /** Content to scan. */
  content: string;
  /** Destination type. */
  destination: DestinationType;
  /** Destination target (email address, URL, etc.). */
  target?: string;
  /** Tool name that generated this content. */
  toolName?: string;
  /** Additional metadata. */
  metadata?: Record<string, unknown>;
}

/** Outbound scan result. */
export interface OutboundResult {
  /** Unique result ID. */
  resultId: string;
  /** Request ID (echoed back). */
  requestId: string;
  /** Action to take. */
  action: 'allow' | 'quarantine' | 'block';
  /** Approval token if allowed. */
  approvalToken?: string;
  /** Quarantine ID if quarantined. */
  quarantineId?: string;
  /** Scan verdict. */
  verdict: 'clean' | 'flagged' | 'error';
  /** Detected flags. */
  flags: ScanFlag[];
  /** Highest classification level found. */
  highestClassification: ClassificationLevel | null;
  /** Scan timing in milliseconds. */
  durationMs: number;
  /** Error message if verdict is 'error'. */
  error?: string;
  /** Timestamp. */
  timestamp: string;
}

/** Inbound inspection request. */
export interface InboundRequest {
  /** Unique request ID. */
  requestId?: string;
  /** Content to inspect. */
  content: string;
  /** Source type (channel name). */
  source: string;
  /** Sender identifier. */
  senderId?: string;
  /** Additional metadata. */
  metadata?: Record<string, unknown>;
}

/** Inbound inspection result. */
export interface InboundResult {
  /** Unique result ID. */
  resultId: string;
  /** Request ID (echoed back). */
  requestId: string;
  /** Whether sensitive data was detected. */
  sensitiveDataDetected: boolean;
  /** Detected flags (informational). */
  flags: ScanFlag[];
  /** Highest classification level found. */
  highestClassification: ClassificationLevel | null;
  /** Recommended posture adjustment. */
  postureRecommendation: PostureLevel | null;
  /** Scan timing in milliseconds. */
  durationMs: number;
  /** Timestamp. */
  timestamp: string;
}

/** Quarantine entry. */
export interface QuarantineEntry {
  /** Quarantine ID. */
  id: string;
  /** Original request ID. */
  requestId: string;
  /** Quarantined content (redacted for storage). */
  contentHash: string;
  /** Content length. */
  contentLength: number;
  /** Destination info. */
  destination: DestinationType;
  target?: string;
  /** Flags that triggered quarantine. */
  flags: ScanFlag[];
  /** Highest classification. */
  highestClassification: ClassificationLevel;
  /** Creation timestamp. */
  createdAt: string;
  /** Status. */
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  /** Resolution timestamp. */
  resolvedAt?: string;
  /** Who resolved it. */
  resolvedBy?: string;
}

// ═══════════════════════════════════════════════════════════════
// GATEWAY HOOK
// ═══════════════════════════════════════════════════════════════

/**
 * GatewayHook integrates the Security Watchdog with OpenClaw.
 * It provides outbound scanning, inbound inspection, and approval management.
 */
export class GatewayHook {
  private readonly config: Required<GatewayHookConfig>;
  private scanner: PatternScanner;
  private _registry: RegistryManager; // Reserved for future use
  private quarantine: Map<string, QuarantineEntry> = new Map();
  private initialized = false;
  
  // Metrics
  private scanCount = 0;
  private blockCount = 0;
  private quarantineCount = 0;
  private errorCount = 0;
  private startedAt = 0;

  constructor(config: GatewayHookConfig) {
    this.config = {
      databasePath: config.databasePath,
      hmacKey: config.hmacKey || randomUUID(),
      outboundEnabled: config.outboundEnabled ?? true,
      inboundEnabled: config.inboundEnabled ?? true,
      postureLevel: config.postureLevel ?? 'standard',
      scannerConfig: config.scannerConfig ?? {},
    };
    
    this.scanner = new PatternScanner({
      databasePath: this.config.databasePath,
      ...this.config.scannerConfig,
    });
    
    this._registry = new RegistryManager(this.config.databasePath);
  }

  /**
   * Initialize the gateway hook.
   * Must be called before scanning.
   */
  initialize(): void {
    this.scanner.initialize();
    this.startedAt = Date.now();
    this.initialized = true;
  }

  /**
   * Scan outbound content before it's sent.
   * Returns allow, quarantine, or block based on content and posture.
   */
  scanOutbound(request: OutboundRequest): OutboundResult {
    const requestId = request.requestId || randomUUID();
    const resultId = randomUUID();
    const startTime = performance.now();

    // If scanning is disabled, allow everything
    if (!this.config.outboundEnabled) {
      return this.createAllowResult(resultId, requestId, startTime);
    }

    if (!this.initialized) {
      this.errorCount++;
      return {
        resultId,
        requestId,
        action: 'quarantine', // Fail-closed
        quarantineId: `err-${randomUUID().slice(0, 8)}`,
        verdict: 'error',
        flags: [],
        highestClassification: null,
        durationMs: performance.now() - startTime,
        error: 'Gateway hook not initialized',
        timestamp: new Date().toISOString(),
      };
    }

    this.scanCount++;

    try {
      // Run the scanner
      const scanResult = this.scanner.scan(request.content);
      
      if (scanResult.verdict === 'error') {
        this.errorCount++;
        const errorResult: OutboundResult = {
          resultId,
          requestId,
          action: 'quarantine', // Fail-closed
          quarantineId: `err-${randomUUID().slice(0, 8)}`,
          verdict: 'error',
          flags: [],
          highestClassification: null,
          durationMs: performance.now() - startTime,
          timestamp: new Date().toISOString(),
        };
        if (scanResult.error) {
          errorResult.error = scanResult.error;
        }
        return errorResult;
      }

      // Determine action based on flags and posture
      const action = this.determineAction(scanResult, request.destination);
      
      if (action === 'allow') {
        const token = this.generateApprovalToken(requestId, scanResult);
        return {
          resultId,
          requestId,
          action: 'allow',
          approvalToken: token,
          verdict: 'clean',
          flags: scanResult.flags,
          highestClassification: scanResult.highestClassification,
          durationMs: performance.now() - startTime,
          timestamp: new Date().toISOString(),
        };
      } else if (action === 'block') {
        this.blockCount++;
        return {
          resultId,
          requestId,
          action: 'block',
          verdict: 'flagged',
          flags: scanResult.flags,
          highestClassification: scanResult.highestClassification,
          durationMs: performance.now() - startTime,
          timestamp: new Date().toISOString(),
        };
      } else {
        // Quarantine
        const quarantineId = this.createQuarantine(requestId, request, scanResult);
        this.quarantineCount++;
        return {
          resultId,
          requestId,
          action: 'quarantine',
          quarantineId,
          verdict: 'flagged',
          flags: scanResult.flags,
          highestClassification: scanResult.highestClassification,
          durationMs: performance.now() - startTime,
          timestamp: new Date().toISOString(),
        };
      }
    } catch (error) {
      this.errorCount++;
      return {
        resultId,
        requestId,
        action: 'quarantine', // Fail-closed
        quarantineId: `err-${randomUUID().slice(0, 8)}`,
        verdict: 'error',
        flags: [],
        highestClassification: null,
        durationMs: performance.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Inspect inbound content for sensitive data.
   * Non-blocking - used for awareness and posture adjustment.
   */
  inspectInbound(request: InboundRequest): InboundResult {
    const requestId = request.requestId || randomUUID();
    const resultId = randomUUID();
    const startTime = performance.now();

    if (!this.config.inboundEnabled || !this.initialized) {
      return {
        resultId,
        requestId,
        sensitiveDataDetected: false,
        flags: [],
        highestClassification: null,
        postureRecommendation: null,
        durationMs: performance.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    }

    try {
      const scanResult = this.scanner.scan(request.content);
      
      // Recommend posture increase if sensitive data detected
      let postureRecommendation: PostureLevel | null = null;
      if (scanResult.highestClassification === ClassificationLevel.NEVER_SHARE) {
        postureRecommendation = 'strict';
      } else if (scanResult.highestClassification === ClassificationLevel.ASK_FIRST) {
        postureRecommendation = 'standard';
      }

      return {
        resultId,
        requestId,
        sensitiveDataDetected: scanResult.flagCount > 0,
        flags: scanResult.flags,
        highestClassification: scanResult.highestClassification,
        postureRecommendation,
        durationMs: performance.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      return {
        resultId,
        requestId,
        sensitiveDataDetected: false,
        flags: [],
        highestClassification: null,
        postureRecommendation: null,
        durationMs: performance.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Get a quarantined entry by ID.
   */
  getQuarantine(quarantineId: string): QuarantineEntry | undefined {
    return this.quarantine.get(quarantineId);
  }

  /**
   * Approve a quarantined request (allows it to proceed).
   * Returns an approval token.
   */
  approveQuarantine(quarantineId: string, approver: string): string | null {
    const entry = this.quarantine.get(quarantineId);
    if (!entry || entry.status !== 'pending') return null;

    entry.status = 'approved';
    entry.resolvedAt = new Date().toISOString();
    entry.resolvedBy = approver;

    return this.generateApprovalToken(entry.requestId, {
      flags: entry.flags,
      highestClassification: entry.highestClassification,
    } as ScanResult);
  }

  /**
   * Reject a quarantined request.
   */
  rejectQuarantine(quarantineId: string, rejector: string): boolean {
    const entry = this.quarantine.get(quarantineId);
    if (!entry || entry.status !== 'pending') return false;

    entry.status = 'rejected';
    entry.resolvedAt = new Date().toISOString();
    entry.resolvedBy = rejector;
    return true;
  }

  /**
   * List pending quarantine entries.
   */
  listPendingQuarantines(): QuarantineEntry[] {
    return Array.from(this.quarantine.values())
      .filter(e => e.status === 'pending');
  }

  /**
   * Set the current posture level.
   */
  setPosture(level: PostureLevel): void {
    this.config.postureLevel = level;
  }

  /**
   * Get current posture level.
   */
  getPosture(): PostureLevel {
    return this.config.postureLevel;
  }

  /**
   * Get health/metrics.
   */
  getHealth(): {
    initialized: boolean;
    outboundEnabled: boolean;
    inboundEnabled: boolean;
    postureLevel: PostureLevel;
    metrics: {
      scansTotal: number;
      blocksTotal: number;
      quarantinesTotal: number;
      quarantinesPending: number;
      errorsTotal: number;
      uptimeMs: number;
    };
  } {
    return {
      initialized: this.initialized,
      outboundEnabled: this.config.outboundEnabled,
      inboundEnabled: this.config.inboundEnabled,
      postureLevel: this.config.postureLevel,
      metrics: {
        scansTotal: this.scanCount,
        blocksTotal: this.blockCount,
        quarantinesTotal: this.quarantineCount,
        quarantinesPending: this.listPendingQuarantines().length,
        errorsTotal: this.errorCount,
        uptimeMs: this.startedAt > 0 ? Date.now() - this.startedAt : 0,
      },
    };
  }

  /**
   * Reload patterns and entries from the registry.
   */
  reload(): void {
    this.scanner.reload();
  }

  /**
   * Get the underlying registry manager for direct access.
   */
  getRegistry(): RegistryManager {
    return this._registry;
  }

  // ════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ════════════════════════════════════════════════════════════

  /** Determine action based on scan result, destination, and posture. */
  private determineAction(
    scanResult: ScanResult,
    destination: DestinationType
  ): 'allow' | 'quarantine' | 'block' {
    // No flags = allow
    if (scanResult.flagCount === 0) {
      return 'allow';
    }

    const classification = scanResult.highestClassification;
    const posture = this.config.postureLevel;

    // Lockdown mode blocks everything flagged
    if (posture === 'lockdown') {
      return 'block';
    }

    // NEVER_SHARE classification handling
    if (classification === ClassificationLevel.NEVER_SHARE) {
      if (posture === 'strict') {
        return 'block';
      }
      return 'quarantine';
    }

    // ASK_FIRST classification handling
    if (classification === ClassificationLevel.ASK_FIRST) {
      if (posture === 'strict') {
        return 'quarantine';
      }
      if (posture === 'permissive') {
        return 'allow';
      }
      return 'quarantine';
    }

    // INTERNAL_ONLY classification handling
    if (classification === ClassificationLevel.INTERNAL_ONLY) {
      // Allow internal destinations
      if (destination === 'file' || destination === 'clipboard') {
        return 'allow';
      }
      if (posture === 'permissive') {
        return 'allow';
      }
      return 'quarantine';
    }

    // PUBLIC - always allow
    return 'allow';
  }

  /** Generate HMAC-signed approval token. */
  private generateApprovalToken(requestId: string, scanResult: ScanResult | { flags: ScanFlag[]; highestClassification: ClassificationLevel | null }): string {
    const payload = {
      requestId,
      timestamp: Date.now(),
      classification: scanResult.highestClassification,
    };
    
    const data = JSON.stringify(payload);
    const signature = createHmac('sha256', this.config.hmacKey)
      .update(data)
      .digest('hex')
      .slice(0, 16);
    
    return Buffer.from(`${data}|${signature}`).toString('base64');
  }

  /** Create a quarantine entry. */
  private createQuarantine(
    requestId: string,
    request: OutboundRequest,
    scanResult: ScanResult
  ): string {
    const id = `quar-${randomUUID().slice(0, 8)}`;
    
    // Hash content for storage (don't store actual content)
    const contentHash = createHmac('sha256', this.config.hmacKey)
      .update(request.content)
      .digest('hex');

    const entry: QuarantineEntry = {
      id,
      requestId,
      contentHash,
      contentLength: request.content.length,
      destination: request.destination,
      flags: scanResult.flags,
      highestClassification: scanResult.highestClassification!,
      createdAt: new Date().toISOString(),
      status: 'pending',
    };
    if (request.target) {
      entry.target = request.target;
    }

    this.quarantine.set(id, entry);
    return id;
  }

  /** Create an allow result (for disabled scanning). */
  private createAllowResult(resultId: string, requestId: string, startTime: number): OutboundResult {
    return {
      resultId,
      requestId,
      action: 'allow',
      approvalToken: this.generateApprovalToken(requestId, { flags: [], highestClassification: null }),
      verdict: 'clean',
      flags: [],
      highestClassification: null,
      durationMs: performance.now() - startTime,
      timestamp: new Date().toISOString(),
    };
  }
}

export default GatewayHook;
