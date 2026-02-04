/**
 * Security Watchdog — Gateway Hook Integration Module
 *
 * Document ID:  SWDOG-MOD-014
 * Version:      1.0 DRAFT
 * Generated:    February 2026
 *
 * This module is the critical integration point between the Security
 * Watchdog and the OpenClaw framework. It registers as an OpenClaw hook,
 * intercepts outbound tool calls and inbound messages, and delegates
 * scanning to the Pattern Scanner (Layer 1).
 *
 * ────────────────────────────────────────────────────────────────
 * PACKAGING:
 *   This file deploys as handler.ts within the OpenClaw hook directory:
 *
 *     ~/.openclaw/hooks/security-watchdog/
 *     ├── HOOK.md            # Frontmatter metadata + description
 *     ├── handler.ts         # THIS FILE (default export)
 *     ├── package.json       # Dependencies + openclaw.hooks entries
 *     └── node_modules/      # Installed dependencies
 *
 * HOOK.md FRONTMATTER:
 *   ---
 *   name: security-watchdog
 *   description: "Security Watchdog — intercepts all agent communications
 *     and enforces data classification policies through multi-layer scanning"
 *   homepage: https://github.com/openclaw/security-watchdog
 *   metadata:
 *     {
 *       "openclaw": {
 *         "emoji": "🛡️",
 *         "events": ["tool:call", "tool:exec", "message:inbound"],
 *         "always": true,
 *         "requires": {
 *           "bins": ["ollama"],
 *           "config": ["security.enabled"]
 *         },
 *         "install": [
 *           {
 *             "id": "npm",
 *             "kind": "npm",
 *             "package": "@openclaw/security-watchdog",
 *             "label": "Install via npm"
 *           }
 *         ]
 *       }
 *     }
 *   ---
 *
 * ────────────────────────────────────────────────────────────────
 * DEPENDENCIES:
 *   Runtime:   crypto (built-in), better-sqlite3
 *   Internal:  @watchdog/types, @watchdog/constants, @watchdog/errors
 *   Peer:      @openclaw/core (provides hook registration API)
 * ────────────────────────────────────────────────────────────────
 *
 * CRITICAL DESIGN NOTE — THE GATING MECHANISM:
 *
 *   The OpenClaw hook system is fire-and-forget: triggerInternalHook()
 *   does not inspect handler return values. This means we CANNOT block
 *   a tool call by returning { action: "deny" } from the hook handler.
 *
 *   The watchdog resolves this through one of four strategies (in
 *   priority order, as determined by the source code review):
 *
 *   1. ChannelSecurityAdapter — If this interface supports a pre-send
 *      gating check, the watchdog registers as a security adapter.
 *      This is the cleanest approach (zero upstream changes).
 *
 *   2. exec-approvals — If the approval schema supports custom approval
 *      providers, the watchdog registers as one. Tool calls require
 *      watchdog approval before execution.
 *
 *   3. Gating Hook PR — Propose a "gating hook" type to OpenClaw where
 *      the return value (allow/deny) controls execution. Clean
 *      architectural addition benefiting the entire ecosystem.
 *
 *   4. WebSocket Middleware — As a last resort, intercept traffic at
 *      the transport layer between agent and gateway. Works without
 *      upstream changes but is architecturally less clean.
 *
 *   This stub implements Strategy 3 (gating hook) as the primary path,
 *   with adapter patterns for Strategies 1 and 2. The actual strategy
 *   used is determined at runtime based on OpenClaw capabilities.
 *
 * ────────────────────────────────────────────────────────────────
 */

import { createHmac, randomUUID, createHash, timingSafeEqual } from "crypto";
import { EventEmitter } from "events";

// ── Import shared types from @watchdog/types ──────────────────
import type {
  OutboundScanRequest,
  OutboundScanResult,
  InboundInspectionRequest,
  InboundInspectionResult,
  ScanVerdict,
  DestinationInfo,
  DestinationType,
  PostureLevel,
  HealthCheckResponse,
  HealthStatus,
  ScanDirection,
} from "@watchdog/types";

import {
  COMPONENT_IDS,
  LIMITS,
  DEFAULTS,
  PATHS,
  HMAC_ALGORITHM,
  APPROVAL_TOKEN_PREFIX,
  APPROVAL_TOKEN_TTL_MS,
  LOG_EVENTS,
  VERSION,
} from "@watchdog/constants";

import { WatchdogError, ScannerError, ConfigurationError } from "@watchdog/errors";


// ═══════════════════════════════════════════════════════════════
// OPENCLAW TYPE DECLARATIONS
// ═══════════════════════════════════════════════════════════════
// These types represent the OpenClaw framework API surface as
// discovered from source code review. They will be replaced by
// actual imports from @openclaw/core once the peer dependency
// is confirmed.

/**
 * OpenClaw internal hook event structure.
 * Discovered from internal-hooks_test.ts: createInternalHookEvent()
 * creates events with type, action, sessionKey, context, timestamp.
 */
interface OpenClawHookEvent {
  /** Event type category (e.g., "tool", "message", "command", "agent"). */
  type: string;
  /** Specific action within the type (e.g., "call", "exec", "inbound"). */
  action: string;
  /** Session key identifying the originating session. */
  sessionKey: string;
  /** Arbitrary context data attached to the event. */
  context: Record<string, unknown>;
  /** When the event was created. */
  timestamp: Date;
}

/**
 * OpenClaw hook handler function signature.
 * Discovered from internal-hooks.ts: handlers are async functions
 * that receive the hook event.
 */
type OpenClawHookHandler = (event: OpenClawHookEvent) => Promise<void>;

/**
 * Extended gating hook handler that returns allow/deny.
 * This is the PROPOSED extension for Strategy 3. If OpenClaw adopts
 * gating hooks, the return value controls execution flow.
 */
interface GatingHookResult {
  /** Whether to allow the operation to proceed. */
  allowed: boolean;
  /** If allowed, an approval token for downstream verification. */
  token?: string;
  /** If denied, a quarantine ID for tracking. */
  quarantineId?: string;
  /** Human-readable reason (shown to agent as tool error). */
  reason?: string;
}

type GatingHookHandler = (event: OpenClawHookEvent) => Promise<GatingHookResult>;

/**
 * OpenClaw hook registration API.
 * Discovered from hooks.ts re-exports: registerHook, unregisterHook, etc.
 */
interface OpenClawHookAPI {
  registerHook: (eventKey: string, handler: OpenClawHookHandler) => void;
  unregisterHook: (eventKey: string, handler: OpenClawHookHandler) => void;
  /**
   * Gating hook registration (Strategy 3 — proposed extension).
   * If supported, registers a handler whose return value gates execution.
   */
  registerGatingHook?: (eventKey: string, handler: GatingHookHandler) => void;
  unregisterGatingHook?: (eventKey: string, handler: GatingHookHandler) => void;
}

/**
 * OpenClaw ChannelSecurityAdapter (Strategy 1).
 * Discovered from index.ts exports. Exact interface TBD — needs
 * investigation of the channel plugin source code.
 */
interface ChannelSecurityAdapter {
  /** Pre-send check: can this payload be transmitted? */
  checkOutbound?: (context: ChannelSecurityContext) => Promise<SecurityCheckResult>;
}

interface ChannelSecurityContext {
  sessionKey: string;
  channelId: string;
  targetId: string;
  content: string;
  toolName?: string;
  toolArgs?: Record<string, unknown>;
}

interface SecurityCheckResult {
  allowed: boolean;
  reason?: string;
  metadata?: Record<string, unknown>;
}

/**
 * OpenClaw diagnostic event API.
 * Discovered from index.ts: emitDiagnosticEvent, onDiagnosticEvent.
 */
interface DiagnosticAPI {
  emitDiagnosticEvent: (event: DiagnosticEventPayload) => void;
  onDiagnosticEvent: (handler: (event: DiagnosticEventPayload) => void) => void;
}

interface DiagnosticEventPayload {
  type: string;
  timestamp: Date;
  data: Record<string, unknown>;
}


// ═══════════════════════════════════════════════════════════════
// GATEWAY HOOK CONFIGURATION
// ═══════════════════════════════════════════════════════════════

/**
 * Configuration specific to the Gateway Hook module.
 * Loaded from the watchdog config.json at the path
 * `gateway.hook.*`.
 */
export interface GatewayHookConfig {
  /**
   * Master enable switch. When false, all hook handlers immediately
   * pass through without scanning. This is the "kill switch."
   * Default: true.
   */
  enabled: boolean;

  /**
   * HMAC key for signing and verifying approval tokens.
   * Must be at least 32 bytes. Loaded from the key file at
   * PATHS.KEY_FILE or generated on first run.
   */
  hmacKey: string;

  /**
   * Maximum time (ms) for the outbound scan pipeline to complete.
   * If exceeded, the payload is quarantined (fail-closed).
   * Default: 5000 (from LIMITS.SCAN_TIMEOUT_MS).
   */
  outboundTimeoutMs: number;

  /**
   * Maximum time (ms) to wait for inbound inspection.
   * Since inbound is non-blocking, this only limits logging latency.
   * Default: 3000.
   */
  inboundTimeoutMs: number;

  /**
   * Whether to scan inbound messages for inventory tracking.
   * Can be disabled to reduce overhead in low-risk environments.
   * Default: true (from DEFAULTS.INBOUND_SCAN_ENABLED).
   */
  inboundScanEnabled: boolean;

  /**
   * Integration strategy to use. Auto-detected at startup.
   * - "gating-hook":       Strategy 3 (proposed PR to OpenClaw)
   * - "security-adapter":  Strategy 1 (ChannelSecurityAdapter)
   * - "exec-approvals":    Strategy 2 (exec-approvals schema)
   * - "websocket-proxy":   Strategy 4 (transport-layer interception)
   * - "auto":              Detect best available strategy at startup
   * Default: "auto".
   */
  integrationStrategy: "auto" | "gating-hook" | "security-adapter" | "exec-approvals" | "websocket-proxy";

  /**
   * OpenClaw event keys to intercept for outbound tool calls.
   * Based on the type:action pattern discovered in source code.
   * Default: ["tool:call", "tool:exec"].
   *
   * NOTE: These are PROVISIONAL names. The source code review
   * identified that actual event names need verification against
   * the full OpenClaw codebase. Update these once confirmed.
   */
  outboundEventKeys: string[];

  /**
   * OpenClaw event keys to intercept for inbound messages.
   * Default: ["message:inbound"].
   */
  inboundEventKeys: string[];

  /**
   * Tool names that bypass scanning entirely (e.g., internal tools
   * that never produce external output).
   * Default: [].
   */
  bypassTools: string[];

  /**
   * Destination targets that bypass scanning (e.g., known-safe
   * internal APIs).
   * Default: [].
   */
  bypassDestinations: string[];

  /**
   * Interval (ms) for reporting health metrics to the Auditor.
   * Default: 30000 (30 seconds).
   */
  healthReportIntervalMs: number;

  /**
   * Maximum number of concurrent outbound scans.
   * Additional requests are queued.
   * Default: 10 (from LIMITS.MAX_CONCURRENT_SCANS).
   */
  maxConcurrentScans: number;
}

/** Default configuration values. */
const DEFAULT_HOOK_CONFIG: GatewayHookConfig = {
  enabled: true,
  hmacKey: "",            // Must be provided — startup fails without it
  outboundTimeoutMs: LIMITS.SCAN_TIMEOUT_MS,
  inboundTimeoutMs: 3_000,
  inboundScanEnabled: DEFAULTS.INBOUND_SCAN_ENABLED,
  integrationStrategy: "auto",
  outboundEventKeys: ["tool:call", "tool:exec"],
  inboundEventKeys: ["message:inbound"],
  bypassTools: [],
  bypassDestinations: [],
  healthReportIntervalMs: DEFAULTS.HEALTH_CHECK_INTERVAL_SECONDS * 1000,
  maxConcurrentScans: LIMITS.MAX_CONCURRENT_SCANS,
};


// ═══════════════════════════════════════════════════════════════
// HOOK METRICS
// ═══════════════════════════════════════════════════════════════

/**
 * Runtime metrics tracked by the Gateway Hook for health reporting
 * and performance monitoring.
 */
interface HookMetrics {
  /** Total outbound events intercepted since startup. */
  outboundIntercepted: number;
  /** Total outbound events that passed through clean. */
  outboundClean: number;
  /** Total outbound events quarantined (flagged). */
  outboundQuarantined: number;
  /** Total outbound events that failed (timeout or error). */
  outboundFailed: number;
  /** Total outbound events bypassed (tool/destination exempt). */
  outboundBypassed: number;
  /** Total inbound events inspected. */
  inboundInspected: number;
  /** Total inbound inspection errors. */
  inboundErrors: number;
  /** Moving average outbound scan latency (ms). */
  avgOutboundLatencyMs: number;
  /** Peak outbound scan latency (ms) since last reset. */
  peakOutboundLatencyMs: number;
  /** Current number of concurrent outbound scans. */
  activeScanCount: number;
  /** Number of scan requests queued waiting for a slot. */
  queuedScanCount: number;
  /** Timestamp of last successful outbound scan. */
  lastOutboundScanAt: string | null;
  /** Timestamp of last successful inbound inspection. */
  lastInboundScanAt: string | null;
  /** Whether the kill switch is active. */
  killSwitchActive: boolean;
  /** Uptime in seconds since hook initialization. */
  uptimeSeconds: number;
  /** Integration strategy in use. */
  activeStrategy: string;
}


// ═══════════════════════════════════════════════════════════════
// APPROVAL TOKEN MANAGER
// ═══════════════════════════════════════════════════════════════

/**
 * Manages HMAC-SHA256 approval tokens that are the hard dependency
 * between the watchdog and the gateway. Without a valid token, no
 * outbound payload transmits.
 *
 * Token format:
 *   APPROVAL_TOKEN_PREFIX + base64(HMAC-SHA256(payload))
 *
 * Where payload = requestId + ":" + contentHash + ":" + timestamp + ":" + verdict
 *
 * Tokens are time-limited (APPROVAL_TOKEN_TTL_MS) to prevent replay.
 */
export class ApprovalTokenManager {
  private readonly key: Buffer;

  constructor(hmacKey: string) {
    if (hmacKey.length < 32) {
      throw new ConfigurationError(
        "HMAC key must be at least 32 characters",
        { keyLength: hmacKey.length },
      );
    }
    this.key = Buffer.from(hmacKey, "utf-8");
  }

  /**
   * Generate an approval token for a clean scan result.
   *
   * @param requestId   - The scan request ID (UUIDv4)
   * @param contentHash - SHA-256 hash of the scanned content
   * @param timestamp   - ISO 8601 timestamp of the verdict
   * @param verdict     - The scan verdict (always "CLEAN" for approvals)
   * @returns Prefixed, base64-encoded HMAC token
   */
  generate(
    requestId: string,
    contentHash: string,
    timestamp: string,
    verdict: string,
  ): string {
    const payload = `${requestId}:${contentHash}:${timestamp}:${verdict}`;
    const hmac = createHmac(HMAC_ALGORITHM, this.key);
    hmac.update(payload);
    return APPROVAL_TOKEN_PREFIX + hmac.digest("hex");
  }

  /**
   * Verify an approval token.
   *
   * Performs timing-safe comparison to prevent timing attacks.
   * Also validates token freshness against APPROVAL_TOKEN_TTL_MS.
   *
   * @param token       - The token to verify (with prefix)
   * @param requestId   - Expected request ID
   * @param contentHash - Expected content hash
   * @param timestamp   - Expected timestamp (also checked for freshness)
   * @param verdict     - Expected verdict
   * @returns true if token is valid and fresh
   */
  verify(
    token: string,
    requestId: string,
    contentHash: string,
    timestamp: string,
    verdict: string,
  ): boolean {
    // Step 1: Check prefix
    if (!token.startsWith(APPROVAL_TOKEN_PREFIX)) {
      return false;
    }

    // Step 2: Check freshness
    const tokenAge = Date.now() - new Date(timestamp).getTime();
    if (tokenAge > APPROVAL_TOKEN_TTL_MS || tokenAge < 0) {
      return false;
    }

    // Step 3: Timing-safe comparison
    const expected = this.generate(requestId, contentHash, timestamp, verdict);
    if (token.length !== expected.length) {
      return false;
    }

    const tokenBuf = Buffer.from(token, "utf-8");
    const expectedBuf = Buffer.from(expected, "utf-8");
    return timingSafeEqual(tokenBuf, expectedBuf);
  }

  /**
   * Compute SHA-256 hash of content for token generation.
   *
   * @param content - The text content to hash
   * @returns Hex-encoded SHA-256 hash
   */
  static hashContent(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }
}


// ═══════════════════════════════════════════════════════════════
// DESTINATION CLASSIFIER
// ═══════════════════════════════════════════════════════════════

/**
 * Classifies tool call targets into destination types.
 *
 * This is the gateway hook's responsibility because it has access
 * to the OpenClaw tool call context (tool name, arguments, channel
 * metadata) that the Scanner does not directly see.
 */
export class DestinationClassifier {
  /**
   * Known tool-to-destination mappings.
   * Loaded from the destinations table in the registry at startup
   * and supplemented by built-in defaults.
   */
  private toolPatterns: Map<string, DestinationClassification> = new Map();

  /**
   * Classify the destination of a tool call.
   *
   * @param toolName - The OpenClaw tool being called
   * @param toolArgs - The tool call arguments
   * @returns DestinationInfo for the Scanner
   */
  classify(toolName: string, toolArgs: Record<string, unknown>): DestinationInfo {
    // TODO: Step 1 — Check tool pattern overrides from registry
    //   Query the toolPatterns map for an exact match on toolName.
    //   If found, use its type and extract the target from toolArgs.

    // TODO: Step 2 — Apply built-in classification heuristics
    //   Social / public tools:
    //     - "moltbook_post", "twitter_post", "social_*" → PUBLIC_PLATFORM
    //     - Extract target URL or platform name from toolArgs
    //   Messaging tools:
    //     - "whatsapp_send", "telegram_send", "discord_send", "signal_send" → PRIVATE_CHANNEL
    //     - Extract recipient from toolArgs.to, toolArgs.target, or toolArgs.channelId
    //   File tools:
    //     - "file_write", "fs_*", "save_*" → LOCAL_FILE
    //     - Extract path from toolArgs.path or toolArgs.filename
    //   API tools:
    //     - "web_fetch", "http_*", "api_*" → API_CALL
    //     - Extract URL from toolArgs.url or toolArgs.endpoint
    //   Owner-only:
    //     - "notify_owner", "owner_dm" → OWNER_ONLY

    // TODO: Step 3 — Determine public visibility
    //   PUBLIC_PLATFORM → isPublic = true
    //   PRIVATE_CHANNEL → isPublic = false (but could be group)
    //   API_CALL → isPublic = depends on endpoint (default true)
    //   LOCAL_FILE → isPublic = false
    //   OWNER_ONLY → isPublic = false

    // TODO: Step 4 — Fall back to UNKNOWN for unrecognized tools
    //   UNKNOWN destinations are treated as PUBLIC (fail-closed)

    throw new Error("Not implemented");
  }

  /**
   * Load tool-to-destination mappings from the registry database.
   *
   * @param patterns - Array of destination patterns from the destinations table
   */
  loadPatterns(patterns: DestinationClassification[]): void {
    // TODO: Clear existing patterns and rebuild the map
    // TODO: Validate each pattern (toolName must be non-empty)
    // TODO: Log the number of patterns loaded
    this.toolPatterns.clear();
    for (const pattern of patterns) {
      this.toolPatterns.set(pattern.toolName, pattern);
    }
  }
}

/** A single tool-to-destination mapping rule. */
interface DestinationClassification {
  /** Tool name or glob pattern (e.g., "moltbook_post", "social_*"). */
  toolName: string;
  /** Destination type classification. */
  type: DestinationType;
  /** Whether this destination is publicly visible. */
  isPublic: boolean;
  /** Template for extracting the target from toolArgs. */
  targetArgPath: string;
  /** Human-readable label template. */
  labelTemplate: string;
}


// ═══════════════════════════════════════════════════════════════
// CONTENT EXTRACTOR
// ═══════════════════════════════════════════════════════════════

/**
 * Extracts scannable text content from tool call arguments.
 *
 * Tool args are a nested key-value structure. The extractor walks
 * the structure and concatenates all string values that could
 * contain sensitive data, while skipping metadata-only fields.
 */
export class ContentExtractor {
  /**
   * Fields to skip during extraction (metadata, not user content).
   * These are common tool argument fields that contain structural
   * data rather than user-generated content.
   */
  private static readonly SKIP_FIELDS = new Set([
    "format", "encoding", "mime_type", "content_type",
    "timeout", "max_retries", "retry_delay",
    "headers", "method", "status_code",
    "width", "height", "quality",
  ]);

  /**
   * Extract all scannable text from tool call arguments.
   *
   * @param toolArgs - The tool call arguments object
   * @returns Concatenated text content suitable for scanning
   */
  static extract(toolArgs: Record<string, unknown>): string {
    // TODO: Implement recursive extraction
    // 1. Walk toolArgs recursively
    // 2. For each string value:
    //    a. Skip if the key is in SKIP_FIELDS
    //    b. Skip if the value is a URL-only string (no spaces, starts with http)
    //       — but DO include the URL itself as it may be a destination
    //    c. Concatenate with newline separator
    // 3. For arrays: extract each element
    // 4. For nested objects: recurse
    // 5. For non-string primitives: skip
    // 6. Trim and deduplicate whitespace
    // 7. Truncate to LIMITS.MAX_SCAN_CONTENT_LENGTH
    throw new Error("Not implemented");
  }

  /**
   * Extract a specific field value from nested tool args.
   * Used by DestinationClassifier to find target URLs, paths, etc.
   *
   * @param toolArgs - The tool call arguments
   * @param path     - Dot-separated path (e.g., "body.message.text")
   * @returns The value at that path, or undefined
   */
  static extractField(toolArgs: Record<string, unknown>, path: string): unknown {
    // TODO: Walk the path, handling arrays and nested objects
    const parts = path.split(".");
    let current: unknown = toolArgs;
    for (const part of parts) {
      if (current === null || current === undefined || typeof current !== "object") {
        return undefined;
      }
      current = (current as Record<string, unknown>)[part];
    }
    return current;
  }
}


// ═══════════════════════════════════════════════════════════════
// CONCURRENCY LIMITER
// ═══════════════════════════════════════════════════════════════

/**
 * Limits concurrent outbound scans to prevent resource exhaustion.
 * Additional requests are queued and processed FIFO.
 */
class ScanConcurrencyLimiter {
  private active: number = 0;
  private readonly queue: Array<{
    resolve: () => void;
    reject: (err: Error) => void;
    timeout: ReturnType<typeof setTimeout>;
  }> = [];

  constructor(
    private readonly maxConcurrent: number,
    private readonly queueTimeoutMs: number = 10_000,
  ) {}

  /**
   * Acquire a scan slot. Resolves when a slot is available.
   * Rejects if the queue timeout expires.
   */
  async acquire(): Promise<void> {
    if (this.active < this.maxConcurrent) {
      this.active++;
      return;
    }

    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const idx = this.queue.findIndex((q) => q.resolve === resolve);
        if (idx >= 0) {
          this.queue.splice(idx, 1);
        }
        reject(new Error(`Scan queue timeout after ${this.queueTimeoutMs}ms`));
      }, this.queueTimeoutMs);

      this.queue.push({ resolve, reject, timeout });
    });
  }

  /**
   * Release a scan slot. Processes the next queued request if any.
   */
  release(): void {
    if (this.queue.length > 0) {
      const next = this.queue.shift()!;
      clearTimeout(next.timeout);
      next.resolve();
    } else {
      this.active = Math.max(0, this.active - 1);
    }
  }

  /** Current number of active scans. */
  get activeCount(): number {
    return this.active;
  }

  /** Current number of queued requests. */
  get queuedCount(): number {
    return this.queue.length;
  }
}


// ═══════════════════════════════════════════════════════════════
// SCANNER BRIDGE
// ═══════════════════════════════════════════════════════════════

/**
 * Interface to the Pattern Scanner (Layer 1).
 *
 * The Gateway Hook communicates with the Scanner through this
 * interface. In production, this is backed by the ScannerPipeline
 * class (05-scanner-stub.ts). For testing, it can be mocked.
 */
export interface ScannerBridge {
  /**
   * Perform an outbound scan.
   *
   * @param request - The structured scan request
   * @returns Scan result with verdict and flags
   * @throws ScannerError on timeout or internal failure
   */
  scanOutbound(request: OutboundScanRequest): Promise<OutboundScanResult>;

  /**
   * Perform an inbound inspection.
   *
   * @param request - The structured inspection request
   * @returns Inspection result with inventory updates
   */
  inspectInbound(request: InboundInspectionRequest): Promise<InboundInspectionResult>;

  /** Check if the scanner is initialized and healthy. */
  isHealthy(): boolean;

  /** Get the current posture level from the Posture Engine. */
  getCurrentPosture(): PostureLevel;
}

/**
 * Interface to the Auditor Daemon (Layer 3).
 *
 * The Gateway Hook reports health metrics and diagnostic events
 * to the Auditor at a regular interval.
 */
export interface AuditorBridge {
  /**
   * Report health status from the gateway hook.
   *
   * @param report - Health check response with metrics
   */
  reportHealth(report: HealthCheckResponse): void;

  /**
   * Log a security event to the audit trail.
   *
   * @param event - Structured event data
   */
  logSecurityEvent(event: Record<string, unknown>): void;
}


// ═══════════════════════════════════════════════════════════════
// GATEWAY HOOK — MAIN CLASS
// ═══════════════════════════════════════════════════════════════

/**
 * The Security Watchdog Gateway Hook.
 *
 * This is the primary integration point between the Security Watchdog
 * and the OpenClaw framework. It intercepts all outbound tool calls
 * and inbound messages, delegating content scanning to the Pattern
 * Scanner (Layer 1).
 *
 * Lifecycle:
 *   1. constructor() — Validates config, creates internal instances
 *   2. initialize() — Detects integration strategy, registers hooks
 *   3. (runtime)    — Intercepts events, scans, approves/quarantines
 *   4. shutdown()   — Unregisters hooks, flushes metrics, cleans up
 *
 * Fail-closed behavior:
 *   - If the Scanner is unhealthy → quarantine (block outbound)
 *   - If a scan times out → quarantine
 *   - If the hook throws → quarantine (caught by error handler)
 *   - If kill switch is active → pass through (intentional bypass)
 *   - If the hook is disabled in config → pass through
 *
 * @example
 * ```ts
 * const hook = new GatewayHook(config, scanner, auditor);
 * await hook.initialize(openclawHookAPI);
 *
 * // Hook is now active — all tool calls pass through it
 *
 * // Emergency bypass:
 * hook.activateKillSwitch("Production issue — disabling scans", "operator");
 *
 * // Graceful shutdown:
 * await hook.shutdown();
 * ```
 */
export class GatewayHook extends EventEmitter {
  // ── Dependencies ───────────────────────────────────────────
  private readonly config: GatewayHookConfig;
  private readonly scanner: ScannerBridge;
  private readonly auditor: AuditorBridge;
  private readonly tokenManager: ApprovalTokenManager;
  private readonly destinationClassifier: DestinationClassifier;
  private readonly concurrencyLimiter: ScanConcurrencyLimiter;

  // ── State ──────────────────────────────────────────────────
  private initialized: boolean = false;
  private killSwitchActive: boolean = false;
  private killSwitchReason: string | null = null;
  private killSwitchOperator: string | null = null;
  private killSwitchActivatedAt: string | null = null;
  private startedAt: string | null = null;
  private activeStrategy: string = "none";

  // ── Hook references (for unregistration) ───────────────────
  private outboundHandler: OpenClawHookHandler | null = null;
  private inboundHandler: OpenClawHookHandler | null = null;
  private gatingHandler: GatingHookHandler | null = null;
  private hookAPI: OpenClawHookAPI | null = null;

  // ── Health reporting timer ─────────────────────────────────
  private healthReportTimer: ReturnType<typeof setInterval> | null = null;

  // ── Metrics ────────────────────────────────────────────────
  private metrics: HookMetrics = {
    outboundIntercepted: 0,
    outboundClean: 0,
    outboundQuarantined: 0,
    outboundFailed: 0,
    outboundBypassed: 0,
    inboundInspected: 0,
    inboundErrors: 0,
    avgOutboundLatencyMs: 0,
    peakOutboundLatencyMs: 0,
    activeScanCount: 0,
    queuedScanCount: 0,
    lastOutboundScanAt: null,
    lastInboundScanAt: null,
    killSwitchActive: false,
    uptimeSeconds: 0,
    activeStrategy: "none",
  };

  // ── Latency tracking (exponential moving average) ──────────
  private latencySampleCount: number = 0;
  private readonly LATENCY_EMA_ALPHA = 0.1;

  constructor(
    config: Partial<GatewayHookConfig>,
    scanner: ScannerBridge,
    auditor: AuditorBridge,
  ) {
    super();

    // Merge with defaults
    this.config = { ...DEFAULT_HOOK_CONFIG, ...config };

    // Validate required configuration
    if (!this.config.hmacKey || this.config.hmacKey.length < 32) {
      throw new ConfigurationError(
        "Gateway hook requires an HMAC key of at least 32 characters. " +
        "Set gateway.hook.hmacKey in config.json or generate one with setup.sh.",
        { keyLength: this.config.hmacKey?.length ?? 0 },
      );
    }

    this.scanner = scanner;
    this.auditor = auditor;
    this.tokenManager = new ApprovalTokenManager(this.config.hmacKey);
    this.destinationClassifier = new DestinationClassifier();
    this.concurrencyLimiter = new ScanConcurrencyLimiter(
      this.config.maxConcurrentScans,
      this.config.outboundTimeoutMs * 2,  // Queue timeout = 2x scan timeout
    );
  }


  // ── Lifecycle ──────────────────────────────────────────────

  /**
   * Initialize the gateway hook and register with OpenClaw.
   *
   * Detects the best available integration strategy, registers
   * event handlers, and starts the health reporting timer.
   *
   * @param hookAPI - The OpenClaw hook registration API
   * @throws ConfigurationError if the API is missing or strategy detection fails
   */
  async initialize(hookAPI: OpenClawHookAPI): Promise<void> {
    if (this.initialized) {
      throw new ConfigurationError("Gateway hook is already initialized");
    }

    this.hookAPI = hookAPI;
    this.startedAt = new Date().toISOString();

    // TODO: Step 1 — Detect integration strategy
    //   if (config.integrationStrategy === "auto") {
    //     if (hookAPI.registerGatingHook) → use "gating-hook"
    //     else → fall back to "websocket-proxy" or fire-and-forget with
    //            ChannelSecurityAdapter wrapping
    //   }
    //   Log the detected strategy

    // TODO: Step 2 — Register outbound hook(s)
    //   For "gating-hook" strategy:
    //     Create this.gatingHandler = this.handleOutboundGating.bind(this)
    //     For each eventKey in config.outboundEventKeys:
    //       hookAPI.registerGatingHook(eventKey, this.gatingHandler)
    //
    //   For "fire-and-forget" strategy (fallback):
    //     Create this.outboundHandler = this.handleOutboundFireAndForget.bind(this)
    //     For each eventKey in config.outboundEventKeys:
    //       hookAPI.registerHook(eventKey, this.outboundHandler)
    //     NOTE: This alone does NOT gate — must be paired with
    //     ChannelSecurityAdapter or exec-approvals for actual blocking

    // TODO: Step 3 — Register inbound hook(s)
    //   if (config.inboundScanEnabled) {
    //     Create this.inboundHandler = this.handleInbound.bind(this)
    //     For each eventKey in config.inboundEventKeys:
    //       hookAPI.registerHook(eventKey, this.inboundHandler)
    //   }

    // TODO: Step 4 — Start health reporting timer
    //   this.healthReportTimer = setInterval(
    //     () => this.reportHealth(),
    //     config.healthReportIntervalMs
    //   )

    // TODO: Step 5 — Load destination patterns from registry
    //   this.destinationClassifier.loadPatterns(await scanner.getDestinationPatterns())

    // TODO: Step 6 — Mark as initialized
    //   this.initialized = true
    //   this.activeStrategy = detectedStrategy
    //   Log: "Security Watchdog gateway hook initialized (strategy: ${strategy})"

    throw new Error("Not implemented");
  }

  /**
   * Graceful shutdown: unregister all hooks, stop timers, flush metrics.
   *
   * After shutdown, the gateway hook passes through all traffic
   * without scanning. Must call initialize() again to re-enable.
   */
  async shutdown(): Promise<void> {
    if (!this.initialized || !this.hookAPI) {
      return;
    }

    // TODO: Step 1 — Unregister outbound hook(s)
    //   if (this.gatingHandler && hookAPI.unregisterGatingHook) {
    //     for each eventKey in config.outboundEventKeys:
    //       hookAPI.unregisterGatingHook(eventKey, this.gatingHandler)
    //   }
    //   if (this.outboundHandler) {
    //     for each eventKey in config.outboundEventKeys:
    //       hookAPI.unregisterHook(eventKey, this.outboundHandler)
    //   }

    // TODO: Step 2 — Unregister inbound hook
    //   if (this.inboundHandler) {
    //     for each eventKey in config.inboundEventKeys:
    //       hookAPI.unregisterHook(eventKey, this.inboundHandler)
    //   }

    // TODO: Step 3 — Stop health reporting timer
    //   if (this.healthReportTimer) {
    //     clearInterval(this.healthReportTimer)
    //     this.healthReportTimer = null
    //   }

    // TODO: Step 4 — Final health report
    //   this.reportHealth()

    // TODO: Step 5 — Clear state
    //   this.initialized = false
    //   this.hookAPI = null
    //   this.outboundHandler = null
    //   this.inboundHandler = null
    //   this.gatingHandler = null
    //   Log: "Security Watchdog gateway hook shut down"

    throw new Error("Not implemented");
  }


  // ── Outbound Interception (Gating Strategy) ────────────────

  /**
   * Outbound handler for the GATING HOOK strategy.
   *
   * This is the preferred integration path. The handler's return
   * value (allowed: true/false) directly controls whether the
   * tool call proceeds.
   *
   * @param event - OpenClaw hook event for an outbound tool call
   * @returns GatingHookResult with allow/deny decision
   */
  private async handleOutboundGating(event: OpenClawHookEvent): Promise<GatingHookResult> {
    const interceptedAt = Date.now();
    const requestId = randomUUID();

    // Step 1: Kill switch check
    if (this.killSwitchActive) {
      this.metrics.outboundBypassed++;
      return {
        allowed: true,
        reason: "Kill switch active — bypass",
      };
    }

    // Step 2: Master enable check
    if (!this.config.enabled) {
      this.metrics.outboundBypassed++;
      return {
        allowed: true,
        reason: "Hook disabled in configuration",
      };
    }

    // Step 3: Scanner health check
    if (!this.scanner.isHealthy()) {
      this.metrics.outboundFailed++;
      this.auditor.logSecurityEvent({
        event: LOG_EVENTS.HEALTH_CHECK_FAILED,
        component: COMPONENT_IDS.SCANNER,
        requestId,
        timestamp: new Date().toISOString(),
      });
      // Fail-closed: block if scanner is unhealthy
      return {
        allowed: false,
        quarantineId: `quar-health-${requestId.slice(0, 8)}`,
        reason: "Scanner unavailable — payload quarantined for safety",
      };
    }

    this.metrics.outboundIntercepted++;

    try {
      // Step 4: Extract tool call context from the event
      const toolName = (event.context.toolName as string) ?? "unknown";
      const toolArgs = (event.context.toolArgs as Record<string, unknown>) ?? {};
      const sessionId = event.sessionKey;
      const agentId = (event.context.agentId as string) ?? "unknown";

      // Step 5: Check bypass lists
      if (this.config.bypassTools.includes(toolName)) {
        this.metrics.outboundBypassed++;
        return {
          allowed: true,
          reason: `Tool "${toolName}" is in bypass list`,
        };
      }

      // Step 6: Acquire concurrency slot (may queue)
      await this.concurrencyLimiter.acquire();
      this.metrics.activeScanCount = this.concurrencyLimiter.activeCount;
      this.metrics.queuedScanCount = this.concurrencyLimiter.queuedCount;

      try {
        // Step 7: Classify destination
        const destination = this.destinationClassifier.classify(toolName, toolArgs);

        // Step 8: Check destination bypass list
        if (this.config.bypassDestinations.includes(destination.target)) {
          this.metrics.outboundBypassed++;
          return {
            allowed: true,
            reason: `Destination "${destination.target}" is in bypass list`,
          };
        }

        // Step 9: Extract content for scanning
        const content = ContentExtractor.extract(toolArgs);
        const contentHash = ApprovalTokenManager.hashContent(content);

        // Step 10: Build the scan request
        const scanRequest: OutboundScanRequest = {
          requestId,
          timestamp: new Date().toISOString(),
          sessionId,
          agentId,
          direction: "OUTBOUND" as ScanDirection,
          toolName,
          toolArgs,
          content,
          destination,
          currentPosture: this.scanner.getCurrentPosture(),
        };

        // Step 11: Execute scan with timeout
        const scanResult = await this.executeOutboundScanWithTimeout(scanRequest);

        // Step 12: Process result
        const latencyMs = Date.now() - interceptedAt;
        this.updateLatencyMetrics(latencyMs);
        this.metrics.lastOutboundScanAt = new Date().toISOString();

        if (scanResult.verdict === "CLEAN") {
          this.metrics.outboundClean++;
          return {
            allowed: true,
            token: scanResult.approvalToken!,
          };
        } else {
          this.metrics.outboundQuarantined++;
          return {
            allowed: false,
            quarantineId: scanResult.quarantineId!,
            reason: "Content flagged by security scanner — payload quarantined",
          };
        }
      } finally {
        // Always release the concurrency slot
        this.concurrencyLimiter.release();
        this.metrics.activeScanCount = this.concurrencyLimiter.activeCount;
        this.metrics.queuedScanCount = this.concurrencyLimiter.queuedCount;
      }
    } catch (error) {
      // Fail-closed: quarantine on any unhandled error
      this.metrics.outboundFailed++;
      const quarantineId = `quar-err-${requestId.slice(0, 8)}`;

      this.auditor.logSecurityEvent({
        event: LOG_EVENTS.SCAN_TIMEOUT,
        requestId,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });

      return {
        allowed: false,
        quarantineId,
        reason: "Internal error during security scan — payload quarantined",
      };
    }
  }


  // ── Outbound Interception (Fire-and-Forget Fallback) ───────

  /**
   * Outbound handler for the FIRE-AND-FORGET fallback strategy.
   *
   * Since the hook system does not inspect return values, this
   * handler cannot directly block a tool call. Instead, it:
   *   1. Runs the scan pipeline
   *   2. If CLEAN: records the approval token
   *   3. If FLAGGED: records the quarantine in the database
   *
   * Actual blocking must be enforced by a complementary mechanism:
   *   - ChannelSecurityAdapter.checkOutbound() queries the
   *     approval token store before transmitting
   *   - exec-approvals requires a valid approval before executing
   *
   * @param event - OpenClaw hook event (return value ignored by framework)
   */
  private async handleOutboundFireAndForget(event: OpenClawHookEvent): Promise<void> {
    // TODO: Implement the same logic as handleOutboundGating but
    //   instead of returning GatingHookResult:
    //
    //   If CLEAN:
    //     1. Store the approval token in a short-lived cache or database
    //        keyed by (sessionId + toolCallId)
    //     2. The ChannelSecurityAdapter or exec-approvals mechanism
    //        checks this store before allowing transmission
    //
    //   If FLAGGED:
    //     1. Record the quarantine in the quarantine_queue table
    //     2. The complementary mechanism detects missing approval
    //        and blocks the transmission
    //
    //   If ERROR:
    //     1. Do NOT store an approval token (fail-closed)
    //     2. The complementary mechanism blocks by default

    // For now, delegate to the gating handler and log the result
    try {
      const result = await this.handleOutboundGating(event);

      if (result.allowed && result.token) {
        // TODO: Store approval token in the token cache
        //   tokenCache.set(event.sessionKey + ":" + event.context.toolCallId, {
        //     token: result.token,
        //     expiresAt: Date.now() + APPROVAL_TOKEN_TTL_MS,
        //   });
      }
      // If not allowed, quarantine is already recorded by the gating handler

    } catch (error) {
      // Fail-closed: no approval token stored → transmission blocked
      this.auditor.logSecurityEvent({
        event: LOG_EVENTS.SCAN_TIMEOUT,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });
    }
  }


  // ── Inbound Inspection ─────────────────────────────────────

  /**
   * Inbound message handler.
   *
   * Inspects incoming content for sensitive data and updates the
   * inventory. This is always fire-and-forget — inbound content
   * is delivered to the assistant regardless of scan results.
   * The value is in populating the inventory for posture adjustment.
   *
   * @param event - OpenClaw hook event for an inbound message
   */
  private async handleInbound(event: OpenClawHookEvent): Promise<void> {
    if (!this.config.inboundScanEnabled || this.killSwitchActive) {
      return;
    }

    const requestId = randomUUID();

    try {
      // Step 1: Extract content from the inbound event
      const content = (event.context.content as string)
        ?? (event.context.text as string)
        ?? "";
      if (!content || content.trim().length === 0) {
        return; // Nothing to inspect
      }

      // Step 2: Build the inspection request
      const inspectionRequest: InboundInspectionRequest = {
        requestId,
        timestamp: new Date().toISOString(),
        sessionId: event.sessionKey,
        agentId: (event.context.agentId as string) ?? "unknown",
        direction: "INBOUND" as ScanDirection,
        content,
        sourceChannel: (event.context.channelId as string) ?? "unknown",
        sourceIdentifier: (event.context.senderId as string) ?? "unknown",
        currentPosture: this.scanner.getCurrentPosture(),
      };

      // Step 3: Run inspection with timeout
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error("Inbound inspection timeout")), this.config.inboundTimeoutMs);
      });

      await Promise.race([
        this.scanner.inspectInbound(inspectionRequest),
        timeoutPromise,
      ]);

      this.metrics.inboundInspected++;
      this.metrics.lastInboundScanAt = new Date().toISOString();

    } catch (error) {
      // Inbound errors are non-critical — log and continue
      this.metrics.inboundErrors++;
      this.auditor.logSecurityEvent({
        event: "inbound.inspection_error",
        requestId,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });
    }
  }


  // ── Scan Execution ─────────────────────────────────────────

  /**
   * Execute an outbound scan with a timeout guard.
   *
   * If the scan exceeds config.outboundTimeoutMs, the promise
   * rejects, and the caller's fail-closed logic quarantines
   * the payload.
   *
   * @param request - The outbound scan request
   * @returns Scan result (resolves before timeout)
   * @throws Error if scan times out
   */
  private async executeOutboundScanWithTimeout(
    request: OutboundScanRequest,
  ): Promise<OutboundScanResult> {
    return new Promise<OutboundScanResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(
          ScannerError.timeout(request.requestId, this.config.outboundTimeoutMs),
        );
      }, this.config.outboundTimeoutMs);

      this.scanner
        .scanOutbound(request)
        .then((result) => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch((err) => {
          clearTimeout(timer);
          reject(err);
        });
    });
  }


  // ── Kill Switch ────────────────────────────────────────────

  /**
   * Activate the kill switch — immediately bypass all scanning.
   *
   * DANGEROUS: This disables all security checks. Use only in
   * production emergencies where scanning is causing operational
   * issues (e.g., Presidio service down causing timeouts).
   *
   * The kill switch is logged to the audit trail and reported
   * to the Auditor as a DEGRADED health status.
   *
   * @param reason   - Human-readable reason (logged to audit trail)
   * @param operator - Who activated the kill switch (logged)
   */
  activateKillSwitch(reason: string, operator: string): void {
    this.killSwitchActive = true;
    this.killSwitchReason = reason;
    this.killSwitchOperator = operator;
    this.killSwitchActivatedAt = new Date().toISOString();
    this.metrics.killSwitchActive = true;

    this.auditor.logSecurityEvent({
      event: "hook.kill_switch_activated",
      reason,
      operator,
      timestamp: this.killSwitchActivatedAt,
    });

    this.emit("kill-switch", { active: true, reason, operator });
  }

  /**
   * Deactivate the kill switch — resume normal scanning.
   *
   * @param operator - Who deactivated the kill switch (logged)
   */
  deactivateKillSwitch(operator: string): void {
    const wasActive = this.killSwitchActive;
    const duration = this.killSwitchActivatedAt
      ? Date.now() - new Date(this.killSwitchActivatedAt).getTime()
      : 0;

    this.killSwitchActive = false;
    this.killSwitchReason = null;
    this.killSwitchOperator = null;
    this.killSwitchActivatedAt = null;
    this.metrics.killSwitchActive = false;

    if (wasActive) {
      this.auditor.logSecurityEvent({
        event: "hook.kill_switch_deactivated",
        operator,
        durationMs: duration,
        timestamp: new Date().toISOString(),
      });
    }

    this.emit("kill-switch", { active: false, operator });
  }


  // ── Health Reporting ───────────────────────────────────────

  /**
   * Build and send a health report to the Auditor.
   * Called periodically by the health reporting timer.
   */
  private reportHealth(): void {
    const uptimeMs = this.startedAt
      ? Date.now() - new Date(this.startedAt).getTime()
      : 0;

    this.metrics.uptimeSeconds = Math.floor(uptimeMs / 1000);
    this.metrics.activeStrategy = this.activeStrategy;
    this.metrics.activeScanCount = this.concurrencyLimiter.activeCount;
    this.metrics.queuedScanCount = this.concurrencyLimiter.queuedCount;

    // Determine health status
    let status: HealthStatus;
    if (!this.initialized) {
      status = "UNHEALTHY" as HealthStatus;
    } else if (this.killSwitchActive) {
      status = "DEGRADED" as HealthStatus;
    } else if (!this.scanner.isHealthy()) {
      status = "DEGRADED" as HealthStatus;
    } else {
      status = "HEALTHY" as HealthStatus;
    }

    const report: HealthCheckResponse = {
      componentId: COMPONENT_IDS.GATEWAY_HOOK,
      status,
      timestamp: new Date().toISOString(),
      details: {
        version: VERSION,
        strategy: this.activeStrategy,
        killSwitch: this.killSwitchActive,
        killSwitchReason: this.killSwitchReason,
        metrics: { ...this.metrics },
      },
      responseTimeMs: 0, // Hook health check is local, no latency
    };

    this.auditor.reportHealth(report);
  }


  // ── Metrics Helpers ────────────────────────────────────────

  /**
   * Update the exponential moving average for outbound scan latency.
   */
  private updateLatencyMetrics(latencyMs: number): void {
    if (this.latencySampleCount === 0) {
      this.metrics.avgOutboundLatencyMs = latencyMs;
    } else {
      this.metrics.avgOutboundLatencyMs =
        this.LATENCY_EMA_ALPHA * latencyMs +
        (1 - this.LATENCY_EMA_ALPHA) * this.metrics.avgOutboundLatencyMs;
    }
    this.latencySampleCount++;

    if (latencyMs > this.metrics.peakOutboundLatencyMs) {
      this.metrics.peakOutboundLatencyMs = latencyMs;
    }
  }

  /**
   * Reset peak latency counter. Called by the dashboard or Auditor
   * at the start of each metrics aggregation window.
   */
  resetPeakLatency(): void {
    this.metrics.peakOutboundLatencyMs = 0;
  }


  // ── Public Accessors ───────────────────────────────────────

  /** Whether the hook is initialized and registered. */
  get isInitialized(): boolean {
    return this.initialized;
  }

  /** Whether the kill switch is currently active. */
  get isKillSwitchActive(): boolean {
    return this.killSwitchActive;
  }

  /** Current runtime metrics snapshot. */
  getMetrics(): Readonly<HookMetrics> {
    return { ...this.metrics };
  }

  /** The approval token manager (exposed for direct verification). */
  getTokenManager(): ApprovalTokenManager {
    return this.tokenManager;
  }
}


// ═══════════════════════════════════════════════════════════════
// DEFAULT EXPORT — OPENCLAW HANDLER ENTRY POINT
// ═══════════════════════════════════════════════════════════════

/**
 * OpenClaw hook handler factory.
 *
 * This is the default export that OpenClaw's loader.ts will import
 * from handler.ts. It returns the hook handler function that gets
 * registered for the events declared in HOOK.md frontmatter.
 *
 * OpenClaw calls this function once during hook loading. The returned
 * function is then registered for each event key in the metadata.
 *
 * IMPORTANT: Because OpenClaw registers the SAME handler function
 * for ALL events listed in the frontmatter, the handler must
 * dispatch based on event.type and event.action internally.
 *
 * @example HOOK.md frontmatter:
 * ```
 * "events": ["tool:call", "tool:exec", "message:inbound"]
 * ```
 *
 * OpenClaw loader does:
 * ```ts
 * const handler = (await import("./handler.ts")).default;
 * registerInternalHook("tool:call", handler);
 * registerInternalHook("tool:exec", handler);
 * registerInternalHook("message:inbound", handler);
 * ```
 */

/**
 * Singleton GatewayHook instance.
 * Created lazily on first event if not already initialized.
 */
let hookInstance: GatewayHook | null = null;

/**
 * Initialize the gateway hook singleton.
 *
 * Must be called before the first event arrives. Typically called
 * during OpenClaw startup, either by the installer script or by
 * a bootstrap hook.
 *
 * @param config  - Hook configuration (merged with defaults)
 * @param scanner - ScannerBridge instance (from the Scanner module)
 * @param auditor - AuditorBridge instance (from the Auditor module)
 * @param hookAPI - OpenClaw hook registration API
 */
export async function initializeGatewayHook(
  config: Partial<GatewayHookConfig>,
  scanner: ScannerBridge,
  auditor: AuditorBridge,
  hookAPI: OpenClawHookAPI,
): Promise<GatewayHook> {
  if (hookInstance?.isInitialized) {
    throw new ConfigurationError("Gateway hook is already initialized");
  }

  hookInstance = new GatewayHook(config, scanner, auditor);
  await hookInstance.initialize(hookAPI);
  return hookInstance;
}

/**
 * Get the current gateway hook instance.
 * Returns null if not yet initialized.
 */
export function getGatewayHook(): GatewayHook | null {
  return hookInstance;
}

/**
 * Default export: The hook handler function for OpenClaw's loader.
 *
 * This is the function OpenClaw imports and registers. It dispatches
 * to the appropriate GatewayHook method based on event type.
 *
 * If the hook singleton is not yet initialized, events are silently
 * dropped (logged as warnings). This handles the race condition
 * where OpenClaw fires events before the watchdog has finished
 * its async initialization.
 */
const handler: OpenClawHookHandler = async (event: OpenClawHookEvent): Promise<void> => {
  if (!hookInstance?.isInitialized) {
    // TODO: Log warning: "Security Watchdog hook received event before initialization"
    // This can happen during startup. Events are dropped (fail-open during boot).
    // The initialization timeout in setup.sh ensures this window is brief.
    return;
  }

  // Dispatch based on event type
  // NOTE: The actual event type:action strings need verification
  // against the OpenClaw source. These are provisional.
  switch (event.type) {
    case "tool":
      // Outbound tool call — handled by the gating or fire-and-forget strategy
      // The actual scanning is triggered by the strategy-specific handler
      // registered during initialize(). This default handler is a fallback
      // for events that don't match a registered gating hook.
      break;

    case "message":
      if (event.action === "inbound") {
        // Inbound message — delegate to inbound handler
        // (already registered separately during initialize())
      }
      break;

    default:
      // Unknown event type — ignore
      break;
  }
};

export default handler;


// ═══════════════════════════════════════════════════════════════
// HOOK.MD TEMPLATE
// ═══════════════════════════════════════════════════════════════

/**
 * This constant contains the complete HOOK.md file content
 * for the security-watchdog hook. Used by the installer to
 * generate the file.
 */
export const HOOK_MD_CONTENT = `---
name: security-watchdog
description: "Security Watchdog — intercepts all outbound agent communications and enforces data classification policies through multi-layer scanning. Protects against unauthorized exposure of PII, credentials, and user-defined sensitive data."
homepage: https://github.com/openclaw/security-watchdog
metadata:
  {
    "openclaw": {
      "emoji": "🛡️",
      "events": ["tool:call", "tool:exec", "message:inbound"],
      "always": true,
      "requires": {
        "bins": ["ollama"],
        "config": ["security.enabled"]
      },
      "install": [
        {
          "id": "npm",
          "kind": "npm",
          "package": "@openclaw/security-watchdog",
          "label": "Install via npm"
        },
        {
          "id": "bundled",
          "kind": "bundled",
          "label": "Bundled with Security Watchdog"
        }
      ]
    }
  }
---

# Security Watchdog

The Security Watchdog is an independent security layer that intercepts all agent
communications and enforces data classification policies. It prevents unauthorized
exposure of PII, credentials, and user-defined sensitive data through a three-layer
scanning architecture:

- **Layer 0 (Registry):** SQLite database of patterns and user-defined sensitive entries
- **Layer 1 (Scanner):** Deterministic PII detection via Presidio, detect-secrets, and fuse.js
- **Layer 2 (Security Agent):** Local AI (Ollama) for contextual classification
- **Layer 3 (Auditor):** Independent health monitoring and audit logging

## How It Works

Every outbound tool call passes through the watchdog before reaching any external
service. The scanner checks content against known PII patterns and user-defined
sensitive data. Clean payloads receive a signed approval token; flagged payloads
are quarantined for Security Agent review or human escalation.

Inbound messages are inspected for sensitive data to populate the data inventory,
enabling dynamic posture adjustment.

## Requirements

- **Ollama:** Required for Layer 2 (Security Agent) contextual classification
- **Presidio:** HTTP microservice for structural PII detection
- **SQLite:** Embedded database for registry, inventory, and audit logs

## Configuration

Configuration is stored at \`~/.openclaw/security/config.json\`.
See the Security Watchdog documentation for full configuration reference.

## Kill Switch

In emergencies, scanning can be bypassed via CLI:
\`\`\`bash
watchdog kill-switch --activate --reason "production issue"
watchdog kill-switch --deactivate
\`\`\`
`;
