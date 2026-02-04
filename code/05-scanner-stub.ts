/**
 * Security Watchdog — Pattern Scanner (Layer 1) Code Stub
 *
 * Document ID:  SWDOG-MOD-005
 * Version:      1.0 DRAFT
 * Generated:    February 2026
 *
 * This file defines the complete class structure, method signatures,
 * and type annotations for the Pattern Scanner module. Developers
 * implement the TODO markers. All public APIs are fully typed.
 *
 * ────────────────────────────────────────────────────────────────
 * DEPENDENCIES:
 *   Runtime:   fuse.js, better-sqlite3, natural, crypto (built-in)
 *   External:  Presidio HTTP service (localhost:5002)
 *   External:  detect-secrets CLI (Python)
 *   Internal:  @watchdog/types (02-interfaces.ts)
 * ────────────────────────────────────────────────────────────────
 */

import Fuse from "fuse.js";
import Database from "better-sqlite3";
import { createHmac, randomUUID, createHash } from "crypto";

// ── Import shared types from @watchdog/types ──────────────────
import type {
  OutboundScanRequest,
  OutboundScanResult,
  InboundInspectionRequest,
  InboundInspectionResult,
  ScanFlag,
  ScanStage,
  ScanVerdict,
  DestinationInfo,
  DestinationType,
  PresidioAnalyzeRequest,
  PresidioAnalyzeResponse,
  PresidioEntity,
  InventoryEntry,
  PatternDefinition,
  UserDefinedEntry,
  EntryVariant,
  DestinationRule,
  ClassificationLevel,
  PostureLevel,
  HealthCheckResponse,
  HealthStatus,
  ClassificationRequest,
  ClassificationResponse,
  FlagSource,
  WatchdogError,
  WatchdogErrorCode,
  ScanDirection,
} from "@watchdog/types";


// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

/** Scanner-specific configuration. Loaded from watchdog config.json. */
export interface ScannerConfig {
  /** Presidio HTTP microservice URL (default: http://127.0.0.1:5002). */
  presidioUrl: string;
  /** Minimum Presidio confidence score to flag (default: 0.35). */
  presidioMinScore: number;
  /** HTTP timeout for Presidio requests in ms (default: 500). */
  presidioTimeoutMs: number;
  /** fuse.js threshold: 0.0 = exact, 1.0 = everything (default: 0.35). */
  fuseThreshold: number;
  /** fuse.js distance: max char distance for match (default: 100). */
  fuseDistance: number;
  /** Minimum fuse.js match char length (default: 3). */
  fuseMinMatchCharLength: number;
  /** Maximum total scan time in ms before timeout (default: 5000). */
  totalTimeoutMs: number;
  /** Whether inbound scanning is enabled (default: true). */
  inboundScanEnabled: boolean;
  /** Path to detect-secrets executable (default: "detect-secrets"). */
  detectSecretsPath: string;
  /** Whether Stage 2 (credential detection) is enabled (default: true). */
  detectSecretsEnabled: boolean;
  /** Decision cache TTL in ms (default: 86400000 = 24h). */
  cacheMaxAge: number;
  /** Maximum cached scan results before LRU eviction (default: 10000). */
  cacheMaxSize: number;
  /** Security Agent service URL (default: http://127.0.0.1:5003). */
  securityAgentUrl: string;
  /** HMAC signing key for approval tokens. */
  hmacKey: string;
  /** Database path (default: ~/.openclaw/security/registry.db). */
  databasePath: string;
}

/** Default Scanner configuration. */
export const DEFAULT_SCANNER_CONFIG: ScannerConfig = {
  presidioUrl: "http://127.0.0.1:5002",
  presidioMinScore: 0.35,
  presidioTimeoutMs: 500,
  fuseThreshold: 0.35,
  fuseDistance: 100,
  fuseMinMatchCharLength: 3,
  totalTimeoutMs: 5000,
  inboundScanEnabled: true,
  detectSecretsPath: "detect-secrets",
  detectSecretsEnabled: true,
  cacheMaxAge: 86_400_000,
  cacheMaxSize: 10_000,
  securityAgentUrl: "http://127.0.0.1:5003",
  hmacKey: "",
  databasePath: "",
};


// ═══════════════════════════════════════════════════════════════
// INTERNAL TYPES
// ═══════════════════════════════════════════════════════════════

/** Result from a single pipeline stage. */
export interface StageResult {
  /** Stage name identifier. */
  stageName: "presidio" | "detect_secrets" | "fuzzy_match";
  /** Whether the stage was executed (may be skipped). */
  executed: boolean;
  /** Duration in milliseconds. */
  durationMs: number;
  /** Flags raised by this stage. */
  flags: ScanFlag[];
  /** Error message if stage failed (null if successful). */
  error: string | null;
}

/** Content extracted from tool call arguments. */
export interface ExtractedContent {
  /** Concatenated text content for scanning. */
  text: string;
  /** Source fields from which content was extracted. */
  sourceFields: string[];
  /** Total character count. */
  charCount: number;
}

/** A searchable entry loaded from the registry for fuse.js indexing. */
export interface SearchableEntry {
  /** Registry entry ID. */
  entryId: number;
  /** Entry label. */
  label: string;
  /** Primary value to match. */
  primaryValue: string;
  /** All variant texts, concatenated with separators for search. */
  variants: string[];
  /** Classification level. */
  classification: ClassificationLevel;
  /** Entry category. */
  category: string;
}

/** A cached scan result for idempotency. */
interface CachedResult {
  /** The scan result. */
  result: OutboundScanResult | InboundInspectionResult;
  /** Timestamp when cached. */
  cachedAt: number;
}

/** Destination rule loaded from registry, augmented for matching. */
interface LoadedDestinationRule {
  entryId: number;
  destinationType: DestinationType;
  targetPattern: RegExp | null;
  overrideClassification: ClassificationLevel;
}

/** Destination pattern from the destinations table. */
interface LoadedDestinationPattern {
  destinationType: DestinationType;
  targetRegex: RegExp;
  label: string;
  isPublic: boolean;
}

/** Tool-specific content extraction function signature. */
type ContentExtractor = (toolArgs: Record<string, unknown>) => ExtractedContent;


// ═══════════════════════════════════════════════════════════════
// PATTERN SCANNER — MAIN CLASS
// ═══════════════════════════════════════════════════════════════

/**
 * PatternScanner is the main entry point for Layer 1 scanning.
 * It orchestrates the three-stage pipeline, manages the registry
 * preload, and provides the gateway hook handlers.
 *
 * Lifecycle:
 *   1. Construct with config
 *   2. Call initialize() to connect to DB and preload registry
 *   3. Register hooks via getOutboundHandler() / getInboundHandler()
 *   4. Call shutdown() on process exit
 */
export class PatternScanner {
  private readonly config: ScannerConfig;
  private readonly pipeline: ScanPipeline;
  private readonly destinationClassifier: DestinationClassifier;
  private readonly registryLoader: RegistryLoader;
  private readonly decisionLogger: DecisionLogger;
  private readonly resultCache: ResultCache;
  private readonly tokenGenerator: ApprovalTokenGenerator;
  private readonly quarantineManager: QuarantineManager;
  private readonly agentClient: SecurityAgentClient;

  private db: Database.Database | null = null;
  private enabled: boolean = true;
  private initialized: boolean = false;

  // ── Metrics ───────────────────────────────────────────────
  private scanCountSinceLastCheck: number = 0;
  private errorCountSinceLastCheck: number = 0;
  private startedAt: number = 0;

  constructor(config: Partial<ScannerConfig> = {}) {
    this.config = { ...DEFAULT_SCANNER_CONFIG, ...config };
    this.pipeline = new ScanPipeline(this.config);
    this.destinationClassifier = new DestinationClassifier();
    this.registryLoader = new RegistryLoader(this.config);
    this.decisionLogger = new DecisionLogger();
    this.resultCache = new ResultCache(this.config.cacheMaxSize, this.config.cacheMaxAge);
    this.tokenGenerator = new ApprovalTokenGenerator(this.config.hmacKey);
    this.quarantineManager = new QuarantineManager();
    this.agentClient = new SecurityAgentClient(this.config.securityAgentUrl);
  }

  /**
   * Initialize the Scanner: connect to database, preload registry,
   * build fuse.js index, and register pipeline stages.
   */
  async initialize(): Promise<void> {
    // TODO: Open database connection with required pragmas
    // TODO: Preload registry (patterns, entries, variants, destination rules)
    // TODO: Build fuse.js index from loaded entries
    // TODO: Register pipeline stages (Presidio, detect-secrets, fuse.js)
    // TODO: Load destination patterns from destinations table
    // TODO: Set initialized = true, record startedAt timestamp
    throw new Error("Not implemented");
  }

  /**
   * Graceful shutdown: close database, clear caches, flush logs.
   */
  async shutdown(): Promise<void> {
    // TODO: Flush any pending decision log writes
    // TODO: Close database connection
    // TODO: Clear result cache
    // TODO: Set initialized = false
    throw new Error("Not implemented");
  }

  // ── Gateway Hook Handlers ─────────────────────────────────

  /**
   * Returns the synchronous outbound hook handler for gateway registration.
   * This function is called by the gateway for every outbound tool call.
   *
   * @returns Hook handler function compatible with OpenClaw gateway.hooks.register()
   */
  getOutboundHandler(): (event: unknown) => Promise<{ action: string; token?: string; quarantineId?: string }> {
    return async (event: unknown) => {
      try {
        const result = await this.handleOutbound(event as OutboundScanRequest);
        if (result.verdict === "CLEAN") {
          return { action: "allow", token: result.approvalToken! };
        } else {
          return { action: "quarantine", quarantineId: result.quarantineId! };
        }
      } catch (error) {
        // Fail-closed: quarantine on any unhandled error
        const quarantineId = `quar-err-${randomUUID().slice(0, 8)}`;
        // TODO: Log error with full context (but not content)
        return { action: "quarantine", quarantineId };
      }
    };
  }

  /**
   * Returns the asynchronous inbound hook handler for gateway registration.
   *
   * @returns Hook handler function. Return value is advisory only.
   */
  getInboundHandler(): (event: unknown) => Promise<void> {
    return async (event: unknown) => {
      try {
        await this.handleInbound(event as InboundInspectionRequest);
      } catch (error) {
        // Inbound errors are non-critical — log and continue
        // TODO: Log error
      }
    };
  }

  /**
   * Process an outbound tool call through the scan pipeline.
   *
   * @param request - Outbound scan request from the gateway hook
   * @returns Scan result with verdict, flags, and timing
   */
  async handleOutbound(request: OutboundScanRequest): Promise<OutboundScanResult> {
    // TODO: Check if scanner is enabled (kill switch)
    // TODO: Check result cache for duplicate requestId
    // TODO: Extract content from tool args
    // TODO: Classify destination
    // TODO: Run scan pipeline (all stages)
    // TODO: Assemble verdict (CLEAN or FLAGGED)
    // TODO: If CLEAN: generate approval token
    // TODO: If FLAGGED: create quarantine, send to Security Agent
    // TODO: Log decision to database
    // TODO: Cache result
    // TODO: Return OutboundScanResult
    throw new Error("Not implemented");
  }

  /**
   * Inspect inbound content for sensitive data.
   * Non-blocking — logs to inventory and recommends posture adjustment.
   *
   * @param request - Inbound inspection request
   * @returns Inspection result with inventory updates and posture recommendation
   */
  async handleInbound(request: InboundInspectionRequest): Promise<InboundInspectionResult> {
    // TODO: Check if inbound scanning is enabled
    // TODO: Run scan pipeline (Presidio + fuse.js only; no detect-secrets for inbound)
    // TODO: Create/update inventory entries for detected sensitive data
    // TODO: Calculate posture recommendation from detected classifications
    // TODO: Log decision to database
    // TODO: Return InboundInspectionResult
    throw new Error("Not implemented");
  }

  // ── Control Methods ───────────────────────────────────────

  /**
   * Disable scanning (kill switch). All outbound scans return CLEAN.
   * DANGEROUS — use only in emergencies.
   *
   * @param reason - Reason for disabling (logged to audit trail)
   * @param operator - Who activated the kill switch
   */
  disable(reason: string, operator: string): void {
    // TODO: Set enabled = false
    // TODO: Log to audit trail with reason and operator
    this.enabled = false;
  }

  /**
   * Re-enable scanning after kill switch.
   *
   * @param operator - Who re-enabled
   */
  enable(operator: string): void {
    // TODO: Set enabled = true
    // TODO: Log to audit trail
    this.enabled = true;
  }

  /**
   * Rebuild the in-memory registry index.
   * Called when registry entries change.
   */
  async reloadRegistry(): Promise<void> {
    // TODO: Re-preload patterns, entries, variants, destination rules
    // TODO: Rebuild fuse.js index
    // TODO: Rebuild destination classifier patterns
    throw new Error("Not implemented");
  }

  /**
   * Health check for the Auditor daemon.
   *
   * @returns Current health status and metrics
   */
  getHealth(): HealthCheckResponse {
    // TODO: Return health status based on:
    //   - Presidio availability (last successful/failed call)
    //   - detect-secrets availability
    //   - fuse.js index loaded
    //   - Database connection status
    //   - Error rate since last check
    //   - Scan count since last check
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// SCAN PIPELINE
// ═══════════════════════════════════════════════════════════════

/**
 * ScanPipeline orchestrates the three detection stages in sequence.
 * Each stage is independently time-bounded and can be skipped
 * based on configuration and runtime conditions.
 */
export class ScanPipeline {
  private readonly config: ScannerConfig;
  private readonly stages: Map<string, ScanStageHandler> = new Map();

  constructor(config: ScannerConfig) {
    this.config = config;
  }

  /**
   * Register a scan stage with the pipeline.
   *
   * @param name - Stage identifier
   * @param handler - Stage handler implementing the ScanStageHandler interface
   */
  registerStage(name: string, handler: ScanStageHandler): void {
    this.stages.set(name, handler);
  }

  /**
   * Execute all registered stages in sequence.
   * Each stage receives the content and produces flags.
   * Stages respect individual and total timeouts.
   *
   * @param content - Extracted text content to scan
   * @param destination - Classified destination info
   * @param postureLevel - Current system posture
   * @param context - Pipeline context (registry data, config)
   * @returns Combined results from all stages
   */
  async execute(
    content: string,
    destination: DestinationInfo,
    postureLevel: PostureLevel,
    context: PipelineContext
  ): Promise<PipelineResult> {
    // TODO: Initialize timing
    // TODO: For each stage in order:
    //   - Check if stage should run (posture, destination, config)
    //   - Execute with individual timeout
    //   - Collect flags
    //   - Check total timeout
    // TODO: Deduplicate overlapping flags across stages
    // TODO: Return combined result with per-stage timing
    throw new Error("Not implemented");
  }
}

/** Interface for individual scan stage handlers. */
export interface ScanStageHandler {
  /** Stage name. */
  readonly name: "presidio" | "detect_secrets" | "fuzzy_match";

  /**
   * Execute the scan stage.
   *
   * @param content - Text to scan
   * @param context - Pipeline context
   * @returns Stage result with flags
   */
  execute(content: string, context: PipelineContext): Promise<StageResult>;

  /**
   * Whether this stage should run given current conditions.
   *
   * @param destination - Target destination
   * @param posture - Current posture level
   * @param previousFlags - Flags from earlier stages
   * @returns true if this stage should execute
   */
  shouldRun(
    destination: DestinationInfo,
    posture: PostureLevel,
    previousFlags: ScanFlag[]
  ): boolean;
}

/** Context passed to all pipeline stages. */
export interface PipelineContext {
  /** Active pattern definitions (preloaded from registry). */
  patterns: PatternDefinition[];
  /** Active user entries with variants (preloaded). */
  entries: SearchableEntry[];
  /** Destination rules (preloaded). */
  destinationRules: LoadedDestinationRule[];
  /** The classified destination for this scan. */
  destination: DestinationInfo;
  /** Current posture level. */
  postureLevel: PostureLevel;
  /** Scanner configuration. */
  config: ScannerConfig;
}

/** Combined result from all pipeline stages. */
export interface PipelineResult {
  /** All flags from all stages (deduplicated). */
  flags: ScanFlag[];
  /** Per-stage execution records. */
  stages: ScanStage[];
  /** Total pipeline execution time in ms. */
  totalDurationMs: number;
  /** Whether any stage was skipped. */
  degraded: boolean;
  /** Degradation details (which stages skipped and why). */
  degradationNotes: string[];
}


// ═══════════════════════════════════════════════════════════════
// STAGE 1: PRESIDIO PII DETECTION
// ═══════════════════════════════════════════════════════════════

/**
 * PresidioStage sends content to the Presidio HTTP microservice
 * and converts detected entities into ScanFlags.
 */
export class PresidioStage implements ScanStageHandler {
  readonly name = "presidio" as const;
  private readonly presidioUrl: string;
  private readonly minScore: number;
  private readonly timeoutMs: number;
  private lastSuccessAt: number = 0;
  private lastErrorAt: number = 0;
  private consecutiveErrors: number = 0;

  constructor(config: ScannerConfig) {
    this.presidioUrl = config.presidioUrl;
    this.minScore = config.presidioMinScore;
    this.timeoutMs = config.presidioTimeoutMs;
  }

  /**
   * Send content to Presidio for PII analysis.
   *
   * @param content - Text to analyze
   * @param context - Pipeline context with pattern definitions
   * @returns Stage result with structural PII flags
   */
  async execute(content: string, context: PipelineContext): Promise<StageResult> {
    const startTime = Date.now();
    try {
      // TODO: POST to Presidio /analyze endpoint
      //   - text: content
      //   - language: "en" (from locale config)
      //   - entities: derive from active patterns with presidio_recognizer
      //   - scoreThreshold: this.minScore
      // TODO: Parse PresidioAnalyzeResponse
      // TODO: Map each PresidioEntity to a ScanFlag:
      //   - Look up pattern by presidio_recognizer in context.patterns
      //   - Use pattern's default_classification
      //   - Apply destination rule overrides from context.destinationRules
      //   - Map Presidio score to flag confidence
      // TODO: Track timing, update lastSuccessAt
      throw new Error("Not implemented");
    } catch (error) {
      // TODO: Handle timeout, connection refused, HTTP errors
      // TODO: Update consecutiveErrors, lastErrorAt
      // TODO: Return empty stage result with error note
      return {
        stageName: this.name,
        executed: true,
        durationMs: Date.now() - startTime,
        flags: [],
        error: (error as Error).message,
      };
    }
  }

  shouldRun(
    _destination: DestinationInfo,
    _posture: PostureLevel,
    _previousFlags: ScanFlag[]
  ): boolean {
    // Presidio always runs (it is the primary detection stage)
    // Exception: if consecutiveErrors > 10, skip until Auditor resets
    return this.consecutiveErrors < 10;
  }

  /** Get Presidio service health for the Scanner's health check. */
  getServiceHealth(): { available: boolean; lastSuccessAt: number; lastErrorAt: number; consecutiveErrors: number } {
    return {
      available: this.consecutiveErrors < 10,
      lastSuccessAt: this.lastSuccessAt,
      lastErrorAt: this.lastErrorAt,
      consecutiveErrors: this.consecutiveErrors,
    };
  }
}


// ═══════════════════════════════════════════════════════════════
// STAGE 2: DETECT-SECRETS (CREDENTIAL DETECTION)
// ═══════════════════════════════════════════════════════════════

/**
 * DetectSecretsStage invokes the detect-secrets Python CLI
 * to scan for credentials, API keys, and other secrets.
 */
export class DetectSecretsStage implements ScanStageHandler {
  readonly name = "detect_secrets" as const;
  private readonly execPath: string;
  private readonly enabled: boolean;

  constructor(config: ScannerConfig) {
    this.execPath = config.detectSecretsPath;
    this.enabled = config.detectSecretsEnabled;
  }

  /**
   * Invoke detect-secrets via subprocess.
   *
   * @param content - Text to scan for secrets
   * @param context - Pipeline context
   * @returns Stage result with credential flags
   */
  async execute(content: string, context: PipelineContext): Promise<StageResult> {
    const startTime = Date.now();
    try {
      // TODO: Write content to a temp file (not stdin for reliability)
      // TODO: execFile(this.execPath, ['scan', '--list', tempFile])
      // TODO: Parse JSON output
      // TODO: Map each detected secret to a ScanFlag:
      //   - source: CREDENTIAL
      //   - entityType: detector name (e.g., "AWSKeyDetector")
      //   - confidence: 0.80 for specific detectors, 0.50 for HighEntropyString
      //   - classificationLevel: NEVER_SHARE for credentials
      // TODO: Clean up temp file
      throw new Error("Not implemented");
    } catch (error) {
      return {
        stageName: this.name,
        executed: true,
        durationMs: Date.now() - startTime,
        flags: [],
        error: (error as Error).message,
      };
    }
  }

  shouldRun(
    destination: DestinationInfo,
    posture: PostureLevel,
    previousFlags: ScanFlag[]
  ): boolean {
    if (!this.enabled) return false;
    // Run when: destination is PUBLIC_PLATFORM, posture is RED/BLACK,
    // or previous stages already raised flags
    return (
      destination.type === "PUBLIC_PLATFORM" ||
      posture === "RED" ||
      posture === "BLACK" ||
      previousFlags.length > 0
    );
  }
}


// ═══════════════════════════════════════════════════════════════
// STAGE 3: FUZZY MATCHING (FUSE.JS)
// ═══════════════════════════════════════════════════════════════

/**
 * FuzzyMatchStage uses fuse.js to match content against user-defined
 * sensitive entries in the registry. Performs both full-content and
 * token-level searches.
 */
export class FuzzyMatchStage implements ScanStageHandler {
  readonly name = "fuzzy_match" as const;
  private fuseIndex: Fuse<SearchableEntry> | null = null;
  private readonly threshold: number;
  private readonly distance: number;
  private readonly minMatchCharLength: number;

  constructor(config: ScannerConfig) {
    this.threshold = config.fuseThreshold;
    this.distance = config.fuseDistance;
    this.minMatchCharLength = config.fuseMinMatchCharLength;
  }

  /**
   * Build the fuse.js index from registry entries.
   * Called on startup and when registry changes.
   *
   * @param entries - Searchable entries loaded from registry
   */
  buildIndex(entries: SearchableEntry[]): void {
    // TODO: Create Fuse instance with configuration:
    //   keys: ['primaryValue', 'variants']
    //   threshold: this.threshold
    //   distance: this.distance
    //   includeScore: true
    //   includeMatches: true
    //   minMatchCharLength: this.minMatchCharLength
    //   useExtendedSearch: true
    this.fuseIndex = new Fuse(entries, {
      keys: [
        { name: "primaryValue", weight: 1.0 },
        { name: "variants", weight: 0.8 },
      ],
      threshold: this.threshold,
      distance: this.distance,
      includeScore: true,
      includeMatches: true,
      minMatchCharLength: this.minMatchCharLength,
      useExtendedSearch: true,
    });
  }

  /**
   * Search content against user-defined entries.
   *
   * @param content - Text to search
   * @param context - Pipeline context
   * @returns Stage result with fuzzy/exact match flags
   */
  async execute(content: string, context: PipelineContext): Promise<StageResult> {
    const startTime = Date.now();
    const flags: ScanFlag[] = [];

    if (!this.fuseIndex) {
      return {
        stageName: this.name,
        executed: false,
        durationMs: 0,
        flags: [],
        error: "fuse.js index not initialized",
      };
    }

    try {
      // TODO: Pass 1 — Full content search
      //   Search the entire content string against all entries
      //   Map results to ScanFlags with position info

      // TODO: Pass 2 — Token-level search
      //   Tokenize content (using natural or whitespace split)
      //   Search each token individually
      //   Deduplicate with Pass 1 results

      // TODO: Detect tagged format [SENSITIVE:type:value]
      //   Cross-reference with registry entries
      //   Tagged matches get confidence 1.0

      // TODO: Apply destination rule overrides to classification levels

      // TODO: Convert fuse.js score to confidence:
      //   confidence = 1.0 - fuseScore
      //   confidence > 0.95 → EXACT_MATCH source
      //   confidence 0.65-0.95 → FUZZY_MATCH source
      //   confidence < 0.65 → discard (below threshold)

      throw new Error("Not implemented");
    } catch (error) {
      return {
        stageName: this.name,
        executed: true,
        durationMs: Date.now() - startTime,
        flags,
        error: (error as Error).message,
      };
    }
  }

  shouldRun(
    _destination: DestinationInfo,
    _posture: PostureLevel,
    _previousFlags: ScanFlag[]
  ): boolean {
    // fuse.js always runs — it is the only stage that checks
    // user-defined entries. Without it, custom sensitive data
    // (family names, technology references) would go undetected.
    return this.fuseIndex !== null;
  }
}


// ═══════════════════════════════════════════════════════════════
// DESTINATION CLASSIFIER
// ═══════════════════════════════════════════════════════════════

/**
 * DestinationClassifier categorizes outbound tool call targets
 * into destination types using configurable patterns from the
 * destinations table.
 */
export class DestinationClassifier {
  private patterns: LoadedDestinationPattern[] = [];
  private extractors: Map<string, ContentExtractor> = new Map();

  /**
   * Load destination patterns from the registry.
   *
   * @param destinations - Rows from the destinations table
   */
  loadPatterns(destinations: Array<{
    destination_type: string;
    target_pattern: string;
    label: string;
    is_public: number;
  }>): void {
    // TODO: Compile target_pattern strings into RegExp objects
    // TODO: Store as LoadedDestinationPattern array
    // TODO: Register default content extractors for known tools
    throw new Error("Not implemented");
  }

  /**
   * Classify the destination of an outbound tool call.
   *
   * @param toolName - The tool being called
   * @param toolArgs - The tool call arguments
   * @returns Classified destination info
   */
  classify(toolName: string, toolArgs: Record<string, unknown>): DestinationInfo {
    // TODO: Extract target URL/channel/path from toolArgs based on toolName
    // TODO: Match against loaded patterns
    // TODO: Return DestinationInfo with type, target, label, isPublic
    // TODO: Default to UNKNOWN with isPublic: true if no match
    throw new Error("Not implemented");
  }

  /**
   * Extract text content from tool call arguments.
   * Uses tool-specific extractors where registered; falls back to
   * stringifying all string values in the args.
   *
   * @param toolName - Tool being called
   * @param toolArgs - Arguments to extract content from
   * @returns Extracted text content
   */
  extractContent(toolName: string, toolArgs: Record<string, unknown>): ExtractedContent {
    // TODO: Check if a tool-specific extractor is registered
    // TODO: If yes, use it
    // TODO: If no, walk toolArgs recursively and concatenate all string values
    throw new Error("Not implemented");
  }

  /**
   * Register a content extractor for a specific tool.
   *
   * @param toolName - Tool name (e.g., "web_fetch", "whatsapp_send")
   * @param extractor - Extraction function
   */
  registerExtractor(toolName: string, extractor: ContentExtractor): void {
    this.extractors.set(toolName, extractor);
  }
}


// ═══════════════════════════════════════════════════════════════
// REGISTRY LOADER
// ═══════════════════════════════════════════════════════════════

/**
 * RegistryLoader handles database access for preloading patterns,
 * entries, variants, and destination rules into memory. All database
 * queries use prepared statements with bound parameters.
 */
export class RegistryLoader {
  private readonly config: ScannerConfig;
  private db: Database.Database | null = null;

  constructor(config: ScannerConfig) {
    this.config = config;
  }

  /**
   * Open database connection with required pragmas.
   *
   * @param dbPath - Path to registry.db
   */
  connect(dbPath: string): void {
    // TODO: Open database with better-sqlite3
    // TODO: Set pragmas: WAL, busy_timeout, foreign_keys, synchronous, cache_size, temp_store, mmap_size
    // TODO: Verify file permissions (600)
    throw new Error("Not implemented");
  }

  /**
   * Load all active patterns for the given locales.
   *
   * @param localeIds - Active locale IDs
   * @returns Array of PatternDefinition
   */
  loadPatterns(localeIds: string[]): PatternDefinition[] {
    // TODO: SELECT * FROM patterns WHERE locale_id IN (?) AND is_active = 1
    throw new Error("Not implemented");
  }

  /**
   * Load all active user entries with their variants.
   *
   * @returns Array of SearchableEntry (entries + variants merged)
   */
  loadEntriesWithVariants(): SearchableEntry[] {
    // TODO: SELECT from v_entries_with_variants view
    // TODO: Parse variants (split by '|||')
    // TODO: Return SearchableEntry array
    throw new Error("Not implemented");
  }

  /**
   * Load all destination rules for active entries.
   *
   * @returns Array of LoadedDestinationRule with compiled regex
   */
  loadDestinationRules(): LoadedDestinationRule[] {
    // TODO: SELECT from destination_rules JOIN user_entries
    // TODO: Compile target_pattern to RegExp where not null
    throw new Error("Not implemented");
  }

  /**
   * Load destination patterns for the classifier.
   *
   * @returns Rows from the destinations table
   */
  loadDestinations(): Array<{
    destination_type: string;
    target_pattern: string;
    label: string;
    is_public: number;
  }> {
    // TODO: SELECT from destinations WHERE is_active = 1
    throw new Error("Not implemented");
  }

  /**
   * Write a scan decision record to the database.
   *
   * @param decision - The scan decision to log
   */
  writeScanDecision(decision: ScanDecisionRow): void {
    // TODO: INSERT INTO scan_decisions (...)
    // TODO: INSERT INTO scan_flags for each flag
    throw new Error("Not implemented");
  }

  /**
   * Write or update an inventory entry.
   *
   * @param entry - Inventory entry to upsert
   */
  upsertInventory(entry: InventoryEntry): void {
    // TODO: INSERT OR REPLACE INTO inventory (...)
    throw new Error("Not implemented");
  }

  /**
   * Write a quarantine entry.
   *
   * @param quarantine - Quarantine record
   */
  writeQuarantine(quarantine: QuarantineRow): void {
    // TODO: INSERT INTO quarantine_queue (...)
    throw new Error("Not implemented");
  }

  /**
   * Close the database connection.
   */
  close(): void {
    this.db?.close();
    this.db = null;
  }
}

/** Row shape for scan_decisions INSERT. */
export interface ScanDecisionRow {
  request_id: string;
  timestamp: string;
  direction: string;
  session_id: string;
  agent_id: string;
  tool_name: string | null;
  content_hash: string;
  content_length: number;
  destination_type: string | null;
  destination_target: string | null;
  destination_label: string | null;
  destination_public: number | null;
  source_channel: string | null;
  source_id: string | null;
  posture_level: string;
  scanner_verdict: string;
  scanner_duration_ms: number;
  flag_count: number;
  flag_summary: string | null;
  stages_executed: string | null;
  quarantine_id: string | null;
  final_outcome: string;
  total_duration_ms: number;
  approval_token: string | null;
}

/** Row shape for quarantine_queue INSERT. */
export interface QuarantineRow {
  quarantine_id: string;
  request_id: string;
  tool_name: string;
  tool_args_encrypted: string;
  content_hash: string;
  destination_type: string;
  destination_target: string;
  destination_label: string;
  destination_public: number;
  state: string;
}


// ═══════════════════════════════════════════════════════════════
// APPROVAL TOKEN GENERATOR
// ═══════════════════════════════════════════════════════════════

/**
 * Generates and verifies HMAC-SHA256 approval tokens.
 * These tokens are the hard dependency between the watchdog
 * and the gateway — without a valid token, no payload transmits.
 */
export class ApprovalTokenGenerator {
  private readonly key: string;

  constructor(hmacKey: string) {
    this.key = hmacKey;
  }

  /**
   * Generate an approval token for a clean scan.
   *
   * @param requestId - The scan request ID
   * @param contentHash - SHA-256 hash of the scanned content
   * @param timestamp - ISO 8601 timestamp of the verdict
   * @param verdict - The scan verdict ("CLEAN" or final decision)
   * @returns Signed HMAC-SHA256 token
   */
  generate(requestId: string, contentHash: string, timestamp: string, verdict: string): string {
    // TODO: HMAC-SHA256 over (requestId + contentHash + timestamp + verdict)
    // TODO: Return hex-encoded signature
    const payload = `${requestId}:${contentHash}:${timestamp}:${verdict}`;
    return createHmac("sha256", this.key).update(payload).digest("hex");
  }

  /**
   * Verify an approval token.
   *
   * @param token - Token to verify
   * @param requestId - Expected request ID
   * @param contentHash - Expected content hash
   * @param timestamp - Expected timestamp
   * @param verdict - Expected verdict
   * @returns true if token is valid
   */
  verify(token: string, requestId: string, contentHash: string, timestamp: string, verdict: string): boolean {
    const expected = this.generate(requestId, contentHash, timestamp, verdict);
    // Timing-safe comparison
    if (token.length !== expected.length) return false;
    let result = 0;
    for (let i = 0; i < token.length; i++) {
      result |= token.charCodeAt(i) ^ expected.charCodeAt(i);
    }
    return result === 0;
  }
}


// ═══════════════════════════════════════════════════════════════
// QUARANTINE MANAGER
// ═══════════════════════════════════════════════════════════════

/**
 * Manages the quarantine lifecycle for flagged payloads.
 * Handles encryption of tool args and state transitions.
 */
export class QuarantineManager {
  /**
   * Create a quarantine entry for a flagged payload.
   *
   * @param requestId - Scan request ID
   * @param toolName - Tool that was called
   * @param toolArgs - Full tool call arguments (will be encrypted)
   * @param contentHash - SHA-256 of the content
   * @param destination - Destination info
   * @returns Quarantine ID and encrypted row
   */
  createQuarantine(
    requestId: string,
    toolName: string,
    toolArgs: Record<string, unknown>,
    contentHash: string,
    destination: DestinationInfo
  ): { quarantineId: string; row: QuarantineRow } {
    // TODO: Generate quarantine ID (quar- prefix + short UUID)
    // TODO: Encrypt toolArgs with AES-256-GCM using config key
    // TODO: Return quarantine ID and row for database insert
    throw new Error("Not implemented");
  }

  /**
   * Encrypt tool arguments for storage.
   *
   * @param toolArgs - Arguments to encrypt
   * @param key - Encryption key
   * @returns Base64-encoded ciphertext with IV prepended
   */
  encryptToolArgs(toolArgs: Record<string, unknown>, key: Buffer): string {
    // TODO: AES-256-GCM encryption
    // TODO: Random 12-byte IV
    // TODO: Return iv:ciphertext:authTag as base64
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// SECURITY AGENT CLIENT
// ═══════════════════════════════════════════════════════════════

/**
 * HTTP client for sending classification requests to the
 * Security Agent (Layer 2).
 */
export class SecurityAgentClient {
  private readonly agentUrl: string;

  constructor(agentUrl: string) {
    this.agentUrl = agentUrl;
  }

  /**
   * Send a classification request to the Security Agent.
   * This is fire-and-forget from the Scanner's perspective —
   * the Security Agent processes asynchronously and updates
   * the quarantine state directly in the database.
   *
   * @param request - Classification request payload
   */
  async requestClassification(request: ClassificationRequest): Promise<void> {
    // TODO: POST to ${this.agentUrl}/classify
    // TODO: Set timeout (15s per config)
    // TODO: Fire-and-forget — don't await full classification
    // TODO: Handle connection errors (log, Auditor notification)
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// DECISION LOGGER
// ═══════════════════════════════════════════════════════════════

/**
 * Logs scan decisions to the database. Handles content hashing
 * (never stores raw content) and flag summarization.
 */
export class DecisionLogger {
  /**
   * Hash content for storage in the audit log.
   * Raw content is NEVER stored — only the SHA-256 hash.
   *
   * @param content - Raw content to hash
   * @returns SHA-256 hex digest
   */
  hashContent(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }

  /**
   * Build a human-readable flag summary for the scan_decisions table.
   *
   * @param flags - Flags to summarize
   * @returns JSON string of flag summary
   */
  summarizeFlags(flags: ScanFlag[]): string {
    // TODO: Create concise summary of each flag:
    //   { entityType, source, confidence, classificationLevel }
    // TODO: Return JSON string
    return JSON.stringify(
      flags.map(f => ({
        type: f.entityType,
        source: f.source,
        confidence: f.confidence,
        level: f.classificationLevel,
      }))
    );
  }

  /**
   * Determine the final outcome string for the scan_decisions table.
   *
   * @param verdict - Scanner verdict
   * @param direction - Scan direction
   * @returns Final outcome string
   */
  determineFinalOutcome(
    verdict: "CLEAN" | "FLAGGED",
    direction: "OUTBOUND" | "INBOUND"
  ): string {
    if (direction === "INBOUND") {
      return verdict === "CLEAN" ? "inspected_clean" : "inventoried";
    }
    // For outbound, final outcome depends on Security Agent / escalation
    // At Scanner level, we only know: transmitted (CLEAN) or pending (FLAGGED)
    return verdict === "CLEAN" ? "transmitted" : "blocked"; // Updated later by agent/escalation
  }
}


// ═══════════════════════════════════════════════════════════════
// RESULT CACHE
// ═══════════════════════════════════════════════════════════════

/**
 * LRU cache for scan results, providing idempotency on duplicate
 * requestIds (gateway retries).
 */
export class ResultCache {
  private readonly maxSize: number;
  private readonly maxAge: number;
  private cache: Map<string, CachedResult> = new Map();

  constructor(maxSize: number, maxAge: number) {
    this.maxSize = maxSize;
    this.maxAge = maxAge;
  }

  /**
   * Get a cached result by request ID.
   *
   * @param requestId - Scan request ID
   * @returns Cached result if found and not expired, null otherwise
   */
  get(requestId: string): OutboundScanResult | InboundInspectionResult | null {
    const entry = this.cache.get(requestId);
    if (!entry) return null;
    if (Date.now() - entry.cachedAt > this.maxAge) {
      this.cache.delete(requestId);
      return null;
    }
    return entry.result;
  }

  /**
   * Store a scan result in the cache.
   *
   * @param requestId - Scan request ID
   * @param result - Result to cache
   */
  set(requestId: string, result: OutboundScanResult | InboundInspectionResult): void {
    // LRU eviction if at capacity
    if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }
    this.cache.set(requestId, { result, cachedAt: Date.now() });
  }

  /**
   * Clear all cached results.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get current cache size.
   */
  get size(): number {
    return this.cache.size;
  }
}


// ═══════════════════════════════════════════════════════════════
// CONTENT EXTRACTORS (for known tools)
// ═══════════════════════════════════════════════════════════════

/**
 * Pre-built content extractors for common OpenClaw tools.
 * These know the structure of each tool's arguments and
 * extract the text fields that need scanning.
 */
export const CONTENT_EXTRACTORS: Record<string, ContentExtractor> = {
  /**
   * web_fetch: Extract body content for POST/PUT, URL for GET.
   */
  web_fetch: (toolArgs: Record<string, unknown>): ExtractedContent => {
    const parts: string[] = [];
    const fields: string[] = [];

    const method = (toolArgs.method as string || "GET").toUpperCase();
    if (toolArgs.url) {
      parts.push(String(toolArgs.url));
      fields.push("url");
    }
    if (method === "POST" || method === "PUT") {
      const body = toolArgs.body;
      if (typeof body === "string") {
        parts.push(body);
        fields.push("body");
      } else if (body && typeof body === "object") {
        // Recursively extract string values from body object
        const extractStrings = (obj: unknown, prefix: string): void => {
          if (typeof obj === "string") {
            parts.push(obj);
            fields.push(prefix);
          } else if (obj && typeof obj === "object") {
            for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
              extractStrings(v, `${prefix}.${k}`);
            }
          }
        };
        extractStrings(body, "body");
      }
    }

    const text = parts.join("\n");
    return { text, sourceFields: fields, charCount: text.length };
  },

  /**
   * whatsapp_send / telegram_send / discord_send: Extract message text.
   */
  whatsapp_send: (toolArgs: Record<string, unknown>): ExtractedContent => {
    const text = String(toolArgs.text || toolArgs.message || toolArgs.content || "");
    return { text, sourceFields: ["text"], charCount: text.length };
  },

  /**
   * exec: Extract command string (for file writes, look for redirect/echo).
   */
  exec: (toolArgs: Record<string, unknown>): ExtractedContent => {
    const command = String(toolArgs.command || toolArgs.cmd || "");
    return { text: command, sourceFields: ["command"], charCount: command.length };
  },

  /**
   * file_write: Extract file content.
   */
  file_write: (toolArgs: Record<string, unknown>): ExtractedContent => {
    const content = String(toolArgs.content || toolArgs.data || toolArgs.text || "");
    return { text: content, sourceFields: ["content"], charCount: content.length };
  },
};

// Alias shared tools
CONTENT_EXTRACTORS.telegram_send = CONTENT_EXTRACTORS.whatsapp_send;
CONTENT_EXTRACTORS.discord_send = CONTENT_EXTRACTORS.whatsapp_send;
CONTENT_EXTRACTORS.signal_send = CONTENT_EXTRACTORS.whatsapp_send;


// ═══════════════════════════════════════════════════════════════
// TAGGED FORMAT DETECTOR
// ═══════════════════════════════════════════════════════════════

/**
 * Detects [SENSITIVE:type:value] tags in content and cross-references
 * them with registry entries.
 */
export class TaggedFormatDetector {
  /** Regex to match tagged format. */
  private static readonly TAG_REGEX = /\[SENSITIVE:([^:]+):([^\]]+)\]/gi;

  /**
   * Scan content for tagged sensitive data markers.
   *
   * @param content - Text to scan
   * @param entries - Registry entries for cross-reference
   * @returns Array of ScanFlags for matched tags
   */
  detect(content: string, entries: SearchableEntry[]): ScanFlag[] {
    const flags: ScanFlag[] = [];
    let match: RegExpExecArray | null;

    // Reset regex lastIndex for safety
    TaggedFormatDetector.TAG_REGEX.lastIndex = 0;

    while ((match = TaggedFormatDetector.TAG_REGEX.exec(content)) !== null) {
      const [fullMatch, type, value] = match;
      const offsetStart = match.index;
      const offsetEnd = offsetStart + fullMatch.length;

      // TODO: Cross-reference type and value against entries
      // TODO: If matched, use entry's classification
      // TODO: If not matched, flag as UNKNOWN with ASK_FIRST
      // TODO: Tagged matches always have confidence 1.0

      flags.push({
        flagId: randomUUID(),
        source: "EXACT_MATCH" as FlagSource,
        entityType: `tagged:${type}`,
        matchedText: value,
        confidence: 1.0,
        offsetStart,
        offsetEnd,
        classificationLevel: null, // TODO: Resolve from registry
        registryEntryId: null,     // TODO: Resolve from registry
      });
    }

    return flags;
  }
}


// ═══════════════════════════════════════════════════════════════
// FLAG DEDUPLICATION
// ═══════════════════════════════════════════════════════════════

/**
 * Deduplicates overlapping flags from different pipeline stages.
 * When two flags cover the same text span, the higher-confidence
 * flag is retained.
 */
export function deduplicateFlags(flags: ScanFlag[]): ScanFlag[] {
  if (flags.length <= 1) return flags;

  // Sort by offsetStart, then by confidence descending
  const sorted = [...flags].sort((a, b) => {
    if (a.offsetStart !== b.offsetStart) return a.offsetStart - b.offsetStart;
    return b.confidence - a.confidence;
  });

  const result: ScanFlag[] = [];
  let lastEnd = -1;

  for (const flag of sorted) {
    // If this flag overlaps with the previous retained flag,
    // keep only the higher-confidence one (already sorted)
    if (flag.offsetStart < lastEnd) {
      // Overlapping — skip lower-confidence flag
      continue;
    }
    result.push(flag);
    lastEnd = flag.offsetEnd;
  }

  return result;
}


// ═══════════════════════════════════════════════════════════════
// MODULE EXPORTS
// ═══════════════════════════════════════════════════════════════

export {
  PatternScanner as default,
  PatternScanner,
};
