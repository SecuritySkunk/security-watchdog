/**
 * Security Watchdog — Human Escalation Interface
 *
 * Module:       09 — Human Escalation Interface
 * Document ID:  SWDOG-MOD-009
 * Version:      1.0 DRAFT
 * Generated:    February 2026
 *
 * This module routes ambiguous Security Agent decisions to the system
 * owner for human judgment. It manages the full escalation lifecycle:
 * create → format → send → await → process → confirm.
 *
 * Implements interfaces IF-007 (Security Agent → Escalation) and
 * IF-008 (Escalation → Gateway / User Messaging).
 *
 * ────────────────────────────────────────────────────────────────
 * DEPENDENCIES:
 *   - @watchdog/types      (shared type definitions)
 *   - better-sqlite3       (escalation persistence)
 *   - crypto               (approval token generation, short ID derivation)
 * ────────────────────────────────────────────────────────────────
 */

import type Database from "better-sqlite3";
import type {
  EscalationRequest,
  EscalationStatus,
  EscalationMessage,
  EscalationReply,
  EscalationResponse,
  EscalationConfig,
  ScanFlag,
  DestinationInfo,
  ClassificationLevel,
  HealthCheckResponse,
  HealthStatus,
  WatchdogError,
  WatchdogErrorCode,
  PostureLevel,
} from "@watchdog/types";


// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

/**
 * Complete configuration for the Escalation Interface.
 * Loaded from ~/.openclaw/security/config.json → escalation key.
 */
export interface EscalationInterfaceConfig {
  /** Primary messaging channel for escalation notifications. */
  preferredChannel: string;
  /** Fallback channel if primary is unavailable. Null = no fallback. */
  fallbackChannel: string | null;
  /** Target peer ID on the channel (phone number, username, etc.). */
  peerId: string;
  /** Default timeout in seconds before an escalation is auto-denied. */
  defaultTimeoutSeconds: number;
  /** Whether to send reminder messages before timeout. */
  sendReminders: boolean;
  /** Seconds before expiry to send a reminder. */
  reminderBeforeExpirySeconds: number;
  /** Batch window: accumulate escalations arriving within this many seconds. */
  batchWindowSeconds: number;
  /** Maximum number of escalations in a single batched message. */
  maxBatchSize: number;
  /** Maximum total delay for batch accumulation in seconds. */
  maxBatchDelaySeconds: number;
  /** Maximum pending escalations before auto-deny. */
  maxPendingEscalations: number;
  /** Time window in seconds for confirming bulk operations (APPROVE-ALL, DENY-ALL). */
  bulkConfirmTimeoutSeconds: number;
  /** HMAC key for generating approval tokens. */
  hmacKey: string;
}

/** Default configuration values. */
export const DEFAULT_ESCALATION_CONFIG: EscalationInterfaceConfig = {
  preferredChannel: "whatsapp",
  fallbackChannel: null,
  peerId: "",
  defaultTimeoutSeconds: 900,
  sendReminders: true,
  reminderBeforeExpirySeconds: 300,
  batchWindowSeconds: 5,
  maxBatchSize: 10,
  maxBatchDelaySeconds: 15,
  maxPendingEscalations: 50,
  bulkConfirmTimeoutSeconds: 60,
  hmacKey: "",
};


// ═══════════════════════════════════════════════════════════════
// INTERNAL TYPES
// ═══════════════════════════════════════════════════════════════

/** Internal representation of a pending escalation in the queue. */
interface PendingEscalation {
  /** Full UUID escalation ID (stored in database). */
  escalationId: string;
  /** Short ID for user-facing messages (e.g., "esc-a1b2c3d4"). */
  shortId: string;
  /** Associated quarantine ID. */
  quarantineId: string;
  /** Original scan request ID. */
  requestId: string;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** ISO 8601 expiry timestamp. */
  expiresAt: string;
  /** Timeout in seconds. */
  timeoutSeconds: number;
  /** Human-readable summary of the flagged content. */
  summary: string;
  /** Destination info for the flagged tool call. */
  destination: DestinationInfo;
  /** Flags that triggered escalation. */
  flags: ScanFlag[];
  /** Security Agent's reasoning for escalation. */
  agentReasoning: string;
  /** Channel the escalation message was sent on. */
  sentOnChannel: string | null;
  /** Whether the message has been sent. */
  messageSent: boolean;
  /** Whether a reminder has been sent. */
  reminderSent: boolean;
  /** Node.js timeout handle for expiry. */
  timeoutHandle: ReturnType<typeof setTimeout> | null;
  /** Node.js timeout handle for reminder. */
  reminderHandle: ReturnType<typeof setTimeout> | null;
  /** Priority score (lower = higher priority). */
  priority: number;
}

/** Parsed response from a user reply. */
interface ParsedResponse {
  /** The response type. */
  type: "APPROVE" | "DENY" | "DENY_AND_ADD" | "APPROVE_ALL" | "DENY_ALL" | "STATUS";
  /** Escalation ID extracted from the response (null for STATUS / bulk ops). */
  escalationId: string | null;
  /** Raw text of the user's reply. */
  rawText: string;
}

/** Result of a batch accumulation window. */
interface BatchedEscalations {
  /** The escalations accumulated in this batch. */
  items: PendingEscalation[];
  /** Formatted message for the batch. */
  message: string;
}

/** Pending bulk operation awaiting confirmation. */
interface PendingBulkOperation {
  /** Operation type. */
  type: "APPROVE_ALL" | "DENY_ALL";
  /** ISO 8601 timestamp when the bulk operation was requested. */
  requestedAt: string;
  /** ISO 8601 timestamp when confirmation expires. */
  expiresAt: string;
  /** Number of escalations that would be affected. */
  count: number;
  /** Timeout handle for confirmation window. */
  timeoutHandle: ReturnType<typeof setTimeout> | null;
}


// ═══════════════════════════════════════════════════════════════
// CHANNEL ADAPTER INTERFACE
// ═══════════════════════════════════════════════════════════════

/**
 * Abstract interface for messaging channel communication.
 *
 * Implementations wrap OpenClaw's Gateway WebSocket RPC to send
 * and receive messages on a specific channel (WhatsApp, Telegram, etc.).
 *
 * The Escalation Interface depends on this abstraction rather than
 * directly on the Gateway, enabling mock adapters for testing.
 */
export interface ChannelAdapter {
  /**
   * Send a text message to a peer on a channel.
   *
   * @param channel  - Channel identifier (e.g., "whatsapp", "telegram")
   * @param peerId   - Target peer ID (phone number, username, etc.)
   * @param text     - Message text to send
   * @returns Promise resolving to true if sent successfully, false on failure
   */
  sendMessage(channel: string, peerId: string, text: string): Promise<boolean>;

  /**
   * Register a callback for incoming messages on the escalation channel.
   *
   * The callback receives every message from the configured peerId.
   * The Escalation Interface filters for response codes internally.
   *
   * @param callback - Function called with (channel, peerId, text, timestamp)
   */
  onMessage(
    callback: (channel: string, peerId: string, text: string, timestamp: string) => void
  ): void;

  /**
   * Check if a channel is currently connected and available.
   *
   * @param channel - Channel identifier
   * @returns Promise resolving to true if the channel can send messages
   */
  isAvailable(channel: string): Promise<boolean>;

  /**
   * Disconnect and clean up resources.
   */
  destroy(): void;
}


// ═══════════════════════════════════════════════════════════════
// ESCALATION FORMATTER
// ═══════════════════════════════════════════════════════════════

/**
 * Formats human-readable messages for escalation notifications,
 * confirmations, and status reports.
 *
 * All methods are pure functions — no side effects, no state.
 * Messages are plain text optimized for mobile display (< 1000
 * characters for single escalations, < 2000 for batched).
 */
export class EscalationFormatter {
  /**
   * Format a single escalation notification message.
   *
   * @param escalation - The pending escalation to format
   * @returns Plain text message ready to send
   */
  formatSingleNotification(escalation: PendingEscalation): string {
    // TODO: Implement message formatting per Section 3.1 of the module spec
    // Template:
    //   ⚠️ WATCHDOG ESCALATION
    //
    //   {agent_name} wants to {action} {destination}.
    //
    //   Flagged:
    //   • {flag_list}
    //
    //   Agent: {agent_reasoning}
    //
    //   Reply:
    //     APPROVE-{shortId}
    //     DENY-{shortId}
    //     DENY-ADD-{shortId}
    //
    //   Expires in {timeout_minutes} min. No reply = DENY.
    throw new Error("Not implemented");
  }

  /**
   * Format a batched escalation notification for multiple pending items.
   *
   * @param escalations - Array of pending escalations to include
   * @returns Plain text batched message ready to send
   */
  formatBatchedNotification(escalations: PendingEscalation[]): string {
    // TODO: Implement batched formatting per Section 3.2 of the module spec
    // Include individual response codes for each item plus APPROVE-ALL / DENY-ALL
    throw new Error("Not implemented");
  }

  /**
   * Format an approval confirmation message.
   *
   * @param escalation - The escalation that was approved
   * @returns Confirmation message text
   */
  formatApprovalConfirmation(escalation: PendingEscalation): string {
    // TODO: Implement per Section 3.3
    // Template: ✅ APPROVED: {agent_name}'s {destination} {action}
    //           Content transmitted.
    throw new Error("Not implemented");
  }

  /**
   * Format a denial confirmation message.
   *
   * @param escalation   - The escalation that was denied
   * @param addedToRegistry - Whether the content was also added to registry
   * @returns Confirmation message text
   */
  formatDenialConfirmation(
    escalation: PendingEscalation,
    addedToRegistry: boolean
  ): string {
    // TODO: Implement per Sections 3.4 and 3.5
    // If addedToRegistry, include the "added to registry as NEVER_SHARE" line
    throw new Error("Not implemented");
  }

  /**
   * Format a timeout notification message.
   *
   * @param escalation - The escalation that timed out
   * @returns Timeout notification text
   */
  formatTimeoutNotification(escalation: PendingEscalation): string {
    // TODO: Implement per Section 3.6
    // Template: ⏰ EXPIRED: {agent_name}'s {destination} {action}
    //           No response received. Content blocked (fail-closed).
    throw new Error("Not implemented");
  }

  /**
   * Format a status response listing all pending escalations.
   *
   * @param pending - All currently pending escalations
   * @returns Status message text, or "no pending" message if empty
   */
  formatStatusResponse(pending: PendingEscalation[]): string {
    // TODO: Implement per Sections 3.7 and 3.8
    throw new Error("Not implemented");
  }

  /**
   * Format a reminder message for an escalation approaching timeout.
   *
   * @param escalation      - The escalation nearing expiry
   * @param minutesRemaining - Minutes until timeout
   * @returns Reminder message text
   */
  formatReminder(escalation: PendingEscalation, minutesRemaining: number): string {
    // TODO: Implement reminder message
    // Template: ⏳ REMINDER: {summary} expires in {minutesRemaining} min.
    //           Reply APPROVE-{shortId} or DENY-{shortId}.
    throw new Error("Not implemented");
  }

  /**
   * Format the confirmation prompt for bulk operations (APPROVE-ALL / DENY-ALL).
   *
   * @param operation - "APPROVE_ALL" or "DENY_ALL"
   * @param count     - Number of escalations that would be affected
   * @returns Confirmation prompt text
   */
  formatBulkConfirmation(operation: "APPROVE_ALL" | "DENY_ALL", count: number): string {
    // TODO: Implement per Section 4.3
    // Template: {Action} all {count} pending escalations? Reply YES to confirm.
    throw new Error("Not implemented");
  }

  /**
   * Format a help message listing valid response codes.
   *
   * @param pending - Currently pending escalations (to include their IDs)
   * @returns Help message text
   */
  formatHelpMessage(pending: PendingEscalation[]): string {
    // TODO: List valid response codes for each pending escalation
    throw new Error("Not implemented");
  }

  /**
   * Format flag details for display in escalation messages.
   * CRITICAL: Never include raw PII values — only labels and classifications.
   *
   * @param flags - Array of scan flags
   * @returns Formatted flag list string
   */
  formatFlags(flags: ScanFlag[]): string {
    // TODO: Format each flag as "• {entityType} — {classificationLevel}"
    // For user-defined entries, show the label. For structural PII, show the type name.
    // NEVER include the matchedText for structural PII (SSN, credit card, etc.)
    // For user-defined entries, the matchedText may be shown if the user explicitly
    // registered it (e.g., "6 children") since they already know the value.
    throw new Error("Not implemented");
  }

  /**
   * Map a tool name to a human-readable action verb.
   *
   * @param toolName        - The tool name from the scan request
   * @param destinationLabel - The destination label
   * @returns Human-readable action phrase (e.g., "post to Moltbook")
   */
  mapToolToAction(toolName: string, destinationLabel: string): string {
    // TODO: Map common tools to verbs:
    //   web_fetch (POST) → "post to {destination}"
    //   whatsapp_send    → "send WhatsApp message"
    //   telegram_send    → "send Telegram message"
    //   exec             → "execute command"
    //   write_file       → "write file"
    //   default          → "use {toolName} on {destination}"
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// RESPONSE PARSER
// ═══════════════════════════════════════════════════════════════

/**
 * Parses user response messages to extract escalation response codes.
 *
 * Parsing rules (from Section 4.2 of the module spec):
 * - Case-insensitive
 * - Whitespace-tolerant (spaces around hyphens stripped)
 * - Prefix matching (trailing text after valid code is ignored)
 * - First valid code wins if multiple are present
 */
export class ResponseParser {
  /**
   * Attempt to parse a response code from user reply text.
   *
   * @param text - Raw reply text from the user
   * @returns ParsedResponse if a valid code is found, null otherwise
   */
  parse(text: string): ParsedResponse | null {
    // TODO: Implement parsing logic
    // 1. Normalize: trim, collapse whitespace, uppercase
    // 2. Strip spaces around hyphens: "APPROVE - esc-abc" → "APPROVE-ESC-ABC"
    // 3. Check for STATUS command
    // 4. Check for APPROVE-ALL / DENY-ALL
    // 5. Check for APPROVE-{id} / DENY-{id} / DENY-ADD-{id}
    // 6. Extract escalation ID from the code
    // 7. Return null if no valid code found
    throw new Error("Not implemented");
  }

  /**
   * Check if a reply text is a bulk confirmation (YES, Y, CONFIRM).
   *
   * @param text - Raw reply text
   * @returns True if the text is a confirmation
   */
  isConfirmation(text: string): boolean {
    // TODO: Check for YES, Y, CONFIRM (case-insensitive, trimmed)
    throw new Error("Not implemented");
  }

  /**
   * Extract the short escalation ID from a full response code string.
   *
   * @param code - Full response code (e.g., "APPROVE-esc-a1b2c3d4")
   * @returns Short ID (e.g., "esc-a1b2c3d4") or null if not found
   */
  extractShortId(code: string): string | null {
    // TODO: Extract the "esc-XXXXXXXX" portion from the code
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// ESCALATION QUEUE
// ═══════════════════════════════════════════════════════════════

/**
 * In-memory priority queue of pending escalations, backed by SQLite
 * for crash recovery.
 *
 * Priority ordering:
 * 1. NEVER_SHARE flags first
 * 2. ASK_FIRST flags second
 * 3. INTERNAL_ONLY flags third
 * 4. Within same priority, FIFO (earliest creation time first)
 */
export class EscalationQueue {
  /** In-memory queue ordered by priority. */
  private queue: PendingEscalation[] = [];

  /** Map of short ID to pending escalation for fast lookup. */
  private shortIdMap: Map<string, PendingEscalation> = new Map();

  /** Map of full escalation ID to pending escalation. */
  private fullIdMap: Map<string, PendingEscalation> = new Map();

  /** Map of content hash to escalation ID for duplicate detection. */
  private contentHashMap: Map<string, string> = new Map();

  constructor(
    private readonly db: Database.Database,
    private readonly maxPending: number
  ) {}

  /**
   * Add an escalation to the queue. Persists to SQLite.
   *
   * @param escalation - The pending escalation to add
   * @returns True if added, false if queue is full or duplicate detected
   * @throws If database write fails
   */
  add(escalation: PendingEscalation): boolean {
    // TODO: Implement
    // 1. Check capacity (maxPending)
    // 2. Check for duplicates (contentHashMap)
    // 3. Insert into SQLite escalations table
    // 4. Add to in-memory queue (sorted by priority)
    // 5. Add to lookup maps
    throw new Error("Not implemented");
  }

  /**
   * Remove a resolved escalation from the queue.
   *
   * @param escalationId - The full escalation ID to remove
   * @returns The removed escalation, or null if not found
   */
  remove(escalationId: string): PendingEscalation | null {
    // TODO: Implement
    // 1. Find in fullIdMap
    // 2. Cancel timeout/reminder handles
    // 3. Remove from all maps and queue array
    // 4. Do NOT remove from SQLite (state is updated, not deleted)
    throw new Error("Not implemented");
  }

  /**
   * Find a pending escalation by its short ID.
   *
   * @param shortId - The short escalation ID (e.g., "esc-a1b2c3d4")
   * @returns The pending escalation, or null if not found or already resolved
   */
  findByShortId(shortId: string): PendingEscalation | null {
    // TODO: Lookup in shortIdMap
    throw new Error("Not implemented");
  }

  /**
   * Find a pending escalation by its full UUID.
   *
   * @param escalationId - The full escalation UUID
   * @returns The pending escalation, or null if not found
   */
  findById(escalationId: string): PendingEscalation | null {
    // TODO: Lookup in fullIdMap
    throw new Error("Not implemented");
  }

  /**
   * Check if an escalation with the same content hash and destination
   * is already pending (duplicate detection).
   *
   * @param contentHash    - SHA-256 hash of the content
   * @param destinationTarget - Destination target URL/path
   * @returns Existing escalation ID if duplicate, null otherwise
   */
  findDuplicate(contentHash: string, destinationTarget: string): string | null {
    // TODO: Check contentHashMap for key = contentHash + ":" + destinationTarget
    throw new Error("Not implemented");
  }

  /**
   * Get all currently pending escalations, ordered by priority.
   *
   * @returns Ordered array of pending escalations
   */
  getAllPending(): PendingEscalation[] {
    // TODO: Return copy of queue array
    throw new Error("Not implemented");
  }

  /**
   * Get the count of pending escalations.
   */
  get pendingCount(): number {
    return this.queue.length;
  }

  /**
   * Check if the queue is at capacity.
   */
  get isFull(): boolean {
    return this.queue.length >= this.maxPending;
  }

  /**
   * Reload pending escalations from SQLite.
   * Called on process startup to recover state.
   */
  loadFromDatabase(): void {
    // TODO: Implement
    // 1. Query: SELECT * FROM escalations WHERE state = 'pending' ORDER BY created_at
    // 2. Reconstruct PendingEscalation objects
    // 3. Compute priorities
    // 4. Insert into queue and maps
    // 5. Check for already-expired escalations (resolve immediately)
    throw new Error("Not implemented");
  }

  /**
   * Compute the priority score for an escalation based on its flags.
   * Lower number = higher priority.
   *
   * @param flags - Scan flags from the escalation
   * @returns Priority score (0 = highest)
   */
  private computePriority(flags: ScanFlag[]): number {
    // TODO: Implement priority scoring
    // NEVER_SHARE flag present → priority 0
    // ASK_FIRST flag present  → priority 1
    // INTERNAL_ONLY           → priority 2
    // No classification       → priority 3
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// TIMEOUT MANAGER
// ═══════════════════════════════════════════════════════════════

/**
 * Manages timeout and reminder timers for pending escalations.
 *
 * Each escalation gets two timers:
 * 1. Reminder timer: fires reminderBeforeExpirySeconds before expiry
 * 2. Expiry timer: fires at expiresAt, triggers auto-deny
 *
 * The Auditor daemon also polls the escalations table for expired
 * entries as a backup in case this process restarts.
 */
export class TimeoutManager {
  /** Active timeout handles keyed by escalation ID. */
  private timeouts: Map<string, ReturnType<typeof setTimeout>> = new Map();

  /** Active reminder handles keyed by escalation ID. */
  private reminders: Map<string, ReturnType<typeof setTimeout>> = new Map();

  constructor(private readonly config: EscalationInterfaceConfig) {}

  /**
   * Start timeout and reminder timers for a new escalation.
   *
   * @param escalationId  - The escalation ID
   * @param expiresAt     - ISO 8601 expiry timestamp
   * @param onTimeout     - Callback invoked when the escalation times out
   * @param onReminder    - Callback invoked when it's time to send a reminder
   */
  startTimers(
    escalationId: string,
    expiresAt: string,
    onTimeout: (escalationId: string) => void,
    onReminder: (escalationId: string) => void
  ): void {
    // TODO: Implement
    // 1. Calculate milliseconds until expiry
    // 2. Set expiry timer with setTimeout
    // 3. If sendReminders is enabled, calculate reminder time and set timer
    // 4. Store handles in maps
    throw new Error("Not implemented");
  }

  /**
   * Cancel all timers for an escalation (called when resolved early).
   *
   * @param escalationId - The escalation ID
   */
  cancelTimers(escalationId: string): void {
    // TODO: Clear both timeout and reminder for this escalation
    throw new Error("Not implemented");
  }

  /**
   * Cancel all active timers (called on shutdown).
   */
  cancelAll(): void {
    // TODO: Iterate all maps and clearTimeout each handle
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// REGISTRY LEARNER
// ═══════════════════════════════════════════════════════════════

/**
 * Updates the Sensitive Data Registry when the user responds with
 * DENY-ADD. This creates permanent entries so that similar content
 * is automatically blocked in future scans.
 */
export class RegistryLearner {
  constructor(private readonly db: Database.Database) {}

  /**
   * Add denied content to the registry as NEVER_SHARE.
   *
   * For each flag in the escalation:
   * - Creates a user_entries row (or upgrades existing)
   * - Creates entry_variants rows for matched text
   *
   * @param escalation - The escalation that was denied
   * @param flags      - The flags to add to registry
   * @returns Array of created/updated entry IDs
   */
  addToRegistry(escalation: PendingEscalation, flags: ScanFlag[]): number[] {
    // TODO: Implement within a SQLite transaction
    // For each flag:
    //   1. Check if user_entries row with same primary_value exists
    //      - If exists and classification < NEVER_SHARE → upgrade
    //      - If exists and classification = NEVER_SHARE → skip (add variants only)
    //      - If not exists → insert new row
    //   2. Derive label from entity type (e.g., "user:family_count" → "family_count")
    //   3. Insert entry_variants for matched text
    //   4. Log the registry update
    throw new Error("Not implemented");
  }

  /**
   * Derive a machine-readable label from an entity type.
   *
   * @param entityType - Entity type from the scan flag
   * @returns Label suitable for user_entries.label
   */
  private deriveLabel(entityType: string): string {
    // TODO: Transform entity types to labels:
    //   "user:family_count" → "denied_family_count"
    //   "US_SSN"            → "denied_us_ssn_instance"
    //   Prefix with "denied_" to indicate it was learned from a DENY-ADD response
    throw new Error("Not implemented");
  }

  /**
   * Derive a display name from an entity type.
   *
   * @param entityType - Entity type from the scan flag
   * @returns Human-readable display name
   */
  private deriveDisplayName(entityType: string): string {
    // TODO: Transform to human-readable:
    //   "user:family_count" → "Family Count (denied)"
    //   "US_SSN"            → "SSN Instance (denied)"
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// APPROVAL TOKEN GENERATOR
// ═══════════════════════════════════════════════════════════════

/**
 * Generates HMAC-SHA256 approval tokens for approved payloads.
 * The token is verified by the Gateway Hook before transmitting
 * a quarantined payload.
 */
export class ApprovalTokenGenerator {
  constructor(private readonly hmacKey: string) {}

  /**
   * Generate an approval token for a resolved escalation.
   *
   * Token = HMAC-SHA256(requestId + contentHash + timestamp + "approved")
   *
   * @param requestId   - Original scan request ID
   * @param contentHash - SHA-256 hash of the scanned content
   * @param timestamp   - ISO 8601 timestamp of approval
   * @returns Base64-encoded HMAC token string
   */
  generate(requestId: string, contentHash: string, timestamp: string): string {
    // TODO: Implement using Node.js crypto module
    // const hmac = crypto.createHmac('sha256', this.hmacKey);
    // hmac.update(requestId + contentHash + timestamp + 'approved');
    // return hmac.digest('base64');
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// SHORT ID GENERATOR
// ═══════════════════════════════════════════════════════════════

/**
 * Generates short, mobile-friendly escalation IDs from full UUIDs.
 * Format: "esc-" + 8 alphanumeric characters.
 */
export class ShortIdGenerator {
  /**
   * Derive a short ID from a full UUID.
   *
   * Takes the first 8 hex chars of the UUID and converts to a
   * deterministic 8-character alphanumeric string.
   *
   * @param uuid - Full UUIDv4 string
   * @returns Short ID (e.g., "esc-a1b2c3d4")
   */
  static fromUUID(uuid: string): string {
    // TODO: Implement
    // 1. Remove hyphens from UUID
    // 2. Take first 8 hex characters
    // 3. Return "esc-" + those 8 characters (lowercase)
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// BATCH ACCUMULATOR
// ═══════════════════════════════════════════════════════════════

/**
 * Accumulates escalation requests arriving within a sliding batch
 * window into a single batched notification.
 *
 * Window rules:
 * - Resets on each new arrival (sliding window)
 * - Capped at maxBatchSize items
 * - Capped at maxBatchDelaySeconds total delay
 * - Flushes when window closes, capacity reached, or max delay exceeded
 */
export class BatchAccumulator {
  /** Items accumulated in the current window. */
  private buffer: PendingEscalation[] = [];

  /** Timer for the current batch window. */
  private windowTimer: ReturnType<typeof setTimeout> | null = null;

  /** Timer for the maximum delay cap. */
  private maxDelayTimer: ReturnType<typeof setTimeout> | null = null;

  /** Timestamp when the first item entered the current batch. */
  private batchStartedAt: number | null = null;

  constructor(
    private readonly config: EscalationInterfaceConfig,
    private readonly onFlush: (items: PendingEscalation[]) => void
  ) {}

  /**
   * Add an escalation to the current batch.
   * May trigger an immediate flush if at capacity.
   *
   * @param escalation - The pending escalation to batch
   */
  add(escalation: PendingEscalation): void {
    // TODO: Implement
    // 1. Add to buffer
    // 2. If first item, start the max delay timer
    // 3. Reset the sliding window timer
    // 4. If buffer.length >= maxBatchSize, flush immediately
    throw new Error("Not implemented");
  }

  /**
   * Flush the accumulated batch immediately.
   * Calls the onFlush callback with all buffered items.
   */
  flush(): void {
    // TODO: Implement
    // 1. Clear both timers
    // 2. Copy buffer
    // 3. Clear buffer and batchStartedAt
    // 4. Call onFlush with the copied items
    throw new Error("Not implemented");
  }

  /**
   * Cancel any pending batch (on shutdown).
   */
  cancel(): void {
    // TODO: Clear timers. Do NOT flush (items remain in queue for restart recovery).
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// MAIN CLASS: ESCALATION INTERFACE
// ═══════════════════════════════════════════════════════════════

/**
 * Main orchestrator for the Human Escalation Interface.
 *
 * Lifecycle:
 * 1. Constructor: wire dependencies
 * 2. start(): load state from DB, register message listener, start health endpoint
 * 3. handleEscalation(): receive requests from Security Agent (IF-007)
 * 4. (incoming messages trigger response processing)
 * 5. stop(): cancel timers, persist state, disconnect
 *
 * @example
 * ```ts
 * const iface = new EscalationInterface(db, channelAdapter, config);
 * await iface.start();
 *
 * // Called by Security Agent on ESCALATE decision:
 * const status = await iface.handleEscalation(escalationRequest);
 * ```
 */
export class EscalationInterface {
  private readonly formatter: EscalationFormatter;
  private readonly parser: ResponseParser;
  private readonly queue: EscalationQueue;
  private readonly timeoutManager: TimeoutManager;
  private readonly registryLearner: RegistryLearner;
  private readonly tokenGenerator: ApprovalTokenGenerator;
  private readonly batchAccumulator: BatchAccumulator;

  /** Pending bulk operation awaiting confirmation, if any. */
  private pendingBulkOp: PendingBulkOperation | null = null;

  /** Whether the interface is running. */
  private running: boolean = false;

  /** ISO 8601 timestamp of when the interface was started. */
  private startedAt: string | null = null;

  constructor(
    private readonly db: Database.Database,
    private readonly channel: ChannelAdapter,
    private readonly config: EscalationInterfaceConfig
  ) {
    this.formatter = new EscalationFormatter();
    this.parser = new ResponseParser();
    this.queue = new EscalationQueue(db, config.maxPendingEscalations);
    this.timeoutManager = new TimeoutManager(config);
    this.registryLearner = new RegistryLearner(db);
    this.tokenGenerator = new ApprovalTokenGenerator(config.hmacKey);
    this.batchAccumulator = new BatchAccumulator(config, (items) => {
      this.sendBatchedNotification(items).catch((err) =>
        console.error("[EscalationInterface] Batch send failed:", err)
      );
    });
  }

  // ─── LIFECYCLE ───────────────────────────────────────────────

  /**
   * Start the Escalation Interface.
   *
   * 1. Reload pending escalations from SQLite (crash recovery)
   * 2. Restart timers for all pending escalations
   * 3. Register incoming message listener on the channel
   * 4. Mark as running
   */
  async start(): Promise<void> {
    // TODO: Implement startup sequence
    // 1. this.queue.loadFromDatabase()
    // 2. For each pending escalation, start timers
    // 3. Register this.onIncomingMessage as the channel listener
    // 4. Set this.running = true, this.startedAt = now
    throw new Error("Not implemented");
  }

  /**
   * Gracefully stop the Escalation Interface.
   *
   * 1. Stop accepting new escalations
   * 2. Cancel all active timers
   * 3. Flush or cancel pending batch
   * 4. Persist state (pending escalations remain in DB)
   * 5. Disconnect channel adapter
   */
  async stop(): Promise<void> {
    // TODO: Implement shutdown sequence
    throw new Error("Not implemented");
  }

  // ─── MAIN ENTRY POINT (IF-007) ──────────────────────────────

  /**
   * Handle an escalation request from the Security Agent.
   *
   * This is the primary entry point, implementing IF-007.
   * Creates the escalation, enqueues it, and initiates the
   * notification flow. Returns a Promise that resolves when
   * the escalation is resolved (approved, denied, or timed out).
   *
   * @param request - EscalationRequest from the Security Agent
   * @returns Promise resolving to EscalationStatus when resolved
   * @throws WatchdogError if the interface is not running or queue is full
   */
  async handleEscalation(request: EscalationRequest): Promise<EscalationStatus> {
    // TODO: Implement the full escalation flow
    // 1. Validate interface is running
    // 2. Generate short ID from escalation UUID
    // 3. Check for duplicates (same content hash + destination)
    // 4. Check queue capacity
    // 5. Create PendingEscalation object
    // 6. Add to queue (persists to SQLite)
    // 7. Start timeout/reminder timers
    // 8. Add to batch accumulator (or send immediately if batching disabled)
    // 9. Return a Promise that resolves when the escalation is resolved
    //    (store the resolve/reject callbacks keyed by escalation ID)
    throw new Error("Not implemented");
  }

  // ─── INCOMING MESSAGE HANDLER ────────────────────────────────

  /**
   * Process an incoming message from the user on the escalation channel.
   *
   * Called by the ChannelAdapter's onMessage callback.
   * Filters for responses from the configured peerId only.
   *
   * @param channel   - Channel the message arrived on
   * @param peerId    - Sender's peer ID
   * @param text      - Message text
   * @param timestamp - ISO 8601 timestamp
   */
  private async onIncomingMessage(
    channel: string,
    peerId: string,
    text: string,
    timestamp: string
  ): Promise<void> {
    // TODO: Implement response processing
    // 1. Verify peerId matches configured peerId (ignore others)
    // 2. Check if we're awaiting a bulk confirmation
    //    - If yes and text is a confirmation → execute bulk op
    //    - If yes and text is not confirmation → cancel bulk op, continue
    // 3. Parse response with ResponseParser
    // 4. If null → send help message
    // 5. If STATUS → send status response
    // 6. If APPROVE-ALL / DENY-ALL → initiate bulk confirmation flow
    // 7. If APPROVE/DENY/DENY-ADD with ID → resolve individual escalation
    throw new Error("Not implemented");
  }

  // ─── RESOLUTION HANDLERS ─────────────────────────────────────

  /**
   * Approve an escalation: release the quarantined payload.
   *
   * @param escalation - The pending escalation to approve
   * @param channel    - Channel the response came from
   * @param rawText    - Raw response text
   */
  private async resolveApprove(
    escalation: PendingEscalation,
    channel: string,
    rawText: string
  ): Promise<void> {
    // TODO: Implement
    // 1. Cancel timers
    // 2. Generate approval token
    // 3. Update quarantine_queue: state='approved', approval_token=token
    // 4. Update escalations: state='approved', response='APPROVE'
    // 5. Update scan_decisions: escalation_response='APPROVE', final_outcome='approved_by_user'
    // 6. Remove from queue
    // 7. Send approval confirmation message
    // 8. Resolve the Promise from handleEscalation
    throw new Error("Not implemented");
  }

  /**
   * Deny an escalation: permanently block the quarantined payload.
   *
   * @param escalation - The pending escalation to deny
   * @param channel    - Channel the response came from
   * @param rawText    - Raw response text
   */
  private async resolveDeny(
    escalation: PendingEscalation,
    channel: string,
    rawText: string
  ): Promise<void> {
    // TODO: Implement
    // 1. Cancel timers
    // 2. Update quarantine_queue: state='blocked', resolved_by='user'
    // 3. Update escalations: state='denied', response='DENY'
    // 4. Update scan_decisions: escalation_response='DENY', final_outcome='denied_by_user'
    // 5. Remove from queue
    // 6. Send denial confirmation message
    // 7. Resolve the Promise from handleEscalation
    throw new Error("Not implemented");
  }

  /**
   * Deny an escalation AND add flagged content to registry as NEVER_SHARE.
   *
   * @param escalation - The pending escalation to deny-and-add
   * @param channel    - Channel the response came from
   * @param rawText    - Raw response text
   */
  private async resolveDenyAndAdd(
    escalation: PendingEscalation,
    channel: string,
    rawText: string
  ): Promise<void> {
    // TODO: Implement
    // 1. Perform all DENY steps
    // 2. Use RegistryLearner to add entries to registry
    // 3. Update escalations: state='denied_and_added', response='DENY_AND_ADD'
    // 4. Update scan_decisions: final_outcome='denied_and_added'
    // 5. Send denial + registry update confirmation message
    throw new Error("Not implemented");
  }

  /**
   * Handle escalation timeout: auto-deny (fail-closed).
   *
   * Called by the TimeoutManager when an escalation expires.
   *
   * @param escalationId - The full escalation ID that timed out
   */
  private async resolveTimeout(escalationId: string): Promise<void> {
    // TODO: Implement
    // 1. Find escalation in queue
    // 2. If already resolved, return (no-op)
    // 3. Update quarantine_queue: state='blocked', resolved_by='timeout'
    // 4. Update escalations: state='timed_out', response='TIMEOUT'
    // 5. Update scan_decisions: final_outcome='denied_by_timeout'
    // 6. Remove from queue
    // 7. Send timeout notification message
    // 8. Resolve the Promise from handleEscalation
    throw new Error("Not implemented");
  }

  // ─── NOTIFICATION METHODS ────────────────────────────────────

  /**
   * Send a single escalation notification to the user.
   *
   * @param escalation - The escalation to notify about
   */
  private async sendSingleNotification(escalation: PendingEscalation): Promise<void> {
    // TODO: Implement
    // 1. Format message with EscalationFormatter
    // 2. Try sending on preferred channel
    // 3. On failure, try fallback channel
    // 4. On total failure, resolve as timeout immediately
    // 5. Update escalation: messageSent=true, sentOnChannel=channel
    // 6. Update database: message_sent=1, message_sent_at=now
    throw new Error("Not implemented");
  }

  /**
   * Send a batched escalation notification to the user.
   *
   * @param escalations - Array of escalations to include in the batch
   */
  private async sendBatchedNotification(escalations: PendingEscalation[]): Promise<void> {
    // TODO: Implement
    // 1. Format batched message with EscalationFormatter
    // 2. Send via channel (with fallback)
    // 3. Update all included escalations as sent
    throw new Error("Not implemented");
  }

  /**
   * Send a message on the escalation channel.
   * Tries the preferred channel first, then fallback.
   *
   * @param text - Message text to send
   * @returns The channel the message was sent on, or null if all failed
   */
  private async sendMessage(text: string): Promise<string | null> {
    // TODO: Implement channel selection logic per Section 6.3
    // 1. Check if preferred channel is available
    // 2. If yes, send. If success, return channel name.
    // 3. If no (or send failed), check if fallback is configured + available
    // 4. If yes, send on fallback. If success, return fallback name.
    // 5. If all fail, return null.
    throw new Error("Not implemented");
  }

  // ─── HEALTH CHECK ────────────────────────────────────────────

  /**
   * Return the current health status of the Escalation Interface.
   * Implements the component health endpoint (IF-009).
   *
   * @returns HealthCheckResponse with escalation-specific details
   */
  getHealth(): HealthCheckResponse {
    // TODO: Implement
    // Return:
    //   component: "escalation-interface"
    //   status: HEALTHY if running + channel available, DEGRADED if fallback only, UNHEALTHY if neither
    //   details: {
    //     pendingCount: queue.pendingCount,
    //     primaryChannelAvailable: boolean,
    //     fallbackChannelAvailable: boolean,
    //     oldestPendingAge: seconds since oldest pending escalation created,
    //   }
    throw new Error("Not implemented");
  }
}


// ═══════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════

export {
  PendingEscalation,
  ParsedResponse,
  BatchedEscalations,
  PendingBulkOperation,
};
