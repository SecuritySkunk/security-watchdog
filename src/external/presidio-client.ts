/**
 * Presidio Client - Integration with Microsoft Presidio PII Detection
 * 
 * Presidio is an open-source PII detection engine that provides
 * NLP-based entity recognition for sensitive data.
 * 
 * Requires: Presidio Analyzer running as HTTP service
 * Docker: docker run -p 5002:3000 mcr.microsoft.com/presidio-analyzer
 */

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

/** Presidio client configuration. */
export interface PresidioConfig {
  /** Base URL for Presidio Analyzer service. Default: http://localhost:5002 */
  analyzerUrl?: string;
  /** Request timeout in milliseconds. Default: 5000 */
  timeoutMs?: number;
  /** Minimum confidence score to accept (0-1). Default: 0.5 */
  minScore?: number;
  /** Default language. Default: 'en' */
  language?: string;
  /** Number of retries on failure. Default: 2 */
  retries?: number;
  /** Retry delay in milliseconds. Default: 100 */
  retryDelayMs?: number;
}

/** Presidio analyze request. */
export interface PresidioAnalyzeRequest {
  /** Text to analyze. */
  text: string;
  /** Language code (e.g., 'en'). */
  language: string;
  /** Specific entities to detect (optional, detects all if empty). */
  entities?: string[];
  /** Minimum confidence threshold. */
  score_threshold?: number;
  /** Return decision process details. */
  return_decision_process?: boolean;
}

/** Presidio entity result from analysis. */
export interface PresidioEntity {
  /** Entity type (e.g., 'PERSON', 'EMAIL_ADDRESS', 'PHONE_NUMBER'). */
  entity_type: string;
  /** Start position in text. */
  start: number;
  /** End position in text. */
  end: number;
  /** Confidence score (0-1). */
  score: number;
  /** Analysis details (if requested). */
  analysis_explanation?: {
    recognizer: string;
    pattern_name?: string;
    pattern?: string;
    original_score: number;
    score: number;
    textual_explanation?: string;
    score_context_improvement?: number;
    supportive_context_word?: string;
    validation_result?: unknown;
  };
}

/** Aggregated result from Presidio analysis. */
export interface PresidioResult {
  /** Whether analysis was successful. */
  success: boolean;
  /** Detected entities. */
  entities: PresidioEntity[];
  /** Error message if failed. */
  error?: string;
  /** Analysis duration in milliseconds. */
  durationMs: number;
  /** Text length analyzed. */
  textLength: number;
}

/** Presidio service health status. */
export interface PresidioHealth {
  /** Whether service is available. */
  available: boolean;
  /** Last successful call timestamp. */
  lastSuccessAt: number;
  /** Last error timestamp. */
  lastErrorAt: number;
  /** Consecutive error count. */
  consecutiveErrors: number;
  /** Service URL. */
  url: string;
}

/** Mapping from Presidio entity types to our classification. */
export type EntityClassification = 'NEVER_SHARE' | 'ASK_FIRST' | 'INTERNAL_ONLY' | 'PUBLIC';

/** Entity type configuration. */
export interface EntityTypeConfig {
  /** Presidio entity type. */
  entityType: string;
  /** Display name. */
  displayName: string;
  /** Default classification. */
  classification: EntityClassification;
  /** Whether this entity type is enabled. */
  enabled: boolean;
}

// ═══════════════════════════════════════════════════════════════
// DEFAULT ENTITY MAPPINGS
// ═══════════════════════════════════════════════════════════════

/** Default entity type configurations. */
export const DEFAULT_ENTITY_TYPES: EntityTypeConfig[] = [
  // High sensitivity - NEVER_SHARE
  { entityType: 'US_SSN', displayName: 'US Social Security Number', classification: 'NEVER_SHARE', enabled: true },
  { entityType: 'US_PASSPORT', displayName: 'US Passport Number', classification: 'NEVER_SHARE', enabled: true },
  { entityType: 'US_DRIVER_LICENSE', displayName: 'US Driver License', classification: 'NEVER_SHARE', enabled: true },
  { entityType: 'US_BANK_NUMBER', displayName: 'US Bank Account Number', classification: 'NEVER_SHARE', enabled: true },
  { entityType: 'US_ITIN', displayName: 'US Individual Taxpayer ID', classification: 'NEVER_SHARE', enabled: true },
  { entityType: 'CREDIT_CARD', displayName: 'Credit Card Number', classification: 'NEVER_SHARE', enabled: true },
  { entityType: 'CRYPTO', displayName: 'Cryptocurrency Wallet', classification: 'NEVER_SHARE', enabled: true },
  { entityType: 'IBAN_CODE', displayName: 'International Bank Account Number', classification: 'NEVER_SHARE', enabled: true },
  { entityType: 'MEDICAL_LICENSE', displayName: 'Medical License Number', classification: 'NEVER_SHARE', enabled: true },
  { entityType: 'IP_ADDRESS', displayName: 'IP Address', classification: 'NEVER_SHARE', enabled: true },
  
  // Medium sensitivity - ASK_FIRST
  { entityType: 'PERSON', displayName: 'Person Name', classification: 'ASK_FIRST', enabled: true },
  { entityType: 'PHONE_NUMBER', displayName: 'Phone Number', classification: 'ASK_FIRST', enabled: true },
  { entityType: 'DATE_TIME', displayName: 'Date/Time', classification: 'ASK_FIRST', enabled: true },
  { entityType: 'LOCATION', displayName: 'Location', classification: 'ASK_FIRST', enabled: true },
  { entityType: 'NRP', displayName: 'Nationality/Religion/Politics', classification: 'ASK_FIRST', enabled: true },
  
  // Lower sensitivity - INTERNAL_ONLY
  { entityType: 'EMAIL_ADDRESS', displayName: 'Email Address', classification: 'INTERNAL_ONLY', enabled: true },
  { entityType: 'URL', displayName: 'URL', classification: 'INTERNAL_ONLY', enabled: true },
  { entityType: 'ORGANIZATION', displayName: 'Organization', classification: 'INTERNAL_ONLY', enabled: true },
];

// ═══════════════════════════════════════════════════════════════
// PRESIDIO CLIENT
// ═══════════════════════════════════════════════════════════════

/**
 * PresidioClient provides integration with Microsoft Presidio
 * for NLP-based PII detection.
 */
export class PresidioClient {
  private readonly config: Required<PresidioConfig>;
  private entityTypes: Map<string, EntityTypeConfig>;
  
  // Health tracking
  private lastSuccessAt = 0;
  private lastErrorAt = 0;
  private consecutiveErrors = 0;

  constructor(config: PresidioConfig = {}) {
    this.config = {
      analyzerUrl: config.analyzerUrl ?? 'http://localhost:5002',
      timeoutMs: config.timeoutMs ?? 5000,
      minScore: config.minScore ?? 0.5,
      language: config.language ?? 'en',
      retries: config.retries ?? 2,
      retryDelayMs: config.retryDelayMs ?? 100,
    };

    // Initialize entity type mappings
    this.entityTypes = new Map(
      DEFAULT_ENTITY_TYPES.map(e => [e.entityType, e])
    );
  }

  /**
   * Analyze text for PII using Presidio.
   */
  async analyze(text: string, options: {
    language?: string;
    entities?: string[];
    minScore?: number;
  } = {}): Promise<PresidioResult> {
    const startTime = performance.now();
    
    if (!text || text.length === 0) {
      return {
        success: true,
        entities: [],
        durationMs: performance.now() - startTime,
        textLength: 0,
      };
    }

    const request: PresidioAnalyzeRequest = {
      text,
      language: options.language || this.config.language,
      score_threshold: options.minScore ?? this.config.minScore,
    };

    if (options.entities && options.entities.length > 0) {
      request.entities = options.entities;
    }

    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        const response = await this.makeRequest('/analyze', request);
        
        if (!response.ok) {
          throw new Error(`Presidio returned ${response.status}: ${await response.text()}`);
        }

        const entities = await response.json() as PresidioEntity[];
        
        this.lastSuccessAt = Date.now();
        this.consecutiveErrors = 0;

        return {
          success: true,
          entities: entities.filter(e => e.score >= (options.minScore ?? this.config.minScore)),
          durationMs: performance.now() - startTime,
          textLength: text.length,
        };
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        if (attempt < this.config.retries) {
          await this.delay(this.config.retryDelayMs * (attempt + 1));
        }
      }
    }

    // All retries failed
    this.lastErrorAt = Date.now();
    this.consecutiveErrors++;

    return {
      success: false,
      entities: [],
      error: lastError?.message || 'Unknown error',
      durationMs: performance.now() - startTime,
      textLength: text.length,
    };
  }

  /**
   * Check if Presidio service is available.
   */
  async checkHealth(): Promise<boolean> {
    try {
      const response = await this.makeRequest('/health', null, 'GET');
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Get list of supported entity types from Presidio.
   */
  async getSupportedEntities(language = 'en'): Promise<string[]> {
    try {
      const response = await this.makeRequest(`/supportedentities?language=${language}`, null, 'GET');
      if (!response.ok) return [];
      return await response.json() as string[];
    } catch {
      return [];
    }
  }

  /**
   * Get health status.
   */
  getHealth(): PresidioHealth {
    return {
      available: this.consecutiveErrors < 5,
      lastSuccessAt: this.lastSuccessAt,
      lastErrorAt: this.lastErrorAt,
      consecutiveErrors: this.consecutiveErrors,
      url: this.config.analyzerUrl,
    };
  }

  /**
   * Get classification for an entity type.
   */
  getEntityClassification(entityType: string): EntityClassification {
    const config = this.entityTypes.get(entityType);
    return config?.classification ?? 'ASK_FIRST'; // Default to ASK_FIRST for unknown
  }

  /**
   * Get display name for an entity type.
   */
  getEntityDisplayName(entityType: string): string {
    const config = this.entityTypes.get(entityType);
    return config?.displayName ?? entityType;
  }

  /**
   * Check if an entity type is enabled.
   */
  isEntityEnabled(entityType: string): boolean {
    const config = this.entityTypes.get(entityType);
    return config?.enabled ?? true;
  }

  /**
   * Configure an entity type.
   */
  configureEntityType(entityType: string, config: Partial<EntityTypeConfig>): void {
    const existing = this.entityTypes.get(entityType) ?? {
      entityType,
      displayName: entityType,
      classification: 'ASK_FIRST' as EntityClassification,
      enabled: true,
    };

    this.entityTypes.set(entityType, { ...existing, ...config });
  }

  /**
   * Get all configured entity types.
   */
  getEntityTypes(): EntityTypeConfig[] {
    return Array.from(this.entityTypes.values());
  }

  /**
   * Get enabled entity type names.
   */
  getEnabledEntityTypes(): string[] {
    return Array.from(this.entityTypes.values())
      .filter(e => e.enabled)
      .map(e => e.entityType);
  }

  /**
   * Reset health tracking (e.g., after service restart).
   */
  resetHealth(): void {
    this.consecutiveErrors = 0;
    this.lastErrorAt = 0;
  }

  // ════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ════════════════════════════════════════════════════════════

  /** Make HTTP request to Presidio. */
  private async makeRequest(
    path: string,
    body: unknown,
    method: 'GET' | 'POST' = 'POST'
  ): Promise<Response> {
    const url = `${this.config.analyzerUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const options: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        signal: controller.signal,
      };

      if (body && method === 'POST') {
        options.body = JSON.stringify(body);
      }

      return await fetch(url, options);
    } finally {
      clearTimeout(timeout);
    }
  }

  /** Delay helper for retries. */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export default PresidioClient;
