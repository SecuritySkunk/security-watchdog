/**
 * Security Agent — Layer 2 AI Classification
 * 
 * Uses local LLM (Ollama) to analyze flagged content and make
 * contextual classification decisions.
 */

import pino from 'pino';
import type { ScanResult, ScanFlag } from '../scanner/pattern-scanner.js';
import { ClassificationLevel } from '../registry/types.js';

const logger = pino({ name: 'watchdog:agent' });

// ─── Configuration ───────────────────────────────────────────

export interface SecurityAgentConfig {
  /** Ollama API endpoint */
  ollamaUrl: string;
  /** Model to use for classification */
  model: string;
  /** Request timeout in ms */
  timeoutMs: number;
  /** Whether to enable the agent (if false, passes through scanner results) */
  enabled: boolean;
  /** Maximum content length to send to LLM */
  maxContentLength: number;
  /** Cache TTL in ms (0 = no cache) */
  cacheTtlMs: number;
}

export const DEFAULT_CONFIG: SecurityAgentConfig = {
  ollamaUrl: 'http://127.0.0.1:11434/v1',
  model: 'deepseek-r1:14b',
  timeoutMs: 30000,
  enabled: true,
  maxContentLength: 4000,
  cacheTtlMs: 300000, // 5 minutes
};

// ─── Types ───────────────────────────────────────────────────

export interface AgentAnalysis {
  /** Original flag from scanner */
  flag: ScanFlag;
  /** Agent's classification decision */
  classification: ClassificationLevel;
  /** Agent's confidence (0-1) */
  confidence: number;
  /** Reasoning for the decision */
  reasoning: string;
  /** Whether this was from cache */
  cached: boolean;
}

export interface AgentResult {
  /** Unique analysis ID */
  analysisId: string;
  /** Timestamp */
  timestamp: Date;
  /** Original scan result */
  scanResult: ScanResult;
  /** Agent analyses for each flag */
  analyses: AgentAnalysis[];
  /** Overall recommended classification */
  overallClassification: ClassificationLevel;
  /** Processing time in ms */
  processingTimeMs: number;
  /** Whether agent was used or bypassed */
  agentUsed: boolean;
  /** Error if agent failed */
  error?: string;
}

interface OllamaMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface OllamaResponse {
  choices: Array<{
    message: {
      content: string;
    };
  }>;
}

interface CacheEntry {
  analysis: AgentAnalysis;
  expiresAt: number;
}

// ─── System Prompt ───────────────────────────────────────────

const SYSTEM_PROMPT = `You are a security classification agent. Your job is to analyze text snippets that have been flagged as potentially containing sensitive information.

For each flagged item, you must decide:
1. Is this actually sensitive data, or a false positive?
2. What classification level should it have?

Classification levels (from most to least restrictive):
- NEVER_SHARE: Credentials, SSNs, private keys, passwords, API keys, financial account numbers
- ASK_FIRST: Personal contact info, names with context, addresses, phone numbers in personal context
- INTERNAL_ONLY: Internal references, non-public business info, IP addresses
- PUBLIC: False positives, example data, clearly fictional, test data, publicly known info

Important rules:
- Example data in documentation or code comments is usually PUBLIC
- Test data with obvious patterns (123-45-6789, test@example.com) is usually PUBLIC
- Real-looking data in actual messages is usually sensitive
- Context matters: "My SSN is 123-45-6789" vs "The SSN format is XXX-XX-XXXX"
- When in doubt, err on the side of caution (higher classification)

Respond with JSON only:
{
  "classification": "NEVER_SHARE|ASK_FIRST|INTERNAL_ONLY|PUBLIC",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation"
}`;

// ─── Security Agent Class ────────────────────────────────────

export class SecurityAgent {
  private config: SecurityAgentConfig;
  private cache: Map<string, CacheEntry> = new Map();
  private analysisCounter = 0;

  constructor(config: Partial<SecurityAgentConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    logger.info({ 
      model: this.config.model, 
      enabled: this.config.enabled 
    }, 'Security Agent initialized');
  }

  /**
   * Analyze scan results and make classification decisions
   */
  async analyze(scanResult: ScanResult, fullContent: string): Promise<AgentResult> {
    const startTime = Date.now();
    const analysisId = `agent-${Date.now()}-${++this.analysisCounter}`;

    // If agent is disabled, pass through scanner results
    if (!this.config.enabled) {
      return this.createPassthroughResult(analysisId, scanResult, startTime);
    }

    // If no flags, nothing to analyze
    if (scanResult.flags.length === 0) {
      return {
        analysisId,
        timestamp: new Date(),
        scanResult,
        analyses: [],
        overallClassification: ClassificationLevel.PUBLIC,
        processingTimeMs: Date.now() - startTime,
        agentUsed: false,
      };
    }

    try {
      const analyses = await this.analyzeFlags(scanResult.flags, fullContent);
      const overallClassification = this.determineOverallClassification(analyses);

      return {
        analysisId,
        timestamp: new Date(),
        scanResult,
        analyses,
        overallClassification,
        processingTimeMs: Date.now() - startTime,
        agentUsed: true,
      };
    } catch (error) {
      logger.error({ error, analysisId }, 'Agent analysis failed');
      
      // Fail closed: use scanner's classification on error
      return {
        analysisId,
        timestamp: new Date(),
        scanResult,
        analyses: scanResult.flags.map(flag => ({
          flag,
          classification: flag.classification,
          confidence: 0.5,
          reasoning: 'Agent unavailable, using scanner classification',
          cached: false,
        })),
        overallClassification: scanResult.highestClassification ?? ClassificationLevel.ASK_FIRST,
        processingTimeMs: Date.now() - startTime,
        agentUsed: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Analyze individual flags
   */
  private async analyzeFlags(flags: ScanFlag[], fullContent: string): Promise<AgentAnalysis[]> {
    const analyses: AgentAnalysis[] = [];

    for (const flag of flags) {
      // Check cache first
      const cacheKey = this.getCacheKey(flag, fullContent);
      const cached = this.getFromCache(cacheKey);
      
      if (cached) {
        analyses.push({ ...cached, cached: true });
        continue;
      }

      // Call LLM for analysis
      const analysis = await this.analyzeFlag(flag, fullContent);
      
      // Cache the result
      this.setCache(cacheKey, analysis);
      
      analyses.push({ ...analysis, cached: false });
    }

    return analyses;
  }

  /**
   * Analyze a single flag using LLM
   */
  private async analyzeFlag(flag: ScanFlag, fullContent: string): Promise<Omit<AgentAnalysis, 'cached'>> {
    const truncatedContent = fullContent.slice(0, this.config.maxContentLength);
    
    const userPrompt = `Analyze this flagged content:

Type: ${flag.patternType}
Matched value: "${flag.matchedText}"
Context: "${flag.context}"
Scanner classification: ${flag.classification}

Full message (truncated):
"""
${truncatedContent}
"""

Is this actually sensitive data? What classification should it have?`;

    const messages: OllamaMessage[] = [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: userPrompt },
    ];

    try {
      const response = await this.callOllama(messages);
      return this.parseResponse(response, flag);
    } catch (error) {
      logger.warn({ error, flagType: flag.patternType }, 'Failed to analyze flag');
      
      // Return scanner's classification on error
      return {
        flag,
        classification: flag.classification,
        confidence: 0.5,
        reasoning: 'LLM analysis failed, using scanner classification',
      };
    }
  }

  /**
   * Call Ollama API
   */
  private async callOllama(messages: OllamaMessage[]): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(`${this.config.ollamaUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env['OLLAMA_API_KEY'] || 'ollama-local'}`,
        },
        body: JSON.stringify({
          model: this.config.model,
          messages,
          temperature: 0.1, // Low temperature for consistent classification
          max_tokens: 500,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as OllamaResponse;
      return data.choices[0]?.message?.content ?? '';
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Parse LLM response into structured analysis
   */
  private parseResponse(response: string, flag: ScanFlag): Omit<AgentAnalysis, 'cached'> {
    try {
      // Extract JSON from response (handle markdown code blocks)
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('No JSON found in response');
      }

      const parsed = JSON.parse(jsonMatch[0]) as {
        classification: string;
        confidence: number;
        reasoning: string;
      };

      // Validate classification
      const classification = this.parseClassification(parsed.classification);
      const confidence = Math.max(0, Math.min(1, parsed.confidence || 0.5));

      return {
        flag,
        classification,
        confidence,
        reasoning: parsed.reasoning || 'No reasoning provided',
      };
    } catch (error) {
      logger.warn({ error, response }, 'Failed to parse LLM response');
      
      return {
        flag,
        classification: flag.classification,
        confidence: 0.5,
        reasoning: 'Failed to parse LLM response, using scanner classification',
      };
    }
  }

  /**
   * Parse classification string to enum
   */
  private parseClassification(value: string): ClassificationLevel {
    const normalized = value.toUpperCase().replace(/[^A-Z_]/g, '');
    
    switch (normalized) {
      case 'NEVER_SHARE':
      case 'NEVERSHARE':
        return ClassificationLevel.NEVER_SHARE;
      case 'ASK_FIRST':
      case 'ASKFIRST':
        return ClassificationLevel.ASK_FIRST;
      case 'INTERNAL_ONLY':
      case 'INTERNALONLY':
        return ClassificationLevel.INTERNAL_ONLY;
      case 'PUBLIC':
        return ClassificationLevel.PUBLIC;
      default:
        return ClassificationLevel.ASK_FIRST; // Safe default
    }
  }

  /**
   * Determine overall classification from analyses
   */
  private determineOverallClassification(analyses: AgentAnalysis[]): ClassificationLevel {
    if (analyses.length === 0) {
      return ClassificationLevel.PUBLIC;
    }

    // Priority order (highest wins)
    const priority = [
      ClassificationLevel.NEVER_SHARE,
      ClassificationLevel.ASK_FIRST,
      ClassificationLevel.INTERNAL_ONLY,
      ClassificationLevel.PUBLIC,
    ];

    for (const level of priority) {
      if (analyses.some(a => a.classification === level)) {
        return level;
      }
    }

    return ClassificationLevel.PUBLIC;
  }

  /**
   * Create passthrough result when agent is disabled
   */
  private createPassthroughResult(
    analysisId: string, 
    scanResult: ScanResult, 
    startTime: number
  ): AgentResult {
    return {
      analysisId,
      timestamp: new Date(),
      scanResult,
      analyses: scanResult.flags.map(flag => ({
        flag,
        classification: flag.classification,
        confidence: 1.0,
        reasoning: 'Agent disabled, using scanner classification',
        cached: false,
      })),
      overallClassification: scanResult.highestClassification ?? ClassificationLevel.PUBLIC,
      processingTimeMs: Date.now() - startTime,
      agentUsed: false,
    };
  }

  // ─── Cache Management ────────────────────────────────────────

  private getCacheKey(flag: ScanFlag, content: string): string {
    // Create a stable cache key from flag properties and content hash
    const contentHash = this.simpleHash(content);
    return `${flag.patternType}:${flag.matchedText}:${contentHash}`;
  }

  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(36);
  }

  private getFromCache(key: string): AgentAnalysis | null {
    if (this.config.cacheTtlMs === 0) return null;
    
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    
    return entry.analysis;
  }

  private setCache(key: string, analysis: Omit<AgentAnalysis, 'cached'>): void {
    if (this.config.cacheTtlMs === 0) return;
    
    this.cache.set(key, {
      analysis: { ...analysis, cached: true },
      expiresAt: Date.now() + this.config.cacheTtlMs,
    });

    // Prune old entries periodically
    if (this.cache.size > 1000) {
      this.pruneCache();
    }
  }

  private pruneCache(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  // ─── Utility Methods ─────────────────────────────────────────

  /**
   * Update configuration
   */
  updateConfig(config: Partial<SecurityAgentConfig>): void {
    this.config = { ...this.config, ...config };
    logger.info({ config: this.config }, 'Agent config updated');
  }

  /**
   * Clear the analysis cache
   */
  clearCache(): void {
    this.cache.clear();
    logger.info('Agent cache cleared');
  }

  /**
   * Get agent status
   */
  getStatus(): {
    enabled: boolean;
    model: string;
    cacheSize: number;
    ollamaUrl: string;
  } {
    return {
      enabled: this.config.enabled,
      model: this.config.model,
      cacheSize: this.cache.size,
      ollamaUrl: this.config.ollamaUrl,
    };
  }

  /**
   * Test connectivity to Ollama
   */
  async testConnection(): Promise<{ ok: boolean; error?: string; latencyMs?: number }> {
    const start = Date.now();
    
    try {
      const response = await fetch(`${this.config.ollamaUrl.replace('/v1', '')}/api/tags`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        return { ok: false, error: `HTTP ${response.status}` };
      }

      return { ok: true, latencyMs: Date.now() - start };
    } catch (error) {
      return { 
        ok: false, 
        error: error instanceof Error ? error.message : String(error) 
      };
    }
  }
}

export default SecurityAgent;
