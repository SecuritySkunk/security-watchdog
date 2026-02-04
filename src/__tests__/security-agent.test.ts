/**
 * Security Agent Tests
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { SecurityAgent, DEFAULT_CONFIG } from '../agent/security-agent.js';
import { ClassificationLevel } from '../registry/types.js';
import type { ScanResult, ScanFlag } from '../scanner/pattern-scanner.js';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('SecurityAgent', () => {
  let agent: SecurityAgent;

  beforeEach(() => {
    vi.clearAllMocks();
    agent = new SecurityAgent({
      ollamaUrl: 'http://localhost:11434/v1',
      model: 'test-model',
      timeoutMs: 5000,
      enabled: true,
      cacheTtlMs: 0, // Disable cache for tests
    });
  });

  afterEach(() => {
    agent.clearCache();
  });

  // ─── Initialization ─────────────────────────────────────────

  describe('Initialization', () => {
    it('should initialize with default config', () => {
      const defaultAgent = new SecurityAgent();
      const status = defaultAgent.getStatus();
      
      expect(status.enabled).toBe(DEFAULT_CONFIG.enabled);
      expect(status.model).toBe(DEFAULT_CONFIG.model);
    });

    it('should initialize with custom config', () => {
      const customAgent = new SecurityAgent({
        model: 'custom-model',
        enabled: false,
      });
      const status = customAgent.getStatus();
      
      expect(status.model).toBe('custom-model');
      expect(status.enabled).toBe(false);
    });

    it('should update config', () => {
      agent.updateConfig({ model: 'new-model' });
      expect(agent.getStatus().model).toBe('new-model');
    });
  });

  // ─── Analysis with Agent Disabled ───────────────────────────

  describe('Agent Disabled', () => {
    beforeEach(() => {
      agent.updateConfig({ enabled: false });
    });

    it('should passthrough scanner results when disabled', async () => {
      const scanResult = createScanResult([
        createFlag('ssn', '123-45-6789', ClassificationLevel.NEVER_SHARE),
      ]);

      const result = await agent.analyze(scanResult, 'My SSN is 123-45-6789');

      expect(result.agentUsed).toBe(false);
      expect(result.analyses).toHaveLength(1);
      expect(result.analyses[0].classification).toBe(ClassificationLevel.NEVER_SHARE);
      expect(result.analyses[0].reasoning).toContain('Agent disabled');
    });

    it('should preserve overall classification when disabled', async () => {
      const scanResult = createScanResult([
        createFlag('email', 'test@example.com', ClassificationLevel.ASK_FIRST),
        createFlag('ssn', '123-45-6789', ClassificationLevel.NEVER_SHARE),
      ]);

      const result = await agent.analyze(scanResult, 'Test content');

      expect(result.overallClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });
  });

  // ─── Analysis with No Flags ─────────────────────────────────

  describe('No Flags', () => {
    it('should return PUBLIC classification for empty flags', async () => {
      const scanResult = createScanResult([]);

      const result = await agent.analyze(scanResult, 'Clean content');

      expect(result.agentUsed).toBe(false);
      expect(result.analyses).toHaveLength(0);
      expect(result.overallClassification).toBe(ClassificationLevel.PUBLIC);
    });
  });

  // ─── LLM Analysis ───────────────────────────────────────────

  describe('LLM Analysis', () => {
    it('should call Ollama API for analysis', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                classification: 'NEVER_SHARE',
                confidence: 0.95,
                reasoning: 'This is a real SSN',
              }),
            },
          }],
        }),
      });

      const scanResult = createScanResult([
        createFlag('ssn', '123-45-6789', ClassificationLevel.NEVER_SHARE),
      ]);

      const result = await agent.analyze(scanResult, 'My SSN is 123-45-6789');

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(result.agentUsed).toBe(true);
      expect(result.analyses[0].classification).toBe(ClassificationLevel.NEVER_SHARE);
      expect(result.analyses[0].confidence).toBe(0.95);
    });

    it('should downgrade classification for false positives', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                classification: 'PUBLIC',
                confidence: 0.9,
                reasoning: 'This is example data in documentation',
              }),
            },
          }],
        }),
      });

      const scanResult = createScanResult([
        createFlag('ssn', '123-45-6789', ClassificationLevel.NEVER_SHARE),
      ]);

      const result = await agent.analyze(scanResult, 'Example SSN format: 123-45-6789');

      expect(result.analyses[0].classification).toBe(ClassificationLevel.PUBLIC);
      expect(result.analyses[0].reasoning).toContain('example');
    });

    it('should handle markdown-wrapped JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: '```json\n{"classification": "ASK_FIRST", "confidence": 0.8, "reasoning": "Personal email"}\n```',
            },
          }],
        }),
      });

      const scanResult = createScanResult([
        createFlag('email', 'john@example.com', ClassificationLevel.ASK_FIRST),
      ]);

      const result = await agent.analyze(scanResult, 'Contact john@example.com');

      expect(result.analyses[0].classification).toBe(ClassificationLevel.ASK_FIRST);
    });

    it('should analyze multiple flags', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: {
                content: JSON.stringify({
                  classification: 'NEVER_SHARE',
                  confidence: 0.95,
                  reasoning: 'Real SSN',
                }),
              },
            }],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: {
                content: JSON.stringify({
                  classification: 'PUBLIC',
                  confidence: 0.85,
                  reasoning: 'Example email',
                }),
              },
            }],
          }),
        });

      const scanResult = createScanResult([
        createFlag('ssn', '123-45-6789', ClassificationLevel.NEVER_SHARE),
        createFlag('email', 'test@example.com', ClassificationLevel.ASK_FIRST),
      ]);

      const result = await agent.analyze(scanResult, 'SSN: 123-45-6789, email: test@example.com');

      expect(result.analyses).toHaveLength(2);
      expect(result.overallClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });
  });

  // ─── Error Handling ─────────────────────────────────────────

  describe('Error Handling', () => {
    it('should fail closed on API error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const scanResult = createScanResult([
        createFlag('ssn', '123-45-6789', ClassificationLevel.NEVER_SHARE),
      ]);

      const result = await agent.analyze(scanResult, 'My SSN is 123-45-6789');

      // Agent was attempted but failed - still counts as "used" (tried)
      expect(result.agentUsed).toBe(true);
      // Reasoning should indicate LLM failure
      expect(result.analyses[0].reasoning).toContain('failed');
      // Should use scanner's classification as fallback (fail closed)
      expect(result.overallClassification).toBe(ClassificationLevel.NEVER_SHARE);
    });

    it('should handle malformed JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: 'This is not JSON',
            },
          }],
        }),
      });

      const scanResult = createScanResult([
        createFlag('email', 'test@example.com', ClassificationLevel.ASK_FIRST),
      ]);

      const result = await agent.analyze(scanResult, 'Contact test@example.com');

      // Should fall back to scanner classification
      expect(result.analyses[0].classification).toBe(ClassificationLevel.ASK_FIRST);
      expect(result.analyses[0].reasoning).toContain('Failed to parse');
    });

    it('should handle HTTP error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const scanResult = createScanResult([
        createFlag('phone', '555-123-4567', ClassificationLevel.ASK_FIRST),
      ]);

      const result = await agent.analyze(scanResult, 'Call 555-123-4567');

      // Agent was attempted but failed
      expect(result.agentUsed).toBe(true);
      // Should fall back to scanner classification
      expect(result.analyses[0].reasoning).toContain('failed');
      expect(result.overallClassification).toBe(ClassificationLevel.ASK_FIRST);
    });
  });

  // ─── Classification Parsing ─────────────────────────────────

  describe('Classification Parsing', () => {
    const testCases = [
      { input: 'NEVER_SHARE', expected: ClassificationLevel.NEVER_SHARE },
      { input: 'never_share', expected: ClassificationLevel.NEVER_SHARE },
      { input: 'NEVERSHARE', expected: ClassificationLevel.NEVER_SHARE },
      { input: 'ASK_FIRST', expected: ClassificationLevel.ASK_FIRST },
      { input: 'ask_first', expected: ClassificationLevel.ASK_FIRST },
      { input: 'INTERNAL_ONLY', expected: ClassificationLevel.INTERNAL_ONLY },
      { input: 'PUBLIC', expected: ClassificationLevel.PUBLIC },
      { input: 'unknown', expected: ClassificationLevel.ASK_FIRST }, // Safe default
    ];

    for (const { input, expected } of testCases) {
      it(`should parse "${input}" as ${expected}`, async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: {
                content: JSON.stringify({
                  classification: input,
                  confidence: 0.9,
                  reasoning: 'Test',
                }),
              },
            }],
          }),
        });

        const scanResult = createScanResult([
          createFlag('test', 'value', ClassificationLevel.ASK_FIRST),
        ]);

        const result = await agent.analyze(scanResult, 'Test content');

        expect(result.analyses[0].classification).toBe(expected);
      });
    }
  });

  // ─── Caching ────────────────────────────────────────────────

  describe('Caching', () => {
    beforeEach(() => {
      agent.updateConfig({ cacheTtlMs: 60000 }); // Enable cache
    });

    it('should cache analysis results', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                classification: 'NEVER_SHARE',
                confidence: 0.95,
                reasoning: 'Cached result',
              }),
            },
          }],
        }),
      });

      const scanResult = createScanResult([
        createFlag('ssn', '123-45-6789', ClassificationLevel.NEVER_SHARE),
      ]);
      const content = 'My SSN is 123-45-6789';

      // First call - should hit API
      await agent.analyze(scanResult, content);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      const result2 = await agent.analyze(scanResult, content);
      expect(mockFetch).toHaveBeenCalledTimes(1); // No additional calls
      expect(result2.analyses[0].cached).toBe(true);
    });

    it('should clear cache', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify({
                classification: 'NEVER_SHARE',
                confidence: 0.95,
                reasoning: 'Test',
              }),
            },
          }],
        }),
      });

      const scanResult = createScanResult([
        createFlag('ssn', '123-45-6789', ClassificationLevel.NEVER_SHARE),
      ]);
      const content = 'Test content';

      await agent.analyze(scanResult, content);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      agent.clearCache();

      await agent.analyze(scanResult, content);
      expect(mockFetch).toHaveBeenCalledTimes(2); // Called again after cache clear
    });
  });

  // ─── Connection Test ────────────────────────────────────────

  describe('Connection Test', () => {
    it('should report successful connection', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ models: [] }),
      });

      const result = await agent.testConnection();

      expect(result.ok).toBe(true);
      expect(result.latencyMs).toBeDefined();
    });

    it('should report failed connection', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const result = await agent.testConnection();

      expect(result.ok).toBe(false);
      expect(result.error).toContain('Connection refused');
    });
  });

  // ─── Overall Classification ─────────────────────────────────

  describe('Overall Classification', () => {
    it('should use highest classification from analyses', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: { content: JSON.stringify({ classification: 'PUBLIC', confidence: 0.9, reasoning: 'Test' }) },
            }],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: { content: JSON.stringify({ classification: 'ASK_FIRST', confidence: 0.9, reasoning: 'Test' }) },
            }],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{
              message: { content: JSON.stringify({ classification: 'INTERNAL_ONLY', confidence: 0.9, reasoning: 'Test' }) },
            }],
          }),
        });

      const scanResult = createScanResult([
        createFlag('test1', 'value1', ClassificationLevel.PUBLIC),
        createFlag('test2', 'value2', ClassificationLevel.PUBLIC),
        createFlag('test3', 'value3', ClassificationLevel.PUBLIC),
      ]);

      const result = await agent.analyze(scanResult, 'Test content');

      // ASK_FIRST is highest among PUBLIC, ASK_FIRST, INTERNAL_ONLY
      expect(result.overallClassification).toBe(ClassificationLevel.ASK_FIRST);
    });
  });
});

// ─── Helper Functions ─────────────────────────────────────────

function createScanResult(flags: ScanFlag[]): ScanResult {
  const highestClassification = flags.length > 0
    ? flags.reduce((highest, flag) => {
        const priority = [
          ClassificationLevel.NEVER_SHARE,
          ClassificationLevel.ASK_FIRST,
          ClassificationLevel.INTERNAL_ONLY,
          ClassificationLevel.PUBLIC,
        ];
        return priority.indexOf(flag.classification) < priority.indexOf(highest)
          ? flag.classification
          : highest;
      }, ClassificationLevel.PUBLIC)
    : null;

  return {
    scanId: `scan-${Date.now()}`,
    scannedAt: new Date().toISOString(),
    inputLength: 100,
    durationMs: 10,
    flags,
    flagCount: flags.length,
    highestClassification,
    verdict: flags.length > 0 ? 'flagged' : 'clean',
  };
}

function createFlag(
  patternType: string,
  matchedText: string,
  classification: ClassificationLevel
): ScanFlag {
  return {
    id: `flag-${Date.now()}-${Math.random()}`,
    source: 'pattern',
    patternType,
    patternId: 1,
    matchedText,
    classification,
    context: `...${matchedText}...`,
    startIndex: 0,
    endIndex: matchedText.length,
  };
}
