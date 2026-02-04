/**
 * Unit tests for PresidioClient
 * 
 * Note: These tests mock the Presidio HTTP service.
 * For integration testing with real Presidio, set PRESIDIO_URL env var.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PresidioClient, DEFAULT_ENTITY_TYPES, type PresidioEntity } from '../external/presidio-client.js';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('PresidioClient', () => {
  let client: PresidioClient;

  beforeEach(() => {
    mockFetch.mockReset();
    client = new PresidioClient({
      analyzerUrl: 'http://localhost:5002',
      timeoutMs: 1000,
      minScore: 0.5,
      retries: 1,
      retryDelayMs: 10,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Configuration', () => {
    it('should use default config values', () => {
      const defaultClient = new PresidioClient();
      const health = defaultClient.getHealth();
      expect(health.url).toBe('http://localhost:5002');
    });

    it('should override config values', () => {
      const customClient = new PresidioClient({
        analyzerUrl: 'http://custom:8080',
        minScore: 0.8,
      });
      const health = customClient.getHealth();
      expect(health.url).toBe('http://custom:8080');
    });
  });

  describe('Entity Type Mapping', () => {
    it('should have default entity types', () => {
      expect(DEFAULT_ENTITY_TYPES.length).toBeGreaterThan(10);
    });

    it('should get classification for known entity', () => {
      const classification = client.getEntityClassification('US_SSN');
      expect(classification).toBe('NEVER_SHARE');
    });

    it('should get classification for phone number', () => {
      const classification = client.getEntityClassification('PHONE_NUMBER');
      expect(classification).toBe('ASK_FIRST');
    });

    it('should return ASK_FIRST for unknown entity', () => {
      const classification = client.getEntityClassification('UNKNOWN_TYPE');
      expect(classification).toBe('ASK_FIRST');
    });

    it('should get display name for entity', () => {
      const name = client.getEntityDisplayName('US_SSN');
      expect(name).toBe('US Social Security Number');
    });

    it('should check if entity is enabled', () => {
      expect(client.isEntityEnabled('US_SSN')).toBe(true);
    });

    it('should configure entity type', () => {
      client.configureEntityType('CUSTOM_TYPE', {
        displayName: 'Custom Entity',
        classification: 'NEVER_SHARE',
        enabled: true,
      });

      expect(client.getEntityDisplayName('CUSTOM_TYPE')).toBe('Custom Entity');
      expect(client.getEntityClassification('CUSTOM_TYPE')).toBe('NEVER_SHARE');
    });

    it('should list all entity types', () => {
      const types = client.getEntityTypes();
      expect(types.length).toBe(DEFAULT_ENTITY_TYPES.length);
    });

    it('should list enabled entity types', () => {
      const enabled = client.getEnabledEntityTypes();
      expect(enabled.length).toBe(DEFAULT_ENTITY_TYPES.length);
      expect(enabled).toContain('US_SSN');
    });
  });

  describe('Analysis', () => {
    it('should return empty for empty text', async () => {
      const result = await client.analyze('');
      
      expect(result.success).toBe(true);
      expect(result.entities.length).toBe(0);
      expect(result.textLength).toBe(0);
    });

    it('should detect entities from Presidio response', async () => {
      const mockEntities: PresidioEntity[] = [
        { entity_type: 'US_SSN', start: 8, end: 19, score: 0.85 },
        { entity_type: 'PHONE_NUMBER', start: 35, end: 47, score: 0.75 },
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockEntities,
      });

      const result = await client.analyze('My SSN: 123-45-6789 and phone: 555-123-4567');

      expect(result.success).toBe(true);
      expect(result.entities.length).toBe(2);
      expect(result.entities[0].entity_type).toBe('US_SSN');
      expect(result.entities[1].entity_type).toBe('PHONE_NUMBER');
      expect(result.durationMs).toBeGreaterThan(0);
    });

    it('should filter by minimum score', async () => {
      const mockEntities: PresidioEntity[] = [
        { entity_type: 'US_SSN', start: 0, end: 11, score: 0.9 },
        { entity_type: 'PERSON', start: 20, end: 30, score: 0.3 }, // Below threshold
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockEntities,
      });

      const result = await client.analyze('123-45-6789 belongs to John Doe');

      expect(result.success).toBe(true);
      expect(result.entities.length).toBe(1); // Only SSN passes threshold
      expect(result.entities[0].entity_type).toBe('US_SSN');
    });

    it('should use custom options', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [],
      });

      await client.analyze('Test', {
        language: 'de',
        entities: ['PERSON', 'LOCATION'],
        minScore: 0.8,
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:5002/analyze',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"language":"de"'),
        })
      );
    });

    it('should handle API errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: async () => 'Internal Server Error',
      });

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: async () => 'Internal Server Error',
      });

      const result = await client.analyze('test text');

      expect(result.success).toBe(false);
      expect(result.error).toContain('500');
      expect(result.entities.length).toBe(0);
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const result = await client.analyze('test text');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Connection refused');
    });

    it('should retry on failure', async () => {
      // First call fails, second succeeds
      mockFetch.mockRejectedValueOnce(new Error('Temporary failure'));
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [{ entity_type: 'PERSON', start: 0, end: 5, score: 0.8 }],
      });

      const result = await client.analyze('Hello World');

      expect(result.success).toBe(true);
      expect(result.entities.length).toBe(1);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Health Tracking', () => {
    it('should track successful calls', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [],
      });

      await client.analyze('test');

      const health = client.getHealth();
      expect(health.available).toBe(true);
      expect(health.consecutiveErrors).toBe(0);
      expect(health.lastSuccessAt).toBeGreaterThan(0);
    });

    it('should track failed calls', async () => {
      mockFetch.mockRejectedValue(new Error('Failed'));

      await client.analyze('test');
      await client.analyze('test');

      const health = client.getHealth();
      expect(health.consecutiveErrors).toBe(2);
      expect(health.lastErrorAt).toBeGreaterThan(0);
    });

    it('should mark unavailable after many failures', async () => {
      mockFetch.mockRejectedValue(new Error('Failed'));

      // Trigger 5 failures
      for (let i = 0; i < 5; i++) {
        await client.analyze('test');
      }

      const health = client.getHealth();
      expect(health.available).toBe(false);
      expect(health.consecutiveErrors).toBe(5);
    });

    it('should reset health tracking', async () => {
      mockFetch.mockRejectedValue(new Error('Failed'));
      await client.analyze('test');

      client.resetHealth();

      const health = client.getHealth();
      expect(health.consecutiveErrors).toBe(0);
      expect(health.available).toBe(true);
    });
  });

  describe('Health Check', () => {
    it('should return true when service is healthy', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });

      const healthy = await client.checkHealth();
      expect(healthy).toBe(true);
    });

    it('should return false when service is unhealthy', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false });

      const healthy = await client.checkHealth();
      expect(healthy).toBe(false);
    });

    it('should return false on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const healthy = await client.checkHealth();
      expect(healthy).toBe(false);
    });
  });

  describe('Supported Entities', () => {
    it('should get supported entities', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ['PERSON', 'PHONE_NUMBER', 'US_SSN'],
      });

      const entities = await client.getSupportedEntities();
      expect(entities).toContain('US_SSN');
    });

    it('should return empty on error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Failed'));

      const entities = await client.getSupportedEntities();
      expect(entities).toEqual([]);
    });
  });
});

// Integration test (only runs if PRESIDIO_URL is set)
describe.skipIf(!process.env.PRESIDIO_URL)('PresidioClient Integration', () => {
  let client: PresidioClient;

  beforeEach(() => {
    vi.restoreAllMocks();
    client = new PresidioClient({
      analyzerUrl: process.env.PRESIDIO_URL,
    });
  });

  it('should connect to real Presidio', async () => {
    const healthy = await client.checkHealth();
    expect(healthy).toBe(true);
  });

  it('should analyze real text', async () => {
    const result = await client.analyze('My name is John Smith and my email is john@example.com');
    expect(result.success).toBe(true);
    expect(result.entities.length).toBeGreaterThan(0);
  });
});
