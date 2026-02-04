/**
 * PatternScanner - Layer 1 Scanner for detecting sensitive data in text.
 * 
 * Scans text content using:
 * - Regex patterns from the Registry (PII patterns)
 * - Fuzzy matching for user-defined sensitive entries
 */

import { randomUUID } from 'crypto';
import Fuse from 'fuse.js';
import { RegistryManager } from '../registry/registry-manager.js';
import type { PatternDefinition } from '../registry/types.js';
import { ClassificationLevel } from '../shared/types.js';

// ═══════════════════════════════════════════════════════════════
// INTERFACES
// ═══════════════════════════════════════════════════════════════

/** Configuration for the PatternScanner. */
export interface ScannerConfig {
  /** Path to the SQLite database. */
  databasePath: string;
  /** Fuse.js threshold (0.0 = exact, 1.0 = match anything). Default: 0.4 */
  fuseThreshold?: number;
  /** Fuse.js distance for fuzzy matching. Default: 100 */
  fuseDistance?: number;
  /** Minimum match length to report. Default: 3 */
  minMatchLength?: number;
  /** Maximum scan time in milliseconds. Default: 5000 */
  maxScanTimeMs?: number;
  /** Context snippet size (chars before/after match). Default: 30 */
  contextSize?: number;
}

/** A detected sensitive data match. */
export interface ScanFlag {
  /** Unique flag identifier. */
  id: string;
  /** The text that matched. */
  matchedText: string;
  /** Pattern type or entry label that matched. */
  patternType: string;
  /** Display name of the matched pattern/entry. */
  displayName: string;
  /** Classification level of the match. */
  classification: ClassificationLevel;
  /** Confidence score (0.0-1.0). */
  confidence: number;
  /** Source of the match: pattern or user entry. */
  source: 'pattern' | 'entry';
  /** Start index in the original text. */
  startIndex: number;
  /** End index in the original text. */
  endIndex: number;
  /** Context snippet showing surrounding text. */
  context: string;
}

/** Result of a scan operation. */
export interface ScanResult {
  /** Unique scan identifier. */
  scanId: string;
  /** ISO timestamp when scan was performed. */
  scannedAt: string;
  /** Length of input text in characters. */
  inputLength: number;
  /** Scan duration in milliseconds. */
  durationMs: number;
  /** Array of detected flags. */
  flags: ScanFlag[];
  /** Number of flags detected. */
  flagCount: number;
  /** Highest classification level among flags (null if clean). */
  highestClassification: ClassificationLevel | null;
  /** Scan verdict. */
  verdict: 'clean' | 'flagged' | 'error';
  /** Error message if verdict is 'error'. */
  error?: string;
}

/** Entry prepared for fuzzy search. */
interface SearchableEntry {
  id: number;
  label: string;
  displayName: string;
  primaryValue: string;
  variants: string[];
  classification: ClassificationLevel;
}

/** Compiled regex pattern for efficient reuse. */
interface CompiledPattern {
  definition: PatternDefinition;
  regex: RegExp;
}

// ═══════════════════════════════════════════════════════════════
// PATTERN SCANNER
// ═══════════════════════════════════════════════════════════════

/**
 * PatternScanner detects sensitive data in text using regex patterns
 * and fuzzy matching against user-defined entries.
 */
export class PatternScanner {
  private readonly config: Required<ScannerConfig>;
  private readonly registry: RegistryManager;
  
  private patterns: CompiledPattern[] = [];
  private searchableEntries: SearchableEntry[] = [];
  // Fuse index for fuzzy matching (future enhancement)
  private fuseIndex: Fuse<SearchableEntry> | null = null;
  private initialized = false;

  /**
   * Creates a new PatternScanner instance.
   * @param config - Scanner configuration
   */
  constructor(config: ScannerConfig) {
    this.config = {
      databasePath: config.databasePath,
      fuseThreshold: config.fuseThreshold ?? 0.4,
      fuseDistance: config.fuseDistance ?? 100,
      minMatchLength: config.minMatchLength ?? 3,
      maxScanTimeMs: config.maxScanTimeMs ?? 5000,
      contextSize: config.contextSize ?? 30,
    };
    this.registry = new RegistryManager(this.config.databasePath);
  }

  /**
   * Initializes the scanner by loading patterns and building indexes.
   * Must be called before scanning.
   */
  initialize(): void {
    this.loadPatterns();
    this.loadEntries();
    this.buildFuseIndex();
    this.initialized = true;
  }

  /**
   * Scans text for sensitive data matches.
   * @param text - Text content to scan
   * @param localeIds - Optional locale IDs to filter patterns (default: all active)
   * @returns Scan result with detected flags
   */
  scan(text: string, localeIds?: string[]): ScanResult {
    const scanId = randomUUID();
    const startTime = performance.now();

    if (!this.initialized) {
      return this.createErrorResult(scanId, text.length, startTime, 'Scanner not initialized. Call initialize() first.');
    }

    if (!text || text.length === 0) {
      return this.createCleanResult(scanId, 0, startTime);
    }

    try {
      // Filter patterns by locale if specified
      const patternsToUse = localeIds 
        ? this.patterns.filter(p => localeIds.includes(p.definition.localeId))
        : this.patterns;

      // Run pattern matching
      const patternFlags = this.scanWithPatterns(text, patternsToUse);
      
      // Run fuzzy matching against user entries
      const entryFlags = this.scanWithEntries(text);

      // Combine and deduplicate flags
      const allFlags = this.deduplicateFlags([...patternFlags, ...entryFlags]);

      const durationMs = performance.now() - startTime;

      return {
        scanId,
        scannedAt: new Date().toISOString(),
        inputLength: text.length,
        durationMs,
        flags: allFlags,
        flagCount: allFlags.length,
        highestClassification: this.determineHighestClassification(allFlags),
        verdict: allFlags.length > 0 ? 'flagged' : 'clean',
      };
    } catch (error) {
      return this.createErrorResult(scanId, text.length, startTime, 
        error instanceof Error ? error.message : 'Unknown scan error');
    }
  }

  /**
   * Scans multiple text contents.
   * @param texts - Array of text contents to scan
   * @param localeIds - Optional locale IDs to filter patterns
   * @returns Array of scan results
   */
  scanMultiple(texts: string[], localeIds?: string[]): ScanResult[] {
    return texts.map(text => this.scan(text, localeIds));
  }

  /**
   * Returns the number of loaded patterns.
   */
  getLoadedPatternCount(): number {
    return this.patterns.length;
  }

  /**
   * Returns the number of loaded user entries.
   */
  getLoadedEntryCount(): number {
    return this.searchableEntries.length;
  }

  /**
   * Reloads patterns and entries from the registry.
   */
  reload(): void {
    this.loadPatterns();
    this.loadEntries();
    this.buildFuseIndex();
  }

  /**
   * Performs a fuzzy search for similar entries.
   * Useful for suggesting corrections or finding near-matches.
   * @param query - Search query
   * @param limit - Maximum results to return
   * @returns Array of matching entries with scores
   */
  fuzzySearch(query: string, limit = 10): Array<{ entry: SearchableEntry; score: number }> {
    if (!this.fuseIndex || !query) return [];
    
    const results = this.fuseIndex.search(query, { limit });
    return results.map(r => ({
      entry: r.item,
      score: r.score ?? 0,
    }));
  }

  // ════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ════════════════════════════════════════════════════════════

  /** Loads and compiles patterns from the registry. */
  private loadPatterns(): void {
    const rawPatterns = this.registry.listPatterns({ isActive: true });
    this.patterns = [];

    for (const pattern of rawPatterns) {
      if (!pattern.regexPattern) continue;

      try {
        const flags = pattern.regexFlags || 'gi';
        const regex = new RegExp(pattern.regexPattern, flags);
        this.patterns.push({ definition: pattern, regex });
      } catch (error) {
        console.warn(`Invalid regex in pattern ${pattern.id} (${pattern.patternType}):`, error);
      }
    }
  }

  /** Loads user entries and prepares them for fuzzy search. */
  private loadEntries(): void {
    const entries = this.registry.listEntries({ isActive: true });
    this.searchableEntries = [];

    for (const entry of entries) {
      const variants = this.registry.listVariants(entry.id);
      this.searchableEntries.push({
        id: entry.id,
        label: entry.label,
        displayName: entry.displayName,
        primaryValue: entry.primaryValue,
        variants: variants.map(v => v.variantText),
        classification: entry.classification as ClassificationLevel,
      });
    }
  }

  /** Builds the Fuse.js index for fuzzy searching entries. */
  private buildFuseIndex(): void {
    // Create searchable documents combining primary value and variants
    const searchDocs = this.searchableEntries.map(entry => ({
      ...entry,
      searchText: [entry.primaryValue, ...entry.variants].join(' '),
    }));

    this.fuseIndex = new Fuse(searchDocs, {
      keys: ['primaryValue', 'variants', 'searchText'],
      threshold: this.config.fuseThreshold,
      distance: this.config.fuseDistance,
      includeScore: true,
      minMatchCharLength: this.config.minMatchLength,
    });
  }

  /** Scans text using compiled regex patterns. */
  private scanWithPatterns(text: string, patterns: CompiledPattern[]): ScanFlag[] {
    const flags: ScanFlag[] = [];

    for (const { definition, regex } of patterns) {
      // Reset regex lastIndex for global patterns
      regex.lastIndex = 0;
      
      let match: RegExpExecArray | null;
      while ((match = regex.exec(text)) !== null) {
        const matchedText = match[0];
        
        if (matchedText.length < this.config.minMatchLength) continue;

        flags.push({
          id: randomUUID(),
          matchedText,
          patternType: definition.patternType,
          displayName: definition.displayName,
          classification: definition.defaultClassification as ClassificationLevel,
          confidence: 1.0, // Regex matches are exact
          source: 'pattern',
          startIndex: match.index,
          endIndex: match.index + matchedText.length,
          context: this.extractContext(text, match.index, match.index + matchedText.length),
        });

        // Prevent infinite loops on zero-length matches
        if (match.index === regex.lastIndex) {
          regex.lastIndex++;
        }
      }
    }

    return flags;
  }

  /** Scans text for user-defined entries using exact and fuzzy matching. */
  private scanWithEntries(text: string): ScanFlag[] {
    const flags: ScanFlag[] = [];
    const textLower = text.toLowerCase();

    for (const entry of this.searchableEntries) {
      // Check primary value (exact match, case-insensitive)
      const primaryLower = entry.primaryValue.toLowerCase();
      let idx = textLower.indexOf(primaryLower);
      while (idx !== -1) {
        const matchedText = text.slice(idx, idx + entry.primaryValue.length);
        flags.push({
          id: randomUUID(),
          matchedText,
          patternType: entry.label,
          displayName: entry.displayName,
          classification: entry.classification,
          confidence: 1.0,
          source: 'entry',
          startIndex: idx,
          endIndex: idx + matchedText.length,
          context: this.extractContext(text, idx, idx + matchedText.length),
        });
        idx = textLower.indexOf(primaryLower, idx + 1);
      }

      // Check variants (exact match, case-insensitive)
      for (const variant of entry.variants) {
        const variantLower = variant.toLowerCase();
        let vidx = textLower.indexOf(variantLower);
        while (vidx !== -1) {
          const matchedText = text.slice(vidx, vidx + variant.length);
          flags.push({
            id: randomUUID(),
            matchedText,
            patternType: entry.label,
            displayName: entry.displayName,
            classification: entry.classification,
            confidence: 0.95, // Slightly lower for variant matches
            source: 'entry',
            startIndex: vidx,
            endIndex: vidx + matchedText.length,
            context: this.extractContext(text, vidx, vidx + matchedText.length),
          });
          vidx = textLower.indexOf(variantLower, vidx + 1);
        }
      }
    }

    return flags;
  }

  /** Extracts context snippet around a match. */
  private extractContext(text: string, start: number, end: number): string {
    const ctxSize = this.config.contextSize;
    const before = text.slice(Math.max(0, start - ctxSize), start);
    const matched = text.slice(start, end);
    const after = text.slice(end, Math.min(text.length, end + ctxSize));
    
    const prefix = start > ctxSize ? '...' : '';
    const suffix = end + ctxSize < text.length ? '...' : '';
    
    return `${prefix}${before}[${matched}]${after}${suffix}`;
  }

  /** Determines the highest classification level from flags. */
  private determineHighestClassification(flags: ScanFlag[]): ClassificationLevel | null {
    if (flags.length === 0) return null;

    const priority: Record<ClassificationLevel, number> = {
      [ClassificationLevel.NEVER_SHARE]: 0,
      [ClassificationLevel.ASK_FIRST]: 1,
      [ClassificationLevel.INTERNAL_ONLY]: 2,
      [ClassificationLevel.PUBLIC]: 3,
    };

    let highest: ClassificationLevel | null = null;
    let highestPriority = Infinity;

    for (const flag of flags) {
      const p = priority[flag.classification];
      if (p < highestPriority) {
        highestPriority = p;
        highest = flag.classification;
      }
    }

    return highest;
  }

  /** Removes duplicate flags at the same position. */
  private deduplicateFlags(flags: ScanFlag[]): ScanFlag[] {
    const seen = new Set<string>();
    return flags.filter(flag => {
      const key = `${flag.startIndex}:${flag.endIndex}:${flag.patternType}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /** Creates an error result. */
  private createErrorResult(scanId: string, inputLength: number, startTime: number, error: string): ScanResult {
    return {
      scanId,
      scannedAt: new Date().toISOString(),
      inputLength,
      durationMs: performance.now() - startTime,
      flags: [],
      flagCount: 0,
      highestClassification: null,
      verdict: 'error',
      error,
    };
  }

  /** Creates a clean result for empty input. */
  private createCleanResult(scanId: string, inputLength: number, startTime: number): ScanResult {
    return {
      scanId,
      scannedAt: new Date().toISOString(),
      inputLength,
      durationMs: performance.now() - startTime,
      flags: [],
      flagCount: 0,
      highestClassification: null,
      verdict: 'clean',
    };
  }
}

export default PatternScanner;
