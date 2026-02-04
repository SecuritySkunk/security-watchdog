import Database from 'better-sqlite3';
import { ClassificationLevel, CreatePatternInput, UpdatePatternInput, PatternQueryFilter, PatternDefinition, RegistryError, RegistryErrorCode } from './types.js';

export class PatternRepository {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
  }

  /**
   * Insert a new pattern into the database.
   * @param input - The pattern data to insert.
   * @returns The inserted pattern with its ID.
   * @throws RegistryError if there is an error during insertion or locale does not exist.
   */
  create(input: CreatePatternInput): PatternDefinition {
    const stmt = this.db.prepare(`
      INSERT INTO patterns (
        locale_id, category, pattern_type, display_name, presidio_recognizer,
        regex_pattern, regex_flags, validation_function, default_classification,
        false_positive_hints, example_values
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    try {
      this.validateLocale(input.localeId);
      const info = stmt.run(
        input.localeId,
        input.category,
        input.patternType,
        input.displayName,
        input.presidioRecognizer || null,
        input.regexPattern || null,
        input.regexFlags || 'i',
        input.validationFunction || null,
        input.defaultClassification,
        JSON.stringify(input.falsePositiveHints || []),
        JSON.stringify(input.exampleValues || [])
      );
      return this.getById(Number(info.lastInsertRowid)) as PatternDefinition;
    } catch (error: any) {
      if (error.code === 'SQLITE_CONSTRAINT') {
        throw new RegistryError(RegistryErrorCode.CONSTRAINT_VIOLATION, 'Pattern already exists with the same locale_id, category, and pattern_type.');
      }
      throw new RegistryError(RegistryErrorCode.QUERY_ERROR, `Failed to create pattern: ${error.message}`);
    }
  }

  /**
   * Get a single pattern by its ID.
   * @param id - The ID of the pattern to retrieve.
   * @returns The pattern definition or null if not found.
   */
  getById(id: number): PatternDefinition | null {
    const stmt = this.db.prepare(`
      SELECT * FROM patterns WHERE id = ?
    `);
    try {
      const row = stmt.get(id);
      return row ? this.mapRowToPattern(row) : null;
    } catch (error: any) {
      throw new RegistryError(RegistryErrorCode.QUERY_ERROR, `Failed to get pattern by ID: ${error.message}`);
    }
  }

  /**
   * Update fields of an existing pattern.
   * @param id - The ID of the pattern to update.
   * @param input - The fields to update.
   * @returns The updated pattern definition.
   * @throws RegistryError if the pattern is not found or there is an error during update.
   */
  update(id: number, input: UpdatePatternInput): PatternDefinition {
    const stmt = this.db.prepare(`
      UPDATE patterns SET
        display_name = COALESCE(?, display_name),
        presidio_recognizer = COALESCE(?, presidio_recognizer),
        regex_pattern = COALESCE(?, regex_pattern),
        regex_flags = COALESCE(?, regex_flags),
        validation_function = COALESCE(?, validation_function),
        default_classification = COALESCE(?, default_classification),
        false_positive_hints = COALESCE(?, false_positive_hints),
        example_values = COALESCE(?, example_values),
        is_active = COALESCE(?, is_active),
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ?
    `);

    try {
      const result = stmt.run(
        input.displayName,
        input.presidioRecognizer,
        input.regexPattern,
        input.regexFlags,
        input.validationFunction,
        input.defaultClassification,
        input.falsePositiveHints ? JSON.stringify(input.falsePositiveHints) : undefined,
        input.exampleValues ? JSON.stringify(input.exampleValues) : undefined,
        input.isActive !== undefined ? (input.isActive ? 1 : 0) : undefined,
        id
      );

      if (result.changes === 0) {
        throw new RegistryError(RegistryErrorCode.NOT_FOUND, `Pattern with ID ${id} not found.`);
      }

      return this.getById(id) as PatternDefinition;
    } catch (error: any) {
      throw new RegistryError(RegistryErrorCode.QUERY_ERROR, `Failed to update pattern: ${error.message}`);
    }
  }

  /**
   * Deactivate a pattern by setting is_active to 0.
   * @param id - The ID of the pattern to deactivate.
   * @throws RegistryError if the pattern is not found or there is an error during deactivation.
   */
  deactivate(id: number): void {
    const stmt = this.db.prepare(`
      UPDATE patterns SET is_active = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?
    `);

    try {
      const result = stmt.run(id);
      if (result.changes === 0) {
        throw new RegistryError(RegistryErrorCode.NOT_FOUND, `Pattern with ID ${id} not found.`);
      }
    } catch (error: any) {
      throw new RegistryError(RegistryErrorCode.QUERY_ERROR, `Failed to deactivate pattern: ${error.message}`);
    }
  }

  /**
   * Physically delete a pattern from the database.
   * @param id - The ID of the pattern to delete.
   * @throws RegistryError if there is an error during deletion.
   */
  hardDelete(id: number): void {
    const stmt = this.db.prepare(`
      DELETE FROM patterns WHERE id = ?
    `);

    try {
      stmt.run(id);
    } catch (error: any) {
      throw new RegistryError(RegistryErrorCode.QUERY_ERROR, `Failed to delete pattern: ${error.message}`);
    }
  }

  /**
   * List patterns with optional filters.
   * @param filter - The filter criteria for the query.
   * @returns An array of pattern definitions matching the filter.
   */
  list(filter?: PatternQueryFilter): PatternDefinition[] {
    let query = `
      SELECT * FROM patterns
      WHERE 1=1
    `;
    const params: any[] = [];

    if (filter?.localeId) {
      query += ' AND locale_id = ?';
      params.push(filter.localeId);
    }
    if (filter?.category) {
      query += ' AND category = ?';
      params.push(filter.category);
    }
    if (filter?.isActive !== undefined) {
      query += ' AND is_active = ?';
      params.push(filter.isActive ? 1 : 0);
    }
    if (filter?.classification) {
      query += ' AND default_classification = ?';
      params.push(filter.classification);
    }

    if (filter?.limit !== undefined) {
      query += ' LIMIT ?';
      params.push(filter.limit);
    }
    if (filter?.offset !== undefined) {
      query += ' OFFSET ?';
      params.push(filter.offset);
    }

    const stmt = this.db.prepare(query);

    try {
      const rows = stmt.all(...params);
      return rows.map(this.mapRowToPattern);
    } catch (error: any) {
      throw new RegistryError(RegistryErrorCode.QUERY_ERROR, `Failed to list patterns: ${error.message}`);
    }
  }

  /**
   * Bulk load patterns for the scanner based on locale IDs.
   * @param localeIds - An array of locale IDs to filter by.
   * @returns An array of pattern definitions matching the locale IDs.
   */
  preloadForScanner(localeIds: string[]): PatternDefinition[] {
    if (localeIds.length === 0) return [];

    const placeholders = localeIds.map(() => '?').join(',');
    const query = `
      SELECT * FROM patterns WHERE locale_id IN (${placeholders})
    `;
    const stmt = this.db.prepare(query);

    try {
      const rows = stmt.all(...localeIds);
      return rows.map(this.mapRowToPattern);
    } catch (error: any) {
      throw new RegistryError(RegistryErrorCode.QUERY_ERROR, `Failed to preload patterns for scanner: ${error.message}`);
    }
  }

  /**
   * Count the number of patterns matching the filter criteria.
   * @param filter - The filter criteria for the query.
   * @returns The count of patterns matching the filter.
   */
  count(filter?: PatternQueryFilter): number {
    let query = `
      SELECT COUNT(*) FROM patterns
      WHERE 1=1
    `;
    const params: any[] = [];

    if (filter?.localeId) {
      query += ' AND locale_id = ?';
      params.push(filter.localeId);
    }
    if (filter?.category) {
      query += ' AND category = ?';
      params.push(filter.category);
    }
    if (filter?.isActive !== undefined) {
      query += ' AND is_active = ?';
      params.push(filter.isActive ? 1 : 0);
    }
    if (filter?.classification) {
      query += ' AND default_classification = ?';
      params.push(filter.classification);
    }

    const stmt = this.db.prepare(query);

    try {
      return stmt.pluck().get(...params) as number;
    } catch (error: any) {
      throw new RegistryError(RegistryErrorCode.QUERY_ERROR, `Failed to count patterns: ${error.message}`);
    }
  }

  /**
   * Validate that a locale exists in the database.
   * @param localeId - The locale ID to validate.
   * @throws RegistryError if the locale does not exist.
   */
  private validateLocale(localeId: string): void {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) FROM locales WHERE locale_id = ?
    `);

    try {
      const count = stmt.pluck().get(localeId) as number;
      if (count === 0) {
        throw new RegistryError(RegistryErrorCode.INVALID_LOCALE, `Locale with ID ${localeId} does not exist.`);
      }
    } catch (error: any) {
      throw new RegistryError(RegistryErrorCode.QUERY_ERROR, `Failed to validate locale: ${error.message}`);
    }
  }

  /**
   * Map a database row to a PatternDefinition object.
   * @param row - The database row to map.
   * @returns A PatternDefinition object.
   */
  private mapRowToPattern(row: any): PatternDefinition {
    return {
      id: row.id,
      localeId: row.locale_id,
      category: row.category,
      patternType: row.pattern_type,
      displayName: row.display_name,
      presidioRecognizer: row.presidio_recognizer || null,
      regexPattern: row.regex_pattern || null,
      regexFlags: row.regex_flags,
      validationFunction: row.validation_function || null,
      defaultClassification: row.default_classification as ClassificationLevel,
      falsePositiveHints: JSON.parse(row.false_positive_hints) || [],
      exampleValues: JSON.parse(row.example_values) || [],
      isActive: row.is_active === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
