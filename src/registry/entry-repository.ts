import Database from 'better-sqlite3';
import { 
  ClassificationLevel, 
  RegistryError, 
  RegistryErrorCode,
  type UserDefinedEntry,
  type EntryVariant,
  type CreateEntryInput,
  type UpdateEntryInput,
  type EntryQueryFilter,
} from './types.js';

export class EntryRepository {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
  }

  /**
   * Create a new user-defined entry with optional variants.
   * @param input - The data for creating the entry.
   * @returns The created entry with its variants.
   */
  create(input: CreateEntryInput): UserDefinedEntry & { variants: EntryVariant[] } {
    const stmt = this.db.prepare(`
      INSERT INTO user_entries (label, display_name, primary_value, classification, category, notes)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const variantStmt = this.db.prepare(`
      INSERT INTO entry_variants (entry_id, variant_text) VALUES (?, ?)
    `);

    let entryId: number = 0;
    try {
      this.db.transaction(() => {
        const info = stmt.run(
          input.label,
          input.displayName,
          input.primaryValue,
          input.classification,
          input.category || 'general',
          input.notes || null
        );
        if (!info.lastInsertRowid) throw new RegistryError(RegistryErrorCode.INTERNAL_ERROR, 'Failed to insert entry');
        entryId = Number(info.lastInsertRowid);

        if (input.variants) {
          for (const variant of input.variants) {
            try {
              variantStmt.run(entryId, variant);
            } catch (error: any) {
              if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                throw new RegistryError(RegistryErrorCode.DUPLICATE_VARIANT, `Variant "${variant}" already exists for this entry`);
              }
              throw error;
            }
          }
        }
      })();
    } catch (error: any) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw new RegistryError(RegistryErrorCode.DUPLICATE_LABEL, `Label "${input.label}" already exists`);
      }
      throw error;
    }

    return this.getById(entryId)!; // Safe to assert non-null since we just inserted it
  }

  /**
   * Get a user-defined entry by its ID.
   * @param id - The ID of the entry.
   * @returns The entry with its variants, or null if not found.
   */
  getById(id: number): (UserDefinedEntry & { variants: EntryVariant[] }) | null {
    const entryStmt = this.db.prepare(`
      SELECT * FROM user_entries WHERE id = ?
    `);
    const variantStmt = this.db.prepare(`
      SELECT * FROM entry_variants WHERE entry_id = ?
    `);

    const entryRow = entryStmt.get(id) as any;
    if (!entryRow) return null;

    const variantRows = variantStmt.all(id) as any[];
    const variants: EntryVariant[] = variantRows.map(row => ({
      id: row.id as number,
      entryId: row.entry_id as number,
      variantText: row.variant_text as string,
      createdAt: row.created_at as string,
    }));

    return {
      id: entryRow.id as number,
      label: entryRow.label as string,
      displayName: entryRow.display_name as string,
      primaryValue: entryRow.primary_value as string,
      classification: entryRow.classification as ClassificationLevel,
      category: entryRow.category as string,
      notes: entryRow.notes as string | null,
      isActive: Boolean(entryRow.is_active),
      createdAt: entryRow.created_at as string,
      updatedAt: entryRow.updated_at as string,
      variants,
    };
  }

  /**
   * Get a user-defined entry by its label.
   * @param label - The label of the entry.
   * @returns The entry with its variants, or null if not found.
   */
  getByLabel(label: string): (UserDefinedEntry & { variants: EntryVariant[] }) | null {
    const entryStmt = this.db.prepare(`
      SELECT * FROM user_entries WHERE label = ?
    `);
    const variantStmt = this.db.prepare(`
      SELECT * FROM entry_variants WHERE entry_id = ?
    `);

    const entryRow = entryStmt.get(label) as any;
    if (!entryRow) return null;

    const variantRows = variantStmt.all(entryRow.id) as any[];
    const variants: EntryVariant[] = variantRows.map(row => ({
      id: row.id as number,
      entryId: row.entry_id as number,
      variantText: row.variant_text as string,
      createdAt: row.created_at as string,
    }));

    return {
      id: entryRow.id as number,
      label: entryRow.label as string,
      displayName: entryRow.display_name as string,
      primaryValue: entryRow.primary_value as string,
      classification: entryRow.classification as ClassificationLevel,
      category: entryRow.category as string,
      notes: entryRow.notes as string | null,
      isActive: Boolean(entryRow.is_active),
      createdAt: entryRow.created_at as string,
      updatedAt: entryRow.updated_at as string,
      variants,
    };
  }

  /**
   * Update an existing user-defined entry.
   * @param id - The ID of the entry to update.
   * @param input - The data for updating the entry.
   * @returns The updated entry.
   */
  update(id: number, input: UpdateEntryInput): UserDefinedEntry {
    const stmt = this.db.prepare(`
      UPDATE user_entries
      SET display_name = ?, primary_value = ?, classification = ?, category = ?, notes = ?, is_active = ?
      WHERE id = ?
    `);

    try {
      const info = stmt.run(
        input.displayName || undefined,
        input.primaryValue || undefined,
        input.classification || undefined,
        input.category || undefined,
        input.notes !== undefined ? input.notes : undefined,
        input.isActive !== undefined ? (input.isActive ? 1 : 0) : undefined,
        id
      );
      if (info.changes === 0) throw new RegistryError(RegistryErrorCode.NOT_FOUND, `Entry with ID ${id} not found`);
    } catch (error: any) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw new RegistryError(RegistryErrorCode.CONSTRAINT_VIOLATION, 'Update violates a unique constraint');
      }
      throw error;
    }

    const result = this.getById(id);
    if (result === null) {
      throw new RegistryError(RegistryErrorCode.NOT_FOUND, `Entry with ID ${id} not found after update`);
    }
    return result;
  }

  /**
   * Deactivate a user-defined entry.
   * @param id - The ID of the entry to deactivate.
   */
  deactivate(id: number): void {
    const stmt = this.db.prepare(`
      UPDATE user_entries SET is_active = 0 WHERE id = ?
    `);
    const info = stmt.run(id);
    if (info.changes === 0) throw new RegistryError(RegistryErrorCode.NOT_FOUND, `Entry with ID ${id} not found`);
  }

  /**
   * Hard delete a user-defined entry.
   * @param id - The ID of the entry to delete.
   */
  hardDelete(id: number): void {
    const stmt = this.db.prepare(`
      DELETE FROM user_entries WHERE id = ?
    `);
    const info = stmt.run(id);
    if (info.changes === 0) throw new RegistryError(RegistryErrorCode.NOT_FOUND, `Entry with ID ${id} not found`);
  }

  /**
   * List user-defined entries based on optional filters.
   * @param filter - The filters to apply.
   * @returns An array of entries.
   */
  list(filter?: EntryQueryFilter): UserDefinedEntry[] {
    let query = `
      SELECT * FROM user_entries
      WHERE 1=1
    `;
    const params: any[] = [];

    if (filter?.category) {
      query += ' AND category = ?';
      params.push(filter.category);
    }
    if (filter?.classification) {
      query += ' AND classification = ?';
      params.push(filter.classification);
    }
    if (filter?.isActive !== undefined) {
      query += ' AND is_active = ?';
      params.push(filter.isActive ? 1 : 0);
    }
    if (filter?.keyword) {
      query += ` AND (label LIKE ? OR display_name LIKE ? OR primary_value LIKE ?)`;
      const keyword = `%${filter.keyword}%`;
      params.push(keyword, keyword, keyword);
    }

    query += ' ORDER BY created_at DESC';

    if (filter?.limit !== undefined) {
      query += ' LIMIT ?';
      params.push(filter.limit);
    }
    if (filter?.offset !== undefined) {
      query += ' OFFSET ?';
      params.push(filter.offset);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as any[];

    return rows.map(row => ({
      id: row.id,
      label: row.label,
      displayName: row.display_name,
      primaryValue: row.primary_value,
      classification: row.classification as ClassificationLevel,
      category: row.category,
      notes: row.notes,
      isActive: !!row.is_active,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  /**
   * Preload entries for the scanner with their variant texts as string arrays.
   * @returns An array of entries with variants as strings.
   */
  preloadForScanner(): Array<UserDefinedEntry & { variants: string[] }> {
    const entryStmt = this.db.prepare(`
      SELECT * FROM user_entries
    `);
    const variantStmt = this.db.prepare(`
      SELECT variant_text FROM entry_variants WHERE entry_id = ?
    `);

    const entries = entryStmt.all() as any[];
    return entries.map(entryRow => {
      const variants = variantStmt.all(entryRow.id) as { variant_text: string }[];
      return {
        id: entryRow.id,
        label: entryRow.label,
        displayName: entryRow.display_name,
        primaryValue: entryRow.primary_value,
        classification: entryRow.classification as ClassificationLevel,
        category: entryRow.category,
        notes: entryRow.notes,
        isActive: !!entryRow.is_active,
        createdAt: entryRow.created_at,
        updatedAt: entryRow.updated_at,
        variants: variants.map(v => v.variant_text),
      };
    });
  }

  /**
   * Count user-defined entries based on optional filters.
   * @param filter - The filters to apply.
   * @returns The count of entries.
   */
  count(filter?: EntryQueryFilter): number {
    let query = `
      SELECT COUNT(*) FROM user_entries
      WHERE 1=1
    `;
    const params: any[] = [];

    if (filter?.category) {
      query += ' AND category = ?';
      params.push(filter.category);
    }
    if (filter?.classification) {
      query += ' AND classification = ?';
      params.push(filter.classification);
    }
    if (filter?.isActive !== undefined) {
      query += ' AND is_active = ?';
      params.push(filter.isActive ? 1 : 0);
    }
    if (filter?.keyword) {
      query += ` AND (label LIKE ? OR display_name LIKE ? OR primary_value LIKE ?)`;
      const keyword = `%${filter.keyword}%`;
      params.push(keyword, keyword, keyword);
    }

    const stmt = this.db.prepare(query);
    const result = stmt.get(...params) as { 'COUNT(*)': number };
    return result['COUNT(*)'];
  }

  /**
   * Add a variant to an existing user-defined entry.
   * @param entryId - The ID of the entry.
   * @param variantText - The text of the variant.
   * @returns The created variant.
   */
  addVariant(entryId: number, variantText: string): EntryVariant {
    const stmt = this.db.prepare(`
      INSERT INTO entry_variants (entry_id, variant_text) VALUES (?, ?)
    `);

    try {
      const info = stmt.run(entryId, variantText);
      if (!info.lastInsertRowid) throw new RegistryError(RegistryErrorCode.INTERNAL_ERROR, 'Failed to insert variant');
      return this.getVariantById(Number(info.lastInsertRowid))!; // Safe to assert non-null since we just inserted it
    } catch (error: any) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw new RegistryError(RegistryErrorCode.DUPLICATE_VARIANT, `Variant "${variantText}" already exists for this entry`);
      }
      throw error;
    }
  }

  /**
   * Remove a variant by its ID.
   * @param variantId - The ID of the variant to remove.
   */
  removeVariant(variantId: number): void {
    const stmt = this.db.prepare(`
      DELETE FROM entry_variants WHERE id = ?
    `);
    const info = stmt.run(variantId);
    if (info.changes === 0) throw new RegistryError(RegistryErrorCode.NOT_FOUND, `Variant with ID ${variantId} not found`);
  }

  /**
   * List variants for a specific user-defined entry.
   * @param entryId - The ID of the entry.
   * @returns An array of variants.
   */
  listVariants(entryId: number): EntryVariant[] {
    const stmt = this.db.prepare(`
      SELECT * FROM entry_variants WHERE entry_id = ?
    `);
    const rows = stmt.all(entryId) as any[];

    return rows.map(row => ({
      id: row.id,
      entryId: row.entry_id,
      variantText: row.variant_text,
      createdAt: row.created_at,
    }));
  }

  /**
   * Get a variant by its ID.
   * @param variantId - The ID of the variant.
   * @returns The variant, or null if not found.
   */
  private getVariantById(variantId: number): EntryVariant | null {
    const stmt = this.db.prepare(`
      SELECT * FROM entry_variants WHERE id = ?
    `);
    const row = stmt.get(variantId) as any;
    if (!row) return null;

    return {
      id: row.id,
      entryId: row.entry_id,
      variantText: row.variant_text,
      createdAt: row.created_at,
    };
  }
}
