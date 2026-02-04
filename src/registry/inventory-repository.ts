import Database from 'better-sqlite3';
import type { CreateInventoryInput, UpdateInventoryInput, InventoryEntry, InventoryQueryFilter, InventoryStats } from './types.js';

export class InventoryRepository {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
  }

  /**
   * Adds or updates an inventory entry.
   * @param input - The data to create or update the inventory entry with.
   * @returns The created or updated inventory entry.
   */
  addOrUpdate(input: CreateInventoryInput): InventoryEntry {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO inventory (
        registry_ref_type, registry_ref_id, registry_ref_label, storage_location,
        storage_type, data_form, detected_by, current_classification
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      input.registryRefType,
      input.registryRefId,
      input.registryRefLabel,
      input.storageLocation,
      input.storageType,
      input.dataForm || 'verbatim',
      input.detectedBy,
      input.currentClassification
    );

    // Use lastInsertRowid to get the inserted/updated row
    return this.getById(Number(result.lastInsertRowid))!;
  }

  /**
   * Retrieves an inventory entry by its ID.
   * @param id - The ID of the inventory entry to retrieve.
   * @returns The inventory entry or null if not found.
   */
  getById(id: number): InventoryEntry | null {
    const stmt = this.db.prepare(`
      SELECT * FROM inventory WHERE id = ?
    `);
    const row = stmt.get(id);

    return row ? this.mapRowToInventoryEntry(row) : null;
  }

  /**
   * Updates an existing inventory entry.
   * @param id - The ID of the inventory entry to update.
   * @param input - The data to update the inventory entry with.
   * @returns The updated inventory entry.
   */
  update(id: number, input: UpdateInventoryInput): InventoryEntry {
    const stmt = this.db.prepare(`
      UPDATE inventory SET
        storage_location = COALESCE(?, storage_location),
        storage_type = COALESCE(?, storage_type),
        data_form = COALESCE(?, data_form),
        current_classification = COALESCE(?, current_classification),
        is_active = COALESCE(?, is_active),
        deactivated_by = CASE WHEN ? IS NOT NULL THEN ? ELSE deactivated_by END
      WHERE id = ?
    `);
    stmt.run(
      input.storageLocation,
      input.storageType,
      input.dataForm,
      input.currentClassification,
      input.isActive !== undefined ? (input.isActive ? 1 : 0) : null,
      input.deactivatedBy,
      input.deactivatedBy,
      id
    );

    return this.getById(id)!;
  }

  /**
   * Deactivates an inventory entry.
   * @param id - The ID of the inventory entry to deactivate.
   * @param deactivatedBy - The user or system that deactivated the entry.
   */
  deactivate(id: number, deactivatedBy: string): void {
    const stmt = this.db.prepare(`
      UPDATE inventory SET
        is_active = 0,
        deactivated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        deactivated_by = ?
      WHERE id = ?
    `);
    stmt.run(deactivatedBy, id);
  }

  /**
   * Verifies an inventory entry by updating the last_verified_at timestamp.
   * @param id - The ID of the inventory entry to verify.
   */
  verify(id: number): void {
    const stmt = this.db.prepare(`
      UPDATE inventory SET
        last_verified_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ?
    `);
    stmt.run(id);
  }

  /**
   * Queries inventory entries based on the provided filter.
   * @param filter - The filter criteria for querying inventory entries.
   * @returns An array of inventory entries that match the filter criteria.
   */
  query(filter?: InventoryQueryFilter): InventoryEntry[] {
    let query = `
      SELECT * FROM inventory WHERE 1=1
    `;
    const params: any[] = [];

    if (filter?.classification) {
      query += ' AND current_classification = ?';
      params.push(filter.classification);
    }
    if (filter?.storageType) {
      query += ' AND storage_type = ?';
      params.push(filter.storageType);
    }
    if (filter?.storageLocation) {
      query += ' AND storage_location = ?';
      params.push(filter.storageLocation);
    }
    if (filter?.isActive !== undefined) {
      query += ' AND is_active = ?';
      params.push(filter.isActive ? 1 : 0);
    }
    if (filter?.registryRefType) {
      query += ' AND registry_ref_type = ?';
      params.push(filter.registryRefType);
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
    const rows = stmt.all(...params);

    return rows.map(row => this.mapRowToInventoryEntry(row));
  }

  /**
   * Retrieves statistics about the inventory entries.
   * @returns An object containing various statistics about the inventory entries.
   */
  getStats(): InventoryStats {
    const activeStmt = this.db.prepare(`
      SELECT COUNT(*) AS total_active FROM inventory WHERE is_active = 1
    `);
    const inactiveStmt = this.db.prepare(`
      SELECT COUNT(*) AS total_inactive FROM inventory WHERE is_active = 0
    `);
    const classificationStmt = this.db.prepare(`
      SELECT current_classification, COUNT(*) AS count
      FROM inventory WHERE is_active = 1
      GROUP BY current_classification
    `);
    const storageTypeStmt = this.db.prepare(`
      SELECT storage_type, COUNT(*) AS count
      FROM inventory WHERE is_active = 1
      GROUP BY storage_type
    `);
    const dataFormStmt = this.db.prepare(`
      SELECT data_form, COUNT(*) AS count
      FROM inventory WHERE is_active = 1
      GROUP BY data_form
    `);
    const oldestStmt = this.db.prepare(`
      SELECT * FROM inventory WHERE is_active = 1 ORDER BY first_detected_at ASC LIMIT 1
    `);
    const newestStmt = this.db.prepare(`
      SELECT * FROM inventory WHERE is_active = 1 ORDER BY first_detected_at DESC LIMIT 1
    `);

    const activeResult = activeStmt.get() as { total_active: number } | undefined;
    const inactiveResult = inactiveStmt.get() as { total_inactive: number } | undefined;
    const totalActive = activeResult?.total_active ?? 0;
    const totalInactive = inactiveResult?.total_inactive ?? 0;
    
    const classificationRows = classificationStmt.all() as Array<{ current_classification: string; count: number }>;
    const byClassification: Record<string, number> = {};
    for (const row of classificationRows) {
      byClassification[row.current_classification] = row.count;
    }
    
    const storageTypeRows = storageTypeStmt.all() as Array<{ storage_type: string; count: number }>;
    const byStorageType: Record<string, number> = {};
    for (const row of storageTypeRows) {
      byStorageType[row.storage_type] = row.count;
    }
    
    const dataFormRows = dataFormStmt.all() as Array<{ data_form: string; count: number }>;
    const byDataForm: Record<string, number> = {};
    for (const row of dataFormRows) {
      byDataForm[row.data_form] = row.count;
    }
    
    const oldestRow = oldestStmt.get();
    const newestRow = newestStmt.get();
    const oldestActiveItem = oldestRow ? this.mapRowToInventoryEntry(oldestRow) : null;
    const newestActiveItem = newestRow ? this.mapRowToInventoryEntry(newestRow) : null;

    return {
      totalActive,
      totalInactive,
      byClassification,
      byStorageType,
      byDataForm,
      oldestActiveItem,
      newestActiveItem,
    };
  }

  /**
   * Retrieves posture input data from the v_posture_input view.
   * @returns An object containing posture input data.
   */
  getPostureInput(): { neverShareCount: number; askFirstCount: number; internalOnlyCount: number; totalActive: number } {
    const stmt = this.db.prepare(`
      SELECT never_share_count, ask_first_count, internal_only_count, total_active
      FROM v_posture_input
    `);
    const row = stmt.get() as { never_share_count: number; ask_first_count: number; internal_only_count: number; total_active: number } | undefined;
    return {
      neverShareCount: row?.never_share_count ?? 0,
      askFirstCount: row?.ask_first_count ?? 0,
      internalOnlyCount: row?.internal_only_count ?? 0,
      totalActive: row?.total_active ?? 0,
    };
  }

  /**
   * Deactivates inventory entries by storage location.
   * @param storageLocation - The storage location to deactivate entries for.
   * @param deactivatedBy - The user or system that deactivated the entries.
   * @returns The number of entries deactivated.
   */
  deactivateByLocation(storageLocation: string, deactivatedBy: string): number {
    const stmt = this.db.prepare(`
      UPDATE inventory SET
        is_active = 0,
        deactivated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        deactivated_by = ?
      WHERE storage_location = ? AND is_active = 1
    `);
    return stmt.run(deactivatedBy, storageLocation).changes;
  }

  /**
   * Purges inactive inventory entries older than a specified number of days.
   * @param olderThanDays - The number of days after which to purge inactive entries.
   * @returns The number of entries purged.
   */
  purgeInactive(olderThanDays: number): number {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);
    const stmt = this.db.prepare(`
      DELETE FROM inventory
      WHERE is_active = 0 AND deactivated_at < ?
    `);
    return stmt.run(cutoffDate.toISOString()).changes;
  }

  /**
   * Finds stale inventory entries that have not been verified in a specified number of hours.
   * @param olderThanHours - The number of hours after which an entry is considered stale.
   * @returns An array of stale inventory entries.
   */
  findStale(olderThanHours: number): InventoryEntry[] {
    const cutoffDate = new Date();
    cutoffDate.setHours(cutoffDate.getHours() - olderThanHours);
    const stmt = this.db.prepare(`
      SELECT * FROM inventory
      WHERE is_active = 1 AND last_verified_at < ?
    `);
    const rows = stmt.all(cutoffDate.toISOString());

    return rows.map(row => this.mapRowToInventoryEntry(row));
  }

  /**
   * Maps a database row to an InventoryEntry object.
   * @param row - The database row to map.
   * @returns An InventoryEntry object.
   */
  private mapRowToInventoryEntry(row: any): InventoryEntry {
    return {
      id: row.id,
      registryRefType: row.registry_ref_type,
      registryRefId: row.registry_ref_id,
      registryRefLabel: row.registry_ref_label,
      storageLocation: row.storage_location,
      storageType: row.storage_type,
      dataForm: row.data_form,
      detectedBy: row.detected_by,
      currentClassification: row.current_classification,
      isActive: row.is_active === 1,
      firstDetectedAt: row.first_detected_at,
      lastVerifiedAt: row.last_verified_at,
      deactivatedAt: row.deactivated_at || null,
      deactivatedBy: row.deactivated_by || null,
    };
  }
}
