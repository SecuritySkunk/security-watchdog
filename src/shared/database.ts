/**
 * Security Watchdog — Database Connection Manager
 * 
 * Provides a singleton database connection with proper configuration.
 */

import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as path from 'path';
import pino from 'pino';

const logger = pino({ name: 'watchdog:database' });

export interface DatabaseConfig {
  dbPath: string;
  walMode?: boolean;
  verbose?: boolean;
}

const DEFAULT_DB_PATH = path.join(
  process.env['HOME'] ?? '~',
  '.openclaw',
  'security',
  'registry.db'
);

let dbInstance: Database.Database | null = null;

/**
 * Get or create the database connection.
 */
export function getDatabase(config?: Partial<DatabaseConfig>): Database.Database {
  if (dbInstance !== null) {
    return dbInstance;
  }

  const dbPath = config?.dbPath ?? DEFAULT_DB_PATH;
  const walMode = config?.walMode ?? true;

  // Verify database file exists
  if (!fs.existsSync(dbPath)) {
    throw new Error(`Database file not found: ${dbPath}. Run 'npm run db:init' first.`);
  }

  logger.info({ dbPath }, 'Opening database connection');

  dbInstance = new Database(dbPath, {
    verbose: config?.verbose === true ? (msg) => logger.debug(msg) : undefined,
  });

  // Configure pragmas
  if (walMode) {
    dbInstance.pragma('journal_mode = WAL');
  }
  dbInstance.pragma('busy_timeout = 5000');
  dbInstance.pragma('foreign_keys = ON');
  dbInstance.pragma('synchronous = NORMAL');
  dbInstance.pragma('cache_size = -8000');
  dbInstance.pragma('temp_store = MEMORY');

  // Verify connection
  const version = dbInstance.pragma('user_version', { simple: true });
  logger.info({ version }, 'Database connection established');

  return dbInstance;
}

/**
 * Close the database connection.
 */
export function closeDatabase(): void {
  if (dbInstance !== null) {
    logger.info('Closing database connection');
    dbInstance.close();
    dbInstance = null;
  }
}

/**
 * Check if the database is connected.
 */
export function isDatabaseConnected(): boolean {
  return dbInstance !== null && dbInstance.open;
}

/**
 * Get database status information.
 */
export function getDatabaseStatus(): {
  connected: boolean;
  path: string | null;
  walMode: boolean;
} {
  if (dbInstance === null) {
    return { connected: false, path: null, walMode: false };
  }

  const journalMode = dbInstance.pragma('journal_mode', { simple: true }) as string;

  return {
    connected: dbInstance.open,
    path: dbInstance.name,
    walMode: journalMode.toLowerCase() === 'wal',
  };
}
