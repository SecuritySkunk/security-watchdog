/**
 * Database Initialization Script
 * 
 * Creates the SQLite database and runs the schema.
 * Usage: npx tsx scripts/init-db.ts [--force]
 * 
 * Options:
 *   --force  Delete existing database and recreate
 */

import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const DB_DIR = path.join(process.env.HOME || '~', '.openclaw', 'security');
const DB_PATH = path.join(DB_DIR, 'registry.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

function main(): void {
  const forceRecreate = process.argv.includes('--force');

  console.log('Security Watchdog — Database Initialization');
  console.log('============================================\n');

  // Ensure directory exists with secure permissions
  if (!fs.existsSync(DB_DIR)) {
    console.log(`Creating directory: ${DB_DIR}`);
    fs.mkdirSync(DB_DIR, { recursive: true, mode: 0o700 });
  }

  // Check for existing database
  if (fs.existsSync(DB_PATH)) {
    if (forceRecreate) {
      console.log(`Removing existing database: ${DB_PATH}`);
      fs.unlinkSync(DB_PATH);
      // Also remove WAL files if they exist
      const walPath = DB_PATH + '-wal';
      const shmPath = DB_PATH + '-shm';
      if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
      if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    } else {
      console.log(`Database already exists at: ${DB_PATH}`);
      console.log('Use --force to recreate.\n');
      process.exit(0);
    }
  }

  // Read schema
  console.log(`Reading schema from: ${SCHEMA_PATH}`);
  const schema = fs.readFileSync(SCHEMA_PATH, 'utf-8');

  // Create database
  console.log(`Creating database at: ${DB_PATH}`);
  const db = new Database(DB_PATH);

  try {
    // Execute schema
    console.log('Executing schema...');
    db.exec(schema);

    // Set secure file permissions
    fs.chmodSync(DB_PATH, 0o600);
    console.log('Set file permissions to 600 (owner read/write only)');

    // Verify tables
    const tables = db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' AND name NOT LIKE 'sqlite_%'
      ORDER BY name
    `).all() as Array<{ name: string }>;

    console.log(`\nCreated ${tables.length} tables:`);
    for (const table of tables) {
      const count = db.prepare(`SELECT COUNT(*) as count FROM "${table.name}"`).get() as { count: number };
      console.log(`  - ${table.name} (${count.count} rows)`);
    }

    console.log('\n✓ Database initialized successfully!\n');

  } catch (error) {
    console.error('\n✗ Error initializing database:', error);
    process.exit(1);
  } finally {
    db.close();
  }
}

main();
