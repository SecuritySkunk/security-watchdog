#!/usr/bin/env node
/**
 * Dashboard CLI — Start the Security Watchdog Dashboard
 * 
 * Usage:
 *   npx tsx src/dashboard/cli.ts --db ./watchdog.db
 *   npx tsx src/dashboard/cli.ts --db ./watchdog.db --port 3000
 * 
 * Environment variables:
 *   WATCHDOG_DB    - Path to SQLite database (default: ~/.openclaw/security/registry.db)
 *   WATCHDOG_PORT  - Server port (default: 3847)
 *   NODE_ENV       - Set to 'production' for production mode
 *   LOG_LEVEL      - Logging level (debug, info, warn, error)
 */

import { DashboardServer } from './server.js';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const args = process.argv.slice(2);

function getArg(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1) return undefined;
  return args[idx + 1];
}

function showHelp(): void {
  console.log(`
🛡️  Security Watchdog Dashboard

Usage:
  npx tsx src/dashboard/cli.ts [options]
  npm run dashboard -- [options]

Options:
  --db <path>     Path to SQLite database
  --port <number> Server port (default: 3847)
  --help          Show this help message

Environment variables:
  WATCHDOG_DB     Path to SQLite database
  WATCHDOG_PORT   Server port
  NODE_ENV        Set to 'production' for production mode
  LOG_LEVEL       Logging level (debug, info, warn, error)

Examples:
  npm run dashboard -- --db ~/.openclaw/security/registry.db
  WATCHDOG_PORT=8080 npm run dashboard
`);
  process.exit(0);
}

if (args.includes('--help') || args.includes('-h')) {
  showHelp();
}

// Default database path
const defaultDbPath = join(homedir(), '.openclaw', 'security', 'registry.db');
const dbPath = getArg('db') || process.env['WATCHDOG_DB'] || defaultDbPath;
const port = parseInt(getArg('port') || process.env['WATCHDOG_PORT'] || '3847');

// Validate database exists
if (!existsSync(dbPath)) {
  console.error(`❌ Database not found: ${dbPath}`);
  console.error(`   Run 'npm run db:init' to create the database.`);
  process.exit(1);
}

console.log(`
🛡️  Security Watchdog Dashboard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Database: ${dbPath}
Port:     ${port}
Mode:     ${process.env['NODE_ENV'] || 'development'}
`);

const server = new DashboardServer({
  databasePath: dbPath,
  port,
});

let isShuttingDown = false;

async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;
  
  console.log(`\n${signal} received, shutting down gracefully...`);
  
  try {
    await server.stop();
    console.log('✅ Server stopped');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
}

server.start().then(() => {
  console.log(`✅ Dashboard running at http://localhost:${port}`);
  console.log(`   Health check:  http://localhost:${port}/health`);
  console.log(`   Metrics:       http://localhost:${port}/metrics`);
  console.log(`   Press Ctrl+C to stop\n`);
}).catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

// Graceful shutdown handlers
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGHUP', () => shutdown('SIGHUP'));

// Handle uncaught errors
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  shutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason);
  shutdown('unhandledRejection');
});
