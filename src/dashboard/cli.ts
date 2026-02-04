#!/usr/bin/env node
/**
 * Dashboard CLI — Start the Security Watchdog Dashboard
 * 
 * Usage:
 *   npx tsx src/dashboard/cli.ts --db ./watchdog.db
 *   npx tsx src/dashboard/cli.ts --db ./watchdog.db --port 3000
 */

import { DashboardServer } from './server.js';

const args = process.argv.slice(2);

function getArg(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1) return undefined;
  return args[idx + 1];
}

const dbPath = getArg('db') || process.env['WATCHDOG_DB'] || './watchdog.db';
const port = parseInt(getArg('port') || process.env['WATCHDOG_PORT'] || '3847');

console.log(`
🛡️  Security Watchdog Dashboard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Database: ${dbPath}
Port:     ${port}
`);

const server = new DashboardServer({
  databasePath: dbPath,
  port,
});

server.start().then(() => {
  console.log(`✅ Dashboard running at http://localhost:${port}`);
  console.log(`   Press Ctrl+C to stop\n`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  await server.stop();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await server.stop();
  process.exit(0);
});
