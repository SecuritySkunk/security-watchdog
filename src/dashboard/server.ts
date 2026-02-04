/**
 * Dashboard Server — Web UI for Security Watchdog
 * 
 * Provides:
 * - REST API for querying registry, logs, and quarantine
 * - Static file serving for dashboard UI
 * - Real-time metrics and health status
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import pino from 'pino';

import { RegistryManager } from '../registry/registry-manager.js';
import { GatewayHook } from '../gateway/gateway-hook.js';
import { DecisionLogger } from '../audit/decision-logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const logger = pino({ name: 'watchdog:dashboard' });

// ─── Configuration ───────────────────────────────────────────

export interface DashboardConfig {
  port: number;
  databasePath: string;
  corsOrigins?: string[];
}

export const DEFAULT_CONFIG: DashboardConfig = {
  port: 3847,
  databasePath: '',
  corsOrigins: ['http://localhost:3847'],
};

// ─── Dashboard Server Class ──────────────────────────────────

export class DashboardServer {
  private app: express.Application;
  private config: DashboardConfig;
  private registry: RegistryManager;
  private gateway: GatewayHook;
  private auditLogger: DecisionLogger;
  private server?: ReturnType<typeof this.app.listen>;

  constructor(config: Partial<DashboardConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    
    if (!this.config.databasePath) {
      throw new Error('Database path is required');
    }

    this.app = express();
    this.registry = new RegistryManager(this.config.databasePath);
    this.gateway = new GatewayHook({ databasePath: this.config.databasePath });
    this.auditLogger = new DecisionLogger({ databasePath: this.config.databasePath });
    
    this.gateway.initialize();
    this.setupMiddleware();
    this.setupRoutes();
  }

  // ─── Middleware ────────────────────────────────────────────

  private setupMiddleware(): void {
    this.app.use(cors({ origin: this.config.corsOrigins }));
    this.app.use(express.json());
    
    // Serve static files from public directory
    this.app.use(express.static(path.join(__dirname, 'public')));

    // Request logging
    this.app.use((req: Request, _res: Response, next: NextFunction) => {
      logger.debug({ method: req.method, path: req.path }, 'Request');
      next();
    });
  }

  // ─── Routes ────────────────────────────────────────────────

  private setupRoutes(): void {
    // Health check
    this.app.get('/api/health', (_req, res) => {
      res.json({ status: 'ok', timestamp: new Date().toISOString() });
    });

    // ─── Stats & Overview ────────────────────────────────────

    this.app.get('/api/stats', (_req, res) => {
      try {
        const gatewayHealth = this.gateway.getHealth();
        const auditStats = this.auditLogger.getStats();
        const patternCount = this.registry.countPatterns();
        const entryCount = this.registry.countEntries();

        res.json({
          registry: {
            patterns: patternCount,
            entries: entryCount,
          },
          gateway: {
            posture: gatewayHealth.postureLevel,
            scans: gatewayHealth.metrics.scansTotal,
            blocks: gatewayHealth.metrics.blocksTotal,
            quarantines: gatewayHealth.metrics.quarantinesTotal,
            pending: gatewayHealth.metrics.quarantinesPending,
            uptime: gatewayHealth.metrics.uptimeMs,
          },
          audit: {
            totalDecisions: auditStats.totalDecisions,
            byAction: auditStats.byAction,
            byVerdict: auditStats.byVerdict,
            avgDurationMs: auditStats.avgDurationMs,
          },
        });
      } catch (error) {
        logger.error({ error }, 'Failed to get stats');
        res.status(500).json({ error: 'Failed to get stats' });
      }
    });

    // ─── Quarantine Management ───────────────────────────────

    this.app.get('/api/quarantine', (_req, res) => {
      try {
        const pending = this.gateway.listPendingQuarantines();
        res.json({ quarantines: pending });
      } catch (error) {
        logger.error({ error }, 'Failed to list quarantines');
        res.status(500).json({ error: 'Failed to list quarantines' });
      }
    });

    this.app.get('/api/quarantine/:id', (req, res) => {
      try {
        const entry = this.gateway.getQuarantine(req.params.id);
        if (!entry) {
          res.status(404).json({ error: 'Quarantine not found' });
          return;
        }
        res.json(entry);
      } catch (error) {
        logger.error({ error }, 'Failed to get quarantine');
        res.status(500).json({ error: 'Failed to get quarantine' });
      }
    });

    this.app.post('/api/quarantine/:id/approve', (req, res) => {
      try {
        const approver = req.body.approver || 'dashboard-user';
        const token = this.gateway.approveQuarantine(req.params.id, approver);
        
        if (!token) {
          res.status(404).json({ error: 'Quarantine not found or already processed' });
          return;
        }
        
        res.json({ approved: true, token });
      } catch (error) {
        logger.error({ error }, 'Failed to approve quarantine');
        res.status(500).json({ error: 'Failed to approve quarantine' });
      }
    });

    this.app.post('/api/quarantine/:id/reject', (req, res) => {
      try {
        const rejector = req.body.rejector || 'dashboard-user';
        const success = this.gateway.rejectQuarantine(req.params.id, rejector);
        
        if (!success) {
          res.status(404).json({ error: 'Quarantine not found or already processed' });
          return;
        }
        
        res.json({ rejected: true });
      } catch (error) {
        logger.error({ error }, 'Failed to reject quarantine');
        res.status(500).json({ error: 'Failed to reject quarantine' });
      }
    });

    // ─── Patterns ────────────────────────────────────────────

    this.app.get('/api/patterns', (req, res) => {
      try {
        // Build filter only with defined values
        const filter: Parameters<typeof this.registry.listPatterns>[0] = {};
        const category = req.query['category'];
        const localeId = req.query['localeId'];
        const isActiveStr = req.query['isActive'];
        
        if (typeof category === 'string') filter.category = category;
        if (typeof localeId === 'string') filter.localeId = localeId;
        if (typeof isActiveStr === 'string') filter.isActive = isActiveStr === 'true';
        
        const patterns = this.registry.listPatterns(filter);
        res.json({ patterns });
      } catch (error) {
        logger.error({ error }, 'Failed to list patterns');
        res.status(500).json({ error: 'Failed to list patterns' });
      }
    });

    this.app.get('/api/patterns/:id', (req, res) => {
      try {
        const pattern = this.registry.getPattern(parseInt(req.params.id));
        if (!pattern) {
          res.status(404).json({ error: 'Pattern not found' });
          return;
        }
        res.json(pattern);
      } catch (error) {
        logger.error({ error }, 'Failed to get pattern');
        res.status(500).json({ error: 'Failed to get pattern' });
      }
    });

    this.app.post('/api/patterns', (req, res) => {
      try {
        const pattern = this.registry.createPattern(req.body);
        res.status(201).json(pattern);
      } catch (error) {
        logger.error({ error }, 'Failed to create pattern');
        res.status(500).json({ error: 'Failed to create pattern' });
      }
    });

    this.app.put('/api/patterns/:id', (req, res) => {
      try {
        const pattern = this.registry.updatePattern(parseInt(req.params.id), req.body);
        res.json(pattern);
      } catch (error) {
        logger.error({ error }, 'Failed to update pattern');
        res.status(500).json({ error: 'Failed to update pattern' });
      }
    });

    this.app.delete('/api/patterns/:id', (req, res) => {
      try {
        this.registry.deactivatePattern(parseInt(req.params.id));
        res.json({ deactivated: true });
      } catch (error) {
        logger.error({ error }, 'Failed to deactivate pattern');
        res.status(500).json({ error: 'Failed to deactivate pattern' });
      }
    });

    // ─── User Entries ────────────────────────────────────────

    this.app.get('/api/entries', (req, res) => {
      try {
        // Build filter only with defined values
        const filter: Parameters<typeof this.registry.listEntries>[0] = {};
        const category = req.query['category'];
        const isActiveStr = req.query['isActive'];
        
        if (typeof category === 'string') filter.category = category;
        if (typeof isActiveStr === 'string') filter.isActive = isActiveStr === 'true';
        
        const entries = this.registry.listEntries(filter);
        res.json({ entries });
      } catch (error) {
        logger.error({ error }, 'Failed to list entries');
        res.status(500).json({ error: 'Failed to list entries' });
      }
    });

    this.app.get('/api/entries/:id', (req, res) => {
      try {
        const entry = this.registry.getEntry(parseInt(req.params.id));
        if (!entry) {
          res.status(404).json({ error: 'Entry not found' });
          return;
        }
        res.json(entry);
      } catch (error) {
        logger.error({ error }, 'Failed to get entry');
        res.status(500).json({ error: 'Failed to get entry' });
      }
    });

    this.app.post('/api/entries', (req, res) => {
      try {
        const entry = this.registry.createEntry(req.body);
        res.status(201).json(entry);
      } catch (error) {
        logger.error({ error }, 'Failed to create entry');
        res.status(500).json({ error: 'Failed to create entry' });
      }
    });

    this.app.put('/api/entries/:id', (req, res) => {
      try {
        const entry = this.registry.updateEntry(parseInt(req.params.id), req.body);
        res.json(entry);
      } catch (error) {
        logger.error({ error }, 'Failed to update entry');
        res.status(500).json({ error: 'Failed to update entry' });
      }
    });

    this.app.delete('/api/entries/:id', (req, res) => {
      try {
        this.registry.deactivateEntry(parseInt(req.params.id));
        res.json({ deactivated: true });
      } catch (error) {
        logger.error({ error }, 'Failed to deactivate entry');
        res.status(500).json({ error: 'Failed to deactivate entry' });
      }
    });

    // ─── Entry Variants ──────────────────────────────────────

    this.app.get('/api/entries/:id/variants', (req, res) => {
      try {
        const variants = this.registry.listVariants(parseInt(req.params.id));
        res.json({ variants });
      } catch (error) {
        logger.error({ error }, 'Failed to list variants');
        res.status(500).json({ error: 'Failed to list variants' });
      }
    });

    this.app.post('/api/entries/:id/variants', (req, res) => {
      try {
        const variant = this.registry.addVariant(parseInt(req.params.id), req.body.text);
        res.status(201).json(variant);
      } catch (error) {
        logger.error({ error }, 'Failed to add variant');
        res.status(500).json({ error: 'Failed to add variant' });
      }
    });

    this.app.delete('/api/variants/:id', (req, res) => {
      try {
        this.registry.removeVariant(parseInt(req.params.id));
        res.json({ removed: true });
      } catch (error) {
        logger.error({ error }, 'Failed to remove variant');
        res.status(500).json({ error: 'Failed to remove variant' });
      }
    });

    // ─── Audit Log ───────────────────────────────────────────

    this.app.get('/api/audit', (req, res) => {
      try {
        const limitStr = req.query['limit'];
        const offsetStr = req.query['offset'];
        const limit = parseInt(limitStr as string) || 50;
        const offset = parseInt(offsetStr as string) || 0;
        
        const entries = this.auditLogger.query({ limit, offset });
        res.json({ entries, limit, offset });
      } catch (error) {
        logger.error({ error }, 'Failed to query audit log');
        res.status(500).json({ error: 'Failed to query audit log' });
      }
    });

    // ─── Gateway Control ─────────────────────────────────────

    this.app.get('/api/gateway/posture', (_req, res) => {
      try {
        const posture = this.gateway.getPosture();
        res.json({ posture });
      } catch (error) {
        logger.error({ error }, 'Failed to get posture');
        res.status(500).json({ error: 'Failed to get posture' });
      }
    });

    this.app.post('/api/gateway/posture', (req, res) => {
      try {
        const { level } = req.body;
        if (!['permissive', 'standard', 'strict', 'lockdown'].includes(level)) {
          res.status(400).json({ error: 'Invalid posture level' });
          return;
        }
        this.gateway.setPosture(level);
        res.json({ posture: level });
      } catch (error) {
        logger.error({ error }, 'Failed to set posture');
        res.status(500).json({ error: 'Failed to set posture' });
      }
    });

    // ─── Test Scan ───────────────────────────────────────────

    this.app.post('/api/test/scan', (req, res) => {
      try {
        const { content, destination } = req.body;
        if (!content) {
          res.status(400).json({ error: 'Content is required' });
          return;
        }

        const result = this.gateway.scanOutbound({
          content,
          destination: destination || 'test',
        });

        res.json(result);
      } catch (error) {
        logger.error({ error }, 'Failed to test scan');
        res.status(500).json({ error: 'Failed to test scan' });
      }
    });

    // ─── Fallback to index.html for SPA ──────────────────────

    this.app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'public', 'index.html'));
    });
  }

  // ─── Lifecycle ─────────────────────────────────────────────

  start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = this.app.listen(this.config.port, () => {
        logger.info({ port: this.config.port }, 'Dashboard server started');
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.server) {
        resolve();
        return;
      }
      this.server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  getPort(): number {
    return this.config.port;
  }
}

export default DashboardServer;
