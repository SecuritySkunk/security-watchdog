/**
 * Auditor Daemon — System Health and Monitoring
 * 
 * Provides:
 * 1. Health monitoring for all system components
 * 2. Workspace scanning for sensitive data discovery
 * 3. Metrics aggregation and reporting
 * 4. System mode management
 */

import pino from 'pino';
import { EventEmitter } from 'events';
import * as fs from 'fs';
import * as path from 'path';

import { PatternScanner } from '../scanner/pattern-scanner.js';
import { SecurityAgent } from '../agent/security-agent.js';
import { GatewayHook } from '../gateway/gateway-hook.js';
import { RegistryManager } from '../registry/registry-manager.js';
import { DecisionLogger } from '../audit/decision-logger.js';
import { ClassificationLevel } from '../registry/types.js';

const logger = pino({ name: 'watchdog:auditor' });

// ─── Configuration ───────────────────────────────────────────

export interface AuditorConfig {
  /** Database path for registry */
  databasePath: string;
  /** Workspace directory to scan */
  workspacePath: string | undefined;
  /** How often to run health checks (ms) */
  healthCheckIntervalMs: number;
  /** How often to run workspace scans (ms) */
  workspaceScanIntervalMs: number;
  /** File extensions to scan */
  scanExtensions: string[];
  /** Directories to ignore */
  ignoreDirs: string[];
  /** Maximum file size to scan (bytes) */
  maxFileSizeBytes: number;
  /** Enable workspace scanning */
  workspaceScanEnabled: boolean;
  /** Enable metrics collection */
  metricsEnabled: boolean;
}

export const DEFAULT_CONFIG: AuditorConfig = {
  databasePath: '',
  workspacePath: undefined,
  healthCheckIntervalMs: 60000, // 1 minute
  workspaceScanIntervalMs: 3600000, // 1 hour
  scanExtensions: ['.txt', '.md', '.json', '.yaml', '.yml', '.env', '.config', '.log'],
  ignoreDirs: ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv'],
  maxFileSizeBytes: 1024 * 1024, // 1MB
  workspaceScanEnabled: true,
  metricsEnabled: true,
};

// ─── Types ───────────────────────────────────────────────────

export type SystemMode = 'normal' | 'elevated' | 'lockdown' | 'maintenance';

export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  lastCheck: Date;
  latencyMs?: number | undefined;
  error?: string | undefined;
  details?: Record<string, unknown> | undefined;
}

export interface SystemHealth {
  overall: 'healthy' | 'degraded' | 'unhealthy';
  components: ComponentHealth[];
  timestamp: Date;
  uptimeMs: number;
}

export interface WorkspaceScanResult {
  scanId: string;
  timestamp: Date;
  path: string;
  filesScanned: number;
  filesSkipped: number;
  totalFlags: number;
  flagsByClassification: Record<string, number>;
  flagsByFile: Array<{
    file: string;
    flags: number;
    highestClassification: ClassificationLevel | null;
  }>;
  durationMs: number;
  errors: string[];
}

export interface AuditorMetrics {
  /** Total scans performed */
  totalScans: number;
  /** Total flags detected */
  totalFlags: number;
  /** Flags by classification */
  flagsByClassification: Record<string, number>;
  /** Scans in last hour */
  scansLastHour: number;
  /** Average scan duration */
  avgScanDurationMs: number;
  /** System uptime */
  uptimeMs: number;
  /** Last health check */
  lastHealthCheck: Date | null;
  /** Last workspace scan */
  lastWorkspaceScan: Date | null;
  /** Current system mode */
  systemMode: SystemMode;
}

export interface AuditorEvents {
  'health:check': (health: SystemHealth) => void;
  'health:degraded': (component: ComponentHealth) => void;
  'workspace:scan:start': (path: string) => void;
  'workspace:scan:complete': (result: WorkspaceScanResult) => void;
  'workspace:scan:error': (error: Error) => void;
  'mode:change': (oldMode: SystemMode, newMode: SystemMode) => void;
  'alert': (level: 'info' | 'warn' | 'error', message: string) => void;
}

// ─── Auditor Daemon Class ────────────────────────────────────

export class AuditorDaemon extends EventEmitter {
  private config: AuditorConfig;
  private scanner?: PatternScanner;
  private agent?: SecurityAgent;
  private gateway?: GatewayHook;
  private registry?: RegistryManager;
  private auditLogger?: DecisionLogger;

  private startTime: number = 0;
  private healthCheckInterval?: ReturnType<typeof setInterval>;
  private workspaceScanInterval?: ReturnType<typeof setInterval>;
  private currentMode: SystemMode = 'normal';
  private isRunning = false;

  // Metrics
  private scanCount = 0;
  private totalFlags = 0;
  private flagsByClassification: Record<string, number> = {};
  private scanDurations: number[] = [];
  private lastHealthCheck: Date | null = null;
  private lastWorkspaceScan: Date | null = null;

  constructor(config: Partial<AuditorConfig>) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // ─── Lifecycle ───────────────────────────────────────────────

  /**
   * Start the auditor daemon
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      logger.warn('Auditor daemon already running');
      return;
    }

    logger.info({ config: this.config }, 'Starting auditor daemon');
    this.startTime = Date.now();
    this.isRunning = true;

    // Initialize components
    this.initializeComponents();

    // Start health check interval
    this.healthCheckInterval = setInterval(
      () => this.runHealthCheck(),
      this.config.healthCheckIntervalMs
    );

    // Start workspace scan interval (if enabled)
    if (this.config.workspaceScanEnabled && this.config.workspacePath) {
      this.workspaceScanInterval = setInterval(
        () => this.scanWorkspace(),
        this.config.workspaceScanIntervalMs
      );
    }

    // Run initial health check
    await this.runHealthCheck();

    this.emit('alert', 'info', 'Auditor daemon started');
  }

  /**
   * Stop the auditor daemon
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      return;
    }

    logger.info('Stopping auditor daemon');

    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    if (this.workspaceScanInterval) {
      clearInterval(this.workspaceScanInterval);
    }

    this.isRunning = false;
    this.emit('alert', 'info', 'Auditor daemon stopped');
  }

  /**
   * Initialize component references
   */
  private initializeComponents(): void {
    if (this.config.databasePath) {
      this.registry = new RegistryManager(this.config.databasePath);
      this.scanner = new PatternScanner({ databasePath: this.config.databasePath });
      this.scanner.initialize();
      
      this.gateway = new GatewayHook({
        databasePath: this.config.databasePath,
      });
      this.gateway.initialize();

      this.agent = new SecurityAgent({
        enabled: true,
      });

      this.auditLogger = new DecisionLogger({
        databasePath: this.config.databasePath,
      });
    }
  }

  // ─── Health Monitoring ───────────────────────────────────────

  /**
   * Run a health check on all components
   */
  async runHealthCheck(): Promise<SystemHealth> {
    const startTime = Date.now();
    const components: ComponentHealth[] = [];

    // Check scanner
    components.push(await this.checkScannerHealth());

    // Check agent
    components.push(await this.checkAgentHealth());

    // Check gateway
    components.push(await this.checkGatewayHealth());

    // Check registry
    components.push(await this.checkRegistryHealth());

    // Check audit logger
    components.push(await this.checkAuditLoggerHealth());

    // Determine overall health
    const unhealthyCount = components.filter(c => c.status === 'unhealthy').length;
    const degradedCount = components.filter(c => c.status === 'degraded').length;

    let overall: 'healthy' | 'degraded' | 'unhealthy';
    if (unhealthyCount > 0) {
      overall = 'unhealthy';
    } else if (degradedCount > 0) {
      overall = 'degraded';
    } else {
      overall = 'healthy';
    }

    const health: SystemHealth = {
      overall,
      components,
      timestamp: new Date(),
      uptimeMs: Date.now() - this.startTime,
    };

    this.lastHealthCheck = new Date();
    this.emit('health:check', health);

    // Emit degraded events
    for (const component of components) {
      if (component.status === 'unhealthy' || component.status === 'degraded') {
        this.emit('health:degraded', component);
      }
    }

    logger.info({ overall, checkDurationMs: Date.now() - startTime }, 'Health check complete');
    return health;
  }

  private async checkScannerHealth(): Promise<ComponentHealth> {
    const start = Date.now();
    try {
      if (!this.scanner) {
        return { name: 'scanner', status: 'unknown', lastCheck: new Date() };
      }

      // Try a simple scan
      const result = this.scanner.scan('health check test');
      
      return {
        name: 'scanner',
        status: 'healthy',
        lastCheck: new Date(),
        latencyMs: Date.now() - start,
        details: { verdict: result.verdict },
      };
    } catch (error) {
      return {
        name: 'scanner',
        status: 'unhealthy',
        lastCheck: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async checkAgentHealth(): Promise<ComponentHealth> {
    try {
      if (!this.agent) {
        return { name: 'agent', status: 'unknown', lastCheck: new Date() };
      }

      const status = this.agent.getStatus();
      const connectionTest = await this.agent.testConnection();

      return {
        name: 'agent',
        status: connectionTest.ok ? 'healthy' : 'degraded',
        lastCheck: new Date(),
        latencyMs: connectionTest.latencyMs,
        details: { 
          enabled: status.enabled,
          model: status.model,
          ollamaConnected: connectionTest.ok,
        },
        error: connectionTest.error,
      };
    } catch (error) {
      return {
        name: 'agent',
        status: 'unhealthy',
        lastCheck: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async checkGatewayHealth(): Promise<ComponentHealth> {
    const start = Date.now();
    try {
      if (!this.gateway) {
        return { name: 'gateway', status: 'unknown', lastCheck: new Date() };
      }

      const health = this.gateway.getHealth();
      
      return {
        name: 'gateway',
        status: health.initialized ? 'healthy' : 'degraded',
        lastCheck: new Date(),
        latencyMs: Date.now() - start,
        details: {
          initialized: health.initialized,
          postureLevel: health.postureLevel,
          scansTotal: health.metrics.scansTotal,
          uptimeMs: health.metrics.uptimeMs,
        },
      };
    } catch (error) {
      return {
        name: 'gateway',
        status: 'unhealthy',
        lastCheck: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async checkRegistryHealth(): Promise<ComponentHealth> {
    const start = Date.now();
    try {
      if (!this.registry) {
        return { name: 'registry', status: 'unknown', lastCheck: new Date() };
      }

      // Simple health check: try to count patterns and entries
      const patternCount = this.registry.countPatterns();
      const entryCount = this.registry.countEntries();
      
      return {
        name: 'registry',
        status: 'healthy',
        lastCheck: new Date(),
        latencyMs: Date.now() - start,
        details: {
          patternCount,
          entryCount,
        },
      };
    } catch (error) {
      return {
        name: 'registry',
        status: 'unhealthy',
        lastCheck: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async checkAuditLoggerHealth(): Promise<ComponentHealth> {
    const start = Date.now();
    try {
      if (!this.auditLogger) {
        return { name: 'auditLogger', status: 'unknown', lastCheck: new Date() };
      }

      const stats = this.auditLogger.getStats();
      
      return {
        name: 'auditLogger',
        status: 'healthy',
        lastCheck: new Date(),
        latencyMs: Date.now() - start,
        details: {
          totalDecisions: stats.totalDecisions,
          avgDurationMs: stats.avgDurationMs,
        },
      };
    } catch (error) {
      return {
        name: 'auditLogger',
        status: 'unhealthy',
        lastCheck: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  // ─── Workspace Scanning ──────────────────────────────────────

  /**
   * Scan the workspace directory for sensitive data
   */
  async scanWorkspace(workspacePath?: string): Promise<WorkspaceScanResult> {
    const scanPath = workspacePath || this.config.workspacePath;
    if (!scanPath) {
      throw new Error('No workspace path configured');
    }

    if (!this.scanner) {
      throw new Error('Scanner not initialized');
    }

    const scanId = `ws-${Date.now()}`;
    const startTime = Date.now();
    
    this.emit('workspace:scan:start', scanPath);
    logger.info({ scanId, path: scanPath }, 'Starting workspace scan');

    const result: WorkspaceScanResult = {
      scanId,
      timestamp: new Date(),
      path: scanPath,
      filesScanned: 0,
      filesSkipped: 0,
      totalFlags: 0,
      flagsByClassification: {},
      flagsByFile: [],
      durationMs: 0,
      errors: [],
    };

    try {
      await this.scanDirectory(scanPath, result);
      
      result.durationMs = Date.now() - startTime;
      this.lastWorkspaceScan = new Date();
      
      // Update metrics
      this.scanCount++;
      this.totalFlags += result.totalFlags;
      this.scanDurations.push(result.durationMs);
      
      for (const [classification, count] of Object.entries(result.flagsByClassification)) {
        this.flagsByClassification[classification] = 
          (this.flagsByClassification[classification] || 0) + count;
      }

      this.emit('workspace:scan:complete', result);
      logger.info({ 
        scanId, 
        filesScanned: result.filesScanned,
        totalFlags: result.totalFlags,
        durationMs: result.durationMs,
      }, 'Workspace scan complete');

      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      result.errors.push(errorMessage);
      this.emit('workspace:scan:error', error instanceof Error ? error : new Error(errorMessage));
      throw error;
    }
  }

  private async scanDirectory(dirPath: string, result: WorkspaceScanResult): Promise<void> {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);

      if (entry.isDirectory()) {
        if (!this.config.ignoreDirs.includes(entry.name)) {
          await this.scanDirectory(fullPath, result);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        
        if (this.config.scanExtensions.includes(ext)) {
          await this.scanFile(fullPath, result);
        } else {
          result.filesSkipped++;
        }
      }
    }
  }

  private async scanFile(filePath: string, result: WorkspaceScanResult): Promise<void> {
    try {
      const stats = fs.statSync(filePath);
      
      if (stats.size > this.config.maxFileSizeBytes) {
        result.filesSkipped++;
        return;
      }

      const content = fs.readFileSync(filePath, 'utf-8');
      const scanResult = this.scanner!.scan(content);

      result.filesScanned++;

      if (scanResult.flagCount > 0) {
        result.totalFlags += scanResult.flagCount;
        
        // Track by classification
        for (const flag of scanResult.flags) {
          const classification = flag.classification;
          result.flagsByClassification[classification] = 
            (result.flagsByClassification[classification] || 0) + 1;
        }

        // Track by file
        result.flagsByFile.push({
          file: filePath,
          flags: scanResult.flagCount,
          highestClassification: scanResult.highestClassification,
        });
      }
    } catch (error) {
      result.errors.push(`Failed to scan ${filePath}: ${error instanceof Error ? error.message : 'Unknown'}`);
    }
  }

  // ─── System Mode Management ──────────────────────────────────

  /**
   * Get current system mode
   */
  getSystemMode(): SystemMode {
    return this.currentMode;
  }

  /**
   * Set system mode
   */
  setSystemMode(mode: SystemMode): void {
    if (mode === this.currentMode) {
      return;
    }

    const oldMode = this.currentMode;
    this.currentMode = mode;

    logger.info({ oldMode, newMode: mode }, 'System mode changed');
    this.emit('mode:change', oldMode, mode);
    this.emit('alert', 'info', `System mode changed from ${oldMode} to ${mode}`);

    // Adjust gateway posture based on mode
    if (this.gateway) {
      const postureMap: Record<SystemMode, 'permissive' | 'standard' | 'strict' | 'lockdown'> = {
        normal: 'standard',
        elevated: 'strict',
        lockdown: 'lockdown',
        maintenance: 'permissive',
      };
      this.gateway.setPosture(postureMap[mode]);
    }
  }

  // ─── Metrics ─────────────────────────────────────────────────

  /**
   * Get current metrics
   */
  getMetrics(): AuditorMetrics {
    const now = Date.now();

    // Calculate scans in last hour (simplified - would need timestamp tracking)
    const scansLastHour = this.scanDurations.length; // Simplified

    // Calculate average scan duration
    const avgScanDurationMs = this.scanDurations.length > 0
      ? this.scanDurations.reduce((a, b) => a + b, 0) / this.scanDurations.length
      : 0;

    return {
      totalScans: this.scanCount,
      totalFlags: this.totalFlags,
      flagsByClassification: { ...this.flagsByClassification },
      scansLastHour,
      avgScanDurationMs,
      uptimeMs: this.startTime > 0 ? now - this.startTime : 0,
      lastHealthCheck: this.lastHealthCheck,
      lastWorkspaceScan: this.lastWorkspaceScan,
      systemMode: this.currentMode,
    };
  }

  /**
   * Reset metrics
   */
  resetMetrics(): void {
    this.scanCount = 0;
    this.totalFlags = 0;
    this.flagsByClassification = {};
    this.scanDurations = [];
    logger.info('Metrics reset');
  }

  // ─── Status ──────────────────────────────────────────────────

  /**
   * Get daemon status
   */
  getStatus(): {
    running: boolean;
    mode: SystemMode;
    uptimeMs: number;
    healthCheckIntervalMs: number;
    workspaceScanEnabled: boolean;
    lastHealthCheck: Date | null;
    lastWorkspaceScan: Date | null;
  } {
    return {
      running: this.isRunning,
      mode: this.currentMode,
      uptimeMs: this.startTime > 0 ? Date.now() - this.startTime : 0,
      healthCheckIntervalMs: this.config.healthCheckIntervalMs,
      workspaceScanEnabled: this.config.workspaceScanEnabled,
      lastHealthCheck: this.lastHealthCheck,
      lastWorkspaceScan: this.lastWorkspaceScan,
    };
  }
}

export default AuditorDaemon;
