/**
 * Scanner Module - Public API
 * 
 * Layer 1 of the Security Watchdog - detects sensitive data in text.
 */

export { PatternScanner, default } from './pattern-scanner.js';
export type { ScannerConfig, ScanFlag, ScanResult } from './pattern-scanner.js';
