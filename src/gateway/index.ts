/**
 * Gateway Module - Public API
 * 
 * Integration layer between Security Watchdog and OpenClaw.
 */

export { GatewayHook, default } from './gateway-hook.js';
export type {
  GatewayHookConfig,
  PostureLevel,
  DestinationType,
  OutboundRequest,
  OutboundResult,
  InboundRequest,
  InboundResult,
  QuarantineEntry,
} from './gateway-hook.js';
