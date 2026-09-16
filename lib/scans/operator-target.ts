import { isIP } from 'node:net';

export class OperatorTargetError extends Error {
 constructor(public code: 'INVALID_TARGET' | 'TARGET_NOT_ALLOWED' | 'OPERATOR_DISABLED', message: string) {
  super(message);
  this.name = 'OperatorTargetError';
 }
}

export function normalizeOperatorTarget(input: string): string {
 const raw = input.trim();
 if (!raw) throw new OperatorTargetError('INVALID_TARGET', 'Enter a target domain.');
 let url: URL;
 try { url = new URL(raw.includes('://') ? raw : `https://${raw}`); }
 catch { throw new OperatorTargetError('INVALID_TARGET', 'Enter a valid HTTP or HTTPS target.'); }
 if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.port) {
  throw new OperatorTargetError('INVALID_TARGET', 'Only HTTP/HTTPS domains without credentials or custom ports are allowed.');
 }
 const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
 if (!hostname || hostname.length > 253 || hostname === 'localhost' || hostname.endsWith('.localhost') || isIP(hostname)) {
  throw new OperatorTargetError('INVALID_TARGET', 'Localhost and IP targets are not allowed.');
 }
 if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(hostname) || hostname.includes('..')) {
  throw new OperatorTargetError('INVALID_TARGET', 'Enter a valid domain name.');
 }
 return hostname;
}

export function getOperatorAllowedTargets(raw = process.env.SCOPEX_ALLOWED_TARGETS ?? ''): Set<string> {
 const targets = new Set<string>();
 for (const item of raw.split(',')) {
  const value = item.trim();
  if (!value) continue;
  targets.add(normalizeOperatorTarget(value));
 }
 return targets;
}

export function assertOperatorTargetAllowed(input: string, raw = process.env.SCOPEX_ALLOWED_TARGETS ?? ''): string {
 if (process.env.SCOPEX_OPERATOR_MODE !== 'enabled') {
  throw new OperatorTargetError('OPERATOR_DISABLED', 'Development assessment mode is disabled.');
 }
 const hostname = normalizeOperatorTarget(input);
 if (!getOperatorAllowedTargets(raw).has(hostname)) {
  throw new OperatorTargetError('TARGET_NOT_ALLOWED', 'This target is not on the development allowlist.');
 }
 return hostname;
}
