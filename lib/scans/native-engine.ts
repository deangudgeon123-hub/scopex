import { normalizeOperatorTarget } from './operator-target';
import { probeHttpHead, probeTls, type HeaderMap, type HttpProbeResult, type TlsProbeResult } from './native-http';

export type ObservationKind = 'http' | 'tls' | 'header' | 'redirect' | 'network';
export type ObservationStatus = 'pass' | 'warn' | 'info' | 'error';
export type ObservationData = Record<string, string | number | boolean | null>;

export interface NativeObservation {
 observation_key: string;
 kind: ObservationKind;
 status: ObservationStatus;
 summary: string;
 data: ObservationData;
}

export interface NativeScanInput {
 hostname: string;
 origin: string;
 timeoutMs?: number;
 maxRequests?: number;
 requestsPerSecond?: number;
}

export interface NativeScanResult {
 observations: NativeObservation[];
 pagesChecked: number;
 requestsMade: number;
}

type NativeScanDependencies = {
 httpProbe?: (url: string, timeoutMs?: number) => Promise<HttpProbeResult>;
 tlsProbe?: (hostname: string, timeoutMs?: number) => Promise<TlsProbeResult>;
 sleep?: (ms: number) => Promise<void>;
};

function observation(observation_key: string, kind: ObservationKind, status: ObservationStatus, summary: string, data: ObservationData = {}): NativeObservation {
 return { observation_key, kind, status, summary, data };
}

function header(headers: HeaderMap, name: string): string | null {
 const value = headers[name.toLowerCase()];
 if (Array.isArray(value)) return value.join(', ');
 return typeof value === 'string' ? value : null;
}

export function evaluateSecurityHeaders(headers: HeaderMap, https = true): NativeObservation[] {
 const csp = header(headers, 'content-security-policy');
 const xcto = header(headers, 'x-content-type-options');
 const referrer = header(headers, 'referrer-policy');
 const permissions = header(headers, 'permissions-policy');
 const xfo = header(headers, 'x-frame-options');
 const hsts = header(headers, 'strict-transport-security');
 const hasFrameAncestors = Boolean(csp && /(?:^|;)\s*frame-ancestors\s+/i.test(csp));
 const results = [
  observation('header.content_security_policy', 'header', csp ? 'pass' : 'warn', csp ? 'Content-Security-Policy is present.' : 'Content-Security-Policy is not present.', { present: Boolean(csp) }),
  observation('header.x_content_type_options', 'header', xcto?.toLowerCase() === 'nosniff' ? 'pass' : 'warn', xcto?.toLowerCase() === 'nosniff' ? 'X-Content-Type-Options is set to nosniff.' : 'X-Content-Type-Options nosniff is not present.', { present: Boolean(xcto), nosniff: xcto?.toLowerCase() === 'nosniff' }),
  observation('header.referrer_policy', 'header', referrer ? 'pass' : 'warn', referrer ? 'Referrer-Policy is present.' : 'Referrer-Policy is not present.', { present: Boolean(referrer) }),
  observation('header.permissions_policy', 'header', permissions ? 'pass' : 'info', permissions ? 'Permissions-Policy is present.' : 'Permissions-Policy is not present.', { present: Boolean(permissions) }),
  observation('header.frame_protection', 'header', (hasFrameAncestors || Boolean(xfo)) ? 'pass' : 'warn', (hasFrameAncestors || Boolean(xfo)) ? 'Frame embedding protection is present.' : 'No frame embedding protection header was observed.', { cspFrameAncestors: hasFrameAncestors, xFrameOptions: Boolean(xfo) }),
 ];
 if (https) {
  const maxAge = hsts?.match(/(?:^|;)\s*max-age=(\d+)/i)?.[1];
  const enabled = Boolean(maxAge && Number(maxAge) > 0);
  results.push(observation('header.hsts', 'header', enabled ? 'pass' : 'warn', enabled ? 'HTTP Strict Transport Security is enabled.' : 'HTTP Strict Transport Security is not enabled.', { present: Boolean(hsts), enabled }));
 }
 return results;
}

export function evaluateHttpToHttps(hostname: string, probe: HttpProbeResult): NativeObservation {
 if (!probe.location) return observation('redirect.http_to_https', 'redirect', 'warn', 'HTTP did not advertise a redirect to HTTPS.', { statusCode: probe.statusCode });
 try {
  const target = new URL(probe.location, `http://${hostname}/`);
  const exactHost = target.hostname.toLowerCase().replace(/\.$/, '') === hostname;
  const safeShape = !target.username && !target.password && !target.port;
  const httpsRedirect = target.protocol === 'https:' && exactHost && safeShape;
  return observation('redirect.http_to_https', 'redirect', httpsRedirect ? 'pass' : 'warn', httpsRedirect ? 'HTTP redirects to HTTPS on the authorised hostname.' : 'HTTP redirect does not stay on the authorised HTTPS hostname.', { statusCode: probe.statusCode, httpsRedirect, exactHost });
 } catch {
  return observation('redirect.http_to_https', 'redirect', 'warn', 'HTTP returned an invalid redirect location.', { statusCode: probe.statusCode });
 }
}

export function evaluateTls(result: TlsProbeResult, now = Date.now()): NativeObservation[] {
 const protocolOk = result.protocol === 'TLSv1.3' || result.protocol === 'TLSv1.2';
 const expiry = result.validTo ? Date.parse(result.validTo) : Number.NaN;
 const daysRemaining = Number.isFinite(expiry) ? Math.floor((expiry - now) / 86_400_000) : null;
 const certificateOk = result.authorized && daysRemaining !== null && daysRemaining >= 0;
 return [
  observation('tls.certificate', 'tls', certificateOk ? 'pass' : 'warn', certificateOk ? 'TLS certificate validation succeeded.' : 'TLS certificate validation did not succeed.', { authorized: result.authorized, authorizationError: result.authorizationError }),
  observation('tls.protocol', 'tls', protocolOk ? 'pass' : 'warn', protocolOk ? `Negotiated ${result.protocol}.` : 'A modern TLS 1.2+ protocol was not observed.', { protocol: result.protocol, cipher: result.cipher }),
  observation('tls.expiry', 'tls', daysRemaining !== null && daysRemaining >= 30 ? 'pass' : 'warn', daysRemaining === null ? 'Certificate expiry could not be read.' : `Certificate has ${daysRemaining} day(s) remaining.`, { daysRemaining, validTo: result.validTo }),
 ];
}

function validatedOrigin(hostname: string, origin: string): URL {
 const url = new URL(origin);
 if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.port || url.pathname !== '/' || url.search || url.hash) throw new Error('INVALID_SCAN_ORIGIN');
 if (url.hostname.toLowerCase().replace(/\.$/, '') !== hostname) throw new Error('ORIGIN_HOST_MISMATCH');
 return url;
}

export async function scanNativeConfiguration(input: NativeScanInput, dependencies: NativeScanDependencies = {}): Promise<NativeScanResult> {
 const hostname = normalizeOperatorTarget(input.hostname);
 const origin = validatedOrigin(hostname, input.origin);
 const timeoutMs = Math.min(Math.max(input.timeoutMs ?? 8000, 1000), 15000);
 const maxRequests = Math.min(Math.max(input.maxRequests ?? 2, 0), 2);
 const requestsPerSecond = Math.min(Math.max(input.requestsPerSecond ?? 1, 1), 5);
 const httpProbe = dependencies.httpProbe ?? probeHttpHead;
 const tlsProbe = dependencies.tlsProbe ?? probeTls;
 const sleep = dependencies.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
 const observations: NativeObservation[] = [];
 let pagesChecked = 0;
 let requestsMade = 0;

 if (maxRequests >= 1) {
  requestsMade += 1;
  try {
   const http = await httpProbe(`http://${hostname}/`, timeoutMs);
   pagesChecked += 1;
   observations.push(evaluateHttpToHttps(hostname, http));
  } catch (error) {
   observations.push(observation('redirect.http_to_https', 'redirect', 'error', 'HTTP redirect check could not be completed.', { error: error instanceof Error ? error.message.slice(0, 120) : 'HTTP_CHECK_FAILED' }));
  }
 }

 if (maxRequests >= 2) {
  await sleep(Math.ceil(1000 / requestsPerSecond));
  requestsMade += 1;
  try {
   const https = await httpProbe(`https://${hostname}/`, timeoutMs);
   pagesChecked += 1;
   observations.push(observation('http.https_reachable', 'http', https.statusCode > 0 && https.statusCode < 600 ? 'pass' : 'warn', `HTTPS returned status ${https.statusCode}.`, { statusCode: https.statusCode }));
   observations.push(...evaluateSecurityHeaders(https.headers, true));
  } catch (error) {
   observations.push(observation('http.https_reachable', 'http', 'error', 'HTTPS response headers could not be read.', { error: error instanceof Error ? error.message.slice(0, 120) : 'HTTPS_CHECK_FAILED' }));
  }
 }

 if (origin.protocol === 'https:') {
  try {
   const tls = await tlsProbe(hostname, timeoutMs);
   observations.push(...evaluateTls(tls));
  } catch (error) {
   observations.push(observation('tls.connection', 'tls', 'error', 'TLS handshake could not be completed.', { error: error instanceof Error ? error.message.slice(0, 120) : 'TLS_CHECK_FAILED' }));
  }
 } else {
  observations.push(observation('tls.connection', 'tls', 'info', 'Configured origin uses HTTP, so TLS was not expected for the origin.', {}));
 }

 return { observations, pagesChecked, requestsMade };
}
