import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { isIP } from 'node:net';

export type ObservationKind = 'http' | 'tls' | 'redirect' | 'headers' | 'metadata';
export type ObservationOutcome = 'pass' | 'warning' | 'info' | 'error';

export type NativeObservation = {
 check_id: string;
 kind: ObservationKind;
 outcome: ObservationOutcome;
 summary: string;
 observed_url: string | null;
 data: Record<string, string | number | boolean | null>;
};

type HttpSnapshot = {
 status: number;
 headers: Record<string, string | string[] | undefined>;
};

type TlsSnapshot = {
 protocol: string | null;
 cipher: string | null;
 authorized: boolean;
 valid_from: string | null;
 valid_to: string | null;
 fingerprint256: string | null;
 subject_cn: string | null;
 issuer_cn: string | null;
};

export type NativeScannerDeps = {
 requestRoot: (protocol: 'http:' | 'https:', hostname: string, timeoutMs: number) => Promise<HttpSnapshot>;
 inspectTls: (hostname: string, timeoutMs: number) => Promise<TlsSnapshot>;
 sleep: (ms: number) => Promise<void>;
};

function isPrivateIpv4(address: string) {
 const octets = address.split('.').map(Number);
 if (octets.length !== 4 || octets.some((v) => !Number.isInteger(v) || v < 0 || v > 255)) return true;
 const [a, b] = octets;
 return a === 0 || a === 10 || a === 127 || a >= 224 ||
  (a === 100 && b >= 64 && b <= 127) ||
  (a === 169 && b === 254) ||
  (a === 172 && b >= 16 && b <= 31) ||
  (a === 192 && (b === 0 || b === 168)) ||
  (a === 198 && (b === 18 || b === 19 || b === 51)) ||
  (a === 203 && b === 0);
}

export function isPublicIp(address: string): boolean {
 const version = isIP(address);
 if (version === 4) return !isPrivateIpv4(address);
 if (version !== 6) return false;
 const value = address.toLowerCase();
 if (value === '::' || value === '::1') return false;
 if (value.startsWith('::ffff:')) return isPublicIp(value.slice(7));
 if (value.startsWith('fc') || value.startsWith('fd')) return false;
 if (/^fe[89ab]/.test(value)) return false;
 if (value.startsWith('ff')) return false;
 if (value.startsWith('2001:db8:')) return false;
 return true;
}

async function resolvePublicHost(hostname: string) {
 const answers = await dns.lookup(hostname, { all: true, verbatim: true });
 if (!answers.length) throw new Error('DNS_NO_PUBLIC_ADDRESS');
 if (answers.some((answer) => !isPublicIp(answer.address))) throw new Error('DNS_PRIVATE_ADDRESS_BLOCKED');
 return answers[0];
}

function lowerHeaders(headers: http.IncomingHttpHeaders): Record<string, string | string[] | undefined> {
 const result: Record<string, string | string[] | undefined> = {};
 for (const [key, value] of Object.entries(headers)) result[key.toLowerCase()] = value;
 return result;
}

async function requestRoot(protocol: 'http:' | 'https:', hostname: string, timeoutMs: number): Promise<HttpSnapshot> {
 const resolved = await resolvePublicHost(hostname);
 const transport = protocol === 'https:' ? https : http;
 return new Promise((resolve, reject) => {
  const request = transport.request({
   protocol,
   hostname: resolved.address,
   port: protocol === 'https:' ? 443 : 80,
   method: 'HEAD',
   path: '/',
   servername: protocol === 'https:' ? hostname : undefined,
   rejectUnauthorized: protocol === 'https:' ? true : undefined,
   headers: { Host: hostname, 'User-Agent': 'SCOPEX-Native-Scanner/0.1' },
  }, (response) => {
   const snapshot = { status: response.statusCode ?? 0, headers: lowerHeaders(response.headers) };
   response.resume();
   resolve(snapshot);
  });
  request.setTimeout(timeoutMs, () => request.destroy(new Error('REQUEST_TIMEOUT')));
  request.once('error', reject);
  request.end();
 });
}

function firstDnValue(value: string | string[] | undefined): string | null {
 return Array.isArray(value) ? value[0] ?? null : value ?? null;
}

async function inspectTls(hostname: string, timeoutMs: number): Promise<TlsSnapshot> {
 const resolved = await resolvePublicHost(hostname);
 return new Promise((resolve, reject) => {
  const socket = tls.connect({ host: resolved.address, port: 443, servername: hostname, rejectUnauthorized: true });
  const timer = setTimeout(() => socket.destroy(new Error('TLS_TIMEOUT')), timeoutMs);
  socket.once('secureConnect', () => {
   clearTimeout(timer);
   const certificate = socket.getPeerCertificate();
   const cipher = socket.getCipher();
   const result: TlsSnapshot = {
    protocol: socket.getProtocol(),
    cipher: cipher?.name ?? null,
    authorized: socket.authorized,
    valid_from: certificate.valid_from ?? null,
    valid_to: certificate.valid_to ?? null,
    fingerprint256: certificate.fingerprint256 ?? null,
    subject_cn: firstDnValue(certificate.subject?.CN),
    issuer_cn: firstDnValue(certificate.issuer?.CN),
   };
   socket.end();
   resolve(result);
  });
  socket.once('error', (error) => {
   clearTimeout(timer);
   reject(error);
  });
 });
}

function firstHeader(headers: Record<string, string | string[] | undefined>, name: string): string | null {
 const value = headers[name.toLowerCase()];
 return Array.isArray(value) ? value[0] ?? null : value ?? null;
}

export function isSameHostHttpsRedirect(hostname: string, location: string | null): boolean {
 if (!location) return false;
 try {
  const url = new URL(location, `http://${hostname}/`);
  return url.protocol === 'https:' && url.hostname.toLowerCase() === hostname.toLowerCase() && !url.username && !url.password && !url.port;
 } catch {
  return false;
 }
}

export function securityHeaderSnapshot(headers: Record<string, string | string[] | undefined>) {
 return {
  strict_transport_security: Boolean(firstHeader(headers, 'strict-transport-security')),
  content_security_policy: Boolean(firstHeader(headers, 'content-security-policy')),
  x_content_type_options: Boolean(firstHeader(headers, 'x-content-type-options')),
  x_frame_options: Boolean(firstHeader(headers, 'x-frame-options')),
  referrer_policy: Boolean(firstHeader(headers, 'referrer-policy')),
  permissions_policy: Boolean(firstHeader(headers, 'permissions-policy')),
 };
}

function safeError(error: unknown) {
 if (!(error instanceof Error)) return 'UNKNOWN_ERROR';
 const code = (error as NodeJS.ErrnoException).code;
 return String(code || error.message || 'SCAN_ERROR').slice(0, 120).replace(/[^A-Z0-9_.:-]/gi, '_');
}

const defaultDeps: NativeScannerDeps = {
 requestRoot,
 inspectTls,
 sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

export async function runNativeHttpTlsChecks(
 hostname: string,
 timeoutSeconds: number,
 requestsPerSecond: number,
 deps: NativeScannerDeps = defaultDeps,
): Promise<NativeObservation[]> {
 const timeoutMs = Math.max(1000, Math.min(timeoutSeconds * 1000, 15000));
 const requestGapMs = Math.ceil(1000 / Math.max(1, Math.min(requestsPerSecond, 5)));
 const observations: NativeObservation[] = [];
 let httpsSnapshot: HttpSnapshot | null = null;

 try {
  httpsSnapshot = await deps.requestRoot('https:', hostname, timeoutMs);
  observations.push({
   check_id: 'https_response', kind: 'http', outcome: 'pass', summary: 'HTTPS root responded.', observed_url: `https://${hostname}/`,
   data: { status: httpsSnapshot.status },
  });
 } catch (error) {
  observations.push({
   check_id: 'https_response', kind: 'http', outcome: 'error', summary: 'HTTPS root request failed.', observed_url: `https://${hostname}/`,
   data: { error: safeError(error) },
  });
 }

 await deps.sleep(requestGapMs);
 try {
  const httpSnapshot = await deps.requestRoot('http:', hostname, timeoutMs);
  const location = firstHeader(httpSnapshot.headers, 'location');
  const redirectsToHttps = httpSnapshot.status >= 300 && httpSnapshot.status < 400 && isSameHostHttpsRedirect(hostname, location);
  observations.push({
   check_id: 'http_to_https', kind: 'redirect', outcome: redirectsToHttps ? 'pass' : 'warning',
   summary: redirectsToHttps ? 'HTTP redirects to same-host HTTPS.' : 'HTTP did not prove a same-host HTTPS redirect.',
   observed_url: `http://${hostname}/`, data: { status: httpSnapshot.status, location },
  });
 } catch (error) {
  observations.push({
   check_id: 'http_to_https', kind: 'redirect', outcome: 'error', summary: 'HTTP redirect check failed.', observed_url: `http://${hostname}/`,
   data: { error: safeError(error) },
  });
 }

 if (httpsSnapshot) {
  observations.push({
   check_id: 'security_headers', kind: 'headers', outcome: 'info', summary: 'Recorded presence of selected response security headers.', observed_url: `https://${hostname}/`,
   data: securityHeaderSnapshot(httpsSnapshot.headers),
  });
 } else {
  observations.push({
   check_id: 'security_headers', kind: 'headers', outcome: 'error', summary: 'Security headers could not be observed because HTTPS was unavailable.', observed_url: `https://${hostname}/`,
   data: { error: 'HTTPS_HEADERS_UNAVAILABLE' },
  });
 }

 try {
  const details = await deps.inspectTls(hostname, timeoutMs);
  observations.push({
   check_id: 'tls_handshake', kind: 'tls', outcome: details.authorized ? 'pass' : 'warning', summary: details.authorized ? 'TLS handshake and certificate validation succeeded.' : 'TLS handshake completed without trusted certificate authorization.', observed_url: `https://${hostname}/`,
   data: { ...details },
  });
 } catch (error) {
  observations.push({
   check_id: 'tls_handshake', kind: 'tls', outcome: 'error', summary: 'TLS handshake or certificate validation failed.', observed_url: `https://${hostname}/`,
   data: { error: safeError(error) },
  });
 }

 return observations;
}
