import { request as httpRequest, type IncomingHttpHeaders, type IncomingMessage } from 'node:http';
import { request as httpsRequest, type RequestOptions as HttpsRequestOptions } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { resolvePublicAddresses, type AddressResolver } from './network-policy';

export type HeaderMap = IncomingHttpHeaders;

export interface HttpProbeResult {
 requestedUrl: string;
 statusCode: number;
 headers: HeaderMap;
 location: string | null;
 remoteAddress: string;
}

export interface TlsProbeResult {
 authorized: boolean;
 authorizationError: string | null;
 protocol: string | null;
 cipher: string | null;
 validFrom: string | null;
 validTo: string | null;
 subjectCn: string | null;
 issuerCn: string | null;
 fingerprint256: string | null;
 remoteAddress: string;
}

function validateProbeUrl(value: string): URL {
 const url = new URL(value);
 if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.port) {
  throw new Error('UNSAFE_PROBE_URL');
 }
 return url;
}

function certificateName(value: string | string[] | undefined): string | null {
 if (Array.isArray(value)) return value[0] ?? null;
 return value ?? null;
}

export async function probeHttpHead(value: string, timeoutMs = 8000, resolver?: AddressResolver): Promise<HttpProbeResult> {
 const url = validateProbeUrl(value);
 const [target] = await resolvePublicAddresses(url.hostname, resolver);
 return new Promise<HttpProbeResult>((resolve, reject) => {
  let settled = false;
  const options: HttpsRequestOptions = {
   protocol: url.protocol,
   hostname: target.address,
   port: url.protocol === 'https:' ? 443 : 80,
   method: 'HEAD',
   path: `${url.pathname || '/'}${url.search}`,
   servername: url.protocol === 'https:' ? url.hostname : undefined,
   rejectUnauthorized: url.protocol === 'https:' ? false : undefined,
   headers: {
    host: url.hostname,
    'user-agent': 'SCOPEX/0.1 safe-configuration-check',
    accept: '*/*',
    connection: 'close',
   },
  };
  const onResponse = (response: IncomingMessage) => {
   if (settled) return;
   settled = true;
   const result: HttpProbeResult = {
    requestedUrl: url.toString(),
    statusCode: response.statusCode ?? 0,
    headers: response.headers,
    location: typeof response.headers.location === 'string' ? response.headers.location : null,
    remoteAddress: target.address,
   };
   response.destroy();
   resolve(result);
  };
  const req = url.protocol === 'https:' ? httpsRequest(options, onResponse) : httpRequest(options, onResponse);
  req.setTimeout(timeoutMs, () => req.destroy(new Error('HTTP_TIMEOUT')));
  req.once('error', (error) => {
   if (settled) return;
   settled = true;
   reject(error);
  });
  req.end();
 });
}

export async function probeTls(hostname: string, timeoutMs = 8000, resolver?: AddressResolver): Promise<TlsProbeResult> {
 const [target] = await resolvePublicAddresses(hostname, resolver);
 return new Promise<TlsProbeResult>((resolve, reject) => {
  let settled = false;
  const socket = tlsConnect({
   host: target.address,
   port: 443,
   servername: hostname,
   rejectUnauthorized: false,
  });
  socket.setTimeout(timeoutMs, () => socket.destroy(new Error('TLS_TIMEOUT')));
  socket.once('secureConnect', () => {
   if (settled) return;
   settled = true;
   const certificate = socket.getPeerCertificate();
   const cipher = socket.getCipher();
   const result: TlsProbeResult = {
    authorized: socket.authorized,
    authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
    protocol: socket.getProtocol(),
    cipher: cipher?.name ?? null,
    validFrom: certificate?.valid_from ?? null,
    validTo: certificate?.valid_to ?? null,
    subjectCn: certificateName(certificate?.subject?.CN),
    issuerCn: certificateName(certificate?.issuer?.CN),
    fingerprint256: certificate?.fingerprint256 ?? null,
    remoteAddress: target.address,
   };
   socket.end();
   resolve(result);
  });
  socket.once('error', (error) => {
   if (settled) return;
   settled = true;
   reject(error);
  });
 });
}
