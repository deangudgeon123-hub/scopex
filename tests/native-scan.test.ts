import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPublicIpAddress, resolvePublicAddresses } from '../lib/scans/network-policy';
import { evaluateSecurityHeaders, scanNativeConfiguration } from '../lib/scans/native-engine';
import type { HttpProbeResult, TlsProbeResult } from '../lib/scans/native-http';

test('network policy rejects private, local, documentation and metadata ranges', async () => {
 assert.equal(isPublicIpAddress('1.1.1.1'), true);
 assert.equal(isPublicIpAddress('8.8.8.8'), true);
 for (const address of ['10.0.0.1','127.0.0.1','169.254.169.254','172.16.0.1','192.168.1.1','100.64.0.1','192.0.2.1','203.0.113.1','::1','fc00::1','fe80::1','2001:db8::1']) {
  assert.equal(isPublicIpAddress(address), false, address);
 }
 assert.equal(isPublicIpAddress('2606:4700:4700::1111'), true);
 await assert.rejects(resolvePublicAddresses('example.test', async () => [{ address: '1.1.1.1', family: 4 }, { address: '127.0.0.1', family: 4 }]), /non-public/i);
});

test('security header evaluator stays descriptive and does not invent severity', () => {
 const observations = evaluateSecurityHeaders({
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
  'strict-transport-security': 'max-age=31536000',
 }, true);
 assert.equal(observations.find((item) => item.observation_key === 'header.content_security_policy')?.status, 'pass');
 assert.equal(observations.find((item) => item.observation_key === 'header.hsts')?.status, 'pass');
 assert.equal(observations.some((item) => !['pass','warn','info','error'].includes(item.status)), false);
});

test('native engine performs bounded HTTP/TLS checks using injected probes', async () => {
 const urls: string[] = [];
 const httpProbe = async (url: string): Promise<HttpProbeResult> => {
  urls.push(url);
  if (url.startsWith('http://')) return { requestedUrl: url, statusCode: 301, headers: { location: 'https://example.com/' }, location: 'https://example.com/', remoteAddress: '1.1.1.1' };
  return {
   requestedUrl: url,
   statusCode: 200,
   headers: {
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=()',
    'strict-transport-security': 'max-age=31536000',
   },
   location: null,
   remoteAddress: '1.1.1.1',
  };
 };
 const tlsProbe = async (): Promise<TlsProbeResult> => ({
  authorized: true,
  authorizationError: null,
  protocol: 'TLSv1.3',
  cipher: 'TLS_AES_256_GCM_SHA384',
  validFrom: '2026-01-01T00:00:00Z',
  validTo: '2099-01-01T00:00:00Z',
  subjectCn: 'example.com',
  issuerCn: 'Example CA',
  fingerprint256: 'AA:BB',
  remoteAddress: '1.1.1.1',
 });
 const result = await scanNativeConfiguration({ hostname: 'example.com', origin: 'https://example.com', maxRequests: 2 }, { httpProbe, tlsProbe });
 assert.deepEqual(urls, ['http://example.com/','https://example.com/']);
 assert.equal(result.requestsMade, 2);
 assert.equal(result.pagesChecked, 2);
 assert.equal(result.observations.find((item) => item.observation_key === 'redirect.http_to_https')?.status, 'pass');
 assert.equal(result.observations.find((item) => item.observation_key === 'tls.protocol')?.status, 'pass');
});
