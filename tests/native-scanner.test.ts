import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPublicIp, isSameHostHttpsRedirect, runNativeHttpTlsChecks, securityHeaderSnapshot } from '../lib/scans/native-scanner';

test('public IP guard blocks private and special-use ranges', () => {
 assert.equal(isPublicIp('8.8.8.8'), true);
 assert.equal(isPublicIp('1.1.1.1'), true);
 for (const address of ['127.0.0.1','10.0.0.4','172.16.0.1','192.168.1.2','169.254.1.1','100.64.0.1','::1','fc00::1','fe80::1','2001:db8::1']) {
  assert.equal(isPublicIp(address), false, address);
 }
});

test('redirect guard only accepts same-host HTTPS without a custom port', () => {
 assert.equal(isSameHostHttpsRedirect('example.com', 'https://example.com/login'), true);
 assert.equal(isSameHostHttpsRedirect('example.com', '/login'), false);
 assert.equal(isSameHostHttpsRedirect('example.com', 'https://www.example.com/'), false);
 assert.equal(isSameHostHttpsRedirect('example.com', 'https://example.com:8443/'), false);
 assert.equal(isSameHostHttpsRedirect('example.com', 'http://example.com/'), false);
});

test('security header snapshot records presence without inventing a score', () => {
 assert.deepEqual(securityHeaderSnapshot({
  'strict-transport-security': 'max-age=31536000',
  'content-security-policy': "default-src 'self'",
  'x-content-type-options': 'nosniff',
 }), {
  strict_transport_security: true,
  content_security_policy: true,
  x_content_type_options: true,
  x_frame_options: false,
  referrer_policy: false,
  permissions_policy: false,
 });
});

test('native scanner emits bounded HTTP, redirect, header and TLS observations', async () => {
 const calls: string[] = [];
 const observations = await runNativeHttpTlsChecks('example.com', 10, 5, {
  async requestRoot(protocol) {
   calls.push(protocol);
   if (protocol === 'https:') return {
    status: 200,
    headers: {
     'strict-transport-security': 'max-age=31536000',
     'content-security-policy': "default-src 'self'",
     'x-content-type-options': 'nosniff',
    },
   };
   return { status: 308, headers: { location: 'https://example.com/' } };
  },
  async inspectTls() {
   return {
    protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', authorized: true,
    valid_from: 'Sep 1 00:00:00 2026 GMT', valid_to: 'Dec 1 00:00:00 2026 GMT',
    fingerprint256: 'AA:BB', subject_cn: 'example.com', issuer_cn: 'Test CA',
   };
  },
  async sleep() {},
 });
 assert.deepEqual(calls, ['https:', 'http:']);
 assert.equal(observations.length, 4);
 assert.equal(observations.find((item) => item.check_id === 'https_response')?.outcome, 'pass');
 assert.equal(observations.find((item) => item.check_id === 'http_to_https')?.outcome, 'pass');
 assert.equal(observations.find((item) => item.check_id === 'security_headers')?.outcome, 'info');
 assert.equal(observations.find((item) => item.check_id === 'tls_handshake')?.outcome, 'pass');
});

test('native scanner records transport failures instead of fabricating success', async () => {
 const observations = await runNativeHttpTlsChecks('example.com', 10, 5, {
  async requestRoot(protocol) {
   throw new Error(protocol === 'https:' ? 'ECONNREFUSED' : 'ENETUNREACH');
  },
  async inspectTls() { throw new Error('CERT_HAS_EXPIRED'); },
  async sleep() {},
 });
 assert.equal(observations.find((item) => item.check_id === 'https_response')?.outcome, 'error');
 assert.equal(observations.find((item) => item.check_id === 'security_headers')?.outcome, 'error');
 assert.equal(observations.find((item) => item.check_id === 'tls_handshake')?.outcome, 'error');
});
