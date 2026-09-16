import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

const TOKEN = 'fedcba9876543210fedcba9876543210';

async function setup() {
 const db = new PGlite();
 await db.exec(`create role anon; create role authenticated; create role service_role bypassrls;
 create schema auth; create table auth.users(id uuid primary key);
 create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid $$;
 grant usage on schema auth to authenticated,anon; grant execute on function auth.uid() to authenticated,anon;`);
 for (const file of readdirSync('supabase/migrations').filter((file) => file.endsWith('.sql')).sort()) {
  await db.exec(readFileSync(`supabase/migrations/${file}`, 'utf8'));
 }
 await db.query(`select scopex_private.configure_operator_token($1)`, [TOKEN]);
 await db.query(`select scopex_private.register_operator_target($1,$2)`, ['example.com','https://example.com']);
 return db;
}

test('native worker leases a queued scan and persists bounded observations', async () => {
 const db = await setup();
 try {
  await db.exec('set role anon');
  const queued = await db.query<{request_operator_scan:string}>(`select public.request_operator_scan($1,$2)`, ['example.com', TOKEN]);
  const scanId = queued.rows[0].request_operator_scan;

  await assert.rejects(db.query(`select * from public.lease_next_operator_scan($1,$2)`, ['wrong-token','worker-test']), /OPERATOR_UNAUTHORIZED/);
  const lease = await db.query<{scan_id:string;hostname:string;origin:string;timeout_seconds:number;requests_per_second:number}>(
   `select * from public.lease_next_operator_scan($1,$2)`, [TOKEN,'worker-test'],
  );
  assert.equal(lease.rows.length, 1);
  assert.equal(lease.rows[0].scan_id, scanId);
  assert.equal(lease.rows[0].hostname, 'example.com');
  assert.equal(lease.rows[0].origin, 'https://example.com');

  const observations = [
   { check_id: 'https_response', kind: 'http', outcome: 'pass', observed_url: 'https://example.com/', data: { status: 200 } },
   { check_id: 'http_to_https', kind: 'redirect', outcome: 'pass', observed_url: 'http://example.com/', data: { status: 308, location: 'https://example.com/' } },
   { check_id: 'security_headers', kind: 'headers', outcome: 'info', observed_url: 'https://example.com/', data: { strict_transport_security: true } },
   { check_id: 'tls_handshake', kind: 'tls', outcome: 'pass', observed_url: 'https://example.com/', data: { protocol: 'TLSv1.3' } },
  ];
  await db.query(`select public.complete_operator_scan_native($1,$2,$3::jsonb,$4)`, [scanId,TOKEN,JSON.stringify(observations),1]);

  await db.exec('reset role');
  const status = await db.query<{status:string;checks_run:number;pages_checked:number}>(`select status,checks_run,pages_checked from public.scans where id=$1`, [scanId]);
  assert.deepEqual(status.rows[0], { status: 'completed', checks_run: 4, pages_checked: 1 });

  const stored = await db.query<{check_id:string}>(`select check_id from public.scan_observations where scan_id=$1 order by check_id`, [scanId]);
  assert.deepEqual(stored.rows.map((row) => row.check_id), ['http_to_https','https_response','security_headers','tls_handshake']);

  await db.exec('set role authenticated');
  await assert.rejects(db.query(`select * from public.lease_next_operator_scan($1,$2)`, [TOKEN,'worker-test']), /permission denied/);
 } finally {
  await db.close();
 }
});

test('native completion rejects malformed observation payloads atomically', async () => {
 const db = await setup();
 try {
  await db.exec('set role anon');
  const queued = await db.query<{request_operator_scan:string}>(`select public.request_operator_scan($1,$2)`, ['example.com', TOKEN]);
  const scanId = queued.rows[0].request_operator_scan;
  await db.query(`select * from public.lease_next_operator_scan($1,$2)`, [TOKEN,'worker-test']);
  await assert.rejects(
   db.query(`select public.complete_operator_scan_native($1,$2,$3::jsonb,$4)`, [scanId,TOKEN,JSON.stringify([{ check_id: 'BAD ID', kind: 'http', outcome: 'pass', data: {} }]),1]),
   /INVALID_OBSERVATION/,
  );
  await db.exec('reset role');
  assert.equal((await db.query(`select * from public.scan_observations where scan_id=$1`, [scanId])).rows.length, 0);
  assert.equal((await db.query<{status:string}>(`select status from public.scans where id=$1`, [scanId])).rows[0].status, 'running');
 } finally {
  await db.close();
 }
});
