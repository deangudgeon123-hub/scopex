import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

const TOKEN = '0123456789abcdef0123456789abcdef';

test('service-role worker claims a queued scan, stores observations, and completes it', async () => {
 const db = new PGlite();
 try {
  await db.exec(`create role anon; create role authenticated; create role service_role bypassrls;
  create schema auth; create table auth.users(id uuid primary key);
  create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid $$;
  grant usage on schema auth to authenticated,anon; grant execute on function auth.uid() to authenticated,anon;`);
  for (const file of readdirSync('supabase/migrations').filter((file) => file.endsWith('.sql')).sort()) {
   await db.exec(readFileSync(`supabase/migrations/${file}`, 'utf8'));
  }
  await db.query(`select scopex_private.configure_operator_token($1)`, [TOKEN]);
  await db.query(`select scopex_private.register_operator_target($1,$2)`, ['example.com','https://example.com']);
  await db.exec('set role anon');
  const queued = await db.query<{request_operator_scan:string}>(`select public.request_operator_scan($1,$2)`, ['example.com',TOKEN]);
  const scanId = queued.rows[0].request_operator_scan;

  await db.exec('reset role; set role service_role');
  const claimed = await db.query<{scan_id:string;hostname:string;origin:string;max_requests:number}>(`select * from public.claim_operator_scan($1)`, ['worker-test']);
  assert.equal(claimed.rows[0].scan_id, scanId);
  assert.equal(claimed.rows[0].hostname, 'example.com');
  assert.equal(claimed.rows[0].origin, 'https://example.com');
  assert.equal(claimed.rows[0].max_requests, 20);

  const payload = JSON.stringify([
   { observation_key: 'redirect.http_to_https', kind: 'redirect', status: 'pass', summary: 'HTTP redirects to HTTPS.', data: { statusCode: 301 } },
   { observation_key: 'tls.protocol', kind: 'tls', status: 'pass', summary: 'Negotiated TLSv1.3.', data: { protocol: 'TLSv1.3' } },
  ]);
  const stored = await db.query<{store_operator_scan_observations:number}>(`select public.store_operator_scan_observations($1,$2::jsonb)`, [scanId,payload]);
  assert.equal(stored.rows[0].store_operator_scan_observations, 2);
  await db.query(`select public.finish_operator_scan($1,$2,$3,$4)`, [scanId,2,2,null]);
  const observations = await db.query<{observation_key:string}>(`select observation_key from public.scan_observations where scan_id=$1 order by observation_key`, [scanId]);
  assert.deepEqual(observations.rows.map((row) => row.observation_key), ['redirect.http_to_https','tls.protocol']);

  await db.exec('set role anon');
  const status = await db.query<{status:string;checks_run:number;pages_checked:number}>(`select status,checks_run,pages_checked from public.get_operator_scan_status($1,$2)`, [scanId,TOKEN]);
  assert.equal(status.rows[0].status, 'completed');
  assert.equal(status.rows[0].checks_run, 2);
  assert.equal(status.rows[0].pages_checked, 2);

  await db.exec('set role authenticated');
  await assert.rejects(db.query(`select * from public.claim_operator_scan($1)`, ['not-allowed']), /permission denied/);
 } finally {
  await db.close();
 }
});
