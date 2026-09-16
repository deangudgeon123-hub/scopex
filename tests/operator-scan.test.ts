import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

const TOKEN = '0123456789abcdef0123456789abcdef';

test('operator scan queue enforces allowlist, token and state transitions', async () => {
 const db = new PGlite();
 try {
  await db.exec(`create role anon; create role authenticated; create role service_role bypassrls;
  create schema auth; create table auth.users(id uuid primary key);
  create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid $$;
  grant usage on schema auth to authenticated,anon; grant execute on function auth.uid() to authenticated,anon;`);
  for (const file of readdirSync('supabase/migrations').filter(f => f.endsWith('.sql')).sort()) {
   await db.exec(readFileSync(`supabase/migrations/${file}`, 'utf8'));
  }
  await db.query(`select scopex_private.configure_operator_token($1)`, [TOKEN]);
  await db.query(`select scopex_private.register_operator_target($1,$2)`, ['example.com','https://example.com']);

  await db.exec('set role authenticated');
  await assert.rejects(db.query(`select public.request_operator_scan($1,$2)`, ['example.com',TOKEN]), /permission denied/);

  await db.exec('set role anon');
  await assert.rejects(db.query(`select public.request_operator_scan($1,$2)`, ['example.com','wrong-token']), /OPERATOR_UNAUTHORIZED/);
  await assert.rejects(db.query(`select public.request_operator_scan($1,$2)`, ['evil.example.com',TOKEN]), /TARGET_NOT_ALLOWED/);
  const queued = await db.query<{request_operator_scan:string}>(`select public.request_operator_scan($1,$2)`, ['example.com',TOKEN]);
  const scanId = queued.rows[0].request_operator_scan;
  assert.match(scanId, /^[0-9a-f-]{36}$/i);
  await assert.rejects(db.query(`select public.request_operator_scan($1,$2)`, ['example.com',TOKEN]), /SCAN_ALREADY_ACTIVE/);

  let status = await db.query<{status:string}>(`select status from public.get_operator_scan_status($1,$2)`, [scanId,TOKEN]);
  assert.equal(status.rows[0].status, 'queued');

  await db.exec('reset role');
  await db.query(`select scopex_private.lease_operator_scan($1,$2)`, [scanId,'worker-test']);
  await assert.rejects(db.query(`select scopex_private.lease_operator_scan($1,$2)`, [scanId,'worker-test']), /INVALID_JOB_TRANSITION/);
  await db.exec('set role anon');
  status = await db.query<{status:string}>(`select status from public.get_operator_scan_status($1,$2)`, [scanId,TOKEN]);
  assert.equal(status.rows[0].status, 'running');

  await db.exec('reset role');
  await db.query(`select scopex_private.complete_operator_scan($1,$2,$3)`, [scanId,12,1]);
  await db.exec('set role anon');
  status = await db.query<{status:string}>(`select status from public.get_operator_scan_status($1,$2)`, [scanId,TOKEN]);
  assert.equal(status.rows[0].status, 'completed');

  const second = await db.query<{request_operator_scan:string}>(`select public.request_operator_scan($1,$2)`, ['example.com',TOKEN]);
  const secondId = second.rows[0].request_operator_scan;
  await db.exec('reset role');
  await db.query(`select scopex_private.fail_operator_scan($1,$2)`, [secondId,'TEST_FAILURE']);
  await db.exec('set role anon');
  const failed = await db.query<{status:string;failure_code:string}>(`select status,failure_code from public.get_operator_scan_status($1,$2)`, [secondId,TOKEN]);
  assert.equal(failed.rows[0].status, 'failed');
  assert.equal(failed.rows[0].failure_code, 'TEST_FAILURE');
 } finally {
  await db.close();
 }
});
