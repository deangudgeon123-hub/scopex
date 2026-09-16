import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import type { Database } from '../lib/domain/database';
import { runNativeHttpTlsChecks } from '../lib/scans/native-scanner';

function required(name: string) {
 const value = process.env[name]?.trim();
 if (!value) throw new Error(`${name} is required.`);
 return value;
}

const url = process.env.SUPABASE_URL?.trim() || required('NEXT_PUBLIC_SUPABASE_URL');
const key = process.env.SUPABASE_PUBLISHABLE_KEY?.trim() || required('NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY');
const token = required('SCOPEX_OPERATOR_TOKEN');
if (token.length < 32) throw new Error('SCOPEX_OPERATOR_TOKEN must be at least 32 characters.');

const workerId = process.env.SCOPEX_WORKER_ID?.trim() || `native-${randomUUID()}`;
const pollMs = Math.max(1000, Math.min(Number(process.env.SCOPEX_WORKER_POLL_MS || 5000), 60000));
const port = Number(process.env.PORT || 10000);
const client = createClient<Database>(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
let lastRunAt: string | null = null;
let lastError: string | null = null;

function errorCode(error: unknown) {
 if (!(error instanceof Error)) return 'WORKER_ERROR';
 const code = (error as NodeJS.ErrnoException).code;
 return String(code || error.message || 'WORKER_ERROR').slice(0, 120).replace(/[^A-Z0-9_.:-]/gi, '_');
}

async function processOne() {
 const lease = await client.rpc('lease_next_operator_scan', { p_token: token, p_worker_id: workerId });
 if (lease.error) throw new Error(`LEASE_FAILED:${lease.error.message}`);
 const job = lease.data?.[0];
 if (!job) return false;

 lastRunAt = new Date().toISOString();
 try {
  const observations = await runNativeHttpTlsChecks(job.hostname, job.timeout_seconds, job.requests_per_second);
  const completed = await client.rpc('complete_operator_scan_native', {
   p_scan_id: job.scan_id,
   p_token: token,
   p_observations: observations,
   p_pages_checked: 1,
  });
  if (completed.error) throw new Error(`COMPLETE_FAILED:${completed.error.message}`);
  lastError = null;
  console.log(`completed native scan ${job.scan_id} for ${job.hostname} with ${observations.length} observations`);
 } catch (error) {
  const code = errorCode(error);
  lastError = code;
  console.error(`native scan ${job.scan_id} failed`, code);
  const failed = await client.rpc('fail_operator_scan_native', { p_scan_id: job.scan_id, p_token: token, p_failure_code: code });
  if (failed.error) console.error(`failed to mark ${job.scan_id} failed`, failed.error.message);
 }
 return true;
}

async function loop() {
 for (;;) {
  try {
   const processed = await processOne();
   if (!processed) await new Promise((resolve) => setTimeout(resolve, pollMs));
  } catch (error) {
   lastError = errorCode(error);
   console.error('native worker loop error', lastError);
   await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
 }
}

createServer((request, response) => {
 if (request.url !== '/health') {
  response.writeHead(404, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ error: 'not_found' }));
  return;
 }
 response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
 response.end(JSON.stringify({ ok: true, workerId, lastRunAt, lastError }));
}).listen(port, '0.0.0.0', () => console.log(`SCOPEX native worker listening on ${port}`));

void loop();
