import { createClient } from '@supabase/supabase-js';
import type { Database } from '../lib/domain/database';
import type { Json } from '../lib/domain';
import { scanNativeConfiguration } from '../lib/scans/native-engine';

function required(name: string): string {
 const value = process.env[name]?.trim();
 if (!value) throw new Error(`${name} is required.`);
 return value;
}

function workerId(): string {
 return (process.env.SCOPEX_WORKER_ID?.trim() || `scopex-native-${process.pid}`).slice(0, 120);
}

function pollDelay(): number {
 const parsed = Number(process.env.SCOPEX_WORKER_POLL_MS ?? 5000);
 return Number.isFinite(parsed) ? Math.min(Math.max(Math.trunc(parsed), 1000), 60000) : 5000;
}

function failureCode(error: unknown): string {
 if (!(error instanceof Error)) return 'NATIVE_SCAN_FAILED';
 const value = error.message.toUpperCase().replace(/[^A-Z0-9_]+/g, '_').replace(/^_+|_+$/g, '');
 return (value || 'NATIVE_SCAN_FAILED').slice(0, 120);
}

const client = createClient<Database>(required('SUPABASE_URL'), required('SUPABASE_SERVICE_ROLE_KEY'), {
 auth: { persistSession: false, autoRefreshToken: false },
});

export async function runOneNativeScan(): Promise<boolean> {
 const claim = await client.rpc('claim_operator_scan', { p_worker_id: workerId() });
 if (claim.error) throw new Error(`CLAIM_FAILED: ${claim.error.message}`);
 const job = claim.data?.[0];
 if (!job) return false;

 let checksRun = 0;
 let pagesChecked = 0;
 try {
  const result = await scanNativeConfiguration({
   hostname: job.hostname,
   origin: job.origin,
   timeoutMs: Math.min(job.timeout_seconds * 1000, 15000),
   maxRequests: Math.min(job.max_requests, 2),
  });
  checksRun = result.observations.length;
  pagesChecked = result.pagesChecked;
  const stored = await client.rpc('store_operator_scan_observations', {
   p_scan_id: job.scan_id,
   p_observations: result.observations as unknown as Json,
  });
  if (stored.error) throw new Error(`OBSERVATION_STORE_FAILED: ${stored.error.message}`);
  const completed = await client.rpc('finish_operator_scan', {
   p_scan_id: job.scan_id,
   p_checks_run: checksRun,
   p_pages_checked: pagesChecked,
   p_failure_code: null,
  });
  if (completed.error) throw new Error(`SCAN_FINISH_FAILED: ${completed.error.message}`);
  console.log(JSON.stringify({ event: 'scan_completed', scanId: job.scan_id, checksRun, pagesChecked }));
  return true;
 } catch (error) {
  const failed = await client.rpc('finish_operator_scan', {
   p_scan_id: job.scan_id,
   p_checks_run: checksRun,
   p_pages_checked: pagesChecked,
   p_failure_code: failureCode(error),
  });
  if (failed.error) console.error('Failed to persist scan failure', failed.error.message);
  console.error('Native scan failed', error);
  return true;
 }
}

async function main() {
 if (process.argv.includes('--once')) {
  await runOneNativeScan();
  return;
 }
 const delay = pollDelay();
 console.log(JSON.stringify({ event: 'worker_started', workerId: workerId(), pollMs: delay }));
 for (;;) {
  try {
   const worked = await runOneNativeScan();
   if (!worked) await new Promise((resolve) => setTimeout(resolve, delay));
  } catch (error) {
   console.error('Worker iteration failed', error);
   await new Promise((resolve) => setTimeout(resolve, delay));
  }
 }
}

if (import.meta.url === `file://${process.argv[1]}`) {
 main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
 });
}
