import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { assertOperatorTargetAllowed, OperatorTargetError } from '@/lib/scans/operator-target';

export const runtime = 'nodejs';

function operatorToken() {
 const token = process.env.SCOPEX_OPERATOR_TOKEN?.trim();
 if (!token || token.length < 32) throw new Error('SCOPEX_OPERATOR_TOKEN is missing or too short.');
 return token;
}

function rpcMessage(error: { message?: string } | null) {
 return error?.message ?? 'Operator scan request failed.';
}

export async function POST(request: NextRequest) {
 try {
  const body = await request.json() as { target?: unknown };
  if (typeof body.target !== 'string') return NextResponse.json({ error: 'target is required' }, { status: 400 });
  const hostname = assertOperatorTargetAllowed(body.target);
  const client = await createClient();
  const result = await client.rpc('request_operator_scan', { p_hostname: hostname, p_token: operatorToken() });
  if (result.error) {
   const message = rpcMessage(result.error);
   if (message.includes('OPERATOR_UNAUTHORIZED')) return NextResponse.json({ error: 'Operator mode is not configured.' }, { status: 503 });
   if (message.includes('TARGET_NOT_ALLOWED') || message.includes('TARGET_SCOPE_EXPIRED')) return NextResponse.json({ error: 'Target is not authorised for development scanning.' }, { status: 403 });
   if (message.includes('SCAN_ALREADY_ACTIVE')) return NextResponse.json({ error: 'A scan is already queued or running for this target.' }, { status: 409 });
   return NextResponse.json({ error: 'Could not queue assessment.' }, { status: 500 });
  }
  return NextResponse.json({ scanId: result.data, hostname, status: 'queued' }, { status: 202 });
 } catch (error) {
  if (error instanceof OperatorTargetError) {
   const status = error.code === 'OPERATOR_DISABLED' ? 404 : error.code === 'TARGET_NOT_ALLOWED' ? 403 : 400;
   return NextResponse.json({ error: error.message }, { status });
  }
  if (error instanceof SyntaxError) return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 });
  console.error('operator scan request failed', error);
  return NextResponse.json({ error: 'Operator assessment service is not configured.' }, { status: 503 });
 }
}

export async function GET(request: NextRequest) {
 try {
  if (process.env.SCOPEX_OPERATOR_MODE !== 'enabled') return NextResponse.json({ error: 'Not found.' }, { status: 404 });
  const scanId = request.nextUrl.searchParams.get('scanId');
  if (!scanId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(scanId)) {
   return NextResponse.json({ error: 'Valid scanId is required.' }, { status: 400 });
  }
  const client = await createClient();
  const result = await client.rpc('get_operator_scan_status', { p_scan_id: scanId, p_token: operatorToken() });
  if (result.error) {
   if (rpcMessage(result.error).includes('OPERATOR_UNAUTHORIZED')) return NextResponse.json({ error: 'Operator mode is not configured.' }, { status: 503 });
   return NextResponse.json({ error: 'Could not read assessment status.' }, { status: 500 });
  }
  const row = result.data?.[0];
  if (!row) return NextResponse.json({ error: 'Assessment not found.' }, { status: 404 });
  return NextResponse.json(row);
 } catch (error) {
  console.error('operator scan status failed', error);
  return NextResponse.json({ error: 'Operator assessment service is not configured.' }, { status: 503 });
 }
}
