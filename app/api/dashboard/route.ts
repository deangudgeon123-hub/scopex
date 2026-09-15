import { NextResponse } from 'next/server';
import { getDashboardService } from '@/lib/data/service';
import { DataAccessError } from '@/lib/data/supabase';
export const dynamic = 'force-dynamic';
export async function GET(request: Request) {
 const headers = { 'Cache-Control': 'private, no-store' };
 const projectId = new URL(request.url).searchParams.get('projectId') ?? undefined;
 if (projectId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(projectId)) return NextResponse.json({ error: 'Invalid project ID.' }, { status: 400, headers });
 try {
  const service = await getDashboardService();
  return NextResponse.json(await service.getDashboard(projectId), { headers });
 } catch (error) {
  const status = error instanceof DataAccessError ? { UNAUTHENTICATED: 401, NOT_FOUND: 404, DATABASE: 503 }[error.code] : 503;
  return NextResponse.json({ error: status === 401 ? 'Sign in to view your workspace.' : 'Dashboard unavailable. Please try again.' }, { status, headers });
 }
}
