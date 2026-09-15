import 'server-only';
import { getDataMode } from '@/lib/supabase/config';
import { createClient } from '@/lib/supabase/server';
import { DemoDashboardRepository } from './demo';
import { SupabaseDashboardRepository } from './supabase';
import type { DashboardRepository } from './contracts';
export async function getDashboardService(): Promise<DashboardRepository> {
 if (getDataMode() === 'demo') return new DemoDashboardRepository();
 return new SupabaseDashboardRepository(await createClient());
}
