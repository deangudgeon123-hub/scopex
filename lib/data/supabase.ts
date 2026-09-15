import 'server-only';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { Database } from '@/lib/domain/database';
import type { DashboardData, DashboardRepository } from './contracts';
import { projectDashboard } from './projection';
export class DataAccessError extends Error {
 constructor(public readonly code: 'UNAUTHENTICATED' | 'NOT_FOUND' | 'DATABASE', message: string) { super(message); }
}
export class SupabaseDashboardRepository implements DashboardRepository {
 constructor(private readonly client: SupabaseClient<Database>) {}
 async getDashboard(projectId?: string): Promise<DashboardData> {
  const { data: { user }, error: authError } = await this.client.auth.getUser();
  if (authError || !user) throw new DataAccessError('UNAUTHENTICATED', 'Sign in to view your workspace.');
  let projectQuery = this.client.from('projects').select('*').order('created_at').limit(1);
  if (projectId) projectQuery = projectQuery.eq('id', projectId);
  const { data: projects, error } = await projectQuery;
  if (error) throw new DataAccessError('DATABASE', 'Your projects could not be loaded.');
  const project = projects?.[0];
  if (projectId && !project) throw new DataAccessError('NOT_FOUND', 'Project unavailable.');
  if (!project) return projectDashboard(null, null, [], [], []);
  const [workspace, assets, findings, scans] = await Promise.all([
   this.client.from('organizations').select('*').eq('id', project.organization_id).single(),
   this.client.from('assets').select('*').eq('organization_id', project.organization_id).eq('project_id', project.id).order('created_at'),
   this.client.from('findings').select('*').eq('organization_id', project.organization_id).eq('project_id', project.id).eq('state', 'open').order('last_seen', { ascending: false }),
   this.client.from('scans').select('*').eq('organization_id', project.organization_id).eq('project_id', project.id).order('created_at', { ascending: false }).limit(1),
  ]);
  if (workspace.error || assets.error || findings.error || scans.error) throw new DataAccessError('DATABASE', 'Your security overview could not be loaded.');
  return projectDashboard(workspace.data, project, assets.data ?? [], findings.data ?? [], scans.data ?? []);
 }
}
