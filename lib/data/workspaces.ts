import 'server-only';
import { createClient } from '@/lib/supabase/server';
import { DataAccessError } from './supabase';
function name(value: string) {
 const result = value.trim();
 if (!result || result.length > 120) throw new Error('Use a name between 1 and 120 characters.');
 return result;
}
/** These operations use the signed-in user's RLS permissions, never a service key. */
export async function createWorkspace(value: string) {
 const client = await createClient();
 const { data: { user }, error } = await client.auth.getUser();
 if (error || !user) throw new DataAccessError('UNAUTHENTICATED', 'Sign in to create a workspace.');
 const result = await client.from('organizations').insert({ name: name(value), owner_id: user.id }).select().single();
 if (result.error) throw new DataAccessError('DATABASE', 'Workspace could not be created.');
 return result.data;
}
export async function createProject(organizationId: string, value: string) {
 const client = await createClient();
 const result = await client.from('projects').insert({ organization_id: organizationId, name: name(value) }).select().single();
 if (result.error) throw new DataAccessError('DATABASE', 'Project could not be created.');
 return result.data;
}
export async function createAsset(organizationId: string, projectId: string, website: string) {
 const url = new URL(website);
 if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.port || url.hostname.length > 253) throw new Error('Enter an HTTP or HTTPS website without credentials or a custom port.');
 const client = await createClient();
 const result = await client.from('assets').insert({ organization_id: organizationId, project_id: projectId, hostname: url.hostname.toLowerCase(), origin: url.origin }).select().single();
 if (result.error) throw new DataAccessError('DATABASE', 'Website could not be added. It may already exist in this project.');
 return result.data;
}
