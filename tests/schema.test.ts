import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';
const A = '00000000-0000-0000-0000-000000000001';
const B = '00000000-0000-0000-0000-000000000002';
test('migration applies and isolates tenants; trusted records cannot be forged', async () => {
 const db = new PGlite();
 try {
 await db.exec(`create role anon; create role authenticated; create role service_role bypassrls;
 create schema auth; create table auth.users(id uuid primary key);
 create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid $$;
 grant usage on schema auth to authenticated,anon; grant execute on function auth.uid() to authenticated,anon;
 insert into auth.users values ('${A}'),('${B}');`);
 for (const file of readdirSync('supabase/migrations').filter(f => f.endsWith('.sql')).sort()) await db.exec(readFileSync(`supabase/migrations/${file}`, 'utf8'));
 await db.exec(readFileSync('supabase/verify.sql', 'utf8'));
 await db.exec(`set role authenticated; set request.jwt.claim.sub = '${A}'`);
 const orgA = (await db.query<{id:string}>(`insert into organizations(owner_id,name) values ('${A}','A') returning id`)).rows[0].id;
 const projectA = (await db.query<{id:string}>(`insert into projects(organization_id,name) values ('${orgA}','A project') returning id`)).rows[0].id;
 const assetA = (await db.query<{id:string}>(`insert into assets(organization_id,project_id,hostname,origin) values ('${orgA}','${projectA}','example.com','https://example.com') returning id`)).rows[0].id;
 assert.equal((await db.query('select * from audit_logs')).rows.length, 3);
 await assert.rejects(db.exec(`update assets set verification_status='verified' where id='${assetA}'`), /permission denied/);
 await assert.rejects(db.exec(`insert into assets(organization_id,project_id,hostname,origin,verification_status) values ('${orgA}','${projectA}','evil.com','https://evil.com','verified')`), /permission denied/);
 for (const table of ['asset_verifications','organization_members','scopes','scan_policies','scans','scan_jobs','scan_events','scan_observations','findings','finding_instances','evidence','retests','audit_logs']) {
  const privileges = await db.query<{allowed:boolean}>(`select has_table_privilege('authenticated','public.${table}','INSERT') as allowed`);
  assert.equal(privileges.rows[0].allowed, false, table);
 }
 await db.exec(`set request.jwt.claim.sub = '${B}'`);
 assert.equal((await db.query('select * from organizations')).rows.length, 0);
 assert.equal((await db.query('select * from assets')).rows.length, 0);
 assert.equal((await db.query('select * from audit_logs')).rows.length, 0);
 await assert.rejects(db.exec(`insert into projects(organization_id,name) values ('${orgA}','Intruder')`), /row-level security/);
 const orgB = (await db.query<{id:string}>(`insert into organizations(owner_id,name) values ('${B}','B') returning id`)).rows[0].id;
 await assert.rejects(db.exec(`insert into assets(organization_id,project_id,hostname,origin) values ('${orgB}','${projectA}','cross.example','https://cross.example')`), /foreign key/);
 await db.exec('reset role');
 await db.exec(`insert into organization_members(organization_id,user_id,role) values ('${orgA}','${B}','viewer'); set role authenticated`);
 assert.equal((await db.query('select * from assets')).rows.length, 1);
 await assert.rejects(db.exec(`insert into projects(organization_id,name) values ('${orgA}','Viewer write')`), /row-level security/);
 await db.exec('set role anon');
 await assert.rejects(db.exec('select * from assets'), /permission denied/);
 await db.exec('reset role');
 const unsecured = await db.query(`select tablename from pg_tables where schemaname='public' and not rowsecurity`);
 assert.equal(unsecured.rows.length, 0);
 } finally { await db.close(); }
});
