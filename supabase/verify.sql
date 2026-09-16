-- Read-only verification after applying all committed SCOPEX migrations.
-- Run in the dedicated SCOPEX project's SQL editor, never another product's DB.
do $$
declare table_name text;
begin
 foreach table_name in array array['organizations','organization_members','projects',
 'assets','asset_verifications','scopes','scan_policies','scans','scan_jobs',
 'scan_events','scan_observations','findings','finding_instances','evidence','retests','audit_logs'] loop
  if not exists (select 1 from pg_tables t where t.schemaname='public'
    and t.tablename=table_name and t.rowsecurity) then
   raise exception 'Missing table or RLS: %', table_name;
  end if;
  if not exists (select 1 from pg_policies p where p.schemaname='public' and p.tablename=table_name) then
   raise exception 'Missing policy: %', table_name;
  end if;
  if has_table_privilege('anon', 'public.' || table_name, 'SELECT') then
   raise exception 'Unexpected anonymous table access: %', table_name;
  end if;
 end loop;
end $$;
select tablename, rowsecurity from pg_tables where schemaname='public' order by tablename;
