-- Development-only operator scan queue. This does NOT prove domain ownership.
-- Exact targets must be registered by a trusted operator before the public RPC can queue a scan.

create table scopex_private.operator_context (
 singleton boolean primary key default true check (singleton),
 user_id uuid not null unique references auth.users(id) on delete restrict,
 organization_id uuid not null unique references public.organizations(id) on delete restrict,
 project_id uuid not null unique references public.projects(id) on delete restrict,
 policy_id uuid not null unique references public.scan_policies(id) on delete restrict,
 operator_token text,
 created_at timestamptz not null default now()
);

create table scopex_private.operator_targets (
 hostname text primary key check (hostname = lower(hostname) and hostname ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'),
 origin text not null check (origin ~ '^https?://'),
 asset_id uuid not null unique references public.assets(id) on delete cascade,
 scope_id uuid not null unique references public.scopes(id) on delete cascade,
 enabled boolean not null default true,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);

revoke all on scopex_private.operator_context, scopex_private.operator_targets from public, anon, authenticated;
grant select, insert, update, delete on scopex_private.operator_context, scopex_private.operator_targets to service_role;

do $$
declare
 v_user uuid := gen_random_uuid();
 v_org uuid;
 v_project uuid;
 v_policy uuid;
begin
 insert into auth.users(id) values (v_user);
 insert into public.organizations(owner_id, name) values (v_user, 'SCOPEX Development Operator') returning id into v_org;
 insert into public.projects(organization_id, name) values (v_org, 'Private assessment development') returning id into v_project;
 insert into public.scan_policies(organization_id, name, scan_type, max_requests, requests_per_second, timeout_seconds, enabled)
 values (v_org, 'Native safe checks', 'configuration', 20, 1, 60, true) returning id into v_policy;
 insert into scopex_private.operator_context(singleton, user_id, organization_id, project_id, policy_id)
 values (true, v_user, v_org, v_project, v_policy);
end $$;

create or replace function scopex_private.configure_operator_token(p_token text)
returns boolean language plpgsql security definer set search_path = '' as $$
begin
 if length(trim(coalesce(p_token,''))) < 32 then raise exception 'OPERATOR_TOKEN_TOO_SHORT' using errcode='22023'; end if;
 update scopex_private.operator_context set operator_token = p_token where singleton = true;
 return true;
end; $$;

create or replace function scopex_private.register_operator_target(p_hostname text, p_origin text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
 v_hostname text := lower(trim(both '.' from trim(coalesce(p_hostname,''))));
 v_origin text := lower(trim(trailing '/' from trim(coalesce(p_origin,''))));
 v_context scopex_private.operator_context%rowtype;
 v_asset uuid;
 v_scope uuid;
begin
 if v_hostname = '' or length(v_hostname) > 253 or v_hostname !~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'
    or v_hostname = 'localhost' or v_hostname like '%.localhost' or v_hostname ~ '^[0-9.]+$' then
  raise exception 'INVALID_OPERATOR_TARGET' using errcode='22023';
 end if;
 if v_origin not in ('https://' || v_hostname, 'http://' || v_hostname) then
  raise exception 'INVALID_OPERATOR_ORIGIN' using errcode='22023';
 end if;
 select * into strict v_context from scopex_private.operator_context where singleton = true;
 select asset_id, scope_id into v_asset, v_scope from scopex_private.operator_targets where hostname = v_hostname;
 if v_asset is not null then
  update public.assets set origin = v_origin where id = v_asset;
  update public.scopes set expires_at = now() + interval '30 days' where id = v_scope;
  update scopex_private.operator_targets set origin = v_origin, enabled = true, updated_at = now() where hostname = v_hostname;
  return v_asset;
 end if;
 insert into public.assets(organization_id, project_id, hostname, origin)
 values (v_context.organization_id, v_context.project_id, v_hostname, v_origin) returning id into v_asset;
 insert into public.scopes(organization_id, project_id, asset_id, allowed_paths, include_subdomains, authorized_by, expires_at)
 values (v_context.organization_id, v_context.project_id, v_asset, array['/'], false, v_context.user_id, now() + interval '30 days') returning id into v_scope;
 insert into scopex_private.operator_targets(hostname, origin, asset_id, scope_id) values (v_hostname, v_origin, v_asset, v_scope);
 return v_asset;
end; $$;

create or replace function public.request_operator_scan(p_hostname text, p_token text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
 v_hostname text := lower(trim(both '.' from trim(coalesce(p_hostname,''))));
 v_target scopex_private.operator_targets%rowtype;
 v_context scopex_private.operator_context%rowtype;
 v_scan uuid;
begin
 select * into strict v_context from scopex_private.operator_context where singleton = true;
 if v_context.operator_token is null or p_token is distinct from v_context.operator_token then raise exception 'OPERATOR_UNAUTHORIZED' using errcode='P0001'; end if;
 select * into v_target from scopex_private.operator_targets where hostname = v_hostname and enabled = true;
 if not found then raise exception 'TARGET_NOT_ALLOWED' using errcode='P0001'; end if;
 if not exists (select 1 from public.scopes s where s.id = v_target.scope_id and s.asset_id = v_target.asset_id and s.expires_at > now()) then
  raise exception 'TARGET_SCOPE_EXPIRED' using errcode='P0001';
 end if;
 if exists (select 1 from public.scans s where s.asset_id = v_target.asset_id and s.status in ('queued','running')) then
  raise exception 'SCAN_ALREADY_ACTIVE' using errcode='P0001';
 end if;
 insert into public.scans(organization_id, project_id, asset_id, scope_id, policy_id, requested_by, status)
 values (v_context.organization_id, v_context.project_id, v_target.asset_id, v_target.scope_id, v_context.policy_id, v_context.user_id, 'queued') returning id into v_scan;
 insert into public.scan_jobs(organization_id, scan_id, status) values (v_context.organization_id, v_scan, 'queued');
 insert into public.scan_events(organization_id, scan_id, event_type, message) values (v_context.organization_id, v_scan, 'queued', 'Operator assessment queued.');
 return v_scan;
end; $$;

create or replace function public.get_operator_scan_status(p_scan_id uuid, p_token text)
returns table(scan_id uuid, hostname text, status text, created_at timestamptz, started_at timestamptz, completed_at timestamptz, failure_code text)
language plpgsql stable security definer set search_path = '' as $$
declare v_context scopex_private.operator_context%rowtype;
begin
 select * into strict v_context from scopex_private.operator_context where singleton = true;
 if v_context.operator_token is null or p_token is distinct from v_context.operator_token then raise exception 'OPERATOR_UNAUTHORIZED' using errcode='P0001'; end if;
 return query select s.id, t.hostname, s.status, s.created_at, s.started_at, s.completed_at, s.failure_code
 from public.scans s join scopex_private.operator_targets t on t.asset_id = s.asset_id where s.id = p_scan_id;
end; $$;

create or replace function scopex_private.lease_operator_scan(p_scan_id uuid, p_worker_id text)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_context scopex_private.operator_context%rowtype;
begin
 if trim(coalesce(p_worker_id,'')) = '' then raise exception 'WORKER_ID_REQUIRED' using errcode='22023'; end if;
 select * into strict v_context from scopex_private.operator_context where singleton = true;
 update public.scan_jobs set status='leased', attempts=attempts+1, worker_id=p_worker_id, lease_expires_at=now()+interval '5 minutes'
 where scan_id=p_scan_id and organization_id=v_context.organization_id and status='queued' and attempts < 3;
 if not found then raise exception 'INVALID_JOB_TRANSITION' using errcode='P0001'; end if;
 update public.scans set status='running', started_at=coalesce(started_at,now()), failure_code=null
 where id=p_scan_id and organization_id=v_context.organization_id and status='queued';
 if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;
 insert into public.scan_events(organization_id,scan_id,event_type,message) values(v_context.organization_id,p_scan_id,'running','Operator assessment leased by worker.');
 return true;
end; $$;

create or replace function scopex_private.complete_operator_scan(p_scan_id uuid, p_checks_run integer default 0, p_pages_checked integer default 0)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_context scopex_private.operator_context%rowtype;
begin
 if p_checks_run < 0 or p_pages_checked < 0 then raise exception 'INVALID_SCAN_COUNTS' using errcode='22023'; end if;
 select * into strict v_context from scopex_private.operator_context where singleton = true;
 update public.scan_jobs set status='completed', lease_expires_at=null where scan_id=p_scan_id and organization_id=v_context.organization_id and status='leased';
 if not found then raise exception 'INVALID_JOB_TRANSITION' using errcode='P0001'; end if;
 update public.scans set status='completed', completed_at=now(), checks_run=p_checks_run, pages_checked=p_pages_checked, failure_code=null
 where id=p_scan_id and organization_id=v_context.organization_id and status='running';
 if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;
 insert into public.scan_events(organization_id,scan_id,event_type,message) values(v_context.organization_id,p_scan_id,'completed','Operator assessment completed.');
 return true;
end; $$;

create or replace function scopex_private.fail_operator_scan(p_scan_id uuid, p_failure_code text)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_context scopex_private.operator_context%rowtype; v_code text := left(trim(coalesce(p_failure_code,'SCAN_FAILED')),120);
begin
 select * into strict v_context from scopex_private.operator_context where singleton = true;
 update public.scan_jobs set status='failed', lease_expires_at=null where scan_id=p_scan_id and organization_id=v_context.organization_id and status in ('queued','leased');
 if not found then raise exception 'INVALID_JOB_TRANSITION' using errcode='P0001'; end if;
 update public.scans set status='failed', completed_at=now(), failure_code=v_code where id=p_scan_id and organization_id=v_context.organization_id and status in ('queued','running');
 if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;
 insert into public.scan_events(organization_id,scan_id,event_type,message) values(v_context.organization_id,p_scan_id,'failed','Operator assessment failed.');
 return true;
end; $$;

revoke all on function scopex_private.configure_operator_token(text) from public, anon, authenticated;
revoke all on function scopex_private.register_operator_target(text,text) from public, anon, authenticated;
revoke all on function scopex_private.lease_operator_scan(uuid,text) from public, anon, authenticated;
revoke all on function scopex_private.complete_operator_scan(uuid,integer,integer) from public, anon, authenticated;
revoke all on function scopex_private.fail_operator_scan(uuid,text) from public, anon, authenticated;
grant usage on schema scopex_private to service_role;
grant execute on function scopex_private.configure_operator_token(text) to service_role;
grant execute on function scopex_private.register_operator_target(text,text) to service_role;
grant execute on function scopex_private.lease_operator_scan(uuid,text) to service_role;
grant execute on function scopex_private.complete_operator_scan(uuid,integer,integer) to service_role;
grant execute on function scopex_private.fail_operator_scan(uuid,text) to service_role;

revoke all on function public.request_operator_scan(text,text) from public;
revoke all on function public.get_operator_scan_status(uuid,text) from public;
grant execute on function public.request_operator_scan(text,text) to anon, authenticated;
grant execute on function public.get_operator_scan_status(uuid,text) to anon, authenticated;
