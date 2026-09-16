-- Native configuration scan observations and service-role worker RPCs.
-- Stage 3 stores descriptive observations only. Findings/severity mapping is Stage 4.

create table public.scan_observations (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id) on delete cascade,
 scan_id uuid not null references public.scans(id) on delete cascade,
 asset_id uuid not null references public.assets(id) on delete cascade,
 observation_key text not null check (length(observation_key) between 1 and 120),
 kind text not null check (kind in ('http','tls','header','redirect','network')),
 status text not null check (status in ('pass','warn','info','error')),
 summary text not null check (length(summary) between 1 and 500),
 data jsonb not null default '{}'::jsonb check (jsonb_typeof(data) = 'object' and octet_length(data::text) <= 8192),
 observed_at timestamptz not null default now(),
 unique(scan_id, observation_key)
);

create index scan_observations_scan_idx on public.scan_observations(scan_id, observed_at);
create index scan_observations_asset_idx on public.scan_observations(asset_id, observed_at desc);

alter table public.scan_observations enable row level security;
create policy scan_observations_read on public.scan_observations
 for select to authenticated using (public.can_read_workspace(organization_id));

revoke all on public.scan_observations from anon, authenticated;
grant select on public.scan_observations to authenticated;
grant select, insert, update, delete on public.scan_observations to service_role;

create or replace function public.claim_operator_scan(p_worker_id text)
returns table(
 scan_id uuid,
 hostname text,
 origin text,
 max_requests integer,
 requests_per_second integer,
 timeout_seconds integer
)
language plpgsql security definer set search_path = '' as $$
declare
 v_scan_id uuid;
begin
 if length(trim(coalesce(p_worker_id,''))) not between 1 and 120 then
  raise exception 'WORKER_ID_REQUIRED' using errcode='22023';
 end if;

 select sj.scan_id into v_scan_id
 from public.scan_jobs sj
 join public.scans s on s.id = sj.scan_id
 join public.scopes sc on sc.id = s.scope_id and sc.asset_id = s.asset_id
 join scopex_private.operator_targets t on t.asset_id = s.asset_id and t.scope_id = s.scope_id
 where sj.status = 'queued'
   and sj.available_at <= now()
   and sj.attempts < 3
   and s.status = 'queued'
   and t.enabled = true
   and sc.expires_at > now()
 order by sj.created_at
 for update of sj skip locked
 limit 1;

 if v_scan_id is null then return; end if;

 update public.scan_jobs
 set status='leased', attempts=attempts+1, worker_id=trim(p_worker_id), lease_expires_at=now()+interval '5 minutes'
 where scan_id=v_scan_id and status='queued';
 if not found then raise exception 'INVALID_JOB_TRANSITION' using errcode='P0001'; end if;

 update public.scans
 set status='running', started_at=coalesce(started_at,now()), failure_code=null
 where id=v_scan_id and status='queued';
 if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;

 insert into public.scan_events(organization_id,scan_id,event_type,message)
 select s.organization_id,s.id,'running','Native configuration assessment leased by worker.'
 from public.scans s where s.id=v_scan_id;

 return query
 select s.id, t.hostname, t.origin, p.max_requests, p.requests_per_second, p.timeout_seconds
 from public.scans s
 join public.scan_policies p on p.id=s.policy_id
 join scopex_private.operator_targets t on t.asset_id=s.asset_id and t.scope_id=s.scope_id
 where s.id=v_scan_id;
end; $$;

create or replace function public.store_operator_scan_observations(p_scan_id uuid, p_observations jsonb)
returns integer language plpgsql security definer set search_path = '' as $$
declare
 v_org uuid;
 v_asset uuid;
 v_expected integer;
 v_inserted integer;
begin
 if p_observations is null or jsonb_typeof(p_observations) <> 'array' then
  raise exception 'INVALID_OBSERVATION_PAYLOAD' using errcode='22023';
 end if;
 v_expected := jsonb_array_length(p_observations);
 if v_expected > 50 then raise exception 'TOO_MANY_OBSERVATIONS' using errcode='22023'; end if;

 select s.organization_id,s.asset_id into strict v_org,v_asset
 from public.scans s where s.id=p_scan_id and s.status='running';

 delete from public.scan_observations where scan_id=p_scan_id;

 insert into public.scan_observations(organization_id,scan_id,asset_id,observation_key,kind,status,summary,data)
 select v_org,p_scan_id,v_asset,trim(x.observation_key),x.kind,x.status,trim(x.summary),coalesce(x.data,'{}'::jsonb)
 from jsonb_to_recordset(p_observations) as x(
  observation_key text,
  kind text,
  status text,
  summary text,
  data jsonb
 )
 where length(trim(coalesce(x.observation_key,''))) between 1 and 120
   and x.kind in ('http','tls','header','redirect','network')
   and x.status in ('pass','warn','info','error')
   and length(trim(coalesce(x.summary,''))) between 1 and 500
   and jsonb_typeof(coalesce(x.data,'{}'::jsonb))='object';
 get diagnostics v_inserted = row_count;
 if v_inserted <> v_expected then raise exception 'INVALID_OBSERVATION_PAYLOAD' using errcode='22023'; end if;
 return v_inserted;
end; $$;

create or replace function public.finish_operator_scan(
 p_scan_id uuid,
 p_checks_run integer,
 p_pages_checked integer,
 p_failure_code text default null
)
returns boolean language plpgsql security definer set search_path = '' as $$
declare
 v_org uuid;
 v_code text;
begin
 if p_checks_run < 0 or p_pages_checked < 0 then raise exception 'INVALID_SCAN_COUNTS' using errcode='22023'; end if;
 select organization_id into strict v_org from public.scans where id=p_scan_id;

 if p_failure_code is null then
  update public.scan_jobs set status='completed', lease_expires_at=null
  where scan_id=p_scan_id and status='leased';
  if not found then raise exception 'INVALID_JOB_TRANSITION' using errcode='P0001'; end if;
  update public.scans set status='completed', completed_at=now(), checks_run=p_checks_run, pages_checked=p_pages_checked, failure_code=null
  where id=p_scan_id and status='running';
  if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;
  insert into public.scan_events(organization_id,scan_id,event_type,message)
  values(v_org,p_scan_id,'completed','Native configuration assessment completed.');
 else
  v_code := left(coalesce(nullif(trim(p_failure_code),''),'SCAN_FAILED'),120);
  update public.scan_jobs set status='failed', lease_expires_at=null
  where scan_id=p_scan_id and status in ('queued','leased');
  if not found then raise exception 'INVALID_JOB_TRANSITION' using errcode='P0001'; end if;
  update public.scans set status='failed', completed_at=now(), checks_run=p_checks_run, pages_checked=p_pages_checked, failure_code=v_code
  where id=p_scan_id and status in ('queued','running');
  if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;
  insert into public.scan_events(organization_id,scan_id,event_type,message)
  values(v_org,p_scan_id,'failed','Native configuration assessment failed.');
 end if;
 return true;
end; $$;

revoke all on function public.claim_operator_scan(text) from public, anon, authenticated;
revoke all on function public.store_operator_scan_observations(uuid,jsonb) from public, anon, authenticated;
revoke all on function public.finish_operator_scan(uuid,integer,integer,text) from public, anon, authenticated;
grant execute on function public.claim_operator_scan(text) to service_role;
grant execute on function public.store_operator_scan_observations(uuid,jsonb) to service_role;
grant execute on function public.finish_operator_scan(uuid,integer,integer,text) to service_role;
