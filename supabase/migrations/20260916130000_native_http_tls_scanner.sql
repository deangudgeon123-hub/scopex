-- Stage 3 worker-facing dev RPCs. Raw observations are evidence inputs, not findings.

alter table public.scan_observations
 add column if not exists observed_url text check (observed_url is null or length(observed_url) <= 2048);

create or replace function public.lease_next_operator_scan(p_token text, p_worker_id text)
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
 v_context scopex_private.operator_context%rowtype;
 v_job public.scan_jobs%rowtype;
begin
 select * into strict v_context from scopex_private.operator_context where singleton = true;
 if v_context.operator_token is null or p_token is distinct from v_context.operator_token then
  raise exception 'OPERATOR_UNAUTHORIZED' using errcode='P0001';
 end if;
 if length(trim(coalesce(p_worker_id,''))) < 3 or length(p_worker_id) > 120 then
  raise exception 'WORKER_ID_REQUIRED' using errcode='22023';
 end if;

 select j.* into v_job
 from public.scan_jobs j
 join public.scans s on s.id = j.scan_id and s.organization_id = j.organization_id
 join scopex_private.operator_targets t on t.asset_id = s.asset_id and t.enabled = true
 join public.scopes sc on sc.id = s.scope_id and sc.expires_at > now()
 where j.organization_id = v_context.organization_id
   and j.status = 'queued'
   and j.available_at <= now()
   and j.attempts < 3
 order by j.available_at, j.created_at
 for update of j skip locked
 limit 1;

 if not found then return; end if;

 update public.scan_jobs
 set status='leased', attempts=attempts+1, worker_id=p_worker_id, lease_expires_at=now()+interval '5 minutes'
 where id=v_job.id and status='queued';
 if not found then raise exception 'INVALID_JOB_TRANSITION' using errcode='P0001'; end if;

 update public.scans
 set status='running', started_at=coalesce(started_at,now()), failure_code=null
 where id=v_job.scan_id and organization_id=v_context.organization_id and status='queued';
 if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;

 insert into public.scan_events(organization_id,scan_id,event_type,message)
 values(v_context.organization_id,v_job.scan_id,'running','Native scanner leased assessment.');

 return query
 select s.id, t.hostname, t.origin, p.max_requests, p.requests_per_second, p.timeout_seconds
 from public.scans s
 join scopex_private.operator_targets t on t.asset_id=s.asset_id
 join public.scan_policies p on p.id=s.policy_id
 where s.id=v_job.scan_id;
end; $$;

create or replace function public.complete_operator_scan_native(
 p_scan_id uuid,
 p_token text,
 p_observations jsonb,
 p_pages_checked integer default 1
)
returns boolean language plpgsql security definer set search_path = '' as $$
declare
 v_context scopex_private.operator_context%rowtype;
 v_asset_id uuid;
 v_item jsonb;
 v_key text;
 v_kind text;
 v_status text;
 v_summary text;
 v_observed_url text;
 v_data jsonb;
 v_count integer;
begin
 select * into strict v_context from scopex_private.operator_context where singleton = true;
 if v_context.operator_token is null or p_token is distinct from v_context.operator_token then
  raise exception 'OPERATOR_UNAUTHORIZED' using errcode='P0001';
 end if;
 if p_pages_checked < 0 then raise exception 'INVALID_SCAN_COUNTS' using errcode='22023'; end if;
 if jsonb_typeof(p_observations) <> 'array' then raise exception 'INVALID_OBSERVATIONS' using errcode='22023'; end if;
 v_count := jsonb_array_length(p_observations);
 if v_count < 1 or v_count > 32 then raise exception 'INVALID_OBSERVATION_COUNT' using errcode='22023'; end if;

 select s.asset_id into v_asset_id
 from public.scans s join public.scan_jobs j on j.scan_id=s.id and j.organization_id=s.organization_id
 where s.id=p_scan_id and s.organization_id=v_context.organization_id and s.status='running' and j.status='leased';
 if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;

 for v_item in select value from jsonb_array_elements(p_observations) loop
  if jsonb_typeof(v_item) <> 'object' then raise exception 'INVALID_OBSERVATION' using errcode='22023'; end if;
  v_key := trim(coalesce(v_item->>'check_id',''));
  v_kind := case trim(coalesce(v_item->>'kind','')) when 'headers' then 'header' when 'metadata' then 'network' else trim(coalesce(v_item->>'kind','')) end;
  v_status := case trim(coalesce(v_item->>'outcome','')) when 'warning' then 'warn' else trim(coalesce(v_item->>'outcome','')) end;
  v_summary := trim(coalesce(v_item->>'summary',''));
  v_observed_url := nullif(trim(coalesce(v_item->>'observed_url','')), '');
  v_data := coalesce(v_item->'data', '{}'::jsonb);
  if length(v_key) < 1 or length(v_key) > 120
     or v_kind not in ('http','tls','header','redirect','network')
     or v_status not in ('pass','warn','info','error')
     or length(v_summary) < 1 or length(v_summary) > 500
     or (v_observed_url is not null and length(v_observed_url) > 2048)
     or jsonb_typeof(v_data) <> 'object'
     or octet_length(v_data::text) > 8192 then
   raise exception 'INVALID_OBSERVATION' using errcode='22023';
  end if;
  insert into public.scan_observations(organization_id,scan_id,asset_id,observation_key,kind,status,summary,observed_url,data)
  values(v_context.organization_id,p_scan_id,v_asset_id,v_key,v_kind,v_status,v_summary,v_observed_url,v_data);
 end loop;

 update public.scan_jobs set status='completed', lease_expires_at=null
 where scan_id=p_scan_id and organization_id=v_context.organization_id and status='leased';
 if not found then raise exception 'INVALID_JOB_TRANSITION' using errcode='P0001'; end if;

 update public.scans
 set status='completed', completed_at=now(), checks_run=v_count, pages_checked=p_pages_checked, failure_code=null
 where id=p_scan_id and organization_id=v_context.organization_id and status='running';
 if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;

 insert into public.scan_events(organization_id,scan_id,event_type,message)
 values(v_context.organization_id,p_scan_id,'completed','Native HTTP/TLS assessment completed.');
 return true;
end; $$;

create or replace function public.fail_operator_scan_native(p_scan_id uuid, p_token text, p_failure_code text)
returns boolean language plpgsql security definer set search_path = '' as $$
declare
 v_context scopex_private.operator_context%rowtype;
 v_code text := left(trim(coalesce(p_failure_code,'SCAN_FAILED')),120);
begin
 select * into strict v_context from scopex_private.operator_context where singleton = true;
 if v_context.operator_token is null or p_token is distinct from v_context.operator_token then
  raise exception 'OPERATOR_UNAUTHORIZED' using errcode='P0001';
 end if;
 update public.scan_jobs set status='failed', lease_expires_at=null
 where scan_id=p_scan_id and organization_id=v_context.organization_id and status='leased';
 if not found then raise exception 'INVALID_JOB_TRANSITION' using errcode='P0001'; end if;
 update public.scans set status='failed', completed_at=now(), failure_code=v_code
 where id=p_scan_id and organization_id=v_context.organization_id and status='running';
 if not found then raise exception 'INVALID_SCAN_TRANSITION' using errcode='P0001'; end if;
 insert into public.scan_events(organization_id,scan_id,event_type,message)
 values(v_context.organization_id,p_scan_id,'failed','Native HTTP/TLS assessment failed.');
 return true;
end; $$;

revoke all on function public.lease_next_operator_scan(text,text) from public, authenticated;
revoke all on function public.complete_operator_scan_native(uuid,text,jsonb,integer) from public, authenticated;
revoke all on function public.fail_operator_scan_native(uuid,text,text) from public, authenticated;
grant execute on function public.lease_next_operator_scan(text,text) to anon, service_role;
grant execute on function public.complete_operator_scan_native(uuid,text,jsonb,integer) to anon, service_role;
grant execute on function public.fail_operator_scan_native(uuid,text,text) to anon, service_role;
