-- SCOPEX foundation. No scanners or worker execution are enabled by this migration.
create table public.organizations (
 id uuid primary key default gen_random_uuid(),
 owner_id uuid not null references auth.users(id),
 name text not null check (length(trim(name)) between 1 and 120),
 created_at timestamptz not null default now()
);
create table public.organization_members (
 organization_id uuid not null references public.organizations(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 role text not null default 'member' check (role in ('admin','member','viewer')),
 created_at timestamptz not null default now(),
 primary key (organization_id,user_id)
);
create index organization_members_user_idx on public.organization_members(user_id);
alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
create policy members_read_self on public.organization_members for select to authenticated using (user_id = (select auth.uid()));
create policy organizations_read on public.organizations for select to authenticated using (
 owner_id = (select auth.uid()) or id in (select organization_id from public.organization_members where user_id = (select auth.uid()))
);
create policy organizations_create on public.organizations for insert to authenticated with check (owner_id = (select auth.uid()));
create policy organizations_rename on public.organizations for update to authenticated using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));
-- Invoker helpers keep membership authorization under RLS, with no privileged bypass.
create function public.can_read_workspace(workspace uuid) returns boolean language sql stable security invoker set search_path = '' as $$
 select exists(select 1 from public.organizations where id = workspace);
$$;
create function public.can_manage_workspace(workspace uuid) returns boolean language sql stable security invoker set search_path = '' as $$
 select exists(select 1 from public.organizations where id = workspace and owner_id = (select auth.uid()))
 or exists(select 1 from public.organization_members where organization_id = workspace and user_id = (select auth.uid()) and role in ('admin','member'));
$$;
revoke all on function public.can_read_workspace(uuid), public.can_manage_workspace(uuid) from public;
grant execute on function public.can_read_workspace(uuid), public.can_manage_workspace(uuid) to authenticated, service_role;

create table public.projects (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 name text not null check (length(trim(name)) between 1 and 120),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.projects enable row level security;
create policy workspace_read on public.projects for select to authenticated using (public.can_read_workspace(organization_id));

create table public.assets (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 project_id uuid not null,
 hostname text not null check (hostname = lower(hostname) and hostname ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'),
 origin text not null check (origin ~ '^https?://'),
 verification_status text not null default 'pending' check (verification_status in ('pending','verified','expired','revoked')),
 verified_at timestamptz,
 verification_expires_at timestamptz,
 check (verification_status <> 'verified' or (verified_at is not null and verification_expires_at > verified_at)),
 unique (organization_id,project_id,hostname),
 unique (organization_id,project_id,id),
 foreign key (organization_id,project_id) references public.projects(organization_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.assets enable row level security;
create policy workspace_read on public.assets for select to authenticated using (public.can_read_workspace(organization_id));

create table public.asset_verifications (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 asset_id uuid not null,
 method text not null default 'dns_txt' check (method = 'dns_txt'),
 challenge text not null,
 status text not null default 'pending' check (status in ('pending','verified','expired','failed')),
 expires_at timestamptz not null,
 checked_at timestamptz,
 verified_at timestamptz,
 foreign key (organization_id,asset_id) references public.assets(organization_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.asset_verifications enable row level security;
create policy workspace_read on public.asset_verifications for select to authenticated using (public.can_read_workspace(organization_id));

create table public.scopes (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 project_id uuid not null,
 asset_id uuid not null,
 allowed_paths text[] not null default array['/'],
 include_subdomains boolean not null default false check (include_subdomains = false),
 authorized_by uuid not null references auth.users(id),
 expires_at timestamptz not null,
 unique (organization_id,asset_id,id),
 foreign key (organization_id,project_id,asset_id) references public.assets(organization_id,project_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.scopes enable row level security;
create policy workspace_read on public.scopes for select to authenticated using (public.can_read_workspace(organization_id));

create table public.scan_policies (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 name text not null,
 scan_type text not null default 'configuration' check (scan_type = 'configuration'),
 max_requests integer not null default 20 check (max_requests between 1 and 100),
 requests_per_second integer not null default 1 check (requests_per_second between 1 and 5),
 timeout_seconds integer not null default 60 check (timeout_seconds between 1 and 300),
 enabled boolean not null default false,
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.scan_policies enable row level security;
create policy workspace_read on public.scan_policies for select to authenticated using (public.can_read_workspace(organization_id));

create table public.scans (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 project_id uuid not null,
 asset_id uuid not null,
 scope_id uuid not null,
 policy_id uuid not null,
 requested_by uuid not null references auth.users(id),
 status text not null default 'queued' check (status in ('queued','running','completed','failed','cancelled')),
 started_at timestamptz,
 completed_at timestamptz,
 failure_code text,
 pages_checked integer check (pages_checked >= 0),
 checks_run integer check (checks_run >= 0),
 unique (organization_id,asset_id,id),
 foreign key (organization_id,project_id,asset_id) references public.assets(organization_id,project_id,id),
 foreign key (organization_id,asset_id,scope_id) references public.scopes(organization_id,asset_id,id),
 foreign key (organization_id,policy_id) references public.scan_policies(organization_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.scans enable row level security;
create policy workspace_read on public.scans for select to authenticated using (public.can_read_workspace(organization_id));

create table public.scan_jobs (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 scan_id uuid not null,
 status text not null default 'queued' check (status in ('queued','leased','completed','failed','cancelled')),
 attempts integer not null default 0 check (attempts between 0 and 3),
 available_at timestamptz not null default now(),
 lease_expires_at timestamptz,
 worker_id text,
 unique (scan_id),
 foreign key (organization_id,scan_id) references public.scans(organization_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.scan_jobs enable row level security;
create policy workspace_read on public.scan_jobs for select to authenticated using (public.can_read_workspace(organization_id));

create table public.scan_events (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 scan_id uuid not null,
 event_type text not null,
 message text not null,
 foreign key (organization_id,scan_id) references public.scans(organization_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.scan_events enable row level security;
create policy workspace_read on public.scan_events for select to authenticated using (public.can_read_workspace(organization_id));

create table public.findings (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 project_id uuid not null,
 asset_id uuid not null,
 fingerprint text not null check (length(fingerprint) > 0),
 title text not null,
 severity text not null check (severity in ('critical','high','medium','low','informational')),
 confidence text not null check (confidence in ('confirmed','high','possible','informational')),
 category text not null,
 affected_url text,
 explanation text not null,
 technical_explanation text,
 remediation text not null,
 cwe text[],
 cve text[],
 cvss numeric(3,1) check (cvss between 0 and 10),
 state text not null default 'open' check (state in ('open','fixed','accepted','false_positive')),
 first_seen timestamptz not null default now(),
 last_seen timestamptz not null default now(),
 check (last_seen >= first_seen),
 unique (organization_id,asset_id,fingerprint),
 unique (organization_id,asset_id,id),
 foreign key (organization_id,project_id,asset_id) references public.assets(organization_id,project_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.findings enable row level security;
create policy workspace_read on public.findings for select to authenticated using (public.can_read_workspace(organization_id));

create table public.finding_instances (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 asset_id uuid not null,
 finding_id uuid not null,
 scan_id uuid not null,
 source text not null,
 source_rule_id text not null,
 unique (finding_id,scan_id,source,source_rule_id),
 foreign key (organization_id,asset_id,finding_id) references public.findings(organization_id,asset_id,id),
 foreign key (organization_id,asset_id,scan_id) references public.scans(organization_id,asset_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.finding_instances enable row level security;
create policy workspace_read on public.finding_instances for select to authenticated using (public.can_read_workspace(organization_id));

create table public.evidence (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 finding_instance_id uuid not null,
 kind text not null check (kind in ('http_header','tls','redirect','metadata','note')),
 summary text not null,
 redacted_data jsonb not null default '{}'::jsonb check (jsonb_typeof(redacted_data) = 'object'),
 collected_at timestamptz not null default now(),
 foreign key (organization_id,finding_instance_id) references public.finding_instances(organization_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.evidence enable row level security;
create policy workspace_read on public.evidence for select to authenticated using (public.can_read_workspace(organization_id));

create table public.retests (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 asset_id uuid not null,
 finding_id uuid not null,
 scan_id uuid,
 requested_by uuid not null references auth.users(id),
 status text not null default 'requested' check (status in ('requested','running','passed','failed','inconclusive','cancelled')),
 completed_at timestamptz,
 foreign key (organization_id,asset_id,finding_id) references public.findings(organization_id,asset_id,id),
 foreign key (organization_id,asset_id,scan_id) references public.scans(organization_id,asset_id,id),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.retests enable row level security;
create policy workspace_read on public.retests for select to authenticated using (public.can_read_workspace(organization_id));

create table public.audit_logs (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id),
 actor_id uuid references auth.users(id) on delete set null,
 action text not null,
 entity_type text not null,
 entity_id uuid,
 metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
 created_at timestamptz not null default now(),
 unique (organization_id,id)
);
alter table public.audit_logs enable row level security;
create policy workspace_read on public.audit_logs for select to authenticated using (public.can_read_workspace(organization_id));
create policy workspace_create on public.projects for insert to authenticated with check (public.can_manage_workspace(organization_id));
create policy workspace_create on public.assets for insert to authenticated with check (public.can_manage_workspace(organization_id));

-- Explicit grants: verification, scope, scanner output and audit writes are trusted-backend only.
revoke all on public.organizations, public.organization_members, public.projects, public.assets, public.asset_verifications, public.scopes, public.scan_policies, public.scans, public.scan_jobs, public.scan_events, public.findings, public.finding_instances, public.evidence, public.retests, public.audit_logs from anon, authenticated;
grant select on public.organizations, public.organization_members, public.projects, public.assets, public.asset_verifications, public.scopes, public.scan_policies, public.scans, public.scan_jobs, public.scan_events, public.findings, public.finding_instances, public.evidence, public.retests, public.audit_logs to authenticated;
grant insert (owner_id,name), update (name) on public.organizations to authenticated;
grant insert (organization_id,name) on public.projects to authenticated;
grant insert (organization_id,project_id,hostname,origin) on public.assets to authenticated;
grant all on public.organizations, public.organization_members, public.projects, public.assets, public.asset_verifications, public.scopes, public.scan_policies, public.scans, public.scan_jobs, public.scan_events, public.findings, public.finding_instances, public.evidence, public.retests, public.audit_logs to service_role;
create index scans_project_created_idx on public.scans(organization_id,project_id,created_at desc);
create index findings_project_state_idx on public.findings(organization_id,project_id,state);
create index scan_jobs_available_idx on public.scan_jobs(available_at) where status = 'queued';
create index verification_asset_idx on public.asset_verifications(organization_id,asset_id);
create index instances_finding_idx on public.finding_instances(organization_id,asset_id,finding_id);
create index evidence_instance_idx on public.evidence(organization_id,finding_instance_id);
create index audit_created_idx on public.audit_logs(organization_id,created_at desc);
