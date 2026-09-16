-- Mirrors the hosted SCOPEX native observation checkpoint.
-- Raw observations are scanner evidence inputs, not user-facing findings.

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

alter table public.scan_observations enable row level security;
create policy scan_observations_read on public.scan_observations
 for select to authenticated using (public.can_read_workspace(organization_id));

revoke all on public.scan_observations from anon, authenticated;
grant select on public.scan_observations to authenticated;
grant all on public.scan_observations to service_role;

create index scan_observations_scan_idx on public.scan_observations(scan_id, observed_at);
create index scan_observations_asset_idx on public.scan_observations(asset_id, observed_at desc);
