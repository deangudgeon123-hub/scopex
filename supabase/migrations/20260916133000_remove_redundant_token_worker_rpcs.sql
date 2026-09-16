-- Cleanup for a superseded Stage 3 worker prototype.
-- The production Stage 3 worker uses service-role-only RPCs defined in native_scan_observations.

drop function if exists public.lease_next_operator_scan(text,text);
drop function if exists public.complete_operator_scan_native(uuid,text,jsonb,integer);
drop function if exists public.fail_operator_scan_native(uuid,text,text);

alter table public.scan_observations drop column if exists observed_url;
