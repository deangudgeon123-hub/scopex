-- Narrow, trigger-only privileged writer. Never expose an audit insert RPC.
create schema if not exists scopex_private;
revoke all on schema scopex_private from public, anon, authenticated;
create function scopex_private.record_creation() returns trigger
language plpgsql security definer set search_path = '' as $$
declare workspace uuid;
begin
 -- User-facing writes must have an authenticated actor. Service-role/system writes
 -- supply their own audit event; this trigger never fabricates an actor.
 if auth.uid() is null then return new; end if;
 if tg_table_name = 'organizations' then workspace := new.id;
 else workspace := new.organization_id;
 end if;
 insert into public.audit_logs(organization_id,actor_id,action,entity_type,entity_id)
 values(workspace,auth.uid(),'created',tg_table_name,new.id);
 return new;
end;
$$;
revoke all on function scopex_private.record_creation() from public, anon, authenticated;
create trigger audit_organization_creation after insert on public.organizations for each row execute function scopex_private.record_creation();
create trigger audit_project_creation after insert on public.projects for each row execute function scopex_private.record_creation();
create trigger audit_asset_creation after insert on public.assets for each row execute function scopex_private.record_creation();
