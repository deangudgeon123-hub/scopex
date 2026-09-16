# Private native assessment setup

## Database checkpoint — 16 September 2026

The connected account has no dedicated SCOPEX project. Project creation requires
an explicit organization selection followed by confirmation of the quoted cost.
No existing project has been modified. The available organization is
`deangudgeon123-hub's Org` (`svcrzegvzuddbamxtqgp`).

After creating the dedicated project, apply the existing migrations in filename
order, then run `supabase/verify.sql` in its SQL editor. This read-only check fails
if a required table, RLS policy, or anonymous-access restriction is missing.
There are no database views in the foundation.

Do not turn off RLS or reuse BENCHRX credentials. Do not commit project secrets.
Local PostgreSQL tests apply all migrations and test tenant/write boundaries;
they do not establish that a hosted project exists or is configured.

The development assessment flow is intentionally separate from customer auth.
It must remain unavailable on public production deployments. Explicit operator
allowlisting represents permission to test, not proof of domain ownership, and
must never mark an asset DNS-verified.
