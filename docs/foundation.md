# SCOPEX app foundation

## Implemented

The existing dashboard is a Server Component entry point feeding a typed client dashboard. Data comes through `DashboardRepository`, with separate demo and Supabase implementations. Filtering and the scan modal remain local UI interactions. The scan button is disabled: there is no scanning endpoint, worker, scheduler or exploitation code.

`SCOPEX_DATA_MODE=demo` is the default. Every score, finding, verification indicator and scan shown in this mode is sample data. A visible demo label applies to the entire dashboard and the score is marked DEMO. Demo mode does not access Supabase.

`SCOPEX_DATA_MODE=supabase` uses the signed-in user's cookie session and RLS. Missing configuration, expired authentication or query failures never fall back to sample results. No score or trend is produced for real data. The dashboard loads the oldest accessible project; `GET /api/dashboard?projectId=<uuid>` can select an accessible project explicitly. The endpoint is private/no-store and returns 400/401/404/503 errors without raw database details.

The foundation supplies browser/server Supabase clients, session refresh middleware, and server-only workspace/project/asset creation services. These are integration functions, not yet user-facing onboarding or sign-in forms. No service-role key is used by the app.

## Database setup

Use a dedicated SCOPEX Supabase project. Do not apply these migrations to BENCHRX or another existing product database.

1. Create/select the SCOPEX project and configure Supabase Auth for your application URL.
2. With the Supabase CLI installed, run `supabase init` if a local config is needed, then `supabase link --project-ref YOUR_SCOPEX_REF` and `supabase db push`. Inspect the selected project before pushing. The two ordered SQL files can alternatively be applied through that project's SQL editor.
3. Copy `.env.example` to `.env.local`. Set `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`. Set `SCOPEX_DATA_MODE=supabase` only when the database and sign-in integration are ready.
4. Configure the same variables in Vercel and redeploy. Leave demo mode enabled until then.

No remote database was selected or migrated by this implementation. A SCOPEX project was not present in the connected account. Local SQL verification runs using PGlite PostgreSQL with a minimal Supabase auth/role harness; it does not verify hosted Auth, PostgREST or network configuration.

## Model and authorization

| Records | Purpose | Authenticated writes |
| --- | --- | --- |
| organizations | Workspace name and owner (auth.users) | Create as self; owner may rename |
| organization_members | Member/admin/viewer access | None; trusted membership administration later |
| projects | Group assets within a workspace | Owner/admin/member can create |
| assets | Website record and verification status | Create core fields only; no verification writes |
| asset_verifications | Expiring DNS TXT challenge and check history | None |
| scopes / scan_policies | Exact asset, paths, consent expiry, bounded requests/timeouts | None |
| scans / scan_jobs / scan_events | Assessment lifecycle, leases, attempts and events | None |
| findings / finding_instances | Canonical issue and individual scanner observations | None |
| evidence | Redacted technical observations attached to a scanner instance | None |
| retests | Finding-specific follow-up and outcome | None |
| audit_logs | Workspace-scoped activity | Trigger-only for user-created workspaces/projects/assets |

All public tables have RLS. Explicit grants apply only to SCOPEX tables. Membership reads are limited to the current user. The workspace access helpers are invoker functions, so they cannot bypass RLS. Composite foreign keys prevent children being assigned to a different workspace, project or asset than their parent.

The private audit trigger is the only security-definer function. It has an empty search path, no caller-supplied parameters, no public schema access, and no direct execution grants for API users. It writes only a fixed creation event for the row just authorized by RLS. System operations without an auth user must write their own audit records. User-facing audit updates/deletes are not granted.

## Canonical findings

A finding is unique by `(organization_id, asset_id, fingerprint)`. The future normalizer must compute a stable fingerprint from a canonical rule/category and normalized affected location (including endpoint/parameter when relevant), not the scanner name. This lets multiple tools support one finding without double-counting it. Avoid merging different endpoints or merely similar titles.

`finding_instances` preserve scanner source/rule and scan provenance. Multiple evidence records attach to each instance. Finding severity and confidence are separate. Confidence values map to Confirmed, High confidence, Possible and Informational. CVE/CWE/CVSS are optional. Remediation, plain-English and technical explanations are separate. No scoring formula exists. No finding currently claims confirmed exploitability.

Evidence accepts only redacted JSON objects. Future workers must remove credentials, session cookies, tokens and personal data before persistence; this migration does not implement a redaction engine. Do not persist raw scanner dumps.

## Before enabling assessments

Implement sign-in/onboarding and domain challenge verification, including expiry/revocation. Add a transactional enqueue operation that checks current verified ownership, explicit unexpired scope and enabled policy. Revalidate before every job and network hop. Implement SSRF and DNS rebinding protection, redirect scope checks, rate limits, timeouts, leases and audit events. Scan policies default to disabled and browser users cannot enqueue jobs. The tables are not an execution engine.

## Verification

- `npm ci` uses the committed lockfile.
- `npm test` executes real PostgreSQL migration/RLS checks and service projection tests.
- `npm run build` compiles and checks TypeScript; `npm run typecheck` is available independently.
- `npm run lint` currently aliases the TypeScript check; this project has no ESLint setup.

The manually maintained database TypeScript contract matches these migrations. Generate and review native Supabase types after linking a project, especially before adding joins or database functions.

References: [Supabase SSR clients](https://supabase.com/docs/guides/auth/server-side/creating-a-client), [row-level security](https://supabase.com/docs/guides/database/postgres/row-level-security).
